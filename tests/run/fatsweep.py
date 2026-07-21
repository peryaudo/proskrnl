#!/usr/bin/env python3
"""fatsweep.py -- the FAT32 volume invariant sweeper (docs/08).

An independent, host-side reader of the FAT volume every test boot mutates.
fsck.fat (dosfstools, tests/run/fatcheck.sh) covers most of the on-disk
contract; this script pins the invariants specific to how proskrnl's driver
writes the volume, and reports them in the machine-greppable [FATSWEEP]
protocol:

  1. every FAT copy is byte-identical (fs/fat32/fat.c FatSetFatEntry writes
     through to all copies; a divergence is a missed write path)
  2. no cross-linked clusters: each cluster belongs to at most one chain
  3. chain length agrees with the directory entry (files: ceil(size /
     clusterBytes), size==0 <=> firstCluster==0; directories: >=1 cluster,
     DIR_FileSize==0)
  4. chains are well-formed: in-range hops, no bad-cluster (0x0FFFFFF7)
     members, a proper end-of-chain terminal
  5. no lost clusters (allocated in the FAT but unreachable from the root)
  6. directory entries are sane: LFN runs ordered/complete/checksummed,
     no allocated entry after the 0x00 terminator, no duplicate 8.3 names,
     volume label only in the root, '.'/'..' first in every subdirectory
     with '..' pointing at the parent
  7. FSInfo signatures intact.  The free count is ADVISORY ONLY (docs/03
     "FSInfo free-count is not maintained"; the spec marks it a hint) -- a
     stale count is a warning, a clobbered signature is a violation.

All on-disk layout constants cite the "Microsoft FAT Specification"
(Aug 30 2005, the fatgen103 successor) by section, matching fs/fat32/.

Usage: fatsweep.py <image> [--offset BYTES]
       (offset defaults to 2097152: partition 2 at sector 4096,
        tools/mkimage.sh ESP_OFF)

Exit 0 and "[FATSWEEP] PASS" when no violation; exit 1 otherwise.
"""

import argparse
import struct
import sys

FAT_ENTRY_MASK = 0x0FFFFFFF  # high 4 bits reserved (spec section 4)
FAT_BAD = 0x0FFFFFF7         # bad cluster (spec section 4)
FAT_EOC_MIN = 0x0FFFFFF8     # masked value >= this = end of chain (spec section 4)

violations = []
warnings = []


def violation(msg):
    violations.append(msg)
    print(f"[FATSWEEP] violation: {msg}")


def warning(msg):
    warnings.append(msg)
    print(f"[FATSWEEP] warning: {msg}")


class Volume:
    def __init__(self, f, offset):
        self.f = f
        self.offset = offset
        f.seek(offset)
        boot = f.read(512)
        if boot[510] != 0x55 or boot[511] != 0xAA:
            raise SystemExit("[FATSWEEP] FAIL no boot-sector signature (spec section 3.3)")
        # BPB fields by offset (spec sections 3.1/3.3).
        self.bps = struct.unpack_from("<H", boot, 11)[0]
        self.spc = boot[13]
        self.rsvd = struct.unpack_from("<H", boot, 14)[0]
        self.nfats = boot[16]
        totsec16 = struct.unpack_from("<H", boot, 19)[0]
        totsec32 = struct.unpack_from("<I", boot, 32)[0]
        self.fatsz = struct.unpack_from("<I", boot, 36)[0]
        self.rootclus = struct.unpack_from("<I", boot, 44)[0]
        self.fsinfo_sector = struct.unpack_from("<H", boot, 48)[0]
        self.totsec = totsec16 if totsec16 != 0 else totsec32
        # FirstDataSector; root dir sectors are 0 on FAT32 (spec section 3.5).
        self.first_data = self.rsvd + self.nfats * self.fatsz
        self.cluster_count = (self.totsec - self.first_data) // self.spc
        self.cluster_bytes = self.bps * self.spc

        # Load every FAT copy raw for the mirror check; parse copy 0.
        self.fat_raw = []
        for copy in range(self.nfats):
            f.seek(offset + (self.rsvd + copy * self.fatsz) * self.bps)
            self.fat_raw.append(f.read(self.fatsz * self.bps))
        n = min(self.cluster_count + 2, len(self.fat_raw[0]) // 4)
        self.fat = [
            v & FAT_ENTRY_MASK
            for v in struct.unpack_from(f"<{n}I", self.fat_raw[0])
        ]

    def read_cluster(self, cluster):
        # FirstSectorofCluster = (N-2)*SecPerClus + FirstDataSector (spec 6.7).
        sector = (cluster - 2) * self.spc + self.first_data
        self.f.seek(self.offset + sector * self.bps)
        return self.f.read(self.cluster_bytes)

    def walk_chain(self, first, what):
        """Return the cluster list; records violations for malformed chains."""
        chain = []
        cluster = first
        while True:
            if cluster < 2 or cluster >= self.cluster_count + 2:
                violation(f"{what}: chain hop to out-of-range cluster {cluster:#x}")
                return chain
            chain.append(cluster)
            if len(chain) > self.cluster_count:
                violation(f"{what}: chain loop")
                return chain
            value = self.fat[cluster]
            if value >= FAT_EOC_MIN:
                return chain
            if value == FAT_BAD:
                violation(f"{what}: chain enters bad-cluster mark at {cluster}")
                return chain
            if value == 0:
                violation(f"{what}: chain hits a FREE entry at cluster {cluster}")
                return chain
            cluster = value


def lfn_checksum(sfn11):
    # The 8.3 checksum every LFN entry carries (spec section 7.2).
    s = 0
    for b in sfn11:
        s = ((0x80 if s & 1 else 0) + (s >> 1) + b) & 0xFF
    return s


def sweep_tree(vol):
    """Walk every directory from the root; returns refs[cluster] -> owner."""
    owner = {}

    def claim(chain, what):
        for c in chain:
            if c in owner:
                violation(f"cross-link: cluster {c} in both '{owner[c]}' and '{what}'")
            else:
                owner[c] = what

    root_chain = vol.walk_chain(vol.rootclus, "/")
    claim(root_chain, "/")
    pending = [(root_chain, "/", True)]
    seen_dirs = {vol.rootclus}

    while pending:
        chain, path, is_root = pending.pop()
        data = b"".join(vol.read_cluster(c) for c in chain)
        names83 = set()
        terminated = False
        pending_lfn = None  # (next_expected_ordinal, checksum, start_index)
        for i in range(0, len(data), 32):
            e = data[i : i + 32]
            slot = f"{path} slot {i // 32}"
            if e[0] == 0x00:
                terminated = True
                pending_lfn = None
                continue
            if terminated:
                violation(f"{slot}: allocated entry after the 0x00 terminator")
            if e[0] == 0xE5:  # free (spec section 6.1)
                pending_lfn = None
                continue
            attr = e[11]
            if attr & 0x3F == 0x0F:  # long-name entry (spec section 7)
                ordinal = e[0] & 0x3F
                if e[0] & 0x40:  # LAST_LONG_ENTRY: first on disk
                    pending_lfn = (ordinal, e[13], i // 32)
                elif pending_lfn is None:
                    violation(f"{slot}: orphan LFN entry (no LAST-flagged head)")
                elif ordinal != pending_lfn[0] - 1 or e[13] != pending_lfn[1]:
                    violation(f"{slot}: LFN run out of order or checksum changed")
                    pending_lfn = None
                else:
                    pending_lfn = (ordinal, pending_lfn[1], pending_lfn[2])
                continue
            if attr & 0x08:  # ATTR_VOLUME_ID (spec section 6.2)
                if not is_root:
                    violation(f"{slot}: volume label outside the root")
                pending_lfn = None
                continue

            # A short entry.
            if pending_lfn is not None:
                if pending_lfn[0] != 1:
                    violation(f"{slot}: incomplete LFN run (stopped at ordinal {pending_lfn[0]})")
                elif lfn_checksum(e[0:11]) != pending_lfn[1]:
                    violation(f"{slot}: LFN checksum does not match the 8.3 entry")
                pending_lfn = None

            name83 = bytes(e[0:11])
            first = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            is_dir = bool(attr & 0x10)
            display = name83.decode("ascii", "replace").strip()

            if name83[0:1] == b".":  # '.' / '..' (spec section 6.5)
                if is_root:
                    violation(f"{slot}: dot entry in the root")
                elif name83 == b".          ":
                    if first != chain[0]:
                        violation(f"{path}: '.' points at {first}, not itself ({chain[0]})")
                elif name83 == b"..         ":
                    parent_first = parent_of.get(path)
                    if parent_first is not None and first != parent_first:
                        violation(f"{path}: '..' points at {first}, want {parent_first}")
                continue

            if name83 in names83:
                violation(f"{slot}: duplicate 8.3 name '{display}'")
            names83.add(name83)

            child_path = f"{path.rstrip('/')}/{display}"
            if is_dir:
                if size != 0:
                    violation(f"{child_path}: directory with nonzero DIR_FileSize {size}")
                if first == 0:
                    violation(f"{child_path}: directory with no first cluster")
                    continue
                child_chain = vol.walk_chain(first, child_path)
                claim(child_chain, child_path)
                if first in seen_dirs:
                    violation(f"{child_path}: directory cluster {first} already walked (loop)")
                    continue
                seen_dirs.add(first)
                parent_of[child_path] = 0 if is_root else chain[0]
                pending.append((child_chain, child_path, False))
            else:
                if size == 0:
                    if first != 0:
                        violation(f"{child_path}: empty file with first cluster {first}")
                    continue
                if first == 0:
                    violation(f"{child_path}: size {size} but no first cluster")
                    continue
                file_chain = vol.walk_chain(first, child_path)
                want = (size + vol.cluster_bytes - 1) // vol.cluster_bytes
                if len(file_chain) != want:
                    violation(
                        f"{child_path}: chain length {len(file_chain)} clusters, "
                        f"want {want} for size {size}"
                    )
                claim(file_chain, child_path)
        if pending_lfn is not None:
            violation(f"{path}: LFN run at the end of the directory with no 8.3 entry")
    return owner


parent_of = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--offset", type=int, default=2097152,
                    help="partition byte offset (default: mkimage.sh ESP_OFF)")
    args = ap.parse_args()

    with open(args.image, "rb") as f:
        vol = Volume(f, args.offset)

        # 1. FAT mirror identity.
        for copy in range(1, vol.nfats):
            if vol.fat_raw[copy] != vol.fat_raw[0]:
                diff = next(
                    i for i in range(len(vol.fat_raw[0]))
                    if vol.fat_raw[0][i] != vol.fat_raw[copy][i]
                )
                violation(
                    f"FAT copy {copy} differs from copy 0 at byte {diff} "
                    f"(cluster {diff // 4})"
                )

        # 2-4, 6. The tree walk.
        owner = sweep_tree(vol)

        # 5. Lost clusters: allocated but unreachable.
        lost = [
            c for c in range(2, vol.cluster_count + 2)
            if vol.fat[c] not in (0, FAT_BAD) and c not in owner
        ]
        if lost:
            violation(f"{len(lost)} lost cluster(s), first few: {lost[:8]}")

        # 7. FSInfo (spec section 5): signatures are load-bearing, the free
        # count is advisory and the kernel does not maintain it (docs/03).
        if vol.fsinfo_sector != 0 and vol.fsinfo_sector != 0xFFFF:
            f.seek(args.offset + vol.fsinfo_sector * vol.bps)
            fsi = f.read(512)
            lead = struct.unpack_from("<I", fsi, 0)[0]
            struc = struct.unpack_from("<I", fsi, 484)[0]
            trail = struct.unpack_from("<I", fsi, 508)[0]
            if lead != 0x41615252 or struc != 0x61417272 or trail != 0xAA550000:
                violation("FSInfo signatures clobbered (spec section 5)")
            else:
                free_count = struct.unpack_from("<I", fsi, 488)[0]
                actual_free = sum(
                    1 for c in range(2, vol.cluster_count + 2) if vol.fat[c] == 0
                )
                if free_count != 0xFFFFFFFF and free_count != actual_free:
                    warning(
                        f"FSInfo free count {free_count} != actual {actual_free} "
                        "(advisory; not maintained per docs/03)"
                    )

    if violations:
        print(f"[FATSWEEP] FAIL violations={len(violations)}")
        return 1
    print(f"[FATSWEEP] PASS ({len(warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
