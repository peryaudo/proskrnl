#!/usr/bin/env python3
"""fatgen.py -- the FAT interop battery's deterministic corpus generator
(docs/08 "The FAT on-disk format has its own oracles").

One script is the single source of truth for both directions of the battery:

  emit       write the host->kernel corpus (content files + the mtools bake
             choreography) and the manifest both sides verify against
  verify     after a boot: check the kernel-written battery that mcopy
             extracted against the manifest (existence, size, content)
  fragcheck  assert a baked file's cluster chain really is fragmented (the
             corpus relies on mtools first-fit filling delete-holes; this
             keeps the fragmentation class from silently degrading)

Content is never stored in the manifest: byte j of file index k is
  (k*131 + j*7 + 3) & 0xFF
so the kernel can regenerate/verify content from (index, size) alone, and
this script can do the same for extraction checks. The checksum is FNV-1a
32-bit (offset basis 2166136261, prime 16777619 -- draft-eastlake-fnv):
freestanding-trivial on both sides, and the differential comparison itself
checks that the two implementations agree.

Manifest line format (path LAST so embedded spaces need no quoting):
  <side> <type> <index> <size> <fnv32hex> <flags> <path>
  side:  H = host-baked, kernel reads/verifies
         W = kernel writes, host extracts/verifies
  type:  f = file, d = directory
  flags: '-'   none
         'ci'  compare the name case-insensitively (8.3-only storage: mtools
               may use Windows-NT lowercase NTRes bits the MS spec reserves,
               and extracts SFN-only names lowercased)
         'del' kernel creates then deletes it -- the host must NOT see it
Paths are '/'-separated, relative to /fatcorpus (H) or /fatout (W).
"""

import argparse
import os
import struct
import sys

FNV_BASIS = 2166136261  # draft-eastlake-fnv
FNV_PRIME = 16777619


def fnv1a(data):
    h = FNV_BASIS
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return h


def content(index, size):
    return bytes(((index * 131 + j * 7 + 3) & 0xFF) for j in range(size))


class Corpus:
    def __init__(self):
        self.manifest = []   # (side, type, index, size, fnv, flags, path)
        self.bake = []       # ('mkdir', path) / ('copy', hostname, path) / ('del', path)
        self.hostfiles = {}  # hostname -> bytes
        self.next_index = 1

    def h_dir(self, path):
        flags = "ci" if sfn_only(path.rsplit("/", 1)[-1]) else "-"
        self.manifest.append(("H", "d", 0, 0, 0, flags, path))
        self.bake.append(("mkdir", "/fatcorpus/" + path))

    def h_file(self, path, size, flags="-", listed=True):
        k = self.next_index
        self.next_index += 1
        data = content(k, size)
        host = f"f{k:04d}.bin"
        self.hostfiles[host] = data
        if flags == "-" and sfn_only(path.rsplit("/", 1)[-1]):
            flags = "ci"
        if listed:
            self.manifest.append(("H", "f", k, size, fnv1a(data), flags, path))
        self.bake.append(("copy", host, "/fatcorpus/" + path))
        return path

    def h_del(self, path):
        self.bake.append(("del", "/fatcorpus/" + path))

    def w_dir(self, path):
        self.manifest.append(("W", "d", 0, 0, 0, "-", path))

    def w_file(self, path, size, flags="-"):
        k = self.next_index
        self.next_index += 1
        self.manifest.append(("W", "f", k, size, fnv1a(content(k, size)), flags, path))


def sfn_only(name):
    """True when mtools stores `name` as a bare 8.3 entry with NO LFN run:
    its upcased form fits 8.3 (one dot, base<=8, ext<=3, legal charset).
    mtools records the original case in the Windows-NT DIR_NTRes lowercase
    bits, which the MS FAT spec reserves and fs/fat32/dir.c rightly ignores
    -- so the kernel enumerates such names UPPERCASED, and extraction
    lowercases them; both sides compare case-insensitively ('ci')."""
    if " " in name:
        return False
    parts = name.split(".")
    if len(parts) > 2 or not parts[0]:
        return False
    base, ext = parts[0], parts[1] if len(parts) == 2 else ""
    if len(base) > 8 or len(ext) > 3:
        return False
    legal = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-~!#$%&'()@^`{}")
    return all(c.upper() in legal for c in base + ext)


def mixed_name(prefix, total_len):
    """A deterministic mixed-case name of exactly total_len chars."""
    assert len(prefix) < total_len
    fill = "aBcDeFgHiJkLmNoPqRsTuVwXyZ"
    name = prefix
    i = 0
    while len(name) < total_len:
        name += fill[i % len(fill)]
        i += 1
    return name


def build_corpus(cluster_bytes):
    c = Corpus()
    cb = cluster_bytes

    # --- host -> kernel (/fatcorpus) ---------------------------------------
    # LFN unit boundaries: 13 chars fill exactly one LFN entry with no NUL
    # terminator (spec section 7.3) -- the assembly edge dir.c must get right.
    for length in (12, 13, 14, 25, 26, 27, 38, 39, 40):
        c.h_file(mixed_name(f"Ln{length:03d}", length), 100 + length)
    # Max-length names (20 LFN entries + the SFN = a 21-slot run): mtools'
    # slot allocator fails intermittently on consecutive multi-cluster runs
    # ("No directory slots"), but the first copy into a fresh directory is
    # reliable -- so each gets its own subdirectory. The kernel-side battery
    # (W) covers the same lengths through fs/fat32's own allocator.
    c.h_dir("longnames")
    for length in (253, 254, 255):
        c.h_dir(f"longnames/n{length}")
        c.h_file(f"longnames/n{length}/" + mixed_name(f"Ln{length:03d}", length),
                 100 + length)
    # 8.3-exact names (no LFN run on disk).
    for name in ("UPPER.TXT", "ABCDEFGH.EXT", "NOEXT", "A"):
        c.h_file(name, 64, flags="ci")
    # Case classes.
    c.h_file("lower.txt", 65, flags="ci")  # 8.3-fitting lowercase: NTRes territory
    c.h_file("MixedCase.Dat", 66)
    # SFN-collision family: same 8.3 stem, numeric tails forced to 2 digits.
    for i in range(1, 13):
        c.h_file(f"longcommonprefix{i:02d}.txt", 128 + i)
    # Punctuation / spaces / leading dot.
    c.h_file("two words.txt", 70)
    c.h_file("a.b.c.txt", 71)
    c.h_file(".dotfile", 72)
    # Size classes: cluster edges and page-cache (4 KiB) edges + a long chain.
    sizes = sorted({0, 1, cb - 1, cb, cb + 1, 2 * cb - 1, 2 * cb, 2 * cb + 1,
                    4095, 4096, 4097, 1048576})
    for s in sizes:
        c.h_file(f"sz_{s}.bin", s)
    # Deep nesting.
    path = ""
    for d in range(1, 17):
        path = (path + "/" if path else "") + f"d{d:02d}"
        c.h_dir(path)
    c.h_file(path + "/DeepLeaf.txt", 333)
    # A multi-cluster directory: 200 LFN-named small files.
    c.h_dir("manyfiles")
    for i in range(200):
        c.h_file(f"manyfiles/mf_{i:03d}_LongFileName.txt", i)
    # Fragmentation targets: baked contiguously, then scattered on-image by
    # the `fragment` subcommand (deterministic FAT surgery; mtools' own
    # allocator is not reliably first-fit, so delete-hole choreography
    # cannot guarantee a split chain). fragcheck asserts it worked.
    c.h_file("frag.bin", 64 * 1024)
    c.h_file("frag2.bin", 24 * 1024)

    # --- kernel -> host (/fatout) ------------------------------------------
    c.w_dir("wd1")
    c.w_dir("wd1/wd2")
    c.w_dir("wd1/wd2/wd3")
    for length in (13, 26, 255):
        c.w_file(mixed_name(f"Kn{length:03d}", length), 200 + length)
    c.w_file("KMixedCase.Dat", 90)
    c.w_file("KUPPER.TXT", 91, flags="ci")  # exact-8.3: SFN-only on disk
    c.w_file("two words out.txt", 92)
    for i in range(1, 13):
        c.w_file(f"kernelcommonprefix{i:02d}.txt", 150 + i)
    for s in sorted({0, 1, cb - 1, cb, cb + 1, 2 * cb + 1, 4095, 4096, 4097, 100000}):
        c.w_file(f"ksz_{s}.bin", s)
    c.w_file("wd1/wd2/wd3/Deep Out Leaf.txt", 444)
    for i in range(5):
        c.w_file(f"tmpdel_{i:02d}.bin", 512 + i, flags="del")
    return c


def cmd_emit(args):
    c = build_corpus(args.cluster_bytes)
    hostdir = os.path.join(args.outdir, "hostfiles")
    os.makedirs(hostdir, exist_ok=True)
    for name, data in c.hostfiles.items():
        with open(os.path.join(hostdir, name), "wb") as f:
            f.write(data)
    with open(os.path.join(args.outdir, "bake.txt"), "w") as f:
        for op in c.bake:
            f.write("\t".join(op) + "\n")
    with open(os.path.join(args.outdir, "manifest.txt"), "w") as f:
        f.write(f"# fatgen corpus, cluster_bytes={args.cluster_bytes}\n")
        for side, typ, k, size, h, flags, path in c.manifest:
            f.write(f"{side} {typ} {k} {size} {h:08x} {flags} {path}\n")
    print(f"fatgen: {len(c.manifest)} manifest entries, "
          f"{len(c.hostfiles)} host files, {len(c.bake)} bake ops")


def parse_manifest(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            side, typ, k, size, h, flags, name = line.split(" ", 6)
            entries.append((side, typ, int(k), int(size), int(h, 16), flags, name))
    return entries


def cmd_verify(args):
    entries = [e for e in parse_manifest(args.manifest) if e[0] == "W"]
    fails = 0

    # What the extraction dir actually contains (relative paths).
    found = {}
    for root, dirs, files in os.walk(args.extracted):
        rel = os.path.relpath(root, args.extracted)
        rel = "" if rel == "." else rel.replace(os.sep, "/")
        for d in dirs:
            found[(rel + "/" if rel else "") + d] = None
        for name in files:
            found[(rel + "/" if rel else "") + name] = os.path.join(root, name)

    ci_map = {p.lower(): p for p in found}
    matched = set()
    for side, typ, k, size, h, flags, path in entries:
        if flags == "del":
            hit = path in found or path.lower() in ci_map
            if hit:
                print(f"fatgen verify: FAIL deleted file survived: {path}")
                fails += 1
            continue
        real = path if path in found else ci_map.get(path.lower())
        if real is None:
            print(f"fatgen verify: FAIL missing: {path}")
            fails += 1
            continue
        if flags != "ci" and real != path:
            print(f"fatgen verify: FAIL case mismatch: got '{real}' want '{path}'")
            fails += 1
        matched.add(real)
        if typ == "d":
            if found[real] is not None:
                print(f"fatgen verify: FAIL not a directory: {path}")
                fails += 1
            continue
        with open(found[real], "rb") as f:
            data = f.read()
        if len(data) != size:
            print(f"fatgen verify: FAIL size {len(data)} != {size}: {path}")
            fails += 1
        elif data != content(k, size):
            j = next(i for i in range(size) if data[i] != content(k, size)[i])
            print(f"fatgen verify: FAIL content differs at byte {j}: {path}")
            fails += 1
    extras = set(found) - matched
    # Every parent dir of a matched path is implicitly fine.
    extras = {e for e in extras
              if not any(m.startswith(e + "/") for m in matched)}
    for e in sorted(extras):
        print(f"fatgen verify: FAIL unexpected entry: {e}")
        fails += 1

    print(f"fatgen verify: {fails} failing")
    return 1 if fails else 0


class FatImage:
    """Minimal FAT32 accessor for the fragment/fragcheck subcommands.
    Offsets per the Microsoft FAT Specification (Aug 30 2005) sections
    3.1/3.3/4/6/7 -- the same citations as tests/run/fatsweep.py."""

    def __init__(self, f, offset):
        self.f = f
        self.offset = offset
        f.seek(offset)
        boot = f.read(512)
        self.bps = struct.unpack_from("<H", boot, 11)[0]
        self.spc = boot[13]
        self.rsvd = struct.unpack_from("<H", boot, 14)[0]
        self.nfats = boot[16]
        self.fatsz = struct.unpack_from("<I", boot, 36)[0]
        self.rootclus = struct.unpack_from("<I", boot, 44)[0]
        self.first_data = self.rsvd + self.nfats * self.fatsz
        totsec = struct.unpack_from("<I", boot, 32)[0]
        self.cluster_count = (totsec - self.first_data) // self.spc
        f.seek(offset + self.rsvd * self.bps)
        self.fat = list(struct.unpack(f"<{self.fatsz * self.bps // 4}I",
                                      f.read(self.fatsz * self.bps)))

    def next_cluster(self, c):
        v = self.fat[c] & 0x0FFFFFFF
        return v if 2 <= v < 0x0FFFFFF7 else 0

    def chain(self, first):
        out = []
        c = first
        while 2 <= c < 0x0FFFFFF7:
            out.append(c)
            if len(out) > self.cluster_count:
                break  # looped chain: return what we have (torn-state safe)
            c = self.fat[c] & 0x0FFFFFFF
            if c >= 0x0FFFFFF8:
                break
        return out

    def cluster_pos(self, c):
        return self.offset + ((c - 2) * self.spc + self.first_data) * self.bps

    def read_cluster(self, c):
        self.f.seek(self.cluster_pos(c))
        return self.f.read(self.spc * self.bps)

    def write_cluster(self, c, data):
        self.f.seek(self.cluster_pos(c))
        self.f.write(data)

    def set_fat(self, c, value):
        """Write one entry through to every FAT copy, preserving the
        reserved high 4 bits (spec section 4.1 write code)."""
        self.fat[c] = (self.fat[c] & 0xF0000000) | (value & 0x0FFFFFFF)
        raw = struct.pack("<I", self.fat[c])
        for copy in range(self.nfats):
            self.f.seek(self.offset + (self.rsvd + copy * self.fatsz) * self.bps + c * 4)
            self.f.write(raw)

    def find_entry(self, path):
        """Resolve a '/'-path to its directory entry; returns
        (entry_file_pos, first_cluster, size) or None. LFN per spec sec. 7."""
        parts = path.strip("/").split("/")
        cluster = self.rootclus
        result = None
        for want in parts:
            hit = None
            for c in self.chain(cluster):
                data = self.read_cluster(c)
                lfn = ""
                for i in range(0, len(data), 32):
                    e = data[i:i + 32]
                    if e[0] == 0x00:
                        break
                    if e[0] == 0xE5:
                        lfn = ""
                        continue
                    if e[11] & 0x3F == 0x0F:
                        chars = e[1:11] + e[14:26] + e[28:32]
                        part = chars.decode("utf-16-le").split("\0")[0].rstrip("￿")
                        lfn = part + lfn
                        continue
                    name = lfn or (
                        e[0:8].decode("ascii", "replace").rstrip() +
                        ("." + e[8:11].decode("ascii", "replace").rstrip()
                         if e[8:11] != b"   " else "")
                    )
                    lfn = ""
                    if name.lower() == want.lower():
                        hit = (self.cluster_pos(c) + i, e)
                        break
                if hit:
                    break
            if hit is None:
                return None
            pos, e = hit
            first = (struct.unpack_from("<H", e, 20)[0] << 16) | \
                struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            result = (pos, first, size)
            cluster = first
        return result


def cmd_fragment(args):
    """Scatter a file's chain: move every second cluster to a free cluster
    found from the TOP of the volume (data + FAT links move together, both
    FAT copies updated), leaving a valid volume whose chain has many
    extents. Deterministic -- no reliance on any allocator's policy."""
    with open(args.image, "r+b") as f:
        vol = FatImage(f, args.offset)
        found = vol.find_entry(args.path)
        if found is None:
            print(f"fatgen fragment: '{args.path}' not found")
            return 1
        _, first, _ = found
        chain = vol.chain(first)
        free = [c for c in range(vol.cluster_count + 1, 2, -1)
                if vol.fat[c] & 0x0FFFFFFF == 0]
        moved = 0
        for i in range(1, len(chain), 2):
            if not free:
                break
            target = free.pop(0)
            vol.write_cluster(target, vol.read_cluster(chain[i]))
            vol.set_fat(target, vol.fat[chain[i]] & 0x0FFFFFFF)
            vol.set_fat(chain[i - 1], target)
            vol.set_fat(chain[i], 0)
            chain[i] = target
            # Relink target -> the (unmoved) next cluster.
            if i + 1 < len(chain):
                vol.set_fat(target, chain[i + 1])
            moved += 1
        print(f"fatgen fragment: {args.path}: moved {moved} clusters")
        return 0


def cmd_fragcheck(args):
    """Count a file's chain extents; fail below --min-extents."""
    with open(args.image, "rb") as f:
        vol = FatImage(f, args.offset)
        found = vol.find_entry(args.path)
        if found is None:
            print(f"fatgen fragcheck: '{args.path}' not found")
            return 1
        _, first, size = found
        chain = vol.chain(first)
        extents = sum(1 for i, c in enumerate(chain) if i == 0 or c != chain[i - 1] + 1)
        print(f"fatgen fragcheck: {args.path} size={size} extents={extents}")
        if extents < args.min_extents:
            print(f"fatgen fragcheck: FAIL want >= {args.min_extents} extents")
            return 1
        return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit")
    e.add_argument("--outdir", required=True)
    e.add_argument("--cluster-bytes", type=int, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--extracted", required=True)
    v.add_argument("--manifest", required=True)
    for name in ("fragment", "fragcheck"):
        g = sub.add_parser(name)
        g.add_argument("--image", required=True)
        g.add_argument("--offset", type=int, default=2097152)
        g.add_argument("--path", required=True)
        if name == "fragcheck":
            g.add_argument("--min-extents", type=int, default=2)
    args = ap.parse_args()
    if args.cmd == "emit":
        return cmd_emit(args)
    if args.cmd == "verify":
        return sys.exit(cmd_verify(args))
    if args.cmd == "fragment":
        return sys.exit(cmd_fragment(args))
    return sys.exit(cmd_fragcheck(args))


if __name__ == "__main__":
    main()
