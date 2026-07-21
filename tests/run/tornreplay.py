#!/usr/bin/env python3
"""tornreplay.py -- exhaustive torn-write testing via write-trace prefix
replay (docs/08; run.sh tornwrite).

Art. 3 makes proskrnl's I/O synchronous, single-request, immediate-writeback
-- so the block-write sequence of a workload is deterministic and SHORT, and
every prefix of it is a reachable power-loss state. QEMU's blklogwrites
driver (tools/qemu.sh WRITE_LOG) logs every guest write; this script applies
the log prefix-by-prefix to a pristine copy of the partition and checks each
resulting state:

  structurally FATAL (never acceptable after a power loss):
    - cross-linked clusters, chain loops, out-of-range chain hops
      (the FAT write orderings in fs/fat32/ cannot produce these: a fresh
       cluster is EOC'd before it is linked, truncation EOCs before freeing)
    - a write outside the FAT partition or the m6_blk scratch range
    - a registry hive with a VALID magic that fails to parse -- the
      kernel/cm/hive.c torn-write guarantee is exactly that the magic is
      written LAST, so a valid-magic hive must always parse
  acceptable mid-write states (deterministic loss, not corruption):
    - lost clusters (allocate -> link -> dirent is three writes)
    - FAT copies differing (mirrored sequentially)
    - chain length disagreeing with the directory entry's size in either
      direction (metadata is flushed after cluster ops)
    - orphaned/incomplete LFN runs (multi-slot runs span sector writes)
    - a dirent whose first cluster is free (truncate-to-zero frees the
      chain before the metadata flush)

The final sanity bracket: after applying the WHOLE log the working partition
must be byte-identical to the partition of the actually-booted image --
proving the log is complete and the replay correct.

Log format: third_party/qemu/block/blklogwrites.c (the dm-log-writes
format): a one-sector super {le64 magic 0x6a736677736872, le64 version=1,
le64 nr_entries, le32 sectorsize}, then per write a one-sector entry header
{le64 sector, le64 nr_sectors, le64 flags, le64 data_len} followed by the
data sectors.

Usage: tornreplay.py --pristine <hdd> --final <hdd> --log <bin> [--stride N]
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fatgen import FatImage          # noqa: E402
from regdump import parse_phv1       # noqa: E402

ESP_OFF = 2097152   # mkimage.sh: p2 at sector 4096
PART_LBA = 4096
# tests/kmt/m6_blk.c writes raw sectors in the unpartitioned GPT slack.
SCRATCH_LBA, SCRATCH_END = 1024, 2048

LOG_MAGIC = 0x6A736677736872    # blklogwrites.c WRITE_LOG_MAGIC


def read_log(path):
    """blklogwrites appends, per operation, ONE header sector followed by
    the data sectors (blk_log_writes_co_log: the log qiov is the padded
    32-byte entry + the guest data; entry.data_len is always 0 in QEMU's
    writer — the data length is nr_sectors * sectorsize). Flush entries
    (LOG_FLUSH_FLAG, nr_sectors 0) carry no data; the guest driver never
    negotiates FLUSH, but the device model emits its own — they are dropped
    here since they change no disk state."""
    with open(path, "rb") as f:
        super_block = f.read(512)
        magic, version, nr_entries = struct.unpack_from("<QQQ", super_block, 0)
        sectorsize = struct.unpack_from("<I", super_block, 24)[0]
        if magic != LOG_MAGIC or version != 1:
            raise SystemExit(f"tornreplay: bad log super (magic {magic:#x})")
        entries = []
        for _ in range(nr_entries):
            header = f.read(sectorsize)
            sector, nr_sectors, flags, _data_len = struct.unpack_from("<QQQQ", header, 0)
            data = f.read(nr_sectors * sectorsize) if nr_sectors else b""
            if flags == 1 and nr_sectors == 0:  # LOG_FLUSH_FLAG: no state change
                continue
            entries.append((sector, nr_sectors, flags, data))
        return sectorsize, entries


def check_structure(part_path):
    """The FATAL subset only (see the header); returns a list of problems."""
    problems = []
    with open(part_path, "rb") as f:
        try:
            vol = FatImage(f, 0)
        except Exception as e:  # BPB unreadable = fatal (kernel never writes it)
            return [f"BPB parse failed: {e}"]

        refs = {}

        def walk(first, what):
            chain = []
            c = first
            while True:
                if c < 2 or c >= vol.cluster_count + 2:
                    problems.append(f"{what}: chain hop out of range ({c:#x})")
                    return chain
                if c in refs:
                    if refs[c] == what and c in chain:
                        problems.append(f"{what}: chain loop at {c}")
                    else:
                        problems.append(f"cross-link: {c} in {refs[c]} and {what}")
                    return chain
                refs[c] = what
                chain.append(c)
                if len(chain) > vol.cluster_count:
                    problems.append(f"{what}: chain longer than the volume")
                    return chain
                v = vol.fat[c] & 0x0FFFFFFF
                if v >= 0x0FFFFFF8:
                    return chain
                if v == 0 or v == 0x0FFFFFF7:
                    return chain  # freed/bad mid-chain: acceptable torn state
                c = v

        pending = [(walk(vol.rootclus, "/"), "/")]
        while pending:
            chain, path = pending.pop()
            data = b"".join(vol.read_cluster(c) for c in chain)
            for i in range(0, len(data), 32):
                e = data[i:i + 32]
                if e[0] == 0x00:
                    break
                if e[0] == 0xE5 or e[11] & 0x3F == 0x0F or e[11] & 0x08:
                    continue
                if e[0:1] == b".":
                    continue
                first = (struct.unpack_from("<H", e, 20)[0] << 16) | \
                    struct.unpack_from("<H", e, 26)[0]
                if first == 0:
                    continue
                if first < 2 or first >= vol.cluster_count + 2:
                    problems.append(f"{path} slot {i//32}: first cluster {first:#x} out of range")
                    continue
                if vol.fat[first] & 0x0FFFFFFF == 0:
                    continue  # dirent -> free cluster: acceptable (truncate window)
                name = e[0:11].decode("ascii", "replace").strip()
                child = f"{path}/{name}"
                child_chain = walk(first, child)
                if e[11] & 0x10:
                    pending.append((child_chain, child))
    return problems


def check_hive(part_path):
    """Valid magic => must parse (kernel/cm/hive.c: magic is written LAST)."""
    with open(part_path, "rb") as f:
        try:
            vol = FatImage(f, 0)
            found = vol.find_entry("windows/system32/config/SYSTEM")
        except Exception:
            return None  # structure problems are check_structure's business
        if found is None:
            return None
        _, first, size = found
        if size < 16 or first == 0:
            return None
        data = b"".join(vol.read_cluster(c) for c in vol.chain(first))
        data = data[:size].ljust(size, b"\0")  # short chains read as zeros
        if struct.unpack_from("<I", data, 0)[0] != 0x31564850:  # "PHV1"
            return None  # torn (magic still 0/garbage): falls back to empty
        try:
            parse_phv1(data)
        except Exception as e:
            return f"hive has a valid magic but fails to parse: {e}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pristine", required=True)
    ap.add_argument("--final", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--stride", type=int, default=int(os.environ.get("TORN_STRIDE", "1")))
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    sectorsize, entries = read_log(args.log)
    workdir = args.workdir or os.path.dirname(os.path.abspath(args.log))
    work = os.path.join(workdir, "tornreplay-part.img")

    # Range-validate every entry up front.
    for n, (sector, nr_sectors, flags, data) in enumerate(entries):
        if flags != 0:
            print(f"[KTEST] tornwrite FAIL entry={n} reason=unexpected-flags-{flags:#x}")
            return 1
        in_part = sector >= PART_LBA
        in_scratch = SCRATCH_LBA <= sector and sector + nr_sectors <= SCRATCH_END
        if not in_part and not in_scratch:
            print(f"[KTEST] tornwrite FAIL entry={n} lba={sector} reason=write-outside-volume")
            return 1

    # The pristine partition as the working state.
    with open(args.pristine, "rb") as f:
        f.seek(ESP_OFF)
        blob = f.read()
    with open(work, "wb") as f:
        f.write(blob)

    problems = check_structure(work)
    if problems:
        print(f"[KTEST] tornwrite FAIL prefix=0 reason={problems[0]}")
        return 1

    checked = 0
    with open(work, "r+b") as wf:
        for n, (sector, nr_sectors, flags, data) in enumerate(entries, 1):
            if sector >= PART_LBA:
                wf.seek((sector - PART_LBA) * sectorsize)
                wf.write(data)
                wf.flush()
            if n % args.stride != 0 and n != len(entries):
                continue
            problems = check_structure(work)
            hive_problem = check_hive(work)
            if hive_problem:
                problems.append(hive_problem)
            if problems:
                lba = sector
                print(f"[KTEST] tornwrite FAIL prefix={n} lba={lba} reason={problems[0]}")
                return 1
            checked += 1

    # Completeness bracket: the fully-replayed partition must equal the
    # booted image's partition byte-for-byte.
    with open(args.final, "rb") as f:
        f.seek(ESP_OFF)
        final_blob = f.read()
    with open(work, "rb") as f:
        work_blob = f.read()
    if work_blob != final_blob:
        diff = next(i for i in range(min(len(work_blob), len(final_blob)))
                    if work_blob[i] != final_blob[i])
        print(f"[KTEST] tornwrite FAIL reason=replay-mismatch-at-byte-{diff}")
        return 1

    print(f"[KTEST] tornwrite PASS entries={len(entries)} prefixes-checked={checked}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
