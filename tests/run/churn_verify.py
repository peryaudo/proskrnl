#!/usr/bin/env python3
"""churn_verify.py -- host-side conviction for the FS churn stress (docs/08).

Parses the [CHURN] shadow dump off a boot's serial log and diffs it against
the mcopy-extracted C:\\churn tree: exact path set (case-sensitive -- every
churn name is an LFN, so case round-trips), sizes, and zlib.crc32 content
checksums (the kernel side computes the same reflected-0xEDB88320 CRC from
its model). The extraction reads the volume through mtools -- an
implementation the kernel has never met -- so agreement here closes the
triangle: page cache == shadow model == on-disk bytes as mtools decodes
them.

Usage: churn_verify.py --log <serial.log> --extracted <dir>
"""

import argparse
import os
import sys
import zlib


def parse_dump(log_path):
    files = {}   # rel path under churn/ -> (size, crc)
    dirs = set()
    in_dump = False
    with open(log_path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("[CHURN] BEGIN"):
                in_dump = True
                files.clear()
                dirs.clear()  # keep only the LAST dump in the log
                continue
            if not in_dump:
                continue
            if line.startswith("[CHURN] END"):
                in_dump = False
                continue
            if line.startswith("[CHURN] D "):
                dirs.add(line[10:].split("/", 1)[1])
            elif line.startswith("[CHURN] F "):
                body = line[10:]
                path, size, crc = body.rsplit(" ", 2)
                files[path.split("/", 1)[1]] = (int(size), int(crc, 16))
    return files, dirs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--extracted", required=True)
    args = ap.parse_args()

    files, dirs = parse_dump(args.log)
    if not files and not dirs:
        print("churn_verify: no [CHURN] dump in the log")
        return 1

    found_files = {}
    found_dirs = set()
    for root, ds, fs in os.walk(args.extracted):
        rel = os.path.relpath(root, args.extracted)
        rel = "" if rel == "." else rel.replace(os.sep, "/")
        for d in ds:
            found_dirs.add((rel + "/" if rel else "") + d)
        for name in fs:
            found_files[(rel + "/" if rel else "") + name] = os.path.join(root, name)

    fails = 0
    for path, (size, crc) in sorted(files.items()):
        if path not in found_files:
            print(f"churn_verify: FAIL missing: {path}")
            fails += 1
            continue
        with open(found_files[path], "rb") as f:
            data = f.read()
        if len(data) != size:
            print(f"churn_verify: FAIL size {len(data)} != {size}: {path}")
            fails += 1
        elif zlib.crc32(data) != crc:
            print(f"churn_verify: FAIL crc {zlib.crc32(data):08x} != {crc:08x}: {path}")
            fails += 1
    for path in sorted(set(found_files) - set(files)):
        print(f"churn_verify: FAIL unexpected file: {path}")
        fails += 1
    for path in sorted(found_dirs - dirs):
        print(f"churn_verify: FAIL unexpected directory: {path}")
        fails += 1
    for path in sorted(dirs - found_dirs):
        print(f"churn_verify: FAIL missing directory: {path}")
        fails += 1

    print(f"churn_verify: {len(files)} files, {fails} failing")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
