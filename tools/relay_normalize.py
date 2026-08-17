#!/usr/bin/env python3
"""relay_normalize.py — make Wine +relay traces diffable across machines.

Reads a log (proskrnl serial capture or an oracle stderr capture), keeps only
relay lines, and normalizes away everything that legitimately differs between
two correct runs so that `diff` shows only *semantic* divergence:

  - thread ids -> stable ordinals (t01, t02...) in order of first appearance;
  - the "ret=ADDR" return-address suffix -> dropped;
  - hex values < 0x10000 are KEPT verbatim (delays, flags, error codes,
    device counts — the observable answers the diff exists to compare);
  - larger hex values (pointers, handles, stack addresses — but also any
    absurd delay) -> ~2^N magnitude buckets: pointer jitter between the two
    machines diffs clean, while a 5-day uDelay (~2^29) against a 100 ms one
    (kept exact) still shows as a divergence.

Usage: relay_normalize.py LOG [LOG...]   (writes LOG.norm next to each input)
   or: relay_normalize.py -             (stdin -> stdout)

Built for the SAFlashPlayer freeze investigation (tests/flash/) but generic:
any +relay capture from the pinned Wine or from proskrnl's serial (the fork
routes __wine_dbg_write to NtDisplayString) normalizes the same way.
"""
import re
import sys

RELAY_RE = re.compile(r"^([0-9a-f]{4}):(Call|Ret|CALL|RET)\s+(.*)$")
ADDR_RE = re.compile(r"\b[0-9a-f]{5,16}\b")
RETADDR_RE = re.compile(r"\s+ret=[0-9a-f]+")


def normalize(lines):
    tids = {}
    out = []
    for line in lines:
        line = line.rstrip("\r\n")
        m = RELAY_RE.match(line)
        if not m:
            continue
        tid, kind, rest = m.groups()
        ordinal = tids.setdefault(tid, f"t{len(tids) + 1:02d}")
        rest = RETADDR_RE.sub("", rest)
        rest = ADDR_RE.sub(
            lambda m: (m.group(0) if int(m.group(0), 16) < 0x10000
                       else f"~2^{int(m.group(0), 16).bit_length()}"), rest)
        out.append(f"{ordinal}:{kind} {rest}")
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if sys.argv[1] == "-":
        sys.stdout.write("\n".join(normalize(sys.stdin)) + "\n")
        return
    for path in sys.argv[1:]:
        with open(path, errors="replace") as f:
            result = normalize(f)
        with open(path + ".norm", "w") as f:
            f.write("\n".join(result) + "\n")
        print(f"{path}.norm: {len(result)} relay lines")


if __name__ == "__main__":
    main()
