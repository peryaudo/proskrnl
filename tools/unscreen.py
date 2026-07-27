#!/usr/bin/env python3
# unscreen.py — recover a console program's text from the serial screen diff.
#
# HACK-004's serial console is a SCREEN, not a stream: conhost renders into an
# 80-column screen buffer and the serial backend emits the DIFF (cursor moves,
# erases, the changed cells) rather than the characters a program printed. A
# grep for a test's own output on the raw serial log therefore finds text
# shredded into fragments — which is exactly what the guiwtest gate reads
# (docs/03 "GUI-5 winetest notes": the leg takes its VERDICT from the kernel's
# own line for that reason, but the per-assertion text is what a human needs to
# know WHICH assertion failed, and it was only reachable by eye).
#
# This filter replays the diff back into text. It is deliberately not a
# terminal emulator: the two sequences that carry content are
#
#   CSI <n> C   cursor forward — the diff's way of saying "n unchanged cells",
#               which for a freshly-written line means n spaces;
#   CSI K       erase to end of line — nothing to print.
#
# Everything else (the cursor-visibility bracketing conhost wraps every write
# in, colour, positioning) is dropped, and the remaining printable runs are
# the program's own characters in order.
#
#   unscreen.py < build/tests/guiwtest-serial.log > readable.log
#   unscreen.py --grep 'Test failed' serial.log
#
# The reconstruction is best-effort by construction — a repaint that rewrites
# an earlier cell replays as text in the order the console redrew it, and a
# line the screen wrapped at column 80 arrives as two. Nothing machine-read
# depends on it: every verdict in the tree comes from a [KTEST] line the kernel
# prints straight to serial, never through the console.

import argparse
import re
import sys

# ECMA-48 CSI: ESC '[' <params> <final>. Only 'C' (CUF) carries content.
CSI_RE = re.compile(r"\x1b\[([0-9;?]*)([@-~])")
# Any other two-byte escape (ESC 7, ESC =, ...) carries none.
ESC_RE = re.compile(r"\x1b.")


def replay(text):
    def one(match):
        params, final = match.group(1), match.group(2)
        if final == "C":  # cursor forward over cells the diff left alone
            return " " * (int(params) if params.isdigit() else 1)
        return ""

    return ESC_RE.sub("", CSI_RE.sub(one, text))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", help="serial log (default: stdin)")
    parser.add_argument("--grep", help="print only lines matching this regex")
    args = parser.parse_args()

    raw = open(args.log, "rb").read() if args.log else sys.stdin.buffer.read()
    # latin-1: the log is bytes, and a non-UTF-8 cell must not abort the pass.
    lines = replay(raw.decode("latin-1")).replace("\r", "\n").split("\n")
    pattern = re.compile(args.grep) if args.grep else None
    try:
        for line in lines:
            if pattern is None or pattern.search(line):
                print(line)
    except BrokenPipeError:  # piped into head/grep -m: not an error
        sys.stderr.close()


if __name__ == "__main__":
    main()
