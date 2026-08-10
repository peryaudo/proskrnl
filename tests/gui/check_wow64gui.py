#!/usr/bin/env python3
"""check_wow64gui.py — the WOW64 GUI verdict (docs/02 WOW64 + docs/07).

    check_wow64gui.py --log <serial.log> --before <before.ppm> --after <after.ppm>

A 32-bit .exe, typed at the windowed console, put a window on the desktop.
Three things have to hold together, and each is checked against what the
GUEST declared on serial rather than against a number written here:

  bitness   the client reported wow64=1 ptrsize=4. The first half is the
            KERNEL's answer (ProcessWow64Information), the second the
            compiler's — a 64-bit build of the same source fails both, so
            the leg cannot pass by running the wrong binary.
  geometry  the driver flushed a window whose rectangle is the one the
            client asked for. That flush is the 64-bit half of the path
            (win32u -> winefb.drv) reporting what the 32-bit half asked
            for through wow64win.
  pixels    QEMU's screendump has the client's OWN fill inside that
            rectangle, and did NOT have it before the client ran. The
            before/after pair is what makes the colour evidence rather
            than coincidence: nothing else on this desktop paints it.

Same discipline as check_gui3/4/5: no golden image, every expectation read
out of the log, and the pixels come back through QEMU's own device model
so the kernel is not grading its own homework (Art. 6).
"""
import argparse
import re
import sys

from check_gui4 import Dump, close

READY = re.compile(
    r"\[KTEST\] wow64gui ready "
    r"rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+) color=(?P<color>[0-9a-f]{6})"
)
WOW64 = re.compile(r"\[KTEST\] wow64gui wow64=(?P<wow64>\d+) ptrsize=(?P<ptrsize>\d+)")
PAINTED = re.compile(r"\[KTEST\] wow64gui painted")
FLUSH = re.compile(
    r"\[KTEST\] gui2 window rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+) flush=\d+"
)
# The client parks in its message loop and never reaches ntapi_finish, so
# there is no [KTEST] <name> PASS line to grep — its own assertions announce
# themselves the other way the harness has, by file:line.
CLIENT_ASSERT = re.compile(r"\[ASSERT\] [^\n]*wow64gui\.c:\d+[^\n]*")

# A solid fill, so the floor is high; the frame is borderless (WS_POPUP), so
# the whole rectangle is the client area.
MIN_DOMINANT = 0.95
# Before the client ran, its colour must be essentially absent. Not zero:
# the desktop carries a console window full of antialiased glyphs, and a
# lone stray pixel is not what this is looking for — a painted 360x240 block
# is 86400 of them.
MAX_BEFORE = 0.01


def parse_last(pattern, text, what, path):
    match = None
    for match in pattern.finditer(text):
        pass
    if match is None:
        sys.exit(f"check_wow64gui: no '{what}' marker in {path}")
    return match.groupdict()


def fraction(dump, rect, colour):
    census = dump.census(*rect)
    area = sum(census.values())
    if not area:
        return 0.0, 0, 0
    matching = sum(count for pixel, count in census.items() if close(pixel, colour))
    return matching / area, matching, area


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    args = parser.parse_args()

    with open(args.log, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")

    failures = []

    bitness = parse_last(WOW64, text, "wow64gui wow64=", args.log)
    if bitness["wow64"] != "1":
        failures.append(
            "the client is not a WOW64 process: ProcessWow64Information reported 0"
        )
    if bitness["ptrsize"] != "4":
        failures.append(f"the client is not 32-bit: sizeof(void *) is {bitness['ptrsize']}")
    if not PAINTED.search(text):
        failures.append("the client never reached WM_PAINT")
    for failed in CLIENT_ASSERT.findall(text):
        failures.append(f"the client's own assertion failed: {failed.strip()}")

    ready = parse_last(READY, text, "wow64gui ready", args.log)
    x, y = int(ready["x"]), int(ready["y"])
    w, h = int(ready["w"]), int(ready["h"])
    colour = tuple(int(ready["color"][i : i + 2], 16) for i in (0, 2, 4))
    rect = (x, y, x + w, y + h)

    # The driver's flush of exactly that rectangle: the 64-bit half saying
    # out loud what the 32-bit half asked for.
    if not any(
        (int(m["x"]), int(m["y"]), int(m["w"]), int(m["h"])) == (x, y, w, h)
        for m in (m.groupdict() for m in FLUSH.finditer(text))
    ):
        failures.append(f"no window flush at the client's rectangle {x},{y},{w}x{h}")

    before = Dump(args.before)
    after = Dump(args.after)
    for dump in (before, after):
        if rect[2] > dump.width or rect[3] > dump.height:
            sys.exit(f"check_wow64gui: {rect} does not fit {dump.path} ({dump.width}x{dump.height})")

    share, matching, area = fraction(after, rect, colour)
    if share < MIN_DOMINANT:
        failures.append(
            f"only {matching}/{area} pixels are {colour} in {rect} of {after.path} "
            f"(want at least {MIN_DOMINANT:.0%})"
        )
    share, matching, area = fraction(before, rect, colour)
    if share > MAX_BEFORE:
        failures.append(
            f"{matching}/{area} pixels were already {colour} in {rect} of {before.path} "
            f"before the client ran"
        )

    if failures:
        for failure in failures:
            print(f"check_wow64gui: {failure}", file=sys.stderr)
        return 1
    print(f"check_wow64gui: OK (32-bit window {w}x{h} at {x},{y}, fill {colour})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
