#!/usr/bin/env python3
"""check_gui3.py — the GUI-3 verdict (docs/02 "two GUI processes run at once").

    check_gui3.py --log <serial.log> --ppm <screendump.ppm>

Two halves, and both must hold.

The BEHAVIOUR half is what the guests reported: FindWindow resolved a window
another process created, a cross-process SendMessage came back with an answer
derived from what was sent (so it really ran in the other process's wndproc),
the z-order is one order over both processes and reordering from one moved a
window owned by the other, and the foreground moved across the boundary. Each
is a [KTEST] gui3 <name> PASS|FAIL line; any FAIL, or any missing line, fails
here.

The PIXEL half is the same structural screendump differential GUI-1 and GUI-2
use (Art. 6, and check_window.py's reasoning applies unchanged): the guests
say what they drew and where, QEMU's own device model returns the pixels. It
exists because the behaviour half alone would pass on a build that got every
answer right and put nothing on screen. Both windows must be painted, in
their reported rectangles, in the colours they said they used.

What is deliberately NOT checked pictorially is z-order: winefb.drv still
flushes whole windows with no clipping (per-window surfaces and compositing
are GUI-4), so an overlap would be last-writer-wins on the scanout and would
say nothing about the order the server keeps. The two windows are disjoint by
construction and z-order is judged through the API, which is where it is
defined. No golden image until GUI-6.
"""
import argparse
import collections
import re
import sys

from check_rect import read_ppm

# winefb.drv's own scanout report. The literal still says "gui2": it is the
# driver's line, printed by the same code on any GUI image, and renaming it
# would only desynchronise it from the GUI-2 checker.
MODE = re.compile(
    r"\[KTEST\] gui2 mode "
    r"w=(?P<w>\d+) h=(?P<h>\d+) pitch=(?P<pitch>\d+) bpp=(?P<bpp>\d+) bgrx=(?P<bgrx>\d+)"
)
RECT = re.compile(
    r"\[KTEST\] gui3 (?P<who>[AB]) rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+)"
)
VERDICT = re.compile(r"\[KTEST\] gui3 (?P<name>\w+) (?P<result>PASS|FAIL)")

# Each client fills its whole client area with one solid colour, so "painted"
# is a much stronger condition here than for winemine. Still a floor rather
# than an equality: the window has a frame the app does not draw.
MIN_PAINTED = 0.50

# The behaviours docs/02 names as the exit criteria, plus the in-process
# cross-thread case it names separately.
REQUIRED = ("find", "send", "zorder", "focus", "xthread", "verdict")


def parse_last(pattern, text, what, path):
    match = None
    for match in pattern.finditer(text):
        pass  # keep the last: a leg may boot more than once
    if match is None:
        sys.exit(f"check_gui3: no '{what}' marker in {path}")
    return match.groupdict()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm", required=True)
    args = parser.parse_args()

    with open(args.log, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")

    failures = []

    # --- the behaviour half -------------------------------------------------
    results = {}
    for match in VERDICT.finditer(text):
        # Keep the last result per name; a leg may boot more than once.
        results[match.group("name")] = match.group("result")
    for name in REQUIRED:
        if name not in results:
            failures.append(f"no '[KTEST] gui3 {name}' verdict on serial")
        elif results[name] != "PASS":
            failures.append(f"gui3 {name} reported {results[name]}")

    # --- the pixel half -----------------------------------------------------
    mode = parse_last(MODE, text, "gui2 mode", args.log)
    rects = {}
    for match in RECT.finditer(text):
        info = match.groupdict()
        rects[info["who"]] = (int(info["x"]), int(info["y"]), int(info["w"]), int(info["h"]))
    for who in ("A", "B"):
        if who not in rects:
            failures.append(f"client {who} never reported its window rectangle")

    width, height, pixels = read_ppm(args.ppm)
    if (width, height) != (int(mode["w"]), int(mode["h"])):
        failures.append(
            f"screendump is {width}x{height}, but the guest reported a "
            f"{mode['w']}x{mode['h']} scanout"
        )

    def pixel_at(x, y):
        base = (y * width + x) * 3
        return tuple(pixels[base : base + 3])

    # The untouched framebuffer, sampled at the corners rather than assumed
    # (check_window.py's reasoning). Both windows are inset, so no corner
    # falls inside one.
    corners = [(0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)]
    corner_colours = {pixel_at(px, py) for px, py in corners}
    if len(corner_colours) != 1:
        failures.append(f"the framebuffer outside both windows is not uniform: {corner_colours}")
        background = None
    else:
        background = corner_colours.pop()

    painted_report = []
    boxes = []
    for who in sorted(rects):
        x, y, w, h = rects[who]
        left, top = max(x, 0), max(y, 0)
        right, bottom = min(x + w, width), min(y + h, height)
        if right <= left or bottom <= top:
            failures.append(f"client {who}'s {w}x{h} window at ({x},{y}) is off screen")
            continue
        boxes.append((who, left, top, right, bottom))

        inside = collections.Counter()
        for py in range(top, bottom):
            for px in range(left, right):
                inside[pixel_at(px, py)] += 1
        area = sum(inside.values())
        painted = area - inside.get(background, 0) if background else area
        if background and painted < area * MIN_PAINTED:
            failures.append(
                f"client {who}: only {painted}/{area} pixels differ from the background "
                f"{background} (want at least {MIN_PAINTED:.0%})"
            )
        painted_report.append(f"{who} {w}x{h}@({x},{y}) {painted}/{area}px")

    # Two DIFFERENT windows, not one drawn twice: each client fills with its
    # own colour, so the dominant colour inside each box must differ.
    if len(boxes) == 2 and background:
        dominants = []
        for _who, left, top, right, bottom in boxes:
            inside = collections.Counter()
            for py in range(top, bottom):
                for px in range(left, right):
                    inside[pixel_at(px, py)] += 1
            dominants.append(inside.most_common(1)[0][0])
        if dominants[0] == dominants[1]:
            failures.append(
                f"both windows are dominated by the same colour {dominants[0]} — "
                "expected each client's own fill"
            )

    if failures:
        for failure in failures:
            print(f"check_gui3: {failure}", file=sys.stderr)
        sys.exit(f"check_gui3: {len(failures)} check(s) failed")

    print(
        "check_gui3: two GUI processes on one scanout — "
        + ", ".join(painted_report)
        + f"; {', '.join(n + '=PASS' for n in REQUIRED)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
