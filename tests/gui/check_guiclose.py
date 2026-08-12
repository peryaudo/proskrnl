#!/usr/bin/env python3
"""check_guiclose.py — the guiclose verdict (the vacate repair: a closed
window's pixels leave the screen).

    check_guiclose.py --log <serial.log> --ppm1 <before.ppm> --ppm2 <after.ppm> \\
                      --bbox X,Y,WxH

The leg (tests/run/run.sh guiclose) took ppm1 with only the console showing,
then started winemine from the prompt, dragged it so it straddled the
console's edge and the empty desktop, and closed it with its close button;
ppm2 is the settled frame afterwards, with the cursor parked back on ppm1's
spot. The claim under test is the compositor's exposure contract: everything
the closed window covered is repainted by its owners — the console repaints
its share, the desktop share is background again (docs/03 GUI-4 notes,
"exposure"). Before the hide-time repair existed, exactly this scenario left
the dead window's pixels on the scanout forever (the surface-destroy
callback it relied on never fires; blit.c winefb_surface_destroy names why).

So the verdict is a difference discipline, not a golden: every pixel that
differs between ppm1 and ppm2 must lie inside the console's box (the typed
command and the new prompt legitimately changed it) or on a furniture row
(the taskbar's buttons come and go with the session — check_gui5con's
definition, imported from there). One differing pixel anywhere else is a
remnant of the closed window — the afterimage — and fails the leg. The
console box must also show SOME change: a session that never typed proves
nothing.

check_gui5con's reasoning about the pixel source applies: QEMU's own device
model returns the dumps (Art. 6), and the geometry comes from what the guest
reported, never from assumptions.
"""
import argparse
import re
import sys

from check_gui5con import furniture_rows, load
from check_rect import read_ppm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm1", required=True)
    parser.add_argument("--ppm2", required=True)
    parser.add_argument("--bbox", required=True)
    args = parser.parse_args()

    width, height, bg = load(args.log)
    match = re.fullmatch(r"(-?\d+),(-?\d+),(\d+)x(\d+)", args.bbox)
    if not match:
        sys.exit("check_guiclose: --bbox must be X,Y,WxH")
    bx, by, bw, bh = (int(g) for g in match.groups())

    dumps = []
    for path in (args.ppm1, args.ppm2):
        pw, ph, pixels = read_ppm(path)
        if (pw, ph) != (width, height):
            sys.exit(f"check_guiclose: {path} is {pw}x{ph}, guest reported {width}x{height}")
        dumps.append(pixels)
    before, after = dumps

    furniture = furniture_rows(before, width, height, bg) | furniture_rows(
        after, width, height, bg
    )
    changed_inside = changed_outside = 0
    out_box = [width, height, -1, -1]
    for y in range(height):
        if y in furniture:
            continue
        row = y * width * 3
        for x in range(width):
            base = row + x * 3
            if before[base : base + 3] != after[base : base + 3]:
                if bx <= x < bx + bw and by <= y < by + bh:
                    changed_inside += 1
                else:
                    changed_outside += 1
                    out_box[0] = min(out_box[0], x)
                    out_box[1] = min(out_box[1], y)
                    out_box[2] = max(out_box[2], x)
                    out_box[3] = max(out_box[3], y)

    failures = []
    if changed_inside == 0:
        failures.append("no pixel changed inside the console — the session never typed")
    if changed_outside > 0:
        failures.append(
            f"{changed_outside} pixels differ OUTSIDE the console box "
            f"(bounding {out_box[0]},{out_box[1]}..{out_box[2]},{out_box[3]}) — "
            "the closed window left an afterimage"
        )

    if failures:
        for failure in failures:
            print(f"check_guiclose: {failure}", file=sys.stderr)
        sys.exit(f"check_guiclose: {len(failures)} check(s) failed")

    print(
        f"check_guiclose: closed window fully vacated; {changed_inside} pixels of "
        f"session progress inside the console, none outside"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
