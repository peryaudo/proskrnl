#!/usr/bin/env python3
"""check_gui6.py — the GUI-6 golden-image verdict (docs/02 "Desktop").

    check_gui6.py --golden tests/gui/golden/desktop.ppm --ppm <screendump.ppm>

The thing under test is a desktop someone drew — explorer's wallpaper
rectangle with its file window over it — so the verdict is the one the
earlier GUI checkers deliberately deferred to this milestone (their "No
golden image until GUI-6" notes): an EXACT byte compare against a blessed
frame. Everything that could vary was removed from the leg instead of
tolerated here: no pointer device is attached (no cursor overlay), the
scanout has one fixed mode, the fonts are the pinned tree's own, and the
run.sh leg polls until the frame settles, so a mismatch is a real change —
either a regression or a deliberate rebless (run.sh gui6 --bless).

On mismatch the differing-pixel count and bounding box are printed, which
locates the change (a moved window, a repaint hole, a font change) without
needing the picture.
"""
import argparse
import sys

from check_rect import read_ppm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", required=True, help="the blessed desktop.ppm")
    parser.add_argument("--ppm", required=True, help="QEMU screendump to grade")
    args = parser.parse_args()

    gw, gh, golden = read_ppm(args.golden)
    dw, dh, dump = read_ppm(args.ppm)

    if (gw, gh) != (dw, dh):
        sys.exit(f"check_gui6: size mismatch: golden {gw}x{gh}, dump {dw}x{dh} "
                 "(scanout mode changed? the golden pins 1280x800)")

    golden = golden[:gw * gh * 3]  # read_ppm tolerates trailing bytes
    dump = dump[:gw * gh * 3]

    if golden == dump:
        print(f"check_gui6: exact match ({gw}x{gh})")
        return

    # Locate the difference for the log.
    diff = 0
    min_x = min_y = 1 << 30
    max_x = max_y = -1
    for y in range(gh):
        row = y * gw * 3
        if golden[row:row + gw * 3] == dump[row:row + gw * 3]:
            continue
        for x in range(gw):
            p = row + x * 3
            if golden[p:p + 3] != dump[p:p + 3]:
                diff += 1
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)
    sys.exit(f"check_gui6: {diff} differing pixel(s), bbox "
             f"{min_x},{min_y}..{max_x},{max_y} (golden {args.golden}, dump {args.ppm})")


if __name__ == "__main__":
    main()
