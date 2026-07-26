#!/usr/bin/env python3
"""check_window.py — the GUI-2 verdict (docs/02 "winemine.exe appears on screen").

    check_window.py --log <serial.log> --ppm <screendump.ppm>

Same differential as check_rect.py at GUI-1 (Art. 6): the guest says on
serial what it drew and where, and the pixels come back through QEMU's own
device model. Neither side is hardcoded, so a QEMU that picks a different
default resolution changes the numbers on both at once.

What "appears" means here has to be checked without knowing what winemine
looks like -- there is no golden image until GUI-6, and a byte-compared PPM
would break on any QEMU rendering change while saying nothing about the
kernel. So the test is structural rather than pictorial:

  * the screendump is the size winefb.drv reported the scanout to be;
  * the window rectangle winefb.drv reported is not blank -- a real share of
    its pixels differ from the untouched framebuffer around it, and there is
    more than one distinct colour in it (a window that failed to paint
    reaches the scanout as one flat fill);
  * the framebuffer OUTSIDE the window is untouched, which is what says the
    blit landed where the driver said it did rather than smeared.

That is enough to convict the whole path -- win32u's PE build, the
in-process desktop state, dibdrv, the surface flush, \\Device\\Fb0 -- while
staying silent about which pixels winemine happens to choose.
"""
import argparse
import collections
import re
import sys

from check_rect import read_ppm

MODE = re.compile(
    r"\[KTEST\] gui2 mode "
    r"w=(?P<w>\d+) h=(?P<h>\d+) pitch=(?P<pitch>\d+) bpp=(?P<bpp>\d+) bgrx=(?P<bgrx>\d+)"
)
WINDOW = re.compile(
    r"\[KTEST\] gui2 window "
    r"rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+) flush=(?P<flush>\d+)"
)

# A window has to differ from the untouched framebuffer over at least this
# share of its area before we call it painted. winemine's client area is a
# mine grid on COLOR_3DFACE plus a caption and a menu bar, so in practice
# essentially all of it differs; a tenth is a floor that a blank or
# half-drawn window cannot reach by accident.
MIN_PAINTED = 0.10


def parse_last(pattern, text, what, path):
    match = None
    for match in pattern.finditer(text):
        pass  # keep the last: a leg may boot more than once
    if match is None:
        sys.exit(f"check_window: no '{what}' marker in {path}")
    return match.groupdict()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm", required=True)
    args = parser.parse_args()

    with open(args.log, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")
    mode = parse_last(MODE, text, "gui2 mode", args.log)
    window = parse_last(WINDOW, text, "gui2 window", args.log)

    width, height, pixels = read_ppm(args.ppm)
    if (width, height) != (int(mode["w"]), int(mode["h"])):
        sys.exit(
            f"check_window: screendump is {width}x{height}, "
            f"but the guest reported a {mode['w']}x{mode['h']} scanout"
        )

    def pixel_at(x, y):
        base = (y * width + x) * 3
        return tuple(pixels[base : base + 3])

    x, y = int(window["x"]), int(window["y"])
    w, h = int(window["w"]), int(window["h"])
    left, top = max(x, 0), max(y, 0)
    right, bottom = min(x + w, width), min(y + h, height)
    if right <= left or bottom <= top:
        sys.exit(
            f"check_window: the reported window {w}x{h} at ({x},{y}) "
            f"is entirely off a {width}x{height} screen"
        )

    # The untouched framebuffer: whatever the kernel left there. Sampled at
    # the four corners rather than assumed, so this stays true if the boot
    # ever paints a background of its own.
    corners = [(0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)]
    corner_colours = {pixel_at(px, py) for px, py in corners
                      if not (left <= px < right and top <= py < bottom)}
    if len(corner_colours) != 1:
        sys.exit(f"check_window: the framebuffer outside the window is not uniform: {corner_colours}")
    background = corner_colours.pop()

    inside = collections.Counter()
    for py in range(top, bottom):
        for px in range(left, right):
            inside[pixel_at(px, py)] += 1
    area = sum(inside.values())
    painted = area - inside.get(background, 0)

    failures = []
    if painted < area * MIN_PAINTED:
        failures.append(
            f"only {painted}/{area} pixels in the window differ from the background "
            f"{background} (want at least {MIN_PAINTED:.0%})"
        )
    if len(inside) < 2:
        failures.append(f"the window is one flat colour {next(iter(inside))}")

    # Just outside each edge the framebuffer must still be untouched: that
    # is what proves the blit went where pWindowPosChanged said it would.
    outside = [(left - 1, top), (right, top), (left, top - 1), (left, bottom)]
    for px, py in outside:
        if not (0 <= px < width and 0 <= py < height):
            continue
        got = pixel_at(px, py)
        if got != background:
            failures.append(f"({px},{py}) just outside the window is {got}, expected {background}")

    if failures:
        for failure in failures:
            print(f"check_window: {failure}", file=sys.stderr)
        sys.exit(f"check_window: {len(failures)} check(s) failed")

    print(
        f"check_window: a {w}x{h} window at ({x},{y}) is painted "
        f"({painted}/{area} pixels, {len(inside)} colours) in a {width}x{height} screendump"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
