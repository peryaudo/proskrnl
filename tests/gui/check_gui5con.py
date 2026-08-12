#!/usr/bin/env python3
"""check_gui5con.py — the windowed-conhost verdict's pixel half (GUI-5).

    check_gui5con.py --locate --log <serial.log> --ppm <dump.ppm>
    check_gui5con.py --log <serial.log> --ppm1 <before.ppm> --ppm2 <after.ppm> \
                     --bbox X,Y,WxH

Two modes.

--locate is the leg's readiness poll: no guest process on this image prints
a window rectangle (conhost is stock Wine code), so the console window is
FOUND rather than declared — the bounding box of every pixel that differs
from the desktop background winefb.drv reported ([KTEST] gui2 desktop ...
bg=RRGGBB). A real console window is big (80x25 cells plus frame), holds
more than two colours (frame, client background, prompt glyphs), and is
mostly non-background inside its box; a boot still painting fails all
three, and the leg polls again. On success one line goes to stdout:
`bbox=X,Y,WxH center=CX,CY` — the click target. The pointer must not have
entered the scanout yet (the leg clicks only after locating), so the
software cursor cannot smear the box.

The final mode grades the session's pixels: the window from --locate is
still painted in the after dump, its title band and client area differ
(a caption really is drawn), and the pixels that CHANGED between the two
dumps — the typed command lines and their output advancing the screen —
lie inside the located box (plus the cursor's parking spot, which the
harness placed inside the window by clicking it). Changes outside the box
mean a window moved or repainted where nothing should have; zero changes
mean the typing never reached the screen. The FILE half of the verdict
(out.txt / ctrl.txt extracted from the image) lives in run.sh — pixels
prove the window, files prove the console plumbing behind it.

Explorer-bearing images (GUI-6 onward) add desktop furniture the window
under test does not own: the taskbar, an edge-to-edge band along the
bottom whose buttons repaint on focus changes. No window this leg creates
is ever scanout-wide, so any row whose non-background span reaches both
edges is furniture — excluded from the locate search and from the
outside-the-box change budget. Explorerless images paint no such rows and
are graded exactly as before.
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
DESKTOP = re.compile(r"\[KTEST\] gui2 desktop w=\d+ h=\d+ bg=(?P<bg>[0-9a-fA-F]{6})")

MIN_W, MIN_H = 300, 180   # far below a real 80x25 console, far above noise
TOL = 8                   # per-channel: the scanout may dither


def parse_marker(pattern, text, what):
    match = None
    for match in pattern.finditer(text):
        pass
    if match is None:
        sys.exit(f"check_gui5con: no '{what}' marker on serial")
    return match.groupdict()


def load(log_path):
    with open(log_path, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")
    mode = parse_marker(MODE, text, "gui2 mode")
    desktop = parse_marker(DESKTOP, text, "gui2 desktop")
    bg = tuple(int(desktop["bg"][i : i + 2], 16) for i in (0, 2, 4))
    return int(mode["w"]), int(mode["h"]), bg


def differs(pixels, width, x, y, colour):
    base = (y * width + x) * 3
    return any(abs(pixels[base + i] - colour[i]) > TOL for i in range(3))


def furniture_rows(pixels, width, height, bg):
    """Rows owned by desktop furniture (the taskbar), not by any window.

    A furniture row's non-background pixels span the scanout edge to edge;
    a window's never do (the leg's windows are far narrower than the mode).
    """
    rows = set()
    for y in range(height):
        row = y * width * 3
        left = right = None
        for x in range(width):
            base = row + x * 3
            if (
                abs(pixels[base] - bg[0]) > TOL
                or abs(pixels[base + 1] - bg[1]) > TOL
                or abs(pixels[base + 2] - bg[2]) > TOL
            ):
                if left is None:
                    left = x
                right = x
        if left is not None and right - left + 1 >= width - 4:
            rows.add(y)
    return rows


def bounding_box(pixels, width, height, bg, skip_rows=frozenset()):
    left, top, right, bottom = width, height, -1, -1
    for y in range(height):
        if y in skip_rows:
            continue
        row = y * width * 3
        for x in range(width):
            base = row + x * 3
            if (
                abs(pixels[base] - bg[0]) > TOL
                or abs(pixels[base + 1] - bg[1]) > TOL
                or abs(pixels[base + 2] - bg[2]) > TOL
            ):
                if x < left:
                    left = x
                if x > right:
                    right = x
                if y < top:
                    top = y
                if y > bottom:
                    bottom = y
    if right < 0:
        return None
    return left, top, right - left + 1, bottom - top + 1


def box_colours(pixels, width, box):
    x, y, w, h = box
    inside = collections.Counter()
    for py in range(y, y + h):
        row = py * width * 3
        for px in range(x, x + w):
            base = row + px * 3
            inside[(pixels[base], pixels[base + 1], pixels[base + 2])] += 1
    return inside


def locate(args):
    width, height, bg = load(args.log)
    pw, ph, pixels = read_ppm(args.ppm)
    if (pw, ph) != (width, height):
        sys.exit(f"check_gui5con: dump is {pw}x{ph}, guest reported {width}x{height}")

    furniture = furniture_rows(pixels, width, height, bg)
    box = bounding_box(pixels, width, height, bg, furniture)
    if box is None:
        print("check_gui5con: scanout is all desktop background", file=sys.stderr)
        return 1
    x, y, w, h = box
    if w < MIN_W or h < MIN_H:
        print(f"check_gui5con: non-background box {w}x{h} too small for a console",
              file=sys.stderr)
        return 1

    inside = box_colours(pixels, width, box)
    area = sum(inside.values())
    non_bg = area - inside.get(bg, 0)
    if non_bg < area * 0.5:
        print("check_gui5con: box is mostly desktop background — not one window",
              file=sys.stderr)
        return 1
    rich = [c for c, n in inside.items() if c != bg and n >= 20]
    if len(rich) < 3:
        print(f"check_gui5con: only {len(rich)} colours in the box — no frame+text yet",
              file=sys.stderr)
        return 1

    print(f"bbox={x},{y},{w}x{h} center={x + w // 2},{y + h // 2}")
    return 0


def final(args):
    width, height, bg = load(args.log)
    match = re.fullmatch(r"(-?\d+),(-?\d+),(\d+)x(\d+)", args.bbox)
    if not match:
        sys.exit("check_gui5con: --bbox must be X,Y,WxH")
    bx, by, bw, bh = (int(g) for g in match.groups())

    failures = []
    dumps = []
    for path in (args.ppm1, args.ppm2):
        pw, ph, pixels = read_ppm(path)
        if (pw, ph) != (width, height):
            sys.exit(f"check_gui5con: {path} is {pw}x{ph}, guest reported {width}x{height}")
        dumps.append(pixels)
    before, after = dumps

    # The window is still painted where it was located.
    inside = box_colours(after, width, (bx, by, bw, bh))
    area = sum(inside.values())
    if area - inside.get(bg, 0) < area * 0.5:
        failures.append("the console window is gone from its located box")

    # A caption really is drawn: the title band's dominant colour differs
    # from the client area's (sampled well inside each).
    band = box_colours(after, width, (bx + 4, by + 2, max(bw - 8, 1), 12))
    client = box_colours(after, width, (bx + bw // 4, by + bh // 3, bw // 2, bh // 3))
    if band and client and band.most_common(1)[0][0] == client.most_common(1)[0][0]:
        failures.append("title band and client area share a dominant colour — no caption")

    # The typing advanced the screen, and only inside the window. Taskbar
    # rows are exempt: its buttons legitimately repaint when the click
    # between the dumps changes the foreground window.
    furniture = furniture_rows(before, width, height, bg) | furniture_rows(
        after, width, height, bg
    )
    changed_inside = changed_outside = 0
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
    if changed_inside == 0:
        failures.append("no pixel changed inside the console between the dumps")
    if changed_outside > 0:
        failures.append(
            f"{changed_outside} pixels changed OUTSIDE the console box between the dumps"
        )

    if failures:
        for failure in failures:
            print(f"check_gui5con: {failure}", file=sys.stderr)
        sys.exit(f"check_gui5con: {len(failures)} check(s) failed")

    print(
        f"check_gui5con: console window {bw}x{bh}@({bx},{by}) captioned, painted, "
        f"{changed_inside} pixels of session progress inside it, none outside"
    )
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--locate", action="store_true")
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm")
    parser.add_argument("--ppm1")
    parser.add_argument("--ppm2")
    parser.add_argument("--bbox")
    args = parser.parse_args()

    if args.locate:
        if not args.ppm:
            sys.exit("check_gui5con: --locate needs --ppm")
        return locate(args)
    if not (args.ppm1 and args.ppm2 and args.bbox):
        sys.exit("check_gui5con: final mode needs --ppm1 --ppm2 --bbox")
    return final(args)


if __name__ == "__main__":
    sys.exit(main())
