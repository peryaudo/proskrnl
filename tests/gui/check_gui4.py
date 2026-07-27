#!/usr/bin/env python3
"""check_gui4.py — the GUI-4 verdict (docs/02 "windows can be grabbed and
moved; clicks reach the right window").

    check_gui4.py --log <serial.log> --ppm1 <before.ppm> --ppm2 <after.ppm> \\
                  --ppm3 <cursor-on-window.ppm> --park1 X,Y --park2 X,Y --park3 X,Y

Two halves, and both must hold (the check_gui3.py reasoning applies
unchanged; QEMU's own device model returns the pixels, Art. 6).

The BEHAVIOUR half is what the guests reported under harness-injected
input: B (the upper, captioned window) is above A in the z-order; a click
in the overlap reached B and never A; a click on A's exposed part reached
A and activated it; characters followed the focus (B's then A's); and the
caption drag ended with B reporting a moved window rectangle. The exact
drag delta is enforced by the leg itself (it awaits the marker carrying
the expected rectangle), so here the moved rectangle only has to exist and
be where the pixels say it is.

The PIXEL half is what GUI-3 deliberately could not check: the overlap.
Dump 1 (before the drag): B's fill wins inside the overlap (the compositor
clips A's flushes under B), A's fill shows on A's exposed part, the
desktop background — sampled against the colour the driver REPORTED, never
assumed — fills the corners, and the cursor's arrow sits parked at a known
background point. Dump 2 (after the drag): B's fill sits at its reported
NEW rectangle, A's full rectangle is A's fill again (the mover invalidated
what it uncovered, A repainted cross-process), the vacated strip is
background again, and the cursor sits at the second park point.

The cursor is graded past "it is drawn somewhere", because a scanout with
more than one writer is where a software cursor goes wrong:

- dump 2 additionally forbids FOREIGN pixels inside B's moved window rect.
  B is opaque over its whole rect and nothing is above it, so a pixel
  there wearing the desktop background or A's fill did not come from B --
  it is the cursor depositing pixels it captured somewhere else (the
  save-under stale patch). Neither client repaints itself to hide this any
  more: the drag ends, the cursor parks, and the picture is graded as it
  lands.
- dump 3 puts the cursor INSIDE B's client area and then makes B repaint
  under it. The arrow must still be there afterwards, with B's fill (not
  the desktop background) beside it: a flush that overlaps the cursor must
  not erase it, and must not leave a hole where it was.

No golden image until GUI-6; every check is structural, against what the
guest declared on serial.
"""
import argparse
import collections
import re
import sys

from check_rect import read_ppm

# The driver's own lines keep the "gui2" literal (check_gui3.py's note).
MODE = re.compile(
    r"\[KTEST\] gui2 mode "
    r"w=(?P<w>\d+) h=(?P<h>\d+) pitch=(?P<pitch>\d+) bpp=(?P<bpp>\d+) bgrx=(?P<bgrx>\d+)"
)
DESKTOP = re.compile(r"\[KTEST\] gui2 desktop w=\d+ h=\d+ bg=(?P<bg>[0-9a-f]{6})")
A_READY = re.compile(r"\[KTEST\] gui4 A ready rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+)")
B_READY = re.compile(
    r"\[KTEST\] gui4 B ready wrect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+) "
    r"crect=(?P<cx>-?\d+),(?P<cy>-?\d+),(?P<cw>\d+)x(?P<ch>\d+) "
    r"caption=(?P<capx>-?\d+),(?P<capy>-?\d+) ztop=(?P<ztop>PASS|FAIL)"
)
B_MOVED = re.compile(r"\[KTEST\] gui4 B moved rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+)")
CLICK = re.compile(r"\[KTEST\] gui4 (?P<who>[AB]) click (?P<x>-?\d+),(?P<y>-?\d+)")
CHAR = re.compile(r"\[KTEST\] gui4 (?P<who>[AB]) char=(?P<ch>[0-9a-f]+)")
A_ACTIVE = re.compile(r"\[KTEST\] gui4 A active")

# Solid fills, so strong floors: the client area of each window must be
# dominated by its own fill where it is exposed.
MIN_DOMINANT = 0.80
# Channel tolerance for sampled pixels: the scanout path is lossless on the
# bgrx layout every current image uses, but a repacked mode may round.
TOL = 8

# The clients' fills (tests/gui/gui4a.c / gui4b.c). Declared, not sampled:
# the point is that a specific window's OWN colour won, not merely that
# something was painted.
A_FILL = (0x20, 0x60, 0xC0)
B_FILL = (0xC0, 0x40, 0x20)
CURSOR_BLACK = (0x00, 0x00, 0x00)
CURSOR_WHITE = (0xFF, 0xFF, 0xFF)
# cursor.c's bitmap, so a park point's footprint can be excluded from a census.
CURSOR_W, CURSOR_H = 12, 20
# Slack for a themed window frame that happens to sample near a forbidden
# colour. A stale patch is a whole cursor footprint (240 px), so this floor
# separates the two by an order of magnitude on any window this leg makes.
MAX_FOREIGN = 0.001


def close(a, b, tol=TOL):
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def parse_last(pattern, text, what, path):
    match = None
    for match in pattern.finditer(text):
        pass
    if match is None:
        sys.exit(f"check_gui4: no '{what}' marker in {path}")
    return match.groupdict()


class Dump:
    def __init__(self, path):
        self.width, self.height, self.pixels = read_ppm(path)
        self.path = path

    def at(self, x, y):
        base = (y * self.width + x) * 3
        return tuple(self.pixels[base : base + 3])

    def census(self, left, top, right, bottom):
        left, top = max(left, 0), max(top, 0)
        right, bottom = min(right, self.width), min(bottom, self.height)
        counter = collections.Counter()
        for py in range(top, bottom):
            for px in range(left, right):
                counter[self.at(px, py)] += 1
        return counter


def rect_of(info, x="x", y="y", w="w", h="h"):
    return (int(info[x]), int(info[y]), int(info[x]) + int(info[w]), int(info[y]) + int(info[h]))


def intersect(a, b):
    r = (max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3]))
    return r if r[2] > r[0] and r[3] > r[1] else None


def dominant_check(failures, dump, rect, fill, what):
    census = dump.census(*rect)
    area = sum(census.values())
    if not area:
        failures.append(f"{what}: empty sample region {rect}")
        return
    matching = sum(count for colour, count in census.items() if close(colour, fill))
    if matching < area * MIN_DOMINANT:
        failures.append(
            f"{what}: only {matching}/{area} pixels are {fill} in {rect} of {dump.path} "
            f"(want at least {MIN_DOMINANT:.0%}; dominant is "
            f"{census.most_common(1)[0][0]})"
        )


def cursor_check(failures, dump, park, beneath, what):
    """The arrow is at `park`, and `beneath` (the desktop background, or a
    window's fill when the cursor is parked over one) is what shows beside
    it."""
    x, y = park
    hotspot = dump.at(x, y)
    fill = dump.at(x + 1, y + 3)  # inside the arrow's white fill (cursor.c's bitmap)
    beside = dump.at(x + 20, y)  # right of the 12px-wide arrow: what is under it again
    if not close(hotspot, CURSOR_BLACK):
        failures.append(f"{what}: no cursor outline at park point {park} (got {hotspot})")
    if not close(fill, CURSOR_WHITE):
        failures.append(f"{what}: no cursor fill at {(x + 1, y + 3)} (got {fill})")
    if not close(beside, beneath):
        failures.append(f"{what}: expected {beneath} beside the cursor at {(x + 20, y)}, got {beside}")


def foreign_pixel_check(failures, dump, rect, forbidden, parks, what):
    """No pixel inside `rect` may wear one of the `forbidden` colours.

    Used on a window that is opaque over its whole rect with nothing above
    it: a pixel there carrying a colour that belongs somewhere else on the
    screen was deposited by the cursor's save-under, not painted by the
    window. Park footprints are excluded -- the arrow itself is legitimately
    foreign-coloured (black and white) but its own colours are never in
    `forbidden`, and skipping the rects keeps that independent."""
    left, top = max(rect[0], 0), max(rect[1], 0)
    right, bottom = min(rect[2], dump.width), min(rect[3], dump.height)
    area = max((right - left) * (bottom - top), 0)
    if not area:
        failures.append(f"{what}: empty sample region {rect}")
        return

    found = collections.Counter()
    for py in range(top, bottom):
        for px in range(left, right):
            if any(p[0] <= px < p[0] + CURSOR_W and p[1] <= py < p[1] + CURSOR_H for p in parks):
                continue
            colour = dump.at(px, py)
            for name, value in forbidden:
                if close(colour, value):
                    found[name] += 1
    total = sum(found.values())
    if total > area * MAX_FOREIGN:
        failures.append(
            f"{what}: {total}/{area} pixels in {rect} of {dump.path} carry a colour from "
            f"elsewhere on the screen ({dict(found)}) -- the cursor deposited pixels it "
            f"captured before that area was repainted"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm1", required=True)
    parser.add_argument("--ppm2", required=True)
    parser.add_argument("--ppm3", required=True)
    parser.add_argument("--park1", required=True)
    parser.add_argument("--park2", required=True)
    parser.add_argument("--park3", required=True)
    args = parser.parse_args()

    with open(args.log, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")
    park1 = tuple(int(v) for v in args.park1.split(","))
    park2 = tuple(int(v) for v in args.park2.split(","))
    park3 = tuple(int(v) for v in args.park3.split(","))

    failures = []

    # --- markers ------------------------------------------------------------
    mode = parse_last(MODE, text, "gui2 mode", args.log)
    bg_hex = parse_last(DESKTOP, text, "gui2 desktop", args.log)["bg"]
    background = tuple(int(bg_hex[i : i + 2], 16) for i in (0, 2, 4))
    a_rect = rect_of(parse_last(A_READY, text, "gui4 A ready", args.log))
    b_info = parse_last(B_READY, text, "gui4 B ready", args.log)
    b_wrect = rect_of(b_info)
    b_crect = rect_of(b_info, "cx", "cy", "cw", "ch")
    b_moved = rect_of(parse_last(B_MOVED, text, "gui4 B moved", args.log))

    # --- the behaviour half -------------------------------------------------
    if b_info["ztop"] != "PASS":
        failures.append("B is not above A in the z-order (ztop=FAIL)")

    clicks = collections.defaultdict(list)
    for match in CLICK.finditer(text):
        clicks[match.group("who")].append((int(match.group("x")), int(match.group("y"))))
    chars = collections.defaultdict(set)
    for match in CHAR.finditer(text):
        chars[match.group("who")].add(int(match.group("ch"), 16))

    if not clicks["B"]:
        failures.append("no click ever reached B")
    if not clicks["A"]:
        failures.append("no click ever reached A")
    # The routing proof: nothing that lands where B covers A may reach A.
    for x, y in clicks["A"]:
        if b_wrect[0] <= x < b_wrect[2] and b_wrect[1] <= y < b_wrect[3]:
            failures.append(f"a click at ({x},{y}) inside B's rect leaked through to A")
    if 0x62 not in chars["B"]:
        failures.append("B never received char 'b' (focus did not start on B)")
    if 0x61 not in chars["A"]:
        failures.append("A never received char 'a' (focus did not follow the click)")
    if not A_ACTIVE.search(text):
        failures.append("A never reported activation after being clicked")

    # --- the pixel half -----------------------------------------------------
    dump1, dump2, dump3 = Dump(args.ppm1), Dump(args.ppm2), Dump(args.ppm3)
    for dump in (dump1, dump2, dump3):
        if (dump.width, dump.height) != (int(mode["w"]), int(mode["h"])):
            failures.append(
                f"{dump.path} is {dump.width}x{dump.height}, but the guest reported "
                f"a {mode['w']}x{mode['h']} scanout"
            )
            sys.exit("check_gui4: " + failures[-1])
        for corner in [(0, 0), (dump.width - 1, 0), (0, dump.height - 1),
                       (dump.width - 1, dump.height - 1)]:
            got = dump.at(*corner)
            if not close(got, background):
                failures.append(
                    f"{dump.path}: corner {corner} is {got}, not the reported "
                    f"desktop background {background}"
                )
                break

    # Dump 1: the overlap belongs to B (compositing), A's exposed part to A.
    overlap_client = intersect(a_rect, b_crect)
    if not overlap_client:
        failures.append("the scenario lost its overlap: A and B's client area are disjoint")
    else:
        dominant_check(failures, dump1, overlap_client, B_FILL,
                       "dump1 overlap (B above A must win)")
    exposed = (a_rect[0], a_rect[1], min(a_rect[2], b_wrect[0]), a_rect[3])
    dominant_check(failures, dump1, exposed, A_FILL, "dump1 A's exposed part")
    dominant_check(failures, dump1, b_crect, B_FILL, "dump1 B's client area")
    cursor_check(failures, dump1, park1, background, "dump1 cursor")

    # Dump 2: B at its reported new place; what it uncovered is repaired.
    delta = (b_moved[0] - b_wrect[0], b_moved[1] - b_wrect[1])
    b_crect2 = (b_crect[0] + delta[0], b_crect[1] + delta[1],
                b_crect[2] + delta[0], b_crect[3] + delta[1])
    dominant_check(failures, dump2, b_crect2, B_FILL, "dump2 B's client area (moved)")
    if intersect(a_rect, b_moved):
        failures.append("the drag did not fully uncover A; the A-repaint check is meaningless")
    else:
        dominant_check(failures, dump2, a_rect, A_FILL,
                       "dump2 A's full rect (uncover repaint)")
    # The vacated strip: inside B's old rect, outside its new one and outside
    # A — background again (the mover's desktop repair).
    vacated_total = vacated_bg = 0
    for py in range(max(b_wrect[1], 0), min(b_wrect[3], dump2.height)):
        for px in range(max(b_wrect[0], 0), min(b_wrect[2], dump2.width)):
            if b_moved[0] <= px < b_moved[2] and b_moved[1] <= py < b_moved[3]:
                continue
            if a_rect[0] <= px < a_rect[2] and a_rect[1] <= py < a_rect[3]:
                continue
            if park2[0] <= px < park2[0] + 12 and park2[1] <= py < park2[1] + 20:
                continue  # the parked cursor, if the park point falls here
            vacated_total += 1
            if close(dump2.at(px, py), background):
                vacated_bg += 1
    if vacated_total and vacated_bg < vacated_total * 0.98:
        failures.append(
            f"dump2 vacated area: only {vacated_bg}/{vacated_total} pixels returned "
            f"to the background"
        )
    cursor_check(failures, dump2, park2, background, "dump2 cursor")
    # Nothing repaints B after the drag, so the drag's own cursor traffic --
    # the arrow rode B's caption across the screen -- has to have left the
    # window clean by itself.
    foreign_pixel_check(
        failures, dump2, b_moved,
        [("desktop background", background), ("A's fill", A_FILL)],
        [park2], "dump2 B's moved window rect"
    )

    # Dump 3: the cursor sits inside B's client area and B has repainted
    # under it. Both halves of the stomp are graded -- the arrow survived
    # the flush, and B's fill (not a hole, and not a leftover of what the
    # cursor was over before) is what surrounds it.
    cursor_check(failures, dump3, park3, B_FILL, "dump3 cursor over B")
    dominant_check(failures, dump3, b_crect2, B_FILL, "dump3 B's client area (cursor inside)")
    foreign_pixel_check(
        failures, dump3, b_moved,
        [("desktop background", background), ("A's fill", A_FILL)],
        [park3], "dump3 B's moved window rect"
    )

    if failures:
        for failure in failures:
            print(f"check_gui4: {failure}", file=sys.stderr)
        sys.exit(f"check_gui4: {len(failures)} check(s) failed")

    print(
        "check_gui4: compositing, routing and the drag all hold — "
        f"overlap B-wins at {overlap_client}, click routing clean "
        f"({len(clicks['B'])} to B, {len(clicks['A'])} to A), "
        f"B moved {b_wrect[:2]} -> {b_moved[:2]}, uncovered area repaired, "
        f"cursor at {park1} then {park2}, and it survives a flush under it at {park3}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
