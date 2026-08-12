#!/usr/bin/env python3
"""check_rect.py — the GUI-1 framebuffer verdict (docs/02, docs/08).

    check_rect.py --log <serial.log> --ppm <screendump.ppm>

Reads the geometry and colours the guest reported on serial, then checks
QEMU's screendump of the same frame against them. This is the differential
that convicts \\Device\\Fb0 (Art. 6): the guest says what it painted and
where, and the pixels come back through QEMU's own device model -- two
independent implementations of "what is in the framebuffer", compared.
Nothing here is hardcoded about the mode, so a QEMU that picks a different
default resolution changes the numbers on both sides at once.

No golden image at GUI-1: a byte-compared PPM would break on any QEMU
rendering change without telling us anything about the kernel.
tests/gui/golden/ belongs to gui6 (check_gui6.py), where the thing under
test is a desktop someone drew rather than a rectangle we can describe in
six numbers.
"""
import argparse
import re
import sys

MARKER = re.compile(
    r"\[KTEST\] gui fb drawn "
    r"w=(?P<w>\d+) h=(?P<h>\d+) pitch=(?P<pitch>\d+) "
    r"rect=(?P<x>\d+),(?P<y>\d+),(?P<rw>\d+)x(?P<rh>\d+) "
    r"fg=(?P<fg>[0-9a-f]{6}) bg=(?P<bg>[0-9a-f]{6})"
)


def parse_marker(path):
    with open(path, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")
    match = None
    for match in MARKER.finditer(text):
        pass  # keep the last, in case a leg boots more than once
    if match is None:
        sys.exit(f"check_rect: no '[KTEST] gui fb drawn' marker in {path}")
    fields = match.groupdict()
    rgb = lambda value: tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))
    return {
        "w": int(fields["w"]), "h": int(fields["h"]),
        "x": int(fields["x"]), "y": int(fields["y"]),
        "rw": int(fields["rw"]), "rh": int(fields["rh"]),
        "fg": rgb(fields["fg"]), "bg": rgb(fields["bg"]),
    }


def read_ppm(path):
    """Minimal P6 reader: QEMU's screendump writes maxval 255, 8 bits/channel."""
    with open(path, "rb") as handle:
        data = handle.read()

    fields, offset = [], 0
    while len(fields) < 4:
        if offset >= len(data):
            sys.exit(f"check_rect: {path} is not a complete PPM header")
        if data[offset : offset + 1].isspace():
            offset += 1
            continue
        if data[offset : offset + 1] == b"#":  # comment to end of line
            while offset < len(data) and data[offset : offset + 1] != b"\n":
                offset += 1
            continue
        start = offset
        while offset < len(data) and not data[offset : offset + 1].isspace():
            offset += 1
        fields.append(data[start:offset])
    offset += 1  # exactly one whitespace byte follows maxval

    magic, width, height, maxval = fields
    if magic != b"P6":
        sys.exit(f"check_rect: {path} is {magic!r}, expected P6")
    if int(maxval) != 255:
        sys.exit(f"check_rect: {path} has maxval {int(maxval)}, expected 255")
    width, height = int(width), int(height)
    pixels = data[offset:]
    if len(pixels) < width * height * 3:
        sys.exit(f"check_rect: {path} is truncated ({len(pixels)} bytes of pixel data)")
    return width, height, pixels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm", required=True)
    args = parser.parse_args()

    want = parse_marker(args.log)
    width, height, pixels = read_ppm(args.ppm)

    if (width, height) != (want["w"], want["h"]):
        sys.exit(
            f"check_rect: screendump is {width}x{height}, "
            f"but the guest reported {want['w']}x{want['h']}"
        )

    def pixel_at(x, y):
        base = (y * width + x) * 3
        return tuple(pixels[base : base + 3])

    x, y, rw, rh = want["x"], want["y"], want["rw"], want["rh"]
    failures = []

    # Inside: corners just within the rectangle, the centre, and the edge
    # midpoints -- an off-by-one in the fill bounds shows up at the corners,
    # a pitch mistake shows up as a shear the midpoints catch.
    inside = [
        (x, y), (x + rw - 1, y), (x, y + rh - 1), (x + rw - 1, y + rh - 1),
        (x + rw // 2, y + rh // 2),
        (x + rw // 2, y), (x + rw // 2, y + rh - 1),
        (x, y + rh // 2), (x + rw - 1, y + rh // 2),
    ]
    for px, py in inside:
        got = pixel_at(px, py)
        if got != want["fg"]:
            failures.append(f"({px},{py}) inside the rect is {got}, expected {want['fg']}")

    # Outside: one pixel past each edge, plus the far corner of the screen.
    outside = [
        (x - 1, y), (x + rw, y), (x, y - 1), (x, y + rh),
        (width - 1, height - 1), (0, 0),
    ]
    for px, py in outside:
        if not (0 <= px < width and 0 <= py < height):
            continue
        got = pixel_at(px, py)
        if got != want["bg"]:
            failures.append(f"({px},{py}) outside the rect is {got}, expected {want['bg']}")

    if failures:
        for failure in failures:
            print(f"check_rect: {failure}", file=sys.stderr)
        sys.exit(f"check_rect: {len(failures)} sampled pixel(s) wrong")

    print(
        f"check_rect: {want['rw']}x{want['rh']} rect at ({x},{y}) "
        f"confirmed in a {width}x{height} screendump"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
