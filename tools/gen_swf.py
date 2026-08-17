#!/usr/bin/env python3
"""gen_swf.py — generate an uncompressed diagnostic SWF from scratch.

Written against Adobe's PUBLIC "SWF File Format Specification, Version 19"
(https://www.adobe.com/devnet/swf.html); every structure below cites the spec
chapter it is checked against. No sample SWF was copied and no GPL tooling
(swftools, Ming) is involved — provenance per docs/11.

The movie is an app-level LIVENESS fixture for the SAFlashPlayer freeze
investigation (tests/flash/), NOT a G5 boundary pin: it never asserts an Nt*
behaviour, it only makes the projector's frame-scheduler progress readable
from a screendump. Design (see tests/flash/):

  - The stage is a solid full-stage rectangle whose color changes once per
    SECOND of movie time, stepping through a 16-entry high-contrast palette,
    then stops (DoAction/ActionStop) on the last frame. A screendump therefore
    yields a frame INDEX (seconds of progress), not a moved/didn't-move bit.
  - The frame RATE is a parameter: the same one-color-per-second timeline is
    emitted at any fps, so 30 fps (33 ms frame period) and 10 fps (100 ms)
    fixtures show identical wall-clock color curves while exercising the
    scheduler's two paths (free-run vs timeSetEvent) — the discriminating
    experiment of the freeze investigation.
  - Frame 1's color (palette[0], pure red) differs from both the background
    (dark gray) and anything the projector shows before rendering, so "never
    rendered frame 1" and "rendered frame 1 and stopped" are distinct verdicts.

Usage: gen_swf.py OUT.swf FPS [SECONDS]
"""
import struct
import sys

# 16 high-contrast SATURATED colors, mutually far apart in RGB space so a
# near-exact match survives scanout format conversion. Deliberately no white,
# black, or gray: the verdict counts matching pixels over the whole screen,
# and window chrome / dialog surfaces are white-black-gray. Index 0 (frame 1)
# is pure red: distinct from the dark-gray stage background and from any
# white/gray startup UI.
PALETTE = [
    (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
    (255, 0, 255), (0, 255, 255), (255, 128, 0), (128, 0, 255),
    (0, 255, 128), (255, 0, 128), (0, 128, 255), (128, 255, 0),
    (0, 128, 128), (128, 0, 0), (0, 0, 128), (128, 128, 0),
]
BACKGROUND = (0x30, 0x30, 0x30)

# Stage: 550x400 pt = 11000x8000 twips (1 pt = 20 twips, spec ch. 1 "Twips").
STAGE_W_TWIPS = 11000
STAGE_H_TWIPS = 8000


class BitWriter:
    """MSB-first bit packing (spec ch. 1 'Bit values')."""

    def __init__(self):
        self.bytes = bytearray()
        self.bit = 0  # bits used in the trailing byte

    def write(self, value, nbits):
        for i in range(nbits - 1, -1, -1):
            if self.bit == 0:
                self.bytes.append(0)
            if (value >> i) & 1:
                self.bytes[-1] |= 0x80 >> self.bit
            self.bit = (self.bit + 1) % 8

    def write_signed(self, value, nbits):
        self.write(value & ((1 << nbits) - 1), nbits)

    def align(self):
        self.bit = 0

    def data(self):
        return bytes(self.bytes)


def signed_bits(*values):
    """Bits needed to hold every value as two's complement (spec ch. 1)."""
    need = 1
    for v in values:
        n = v.bit_length() + 1  # one sign bit
        need = max(need, n)
    return need


def rect(xmin, xmax, ymin, ymax):
    """RECT record (spec ch. 1 'Rectangle record')."""
    n = signed_bits(xmin, xmax, ymin, ymax)
    w = BitWriter()
    w.write(n, 5)
    for v in (xmin, xmax, ymin, ymax):
        w.write_signed(v, n)
    return w.data()


def tag(code, body):
    """RECORDHEADER, short or long form (spec ch. 2 'SWF tag format')."""
    if len(body) < 0x3F:
        return struct.pack("<H", (code << 6) | len(body)) + body
    return struct.pack("<HI", (code << 6) | 0x3F, len(body)) + body


def define_shape(shape_id, rgb):
    """DefineShape (tag 2, spec ch. 6): one solid-fill full-stage rectangle.

    Drawn clockwise with FillStyle1 (the fill to the RIGHT of edge direction,
    spec ch. 6 'Shape structures'), so the interior is filled.
    """
    body = struct.pack("<H", shape_id)
    body += rect(0, STAGE_W_TWIPS, 0, STAGE_H_TWIPS)
    # FILLSTYLEARRAY: one solid RGB fill (spec ch. 6 'Fill styles').
    body += bytes([1, 0x00]) + bytes(rgb)
    # LINESTYLEARRAY: empty (spec ch. 6 'Line styles').
    body += bytes([0])
    w = BitWriter()
    w.write(1, 4)  # NumFillBits
    w.write(0, 4)  # NumLineBits
    # StyleChangeRecord: MoveTo (0,0) + FillStyle1 = 1 (spec ch. 6). Flag
    # order MSB->LSB: NewStyles, LineStyle, FillStyle1, FillStyle0, MoveTo.
    w.write(0, 1)          # TypeFlag: non-edge
    w.write(0b00101, 5)    # FillStyle1 + MoveTo
    w.write(0, 5)          # MoveBits = 0: deltas (0,0) take no bits
    w.write(1, 1)          # FillStyle1 index, NumFillBits wide
    # Four StraightEdgeRecords, clockwise (spec ch. 6 'Straight edge record').
    for dx, dy in ((STAGE_W_TWIPS, 0), (0, STAGE_H_TWIPS),
                   (-STAGE_W_TWIPS, 0), (0, -STAGE_H_TWIPS)):
        d = dx if dx else dy
        n = max(2, signed_bits(d))
        w.write(0b11, 2)   # TypeFlag=1 edge, StraightFlag=1
        w.write(n - 2, 4)  # NumBits
        w.write(0, 1)      # GeneralLineFlag=0: axis-aligned
        w.write(0 if dx else 1, 1)  # VertLineFlag
        w.write_signed(d, n)
    w.write(0, 6)  # EndShapeRecord
    w.align()
    return tag(2, body + w.data())


def place_object2(depth, char_id, move):
    """PlaceObject2 (tag 26, spec ch. 3 'PlaceObject2')."""
    flags = 0x02 | (0x01 if move else 0)  # HasCharacter | Move
    return tag(26, struct.pack("<BHH", flags, depth, char_id))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out, fps = sys.argv[1], int(sys.argv[2])
    seconds = int(sys.argv[3]) if len(sys.argv) > 3 else len(PALETTE)
    assert seconds <= len(PALETTE), "one distinct color per second"

    body = rect(0, STAGE_W_TWIPS, 0, STAGE_H_TWIPS)
    # FrameRate is 8.8 fixed point, low byte = fraction (spec ch. 2 header).
    body += struct.pack("<HH", fps << 8, seconds * fps)  # rate, FrameCount
    body += tag(9, bytes(BACKGROUND))  # SetBackgroundColor (spec ch. 3)
    for s in range(seconds):
        body += define_shape(s + 1, PALETTE[s])
        body += place_object2(1, s + 1, move=(s > 0))
        for _ in range(fps):
            body += tag(1, b"")  # ShowFrame (spec ch. 3)
    # No ActionStop: the movie LOOPS. Deliberate — the Flash 8 projector's
    # stopped-at-end state repaints the stage as a striped dither
    # (measured on the pinned oracle), which defeats color classification,
    # while a looping movie keeps showing clean solids. Liveness is then a
    # CHANGING index across dumps; a wedge pins one index forever.
    body += tag(0, b"")  # End
    # Header: FWS = uncompressed, version 8 = the projector's own generation
    # (spec ch. 2 'The SWF header'); FileLength counts the whole file.
    header = b"FWS" + bytes([8])
    data = header + struct.pack("<I", len(body) + 8) + body
    with open(out, "wb") as f:
        f.write(data)
    print(f"{out}: {fps} fps, {seconds}s, {seconds * fps} frames, "
          f"{len(data)} bytes")


if __name__ == "__main__":
    main()
