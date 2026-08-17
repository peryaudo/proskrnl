#!/usr/bin/env python3
"""check_fixture.py — read a screendump and report which fixture frame is up.

Companion to tools/gen_swf.py (the app-level liveness fixture for the
SAFlashPlayer freeze investigation — NOT a G5 boundary pin, see gen_swf.py).
The fixture shows one solid saturated color per second of movie time; this
checker counts, over the WHOLE image, pixels near-matching each palette entry
and reports the dominant index — so it needs no knowledge of where the
projector placed its window, on either side of the differential (QEMU PPM
screendump for proskrnl, Xvfb XWD dump for the Wine oracle).

Usage: check_fixture.py IMAGE [--min-pixels N]
Prints "idx=<i> count=<n>" (or "idx=none") plus every nonzero palette count.
Exit 0 when a dominant index was found, 1 otherwise.
"""
import sys

# Keep in sync with tools/gen_swf.py PALETTE.
PALETTE = [
    (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
    (255, 0, 255), (0, 255, 255), (255, 128, 0), (128, 0, 255),
    (0, 255, 128), (255, 0, 128), (0, 128, 255), (128, 255, 0),
    (0, 128, 128), (128, 0, 0), (0, 0, 128), (128, 128, 0),
]
TOLERANCE = 12


def read_ppm(data):
    """P6 binary PPM (QEMU screendump format)."""
    fields, pos = [], 2
    while len(fields) < 3:
        while pos < len(data) and data[pos] in b" \t\r\n":
            pos += 1
        if data[pos:pos + 1] == b"#":
            while data[pos] != 0x0A:
                pos += 1
            continue
        start = pos
        while data[pos] not in b" \t\r\n":
            pos += 1
        fields.append(int(data[start:pos]))
    pos += 1  # single whitespace after maxval
    w, h, _ = fields
    return w, h, data[pos:pos + w * h * 3], 3, (0, 1, 2)


def read_xwd(data):
    """XWD ZPixmap dump (X11 xwd; format per X11's XWDFileHeader, all fields
    big-endian u32). Handles the 24-depth/32-bpp case Xvfb produces."""
    import struct
    hdr = struct.unpack(">25I", data[:100])
    (header_size, version, pixmap_format, _depth, width, height, _xoff,
     byte_order, _unit, _bit_order, _pad, bits_per_pixel, bytes_per_line,
     _visual, red_mask, _green_mask, _blue_mask, _bits_rgb, _cmap,
     ncolors) = hdr[:20]
    assert version == 7 and pixmap_format == 2, "not a ZPixmap XWD"
    pixels = data[header_size + ncolors * 12:]
    # The per-pixel stride comes from bytes_per_line, NOT bits_per_pixel:
    # Xvfb reports depth-24 visuals with 24 bpp but pads each pixel to 4
    # bytes (bytes_per_line == width*4). red_mask says which channel is
    # high; compute per-byte channel offsets once.
    stride = bytes_per_line // width
    if byte_order == 0:  # LSBFirst
        offsets = (2, 1, 0) if red_mask == 0xFF0000 else (0, 1, 2)
    else:
        hi = stride - 3
        offsets = (hi, hi + 1, hi + 2) if red_mask == 0xFF0000 \
            else (hi + 2, hi + 1, hi)
    return width, height, pixels, stride, offsets


def main():
    path = sys.argv[1]
    min_pixels = 30000
    if "--min-pixels" in sys.argv:
        min_pixels = int(sys.argv[sys.argv.index("--min-pixels") + 1])
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"P6":
        w, h, pixels, stride, (ro, go, bo) = read_ppm(data)
    else:
        w, h, pixels, stride, (ro, go, bo) = read_xwd(data)

    # Palette channels are only 0/128/255, so quantize each channel with a
    # 256-entry table (one pass, no per-palette compare).
    quant = bytearray(1 for _ in range(256))  # 1 = "no palette channel"
    for i in range(256):
        if i <= TOLERANCE:
            quant[i] = 0
        elif abs(i - 128) <= TOLERANCE:
            quant[i] = 128
        elif i >= 255 - TOLERANCE:
            quant[i] = 255
    lookup = {p: i for i, p in enumerate(PALETTE)}
    counts = [0] * len(PALETTE)
    n = min(len(pixels) // stride, w * h)
    for p in range(0, n * stride, stride):
        key = (quant[pixels[p + ro]], quant[pixels[p + go]],
               quant[pixels[p + bo]])
        i = lookup.get(key)
        if i is not None:
            counts[i] += 1

    for i, c in enumerate(counts):
        if c:
            print(f"palette[{i}]={c}", file=sys.stderr)
    best = max(range(len(counts)), key=lambda i: counts[i])
    if counts[best] >= min_pixels:
        print(f"idx={best} count={counts[best]}")
        sys.exit(0)
    print(f"idx=none best={best} count={counts[best]}")
    sys.exit(1)


if __name__ == "__main__":
    main()
