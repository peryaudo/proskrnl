#!/usr/bin/env python3
"""check_gui5.py — the GUI-5 verdict (docs/02 "GUI finishing").

    check_gui5.py --log <serial.log> --ppm <screendump.ppm> --golden <fontdiff.golden>

Three halves, and all must hold.

The BEHAVIOUR half is what the guests reported: the clipboard crossed the
process boundary (owner identity, registered-format identity, the immediate
payload, the DELAYED render round trip, the sequence number, and the
ownership handoff seen from the old owner's side as WM_DESTROYCLIPBOARD plus
the listener's WM_CLIPBOARDUPDATE), a thread-local WH_CBT hook observed a
window being created, AttachThreadInput opened and closed the cross-thread
focus wall, and a WH_KEYBOARD_LL hook saw exactly one injected 'k' — the one
sent while it was armed; the 'k' sent after UnhookWindowsHookEx must have
reached the window (char count) but NOT the hook (llhook count). Counting is
the unhook proof: a hook that outlives its Unhook would print twice.

The PIXEL half is the structural screendump differential every GUI leg uses
(Art. 6): both clients said what they drew and where; QEMU's device model
returns the pixels. Same reasoning as check_gui3.py — the windows are
disjoint by construction, no golden image until GUI-6.

The FONTDIFF half is the guest side of the font-metrics differential: the
same fontdiff.exe the oracle leg runs printed its metric table on serial,
and it must equal tests/gdi/fontdiff.golden line for line — exact integers,
no epsilon (docs/03 "the font oracle": same FreeType, same font bytes,
96 dpi on both sides).
"""
import argparse
import collections
import re
import sys

from check_rect import read_ppm

# winefb.drv's own scanout report (the literal says "gui2" on every GUI
# image; check_gui3.py explains).
MODE = re.compile(
    r"\[KTEST\] gui2 mode "
    r"w=(?P<w>\d+) h=(?P<h>\d+) pitch=(?P<pitch>\d+) bpp=(?P<bpp>\d+) bgrx=(?P<bgrx>\d+)"
)
A_RECT = re.compile(
    r"\[KTEST\] gui5 A ready rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+)"
)
B_RECT = re.compile(
    r"\[KTEST\] gui5 B rect=(?P<x>-?\d+),(?P<y>-?\d+),(?P<w>\d+)x(?P<h>\d+)"
)
FONTDIFF = re.compile(r"\[KTEST\] fontdiff (?:dpi=|face=|done ).*")

# Every verdict gui5b prints, in the order it prints them. Two-word names
# are deliberate ([KTEST] gui5 clip owner PASS): the first word is the
# phase, the second the check.
REQUIRED = (
    "clip owner",
    "clip fmt",
    "clip text",
    "clip render",
    "clip seq",
    "cbt",
    "ati pre",
    "ati attach",
    "ati focus",
    "ati detach",
    "verdict",
)

# gui5a's event reports, each corroborating a server-side notification the
# B-side verdicts alone could fake by passing locally.
A_EVENTS = (
    "A renderfmt f=13",  # WM_RENDERFORMAT for CF_UNICODETEXT (13)
    "A destroyclip",
    "A clipupdate",
)

MIN_PAINTED = 0.50


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--ppm", required=True)
    parser.add_argument("--golden", required=True)
    args = parser.parse_args()

    with open(args.log, "rb") as handle:
        text = handle.read().decode("utf-8", "replace")

    failures = []

    # --- the behaviour half -------------------------------------------------
    for name in REQUIRED:
        matches = re.findall(rf"\[KTEST\] gui5 {re.escape(name)} (PASS|FAIL)", text)
        if not matches:
            failures.append(f"no '[KTEST] gui5 {name}' verdict on serial")
        elif matches[-1] != "PASS":
            failures.append(f"gui5 {name} reported {matches[-1]}")

    for event in A_EVENTS:
        if f"[KTEST] gui5 {event}" not in text:
            failures.append(f"A never reported '{event}'")

    # The unhook proof by counting (see the module docstring).
    llhook_k = len(re.findall(r"\[KTEST\] gui5 llhook vk=4b", text))
    chars_k = len(re.findall(r"\[KTEST\] gui5 B char=6b", text))
    if llhook_k != 1:
        failures.append(f"expected exactly 1 'llhook vk=4b' line, found {llhook_k}")
    if chars_k < 2:
        failures.append(f"expected both 'k' presses to reach the window, found {chars_k}")
    if not re.search(r"\[KTEST\] gui5 unhook ok=1", text):
        failures.append("UnhookWindowsHookEx never reported success")

    # --- the fontdiff half --------------------------------------------------
    with open(args.golden, "r", encoding="utf-8") as handle:
        golden = [line.rstrip("\n") for line in handle if line.strip()]
    guest = [m.group(0).rstrip() for m in FONTDIFF.finditer(text)]
    if guest != golden:
        # Name the first divergence precisely: this is the differential's
        # whole point, and "differs" alone would send someone to a diff tool.
        limit = max(len(guest), len(golden))
        for index in range(limit):
            want = golden[index] if index < len(golden) else "<missing>"
            got = guest[index] if index < len(guest) else "<missing>"
            if want != got:
                failures.append(f"fontdiff line {index + 1}: guest '{got}' != oracle '{want}'")
                break
        failures.append(
            f"guest metric table diverges from tests/gdi/fontdiff.golden "
            f"({len(guest)} guest lines, {len(golden)} golden lines)"
        )

    # --- the pixel half -----------------------------------------------------
    mode = None
    for match in MODE.finditer(text):
        mode = match.groupdict()
    rects = {}
    for pattern, who in ((A_RECT, "A"), (B_RECT, "B")):
        found = None
        for found in pattern.finditer(text):
            pass
        if found is None:
            failures.append(f"client {who} never reported its window rectangle")
        else:
            info = found.groupdict()
            rects[who] = (int(info["x"]), int(info["y"]), int(info["w"]), int(info["h"]))

    if mode is None:
        failures.append("no '[KTEST] gui2 mode' marker on serial")
    else:
        width, height, pixels = read_ppm(args.ppm)
        if (width, height) != (int(mode["w"]), int(mode["h"])):
            failures.append(
                f"screendump is {width}x{height}, but the guest reported a "
                f"{mode['w']}x{mode['h']} scanout"
            )

        def pixel_at(x, y):
            base = (y * width + x) * 3
            return tuple(pixels[base : base + 3])

        corners = [(0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)]
        corner_colours = {pixel_at(px, py) for px, py in corners}
        background = None
        if len(corner_colours) != 1:
            failures.append(
                f"the framebuffer outside both windows is not uniform: {corner_colours}"
            )
        else:
            background = corner_colours.pop()

        boxes = []
        for who in sorted(rects):
            x, y, w, h = rects[who]
            left, top = max(x, 0), max(y, 0)
            right, bottom = min(x + w, width), min(y + h, height)
            if right <= left or bottom <= top:
                failures.append(f"client {who}'s {w}x{h} window at ({x},{y}) is off screen")
                continue
            inside = collections.Counter()
            for py in range(top, bottom):
                for px in range(left, right):
                    inside[pixel_at(px, py)] += 1
            area = sum(inside.values())
            painted = area - inside.get(background, 0) if background else area
            if background and painted < area * MIN_PAINTED:
                failures.append(
                    f"client {who}: only {painted}/{area} pixels differ from the "
                    f"background {background} (want at least {MIN_PAINTED:.0%})"
                )
            boxes.append(inside.most_common(1)[0][0] if area else None)

        if len(boxes) == 2 and background and boxes[0] == boxes[1]:
            failures.append(
                f"both windows are dominated by the same colour {boxes[0]} — "
                "expected each client's own fill"
            )

    if failures:
        for failure in failures:
            print(f"check_gui5: {failure}", file=sys.stderr)
        sys.exit(f"check_gui5: {len(failures)} check(s) failed")

    print(
        "check_gui5: clipboard, hooks and AttachThreadInput hold cross-process; "
        f"the guest metric table matches the oracle golden ({len(golden)} lines)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
