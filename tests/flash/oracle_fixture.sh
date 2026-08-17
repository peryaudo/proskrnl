#!/usr/bin/env bash
# oracle_fixture.sh SWF [WINEDEBUG] — play a gen_swf.py fixture in the
# standalone Flash projector under the PINNED Wine oracle and print the
# progress curve.
#
# The differential control for tests/flash/ (Art. 6): the same fixture runs on
# proskrnl via fixture_rate.sh; this script establishes what the oracle does.
# Screendumps (xwd of the Xvfb root) are taken at t=2,5,10,20s after launch
# and classified by check_fixture.py, so the output is a frame INDEX curve
# ("advanced then stopped" is distinguishable from "never rendered").
#
# Uses the pinned third_party/wine (never a distro wine — CLAUDE.md) with the
# pinned FreeType, under a private Xvfb and a throwaway prefix, mirroring
# tests/run/run.sh's oracle plumbing. Optional $2 is a WINEDEBUG value whose
# output lands in the per-run log (relay tracing for the winmm diff).
set -uo pipefail
SWF="$(realpath "$1")"
DEBUG="${2:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WINEBIN="$ROOT/third_party/wine/wine"
[ -x "$WINEBIN" ] || { echo "pinned wine missing (tools/setup_linux.sh)"; exit 1; }
OUT="$ROOT/build/flash-oracle/$(basename "$SWF" .swf)-$$"
mkdir -p "$OUT"

DISP=":$(( (RANDOM % 500) + 200 ))"
Xvfb "$DISP" -screen 0 1280x800x24 -nolisten tcp &
XVFB=$!
trap 'kill $XVFB 2>/dev/null' EXIT
sleep 1

export DISPLAY="$DISP"
export LD_LIBRARY_PATH="$ROOT/third_party/freetype/x86_64-linux${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# The canonical oracle prefix run.sh's oracle mode auto-creates. Reused, not
# built here: an explicit `wineboot -u` under a bare Xvfb wedges in the
# RunOnce chain, while the auto-init inside any ordinary wine launch
# completes in seconds. Bootstrap with `tests/run/run.sh oracle clock_rate`
# if it does not exist yet.
export WINEPREFIX="$ROOT/build/tests/wineprefix"
[ -f "$WINEPREFIX/drive_c/windows/win.ini" ] || {
    echo "no oracle prefix; run: tests/run/run.sh oracle clock_rate"; exit 1; }
# Mirror the RelayInclude scope the proskrnl side imports from c:\relay.reg,
# so both halves of the differential filter identically.
WINEDEBUG="" "$WINEBIN" reg import "$ROOT/tests/flash/relay.reg" >"$OUT/reg.log" 2>&1
export WINEDEBUG="$DEBUG"

# The projector is a PE app: hand it a Windows-form path (unix paths map
# through the Z: drive but are not translated in argv).
SWFWIN="Z:${SWF//\//\\}"
"$WINEBIN" "$ROOT/SAFlashPlayer.exe" "$SWFWIN" >"$OUT/player.log" 2>&1 &
PLAYER=$!
LAUNCH=$SECONDS
for t in 2 5 10 20 26 30; do
    while (( SECONDS - LAUNCH < t )); do sleep 0.2; done
    xwd -display "$DISP" -root -silent -out "$OUT/t$t.xwd" 2>/dev/null
    verdict=$(python3 "$ROOT/tests/flash/check_fixture.py" "$OUT/t$t.xwd" 2>/dev/null) || true
    echo "t=${t}s $verdict"
done
kill $PLAYER 2>/dev/null; wait $PLAYER 2>/dev/null
"$WINEBIN" wineboot -k >/dev/null 2>&1 || true
echo "artifacts: $OUT"
