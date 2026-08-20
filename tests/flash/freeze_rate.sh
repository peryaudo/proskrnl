#!/usr/bin/env bash
# freeze_rate.sh [N] [kvm|tcg] — measure the SAFlashPlayer startup-freeze
# rate on the gui5con image (flash_player branch).
#
# Each trial boots a fresh copy of build/proskrnl-dev.hdd, clicks the
# console window, launches `c:\SAFlashPlayer.exe c:\troubled_windows.swf`,
# and waits up to 8 minutes for the movie's ダウンロードの完了 dialog
# (detected by pixel-matching the 再生 button against playbtn-ref.png at
# crop (240,215)-(295,240) of the 640x480 screendump):
#
#   DIALOG — the movie played its preload sequence; startup race won.
#   FROZEN — stuck on the first frame: Flash's frame period was latched as
#            raw QPC ticks before its lazily-initialized QPF was set, and
#            timeSetEvent was armed with period_ticks×1000 ms (~5.15 days).
#            The trial then injects an NMI so the serial log ends with the
#            all-threads dump (look for `timeout in 4448…ms`).
#
# Trials run SEQUENTIALLY on purpose: parallel boots load the host, degrade
# QPC granularity to the LAPIC period, and bias Flash into the bad branch
# (a 6-parallel batch froze 6/6 where the idle-host rate is lower). Run on
# an otherwise idle machine for an honest number.
#
# Prereqs: `make dev-img` on this branch (bakes the .exe/.swf into the
# image), python3-PIL. Artifacts per trial land in build/flash-trials/.
set -uo pipefail
N="${1:-3}"
ACCELSEL="${2:-kvm}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REF="$ROOT/tests/flash/playbtn-ref.png"
OUT="$ROOT/build/flash-trials"
IMG="$ROOT/build/proskrnl-dev.hdd"
[ -f "$IMG" ] || { echo "build dev-img first"; exit 1; }

run_trial() {
    local t="$1" DIR="$OUT/t$t"
    rm -rf "$DIR"; mkdir -p "$DIR"
    cp "$IMG" "$DIR/img.hdd"
    # QMP socket in /tmp: a socket path under build/ can exceed the 108-byte
    # AF_UNIX limit depending on where the tree is checked out.
    local sock log="$DIR/serial.log"
    sock=$(mktemp -u /tmp/flashfr-XXXXXX.sock)
    ACCEL="$ACCELSEL" QMP_SOCK="$sock" LOG="$log" GUEST_INTERACTIVE=1 \
        EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM=1536M TIMEOUT=1200 PASS_RE='PRSK-FLASH-NEVER' GUEST_SHELL=1 \
        "$ROOT/tools/qemu.sh" "$DIR/img.hdd" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }
    fail() {
        echo "trial$t: ERROR ($1)"
        qmp quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        return 1
    }
    await() {
        local deadline=$((SECONDS + 300))
        while ((SECONDS < deadline)); do
            grep -qE "$1" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1
            sleep 1
        done
        return 1
    }
    await 'starting cmd\.exe' || { fail "cmd never started"; return; }
    await '\[KTEST\] gui2 input READY' || { fail "no keyboard reader"; return; }
    await '\[KTEST\] gui4 mouse READY' || { fail "no pointer reader"; return; }
    local located="" deadline=$((SECONDS + 300))
    while ((SECONDS < deadline)); do
        qmp screendump "$DIR/boot.ppm" >/dev/null 2>&1 || true
        if located=$(python3 "$ROOT/tests/gui/check_gui5con.py" --locate \
                --log "$log" --ppm "$DIR/boot.ppm" 2>/dev/null); then break; fi
        located=""
        kill -0 "$qemu_wrapper" 2>/dev/null || { fail "QEMU died"; return; }
        sleep 3
    done
    [ -n "$located" ] || { fail "no console window"; return; }
    local cx cy w h maxx maxy
    cx=$(sed -E 's/.*center=([0-9]+),[0-9]+$/\1/' <<<"$located")
    cy=$(sed -E 's/.*center=[0-9]+,([0-9]+)$/\1/' <<<"$located")
    w=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    h=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+ h=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxx=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxy=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+,[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    px() { echo $(( ($1 * maxx + w - 2) / (w - 1) )); }
    py() { echo $(( ($1 * maxy + h - 2) / (h - 1) )); }
    qmp absmove "$(px "$cx")" "$(py "$cy")" >/dev/null
    sleep 1
    qmp button left down >/dev/null && qmp button left up >/dev/null
    sleep 2
    qmp type 'c:\SAFlashPlayer.exe c:\troubled_windows.swf
' >/dev/null
    local found="" launched=$SECONDS
    deadline=$((SECONDS + 480))
    while ((SECONDS < deadline)); do
        qmp screendump "$DIR/f.ppm" >/dev/null 2>&1 || true
        if python3 - "$DIR/f.ppm" "$REF" <<'EOF'
import sys
from PIL import Image, ImageChops
im = Image.open(sys.argv[1]).convert('RGB').crop((240, 215, 295, 240))
ref = Image.open(sys.argv[2]).convert('RGB')
n = sum(1 for p in ImageChops.difference(im, ref).getdata() if p != (0, 0, 0))
sys.exit(0 if n < 100 else 1)
EOF
        then found=1; break; fi
        kill -0 "$qemu_wrapper" 2>/dev/null || { fail "QEMU died mid-wait"; return; }
        sleep 3
    done
    if [ -n "$found" ]; then
        echo "trial$t: DIALOG (after $((SECONDS - launched))s)"
    else
        # Frozen: NMI-panic for the all-threads dump before shutting down.
        python3 - "$sock" <<EOF
import sys
sys.path.insert(0, '$ROOT/tests/gui')
from qmpctl import Qmp
Qmp(sys.argv[1]).execute('inject-nmi')
EOF
        sleep 3
        echo "trial$t: FROZEN (dump in $DIR/serial.log)"
    fi
    qmp quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    rm -f "$DIR/img.hdd" "$sock"
}

froze=0 played=0 errs=0
for t in $(seq 1 "$N"); do
    verdict=$(run_trial "$t")
    echo "$verdict"
    case "$verdict" in
    *DIALOG*) played=$((played + 1)) ;;
    *FROZEN*) froze=$((froze + 1)) ;;
    *) errs=$((errs + 1)) ;;
    esac
done
echo "freeze rate: $froze/$((froze + played)) frozen ($played played, $errs errors)"
