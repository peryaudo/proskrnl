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
    local sersock fifo
    sersock=$(mktemp -u /tmp/flashfr-ser-XXXXXX.sock)
    fifo="$DIR/type.fifo"; rm -f "$fifo"; mkfifo "$fifo"
    ACCEL="$ACCELSEL" QMP_SOCK="$sock" SERIAL_SOCK="$sersock" LOG="$log" \
        GUEST_INTERACTIVE=1 GUEST_SERIAL=1 \
        EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM=1536M TIMEOUT=1200 PASS_RE='PRSK-FLASH-NEVER' \
        "$ROOT/tools/qemu.sh" "$DIR/img.hdd" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    # The prompt is on the SERIAL transport now (GUEST_SERIAL=1), so
    # something must hold that socket open, tee it into $log for the greps
    # below, and carry the lines this trial types. QMP stays, for the
    # screendumps -- this trial needs the console AND the monitor, which is
    # what serial_drive.py exists for.
    while [ ! -S "$sersock" ]; do
        kill -0 "$qemu_wrapper" 2>/dev/null \
            || { echo "trial$t: ERROR (qemu died before its console)"; return 1; }
        sleep 1
    done
    python3 "$ROOT/tests/run/serial_drive.py" "$sersock" "$log" "$fifo" &
    local serial_driver=$!
    # CR, not LF. conhost maps a received '\n' to key_press(VK_RETURN,
    # LEFT_CTRL_PRESSED) (programs/conhost/conhost.c), and the ctrl keymap has
    # no VK_RETURN -- so the byte is INSERTED into the line instead of
    # submitting it and nothing ever runs. console_expect.py sends \r in all
    # of its sends for exactly this reason; the QMP path this replaced sent
    # the `ret` key, which is also Enter and not a linefeed.
    #
    # Bounded, because a write to a fifo blocks until a reader appears: if the
    # driver died (or the guest went away and took it with it) an unbounded
    # write wedges the whole trial loop forever instead of failing it.
    type_line() {
        kill -0 "$serial_driver" 2>/dev/null \
            || { echo "trial$t: ERROR (the serial driver is gone)"; return 1; }
        timeout 30 sh -c 'printf "%s\r" "$1" > "$2"' _ "$1" "$fifo" \
            || { echo "trial$t: ERROR (typing '"'"'$1'"'"' timed out)"; return 1; }
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }
    fail() {
        echo "trial$t: ERROR ($1)"
        qmp quit >/dev/null 2>&1 || true
        kill "$serial_driver" 2>/dev/null || true
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
    # No input-READY awaits. Those markers come from winefb.drv's reader
    # threads, which start at the first window surface -- and on this boot
    # (Gui=1, Serial=1) conhost takes the serial branch and creates none, no
    # explorer runs, and the only GUI client is the projector, which cannot
    # start until after this point. Waiting for them deadlocked the trial for
    # 300 s and then failed it as "no keyboard reader"; they were leftovers of
    # the deleted click-the-console-window path.
    type_line 'c:\SAFlashPlayer.exe c:\troubled_windows.swf'
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
    kill "$serial_driver" 2>/dev/null || true
    rm -f "$DIR/img.hdd" "$sock" "$sersock" "$fifo"
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
