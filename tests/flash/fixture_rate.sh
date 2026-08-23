#!/usr/bin/env bash
# fixture_rate.sh [N] [FIXTURE] [kvm|tcg] [WINEDEBUG] — run a gen_swf.py
# fixture in the standalone Flash projector ON PROSKRNL and print each
# trial's progress curve.
#
# The proskrnl half of the tests/flash differential (the oracle half is
# oracle_fixture.sh). Each trial boots a fresh copy of the gui5con image,
# clicks the console window, optionally sets WINEDEBUG (relay tracing needs
# c:\relay.reg imported first — the trial does that with regedit /S whenever
# a WINEDEBUG value is given), launches
#   c:\SAFlashPlayer.exe c:\<FIXTURE>.swf
# and screendumps at t=2,5,10,20,26,30s after launch. check_fixture.py maps
# each dump to a palette index = seconds of movie progress (the fixture
# shows one color per second for 16s and LOOPS — see gen_swf.py on why no
# ActionStop). Verdicts, off the last two dumps (4s apart, loop period 16s,
# so a live loop can never repeat an index across them):
#   PLAYED      — the index is still changing at t=26..30s.
#   FROZEN(i)   — the index pinned at i; an NMI is injected so the serial
#                 log ends with the all-threads dump.
#   NOSTART     — no palette color ever dominated any dump (movie never
#                 rendered frame 1); NMI-dumped too.
#
# Trials run SEQUENTIALLY on purpose (freeze_rate.sh explains: parallel boots
# load the host and bias the race). Prereqs: make dev-img with the
# fixtures present (build/flash/*.swf are baked when SAFlashPlayer.exe is).
set -uo pipefail
N="${1:-3}"
FIXTURE="${2:-fixture30}"
ACCELSEL="${3:-kvm}"
WDBG="${4:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/flash-fixture/$FIXTURE"
IMG="$ROOT/build/proskrnl-dev.hdd"
[ -f "$IMG" ] || { echo "build dev-img first"; exit 1; }

run_trial() {
    local t="$1" DIR="$OUT/t$t"
    rm -rf "$DIR"; mkdir -p "$DIR"
    cp "$IMG" "$DIR/img.hdd"
    local sock log="$DIR/serial.log"
    sock=$(mktemp -u /tmp/flashfx-XXXXXX.sock)
    local sersock fifo
    sersock=$(mktemp -u /tmp/flashfx-ser-XXXXXX.sock)
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
    if [ -n "$WDBG" ]; then
        type_line 'regedit /S c:\relay.reg'
        sleep 3
        type_line "set WINEDEBUG=$WDBG"
        sleep 1
    fi
    type_line "c:\\SAFlashPlayer.exe c:\\$FIXTURE.swf"
    local launched=$SECONDS curve="" idx="" last="" prev="" at2="" at10=""
    for tp in 2 5 10 20 26 30 45 60; do
        while ((SECONDS - launched < tp)); do sleep 1; done
        qmp screendump "$DIR/f$tp.ppm" >/dev/null 2>&1 || true
        idx=$(python3 "$ROOT/tests/flash/check_fixture.py" "$DIR/f$tp.ppm" \
              2>/dev/null | sed -E 's/^idx=([0-9a-z]+).*/\1/') || idx=none
        curve="$curve t=${tp}s:idx=$idx"
        prev="$last"
        last="$idx"
        [ "$tp" = 2 ] && at2="$idx"
        [ "$tp" = 10 ] && at10="$idx"
        kill -0 "$qemu_wrapper" 2>/dev/null || { fail "QEMU died mid-wait"; return; }
    done
    # A live loop steps one index per second, so across the 45->60s gap a
    # healthy run never repeats, and across 2->10s it must have moved.
    # "Moved eventually but not in the early window" is a CRAWL — the
    # deterministic ~14x-slow pacing measured on proskrnl — kept distinct
    # from PLAYED (oracle speed) and FROZEN (pinned).
    local verdict
    if [ "$last" = "none" ] && [ "$prev" = "none" ]; then
        verdict="NOSTART"
    elif [ "$last" = "$prev" ]; then
        verdict="FROZEN($last)"
    elif [ "$at2" = "$at10" ]; then
        verdict="CRAWL($last)"
    else
        verdict="PLAYED"
    fi
    if [ "$verdict" != "PLAYED" ]; then
        python3 - "$sock" <<EOF
import sys
sys.path.insert(0, '$ROOT/tests/gui')
from qmpctl import Qmp
Qmp(sys.argv[1]).execute('inject-nmi')
EOF
        sleep 3
    fi
    echo "trial$t: $verdict --$curve (dump in $DIR/serial.log)"
    qmp quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    kill "$serial_driver" 2>/dev/null || true
    rm -f "$DIR/img.hdd" "$sock" "$sersock" "$fifo"
}

played=0 froze=0 crawled=0 errs=0
for t in $(seq 1 "$N"); do
    verdict=$(run_trial "$t")
    echo "$verdict"
    case "$verdict" in
    *PLAYED*) played=$((played + 1)) ;;
    *CRAWL*) crawled=$((crawled + 1)) ;;
    *FROZEN*|*NOSTART*) froze=$((froze + 1)) ;;
    *) errs=$((errs + 1)) ;;
    esac
done
echo "$FIXTURE: $played played, $crawled crawled, $froze frozen, $errs errors"
