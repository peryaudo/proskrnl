#!/usr/bin/env bash
# qemu.sh — headless, finite-time QEMU run; verdict from the serial log (docs/08).
#
#   qemu.sh <hdd>
#
# macOS ships no `timeout`, so we use a portable background killer. On Apple
# Silicon the x86-64 guest runs under TCG emulation (no HVF) — slower, correct.
set -uo pipefail

IMG="${1:?usage: qemu.sh <hdd>}"
LOG="${LOG:-build/serial.log}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Prefer the pinned third_party/qemu build (tools/setup_linux.sh) over
# whatever the host has on PATH; $QEMU overrides either way.
find_qemu() {
    if [[ -x "$HERE/../third_party/qemu/build/qemu-system-x86_64" ]]; then
        echo "$HERE/../third_party/qemu/build/qemu-system-x86_64"
    else
        echo "qemu-system-x86_64"
    fi
}
QEMU="${QEMU:-$(find_qemu)}"

# TCG only gained x2APIC — the kernel's clock — in QEMU 9.0 (Ubuntu 24.04 LTS
# ships 8.2). Fail fast instead of hanging silently in timer calibration.
QEMU_MAJOR="$("$QEMU" --version | sed -n 's/.*version \([0-9]*\).*/\1/p' | head -1)"
if [[ -n "$QEMU_MAJOR" && "$QEMU_MAJOR" -lt 9 ]]; then
    echo "qemu.sh: QEMU $QEMU_MAJOR.x lacks TCG x2APIC (need >= 9.0, README \"Prerequisites\")" >&2
    exit 1
fi
TIMEOUT="${TIMEOUT:-30}"
PASS_RE="${PASS_RE:-\[KTEST\] M6 PASS}"
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

"$QEMU" \
    -M q35 \
    -cpu max \
    -m 256M \
    -no-reboot \
    -display none \
    -monitor none \
    -serial "file:$LOG" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -drive file="$IMG",format=raw,if=virtio &
QPID=$!

( sleep "$TIMEOUT"; kill -9 "$QPID" 2>/dev/null ) & KPID=$!
wait "$QPID" 2>/dev/null || true
kill "$KPID" 2>/dev/null || true
wait "$KPID" 2>/dev/null || true

echo "--- serial log ($LOG) ---"
# Display-time symbolization (Art. 9): annotate dump addresses with symbols
# from the build's DWARF. The verdict grep below stays on the RAW log file —
# the symbolizer only decorates what a reader (the LLM loop) sees.
"$HERE/symbolize.py" --kernel "$HERE/../build/proskrnl" \
    --moduledir "$HERE/../build/modules" < "$LOG" || cat "$LOG" || true
echo "--------------------------"
if grep -q "$PASS_RE" "$LOG"; then
    echo "== run: PASS =="
    exit 0
else
    echo "== run: FAIL (verdict '$PASS_RE' not found on serial) =="
    exit 1
fi
