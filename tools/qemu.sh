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
TIMEOUT="${TIMEOUT:-30}"
PASS_RE="${PASS_RE:-\[KTEST\] M2 PASS}"
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

qemu-system-x86_64 \
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
cat "$LOG" || true
echo "--------------------------"
if grep -q "$PASS_RE" "$LOG"; then
    echo "== run: PASS =="
    exit 0
else
    echo "== run: FAIL (verdict '$PASS_RE' not found on serial) =="
    exit 1
fi
