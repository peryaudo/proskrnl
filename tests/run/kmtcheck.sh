#!/usr/bin/env bash
# kmtcheck.sh — every in-kernel suite's verdict actually gates the boot.
#
#   kmtcheck.sh [<serial log>]             # default build/serial.log
#
# WHY THIS EXISTS. A boot's verdict is a single grep for PASS_RE on the serial
# log (tools/qemu.sh), and PASS_RE names ONE line. So every kmt suite whose
# verdict is printed after — or beside — that line was reporting into the void:
# CUI8, PREVENTIVE, SCHED and CONDRV each printed an honest
# `[KTEST] <suite> FAIL failures=N` that turned no leg red, and the in-kernel
# aggregate that KiQemuExit reports omitted them besides (nothing reads that
# status either: the grace-path kill in qemu.sh makes QEMU's exit code
# unreliable by design, so the log stays the single source of the verdict).
#
# The only failures those suites could still convict with were the ones that
# PANIC — an ASSERT or a KASAN trap kills the boot, so the verdict line never
# appears. Every ok() short of that was advisory by accident. That is precisely
# the shape docs/08 forbids and the all-green job's rule states: a verdict
# nobody reached must never read as a verdict that passed.
#
# WHAT IT CHECKS. For each suite below, on a FULL-image boot (`make test`):
#
#   - the suite's `[KTEST] <name> PASS` line is PRESENT — a suite that silently
#     stopped running is caught, not just one that failed; and
#   - no `[KTEST] <name> FAIL` line appears.
#
# ADDING A SUITE. A new kmt suite must be listed here in the same commit that
# adds it, or it is ungated exactly like the four above were. The list cannot
# rot in the dangerous direction — a listed suite that disappears fails this
# check — only in the direction of a new suite nobody added.
#
# SCOPE. Deliberately only the standard image: `make test` is the leg that owns
# the kmt verdicts. The special images (guiwtest, gui*, fatinterop) legitimately
# print FAIL for suites whose modules they do not carry, which is why they set
# their own PASS_RE and do not run this.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG="${1:-$ROOT/build/serial.log}"

# Every suite a standard-image boot runs to a verdict, in boot order
# (kernel/init/main.c KiTestMainThread). FATINTEROP/churn are absent by design
# on this image (they gate on a baked manifest and stay silent), so they are
# not here — run.sh fatinterop/fatstress grep their own verdicts.
SUITES=(
    M1 LIB M2 M3 M4 M5 M6
    CUI8 CONDRV PREVENTIVE SCHED
    ABI M7 M8 M9
    sweep
)

if [[ ! -s "$LOG" ]]; then
    echo "[KTEST] kmtcheck FAIL (no serial log at $LOG)"
    exit 1
fi

fails=0
for suite in "${SUITES[@]}"; do
    if grep -qE "^\[KTEST\] $suite FAIL" "$LOG"; then
        echo "[KTEST] kmtcheck-$suite FAIL ($(grep -oE "^\[KTEST\] $suite FAIL.*" "$LOG" | tail -1))"
        fails=$((fails + 1))
    elif ! grep -qE "^\[KTEST\] $suite PASS" "$LOG"; then
        echo "[KTEST] kmtcheck-$suite FAIL (no verdict on serial — the suite did not run)"
        fails=$((fails + 1))
    fi
done

# The per-case lines too: a kmt ok() failure prints [ASSERT] and increments its
# suite's count, so the loop above already catches it — but an [ASSERT] from a
# suite that then somehow reported PASS is a harness defect worth its own line.
asserts="$(grep -cE '^\[ASSERT\] ' "$LOG" 2>/dev/null || true)"
if [[ "${asserts:-0}" -ne 0 ]]; then
    echo "[KTEST] kmtcheck-asserts FAIL ($asserts [ASSERT] lines on serial)"
    grep -E '^\[ASSERT\] ' "$LOG" | head -10
    fails=$((fails + 1))
fi

if [[ "$fails" -ne 0 ]]; then
    echo "== kmtcheck: FAIL ($fails) — an in-kernel suite reported a failure the"
    echo "   boot's PASS_RE grep alone would have let through; see $LOG."
    exit 1
fi
echo "== kmtcheck: 0 failing (${#SUITES[@]} suites) =="
