#!/usr/bin/env bash
# symcheck.sh — the symbolizer's own regression gate (Art. 9).
#
#   symcheck.sh [<symbolized log>]        # default build/serial.sym.log
#
# tools/symbolize.py recognizes dump addresses by their PRINTED SHAPE: the
# %#018lx width, the kernel's -2 GiB link base, PSP_IMAGE_BASE for flat user
# binaries, and the [USERFAULT] block layout that says which module an address
# belongs to. Nothing in the kernel forces those to agree with the script — and
# because the symbolizer degrades silently to pass-through (by design: it must
# never fail a run), a drift would show up only as dumps that quietly stopped
# carrying symbols, exactly when someone is reading one to debug a failure.
#
# So assert it end-to-end on a green boot, whose log always contains both
# shapes: the deliberate #BP trap self-test (a kernel address) and crash.bin's
# contained access violation (a user address in a boot module's ELF).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG="${1:-$ROOT/build/serial.sym.log}"

if ! command -v llvm-symbolizer >/dev/null 2>&1 || ! command -v llvm-nm >/dev/null 2>&1; then
    # Pass-through is the documented degradation, not a failure; say so by name
    # rather than reporting a PASS nobody proved.
    echo "[KTEST] symbolize SKIP (no llvm-symbolizer/llvm-nm on PATH)"
    exit 0
fi

if [[ ! -s "$LOG" ]]; then
    echo "[KTEST] symbolize FAIL (no symbolized log at $LOG)"
    exit 1
fi

fails=0

# The kernel resolver: an address in the -2 GiB region annotated with a symbol
# AND a kernel/ source location (llvm-symbolizer + the DWARF, not just nm).
if grep -qE '0xffffffff8[0-9a-f]{7} [A-Za-z_][A-Za-z0-9_]*(\+0x[0-9a-f]+)? \(kernel/' "$LOG"; then
    echo "[KTEST] symbolize-kernel PASS"
else
    echo "[KTEST] symbolize-kernel FAIL (no kernel address resolved in $LOG)"
    fails=$((fails + 1))
fi

# The module resolver: crash.bin's faulting RIP, resolved through the .elf kept
# beside the flat .bin — this one also proves the [USERFAULT] block's
# image-name association, the part with no other test coverage at all.
if grep -qE 'RIP=0x[0-9a-f]{16} main(\+0x[0-9a-f]+)? \(tests/boot/crash\.c:[0-9]+\)' "$LOG"; then
    echo "[KTEST] symbolize-user PASS"
else
    echo "[KTEST] symbolize-user FAIL (crash.bin's faulting RIP unresolved in $LOG)"
    fails=$((fails + 1))
fi

if [[ "$fails" -ne 0 ]]; then
    echo "== symcheck: FAIL ($fails) — a dump-print format or link base moved out"
    echo "   from under tools/symbolize.py; see its address regexes."
    exit 1
fi
echo "== symcheck: 0 failing =="
