#!/usr/bin/env bash
# uacheck.sh — a ring-0 fault on a user address is a defect, not a status.
#
#   uacheck.sh <serial log> [<serial log>...]     # explicit logs
#   uacheck.sh --since <marker file> <dir>        # every log in <dir> newer
#                                                 # than <marker> (run.sh)
#
# WHY THIS EXISTS (issue #32 A3). The system service dispatcher arms a ring-0
# fault recovery frame around every ring-3-originated service (kernel/syscall/
# uaccess.h): a fault on a user address inside a service returns
# STATUS_ACCESS_VIOLATION instead of halting the machine. That is correct and
# load-bearing — an unprivileged process must not be able to halt the kernel
# by unmapping a buffer mid-service — and it DESTROYED the signal for the very
# class it backstops. Before it, a missing probe was a [PANIC] with a stack
# trace, impossible to miss. After it, the same missing probe is a silent
# STATUS_ACCESS_VIOLATION indistinguishable from a caller that passed a bad
# pointer on purpose, i.e. from ordinary operation. The backstop stays a
# backstop; this stops it from being camouflage.
#
# WHAT IT CHECKS. The kernel names every unwind on serial:
#
#     [UACCESS] <name> va=<addr> rip=<addr> count=<n>              <- a defect
#     [UACCESS] expected <name> va=<addr> rip=<addr> count=<n>     <- claimed
#
# Any untagged line fails the leg. `expected` is written by exactly one
# arming site in the tree (tests/kmt/m4_usermode.c test_kernel_fault_recovery,
# which provokes the unwind deliberately and convicts the counting itself);
# `git grep 'KiArmFaultRecovery(.*TRUE'` is the complete list of claims.
#
# READING A FAILURE. The rip names the instruction that touched the user
# address with no live probe behind it, and the name says which service was
# running. Every leg writes a symbolized sidecar next to its raw log
# (tools/qemu.sh, tools/symbolize.py) — read the [UACCESS] line THERE and the
# rip resolves to a function and line. The fix is a probe (or a probe token,
# uaccess.h) at that site, never a wider recovery frame.
#
# SCOPE. Every leg: `make test` runs it directly, and tests/run/run.sh runs it
# over every serial log a leg produced. A leg that boots no kernel (the oracle)
# produces no logs and passes vacuously.
set -uo pipefail

logs=()
if [[ "${1:-}" == "--since" ]]; then
    marker="${2:?usage: uacheck.sh --since <marker> <dir>}"
    dir="${3:?usage: uacheck.sh --since <marker> <dir>}"
    [[ -d "$dir" ]] || exit 0
    # The raw logs only: the .sym.log sidecar is the same lines decorated, and
    # counting both would double every offender.
    while IFS= read -r f; do
        logs+=("$f")
    done < <(find "$dir" -name '*.log' ! -name '*.sym.log' -newer "$marker" 2>/dev/null)
else
    (($# > 0)) || { echo "usage: uacheck.sh <serial log>... | --since <marker> <dir>" >&2; exit 2; }
    logs=("$@")
fi

((${#logs[@]})) || exit 0

fails=0
for log in "${logs[@]}"; do
    [[ -s "$log" ]] || continue
    # Untagged = unclaimed. Matching on the prefix rather than on "not
    # expected" anywhere in the line keeps a service NAMED "expected..." from
    # excusing itself.
    hits="$(grep -aE '^\[UACCESS\] ' "$log" 2>/dev/null | grep -avE '^\[UACCESS\] expected ' || true)"
    [[ -n "$hits" ]] || continue
    n="$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
    echo "[KTEST] uacheck FAIL ($n unclaimed ring-0 user-address fault(s) in $log)"
    printf '%s\n' "$hits" | head -10 | sed 's/^/    /'
    fails=$((fails + n))
done

if [[ "$fails" -ne 0 ]]; then
    echo "== uacheck: FAIL ($fails) — a service reached a user address with no live"
    echo "   probe behind it; the recovery frame turned it into STATUS_ACCESS_VIOLATION."
    echo "   Read the rip in the .sym.log sidecar and add the probe (issue #32 A3)."
    exit 1
fi
echo "== uacheck: 0 unclaimed ring-0 user-address faults (${#logs[@]} log(s)) =="
