#!/usr/bin/env bash
#
# run.sh — the ntapi runner. Two modes, one shape (docs/08, docs/14).
#
#   run.sh oracle     Build+run EVERY tests/ntapi test against the host ntdll
#                     (Wine/Windows). This is the SPEC gate: it must be all-green
#                     before you may implement the corresponding kernel code.
#
#   run.sh proskrnl   Build the manifest.txt subset into a disk image and run it
#                     under QEMU. This is the REGRESSION gate: it must stay
#                     all-green as the boundary is implemented.
#
# Verdict protocol: each test emits one machine-greppable line
#     [KTEST] <name> PASS
#     [KTEST] <name> FAIL failures=<n> todo_unexpected=<n>
# We grep those; nothing parses free-text. Exit non-zero iff any test FAILs.
#
# Pre-M1 status: the proskrnl mode is stubbed (needs the kernel + toolchain);
# oracle mode needs a Windows-targeting toolchain (e.g. x86_64-w64-mingw32-gcc)
# and, off Windows, wine to run the resulting .exe.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NTAPI="$ROOT/tests/ntapi"
BUILD="$ROOT/build/tests"
MODE="${1:-}"

: "${CC_ORACLE:=x86_64-w64-mingw32-gcc}"   # override for a different mingw

# The oracle wine: PREFER the pinned third_party/wine build (built in-tree by
# tools/setup_linux.sh) so the oracle can never diverge from the Wine version
# the abi/ contract is generated from; $WINE overrides, host wine is the
# fallback.
find_wine() {
    local w
    for w in "$ROOT/third_party/wine/wine64" "$ROOT/third_party/wine/wine"; do
        [[ -x "$w" ]] && { echo "$w"; return 0; }
    done
    echo "wine"
}
: "${WINE:=$(find_wine)}"                  # runner for the .exe when not on Windows
CFLAGS_COMMON="-std=c11 -O1 -g -Wall -Wextra -I$ROOT -I$NTAPI"

# Every test = a .c under tests/ntapi/<bucket>/ (excludes the harness itself).
all_tests() { find "$NTAPI" -name '*.c' ! -name 'ntapi.c' | sort; }

# Manifest -> absolute .c paths (proskrnl mode only).
manifest_tests() {
    grep -vE '^\s*(#|$)' "$NTAPI/manifest.txt" | while read -r rel; do
        echo "$NTAPI/${rel}.c"
    done
}

run_verdicts() {   # stdin: raw test output -> tee + return fail count
    grep -E '^\[KTEST\] ' || true
}

oracle() {
    mkdir -p "$BUILD"
    local fails=0
    while read -r src; do
        local name exe out
        name="$(basename "${src%.c}")"
        exe="$BUILD/oracle_$name.exe"
        "$CC_ORACLE" $CFLAGS_COMMON -DNTAPI_ORACLE "$src" "$NTAPI/ntapi.c" \
            -lntdll -o "$exe"
        out="$("$WINE" "$exe" 2>&1 || true)"
        echo "$out"
        # tr -d '\r': the .exe's CRT writes CRLF; wine passes it through verbatim.
        echo "$out" | tr -d '\r' | grep -qE "^\[KTEST\] $name PASS$" || fails=$((fails+1))
    done < <(all_tests)
    echo "== oracle: $fails failing =="
    return $(( fails > 0 ? 1 : 0 ))
}

proskrnl() {
    echo "proskrnl mode is not wired up yet (needs M1 kernel + M4 syscall stubs)."
    echo "When it is: compile the manifest subset with -DNTAPI_PROSKRNL against"
    echo "tests/ntapi/syscall/, bake into build/disk.img, boot QEMU with"
    echo "isa-debug-exit + -serial stdio, then run_verdicts over the serial log."
    manifest_tests >/dev/null   # validate manifest parses
    return 0
}

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    *) echo "usage: $0 {oracle|proskrnl}" >&2; exit 2 ;;
esac
