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

# M4 (docs/14): build each manifest test as a flat binary (crt0 + generated
# syscall stubs + the proskrnl ntapi.c + the test), bake them into a disk
# image as Limine boot modules, boot the kernel under QEMU, and read each
# test's own [KTEST] <name> PASS line off the serial log. The kernel runs
# every module as a user process (kernel/init/main.c); a test that fails an
# ok() exits nonzero and prints FAIL.
proskrnl() {
    local llvm cc ld objcopy build kernel img
    llvm="$(dirname "$(command -v clang)")"
    cc="$llvm/clang"
    ld="ld.lld"
    objcopy="$llvm/llvm-objcopy"
    build="$ROOT/build/tests/proskrnl"
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/proskrnl.hdd"
    mkdir -p "$build"

    # The kernel image must exist (make builds it); build it if missing.
    if [[ ! -f "$kernel" ]]; then
        make -C "$ROOT" >/dev/null
    fi

    local ucflags="-std=c11 -target x86_64-unknown-none -ffreestanding \
        -fno-stack-protector -fno-pie -fno-pic -m64 -march=x86-64 \
        -mno-mmx -mno-sse -mno-sse2 -mno-80387 -O2 -g -I$ROOT -I$NTAPI \
        -DNTAPI_PROSKRNL"
    local uldflags="-m elf_x86_64 -static -T $ROOT/user/init-tests/user.ld --build-id=none"

    # Shared runtime objects (crt0 + generated stubs + harness).
    # shellcheck disable=SC2086
    $cc $ucflags -c "$ROOT/user/init-tests/crt0.S" -o "$build/crt0.o"
    # shellcheck disable=SC2086
    $cc $ucflags -c "$NTAPI/syscall/syscall_stubs.S" -o "$build/stubs.o"
    # shellcheck disable=SC2086
    $cc $ucflags -c "$NTAPI/ntapi.c" -o "$build/ntapi.o"

    local specs=() names=()
    while read -r rel _rest; do
        local name bin
        name="$(basename "$rel")"
        bin="$build/$name.bin"
        # shellcheck disable=SC2086
        $cc $ucflags -c "$NTAPI/$rel.c" -o "$build/$name.o"
        # shellcheck disable=SC2086
        $ld $uldflags "$build/crt0.o" "$build/stubs.o" "$build/ntapi.o" "$build/$name.o" \
            -o "$build/$name.elf"
        "$objcopy" -O binary "$build/$name.elf" "$bin"
        specs+=("$bin=expect=0")
        names+=("$name")
    done < <(grep -vE '^\s*(#|$)' "$NTAPI/manifest.txt")

    if [[ ${#names[@]} -eq 0 ]]; then
        echo "== proskrnl: manifest is empty (nothing to run) =="
        return 0
    fi

    "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    local log="$ROOT/build/tests/proskrnl-serial.log"
    LOG="$log" PASS_RE="\[KTEST\] M4 PASS" TIMEOUT="${TIMEOUT:-60}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    local fails=0
    for name in "${names[@]}"; do
        if grep -qE "^\[KTEST\] $name PASS$" "$log" 2>/dev/null; then
            echo "[KTEST] $name PASS"
        else
            echo "[KTEST] $name FAIL"
            fails=$((fails + 1))
        fi
    done
    echo "== proskrnl: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    *) echo "usage: $0 {oracle|proskrnl}" >&2; exit 2 ;;
esac
