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
# fallback. The pinned tree is the PATCHED proskrnl-target fork by design
# (docs/06 "One tree, three roles"): every seam commit is dormant when a
# unixlib is present, so running the oracle on it both enforces that dormancy
# and exercises the identical PE ntdll.dll bytes the Makefile's WINFILES bake
# onto proskrnl's boot volume.
find_wine() {
    local w
    for w in "$ROOT/third_party/wine/wine64" "$ROOT/third_party/wine/wine"; do
        [[ -x "$w" ]] && { echo "$w"; return 0; }
    done
    echo "wine"
}
: "${WINE:=$(find_wine)}"                  # runner for the .exe when not on Windows

# Oracle runs get a scratch prefix under build/ (created by wine on first
# use): the M8 sem_reg tests write real registry keys, and they must land in
# a disposable registry, never the developer's ~/.wine. $WINEPREFIX overrides.
: "${WINEPREFIX:=$BUILD/wineprefix}"
export WINEPREFIX
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
        -mno-mmx -mno-sse -mno-sse2 -mno-80387 \
        -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
        -O2 -g -I$ROOT -I$NTAPI -DNTAPI_PROSKRNL"
    local uldflags="-m elf_x86_64 -static -T $ROOT/user/init-tests/user.ld --build-id=none"

    # Shared runtime objects (crt0 + generated stubs + harness).
    # shellcheck disable=SC2086
    $cc $ucflags -c "$ROOT/user/init-tests/crt0.S" -o "$build/crt0.o"
    # shellcheck disable=SC2086
    $cc $ucflags -c "$NTAPI/syscall/syscall_stubs.S" -o "$build/stubs.o"
    # shellcheck disable=SC2086
    $cc $ucflags -c "$NTAPI/ntapi.c" -o "$build/ntapi.o"

    # The M5 RAM-disk seed files (built by make with the kernel): kmt's
    # image/file section tests read them; they are data, never run.
    local specs=() names=()
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    # The M7 NLS data files (sem_ps/nls_files): the same pinned-Wine tables
    # the kernel serves from C:\windows\system32 (Makefile WINFILES).
    for nls in locale l_intl c_1252 c_437 sortdefault normnfc normnfd normnfkc normnfkd normidna; do
        [[ -f "$ROOT/third_party/wine/nls/$nls.nls" ]] && \
            specs+=("win:$ROOT/third_party/wine/nls/$nls.nls=windows/system32/$nls.nls")
    done
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
    LOG="$log" PASS_RE="\[KTEST\] M6 PASS" TIMEOUT="${TIMEOUT:-60}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # Symbolized sidecar for a human/LLM reading a failure (Art. 9); the
    # verdict greps below stay on the raw log.
    "$ROOT/tools/symbolize.py" --kernel "$kernel" --moduledir "$build" \
        --moduledir "$ROOT/build/modules" < "$log" \
        > "$ROOT/build/tests/proskrnl-serial.sym.log" 2>/dev/null || true

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

# The differential fuzzer (docs/08, tests/fuzz/): random Nt* sequences run on
# both the oracle and proskrnl, divergence == bug. Delegates to fuzz.py, which
# reuses the exact build recipes above. All args after `fuzz` are forwarded.
fuzz() { exec "$ROOT/tests/fuzz/fuzz.py" "$@"; }

# The M8 persistence acceptance (docs/02 "a value written by a user program
# survives reboot"): boot the SAME disk image twice. The m8_persist boot
# module seeds registry values on boot 1 (hive absent) and byte-verifies them
# — and the volatile key's absence — on boot 2, when the kernel has reloaded
# the hive the first boot wrote.
persist() {
    # A VIRGIN image: build/proskrnl.hdd may already carry a seeded hive from
    # an earlier `make run` (m8_persist runs on every boot), which would make
    # boot 1 verify instead of seed. Rebuilding the image resets the disk.
    rm -f "$ROOT/build/proskrnl.hdd"
    make -C "$ROOT" >/dev/null
    local img="$ROOT/build/tests/persist.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl.hdd" "$img"

    local log1="$ROOT/build/tests/persist1.log" log2="$ROOT/build/tests/persist2.log"
    LOG="$log1" TIMEOUT="${TIMEOUT:-60}" "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q 'm8_persist: seeded' "$log1" || \
       ! grep -qE '^\[KTEST\] module /m8_persist.bin PASS' "$log1"; then
        echo "== persist: FAIL (boot 1 did not seed; see $log1) =="
        return 1
    fi
    LOG="$log2" TIMEOUT="${TIMEOUT:-60}" "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q 'm8_persist: verified' "$log2" || \
       ! grep -qE '^\[KTEST\] module /m8_persist.bin PASS' "$log2" || \
       ! grep -qE '^\[KTEST\] M8 PASS' "$log2"; then
        echo "== persist: FAIL (boot 2 did not verify; see $log2) =="
        return 1
    fi
    echo "== persist: PASS (seeded on boot 1, verified after reboot) =="
    return 0
}

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    fuzz)     fuzz "${@:2}" ;;
    persist)  persist ;;
    *) echo "usage: $0 {oracle|proskrnl|fuzz [fuzz.py options]|persist}" >&2; exit 2 ;;
esac
