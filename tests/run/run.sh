#!/usr/bin/env bash
#
# run.sh — the ntapi runner. ONE binary per test, two runners (docs/08,
# docs/14): every test is a single mingw-built, CRT-less PE .exe linked
# against the pinned Wine import libraries.
#
#   run.sh oracle     Run every test .exe under the pinned Wine. This is the
#                     SPEC gate: it must be all-green before you may implement
#                     the corresponding kernel code.
#
#   run.sh proskrnl   Bake the SAME .exes (plus the Wine PE userland) into a
#                     disk image under C:\ntapi and boot it: the kernel's
#                     ntapi runner (kernel/init/main.c) sweeps the directory
#                     and runs each test. This is the REGRESSION gate: it must
#                     stay all-green as the boundary is implemented.
#
#   run.sh winetest   The M10 stretch gate: run the curated manifest of
#                     Wine's-own-test-suite pairs (tests/winetest/) under the
#                     oracle AND on proskrnl. Same one-binary discipline.
#
# Verdict protocol: each test emits one machine-greppable line
#     [KTEST] <name> PASS
#     [KTEST] <name> FAIL failures=<n> todo_unexpected=<n>
# We grep those; nothing parses free-text. Exit non-zero iff any test FAILs.
#
# Needs a Windows-targeting toolchain (x86_64-w64-mingw32-gcc) and the pinned
# third_party/wine build (tools/setup_linux.sh) for the import libraries, the
# oracle runtime, and the DLLs/NLS files the proskrnl image bakes.

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

# The pinned Wine import libraries the test .exes link against (built by
# tools/setup_linux.sh). Import libs bind by DLL name, so the same .exe
# resolves against Wine's ntdll under the oracle and against the baked
# C:\windows\system32 DLLs on proskrnl.
WINE_PE="$ROOT/third_party/wine/dlls"
WINE_LIBS=("$WINE_PE/kernel32/x86_64-windows/libkernel32.a"
           "$WINE_PE/kernelbase/x86_64-windows/libkernelbase.a"
           "$WINE_PE/ntdll/x86_64-windows/libntdll.a")

# Every test = a .c under tests/ntapi/<bucket>/ (excludes the harness itself
# and the helper-DLL sources under dll/).
all_tests() { find "$NTAPI" -name '*.c' ! -name 'ntapi.c' ! -path '*/dll/*' | sort; }

# The search-order probe DLL (sem_ps/dll_load.c): built beside the test
# .exes so a bare-name LoadLibrary resolves it from the application
# directory. CRT-less like everything else here.
build_helper_dll() {   # echoes the .dll path
    local dll="$BUILD/ntapi/prshelper.dll"
    if [[ ! -f "$dll" || "$NTAPI/dll/prshelper.c" -nt "$dll" ]]; then
        "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -shared -Wl,--entry=DllMainCRTStartup "$NTAPI/dll/prshelper.c" \
            "${WINE_LIBS[@]}" -lgcc -o "$dll" >&2
    fi
    echo "$dll"
}

# Build one test into build/tests/ntapi/<name>.exe: no CRT (-nostdlib, entry
# ntapi_start in ntapi.c), the pinned Wine import libs, -lgcc for the mingw
# helpers the compiler may emit (___chkstk_ms). Skips work when up to date.
build_test() {   # $1 = .c path; echoes the .exe path
    local src="$1" name exe
    name="$(basename "${src%.c}")"
    exe="$BUILD/ntapi/$name.exe"
    if [[ ! -f "$exe" || "$src" -nt "$exe" || "$NTAPI/ntapi.c" -nt "$exe" || \
          "$NTAPI/ntapi.h" -nt "$exe" ]]; then
        "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -Wl,--entry=ntapi_start "$src" "$NTAPI/ntapi.c" \
            "${WINE_LIBS[@]}" -lgcc -o "$exe" >&2
    fi
    echo "$exe"
}

oracle() {
    mkdir -p "$BUILD/ntapi"
    build_helper_dll >/dev/null
    local fails=0
    while read -r src; do
        local name exe out
        name="$(basename "${src%.c}")"
        exe="$(build_test "$src")"
        out="$("$WINE" "$exe" 2>&1 || true)"
        echo "$out"
        # tr -d '\r': tolerate CRLF if a console handle translates.
        echo "$out" | tr -d '\r' | grep -qE "^\[KTEST\] $name PASS$" || fails=$((fails+1))
    done < <(all_tests)

    # M10: the standalone cmd.exe (Wine's cmd objects + user/cmd glue) is
    # spec-checked off-target here — the same binary the console image bakes
    # must behave under the oracle (docs/06 one-tree discipline).
    make -C "$ROOT" build/modules/cmd.exe >/dev/null
    local cmdexe="$ROOT/build/modules/cmd.exe" cmdout
    cmdout="$(cd "$BUILD" && "$WINE" "$cmdexe" /c \
        "echo smoke-echo & echo smoke-data > cmdsmoke.txt & type cmdsmoke.txt & del cmdsmoke.txt" \
        2>/dev/null | tr -d '\r')"
    if echo "$cmdout" | grep -q "smoke-echo" && echo "$cmdout" | grep -q "smoke-data"; then
        echo "[KTEST] cmd-standalone PASS"
    else
        echo "[KTEST] cmd-standalone FAIL"
        fails=$((fails+1))
    fi
    echo "== oracle: $fails failing =="
    return $(( fails > 0 ? 1 : 0 ))
}

# Bake the SAME .exes into a disk image under C:\ntapi beside the Wine PE
# userland (ntdll/kernel32/kernelbase + the NLS tables), boot it, and read
# each test's own [KTEST] <name> PASS line off the serial log. The kernel's
# ntapi runner (kernel/init/main.c) sweeps C:\ntapi, runs every .exe as a
# console-less Wine process, and prints '[KTEST] ntapi done' when the sweep
# finishes — the boot's stop condition here.
proskrnl() {
    local kernel img
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/proskrnl.hdd"
    mkdir -p "$BUILD/ntapi"

    # The kernel image must exist (make builds it); build it if missing.
    if [[ ! -f "$kernel" ]]; then
        make -C "$ROOT" >/dev/null
    fi

    # The M5 RAM-disk seed files (built by make with the kernel): kmt's
    # image/file section tests read them; they are data, never run.
    local specs=() names=()
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    # The Wine PE userland the tests run on (the same files Makefile WINFILES
    # bakes for `make test`). M10 widens the set to the CUI DLLs.
    for dll in ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
               cryptbase; do
        specs+=("win:$WINE_PE/$dll/x86_64-windows/$dll.dll=windows/system32/$dll.dll")
    done
    specs+=("win:$(build_helper_dll)=ntapi/prshelper.dll")
    for nls in locale l_intl c_1252 c_437 c_20127 sortdefault normnfc normnfd normnfkc normnfkd \
               normidna; do
        [[ -f "$ROOT/third_party/wine/nls/$nls.nls" ]] && \
            specs+=("win:$ROOT/third_party/wine/nls/$nls.nls=windows/system32/$nls.nls")
    done
    while read -r src; do
        local name exe
        name="$(basename "${src%.c}")"
        exe="$(build_test "$src")"
        specs+=("win:$exe=ntapi/$name.exe")
        names+=("$name")
    done < <(all_tests)

    "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    local log="$ROOT/build/tests/proskrnl-serial.log"
    LOG="$log" PASS_RE="\[KTEST\] ntapi done" TIMEOUT="${TIMEOUT:-420}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # Symbolized sidecar for a human/LLM reading a failure (Art. 9); the
    # verdict greps below stay on the raw log.
    "$ROOT/tools/symbolize.py" --kernel "$kernel" \
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

# The M10 stretch gate (docs/02 "Ideal regression: the CUI subset of Wine's
# own test suite"): the curated manifest of <test_exe>:<subtest> pairs
# (tests/winetest/manifest.txt) must exit 0 under the pinned oracle AND on
# proskrnl. The binaries are the pinned tree's own test objects linked
# standalone (Makefile `wtests`) — ONE binary, two runners, like everything
# else here. On proskrnl the kernel sweep (kernel/init/main.c
# KiRunWineTests) reads the baked manifest, runs each pair on the console
# (winetest prints through msvcrt stdout -> conhost -> serial), and the exit
# code — winetest's failure count — is the verdict.
winetest() {
    local manifest="$ROOT/tests/winetest/manifest.txt"
    make -C "$ROOT" wtests >/dev/null
    mkdir -p "$BUILD/wtests"

    local pairs=()
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        pairs+=("$line")
    done < "$manifest"
    if [[ ${#pairs[@]} -eq 0 ]]; then
        echo "== winetest: manifest empty ==" >&2
        return 2
    fi

    # --- oracle leg (the SPEC gate: green here before the kernel side) ---
    local fails=0
    for pair in "${pairs[@]}"; do
        local exe="${pair%%:*}" sub="${pair#*:}"
        local olog="$BUILD/wtests/${exe}.${sub}.oracle.log"
        # scratch cwd: the cmd tests write test.cmd/test.out where they run
        if (cd "$BUILD/wtests" && "$WINE" "$ROOT/build/wtests/$exe" "$sub") >"$olog" 2>&1; then
            echo "[KTEST] wtest-oracle $pair PASS"
        else
            echo "[KTEST] wtest-oracle $pair FAIL (see $olog)"
            fails=$((fails+1))
        fi
    done

    # --- proskrnl leg (the REGRESSION gate) ---
    local kernel img
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/wtest.hdd"
    if [[ ! -f "$kernel" ]]; then
        make -C "$ROOT" >/dev/null
    fi
    make -C "$ROOT" build/modules/cmd.exe build/modules/conhost.exe >/dev/null

    # The Wine PE userland (the run.sh proskrnl set) + conhost (winetest
    # processes run on the console) + cmd.exe (%COMSPEC%, the cmd tests'
    # subject) + the test binaries and the manifest under C:\wtests. The M5
    # seed modules keep the in-kernel M6 suite green on this image too, and
    # the FULL nls set goes in — the CRT/codepage subtests exercise every
    # codepage the oracle has (a missing c_932.nls reads as a divergence).
    local specs=()
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    for dll in ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
               cryptbase; do
        specs+=("win:$WINE_PE/$dll/x86_64-windows/$dll.dll=windows/system32/$dll.dll")
    done
    local nlsfile
    for nlsfile in "$ROOT"/third_party/wine/nls/*.nls; do
        specs+=("win:$nlsfile=windows/system32/$(basename "$nlsfile")")
    done
    specs+=("win:$ROOT/build/modules/conhost.exe=windows/system32/conhost.exe")
    specs+=("win:$ROOT/build/modules/cmd.exe=windows/system32/cmd.exe")
    for exe in ntdll_test.exe kernel32_test.exe msvcrt_test.exe ucrtbase_test.exe \
               cmd.exe_test.exe; do
        specs+=("win:$ROOT/build/wtests/$exe=wtests/$exe")
    done
    specs+=("win:$manifest=wtests/manifest.txt")

    # MB-scale test binaries: a bigger volume than the 64 MB default. And
    # 1 GiB of guest RAM: no eviction (Art. 3) means the page cache holds
    # every test binary's pages for the whole sweep — memory is provisioned,
    # not managed.
    SIZE_MB=256 "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    local log="$ROOT/build/tests/wtest-serial.log"
    LOG="$log" MEM=1024M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-1200}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    "$ROOT/tools/symbolize.py" --kernel "$kernel" \
        --moduledir "$ROOT/build/modules" < "$log" \
        > "$ROOT/build/tests/wtest-serial.sym.log" 2>/dev/null || true

    # No ^ anchor: conhost cursor escapes may share the verdict's line (the
    # run.sh console precedent).
    for pair in "${pairs[@]}"; do
        if grep -qF "[KTEST] wtest $pair PASS" "$log" 2>/dev/null; then
            echo "[KTEST] wtest $pair PASS"
        else
            echo "[KTEST] wtest $pair FAIL"
            fails=$((fails + 1))
        fi
    done
    echo "== winetest: $fails failing =="
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
    # an earlier `make test` (m8_persist runs on every boot), which would make
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

# The M9 interactive-console acceptance (docs/02 "input typed into the
# serial console echoes through conhost"): boot the console-mode image with
# the serial wire on a unix socket, let console_expect.py type "ping" and
# assert conhost's echo, the cooked line, and the M9 verdict. The loop keeps
# the docs/08 shape — the expect script tees the wire into the log the
# verdict grep reads.
console() {
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/proskrnl-console.hdd"
    local sock="$ROOT/build/tests/console.sock" log="$ROOT/build/tests/console.log"
    mkdir -p "$ROOT/build/tests"

    SERIAL_SOCK="$sock" LOG="$log" TIMEOUT="${TIMEOUT:-180}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        # No ^ anchor: conhost cursor escapes may share the verdict's line.
        if grep -qE '\[KTEST\] module m9_echo.exe PASS' "$log" &&
           grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
            echo "== console: PASS (conhost echo + interactive cmd.exe session) =="
            return 0
        fi
    fi
    wait "$qemu_wrapper" 2>/dev/null || true
    echo "== console: FAIL (see $log) =="
    return 1
}

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    winetest) winetest ;;
    fuzz)     fuzz "${@:2}" ;;
    persist)  persist ;;
    console)  console ;;
    *) echo "usage: $0 {oracle|proskrnl|winetest|fuzz [fuzz.py options]|persist|console}" >&2
       exit 2 ;;
esac
