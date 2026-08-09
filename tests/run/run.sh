#!/usr/bin/env bash
#
# run.sh — the ntapi runner. ONE binary per test, two runners (docs/08,
# docs/14): every test is a single mingw-built, CRT-less PE .exe linked
# against the pinned Wine import libraries.
#
#   run.sh oracle     Run every test .exe under the pinned Wine. This is the
#                     SPEC gate: it must be all-green before you may implement
#                     the corresponding kernel code. The cases are fanned out
#                     over $ORACLE_JOBS workers, one disposable wineprefix
#                     each; the log is replayed in source order afterwards, so
#                     a parallel run reads exactly like a sequential one.
#
#   run.sh proskrnl   Bake the SAME .exes (plus the Wine PE userland) into a
#                     disk image under C:\ntapi and boot it: the kernel's
#                     ntapi runner (kernel/init/main.c) sweeps the directory
#                     and runs each test. This is the REGRESSION gate: it must
#                     stay all-green as the boundary is implemented.
#
#   Both legs take optional <subtest> arguments — a test's base name, or a
#   glob over base names — to run a SUBSET while iterating:
#
#       run.sh oracle   query_dir          # one test under the oracle
#       run.sh proskrnl query_dir          # bake+boot only that one .exe
#       run.sh proskrnl 'se_*' handle_life # globs and several names are fine
#
#   A subset run is for ITERATION, never for a verdict: the gates above are
#   the unfiltered runs, and only those may be reported as green. A pattern
#   that matches nothing is an error (with the list of names), so a typo can
#   never masquerade as "everything passed".
#
#   run.sh winetest   The M10 stretch gate: run the manifest of
#                     Wine's-own-test-suite pairs (tests/winetest/) — the full
#                     non-GUI sweep — under the oracle AND on proskrnl. Same
#                     one-binary discipline.
#
#                     It takes the same optional filter, over manifest PAIRS.
#                     A pair's name is <module>:<subtest> (the module being
#                     the exe without its _test.exe tail: ntdll, kernel32,
#                     msvcrt, ucrtbase, cmd); a bare word with no ':' matches
#                     either half, so:
#
#                         run.sh winetest ntdll:env       # one pair
#                         run.sh winetest ntdll           # a whole module
#                         run.sh winetest printf          # msvcrt + ucrtbase
#                         run.sh winetest 'rtl*' cmd      # globs and lists
#
#                     Same rules as above: iteration only (the subset boots
#                     its own image, build/tests/wtest-subset.hdd, so it can
#                     never be mistaken for the gate's), and a pattern that
#                     matches no pair is an error.
#
#                     WTEST_NO_ORACLE=1 skips the oracle half while iterating
#                     on the kernel side of a pair whose oracle verdict you
#                     already have. It is REFUSED without a filter — the gate
#                     is both legs, always.
#
#   run.sh prebuild   Build every test .exe and run NOTHING. It is a build
#                     step, never a verdict: it exists so a caller that runs
#                     the two ntapi legs in separate sandboxes
#                     (tools/fulltest.sh) pays the ~165 mingw compiles once,
#                     fanned out over $ORACLE_JOBS, instead of once per leg —
#                     the `proskrnl` leg builds them one at a time, and at
#                     ~1.2 s each that is three minutes of the leg's clock.
#                     Both legs then find their .exes up to date and behave
#                     exactly as they always did.
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
# The optional subtest filter (see the header). Only the two ntapi legs and
# the winetest leg take one — every other mode's arguments mean something
# else (`fuzz` forwards its own), so the filter stays empty for them and they
# behave exactly as before. The ntapi legs filter tests/ntapi base names; the
# winetest leg filters manifest pairs (wtest_matches below).
SUBTESTS=()
case "$MODE" in oracle|proskrnl|winetest) SUBTESTS=("${@:2}") ;; esac

: "${CC_ORACLE:=x86_64-w64-mingw32-gcc}"   # override for a different mingw

# The oracle wine: PREFER the pinned third_party/wine build (built in-tree by
# tools/setup_linux.sh) so the oracle can never diverge from the Wine version
# the abi/ contract is generated from; $WINE overrides, host wine is the
# fallback. The pinned tree is the PATCHED proskrnl-target fork by design
# (docs/06 "One tree, three roles"): every seam commit is dormant when a
# unixlib is present, so running the oracle on it both enforces that dormancy
# and exercises the identical PE ntdll.dll bytes the Makefile's WINFILES bake
# onto proskrnl's boot volume.
#
# The pinned wine is wrapped so its font backend resolves to the PINNED
# FreeType: win32u.so does not link that backend, it dlopen()s
# SONAME_LIBFREETYPE ("libfreetype.so.6", recorded by configure) with no
# rpath of its own, and when the open fails it does not fail — it proceeds
# with no fonts at all, which is exactly the silent divergence the
# font-metrics oracle was rebuilt to remove (GUI-3; docs/03 "the font
# oracle"). The path goes in a WRAPPER rather than this script's environment
# because it must reach wine and nothing else: our FreeType is built for
# win32u's needs, not as a system library, and QEMU's GTK stack loads the
# distro fontconfig, which wants symbols this build does not export
# (FT_Get_BDF_Property) — an exported LD_LIBRARY_PATH stops QEMU from
# starting at all. A caller-supplied $WINE is left alone: it pairs with
# whatever FreeType that wine was built against.
find_wine() {
    local w
    for w in "$ROOT/third_party/wine/wine64" "$ROOT/third_party/wine/wine"; do
        [[ -x "$w" ]] || continue
        local wrapper="$BUILD/wine-fonts"
        mkdir -p "$BUILD"
        cat >"$wrapper" <<EOF
#!/bin/sh
# GENERATED by tests/run/run.sh — hands the pinned wine the pinned FreeType.
LD_LIBRARY_PATH="$ROOT/third_party/freetype/x86_64-linux\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
exec "$w" "\$@"
EOF
        chmod +x "$wrapper"
        echo "$wrapper"
        return 0
    done
    echo "wine"
}
: "${WINE:=$(find_wine)}"                  # runner for the .exe when not on Windows

# Oracle runs get a scratch prefix under build/ (created by wine on first
# use): the M8 sem_reg tests write real registry keys, and they must land in
# a disposable registry, never the developer's ~/.wine. $WINEPREFIX overrides.
: "${WINEPREFIX:=$BUILD/wineprefix}"
export WINEPREFIX

# Keep mscoree/mshtml unloadable in every oracle prefix: wine.inf's
# RegisterDllsSection registers both, and their DllRegisterServer is the
# Wine Mono / Gecko INSTALLER (dlls/mscoree/mscoree_main.c
# install_wine_mono, via appwiz.cpl) — a multi-minute download on every
# fresh-prefix init, and addon state the proskrnl side never has. The
# override makes setupapi's registration warn-and-continue instead.
: "${WINEDLLOVERRIDES:=mscoree,mshtml=}"
export WINEDLLOVERRIDES

# The oracle's HOST locale must be UTF-8, and the runner pins it rather than
# inheriting whatever the shell has. Wine derives its UNIX CODEPAGE from the
# host locale (dlls/ntdll/unix/locale.c init_locale -> setlocale/nl_langinfo);
# under C/POSIX that codepage cannot represent the non-ASCII names several
# subtests create, so the oracle answers for a spec it corrupted on the way
# out: `ntdll:directory` failed 82 checks and `ucrtbase:file` died outright
# (file.c:206, "failed to create t\xc3\xa4...txt with locale German.utf8"),
# and BOTH go green — 0 failures — with nothing changed but this. proskrnl
# has no host to inherit from, so an untouched-encoding oracle is also the
# only one the kernel leg can be differential against.
#
# C.UTF-8 rather than a language locale: the encoding is what Wine reads
# here, and C.UTF-8 is the one UTF-8 locale glibc always carries (no
# locale-gen, no distro variance). A caller-supplied $LC_ALL wins — pairing
# the oracle with another locale is a legitimate experiment.
: "${LC_ALL:=C.UTF-8}"
export LC_ALL

# The oracle must not run as ROOT, and this refuses rather than warns. Wine
# maps NT's access checks onto the host's unix permission bits, and root
# bypasses those bits — so every subtest that asserts a REFUSAL gets a
# success instead, and the oracle answers a spec that is wrong in the one
# direction nothing downstream can detect. Measured on the pinned tree, root
# vs. an ordinary user, nothing else changed: ntdll:file 6 failures -> 0,
# kernel32:profile 4 -> 0, kernel32:version 36 -> 0. All three read as
# proskrnl-side divergences until the runner was moved off root.
#
# ORACLE_ALLOW_ROOT=1 is the escape hatch for a container that has no other
# user (it prints what it is buying). CI runs unprivileged, so the gate path
# never takes it.
# `winetest` with WTEST_NO_ORACLE runs no oracle at all, so root is harmless
# there — the guard asks what this invocation will actually run, not what the
# mode usually runs.
RUNS_ORACLE=0
case "$MODE" in
    oracle|fuzz) RUNS_ORACLE=1 ;;
    winetest)    [[ -z "${WTEST_NO_ORACLE:-}" ]] && RUNS_ORACLE=1 ;;
esac
if [[ "$(id -u)" -eq 0 && -z "${ORACLE_ALLOW_ROOT:-}" ]]; then
    case "$RUNS_ORACLE" in
        1)
            echo "run.sh: refusing to run the oracle as root — wine maps NT access checks" >&2
            echo "        onto unix permission bits, which root bypasses, so every subtest" >&2
            echo "        asserting a REFUSAL silently passes (measured: ntdll:file 6->0," >&2
            echo "        kernel32:profile 4->0, kernel32:version 36->0). Run as an" >&2
            echo "        ordinary user, or set ORACLE_ALLOW_ROOT=1 to accept false greens." >&2
            exit 2 ;;
    esac
fi
if [[ "$(id -u)" -eq 0 && -n "${ORACLE_ALLOW_ROOT:-}" && "$RUNS_ORACLE" -eq 1 ]]; then
    echo "== run.sh: ORACLE_ALLOW_ROOT — oracle runs as root; every access-denied" \
         "assertion is a false green ==" >&2
fi

# Fan-out width of the oracle leg (see oracle() for what each worker gets).
# One worker per core: the work is one short-lived process per case, so it
# scales until the cores run out. ORACLE_JOBS=1 is the strictly sequential
# run — the fallback where nproc is absent, and what to set when a case is
# under suspicion of depending on its neighbours.
: "${ORACLE_JOBS:=$(nproc 2>/dev/null || echo 1)}"
ORACLE_OUT="$BUILD/ntapi/out"   # per-case captured output; oracle() owns it

# Per-case wall-clock cap on the oracle leg. A wedged case must fail THAT case,
# by name, instead of consuming the job: the workers' logs are replayed only
# after every worker has finished (see oracle_worker), so one process that
# never returns emits nothing at all — the whole leg's output is lost, not just
# the hung case's, and the CI job dies at its 60-minute timeout-minutes cap
# with the runner's orphan list as the only surviving evidence. That is
# precisely how sem_file/io_teardown cost two 60-minute jobs (issue #118).
# The winetest leg has had per-pair timeouts since it was written (the
# manifest's optional third field); the ntapi legs had none. The proskrnl leg
# needs none — its cases run inside a boot qemu.sh already bounds with $TIMEOUT.
#
# 180 s is a BACKSTOP, not a budget: the whole leg, every case over every
# worker, runs in about four minutes, so no honest case comes near it.
: "${ORACLE_CASE_TIMEOUT:=180}"

# Cases that must run ALONE — every worker idle — because what they measure is
# the MACHINE rather than the boundary. A per-worker prefix cannot isolate
# this: the quantity is host-global, and the neighbours are the load.
#
#   times   sem_ps/times.c asserts SystemProcessorPerformanceInformation's
#           idle counter GREW across a 60 ms sleep. The oracle's Wine answers
#           that class out of the host's /proc/stat, so on a runner whose every
#           core is busy running the rest of this leg the counter does not move
#           and the case fails — as it did on the first sharded CI run, having
#           passed sequentially forever. The assertion is right and the test
#           stays unchanged (fixing the oracle to suit the harness is backwards
#           — Art. 6): a busy machine is simply a different machine, so we stop
#           making it busy.
#
# Add a name here only with that shape of reason, and say which quantity is
# host-global. A case that merely LOOKS timing-ish belongs in the fan-out.
ORACLE_SERIAL_CASES="times"

oracle_is_serial() {   # $1 = test base name
    local name
    for name in $ORACLE_SERIAL_CASES; do
        [[ "$1" == "$name" ]] && return 0
    done
    return 1
}
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
all_sources() { find "$NTAPI" -name '*.c' ! -name 'ntapi.c' ! -path '*/dll/*' | sort; }

# The $SUBTESTS filter (see the header): with no filter EVERYTHING is
# selected, so the unfiltered gates behave exactly as before. Base names are
# unique across the buckets, so a name — or a glob over names — identifies a
# test without its directory.
selected() {   # $1 = test base name
    local name="$1" pat
    (( ${#SUBTESTS[@]} == 0 )) && return 0
    for pat in "${SUBTESTS[@]}"; do
        # shellcheck disable=SC2053  -- $pat is a glob on purpose
        [[ "$name" == $pat ]] && return 0
    done
    return 1
}

# The selected subset of the test sources — what both legs iterate over.
all_tests() {
    local src
    while read -r src; do
        selected "$(basename "${src%.c}")" && echo "$src"
    done < <(all_sources)
}

# A filter that matches nothing is a TYPO, not an empty run: a silently empty
# sweep prints "0 failing" and reads as green (Art. 12's spirit — a run that
# built nothing must not answer plausibly). $@ = the extra, non-tests/ntapi
# names this leg can also run, so `run.sh oracle fontdiff` is legal too.
check_subtests() {
    (( ${#SUBTESTS[@]} == 0 )) && return 0
    local universe=() src pat name hit
    while read -r src; do universe+=("$(basename "${src%.c}")"); done < <(all_sources)
    universe+=("$@")
    for pat in "${SUBTESTS[@]}"; do
        hit=0
        for name in "${universe[@]}"; do
            # shellcheck disable=SC2053
            [[ "$name" == $pat ]] && { hit=1; break; }
        done
        if (( ! hit )); then
            echo "run.sh: no test matches '$pat'. Known tests:" >&2
            printf '  %s\n' "${universe[@]}" | sort >&2
            exit 2
        fi
    done
    echo "== $MODE: subset run (${SUBTESTS[*]}) — NOT the gate; run unfiltered for a verdict =="
}

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
#
# The stale .exe is DELETED before the compiler runs, and a compile failure is
# fatal to the whole run. Neither is belt-and-braces: `oracle`/`proskrnl` are
# invoked as `... || fails=...` at the bottom of this file, which suppresses
# `set -e` throughout their bodies, so without the explicit check a test that
# fails to compile silently re-ran the PREVIOUS build's .exe and printed
# green. That is the same fabricated-plausible-answer failure Art. 12 forbids
# in the kernel, in the harness that judges it.
build_test() {   # $1 = .c path; echoes the .exe path
    local src="$1" name exe
    name="$(basename "${src%.c}")"
    exe="$BUILD/ntapi/$name.exe"
    if [[ ! -f "$exe" || "$src" -nt "$exe" || "$NTAPI/ntapi.c" -nt "$exe" || \
          "$NTAPI/ntapi.h" -nt "$exe" ]]; then
        rm -f "$exe"
        if ! "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -Wl,--entry=ntapi_start "$src" "$NTAPI/ntapi.c" \
            "${WINE_LIBS[@]}" -lgcc -o "$exe" >&2; then
            echo "run.sh: FAILED to build $src — no verdict for '$name'" >&2
            return 1
        fi
    fi
    echo "$exe"
}

# M10: the standalone cmd.exe (Wine's cmd objects + user/wine/programs/cmd glue) is
# spec-checked off-target here — the same binary the console image bakes
# must behave under the oracle (docs/06 one-tree discipline).
oracle_cmd_standalone() {
    make -C "$ROOT" build/modules/cmd.exe >/dev/null
    local cmdexe="$ROOT/build/modules/cmd.exe" cmdout
    cmdout="$(cd "$BUILD" && "$WINE" "$cmdexe" /c \
        "echo smoke-echo & echo smoke-data > cmdsmoke.txt & type cmdsmoke.txt & echo ren-data > cmdren.txt & ren cmdren.txt cmdren2.txt & type cmdren2.txt & del cmdsmoke.txt & del cmdren2.txt" \
        2>/dev/null | tr -d '\r')"
    # ren-data through the RENAMED name: the CUI-5 ren path spec-checked
    # off-target (the same cmd binary the files leg types at).
    if echo "$cmdout" | grep -q "smoke-echo" && echo "$cmdout" | grep -q "smoke-data" &&
       echo "$cmdout" | grep -q "ren-data"; then
        echo "[KTEST] cmd-standalone PASS"
        return 0
    fi
    echo "[KTEST] cmd-standalone FAIL"
    return 1
}

# GUI-3: the oracle is also the font-metrics oracle, and its font backend
# is dlopen'd -- when the open fails win32u proceeds with NO fonts rather
# than failing, so nothing above would notice. Ask it for a face and check
# it answers (tests/gdi/fontsmoke.c). Oracle-only: it links gdi32, which
# the proskrnl ntapi image does not carry.
oracle_fontsmoke() {
    local fontexe fontout
    fontexe="$BUILD/ntapi/fontsmoke.exe"
    if [[ ! -f "$fontexe" || "$ROOT/tests/gdi/fontsmoke.c" -nt "$fontexe" || \
          "$NTAPI/ntapi.c" -nt "$fontexe" ]]; then
        "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -Wl,--entry=ntapi_start "$ROOT/tests/gdi/fontsmoke.c" "$NTAPI/ntapi.c" \
            "${WINE_LIBS[@]}" "$WINE_PE/gdi32/x86_64-windows/libgdi32.a" -lgcc -o "$fontexe" >&2
    fi
    fontout="$("$WINE" "$fontexe" 2>&1 || true)"
    echo "$fontout"
    echo "$fontout" | tr -d '\r' | grep -qE '^\[KTEST\] fontsmoke PASS$'
}

# GUI-5: the metric differential itself (tests/gdi/fontdiff.c — the half
# docs/03 "the font oracle" deferred here). The same binary the gui5 leg
# bakes prints a fixed metric table; the oracle's table is pinned as
# tests/gdi/fontdiff.golden and re-diffed HERE on every run, so the
# golden can never go silently stale. The gui5 leg diffs the guest's
# table against the same file — exact integers, no epsilon (same pinned
# FreeType, same font bytes, 96 dpi on both sides). Regenerate with
# FONTDIFF_REFRESH=1 and commit the diff: a pin bump that moves a metric
# is a reviewed change, never a silent one.
oracle_fontdiff() {
    local fdexe fdout fdlines fdgold="$ROOT/tests/gdi/fontdiff.golden"
    fdexe="$BUILD/ntapi/fontdiff.exe"
    if [[ ! -f "$fdexe" || "$ROOT/tests/gdi/fontdiff.c" -nt "$fdexe" || \
          "$NTAPI/ntapi.c" -nt "$fdexe" ]]; then
        "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -Wl,--entry=ntapi_start "$ROOT/tests/gdi/fontdiff.c" "$NTAPI/ntapi.c" \
            "${WINE_LIBS[@]}" "$WINE_PE/gdi32/x86_64-windows/libgdi32.a" -lgcc -o "$fdexe" >&2
    fi
    fdout="$("$WINE" "$fdexe" 2>&1 || true)"
    echo "$fdout"
    fdlines="$(echo "$fdout" | tr -d '\r' | grep -E '^\[KTEST\] fontdiff (dpi=|face=|done )')"
    if ! echo "$fdout" | tr -d '\r' | grep -qE '^\[KTEST\] fontdiff PASS$'; then
        return 1
    elif [[ "${FONTDIFF_REFRESH:-0}" == "1" ]]; then
        echo "$fdlines" > "$fdgold"
        echo "== fontdiff: golden refreshed ($fdgold) — review and commit the diff =="
    elif ! diff -u "$fdgold" <(echo "$fdlines") >&2; then
        echo "[KTEST] fontdiff-golden FAIL (oracle metrics differ from tests/gdi/fontdiff.golden)"
        return 1
    else
        echo "[KTEST] fontdiff-golden PASS"
    fi
    return 0
}

# One oracle case, start to finish: build it, run it, and leave EVERYTHING it
# printed in $ORACLE_OUT/<name>. Nothing is echoed here — the log is replayed
# in source order after the workers finish (below), so a parallel run reads
# byte-for-byte like a sequential one. A build failure leaves no output file,
# which is how the grading loop tells "never built" from "ran and failed";
# build_test has already named the source on stderr by then.
oracle_one() {   # $1 = .c path
    local src="$1" name exe rc=0
    name="$(basename "${src%.c}")"
    exe="$(build_test "$src")" || return 1
    timeout -s KILL "$ORACLE_CASE_TIMEOUT" "$WINE" "$exe" >"$ORACLE_OUT/$name" 2>&1 || rc=$?
    # 137 = SIGKILL from timeout(1) (124 if it ever gets a softer signal): the
    # case never returned. Grading already counts it as failing — there is no
    # PASS line — but SILENTLY, and a hang that reads like an ordinary FAIL is
    # what made this expensive, so the reason goes in the case's own log where
    # the replay prints it, and on stderr now for whoever is watching.
    if (( rc == 137 || rc == 124 )); then
        echo "[KTEST] $name FAIL (no verdict: killed after ${ORACLE_CASE_TIMEOUT}s — hung)" \
            >>"$ORACLE_OUT/$name"
        echo "run.sh: '$name' hung; killed after ${ORACLE_CASE_TIMEOUT}s" >&2
    fi
}

# Worker $1 of $2: every ($2)th case, starting at $1. Round-robin rather than
# contiguous blocks because the cases are not equal-cost and their order is
# alphabetical by bucket — a block split would hand one worker all of sem_ps.
oracle_worker() {   # $1 = index, $2 = stride, $3.. = the .c paths
    local i="$1" stride="$2"; shift 2
    local srcs=("$@") rc=0
    while (( i < ${#srcs[@]} )); do
        oracle_one "${srcs[$i]}" || rc=1
        i=$(( i + stride ))
    done
    return "$rc"
}

# Build every test .exe, run nothing (see the header). Same round-robin
# fan-out as the oracle leg, and the same build_test — one authority for how a
# test .exe is produced, so a prebuilt tree and a leg-built one are the same
# tree. A build failure is fatal here for the reason it is fatal there: a
# missing .exe must never be silently re-supplied by a previous build.
prebuild_worker() {   # $1 = index, $2 = stride, $3.. = the .c paths
    local i="$1" stride="$2"; shift 2
    local srcs=("$@") rc=0
    while (( i < ${#srcs[@]} )); do
        build_test "${srcs[$i]}" >/dev/null || rc=1
        i=$(( i + stride ))
    done
    return "$rc"
}

prebuild() {
    mkdir -p "$BUILD/ntapi"
    build_helper_dll >/dev/null
    local srcs=() src w pids=() pid rc=0
    while read -r src; do srcs+=("$src"); done < <(all_sources)
    local jobs="$ORACLE_JOBS"
    (( jobs > ${#srcs[@]} )) && jobs=${#srcs[@]}
    (( jobs < 1 )) && jobs=1
    for (( w = 0; w < jobs; w++ )); do
        prebuild_worker "$w" "$jobs" "${srcs[@]}" &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
    if (( rc )); then
        echo "run.sh: a test failed to build — the prebuilt tree is incomplete" >&2
        return 1
    fi
    echo "== prebuild: ${#srcs[@]} test .exes up to date =="
    return 0
}

# The oracle leg. The three checks above are not tests/ntapi cases, so a
# filtered run only reaches one when it is named: `run.sh oracle fontdiff`.
#
# The ntapi cases are FANNED OUT across $ORACLE_JOBS workers: each is an
# independent PE process, and the leg was the longest in CI at 8.5 minutes of
# almost pure process startup. Each worker gets its OWN wineprefix, CREATED by
# wine the way the sequential leg's is (worker n uses $WINEPREFIX-n; worker 0
# uses the base prefix). That is what makes a parallel run semantically
# identical to a sequential one rather than merely faster: the cases address
# absolute paths under C:\ and keys under \Registry\Machine\Software,
# wineserver's namespace is per-prefix, and NtQuerySystemInformation's process
# list is exactly what a neighbour would pollute.
#
# A prefix is CREATED, never copied. `cp -a` of a finished prefix looks
# equivalent and is not: in a copy, opening the volume root `\??\C:` fails
# STATUS_OBJECT_NAME_NOT_FOUND (sem_file/ea_volume), deterministically, while
# the same test passes in a created prefix at the same path. Creation costs
# ~8 s and the workers pay it concurrently, so the copy bought nothing anyway.
# Concurrent creation is safe because each worker owns its prefix — the race
# worth avoiding was ever only two processes creating the SAME one.
#
# ORACLE_JOBS=1 restores the strictly sequential run, in the base prefix
# alone, exactly as before.
oracle() {
    check_subtests cmd-standalone fontsmoke fontdiff
    mkdir -p "$BUILD/ntapi"
    build_helper_dll >/dev/null

    local srcs=() par=() ser=() src
    while read -r src; do
        srcs+=("$src")
        if oracle_is_serial "$(basename "${src%.c}")"; then ser+=("$src"); else par+=("$src"); fi
    done < <(all_tests)
    local total=${#srcs[@]} jobs="$ORACLE_JOBS" w pids=() pid prefix
    local fails=0 buildfail=0 name
    (( total == 0 )) && { echo "run.sh: the oracle leg selected no test" >&2; exit 2; }
    (( jobs > ${#par[@]} )) && jobs=${#par[@]}
    (( jobs < 1 )) && jobs=1

    rm -rf "$ORACLE_OUT"
    mkdir -p "$ORACLE_OUT"

    if (( jobs > 1 )); then
        for (( w = 0; w < jobs; w++ )); do
            (( w == 0 )) && prefix="$WINEPREFIX" || prefix="$WINEPREFIX-$w"
            WINEPREFIX="$prefix" oracle_worker "$w" "$jobs" "${par[@]}" &
            pids+=("$!")
        done
        for pid in "${pids[@]}"; do wait "$pid" || buildfail=1; done
    else
        oracle_worker 0 1 "${par[@]}" || buildfail=1
    fi

    # The serial cases, alone, once every worker is done (see
    # $ORACLE_SERIAL_CASES). The base prefix, because nothing else is running.
    if (( buildfail == 0 )); then
        for src in ${ser[@]+"${ser[@]}"}; do
            oracle_one "$src" || { buildfail=1; break; }
        done
    fi

    # A worker fails only when a case failed to BUILD (a test's own verdict is
    # graded below), and that is fatal to the whole run: without the check, a
    # run that compiled nothing would replay the previous build's output and
    # read as green — the fabrication build_test exists to prevent.
    if (( buildfail )); then
        echo "run.sh: a test failed to build — no oracle verdict" >&2
        exit 1
    fi

    # Replay in source order, and grade. Missing output means the case never
    # ran at all, which is a failure of the harness, not a FAIL verdict.
    for src in "${srcs[@]}"; do
        name="$(basename "${src%.c}")"
        if [[ ! -f "$ORACLE_OUT/$name" ]]; then
            echo "run.sh: no output for '$name' — the oracle leg did not run it" >&2
            exit 1
        fi
        cat "$ORACLE_OUT/$name"
        # tr -d '\r': tolerate CRLF if a console handle translates.
        tr -d '\r' < "$ORACLE_OUT/$name" | grep -qE "^\[KTEST\] $name PASS$" || fails=$((fails+1))
    done

    selected cmd-standalone && { oracle_cmd_standalone || fails=$((fails+1)); }
    selected fontsmoke     && { oracle_fontsmoke     || fails=$((fails+1)); }
    selected fontdiff      && { oracle_fontdiff      || fails=$((fails+1)); }

    echo "== oracle: $fails failing =="
    return $(( fails > 0 ? 1 : 0 ))
}

# Bake the SAME .exes into a disk image under C:\ntapi beside the Wine PE
# userland (ntdll/kernel32/kernelbase + the NLS tables), boot it, and read
# each test's own [KTEST] <name> PASS line off the serial log. The session
# manager (user/smss/session.c, launched by the kernel at end of boot)
# sweeps C:\ntapi, runs every .exe as a console-less Wine process, and
# prints '[KTEST] ntapi done' when the sweep finishes — the boot's stop
# condition here.
#
# A filtered run bakes ONLY the named .exes, so the sweep — and the boot —
# is as short as the subset. Its image and serial log carry their own names:
# build/tests/proskrnl.hdd is the GATE's image, and a partial one must never
# be mistaken for it (or feed a later fatcheck/ftrace as if it were).
proskrnl() {
    check_subtests
    local kernel img
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/proskrnl.hdd"
    local tag=""
    if (( ${#SUBTESTS[@]} )); then
        tag="-subset"
        img="$ROOT/build/tests/proskrnl-subset.hdd"
    fi
    mkdir -p "$BUILD/ntapi"

    # ALWAYS rebuild, never just "build it if missing": the proskrnl leg is
    # the regression gate, and judging a stale kernel against fresh test
    # sources reports the previous build's verdict as this one's. make is
    # incremental, so the cost is nil when nothing changed.
    make -C "$ROOT" >/dev/null || exit 1

    # The M5 RAM-disk seed files (built by make with the kernel): kmt's
    # image/file section tests read them; they are data, never run.
    local specs=() names=()
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    # The Wine PE userland the tests run on (the same files Makefile WINFILES
    # bakes for `make test`): the debug-STRIPPED staging copies — with no COW
    # and no eviction, the -g mingw builds' DWARF triples every mapped image
    # copy (see Makefile winestrip).
    make -C "$ROOT" winestrip >/dev/null
    for dll in ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
               cryptbase; do
        specs+=("win:$ROOT/build/winestrip/$dll.dll=windows/system32/$dll.dll")
    done
    # The session manager drives the sweep (it is what enumerates C:\ntapi
    # and spawns each test through NtCreateUserProcess).
    make -C "$ROOT" build/modules/smss.exe >/dev/null
    specs+=("win:$ROOT/build/modules/smss.exe=windows/system32/smss.exe")
    specs+=("win:$(build_helper_dll)=ntapi/prshelper.dll")
    for nls in locale l_intl c_1252 c_437 c_20127 sortdefault normnfc normnfd normnfkc normnfkd \
               normidna; do
        [[ -f "$ROOT/third_party/wine/nls/$nls.nls" ]] && \
            specs+=("win:$ROOT/third_party/wine/nls/$nls.nls=windows/system32/$nls.nls")
    done
    while read -r src; do
        local name exe
        name="$(basename "${src%.c}")"
        exe="$(build_test "$src")" || exit 1
        specs+=("win:$exe=ntapi/$name.exe")
        names+=("$name")
    done < <(all_tests)

    "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    local log="$ROOT/build/tests/proskrnl$tag-serial.log"
    LOG="$log" PASS_RE="\[KTEST\] ntapi done" TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # The symbolized sidecar (proskrnl-serial.sym.log) is qemu.sh's job now —
    # every leg gets one (Art. 9); the verdict greps stay on the raw log.
    local fails=0
    for name in "${names[@]}"; do
        if grep -qE "^\[KTEST\] $name PASS$" "$log" 2>/dev/null; then
            echo "[KTEST] $name PASS"
        else
            echo "[KTEST] $name FAIL"
            fails=$((fails + 1))
        fi
    done
    # The external FAT oracle on the mutated image (docs/08): the kernel's
    # writes must parse under implementations that have never met fs/fat32/.
    "$ROOT/tests/run/fatcheck.sh" verify "proskrnl$tag" "$img" || fails=$((fails + 1))
    echo "== proskrnl: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# A manifest exe's short module name: the tail the winetest binaries all
# share, dropped. ntdll_test.exe -> ntdll; cmd.exe_test.exe -> cmd.
wtest_module() {   # $1 = manifest exe
    local mod="${1%_test.exe}"
    echo "${mod%.exe}"
}

# Does $1 (a $SUBTESTS pattern) select the pair $2:$3? Matched against the
# canonical <module>:<subtest>, against the raw <exe>:<subtest> the manifest
# spells, and — only for a pattern carrying no ':' — against each half alone,
# so `ntdll` takes a module, `printf` takes that subtest wherever it exists,
# and `ntdll:env` takes the one pair. Globs work in every position.
wtest_matches() {   # $1 = pattern, $2 = exe, $3 = subtest
    local mod
    mod="$(wtest_module "$2")"
    # shellcheck disable=SC2053  -- $1 is a glob on purpose
    [[ "$mod:$3" == $1 || "$2:$3" == $1 ]] && return 0
    if [[ "$1" != *:* ]]; then
        # shellcheck disable=SC2053
        [[ "$mod" == $1 || "$3" == $1 ]] && return 0
    fi
    return 1
}

# The M10 stretch gate (docs/02 "Ideal regression: the CUI subset of Wine's
# own test suite"): the manifest of <test_exe>:<subtest> pairs
# (tests/winetest/manifest.txt) must exit 0 under the pinned oracle AND on
# proskrnl. The manifest is the FULL non-GUI sweep — every subtest of ntdll,
# kernel32, msvcrt, ucrtbase and programs/cmd (advapi32 and user32 excluded;
# user32:msg has its own leg, guiwtest) — so the leg reports the whole
# frontier rather than the part already crossed.
# The binaries are the pinned tree's own test objects linked
# standalone (Makefile `wtests`) — ONE binary, two runners, like everything
# else here. On proskrnl the session manager's sweep (user/smss/
# session.c) reads the baked manifest, runs each pair on the console
# (winetest prints through msvcrt stdout -> conhost -> serial), and the exit
# code — winetest's failure count — is the verdict.
winetest() {
    local manifest="$ROOT/tests/winetest/manifest.txt"
    make -C "$ROOT" wtests >/dev/null
    mkdir -p "$BUILD/wtests"

    # Parse into PARALLEL arrays rather than carrying raw lines around: a
    # manifest line may carry the optional third field (the per-pair timeout,
    # user/smss/session.c), and both the oracle argv and the kernel's verdict
    # line are <exe>:<subtest> only — splitting once here is what keeps the
    # timeout out of them. wtestLines keeps the line verbatim for the baked
    # subset manifest, so the timeout survives to the runner that honors it.
    local wtestExes=() wtestSubs=() wtestKeys=() wtestLines=()
    local line
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        local exe="${line%%:*}" rest="${line#*:}"
        local sub="${rest%%:*}"
        wtestExes+=("$exe"); wtestSubs+=("$sub")
        wtestKeys+=("$exe:$sub"); wtestLines+=("$line")
    done < "$manifest"
    if [[ ${#wtestKeys[@]} -eq 0 ]]; then
        echo "== winetest: manifest empty ==" >&2
        return 2
    fi

    # The $SUBTESTS filter (see the header). A pattern that matches no pair is
    # a TYPO, not an empty run — the ntapi legs' rule (check_subtests) and the
    # same reason: a silently empty sweep prints "0 failing" and reads green.
    local i pat hit
    if (( ${#SUBTESTS[@]} )); then
        for pat in "${SUBTESTS[@]}"; do
            hit=0
            for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
                wtest_matches "$pat" "${wtestExes[i]}" "${wtestSubs[i]}" && { hit=1; break; }
            done
            if (( ! hit )); then
                echo "run.sh: no winetest pair matches '$pat'. Known pairs:" >&2
                for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
                    echo "  $(wtest_module "${wtestExes[i]}"):${wtestSubs[i]}"
                done >&2
                exit 2
            fi
        done
        local selExes=() selSubs=() selKeys=() selLines=()
        for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
            for pat in "${SUBTESTS[@]}"; do
                if wtest_matches "$pat" "${wtestExes[i]}" "${wtestSubs[i]}"; then
                    selExes+=("${wtestExes[i]}"); selSubs+=("${wtestSubs[i]}")
                    selKeys+=("${wtestKeys[i]}"); selLines+=("${wtestLines[i]}")
                    break
                fi
            done
        done
        wtestExes=("${selExes[@]}"); wtestSubs=("${selSubs[@]}")
        wtestKeys=("${selKeys[@]}"); wtestLines=("${selLines[@]}")
        echo "== winetest: subset run (${SUBTESTS[*]}, ${#wtestKeys[@]} pairs)" \
             "— NOT the gate; run unfiltered for a verdict =="
    fi

    # --- oracle leg (the SPEC gate: green here before the kernel side) ---
    # $WTEST_NO_ORACLE skips it while iterating on the KERNEL side of a pair
    # whose oracle verdict you already have — the leg's slowest half, re-run
    # unchanged on every kernel rebuild. It is refused without a filter: the
    # gate is both legs, always, and a knob that could quietly drop the spec
    # half from an unfiltered run would be a way to report a green that was
    # never differential.
    local fails=0
    if [[ -n "${WTEST_NO_ORACLE:-}" ]] && (( ${#SUBTESTS[@]} == 0 )); then
        echo "run.sh: WTEST_NO_ORACLE needs a subset — the unfiltered leg is both legs" >&2
        exit 2
    fi
    if [[ -z "${WTEST_NO_ORACLE:-}" ]]; then
        for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
            local exe="${wtestExes[i]}" sub="${wtestSubs[i]}"
            local olog="$BUILD/wtests/${exe}.${sub}.oracle.log"
            # scratch cwd: the cmd tests write test.cmd/test.out where they run
            if (cd "$BUILD/wtests" && "$WINE" "$ROOT/build/wtests/$exe" "$sub") >"$olog" 2>&1; then
                echo "[KTEST] wtest-oracle ${wtestKeys[i]} PASS"
            else
                echo "[KTEST] wtest-oracle ${wtestKeys[i]} FAIL (see $olog)"
                fails=$((fails+1))
            fi
        done
    else
        echo "== winetest: oracle leg skipped (WTEST_NO_ORACLE) — kernel side only =="
    fi

    # --- proskrnl leg (the REGRESSION gate) ---
    # A subset boots its OWN image (the proskrnl leg's rule): the gate's
    # wtest.hdd must never be left holding a partial manifest, where a later
    # run — or a human reading the file — would take it for the full sweep.
    local kernel img baked
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/wtest.hdd"
    baked="$manifest"
    if (( ${#SUBTESTS[@]} )); then
        img="$ROOT/build/tests/wtest-subset.hdd"
        baked="$BUILD/wtests/manifest-subset.txt"
        {
            echo "# GENERATED by tests/run/run.sh winetest ${SUBTESTS[*]} — a SUBSET of"
            echo "# tests/winetest/manifest.txt, baked for iteration. Never a verdict."
            printf '%s\n' "${wtestLines[@]}"
        } > "$baked"
    fi
    make -C "$ROOT" >/dev/null || exit 1   # always: see the ntapi leg's note
    make -C "$ROOT" build/modules/cmd.exe build/modules/conhost.exe \
        build/modules/smss.exe >/dev/null

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
    make -C "$ROOT" winestrip >/dev/null
    for dll in ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
               cryptbase; do
        specs+=("win:$ROOT/build/winestrip/$dll.dll=windows/system32/$dll.dll")
    done
    local nlsfile
    for nlsfile in "$ROOT"/third_party/wine/nls/*.nls; do
        specs+=("win:$nlsfile=windows/system32/$(basename "$nlsfile")")
    done
    # tzres.dll — the resource-only DLL the time-zone table's MUI_Std/MUI_Dlt
    # values point at ("@tzres.dll,-22000"). Both GetDynamicTimeZoneInformation
    # and GetTimeZoneInformationForYear resolve those through RegLoadMUIStringW
    # against %windir%\system32 (dlls/kernelbase/locale.c), but they disagree
    # about the FAILURE: the first ignores the error and leaves the raw
    # "@tzres.dll,-N" in place, the second falls back to the zone's plain
    # `Std`/`Dlt`. So with the file absent the two APIs answer different
    # strings for the same zone, which is kernel32:time :990-:1008 — a
    # divergence made entirely of a file the oracle's prefix has and the baked
    # image did not (the win.ini story below, one directory up). Taken from the
    # pinned tree unstripped: it is pure resources, with no unixlib half for
    # `winestrip` to remove.
    specs+=("win:$ROOT/third_party/wine/dlls/tzres/x86_64-windows/tzres.dll=windows/system32/tzres.dll")
    # %windir%\{win,system}.ini, for the same reason the nls set goes in.
    # This image carries no wineboot.exe, so smss skips firstboot
    # (user/smss/smss.c) and the `wineboot --init` pass that writes them
    # never runs — while the ORACLE leg runs in a wineprefix where it did.
    # Measured: without win.ini, kernel32:profile's NULL-filename cases
    # (profile.c:95/:101, which read win.ini through GetPrivateProfileIntA,
    # and :229's todo_wine on GetLastError) diverge on the file's absence
    # rather than on anything the kernel does. Generated from the pinned
    # wine.inf's own [SystemIni] payload, never hand-typed
    # (tools/gen_sysini.py; --check proves it byte-identical to a prefix).
    python3 "$ROOT/tools/gen_sysini.py" "$BUILD/wtests/sysini" >/dev/null
    # And self-checked whenever the oracle leg has already materialised the
    # prefix: byte-identical to what wineboot wrote there, so a wine pin that
    # edits [SystemIni] cannot drift the two legs apart unnoticed.
    if [[ -f "$WINEPREFIX/drive_c/windows/win.ini" ]]; then
        python3 "$ROOT/tools/gen_sysini.py" --check "$WINEPREFIX" >/dev/null
    fi
    local inifile
    for inifile in "$BUILD/wtests/sysini"/*.ini; do
        specs+=("win:$inifile=windows/$(basename "$inifile")")
    done
    specs+=("win:$ROOT/build/modules/smss.exe=windows/system32/smss.exe")
    specs+=("win:$ROOT/build/modules/conhost.exe=windows/system32/conhost.exe")
    specs+=("win:$ROOT/build/modules/cmd.exe=windows/system32/cmd.exe")
    # Only the exes the (possibly filtered) manifest names — an unfiltered run
    # bakes all five, a subset bakes just what it will run, which is the ntapi
    # leg's property too: a subset's image is as short as the subset.
    local bakedExes=" "
    for ((i = 0; i < ${#wtestExes[@]}; i++)); do
        [[ "$bakedExes" == *" ${wtestExes[i]} "* ]] || bakedExes+="${wtestExes[i]} "
    done
    # shellcheck disable=SC2086  -- deliberate split on a list we just built
    for exe in $bakedExes; do
        specs+=("win:$ROOT/build/wtests/$exe=wtests/$exe")
    done
    specs+=("win:$baked=wtests/manifest.txt")

    # MB-scale test binaries: a bigger volume than the 64 MB default. And
    # 1 GiB of guest RAM: no eviction (Art. 3) means the page cache holds
    # every test binary's pages for the whole sweep — memory is provisioned,
    # not managed.
    SIZE_MB=256 "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    local log="$ROOT/build/tests/wtest-serial.log"
    if (( ${#SUBTESTS[@]} )); then log="$ROOT/build/tests/wtest-subset-serial.log"; fi
    LOG="$log" MEM=1024M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-1800}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # No ^ anchor: conhost cursor escapes may share the verdict's line (the
    # run.sh console precedent).
    for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
        if grep -qF "[KTEST] wtest ${wtestKeys[i]} PASS" "$log" 2>/dev/null; then
            echo "[KTEST] wtest ${wtestKeys[i]} PASS"
        else
            echo "[KTEST] wtest ${wtestKeys[i]} FAIL"
            fails=$((fails + 1))
        fi
    done
    echo "== winetest: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# GUI-5's trophy gate (docs/02 "the real trophy: run Wine's
# user32/tests/msg.c"): the pinned tree's own user32_test.exe, whole msg
# module, over the full GUI stack — win32u, wineserver-lite, winefb, the
# windowed message machinery — swept by the same kernel wtest runner the
# CUI manifest uses (per-pair timeout via the manifest's third field).
#
# PROSKRNL-ONLY, by measurement (tests/winetest/manifest-gui.txt has the
# full finding): the --without-x oracle cannot host msg.c at all — its null
# display driver refuses every window and the suite hangs. The spec is
# msg.c's own ok()/todo_wine assertions (third-party, Windows-verified;
# todo_wine applies identically on proskrnl). The verdict is a BUDGET
# RATCHET: tests/winetest/msg-budget.txt holds the currently-accepted
# failure count, parsed against winetest's own summary line (the exit code
# clips at 255 and the count does not); more failures than the budget is a
# regression and fails the leg, fewer is a note to ratchet the file down in
# the commit that earned it. 0 is the milestone's end state.
guiwtest() {
    local manifest="$ROOT/tests/winetest/manifest-gui.txt"
    local budgetfile="$ROOT/tests/winetest/msg-budget.txt"
    local budget
    budget="$(grep -vE '^\s*(#|$)' "$budgetfile" | head -1 | tr -d '[:space:]')"
    if ! [[ "$budget" =~ ^[0-9]+$ ]]; then
        echo "== guiwtest: msg-budget.txt holds no number ==" >&2
        return 2
    fi

    local kernel img
    kernel="$ROOT/build/proskrnl"
    img="$ROOT/build/tests/guiwtest.hdd"
    make -C "$ROOT" >/dev/null || exit 1   # always: see the ntapi leg's note
    make -C "$ROOT" winestrip winestrip-gui win32u wineserver-lite \
        build/modules/cmd.exe build/modules/conhost.exe build/modules/smss.exe >/dev/null

    # The winetest image recipe (DLLs, nls, conhost, cmd, the M5 seeds that
    # keep the in-kernel M6 suite green) plus the GUI stack the msg module
    # lives on, plus hid/imm32/setupapi (msg.c's own imports) — all from the
    # same stripped set.
    local specs=()
    local seed
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    for dll in ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
               cryptbase setupapi cfgmgr32 hid user32 gdi32 comctl32 imm32 ole32 combase coml2; do
        specs+=("win:$ROOT/build/winestrip/$dll.dll=windows/system32/$dll.dll")
    done
    specs+=("win:$ROOT/build/modules/win32u.dll=windows/system32/win32u.dll")
    specs+=("win:$ROOT/build/modules/wineserver-lite.exe=windows/system32/wineserver-lite.exe")
    local nlsfile
    for nlsfile in "$ROOT"/third_party/wine/nls/*.nls; do
        specs+=("win:$nlsfile=windows/system32/$(basename "$nlsfile")")
    done
    local fontfile
    for fontfile in "$ROOT"/third_party/wine/fonts/*.ttf "$ROOT"/third_party/wine/fonts/*.fon; do
        specs+=("win:$fontfile=windows/fonts/$(basename "$fontfile")")
    done
    specs+=("win:$ROOT/build/modules/smss.exe=windows/system32/smss.exe")
    specs+=("win:$ROOT/build/modules/conhost.exe=windows/system32/conhost.exe")
    specs+=("win:$ROOT/build/modules/cmd.exe=windows/system32/cmd.exe")
    specs+=("win:$ROOT/third_party/wine/dlls/user32/tests/x86_64-windows/user32_test.exe=wtests/user32_test.exe")
    specs+=("win:$manifest=wtests/manifest.txt")

    SIZE_MB=256 "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null

    # 2 GiB: no COW and this boot holds the server, conhost, a multi-MB
    # test binary and its spawned children resident at once.
    local log="$ROOT/build/tests/guiwtest-serial.log"
    LOG="$log" MEM=2048M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-3600}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # msg.c's own assertion text, replayed out of the console screen diff
    # (tools/unscreen.py). The VERDICT never comes from here — it is the
    # kernel's line below — but a budget above zero is a list of named
    # divergences, and this file is the only place their names survive.
    "$ROOT/tools/unscreen.py" --grep 'Test (failed|succeeded)|marked todo|unhandled exception' \
        "$log" > "$ROOT/build/tests/guiwtest-msg.log" 2>/dev/null || true

    # The ratchet input is the KERNEL's own verdict line (DbgPrint straight
    # to serial — never through the console, whose 80-column screen diff
    # truncates and mangles winetest's text): `[KTEST] wtest <pair> PASS` is
    # zero failures, `FAIL (exit=0xN)` carries winetest's failure count as
    # the exit status (a full 32-bit value — NT exit codes do not clip at
    # 255). A timeout/create failure has no count and always fails the leg.
    local verdict failures
    verdict="$(grep -oE '\[KTEST\] wtest user32_test\.exe:msg (PASS|FAIL \(exit=0x[0-9a-f]+\))' "$log" | tail -1)"
    if [[ -z "$verdict" ]]; then
        echo "== guiwtest: FAIL (no kernel verdict — hung, panicked or timed out; see $log) =="
        return 1
    fi
    if [[ "$verdict" == *PASS ]]; then
        failures=0
    else
        failures=$(( $(grep -oE '0x[0-9a-f]+' <<<"$verdict") ))
        # A failure COUNT is a small number; an NT status (0xC0000005, a
        # crash) is not a count and no budget forgives it.
        if (( failures < 0 || failures > 65535 )); then
            printf -v crash '0x%x' "$(( failures & 0xffffffff ))"
            echo "== guiwtest: FAIL (the msg run crashed, exit=$crash; see $log) =="
            return 1
        fi
    fi
    echo "[KTEST] guiwtest user32:msg failures=$failures budget=$budget"
    if (( failures > budget )); then
        echo "== guiwtest: FAIL ($failures failures against a budget of $budget; see $log) =="
        return 1
    fi
    if (( failures < budget )); then
        echo "== guiwtest: PASS — and $failures < budget $budget: ratchet msg-budget.txt down =="
    else
        echo "== guiwtest: PASS ($failures failures, at budget) =="
    fi
    return 0
}

# The FAT interop battery (docs/08 "The FAT on-disk format has its own
# oracles"): bake an adversarial corpus with mtools + host-side FAT surgery
# (tests/run/fatgen.py), boot, and let the in-kernel suite
# (tests/kmt/fat_interop.c) enumerate/read/checksum it all; then extract the
# battery the kernel wrote and verify it on the host. Both directions of
# dir.c's 8.3/LFN logic meet an implementation they have never met. No Wine
# userland needed: the suite runs in-kernel, gated by the baked manifest.
fatinterop() {
    local kernel="$ROOT/build/proskrnl" img="$BUILD/fatinterop.hdd"
    local work="$BUILD/fatinterop" off=2097152    # mkimage.sh ESP_OFF
    make -C "$ROOT" build/proskrnl >/dev/null || exit 1   # always: see the ntapi leg's note
    rm -rf "$work"
    mkdir -p "$work"

    # Base image: kernel + the M5 seed modules only (keeps M5/M6 green).
    local specs=()
    make -C "$ROOT" build/modules/pe_smoke.exe build/modules/sample.dat >/dev/null 2>&1 || true
    for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
        [[ -f "$seed" ]] && specs+=("$seed=initrd")
    done
    "$ROOT/tools/mkimage.sh" "$kernel" "$img" ${specs[@]+"${specs[@]}"} >/dev/null

    # Cluster size from the real volume (mformat decided it): bytes/sector *
    # sectors/cluster out of the BPB, via fatsweep's parser.
    local cbytes
    cbytes=$(python3 - "$img" <<'PYEOF'
import struct, sys
with open(sys.argv[1], "rb") as f:
    f.seek(2097152)
    boot = f.read(64)
print(struct.unpack_from("<H", boot, 11)[0] * boot[13])
PYEOF
)
    python3 "$ROOT/tests/run/fatgen.py" emit --outdir "$work" --cluster-bytes "$cbytes"

    # Bake the corpus with raw mtools at the ESP offset (the firstboot mcopy
    # precedent). The manifest goes LAST: it is the kernel-side gate, so a
    # partially baked image never runs the suite.
    mmd -i "$img@@$off" ::/fatcorpus
    local fails=0
    while IFS=$'\t' read -r op a b; do
        case "$op" in
            mkdir) mmd  -i "$img@@$off" "::$a" || fails=$((fails+1)) ;;
            copy)  mcopy -i "$img@@$off" "$work/hostfiles/$a" "::$b" || fails=$((fails+1)) ;;
            del)   mdel -i "$img@@$off" "::$a" || fails=$((fails+1)) ;;
        esac
    done < "$work/bake.txt"
    if [[ $fails -ne 0 ]]; then
        echo "== fatinterop: FAIL ($fails bake ops failed) =="
        return 1
    fi
    # Deterministic fragmentation (host-side FAT surgery), then prove it.
    python3 "$ROOT/tests/run/fatgen.py" fragment --image "$img" --path fatcorpus/frag.bin
    python3 "$ROOT/tests/run/fatgen.py" fragment --image "$img" --path fatcorpus/frag2.bin
    python3 "$ROOT/tests/run/fatgen.py" fragcheck --image "$img" --path fatcorpus/frag.bin \
        --min-extents 2 || { echo "== fatinterop: FAIL (fragmentation) =="; return 1; }
    mcopy -i "$img@@$off" "$work/manifest.txt" ::/fatcorpus/manifest.txt

    local log="$BUILD/fatinterop-serial.log"
    LOG="$log" PASS_RE="\[KTEST\] FATINTEROP PASS" TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    fails=0
    if grep -qE '\[KTEST\] FATINTEROP PASS' "$log" 2>/dev/null; then
        echo "[KTEST] fatinterop-boot PASS"
    else
        echo "[KTEST] fatinterop-boot FAIL (see $log)"
        fails=$((fails+1))
    fi

    # Kernel->host: extract AFTER qemu exits (the image lock), verify against
    # the manifest, and run the structural oracles on the mutated image.
    rm -rf "$work/extracted"
    mkdir -p "$work/extracted"
    mcopy -s -p -i "$img@@$off" ::/fatout/. "$work/extracted" 2>/dev/null || true
    if python3 "$ROOT/tests/run/fatgen.py" verify --extracted "$work/extracted/fatout" \
           --manifest "$work/manifest.txt"; then
        echo "[KTEST] fatinterop-extract PASS"
    else
        echo "[KTEST] fatinterop-extract FAIL"
        fails=$((fails+1))
    fi
    "$ROOT/tests/run/fatcheck.sh" verify fatinterop "$img" || fails=$((fails+1))
    echo "== fatinterop: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# The FS churn stress (docs/08): fixed-seed random churn against an
# in-kernel shadow model (tests/kmt/fat_churn.c), across THREE mkfs
# geometries — boundary bugs are geometry-specific. Non-diskfull legs boot
# TWICE (the m8_persist pattern): boot 1 seeds wet, boot 2 replays the
# model dry from the seed alone and verifies through a COLD cache. Then the
# host convicts independently: dump-vs-dump determinism diff, mcopy
# extraction + crc diff (churn_verify.py), fsck.fat + the sweeper.
fatstress() {
    local kernel="$ROOT/build/proskrnl"
    make -C "$ROOT" build/proskrnl >/dev/null || exit 1   # always: see the ntapi leg's note
    make -C "$ROOT" build/modules/pe_smoke.exe build/modules/sample.dat >/dev/null 2>&1 || true
    mkdir -p "$BUILD"

    # name:SIZE_MB:CLUSTER_SECTORS:ops:expect_diskfull:boots
    #   default   the standard geometry (512 B clusters on 64 MiB)
    #   c8        4 KiB clusters (page-size, the untested shape)
    #   nearfull  a small volume + ballast so allocation hits DISK_FULL
    local legs=("default:64::400:0:2" "c8:320:8:400:0:2" "nearfull:36:1:300:1:1")
    local fails=0
    for leg in "${legs[@]}"; do
        local lname lsize lcs lops ldf lboots
        IFS=: read -r lname lsize lcs lops ldf lboots <<< "$leg"
        local img="$BUILD/fatstress-$lname.hdd" cfg="$BUILD/churn-$lname.cfg"
        # The near-full leg gets a huge budget: the point is to press the
        # allocator against a really-full volume (ballast below).
        local budget=6291456
        [[ "$ldf" == 1 ]] && budget=33554432
        printf 'seed=0x1965A11D ops=%s maxfiles=48 maxsize=16384 budget=%s expect_diskfull=%s\n' \
            "$lops" "$budget" "$ldf" > "$cfg"

        local specs=()
        for seed in "$ROOT/build/modules/pe_smoke.exe" "$ROOT/build/modules/sample.dat"; do
            [[ -f "$seed" ]] && specs+=("$seed=initrd")
        done
        specs+=("win:$cfg=churn.cfg")
        SIZE_MB="$lsize" CLUSTER_SECTORS="$lcs" \
            "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null
        if [[ "$ldf" == 1 ]]; then
            # Fill the baked volume down to ~150 KiB free — well inside the
            # churn's working set, so allocation really hits DISK_FULL. The
            # ballast is sized from the image's MEASURED free space, not a
            # fixed count: the kernel binary's size swings by hundreds of
            # KiB across toolchains (debug info), and a fixed 31 MiB once
            # left a container's build ~300 KiB free — above the churn's
            # peak, so DISK_FULL never fired and the leg failed for no
            # kernel fault of its own.
            local off=2097152   # mkimage.sh ESP_OFF
            local freeBytes keepBytes=153600
            # mtools space-groups thousands ("311 296 bytes free"); strip
            # everything but digits from that one line.
            freeBytes=$(mdir -i "$img@@$off" :: | grep 'bytes free' | tr -dc '0-9')
            if [[ -z "$freeBytes" || "$freeBytes" -le "$keepBytes" ]]; then
                echo "[KTEST] fatstress-$lname-seed FAIL (cannot size ballast: free='$freeBytes')"
                fails=$((fails+1))
                continue
            fi
            dd if=/dev/zero of="$BUILD/ballast.bin" bs=1024 \
                count=$(( (freeBytes - keepBytes) / 1024 )) 2>/dev/null
            mcopy -i "$img@@$off" "$BUILD/ballast.bin" ::/ballast.bin
        fi

        local log1="$BUILD/fatstress-$lname-1.log" log2="$BUILD/fatstress-$lname-2.log"
        LOG="$log1" PASS_RE="\[KTEST\] churn-seed PASS" TIMEOUT="${TIMEOUT:-900}" \
            "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
        if ! grep -q '\[KTEST\] churn-seed PASS' "$log1"; then
            echo "[KTEST] fatstress-$lname-seed FAIL (see $log1)"
            fails=$((fails+1))
            continue
        fi
        echo "[KTEST] fatstress-$lname-seed PASS"

        local finalLog="$log1"
        if [[ "$lboots" == 2 ]]; then
            LOG="$log2" PASS_RE="\[KTEST\] churn-verify PASS" TIMEOUT="${TIMEOUT:-900}" \
                "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
            if grep -q '\[KTEST\] churn-verify PASS' "$log2"; then
                echo "[KTEST] fatstress-$lname-verify PASS"
            else
                echo "[KTEST] fatstress-$lname-verify FAIL (see $log2)"
                fails=$((fails+1))
            fi
            # Dry-replay determinism: the two dumps must be identical.
            if diff <(grep '^\[CHURN\] ' "$log1" | tr -d '\r' | sort) \
                    <(grep '^\[CHURN\] ' "$log2" | tr -d '\r' | sort) >/dev/null; then
                echo "[KTEST] fatstress-$lname-replay PASS"
            else
                echo "[KTEST] fatstress-$lname-replay FAIL (dumps differ)"
                fails=$((fails+1))
            fi
            finalLog="$log2"
        fi

        # Host conviction: extraction + crc, then the structural oracles.
        local extract="$BUILD/fatstress-$lname-extract"
        rm -rf "$extract"
        mkdir -p "$extract"
        mcopy -s -p -i "$img@@2097152" ::/churn "$extract" 2>/dev/null || true
        if python3 "$ROOT/tests/run/churn_verify.py" --log "$finalLog" \
               --extracted "$extract/churn"; then
            echo "[KTEST] fatstress-$lname-extract PASS"
        else
            echo "[KTEST] fatstress-$lname-extract FAIL"
            fails=$((fails+1))
        fi
        "$ROOT/tests/run/fatcheck.sh" verify churn "$img" || fails=$((fails+1))
    done
    echo "== fatstress: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# Exhaustive torn-write testing (docs/08): boot a minimal image whose
# workload module (tests/boot/torn_workload.c) exercises every
# disk-write shape while QEMU's blklogwrites driver logs each block write
# (tools/qemu.sh WRITE_LOG); then tests/run/tornreplay.py applies every
# prefix of the log to a pristine copy of the partition — each prefix is a
# reachable power-loss state — and checks structural invariants plus the
# hive's torn-write-falls-back-to-empty guarantee on all of them.
tornwrite() {
    make -C "$ROOT" build/proskrnl build/modules/torn_workload.bin \
        build/modules/pe_smoke.exe build/modules/sample.dat >/dev/null
    local kernel="$ROOT/build/proskrnl" img="$BUILD/tornwrite.hdd"
    local logbin="$BUILD/tornwrite-writes.bin" serial="$BUILD/tornwrite-serial.log"
    mkdir -p "$BUILD"

    local specs=("$ROOT/build/modules/pe_smoke.exe=initrd"
                 "$ROOT/build/modules/sample.dat=initrd"
                 "$ROOT/build/modules/torn_workload.bin=expect=0")
    "$ROOT/tools/mkimage.sh" "$kernel" "$img" "${specs[@]}" >/dev/null
    cp "$img" "$BUILD/tornwrite-pristine.hdd"

    rm -f "$logbin"
    truncate -s 64M "$logbin"
    WRITE_LOG="$logbin" LOG="$serial" PASS_RE="\[KTEST\] module /torn_workload.bin PASS" \
        TIMEOUT="${TIMEOUT:-900}" "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q '\[KTEST\] module /torn_workload.bin PASS' "$serial"; then
        echo "== tornwrite: FAIL (the workload run itself went red; see $serial) =="
        return 1
    fi

    local fails=0
    if python3 "$ROOT/tests/run/tornreplay.py" --pristine "$BUILD/tornwrite-pristine.hdd" \
           --final "$img" --log "$logbin"; then
        :
    else
        fails=$((fails+1))
    fi
    "$ROOT/tests/run/fatcheck.sh" verify tornwrite "$img" || fails=$((fails+1))
    echo "== tornwrite: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# The differential fuzzer (docs/08, tests/fuzz/): random Nt* sequences run on
# both the oracle and proskrnl, divergence == bug. Delegates to fuzz.py, which
# reuses the exact build recipes above. All args after `fuzz` are forwarded.
# No exec: the dispatcher's uacheck sweep has to outlive the leg, and the
# fuzzer is the leg most likely to reach a missing probe — it is the one that
# feeds hostile arguments on purpose.
fuzz() { "$ROOT/tests/fuzz/fuzz.py" "$@"; }

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
    make -C "$ROOT" >/dev/null || exit 1
    local img="$ROOT/build/tests/persist.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl.hdd" "$img"

    local log1="$ROOT/build/tests/persist1.log" log2="$ROOT/build/tests/persist2.log"
    # Boot 1 of a virgin image runs the whole CUI-1 firstboot INF pass
    # (minutes under TCG); boot 2 skips it via wineboot's timestamp check.
    LOG="$log1" TIMEOUT="${TIMEOUT:-900}" "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q 'm8_persist: seeded' "$log1" || \
       ! grep -qE '^\[KTEST\] module /m8_persist.bin PASS' "$log1"; then
        echo "== persist: FAIL (boot 1 did not seed; see $log1) =="
        return 1
    fi
    LOG="$log2" TIMEOUT="${TIMEOUT:-900}" "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q 'm8_persist: verified' "$log2" || \
       ! grep -qE '^\[KTEST\] module /m8_persist.bin PASS' "$log2" || \
       ! grep -qE '^\[KTEST\] M8 PASS' "$log2"; then
        echo "== persist: FAIL (boot 2 did not verify; see $log2) =="
        return 1
    fi
    # The external FAT oracle after boot 2 (the hive write path's image).
    if ! "$ROOT/tests/run/fatcheck.sh" verify persist "$img"; then
        echo "== persist: FAIL (fatcheck) =="
        return 1
    fi
    echo "== persist: PASS (seeded on boot 1, verified after reboot) =="
    return 0
}

# The CUI-1 acceptance (docs/02 "a registry differential vs. the oracle's
# prefix is green" — Art. 6, the diff convicts): boot a VIRGIN standard
# image once (firstboot runs wineboot --init through rundll32/setupapi),
# pull the SYSTEM hive off the FAT volume, and diff it against the registry
# the SAME payload produces in a fresh prefix under the pinned oracle wine.
# regdump.py canonicalizes both sides; regdiff.py carries the documented
# exclusion list (docs/03 "CUI-1 firstboot notes").
firstboot() {
    mkdir -p "$BUILD"

    # --- proskrnl leg: virgin image (the persist() pattern), one boot ---
    rm -f "$ROOT/build/proskrnl.hdd"
    make -C "$ROOT" >/dev/null || exit 1
    local img="$BUILD/firstboot.hdd"
    cp "$ROOT/build/proskrnl.hdd" "$img"
    local log="$BUILD/firstboot.log"
    LOG="$log" PASS_RE="\[KTEST\] firstboot PASS" TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q "\[KTEST\] firstboot PASS" "$log"; then
        echo "[KTEST] firstboot-diff FAIL (boot did not reach firstboot PASS; see $log)"
        return 1
    fi
    # The external FAT oracle BEFORE the hive extraction below: a FAT-corrupt
    # image should fail loudly here, not feed a torn hive to regdiff.
    if ! "$ROOT/tests/run/fatcheck.sh" verify firstboot "$img"; then
        echo "[KTEST] firstboot-diff FAIL (fatcheck on the booted image)"
        return 1
    fi
    # The hive sits on the image's ESP FAT32 partition (mkimage.sh: p2 at
    # sector 4096, the same byte offset mkimage's own mcopy uses).
    local hive="$BUILD/firstboot-SYSTEM"
    rm -f "$hive"
    mcopy -i "$img@@2097152" ::/windows/system32/config/SYSTEM "$hive"

    # --- oracle leg: wineboot --init in a fresh prefix under the pinned wine ---
    # BOTH sides apply the IDENTICAL filtered INF, so the differential
    # isolates the kernel's Cm/setupapi boundary from the directive families
    # tools/filter_inf.py documents as out of scope (their registry effect —
    # RegisterDlls self-registration — is neither applied on proskrnl nor
    # comparable). The filtered INF is staged as input data over the pinned
    # tree's loader/wine.inf for the duration of this one prefix init (the
    # loader's WINEBUILDDIR always wins over the environment, so the file is
    # the only staging point); the byte-identical original is restored even
    # on failure, keeping the pinned tree — the hack meter — clean.
    local prefix="$BUILD/firstboot-prefix"
    local inf="$ROOT/third_party/wine/loader/wine.inf"
    rm -rf "$prefix"
    cp "$inf" "$BUILD/wine.inf.pristine"
    trap 'cp "'"$BUILD"'/wine.inf.pristine" "'"$inf"'"' EXIT
    # --keep WineFakeDlls: fake dlls write no registry, but a prefix without
    # them cannot launch any non-bootstrap process (see tools/filter_inf.py);
    # on the host the sources exist, so the oracle keeps them. The compared
    # AddReg/DelReg/Services payload is byte-identical to the baked INF's.
    python3 "$ROOT/tools/filter_inf.py" --keep WineFakeDlls \
        "$BUILD/wine.inf.pristine" "$BUILD/wine-oracle.inf" 2>/dev/null
    cp "$BUILD/wine-oracle.inf" "$inf"
    # Prefix creation itself applies the payload: ntdll's prefix bootstrap
    # (unix/env.c run_wineboot) runs wineboot --init --update synchronously
    # before the requested command ever loads. The requested command must be
    # a REAL on-disk .exe by unix path — a filtered-INF prefix has no fake
    # dlls, so a builtin app (bare "wineboot", or even an explicit
    # system32 path: load_main_exe hard-fails an explicit path with no file
    # behind it) can never be the initial process. The repo's own standalone
    # cmd.exe doubles as the it-really-booted signal; the registry verdict
    # itself belongs to regdiff, not this exit code.
    local oracle_out
    oracle_out="$(WINEPREFIX="$prefix" "$WINE" "$ROOT/build/modules/cmd.exe" /c \
        "echo firstboot-oracle-ok" 2>"$BUILD/firstboot-oracle.log" | tr -d '\r')"
    if ! echo "$oracle_out" | grep -q "firstboot-oracle-ok"; then
        echo "[KTEST] firstboot-diff FAIL (oracle prefix init failed; see $BUILD/firstboot-oracle.log)"
        cp "$BUILD/wine.inf.pristine" "$inf"
        trap - EXIT
        return 1
    fi
    # wineserver persists system.reg on exit; -w waits for that shutdown.
    WINEPREFIX="$prefix" "$ROOT/third_party/wine/server/wineserver" -w
    cp "$BUILD/wine.inf.pristine" "$inf"
    trap - EXIT

    # --- the differential ---
    if python3 "$ROOT/tests/run/regdiff.py" "$hive" "$prefix/system.reg" \
        "$ROOT/build/wine-proskrnl.inf"; then
        echo "[KTEST] firstboot-diff PASS"
        echo "== firstboot: PASS =="
        return 0
    fi
    echo "[KTEST] firstboot-diff FAIL"
    echo "== firstboot: FAIL (regdiff divergences above) =="
    return 1
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

    # CUI-3: a resident SCM under no-eviction/no-COW needs the winetest
    # leg's provisioning.
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
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

# The CUI-3 acceptance (docs/02 "an sc-style query round-trips; a real
# service installs, starts, and survives reboot, all driven from ring 3"):
# boot ONE console-image disk twice. Boot 1 drives the round-trip from
# cmd.exe — sc query RpcSs over \pipe\svcctl, sc start RpcSs (a real
# service process), sc create + start SvcDemo (tests/cui/svcdemo.c), the
# proof line in C:\svcdemo.log (console_expect.py EXPECT_SCM=1). Boot 2
# asserts the SCM AUTO-started SvcDemo from the persisted registry before
# cmd ever prompted, and the proof file grew (EXPECT_SCM=2).
scm() {
    # A VIRGIN console image (the persist() pattern): a hive seeded by an
    # earlier console run could already carry SvcDemo and break the create.
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/tests/scm.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local boot sock log qemu_wrapper
    for boot in 1 2; do
        sock="$ROOT/build/tests/scm$boot.sock"
        log="$ROOT/build/tests/scm$boot.log"
        SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
            "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
        qemu_wrapper=$!
        if ! EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_SCM="$boot" \
            python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
            wait "$qemu_wrapper" 2>/dev/null || true
            echo "== scm: FAIL (boot $boot; see $log) =="
            return 1
        fi
        wait "$qemu_wrapper" 2>/dev/null || true
        if ! grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
            echo "== scm: FAIL (boot $boot cmd verdict; see $log) =="
            return 1
        fi
    done
    echo "== scm: PASS (sc round-trip + reboot-survival autostart) =="
    return 0
}

# CUI-4 acceptance (docs/02 "a tasklist/taskkill pair works against live
# processes; Ctrl+C interrupts a loop under cmd.exe; a job-object-using build
# tool completes"). One interactive boot over the console image: the
# EXPECT_PROCS block in console_expect.py types the session and asserts the
# markers, ^C included (the serial socket is bidirectional — docs/08).
procs() {
    # A VIRGIN console image (the scm() pattern): a booted image is REWRITTEN
    # by the guest, so its mtime outruns the modules and make would skip the
    # rebuild — the acceptance would then run against an image missing the
    # very programs it types.
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/tests/procs.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local sock="$ROOT/build/tests/procs.sock" log="$ROOT/build/tests/procs.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_PROCS=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        if grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
            echo "== procs: PASS (Ctrl+C interrupt + tasklist/taskkill + job tool) =="
            return 0
        fi
    fi
    wait "$qemu_wrapper" 2>/dev/null || true
    echo "== procs: FAIL (see $log) =="
    return 1
}

# CUI-5 acceptance (docs/02 "move/ren work under cmd.exe; a
# write-tmp-then-rename tool completes"). One interactive boot over the
# console image: the EXPECT_FILES block in console_expect.py types a ren, a
# cross-directory move, and a move /Y replace (the write-tmp-then-rename
# shape), asserting each file's content through its post-rename name.
files() {
    # A VIRGIN console image (the procs() pattern).
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/tests/files.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local sock="$ROOT/build/tests/files.sock" log="$ROOT/build/tests/files.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_FILES=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        if grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
            echo "== files: PASS (ren + move + move /Y replace under cmd.exe) =="
            return 0
        fi
    fi
    wait "$qemu_wrapper" 2>/dev/null || true
    echo "== files: FAIL (see $log) =="
    return 1
}

# The CUI-6 acceptance (docs/02 "a handle-inheritance redirect chain
# round-trips; a timeit-style tool reads real process/thread times; a
# restricted-token launch works"): the files() shape — a virgin console
# image driven by console_expect.py, which types the three baked tools and
# greps their markers off the serial log.
cui6() {
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/tests/cui6.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local sock="$ROOT/build/tests/cui6.sock" log="$ROOT/build/tests/cui6.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_CUI6=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        if grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
            echo "== cui6: PASS (times + handle-redirect + restricted-token under cmd.exe) =="
            return 0
        fi
    fi
    wait "$qemu_wrapper" 2>/dev/null || true
    echo "== cui6: FAIL (see $log) =="
    return 1
}

# The CUI-7 acceptance (docs/02 "reg save/load round-trips and survives
# reboot; an app on the VirtualAlloc2/write-watch path runs"): two boots of
# one console image. Boot 1 drives regtool (seed -> RegSaveKey ->
# RegLoadKey/verify/RegUnLoadKey -> RegNotifyChangeKeyValue) and watchapp
# (VirtualAlloc2 placement + write-watch + kernel-write marking) under a
# live cmd.exe, then exits cleanly. Boot 2 verifies both the seeded key and
# the saved hive FILE survived the power cycle, then ends the machine
# through ring-3 NtShutdownSystem(ShutdownPowerOff) - the clean QEMU exit
# is the live shutdown arm's verdict.
cui7() {
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null
    local img="$ROOT/build/tests/cui7.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local sock="$ROOT/build/tests/cui7.sock" log="$ROOT/build/tests/cui7.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if ! EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_CUI7=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== cui7: FAIL (boot 1; see $log) =="
        return 1
    fi
    wait "$qemu_wrapper" 2>/dev/null || true
    if ! grep -qE '\[KTEST\] module cmd.exe PASS' "$log"; then
        echo "== cui7: FAIL (boot 1 verdict; see $log) =="
        return 1
    fi

    local sock2="$ROOT/build/tests/cui7-2.sock" log2="$ROOT/build/tests/cui7-2.log"
    SERIAL_SOCK="$sock2" LOG="$log2" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    qemu_wrapper=$!
    if ! EXPECT_DEADLINE="${EXPECT_DEADLINE:-600}" EXPECT_CUI7_VERIFY=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock2" "$log2"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== cui7: FAIL (boot 2 verify; see $log2) =="
        return 1
    fi
    # The live NtShutdownSystem arm: QEMU must exit on its own, with the
    # kernel's shutdown line in the log.
    wait "$qemu_wrapper" 2>/dev/null || true
    if ! grep -q '\[KTEST\] shutdown action=2' "$log2"; then
        echo "== cui7: FAIL (no ring-3 shutdown line; see $log2) =="
        return 1
    fi
    echo "== cui7: PASS (reg save/load round-trip survived reboot; watchapp ran; ring-3 poweroff) =="
    return 0
}

# The CUI-8 acceptance leg (docs/19 §8, docs/02 "Done when"): (a) the kmt
# machine verdicts off the standard boot — progress while a fill is parked,
# the committed depth floor, in-flight cancellation; (b) the boundary
# progress case under a physically THROTTLED disk, where a park is
# guaranteed and the test's tolerant skip leg is forbidden; (c) the docs/19
# §8.1 determinism check — two identical boots must produce identical
# [KTEST] verdict lines; (d) the stress boot — every await parks (the
# aggressiveness knob, off on every default image) and the verdicts must
# still MATCH the default run's, or the drain knob leaked into observable
# behaviour and took the project's most valuable property with it.
cui8() {
    local fails=0
    make -C "$ROOT" >/dev/null || exit 1

    # (a) the standard test-image boot carries the kmt CUI-8 suite. An
    # EMPTY serial log means QEMU never launched the guest — an infra
    # flake, not a verdict — so that one case retries once, with the
    # launcher's own output kept for the post-mortem.
    local kmtlog="$BUILD/cui8-kmt-serial.log"
    local attempt
    for attempt in 1 2; do
        LOG="$kmtlog" TIMEOUT="${TIMEOUT:-900}" \
            "$ROOT/tools/qemu.sh" "$ROOT/build/proskrnl.hdd" \
            >"$BUILD/cui8-kmt-qemu.log" 2>&1 || true
        [[ -s "$kmtlog" ]] && break
        echo "cui8: empty serial log from the kmt boot (attempt $attempt);" \
             "see $BUILD/cui8-kmt-qemu.log" >&2
    done
    # Kernel serial lines end CRLF (DbgPrint), so no trailing anchor.
    if grep -q '\[KTEST\] CUI8 PASS' "$kmtlog"; then
        echo "[KTEST] cui8-kmt PASS"
    else
        echo "[KTEST] cui8-kmt FAIL (see $kmtlog and $BUILD/cui8-kmt-qemu.log)"
        fails=$((fails + 1))
    fi
    local depthLine maxDepth
    depthLine="$(grep -E '^\[KTEST\] blk depth ' "$kmtlog" | head -1 || true)"
    maxDepth="$(sed -nE 's/^\[KTEST\] blk depth max=([0-9]+).*/\1/p' <<<"$depthLine")"
    if [[ -n "$maxDepth" && "$maxDepth" -ge 8 ]]; then
        echo "[KTEST] cui8-depth PASS ($depthLine)"
    else
        echo "[KTEST] cui8-depth FAIL (line: '$depthLine')"
        fails=$((fails + 1))
    fi

    # (b) throttled boundary run, with the skip leg forbidden. Two knobs
    # together, each carrying half the guarantee: CUI8_STRESS zeroes the
    # await spin so EVERY await parks BY CONSTRUCTION — the spin's wall
    # time scales with host speed while a throttle is absolute, so on a
    # slower runner the spin can absorb the whole throttled latency and no
    # park ever happens (exactly how this stage first failed in CI) — and
    # the 4 MiB/s throttle makes each park a physically wide window (≥1 ms
    # per page), so the counter thread advances by real margins inside the
    # read syscall. The default-config conviction stays the kmt suite plus
    # the unthrottled tolerant run of this same test.
    # Every child boot below reuses $sublog, and the child truncates it only
    # once it actually reaches qemu — a child that dies earlier (make/mkimage
    # failure, a mingw compile error in a subset test) leaves the PREVIOUS
    # stage's log in place, which the greps and the det comparison would
    # accept as this stage's output (two copies of the same stale file
    # compare identical). Remove it up front so an early death yields a
    # missing log, which every check below treats as FAIL.
    local sublog="$BUILD/proskrnl-subset-serial.log"
    rm -f "$sublog"
    CUI8_STRESS=1 DRIVE_THROTTLE=$((4 * 1024 * 1024)) TIMEOUT=1200 \
        "$0" proskrnl progress_during_io >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-throttled-serial.log" 2>/dev/null || true
    if grep -q '\[KTEST\] progress_during_io PASS' "$sublog" &&
        ! grep -q 'progress_during_io.c.*no scheduling point' "$sublog"; then
        echo "[KTEST] cui8-throttled-progress PASS"
    else
        echo "[KTEST] cui8-throttled-progress FAIL (see $BUILD/cui8-throttled-serial.log)"
        fails=$((fails + 1))
    fi

    # (c) determinism (docs/19 §8.1): identical boots, identical verdicts.
    # Some [KTEST] lines carry timing-dependent MEASUREMENTS, not verdicts,
    # and are excluded: the blk depth line (its mean varies with harvest
    # timing), the timer line (prints the live tick count), the sweep line
    # (prints how many idle sweeps happened to run), and the `sched <name>
    # runs=N maxchoices=M` lines — the linearizability search reports how much
    # of the schedule space it walked, and the stress boot in (d) below walks
    # MORE of it by construction: zeroing the await spin makes every await a
    # parking point, and a parking point is a choice point. Measured:
    #
    #   normal  [KTEST] sched append runs=6 maxchoices=2 bound=2
    #   stress  [KTEST] sched append runs=7 maxchoices=3 bound=2
    #
    # with `test_linearizable_append_race PASS` and `SCHED PASS` identical on
    # both sides. The VERDICT is what must match; a wider search reaching the
    # same verdict is the knob working, not a determinism violation. (The
    # sched lines arrived after this filter was written and CI had not reached
    # this leg since, so the mismatch showed up the first time it ran.)
    local detFilter='blk depth|timer PASS|sweep PASS|cui8 stress knob|^\[KTEST\] sched '
    local detSubset=(file_coherence_mt read_write async_inline cancel_data_io io_teardown)
    rm -f "$sublog"
    "$0" proskrnl "${detSubset[@]}" >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-det-1-serial.log" 2>/dev/null || true
    grep -E '^\[KTEST\] ' "$sublog" 2>/dev/null | grep -vE "$detFilter" > "$BUILD/cui8-det-1.txt" || true
    rm -f "$sublog"
    "$0" proskrnl "${detSubset[@]}" >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-det-2-serial.log" 2>/dev/null || true
    grep -E '^\[KTEST\] ' "$sublog" 2>/dev/null | grep -vE "$detFilter" > "$BUILD/cui8-det-2.txt" || true
    if [[ -s "$BUILD/cui8-det-1.txt" ]] && cmp -s "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-2.txt"; then
        echo "[KTEST] cui8-determinism PASS ($(wc -l < "$BUILD/cui8-det-1.txt") verdict lines)"
    else
        echo "[KTEST] cui8-determinism FAIL (diff $BUILD/cui8-det-1.txt $BUILD/cui8-det-2.txt)"
        fails=$((fails + 1))
    fi

    # (d) the stress boot: CUI8_STRESS=1 bakes the marker that zeroes the
    # await spin, so EVERY await parks — same verdicts required.
    rm -f "$sublog"
    CUI8_STRESS=1 "$0" proskrnl "${detSubset[@]}" >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-stress-serial.log" 2>/dev/null || true
    if ! grep -q 'cui8 stress knob armed' "$sublog" 2>/dev/null; then
        echo "[KTEST] cui8-stress FAIL (knob never armed; see $BUILD/cui8-stress-serial.log)"
        fails=$((fails + 1))
    else
        grep -E '^\[KTEST\] ' "$sublog" | grep -vE "$detFilter" > "$BUILD/cui8-det-stress.txt" || true
        if cmp -s "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-stress.txt"; then
            echo "[KTEST] cui8-stress PASS (park-on-every-await verdicts identical)"
        else
            echo "[KTEST] cui8-stress FAIL (diff $BUILD/cui8-det-1.txt $BUILD/cui8-det-stress.txt)"
            fails=$((fails + 1))
        fi
    fi

    echo "== cui8: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# The CUI-9 measurement leg (docs/17 §2, docs/02 CUI-9): boot the console
# image at a FIXED memory size and drive mmceiling.exe, which spawns
# resident copies of itself until process creation refuses. Its verdict
# lines arrive over NtDisplayString (unmangled by conhost's renderer):
#   [KTEST] cui9 ceiling procs=<N> err=<code> availmb0=<a> availmb=<b>
#   [KTEST] cui9 perproc kb=<n>
# MEM is pinned here because the ceiling is only comparable at one memory
# size — docs/17 §1 records the numbers at this size. Once the milestone
# commits a floor (tests/cui/mmceiling_floor.txt), a sharing regression
# fails HERE, as a machine verdict, not in a semantic test (docs/17 §8
# "the one failure mode no semantic test catches").
cui9() {
    rm -f "$ROOT/build/proskrnl-console.hdd"
    make -C "$ROOT" console-img >/dev/null || exit 1
    local img="$ROOT/build/tests/cui9.hdd"
    mkdir -p "$ROOT/build/tests"
    cp "$ROOT/build/proskrnl-console.hdd" "$img"

    local sock="$ROOT/build/tests/cui9.sock" log="$ROOT/build/tests/cui9.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=512M TIMEOUT="${TIMEOUT:-1200}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!
    if ! EXPECT_DEADLINE="${EXPECT_DEADLINE:-900}" EXPECT_CUI9=1 \
        python3 "$ROOT/tests/run/console_expect.py" "$sock" "$log"; then
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== cui9: FAIL (see $log) =="
        return 1
    fi
    wait "$qemu_wrapper" 2>/dev/null || true

    local ceilingLine procs err
    ceilingLine="$(grep -E '^\[KTEST\] cui9 ceiling ' "$log" | head -1 | tr -d '\r' || true)"
    procs="$(sed -nE 's/.*procs=([0-9]+).*/\1/p' <<<"$ceilingLine")"
    if [[ -z "$procs" ]]; then
        echo "== cui9: FAIL (no ceiling verdict line; see $log) =="
        return 1
    fi
    echo "$ceilingLine"
    # err=0 means mmceiling filled its MAX_CHILDREN array without a refusal:
    # the reported procs is the harness cap, not the machine's ceiling.
    err="$(sed -nE 's/.*err=([0-9]+).*/\1/p' <<<"$ceilingLine")"
    if [[ -z "$err" || "$err" -eq 0 ]]; then
        echo "== cui9: FAIL (no refusal: hit mmceiling's MAX_CHILDREN cap at procs=$procs; raise the cap) =="
        return 1
    fi
    grep -E '^\[KTEST\] cui9 perproc ' "$log" | head -1 | tr -d '\r' || true

    local floorFile="$ROOT/tests/cui/mmceiling_floor.txt"
    if [[ -f "$floorFile" ]]; then
        local floor
        floor="$(tr -dc 0-9 < "$floorFile")"
        if [[ -z "$floor" || "$procs" -lt "$floor" ]]; then
            echo "== cui9: FAIL (ceiling procs=$procs below the committed floor '$floor') =="
            return 1
        fi
        echo "[KTEST] cui9 floor ok procs=$procs floor=$floor"
    fi
    echo "== cui9: PASS (ceiling procs=$procs) =="
    return 0
}

# The GUI-1 acceptance (docs/02 "a user program maps the framebuffer and
# draws a rectangle visible in a screendump; key input is readable"): boot
# the gui image with a QMP socket and a virtio keyboard, wait for the guest
# to report what it painted, screendump the scanout and check the pixels
# against that report, then press a key and watch it come back out of
# \Device\Input0.
#
# There is no oracle leg here and cannot be one: \Device\Fb0 and
# \Device\Input0 are HACK devices (docs/10 HACK-001/002) that NT does not
# have, so no tests/ntapi case can pin them on Wine (the G5 adaptation is
# written out in docs/03 "GUI-1 notes"). What stands in for the oracle is
# QEMU: the pixels are rendered by its device model and the key is injected
# by its input layer, neither of which the kernel controls (Art. 6).
gui() {
    make -C "$ROOT" gui-img >/dev/null
    local img="$ROOT/build/proskrnl-gui.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui.sock" log="$dir/gui.log" ppm="$dir/gui.ppm"
    mkdir -p "$dir"
    # The log too: qemu.sh truncates it, but not before this function starts
    # polling it, and a previous run's markers would satisfy every await
    # instantly -- screendumping a framebuffer the guest has not painted yet.
    rm -f "$sock" "$ppm" "$log"

    # The guest never powers itself off (it must hold the painted frame for
    # the screendump), so this leg always ends the guest itself.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" \
        TIMEOUT="${TIMEOUT:-300}" PASS_RE='\[KTEST\] gui input PASS' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    # Wait for a marker to appear in the serial log, or give up.
    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-180}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    gui_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui: FAIL ($1; see $log) =="
        return 1
    }

    if ! await '\[KTEST\] gui fb drawn '; then
        gui_fail "the guest never reported a painted framebuffer"; return 1
    fi
    if ! python3 "$ROOT/tests/gui/qmpctl.py" "$sock" screendump "$ppm"; then
        gui_fail "screendump failed"; return 1
    fi

    if ! await '\[KTEST\] gui input READY'; then
        gui_fail "the guest never opened \\Device\\Input0"; return 1
    fi
    if ! python3 "$ROOT/tests/gui/qmpctl.py" "$sock" sendkey a; then
        gui_fail "send-key failed"; return 1
    fi
    if ! await '\[KTEST\] gui input (PASS|FAIL)'; then
        gui_fail "no input verdict after send-key"; return 1
    fi

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    # Both halves must be green, and the picture must agree with the guest.
    if ! grep -qE '\[KTEST\] gui fb PASS' "$log"; then
        echo "== gui: FAIL (framebuffer half; see $log) =="; return 1
    fi
    if ! grep -qE '\[KTEST\] gui input PASS' "$log"; then
        echo "== gui: FAIL (input half; see $log) =="; return 1
    fi
    if ! python3 "$ROOT/tests/gui/check_rect.py" --log "$log" --ppm "$ppm"; then
        echo "== gui: FAIL (screendump does not match what the guest painted) =="; return 1
    fi
    echo "== gui: PASS (framebuffer rectangle in a screendump + key input) =="
    return 0
}

# GUI-2 (docs/02 "winemine.exe appears on screen"). Same shape as gui()
# above: boot the gui2 image with a QMP socket and a virtio keyboard, wait
# for winefb.drv to report the scanout and then a painted window,
# screendump, and check the picture against what the guest said.
#
# No oracle leg, for the same reason gui() has none -- \Device\Fb0 is a
# HACK device NT does not have (docs/03 "GUI-1 notes", the G5 adaptation).
# What stands in for it is QEMU's own device model rendering the pixels
# back (Art. 6), plus the fact that everything ABOVE the driver is
# unmodified Wine: user32, gdi32, comctl32 and winemine are the pinned
# tree's own binaries, and win32u is its own sources compiled as PE.
#
# The stack under those binaries is the shipping one: wineserver-lite runs as
# its own process here exactly as it does on the gui3/4/5 images. This leg
# used to be the last consumer of win32u's in-process dispatch mode, which
# made it a test of a superseded arrangement as much as of the applet; what
# it uniquely convicts -- a STOCK unmodified Wine app reaching the scanout --
# is unchanged, and now says something about the system that ships.
gui2() {
    make -C "$ROOT" gui2-img >/dev/null
    local img="$ROOT/build/proskrnl-gui2.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui2.sock" log="$dir/gui2.log" ppm="$dir/gui2.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # gui3's sizing, for gui3's reason: no COW, and this image now runs the
    # server beside the applet, each copying the images it maps.
    #
    # PASS_RE deliberately never matches: qemu.sh's verdict-killer reaps
    # QEMU GRACE seconds after the regex appears, and this leg still needs
    # the live QMP socket for the screendump AFTER the window marker. QEMU's
    # lifetime is owned here (qmpctl quit below), with qemu.sh's TIMEOUT as
    # the wedged-run backstop.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-1536M}" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='PRSK-GUI2-NEVER' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-600}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    gui2_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui2: FAIL ($1; see $log) =="
        return 1
    }

    # The server first, for the localizing reason every other gui leg awaits
    # it: a server that never came up otherwise surfaces as "no window", 900
    # seconds later, pointing at the wrong layer.
    if ! await '\[KTEST\] gui3 server READY'; then
        gui2_fail "wineserver-lite never published its transport"; return 1
    fi
    if ! await '\[KTEST\] gui2 mode '; then
        gui2_fail "winefb.drv never mapped the scanout"; return 1
    fi
    if ! await '\[KTEST\] gui2 window '; then
        gui2_fail "no window ever reached the scanout"; return 1
    fi
    # The first flush is the whole first paint (dibdrv composes the full
    # window before winefb flushes it); winemine then IDLES — no repaint
    # without input, so no later flush to wait for. The sleep lets the
    # scanout and QEMU's device model settle before the dump.
    sleep 3

    if ! python3 "$ROOT/tests/gui/qmpctl.py" "$sock" screendump "$ppm"; then
        gui2_fail "screendump failed"; return 1
    fi

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! python3 "$ROOT/tests/gui/check_window.py" --log "$log" --ppm "$ppm"; then
        echo "== gui2: FAIL (the screendump does not show what the guest painted) =="
        return 1
    fi
    echo "== gui2: PASS (winemine.exe on screen) =="
    return 0
}

# GUI-3 (docs/02 "two GUI processes run at once; Z-order, focus, cross-thread
# SendMessage, FindWindow all behave"): wineserver-lite as a PROCESS with two
# GUI clients above it. Same shape as gui2 -- this function owns QEMU's
# lifetime so the screendump can be taken while the windows are still up --
# but the verdict has two halves: what the guests REPORTED about each
# behaviour, and the pixels proving both windows really reached the scanout
# (tests/gui/check_gui3.py).
gui3() {
    make -C "$ROOT" gui3-img >/dev/null
    local img="$ROOT/build/proskrnl-gui3.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui3.sock" log="$dir/gui3.log" ppm="$dir/gui3.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # More memory than gui2: no COW, and this image runs THREE Wine processes
    # (the server plus two clients), each copying the images it maps.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-1536M}" \
        TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI3-NEVER' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    gui3_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui3: FAIL ($1; see $log) =="
        return 1
    }

    if ! await '\[KTEST\] gui3 server READY'; then
        gui3_fail "wineserver-lite never published its transport"; return 1
    fi
    if ! await '\[KTEST\] gui3 verdict (PASS|FAIL)'; then
        gui3_fail "the second GUI process never reached a verdict"; return 1
    fi
    # Both clients park with their windows up; let the last paint settle on
    # the scanout before dumping (the gui2 reasoning).
    sleep 3

    if ! python3 "$ROOT/tests/gui/qmpctl.py" "$sock" screendump "$ppm"; then
        gui3_fail "screendump failed"; return 1
    fi

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! python3 "$ROOT/tests/gui/check_gui3.py" --log "$log" --ppm "$ppm"; then
        echo "== gui3: FAIL (behaviour or pixels; see $log) =="
        return 1
    fi
    echo "== gui3: PASS (two GUI processes over wineserver-lite) =="
    return 0
}

# GUI-4 (docs/02 "windows can be grabbed and moved; clicks reach the right
# window"): two overlapping windows over wineserver-lite, driven from here
# through QEMU's tablet and keyboard (qmpctl absmove/button/sendkey). Every
# injection is awaited before the next -- the guests print on receipt -- so
# the choreography is sequenced, not timed. Two screendumps: before the
# drag (compositing: the upper window's colour wins the overlap; the cursor
# parked on background) and after it (the window moved; what it uncovered
# was repaired). tests/gui/check_gui4.py grades both halves.
gui4() {
    make -C "$ROOT" gui4-img >/dev/null
    local img="$ROOT/build/proskrnl-gui4.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui4.sock" log="$dir/gui4.log"
    local ppm1="$dir/gui4-before.ppm" ppm2="$dir/gui4-after.ppm" ppm3="$dir/gui4-cursor.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm1" "$ppm2" "$ppm3" "$log"

    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM="${MEM:-1536M}" TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI4-NEVER' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    gui4_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui4: FAIL ($1; see $log) =="
        return 1
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }

    await '\[KTEST\] gui4 A ready rect=' || { gui4_fail "A never came up"; return 1; }
    await '\[KTEST\] gui4 B ready wrect=.* ztop=PASS' || { gui4_fail "B never came up above A"; return 1; }
    await '\[KTEST\] gui4 mouse READY' || { gui4_fail "no pointer reader"; return 1; }

    # Geometry, all guest-reported: the scanout mode, the tablet's own abs
    # range, and the windows' rectangles. Nothing here assumes a size.
    local w h maxx maxy
    w=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    h=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+ h=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxx=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxy=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+,[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    local a_line b_line
    a_line=$(grep -oE '\[KTEST\] gui4 A ready rect=[-0-9]+,[-0-9]+,[0-9]+x[0-9]+' "$log" | tail -1)
    b_line=$(grep -oE '\[KTEST\] gui4 B ready wrect=[-0-9]+,[-0-9]+,[0-9]+x[0-9]+ crect=[-0-9]+,[-0-9]+,[0-9]+x[0-9]+ caption=[-0-9]+,[-0-9]+' "$log" | tail -1)
    local ax ay aw ah bx by bw bh cx cy capx capy
    ax=$(sed -E 's/.*rect=(-?[0-9]+),.*/\1/' <<<"$a_line")
    ay=$(sed -E 's/.*rect=-?[0-9]+,(-?[0-9]+),.*/\1/' <<<"$a_line")
    aw=$(sed -E 's/.*,([0-9]+)x[0-9]+$/\1/' <<<"$a_line")
    ah=$(sed -E 's/.*x([0-9]+)$/\1/' <<<"$a_line")
    bx=$(sed -E 's/.*wrect=(-?[0-9]+),.*/\1/' <<<"$b_line")
    by=$(sed -E 's/.*wrect=-?[0-9]+,(-?[0-9]+),.*/\1/' <<<"$b_line")
    bw=$(sed -E 's/.*wrect=-?[0-9]+,-?[0-9]+,([0-9]+)x.*/\1/' <<<"$b_line")
    bh=$(sed -E 's/.*wrect=-?[0-9]+,-?[0-9]+,[0-9]+x([0-9]+).*/\1/' <<<"$b_line")
    cx=$(sed -E 's/.*crect=(-?[0-9]+),.*/\1/' <<<"$b_line")
    cy=$(sed -E 's/.*crect=-?[0-9]+,(-?[0-9]+),.*/\1/' <<<"$b_line")
    local cw ch
    cw=$(sed -E 's/.*crect=-?[0-9]+,-?[0-9]+,([0-9]+)x.*/\1/' <<<"$b_line")
    ch=$(sed -E 's/.*crect=-?[0-9]+,-?[0-9]+,[0-9]+x([0-9]+).*/\1/' <<<"$b_line")
    capx=$(sed -E 's/.*caption=(-?[0-9]+),.*/\1/' <<<"$b_line")
    capy=$(sed -E 's/.*caption=-?[0-9]+,(-?[0-9]+).*/\1/' <<<"$b_line")
    if [ -z "$w" ] || [ -z "$maxx" ] || [ -z "$capy" ]; then
        gui4_fail "could not parse guest geometry"; return 1
    fi

    # Pixel -> tablet value, exact by construction: v = ceil(px*max/(w-1))
    # makes the guest's floor(v*(w-1)/max) reproduce px (qmpctl.py notes the
    # verbatim QMP->guest path this relies on), so `await` can gate on the
    # guest echoing the exact position back.
    move_px() {
        local vx=$(( ($1 * maxx + w - 2) / (w - 1) ))
        local vy=$(( ($2 * maxy + h - 2) / (h - 1) ))
        qmp absmove "$vx" "$vy" || return 1
        await "\[KTEST\] gui4 ptr x=$1 y=$2 btn=" || return 1
    }

    # Park the cursor over bare desktop and take the before-drag dump.
    local park1x=40 park1y=$((h - 100)) park2x=60 park2y=$((h - 40))
    move_px "$park1x" "$park1y" || { gui4_fail "pointer motion never arrived"; return 1; }
    sleep 2   # let the last flush settle (the gui2 reasoning)
    qmp screendump "$ppm1" || { gui4_fail "screendump 1 failed"; return 1; }

    # Click the centre of the overlap of A with B's CLIENT area (a frame
    # click would be a non-client message): it must reach B (above), never A.
    local ox=$(( ( (ax > cx ? ax : cx) + ( (ax + aw) < (cx + cw) ? (ax + aw) : (cx + cw) ) ) / 2 ))
    local oy=$(( ( (ay > cy ? ay : cy) + ( (ay + ah) < (cy + ch) ? (ay + ah) : (cy + ch) ) ) / 2 ))
    move_px "$ox" "$oy" || { gui4_fail "pointer motion lost"; return 1; }
    qmp button left down && qmp button left up
    await '\[KTEST\] gui4 B click ' || { gui4_fail "the overlap click never reached B"; return 1; }
    qmp sendkey b
    await '\[KTEST\] gui4 B char=62' || { gui4_fail "keyboard input never reached B"; return 1; }

    # Click A's exposed part: focus follows the click across processes.
    move_px $((ax + 50)) $((ay + 50)) || { gui4_fail "pointer motion lost"; return 1; }
    qmp button left down && qmp button left up
    await '\[KTEST\] gui4 A click ' || { gui4_fail "the exposed click never reached A"; return 1; }
    await '\[KTEST\] gui4 A active' || { gui4_fail "the click did not activate A"; return 1; }
    qmp sendkey a
    await '\[KTEST\] gui4 A char=61' || { gui4_fail "focus did not follow the click"; return 1; }

    # Grab B by its own advertised caption point and drag it +150,+120 in
    # ten awaited steps (DefWindowProc's modal loop moves the window per
    # WM_MOUSEMOVE under server-side capture; none of the drag is our code).
    local dragx=$capx dragy=$capy step
    move_px "$dragx" "$dragy" || { gui4_fail "pointer motion lost"; return 1; }
    qmp button left down
    for step in $(seq 1 10); do
        dragx=$((dragx + 15)); dragy=$((dragy + 12))
        move_px "$dragx" "$dragy" || { gui4_fail "drag motion lost at step $step"; return 1; }
    done
    qmp button left up
    await "\[KTEST\] gui4 B moved rect=$((bx + 150)),$((by + 120)),${bw}x${bh}" \
        || { gui4_fail "B never reported the dragged-to rectangle"; return 1; }

    # Park again (a different spot, so the await cannot match the first
    # park) and take the after-drag dump as it lands. Nothing repaints B
    # first: the arrow rode B's caption across the screen, and what that
    # left on the window is exactly what check_gui4.py grades (the
    # foreign-pixel check -- no pixel of B's may wear a colour from
    # elsewhere on the screen).
    move_px "$park2x" "$park2y" || { gui4_fail "pointer motion lost"; return 1; }
    sleep 2
    qmp screendump "$ppm2" || { gui4_fail "screendump 2 failed"; return 1; }

    # The other half of the same question: park the cursor INSIDE B's moved
    # client area and ask B -- still focused from the drag -- to repaint
    # under it. The flush covers the cursor's pixels, so dump 3 is where a
    # cursor that cannot survive a foreign writer disappears. The +150,+120
    # is the drag delta the await above already pinned.
    local park3x=$((cx + 150 + 40)) park3y=$((cy + 120 + 40))
    move_px "$park3x" "$park3y" || { gui4_fail "pointer motion lost"; return 1; }
    qmp sendkey r
    await '\[KTEST\] gui4 B char=72' || { gui4_fail "the repaint request never reached B"; return 1; }
    sleep 2
    qmp screendump "$ppm3" || { gui4_fail "screendump 3 failed"; return 1; }

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! python3 "$ROOT/tests/gui/check_gui4.py" --log "$log" --ppm1 "$ppm1" --ppm2 "$ppm2" \
            --ppm3 "$ppm3" --park1 "$park1x,$park1y" --park2 "$park2x,$park2y" \
            --park3 "$park3x,$park3y"; then
        echo "== gui4: FAIL (behaviour or pixels; see $log) =="
        return 1
    fi
    echo "== gui4: PASS (grabbed, moved, clicked -- the compositor holds) =="
    return 0
}

# GUI-5 (docs/02 "GUI finishing"): clipboard, hooks and AttachThreadInput
# cross-process over the unmodified pinned server, plus the guest half of
# the font-metrics differential (the same fontdiff.exe the oracle block
# above runs, diffed against the same committed golden). The clients judge
# everything they can from inside (gui5b's verdict lines); the harness only
# adds what needs the outside world: real injected keyboard input for the
# WH_KEYBOARD_LL hook — one 'k' while armed (hook line + char), a 'u' to
# unhook, one 'k' after (char only; the checker counts) — and the
# screendump. Keyboard only, deliberately no tablet: with no pointer
# DEVICE no process draws a cursor at all (cursor.c winefb_pointer_present),
# so the fills are pristine by construction rather than by timing.
gui5() {
    make -C "$ROOT" gui5-img >/dev/null
    local img="$ROOT/build/proskrnl-gui5.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui5.sock" log="$dir/gui5.log" ppm="$dir/gui5.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # gui3's sizing reasoning: no COW and four Wine processes across the leg
    # (the server, fontdiff, then the two clients).
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-1536M}" \
        TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI5-NEVER' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    # Count-gated await: the second 'k' press repeats a line the log already
    # holds, so presence alone cannot sequence it.
    await_count() {
        local pattern="$1" n="$2" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            [ "$(grep -cE "$pattern" "$log" 2>/dev/null)" -ge "$n" ] && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1
            sleep 1
        done
        return 1
    }
    gui5_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui5: FAIL ($1; see $log) =="
        return 1
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }

    await '\[KTEST\] gui3 server READY' || { gui5_fail "wineserver-lite never published its transport"; return 1; }
    await '\[KTEST\] fontdiff done n=' || { gui5_fail "fontdiff never finished its table"; return 1; }
    await '\[KTEST\] gui5 A ready rect=' || { gui5_fail "A never came up"; return 1; }
    await '\[KTEST\] gui5 verdict (PASS|FAIL)' || { gui5_fail "B never reached a verdict"; return 1; }
    await '\[KTEST\] gui5 hooks armed' || { gui5_fail "the LL hook was never armed"; return 1; }
    await '\[KTEST\] gui2 input READY' || { gui5_fail "no keyboard reader"; return 1; }

    # 'k' with the LL hook armed: the hook line must precede the char
    # reaching the (focused) judge window.
    qmp sendkey k
    await '\[KTEST\] gui5 llhook vk=4b' || { gui5_fail "the LL hook never saw the keystroke"; return 1; }
    await '\[KTEST\] gui5 B char=6b' || { gui5_fail "the keystroke never reached the window"; return 1; }

    # 'u' unhooks from inside the wndproc...
    qmp sendkey u
    await '\[KTEST\] gui5 unhook ok=1' || { gui5_fail "UnhookWindowsHookEx never ran"; return 1; }

    # ...and the second 'k' must reach the window but NOT the hook — the
    # checker convicts on the line counts.
    qmp sendkey k
    await_count '\[KTEST\] gui5 B char=6b' 2 || { gui5_fail "the post-unhook keystroke never arrived"; return 1; }

    # The listener notification is posted, so give it its own await rather
    # than assuming it beat the verdict line.
    await '\[KTEST\] gui5 A clipupdate' || { gui5_fail "A's clipboard listener never fired"; return 1; }

    sleep 2   # let the last flush settle (the gui2 reasoning)
    qmp screendump "$ppm" || { gui5_fail "screendump failed"; return 1; }

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! python3 "$ROOT/tests/gui/check_gui5.py" --log "$log" --ppm "$ppm" \
            --golden "$ROOT/tests/gdi/fontdiff.golden"; then
        echo "== gui5: FAIL (behaviour, pixels or metrics; see $log) =="
        return 1
    fi
    echo "== gui5: PASS (clipboard, hooks, AttachThreadInput, font differential) =="
    return 0
}

# GUI-5, the windowed conhost (docs/02 "GUI-ifying conhost"): an interactive
# cmd.exe session driven entirely through the REAL console — the window
# CONHOST_GUI draws, the real input queue, conhost's own ^C mapping — with
# the serial transport fully out of the console loop (it still carries the
# kernel's [KTEST] lines, which is HACK-004's permanent debug role). The
# verdict has three independent halves:
#   pixels  the console window is found ON the scanout (no guest process
#           declares it — conhost is stock Wine code), captioned, and the
#           session's typing advances pixels inside it only;
#   files   `looper > c:\ctrl.txt` then ctrl-c, `echo done > c:\out.txt`,
#           extracted from the image post-mortem — loop-alive + loop-caught-1
#           prove the window's WM_KEYDOWN -> map_to_ctrlevent -> CTRL_EVENT
#           ioctl path end to end (ENABLE_PROCESSED_INPUT honoured, the
#           CUI-4 serial intercept never involved), `done` proves the whole
#           write path behind the window;
#   serial  the kernel-side attach markers and the glue's mode marker.
# The guest powers itself off (`exit` -> cmd exits -> smss exits -> KiQemuExit),
# so unlike the other gui legs QEMU's end is awaited, not quit.
gui5con() {
    make -C "$ROOT" gui5con-img >/dev/null
    local img="$ROOT/build/proskrnl-gui5con.hdd"
    local dir="$ROOT/build/tests"
    local sock="$dir/gui5con.sock" log="$dir/gui5con.log"
    local ppm1="$dir/gui5con-before.ppm" ppm2="$dir/gui5con-after.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm1" "$ppm2" "$log"

    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM="${MEM:-1536M}" TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI5CON-NEVER' \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    gui5con_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui5con: FAIL ($1; see $log) =="
        return 1
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }

    await '\[KTEST\] gui5con conhost mode=window' || { gui5con_fail "the windowed conhost never picked window mode"; return 1; }
    await '\[KTEST\] conhost up' || { gui5con_fail "conhost never attached to condrv"; return 1; }
    await 'starting cmd\.exe' || { gui5con_fail "the interactive cmd never started"; return 1; }
    await '\[KTEST\] gui2 input READY' || { gui5con_fail "no keyboard reader"; return 1; }
    await '\[KTEST\] gui4 mouse READY' || { gui5con_fail "no pointer reader"; return 1; }

    # Find the console window by looking at the scanout: poll dumps until
    # check_gui5con.py --locate sees a captioned window with prompt glyphs.
    # The pointer has not moved yet, so no cursor can smear the search.
    local located="" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
    while ((SECONDS < deadline)); do
        qmp screendump "$ppm1" >/dev/null 2>&1 || true
        if located=$(python3 "$ROOT/tests/gui/check_gui5con.py" --locate \
                --log "$log" --ppm "$ppm1" 2>/dev/null); then
            break
        fi
        located=""
        kill -0 "$qemu_wrapper" 2>/dev/null || { gui5con_fail "QEMU died while waiting for the window"; return 1; }
        sleep 3
    done
    [ -n "$located" ] || { gui5con_fail "no console window ever appeared on the scanout"; return 1; }
    local bbox cx cy
    bbox=$(sed -E 's/^bbox=([^ ]+) .*/\1/' <<<"$located")
    cx=$(sed -E 's/.*center=([0-9]+),[0-9]+$/\1/' <<<"$located")
    cy=$(sed -E 's/.*center=[0-9]+,([0-9]+)$/\1/' <<<"$located")

    # Guest-reported geometry for the pixel->tablet arithmetic (the gui4
    # derivation; nothing assumes a size).
    local w h maxx maxy
    w=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    h=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+ h=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxx=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxy=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+,[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    if [ -z "$w" ] || [ -z "$maxx" ]; then
        gui5con_fail "could not parse guest geometry"; return 1
    fi

    # One activation click in the window's centre (click activation is
    # exempt from the focus-stealing rule; firstboot's transient windows can
    # therefore never leave the console unfocused). The cursor stays inside
    # the window for the rest of the leg, so dump 2's only out-of-box pixels
    # would be a real defect.
    qmp absmove $(( (cx * maxx + w - 2) / (w - 1) )) $(( (cy * maxy + h - 2) / (h - 1) ))
    sleep 1
    qmp button left down && qmp button left up
    sleep 2

    # The session. No serial echo exists in window mode, so pacing is by
    # what each step provably needs: looper prints loop-alive into the
    # REDIRECTED file immediately, and its busy loop is bounded at 60 s,
    # far beyond this choreography.
    qmp type 'c:\looper.exe > c:\ctrl.txt
'
    sleep 5
    qmp sendkey ctrl c
    sleep 3
    qmp type 'echo done > c:\out.txt
'
    sleep 3
    qmp screendump "$ppm2" || { gui5con_fail "screendump 2 failed"; return 1; }

    # `exit` powers the guest off (cmd -> smss exit -> KiQemuExit).
    qmp type 'exit
'
    local waited=0
    while kill -0 "$qemu_wrapper" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if ((waited > 120)); then
            gui5con_fail "the guest never powered off after exit"; return 1
        fi
    done
    wait "$qemu_wrapper" 2>/dev/null || true

    # The FILE half: what the console session provably wrote, read back out
    # of the image (the fatcheck idiom — mtools, not the guest).
    local esp_off=2097152
    rm -f "$dir/gui5con-out.txt" "$dir/gui5con-ctrl.txt"
    mcopy -n -i "$img@@$esp_off" ::/out.txt "$dir/gui5con-out.txt" 2>/dev/null \
        || { echo "== gui5con: FAIL (out.txt never written; see $log) =="; return 1; }
    mcopy -n -i "$img@@$esp_off" ::/ctrl.txt "$dir/gui5con-ctrl.txt" 2>/dev/null \
        || { echo "== gui5con: FAIL (ctrl.txt never written; see $log) =="; return 1; }
    grep -q "done" "$dir/gui5con-out.txt" \
        || { echo "== gui5con: FAIL (out.txt lacks 'done') =="; return 1; }
    grep -q "loop-alive" "$dir/gui5con-ctrl.txt" \
        || { echo "== gui5con: FAIL (looper never ran) =="; return 1; }
    grep -q "loop-caught-1" "$dir/gui5con-ctrl.txt" \
        || { echo "== gui5con: FAIL (ctrl-c never reached looper's handler) =="; return 1; }

    if ! python3 "$ROOT/tests/gui/check_gui5con.py" --log "$log" \
            --ppm1 "$ppm1" --ppm2 "$ppm2" --bbox "$bbox"; then
        echo "== gui5con: FAIL (window pixels; see $log) =="
        return 1
    fi
    echo "== gui5con: PASS (windowed conhost: typed, ^C-interrupted, files proven) =="
    return 0
}

# Every leg's serial logs are swept for unclaimed ring-0 faults on user
# addresses before the leg reports (tests/run/uacheck.sh, issue #32 A3): the
# recovery frame turns a missing probe into an ordinary-looking
# STATUS_ACCESS_VIOLATION, so nothing but this sweep distinguishes a leg that
# passed from a leg that passed while swallowing kernel faults. Done here, at
# the ONE dispatcher, rather than in each of the twenty legs — the marker
# scopes the sweep to logs THIS run wrote, so a stale log from an earlier run
# can neither excuse a leg nor condemn one.
UACHECK_MARKER="$BUILD/.uacheck-start"
mkdir -p "$BUILD"
: > "$UACHECK_MARKER"

# An EXIT trap rather than a wrapper function around the dispatch below: a
# `run_mode || status=$?` wrapper would put every leg inside a `||` list,
# where bash suspends errexit for the whole call tree — the legs are written
# under `set -e` and a leg that stopped failing early would be a false green,
# which is the one thing a verification tool may never introduce.
uacheck_sweep() {
    local status=$?
    # Swept even on a red leg: a leg that failed for its own reason may also
    # have swallowed a kernel fault, and that is the finding worth keeping.
    "$ROOT/tests/run/uacheck.sh" --since "$UACHECK_MARKER" "$ROOT/build" || status=1
    exit "$status"
}
trap uacheck_sweep EXIT

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    winetest) winetest ;;   # SUBTESTS filters manifest pairs (see the header)
    prebuild) prebuild ;;   # a BUILD step, not a leg: no verdict comes out of it
    fuzz)     fuzz "${@:2}" ;;
    persist)  persist ;;
    firstboot) firstboot ;;
    console)  console ;;
    scm)      scm ;;
    procs)    procs ;;
    files)    files ;;
    cui6)     cui6 ;;
    cui7)     cui7 ;;
    cui8)     cui8 ;;
    cui9)     cui9 ;;
    fatinterop) fatinterop ;;
    fatstress) fatstress ;;
    tornwrite) tornwrite ;;
    gui)      gui ;;
    gui2)     gui2 ;;
    gui3)     gui3 ;;
    gui4)     gui4 ;;
    gui5)     gui5 ;;
    gui5con)  gui5con ;;
    guiwtest) guiwtest ;;
    *) echo "usage: $0 {oracle [subtest...]|proskrnl [subtest...]|winetest [pair...]|prebuild|fuzz [fuzz.py options]|persist|firstboot|console|scm|procs|files|cui6|cui7|cui8|cui9|fatinterop|fatstress|tornwrite|gui|gui2|gui3|gui4|gui5|gui5con|guiwtest}" >&2
       echo "       subtest = a tests/ntapi test's base name, or a glob over base names" >&2
       echo "       pair    = a winetest <module>[:<subtest>] (ntdll, printf, ntdll:env), or a glob" >&2
       echo "                 (iteration only — the gate is the unfiltered run)" >&2
       exit 2 ;;
esac
