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
# GENERATED by tests/run/run.sh — hands the pinned wine the pinned FreeType
# and refuses to answer without the pinned DISPLAY (start_xvfb below).
if [ -z "\$DISPLAY" ]; then
    echo "run.sh: refusing to run the oracle with no DISPLAY — the pinned wine" >&2
    echo "        is built --with-x, and with no display winex11.drv falls back" >&2
    echo "        to the NULL driver, which refuses every window instead of" >&2
    echo "        failing. That answer is not the oracle's. Reach this wine" >&2
    echo "        through a run.sh mode that starts the display (start_xvfb)." >&2
    exit 2
fi
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

# The oracle's DISPLAY. The pinned wine is built --with-x, so its display
# driver is winex11.drv — and that driver is dlopen'd and FAIL-SOFT exactly
# like the font backend above: with no X connection user32 falls back to the
# null driver, which refuses every window ("The graphics driver is missing")
# and answers plausibly instead of failing. That is the same silent-divergence
# shape GUI-3 rebuilt the oracle to remove, so the runner OWNS the display
# rather than borrowing one: ONE Xvfb per invocation, pinned geometry, never
# the developer's screen. A run on a 4K laptop and a run on a headless CI
# runner then ask the same oracle the same question — which is the whole point
# of the switch (a --without-x oracle could not answer a window question at
# all, so every GUI gate had to be graded against something other than NT's
# behavior).
#
# 1280x800 is proskrnl's own scanout (tests/gui/check_gui6.py pins it, and
# smss starts explorer at that size), so the oracle's screen metrics —
# SM_CXSCREEN, where a default-placed window lands, what a maximized window
# measures — are the TARGET's, not merely fixed. Depth 24 is what Xvfb
# renders; wine reports 32bpp over it either way. -dpi tells the X server
# what to report for the screen's physical size: wine does not read it (its
# system DPI is the registry's LogPixels, defaulting to 96 —
# win32u/sysparams.c), but a screen that claims a different resolution than
# the metrics oracle assumes is a contradiction waiting to be believed by
# some future backend, so it is pinned to the same 96.
#
# $XVFB_SCREEN overrides for an experiment, the way $LC_ALL does.
: "${XVFB_SCREEN:=1280x800x24}"
XVFB_PID=""

start_xvfb() {
    [[ -n "$XVFB_PID" ]] && return 0
    # The pinned tree must actually HAVE the driver. A tree built before the
    # X switch (or restored from a cache that predates it) satisfies every
    # other check in this runner and answers from the null driver forever, so
    # it is refused by name here rather than diagnosed from a hundred window
    # tests failing. Same truthful marker tools/setup_linux.sh reconfigures
    # on: configure records the X11 client library it will dlopen, and errors
    # out when X is wanted but missing.
    local cfg="$ROOT/third_party/wine/include/config.h"
    if [[ "$WINE" == "$BUILD/wine-fonts" && -f "$cfg" ]] &&
        ! grep -q '^#define SONAME_LIBX11 ' "$cfg"; then
        echo "run.sh: the pinned wine was built --without-x — its user32 refuses" >&2
        echo "        every window, so it cannot be the oracle. Rebuild it:" >&2
        echo "        tools/setup_linux.sh (it detects and reconfigures this)." >&2
        exit 2
    fi
    if ! command -v Xvfb >/dev/null 2>&1; then
        echo "run.sh: Xvfb is not installed — the oracle has no display to run on." >&2
        echo "        Install it with the rest of the toolchain: tools/setup_linux.sh" >&2
        exit 2
    fi
    mkdir -p "$BUILD"
    # -displayfd lets the SERVER pick a free display number and tell us which
    # (over fd 3, here a file): two runs on one box — the fulltest legs, a
    # developer beside a CI-like sweep — must not fight over :0. The handoff
    # file is per-PROCESS for the same reason the display number is per-server:
    # `make fulltest` gives each leg its own build/ (a view), but two legs run
    # by hand in ONE tree would otherwise share this path and could read each
    # other's number.
    local fdfile="$BUILD/xvfb.$$.display"
    : > "$fdfile"
    Xvfb -displayfd 3 -screen 0 "$XVFB_SCREEN" -dpi 96 -nolisten tcp -noreset \
        3>"$fdfile" >/dev/null 2>&1 &
    XVFB_PID=$!
    local waited=0 num=""
    while (( waited < 300 )); do
        num="$(tr -d '[:space:]' <"$fdfile")"
        [[ -n "$num" ]] && break
        kill -0 "$XVFB_PID" 2>/dev/null || break
        sleep 0.1
        waited=$(( waited + 1 ))
    done
    rm -f "$fdfile"
    if [[ -z "$num" ]]; then
        # KILL BEFORE CLEARING: a server that started but had not written its
        # number inside the window above is alive and holding a display, and
        # clearing $XVFB_PID first is precisely what would make the EXIT trap's
        # stop_xvfb unable to reap it — leaking the thing that function exists
        # to prevent.
        stop_xvfb
        echo "run.sh: Xvfb failed to start a $XVFB_SCREEN display." >&2
        exit 2
    fi
    export DISPLAY=":$num"
    echo "== oracle display: Xvfb $DISPLAY ($XVFB_SCREEN) =="
}

stop_xvfb() {
    [[ -n "$XVFB_PID" ]] || return 0
    kill "$XVFB_PID" 2>/dev/null || true
    wait "$XVFB_PID" 2>/dev/null || true
    XVFB_PID=""
}

# The oracle's AUDIO backend — the audio Xvfb (docs/23 §6b, the third
# instance of the docs/06 trap after fonts and the display). The pinned wine
# is built --with-pulse, and winepulse.drv is dlopen'd and FAIL-SOFT exactly
# like the font and display backends: with no PulseAudio server mmdevapi
# loads no driver, enumerates ZERO endpoints, and every audio test skips —
# an answer that is not the oracle's. So the runner OWNS a server: ONE
# PulseAudio per invocation with a single null sink at the target's own
# format (48 kHz stereo — what winevsnd reports as the mix format), never a
# borrowed session daemon. A run on a desktop with a sound card and a run on
# a headless CI runner then ask the same oracle the same question.
PULSE_PID=""
PULSE_DIR=""

start_pulse() {
    [[ -n "$PULSE_PID" ]] && return 0
    # The pinned tree must actually HAVE the audio backend — the same
    # truthful-marker refusal as start_xvfb's SONAME_LIBX11 check: configure
    # records the client library in the generated Makefile's PULSE_LIBS
    # exactly when the backend is on (and errors out when it is wanted but
    # missing), so a tree restored from a pre-audio cache is refused by name
    # here rather than diagnosed from every audio pair skipping.
    local mkf="$ROOT/third_party/wine/Makefile"
    if [[ "$WINE" == "$BUILD/wine-fonts" && -f "$mkf" ]] &&
        ! grep -q '^PULSE_LIBS *=.*-lpulse' "$mkf"; then
        echo "run.sh: the pinned wine was built --without-pulse — its mmdevapi" >&2
        echo "        enumerates no endpoint, so it cannot be the audio oracle." >&2
        echo "        Rebuild it: tools/setup_linux.sh (it detects and reconfigures this)." >&2
        exit 2
    fi
    if ! command -v pulseaudio >/dev/null 2>&1; then
        echo "run.sh: pulseaudio is not installed — the oracle has no audio server." >&2
        echo "        Install it with the rest of the toolchain: tools/setup_linux.sh" >&2
        exit 2
    fi
    PULSE_DIR="$BUILD/pulse.$$"
    rm -rf "$PULSE_DIR"
    mkdir -p "$PULSE_DIR/runtime"
    # -n --daemonize=no: no default config, no forking — the runner owns the
    # process the way it owns Xvfb. The runtime/state paths are pinned under
    # build/ so the daemon neither reads nor writes the developer's
    # ~/.config/pulse, and the client socket is addressed absolutely via
    # PULSE_SERVER, so no XDG discovery happens on either side.
    env PULSE_RUNTIME_PATH="$PULSE_DIR/runtime" PULSE_STATE_PATH="$PULSE_DIR/state" \
        pulseaudio -n --daemonize=no --exit-idle-time=-1 --fail=true \
        --load="module-native-protocol-unix auth-anonymous=1 socket=$PULSE_DIR/native" \
        --load="module-null-sink sink_name=oracle rate=48000 channels=2" \
        >"$PULSE_DIR/daemon.log" 2>&1 &
    PULSE_PID=$!
    local waited=0
    while (( waited < 300 )); do
        [[ -S "$PULSE_DIR/native" ]] && break
        kill -0 "$PULSE_PID" 2>/dev/null || break
        sleep 0.1
        waited=$(( waited + 1 ))
    done
    if [[ ! -S "$PULSE_DIR/native" ]]; then
        # Kill before clearing, for the reason start_xvfb spells out.
        stop_pulse
        echo "run.sh: pulseaudio failed to start (see $PULSE_DIR/daemon.log)." >&2
        exit 2
    fi
    export PULSE_SERVER="unix:$PULSE_DIR/native"
    echo "== oracle audio: pulseaudio $PULSE_SERVER (null sink, 48 kHz stereo) =="
}

stop_pulse() {
    [[ -n "$PULSE_PID" ]] || return 0
    kill "$PULSE_PID" 2>/dev/null || true
    wait "$PULSE_PID" 2>/dev/null || true
    PULSE_PID=""
}

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
    oracle|fuzz|guiwtest) RUNS_ORACLE=1 ;;
    winetest)             [[ -z "${WTEST_NO_ORACLE:-}" ]] && RUNS_ORACLE=1 ;;
esac

# The same question one layer wider: which modes run wine ON THE HOST at all,
# and therefore need the display start_xvfb owns. It is a superset of the
# oracle modes — firstboot's registry differential and the compositor unit
# suite run host wine without being "the oracle leg" — and a mode missing
# from it cannot answer from the null driver by accident: the generated
# wrapper refuses to run with no DISPLAY (find_wine above), so the cost of
# forgetting one is a named failure, not a quiet second oracle.
RUNS_WINE=0
case "$MODE" in
    oracle|fuzz|firstboot|winefbunit|resolvunit|guiwtest) RUNS_WINE=1 ;;
    winetest) [[ -z "${WTEST_NO_ORACLE:-}" ]] && RUNS_WINE=1 ;;
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

# Cases whose ORACLE half is PARKED on a named bug in the pinned Wine — where
# the oracle does not merely fail to answer (that is `beyond_oracle`, and its
# contract forbids this use) but answers WRONGLY and intermittently. A spec
# that is right most of the time is not a spec, and a leg that re-rolls it
# until green is worse than one that says so. The proskrnl leg is UNAFFECTED:
# it sweeps every case in the image, so the kernel's half stays gated.
#
#   thread_skip_flags   sem_ps/thread_skip_flags.c creates a suspended thread,
#           terminates it, closes it, and immediately creates the next — four
#           times. On the oracle that pattern loses a race inside wineserver
#           roughly 6% of the time per run (measured: 29 failures / 480 runs
#           with a display, 28 / 480 without, so it is not the X switch), and
#           on a hosted CI runner it lost it twice out of two.
#
#           CONVICTED, not guessed (+server trace, one failing run):
#
#             01b0: new_thread( ..., flags=00000023, request_fd=9, ... )
#             01bc: *fd* 14 <- 33 bad thread id
#             01b0: new_thread() = INVALID_CID { tid=01c0, handle=0034 }
#
#           The reply carries a VALID tid and handle — the thread was created.
#           The error is stale: the dying thread's last fd message reaches
#           server/request.c receive_fd() after its sender is gone,
#           get_thread_from_id() sets STATUS_INVALID_CID for the failed
#           lookup, and that path logs "bad thread id", closes the fd and
#           returns WITHOUT clear_error() — so the error rides out on the
#           reply of whatever request was being handled. NtCreateThreadEx
#           hands STATUS_INVALID_CID to a caller whose thread exists, and
#           leaks it.
#
#           This is an upstream wineserver bug, not a boundary question, and
#           fixing it is a Wine-fork change outside the unixlib seam (G9) —
#           a separate decision from this list. Un-park the moment the pin
#           carries a fix: the case is right and the kernel passes it.
#
# Add a name here only with that shape of reason: the oracle must be WRONG,
# the mechanism named in the pinned tree's own source, and the evidence a
# trace rather than a failure rate. A case that is merely flaky belongs in
# neither list — find out why first.
ORACLE_PARKED_CASES="thread_skip_flags"

oracle_is_parked() {   # $1 = test base name
    local name
    for name in $ORACLE_PARKED_CASES; do
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

# The search-order probe DLL (sem_ps/dll_load.c) and the per-test .exes are
# built by the MAKEFILE (`ntapi-tests`, one rule per source), not here: the
# image bakes the whole suite, so a second compiler invocation with its own
# flags would be a second authority for what a test binary is (Art. 11). The
# output directory is the one the Makefile writes, so the oracle leg finds
# exactly the binaries the image carries.
build_helper_dll() {   # echoes the .dll path
    make -C "$ROOT" "$BUILD/ntapi/prshelper.dll" >&2 || return 1
    echo "$BUILD/ntapi/prshelper.dll"
}

# Build one test and echo its .exe path. Delegating to make also keeps the
# staleness rules in one place — a bucket's util.h and the GENERATED
# syscall/torture_matrix.inc are prerequisites there, and a stale .exe
# reporting the previous build's verdict as this one's is the failure that
# rule exists to prevent (measured: a stale ptr_torture.exe reported a panic
# the current generated table no longer produces).
#
# A compile failure is fatal to the whole run rather than silently re-running
# the previous build's .exe: `oracle`/`proskrnl` are invoked as
# `... || fails=...` at the bottom of this file, which suppresses `set -e`
# throughout their bodies. That is the same fabricated-plausible-answer
# failure Art. 12 forbids in the kernel, in the harness that judges it.
build_test() {   # $1 = .c path; echoes the .exe path
    local src="$1" name exe
    name="$(basename "${src%.c}")"
    exe="$BUILD/ntapi/$name.exe"
    if ! make -C "$ROOT" "$exe" >&2; then
        echo "run.sh: FAILED to build $src — no verdict for '$name'" >&2
        return 1
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

# docs/23 §6b: the audiosmoke pin — the fontsmoke recipe applied to sound.
# The pulse backend is dlopen'd and FAIL-SOFT like the font and display
# backends: with no server mmdevapi enumerates zero endpoints and every
# audio pair SKIPS, which counts as green. Ask the oracle for a render
# endpoint and check it answers (tests/audio/audiosmoke.c). Oracle-only:
# it links ole32, which the proskrnl ntapi image does not carry.
oracle_audiosmoke() {
    local audexe audout
    audexe="$BUILD/ntapi/audiosmoke.exe"
    if [[ ! -f "$audexe" || "$ROOT/tests/audio/audiosmoke.c" -nt "$audexe" || \
          "$NTAPI/ntapi.c" -nt "$audexe" ]]; then
        "$CC_ORACLE" $CFLAGS_COMMON -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -Wl,--entry=ntapi_start "$ROOT/tests/audio/audiosmoke.c" "$NTAPI/ntapi.c" \
            "${WINE_LIBS[@]}" "$WINE_PE/ole32/x86_64-windows/libole32.a" -lgcc -o "$audexe" >&2
    fi
    audout="$("$WINE" "$audexe" 2>&1 || true)"
    echo "$audout"
    echo "$audout" | tr -d '\r' | grep -qE '^\[KTEST\] audiosmoke PASS$'
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

# Build every test .exe, run nothing (see the header). One `make -j` over the
# suite: the Makefile owns the recipe and the staleness rules, so a prebuilt
# tree and a leg-built one are the same tree. A build failure is fatal here
# for the reason it is fatal in build_test — a missing .exe must never be
# silently re-supplied by a previous build.
prebuild() {
    local srcs=() src
    while read -r src; do srcs+=("$src"); done < <(all_sources)
    if ! make -C "$ROOT" -j"$ORACLE_JOBS" ntapi-tests >&2; then
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
    check_subtests cmd-standalone fontsmoke fontdiff audiosmoke
    mkdir -p "$BUILD/ntapi"
    build_helper_dll >/dev/null

    local srcs=() par=() ser=() src
    while read -r src; do
        # A parked case is dropped from the SWEEP but never from the runner:
        # naming it explicitly (`run.sh oracle thread_skip_flags`) runs it, so
        # the evidence for un-parking is one command away. Announced, never
        # silent — a case that vanished quietly is how a sweep starts reading
        # green for the wrong reason.
        if (( ${#SUBTESTS[@]} == 0 )) && oracle_is_parked "$(basename "${src%.c}")"; then
            echo "== oracle: $(basename "${src%.c}") PARKED — the pinned Wine answers it" \
                 "wrongly (see ORACLE_PARKED_CASES); the proskrnl leg still gates it =="
            continue
        fi
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
    selected audiosmoke    && { oracle_audiosmoke    || fails=$((fails+1)); }

    echo "== oracle: $fails failing =="
    return $(( fails > 0 ? 1 : 0 ))
}

# --- the ONE test image -----------------------------------------------------
#
# Every leg below boots the SAME disk image and says on the QEMU command line
# which leg it is (GUEST_LEG) and, for the two sweeps, which subset
# (GUEST_SUBTESTS) — tools/qemu.sh publishes both through fw_cfg and the
# session manager reads them (user/smss/session.c).
#
# There were fourteen images. A leg was selected by whether its client file
# was on the volume, so every leg needed a bake of its own, two legs could
# never share one, and a FILTERED run was yet another image — build/tests/
# proskrnl-subset.hdd, wtest-subset.hdd — that a later run or a human could
# mistake for the gate's. The payload lists that made them drifted apart, and
# a differential leg whose image is not the product's measures the difference
# (the print-winfiles story in the Makefile is one instance of the cost).
#
# A leg that MUTATES the volume still copies it first: `make test` boots the
# image in place, and a leg reading a virgin hive must not be handed that
# boot's leavings.
test_image() {   # echoes the path of the freshly built test image
    # ALWAYS rebuild, never just "build it if missing": these are regression
    # gates, and judging a stale kernel against fresh test sources reports the
    # previous build's verdict as this one's. make is incremental, so the cost
    # is nil when nothing changed.
    make -C "$ROOT" test-img >&2 || exit 1
    echo "$ROOT/build/proskrnl-test.hdd"
}

# A private COPY of it, under the caller's name, for a leg that mutates the
# volume or reads it back afterwards.
test_image_copy() {   # $1 = destination path; echoes it
    local src
    src="$(test_image)" || exit 1
    mkdir -p "$(dirname "$1")"
    cp "$src" "$1"
    echo "$1"
}

# Boot the ntapi sweep and read each test's own [KTEST] <name> PASS line off
# the serial log. The session manager (user/smss/session.c, launched by the
# kernel at end of boot) sweeps C:\ntapi, runs the selected .exes as
# console-less Wine processes, and prints '[KTEST] ntapi done' when the sweep
# finishes — the boot's stop condition here.
#
# A filtered run passes its query to the GUEST, so the sweep — and the boot —
# is as short as the subset while the image stays the gate's. Its serial log
# still carries its own name: a partial run's log must never be mistaken for
# the gate's (or feed a later fatcheck/ftrace as if it were).
proskrnl() {
    check_subtests
    local img tag=""
    (( ${#SUBTESTS[@]} )) && tag="-subset"
    img="$(test_image_copy "$ROOT/build/tests/proskrnl$tag.hdd")" || exit 1

    local log="$ROOT/build/tests/proskrnl$tag-serial.log"
    LOG="$log" PASS_RE="\[KTEST\] ntapi done" TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=ntapi GUEST_SUBTESTS="${SUBTESTS[*]-}" \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true

    # The symbolized sidecar (proskrnl-serial.sym.log) is qemu.sh's job now —
    # every leg gets one (Art. 9); the verdict greps stay on the raw log.
    local fails=0 src name names=()
    while read -r src; do names+=("$(basename "${src%.c}")"); done < <(all_tests)
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
    # Net-2 (docs/24 §6e): the FULL sweep must have genuinely PENDED socket
    # requests — an inline-only \Device\Afd passes every semantic test, so
    # the win is this number. Subset runs may select no sem_net test and
    # are exempt; the gate is the unfiltered leg.
    if (( ${#SUBTESTS[@]} == 0 )); then
        local netstats pended
        netstats="$(grep -aE '^\[KTEST\] net stats ' "$log" | tail -1 | tr -d '\r' || true)"
        pended="$(sed -nE 's/.* pended=([0-9]+).*/\1/p' <<<"$netstats")"
        if [[ -z "$pended" || "$pended" -eq 0 ]]; then
            echo "[KTEST] net-pended FAIL (no pended completions: '$netstats')"
            fails=$((fails + 1))
        else
            echo "[KTEST] net-pended PASS ($netstats)"
        fi
    fi
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

# Which pairs boot the audio image rather than the CUI one (docs/23 §6c):
# the audio test modules import user32/ole32/winmm for REAL (message
# windows, COM apartments), so their pairs cannot run on the CUI machine —
# the manifest header's audio amendment to rule (c).
wtest_is_audio() {   # $1 = exe
    case "$1" in
        mmdevapi_test.exe|winmm_test.exe) return 0 ;;
        *) return 1 ;;
    esac
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
    # timeout out of them. The manifest FILE is baked verbatim, so the
    # timeout reaches the runner that honors it without passing through here.
    local wtestExes=() wtestSubs=() wtestKeys=()
    local line
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        local exe="${line%%:*}" rest="${line#*:}"
        local sub="${rest%%:*}"
        wtestExes+=("$exe"); wtestSubs+=("$sub")
        wtestKeys+=("$exe:$sub")
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
        local selExes=() selSubs=() selKeys=()
        for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
            for pat in "${SUBTESTS[@]}"; do
                if wtest_matches "$pat" "${wtestExes[i]}" "${wtestSubs[i]}"; then
                    selExes+=("${wtestExes[i]}"); selSubs+=("${wtestSubs[i]}")
                    selKeys+=("${wtestKeys[i]}")
                    break
                fi
            done
        done
        wtestExes=("${selExes[@]}"); wtestSubs=("${selSubs[@]}")
        wtestKeys=("${selKeys[@]}")
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

    # %windir%\{win,system}.ini are baked by the Makefile ($(SYSINIFILES),
    # generated from the pinned wine.inf's own [SystemIni] payload by
    # tools/gen_sysini.py — never hand-typed). Self-checked HERE whenever the
    # oracle leg has already materialised the prefix: byte-identical to what
    # wineboot wrote there, so a wine pin that edits [SystemIni] cannot drift
    # the two legs apart unnoticed. Measured, not hypothetical — without
    # win.ini, kernel32:profile's NULL-filename cases diverge on the file's
    # absence rather than on anything the kernel does.
    if [[ -f "$WINEPREFIX/drive_c/windows/win.ini" ]]; then
        python3 "$ROOT/tools/gen_sysini.py" --check "$WINEPREFIX" >/dev/null
    fi

    # --- proskrnl leg (the REGRESSION gate) ---
    # The pairs PARTITION by exe onto two BOOTS (docs/23 §6c): the audio
    # modules need the virtio-snd device on the QEMU command line, every
    # other pair does not. Same image both times — the audio payload is on
    # it either way; what differs is the DEVICE and the filter each boot is
    # given. They used to be two bakes, each carrying a manifest generated
    # for its half, and a subset run generated a third; the file on the media
    # therefore recorded which subset had last been asked for, where a later
    # run or a human reading it would take it for the full sweep.
    local img log logAudio tag=""
    (( ${#SUBTESTS[@]} )) && tag="-subset"
    local w cuiKeys=() audKeys=()
    for ((w = 0; w < ${#wtestKeys[@]}; w++)); do
        if wtest_is_audio "${wtestExes[w]}"; then audKeys+=("${wtestKeys[w]}")
        else cuiKeys+=("${wtestKeys[w]}"); fi
    done
    img="$(test_image_copy "$ROOT/build/tests/wtest$tag.hdd")" || exit 1
    log="$ROOT/build/tests/wtest$tag-serial.log"
    logAudio="$ROOT/build/tests/wtest-audio$tag-serial.log"

    # The GUEST filter is the exact pair list this boot must run — the keys
    # themselves, not the user's query: the CUI/audio partition is the
    # harness's decision and has to reach the guest as a decision, and a
    # `<module>:<subtest>` key is a pattern that matches exactly its own pair
    # (user/smss/session.c SessionWtestPatternMatches).
    #
    # 1 GiB of guest RAM: no eviction (Art. 3) means the page cache holds
    # every test binary's pages for the whole sweep — memory is provisioned,
    # not managed.
    if (( ${#cuiKeys[@]} )); then
        LOG="$log" MEM=1024M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-1800}" \
            GUEST_GUI=0 GUEST_LEG=wtest GUEST_SUBTESTS="${cuiKeys[*]}" \
            "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    fi

    if (( ${#audKeys[@]} )); then
        # The audio boot: virtio-snd backed by the null audiodev — the pairs
        # assert the WASAPI clocks and shapes, not the recording (the WAV
        # verdict is the audio leg's, §6a). Its own copy of the image so the
        # two boots' hive mutations cannot interleave.
        local imgAudio
        imgAudio="$(test_image_copy "$ROOT/build/tests/wtest-audio$tag.hdd")" || exit 1
        LOG="$logAudio" MEM=1024M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-1800}" \
            GUEST_GUI=0 GUEST_LEG=wtest GUEST_SUBTESTS="${audKeys[*]}" \
            EXTRA_DEVICES="virtio-sound-pci,audiodev=snd0" AUDIODEV="none,id=snd0" \
            "$ROOT/tools/qemu.sh" "$imgAudio" >/dev/null 2>&1 || true
    fi

    # No ^ anchor: conhost cursor escapes may share the verdict's line (the
    # run.sh console precedent). Each pair is graded from ITS boot's log.
    local vlog
    for ((i = 0; i < ${#wtestKeys[@]}; i++)); do
        if wtest_is_audio "${wtestExes[i]}"; then vlog="$logAudio"; else vlog="$log"; fi
        if grep -qF "[KTEST] wtest ${wtestKeys[i]} PASS" "$vlog" 2>/dev/null; then
            echo "[KTEST] wtest ${wtestKeys[i]} PASS"
        else
            echo "[KTEST] wtest ${wtestKeys[i]} FAIL"
            fails=$((fails + 1))
        fi
    done
    echo "== winetest: $fails failing =="
    return $((fails > 0 ? 1 : 0))
}

# The oracle half of the trophy gate: the SAME user32_test.exe, the same msg
# module, under the pinned wine on the runner's own display (start_xvfb).
#
# It exists because the leg's number needs a reference. proskrnl's failure
# count is graded against a budget, and a budget is only as honest as what it
# is a budget FOR: without this half, an assertion that fails on unmodified
# Wine in this environment and an assertion that fails because of the kernel
# are the same number. With it, the two are separable — the oracle answers
# from the same unmodified user32/gdi32/comctl32 PE binaries the target runs,
# above the same win32u, with only the display driver and everything under it
# different (winex11.drv on X vs. winefb.drv on \Device\Fb0 over our own
# kernel). A divergence between the two halves is therefore localized to that
# seam by construction.
#
# It is NOT the spec authority, and the switch to --with-x did not make it
# one: an X11 message environment is no more "what NT does" than nulldrv was
# (the point docs/03 "GUI-5 winetest notes" made when it rejected an X
# oracle). The spec stays msg.c's own ok()/todo_wine assertions. What the X
# oracle buys is the thing a --without-x wine could not give at any price: a
# SECOND run of the same code, so a number has something to be compared with.
#
# Ratcheted like the kernel half, against its own file
# (tests/winetest/msg-budget-oracle.txt) rather than demanded green: measured,
# unmodified Wine does not answer this module with zero. It answers ONE, in
# every run, and the one is msg.c:5730 succeeding inside a todo_wine block —
# a stale tag in Wine's own suite, not a divergence of ours (the budget file
# names it). A ceiling of one is what that fact looks like written down; it
# only ever ratchets DOWN, and a Wine pin that fixes the tag is what moves it.
#
# The count is read from winetest's own summary line rather than the exit
# status, because a shell sees an exit code modulo 256 and a failure count
# does not clip — but the two ARE cross-checked below, and that check exists
# because the first draft of this parser was wrong in a way nothing else
# would have caught: this module spawns ~21 children, each printing its own
# "17 tests executed (… 0 failures)" summary, and the parent's line says "1
# failure" — SINGULAR. A `failures\)` match therefore skipped the parent and
# silently read a child's zero. The parent's line is the LAST one (it waits
# on its children before printing), and its count is also its exit status.
guiwtest_oracle() {   # $1 = the user32_test.exe both halves run
    local exe="$1"
    local budgetfile="$ROOT/tests/winetest/msg-budget-oracle.txt"
    local olog="$BUILD/wtests/user32_test.msg.oracle.log"
    local rc=0 failures budget
    # `|| true` for the reason the kernel half's verdict grep needs one: under
    # `set -o pipefail` an absent or comment-only budget file fails the
    # pipeline and `set -e` kills the leg BEFORE the message below can say so.
    budget="$(grep -vE '^\s*(#|$)' "$budgetfile" | head -1 | tr -d '[:space:]' || true)"
    if ! [[ "$budget" =~ ^[0-9]+$ ]]; then
        echo "== guiwtest-oracle: msg-budget-oracle.txt holds no number ==" >&2
        return 2
    fi
    # A tree built before the GUI-5 test target has no user32_test.exe (the
    # stale-cache case the third_party cache's v5 bump exists for). Without
    # this the run produces no summary line and the branch below reports "the
    # msg run never finished" — the --without-x hang's signature — for a file
    # that was simply not there.
    if [[ ! -f "$exe" ]]; then
        echo "== guiwtest-oracle: FAIL (no $exe — the pinned tree's user32 test" \
             "module is not built; run tools/setup_linux.sh) ==" >&2
        return 1
    fi
    mkdir -p "$BUILD/wtests"
    # A scratch cwd, like the CUI oracle half: msg.c writes nothing, but the
    # rule that an oracle never runs in $ROOT is the harness's, not the
    # test's. The cap is a BACKSTOP against a wedged run eating the CI job,
    # not a budget — the run takes minutes.
    (cd "$BUILD/wtests" && timeout -s KILL "${GUIWTEST_ORACLE_TIMEOUT:-1800}" \
        "$WINE" "$exe" msg) >"$olog" 2>&1 || rc=$?
    failures="$(grep -oE '[0-9]+ (failure|failures)\)' "$olog" | tail -1 | grep -oE '^[0-9]+' || true)"
    if [[ -z "$failures" ]]; then
        # No summary line at all: the module never finished. That is exactly
        # the --without-x oracle's own failure mode (it hung in
        # test_SendMessage_other_thread on a window that was never created),
        # so it is named rather than folded into a count — a run that did not
        # run is not a measurement.
        echo "== guiwtest-oracle: FAIL (no winetest summary — the msg run never" \
             "finished, exit=$rc; see $olog) =="
        return 1
    fi
    # The cross-check the comment above promises. Below 255 the exit status IS
    # the count, so a disagreement means the runner misread one of the two and
    # neither number may be graded — it is reported as a broken measurement
    # rather than resolved in favour of whichever is smaller.
    if (( rc < 255 && rc != failures )); then
        echo "== guiwtest-oracle: FAIL (the run exited $rc but its summary line" \
             "says $failures — the runner cannot tell what the oracle answered;" \
             "see $olog) =="
        return 1
    fi
    echo "[KTEST] guiwtest-oracle user32:msg failures=$failures budget=$budget"
    if (( failures > budget )); then
        echo "== guiwtest-oracle: FAIL ($failures failures against a budget of" \
             "$budget on unmodified Wine; see $olog) =="
        return 1
    fi
    if (( failures < budget )); then
        echo "== guiwtest-oracle: PASS — and $failures < budget $budget:" \
             "ratchet msg-budget-oracle.txt down =="
    else
        echo "== guiwtest-oracle: PASS ($failures failures, at budget) =="
    fi
    return 0
}

# GUI-5's trophy gate (docs/02 "the real trophy: run Wine's
# user32/tests/msg.c"): the pinned tree's own user32_test.exe, whole msg
# module, over the full GUI stack — win32u, wineserver-lite, winefb, the
# windowed message machinery — swept by the same kernel wtest runner the
# CUI manifest uses (per-pair timeout via the manifest's third field).
#
# TWO HALVES since the oracle gained a display driver: guiwtest_oracle above
# runs the same binary under the pinned wine on Xvfb (it was PROSKRNL-ONLY
# while the oracle was --without-x — under the null display driver user32
# refuses every window and the suite hangs; tests/winetest/manifest-gui.txt
# has that finding). The spec is still msg.c's own ok()/todo_wine assertions
# (third-party, Windows-verified; todo_wine applies identically on proskrnl).
# The verdict is a BUDGET RATCHET: tests/winetest/msg-budget.txt holds the
# currently-accepted failure count, parsed against winetest's own summary
# line (the exit code clips at 255 and the count does not); more failures
# than the budget is a regression and fails the leg, fewer is a note to
# ratchet the file down in the commit that earned it. 0 is the milestone's
# end state.
guiwtest() {
    local budgetfile="$ROOT/tests/winetest/msg-budget.txt"
    local budget
    budget="$(grep -vE '^\s*(#|$)' "$budgetfile" | head -1 | tr -d '[:space:]')"
    if ! [[ "$budget" =~ ^[0-9]+$ ]]; then
        echo "== guiwtest: msg-budget.txt holds no number ==" >&2
        return 2
    fi
    local testexe="$ROOT/third_party/wine/dlls/user32/tests/x86_64-windows/user32_test.exe"

    # --- oracle half first (minutes), then the kernel half (an hour under
    # TCG). Its verdict does not gate the kernel half: a red leg must not
    # hide the leg behind it, and the number the ratchet wants is measured
    # either way. Both are folded into the leg's exit status at the end.
    local oracleFail=0
    guiwtest_oracle "$testexe" || oracleFail=1

    # The test image carries user32_test.exe and BOTH manifests; the leg name
    # picks manifest-gui.txt (user/smss/session.c SessionRun). It used to bake
    # an image of its own, whose payload was a hand-copied subset of the
    # winetest image's — the kind of second list that drifts.
    local img
    img="$(test_image_copy "$ROOT/build/tests/guiwtest.hdd")" || exit 1

    # 2 GiB: no COW and this boot holds the server, conhost, a multi-MB
    # test binary and its spawned children resident at once.
    local log="$ROOT/build/tests/guiwtest-serial.log"
    LOG="$log" MEM=2048M PASS_RE="\[KTEST\] wtest done" TIMEOUT="${TIMEOUT:-3600}" \
        GUEST_GUI=0 GUEST_LEG=guiwtest \
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
    #
    # `|| true` is load-bearing, not defensive: this script runs under
    # `set -o pipefail`, so a grep that matches NOTHING fails the whole
    # pipeline, the assignment inherits that status, and `set -e` kills the
    # leg on the spot. The no-verdict branch below — the one that names a
    # hung, panicked or timed-out boot — was therefore unreachable: the leg
    # exited 1 having printed nothing about why, which is the single worst
    # moment to say nothing. Found by tracing a deliberately truncated run.
    local verdict failures
    verdict="$(grep -oE '\[KTEST\] wtest user32_test\.exe:msg (PASS|FAIL \(exit=0x[0-9a-f]+\))' "$log" | tail -1 || true)"
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
    # The kernel half passed; the leg has not until both halves have. Every
    # `return 1` above already fails it, so this is the only path where the
    # oracle's verdict can still decide.
    if (( oracleFail )); then
        echo "== guiwtest: FAIL (the kernel half passed, the ORACLE half did not) =="
        return 1
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
    # The verdict-killer's line must be the END OF THE BOOT, not the
    # workload's own PASS: the kernel keeps running (and writing) for the
    # kill's grace period, so killing on the module line leaves the image
    # frozen mid-write inside a LATER kmt suite — the fatcheck below then
    # reads a power-loss state (a half-built file's over-long chain, a FAT
    # mirror written on one copy) and calls the volume dirty, and the
    # completeness bracket can catch a write that was in flight when
    # QEMU died. `[KTEST] sweep PASS` is kernel/init/main.c's last line
    # before KiQemuExit, after which nothing touches the disk, so the image
    # this leg checks is the volume the machine actually left behind. The
    # workload's own verdict is the grep below, unchanged.
    WRITE_LOG="$logbin" LOG="$serial" PASS_RE="\[KTEST\] sweep PASS" \
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
    # A VIRGIN image: the test image may already carry a seeded hive from an
    # earlier `make test` (m8_persist runs on every boot), which would make
    # boot 1 verify instead of seed. Rebuilding it resets the disk, and this
    # leg gets its own copy so the two boots are the only writers.
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/persist.hdd")" || exit 1

    local log1="$ROOT/build/tests/persist1.log" log2="$ROOT/build/tests/persist2.log"
    # Boot 1 of a virgin image runs the whole CUI-1 firstboot INF pass
    # (minutes under TCG); boot 2 skips it via wineboot's timestamp check.
    LOG="$log1" TIMEOUT="${TIMEOUT:-900}" GUEST_GUI=0 \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q 'm8_persist: seeded' "$log1" || \
       ! grep -qE '^\[KTEST\] module /m8_persist.bin PASS' "$log1"; then
        echo "== persist: FAIL (boot 1 did not seed; see $log1) =="
        return 1
    fi
    LOG="$log2" TIMEOUT="${TIMEOUT:-900}" GUEST_GUI=0 \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
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

# The WOW64 milestone's acceptance leg: a 32-bit Win32 CUI binary runs.
#
# tests/cui/hello32.c is an ordinary i686 mingw console program over the same
# Wine import libraries the 64-bit clients use. Nothing in it knows it is a
# guest -- it reaches the kernel only the way any Win32 app does, and every
# syscall it makes has travelled guest -> wow64cpu -> wow64.dll -> the 64-bit
# ntdll first. smss runs it and reports the verdict; the exit status is
# distinct per check, so a WRONG answer (pointer width, IsWow64Process, a
# failed heap round trip) is a distinct failure rather than a silent pass.
wow64() {
    mkdir -p "$BUILD"
    local img log="$BUILD/wow64.log"
    img="$(test_image_copy "$ROOT/build/tests/wow64.hdd")" || exit 1
    LOG="$log" PASS_RE="\[KTEST\] wow64 hello32.exe PASS" TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=wow64 \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 || true
    if ! grep -q "\[KTEST\] wow64 hello32.exe PASS" "$log"; then
        echo "[KTEST] wow64-smoke FAIL (no 32-bit PASS marker; see $log)"
        grep -E "\[KTEST\] wow64 |\[PANIC\]|\[USERFAULT\]" "$log" | tail -5
        return 1
    fi
    echo "[KTEST] wow64-smoke PASS"
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$BUILD/firstboot.hdd")" || exit 1
    local log="$BUILD/firstboot.log"
    LOG="$log" PASS_RE="\[KTEST\] firstboot PASS" TIMEOUT="${TIMEOUT:-900}" GUEST_GUI=0 \
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
    # tools/filter_inf.py documents as out of scope — including RegisterDlls,
    # whose registry effect the guest now DOES apply (the baked inf keeps the
    # directive) and the oracle cannot: with it kept here, the prefix's own
    # pass has all 30 fake dlls to register instead of the three the disk
    # carries and WEDGES (rundll32 at 0% CPU for 18 minutes inside
    # InstallHinfSection, measured). Self-registration output is therefore
    # out of the compared scope, spelled out in regdiff.py's exclusion list
    # the way every other documented delta is.
    # The filtered INF is staged as input data over the pinned
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
        "$ROOT/build/wine-proskrnl-full.inf"; then
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/console.hdd")" || exit 1
    local sock="$ROOT/build/tests/console.sock" log="$ROOT/build/tests/console.log"

    # CUI-3: a resident SCM under no-eviction/no-COW needs the winetest
    # leg's provisioning.
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=console \
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/scm.hdd")" || exit 1

    local boot sock log qemu_wrapper
    for boot in 1 2; do
        sock="$ROOT/build/tests/scm$boot.sock"
        log="$ROOT/build/tests/scm$boot.log"
        SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
            GUEST_GUI=0 GUEST_LEG=console \
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/procs.hdd")" || exit 1

    local sock="$ROOT/build/tests/procs.sock" log="$ROOT/build/tests/procs.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=console \
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/files.hdd")" || exit 1

    local sock="$ROOT/build/tests/files.sock" log="$ROOT/build/tests/files.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=console \
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/cui6.hdd")" || exit 1

    local sock="$ROOT/build/tests/cui6.sock" log="$ROOT/build/tests/cui6.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=console \
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/cui7.hdd")" || exit 1

    local sock="$ROOT/build/tests/cui7.sock" log="$ROOT/build/tests/cui7.log"
    SERIAL_SOCK="$sock" LOG="$log" MEM=1024M TIMEOUT="${TIMEOUT:-900}" \
        GUEST_GUI=0 GUEST_LEG=console \
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

# The comparable form of a boot's [KTEST] lines for the determinism stages
# below: the filtered lines, with IDENTITY VALUES neutralized.
#
# A determinism verdict is about what the kernel DECIDED, and an identity —
# a pid, a handle value, a cookie — is minted from a counter, so it says
# only how many were minted before it. The ntapi image runs `wineboot
# --init` at firstboot (it is the `make run` image now), firstboot's
# transient rundll32 children are not all reaped at a fixed point, and so
# hello.exe's deliberate access violation — kernel/ps/usermode.c names every
# exception it hands to user mode, pid included — reported `pid=336` on one
# boot and `pid=340` on the next. Everything else about the line, the code,
# the rip and the faulting address, matched: the kernel decided the same
# thing about the same instruction both times.
#
# So the pid is REWRITTEN rather than the line DROPPED: dropping it would
# also stop the gate noticing an access violation that happens on one boot
# and not the other, which is exactly the kind of divergence this stage
# exists to catch.
cui8_det_lines() {   # $1 = serial log, $2 = the drop-this-line filter
    grep -aE '^\[KTEST\] ' "$1" 2>/dev/null | grep -vE "$2" | sed -E 's/pid=[0-9]+/pid=<pid>/g' || true
}

# ...and the diff itself, in the leg's own output. The two .txt files are
# named in the FAIL line, but this leg's child boots run with their output
# discarded and CI's log artifact collects *.log — so on a hosted runner the
# only record of WHICH line diverged was a path to a file nobody could open,
# and reproducing the leg locally was the only way to read it. Bounded, so a
# wholesale mismatch (an empty side, say) does not bury the verdict.
cui8_det_diff() {   # $1, $2 = the two extracted verdict files
    echo "    --- the diverging verdict lines (first 20) ---"
    diff "$1" "$2" 2>/dev/null | head -20 | sed 's/^/    /' || true
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
        LOG="$kmtlog" TIMEOUT="${TIMEOUT:-900}" GUEST_GUI=0 \
            "$ROOT/tools/qemu.sh" "$(test_image)" \
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
    local detFilter='blk depth|blk irq|blk idle|timer PASS|sweep PASS|cui8 stress knob|^\[KTEST\] sched '
    local detSubset=(file_coherence_mt read_write async_inline cancel_data_io io_teardown)
    rm -f "$sublog"
    "$0" proskrnl "${detSubset[@]}" >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-det-1-serial.log" 2>/dev/null || true
    cui8_det_lines "$sublog" "$detFilter" > "$BUILD/cui8-det-1.txt"
    rm -f "$sublog"
    "$0" proskrnl "${detSubset[@]}" >/dev/null 2>&1 || true
    cp -f "$sublog" "$BUILD/cui8-det-2-serial.log" 2>/dev/null || true
    cui8_det_lines "$sublog" "$detFilter" > "$BUILD/cui8-det-2.txt"
    if [[ -s "$BUILD/cui8-det-1.txt" ]] && cmp -s "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-2.txt"; then
        echo "[KTEST] cui8-determinism PASS ($(wc -l < "$BUILD/cui8-det-1.txt") verdict lines)"
    else
        echo "[KTEST] cui8-determinism FAIL (diff $BUILD/cui8-det-1.txt $BUILD/cui8-det-2.txt)"
        cui8_det_diff "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-2.txt"
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
        cui8_det_lines "$sublog" "$detFilter" > "$BUILD/cui8-det-stress.txt"
        if cmp -s "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-stress.txt"; then
            echo "[KTEST] cui8-stress PASS (park-on-every-await verdicts identical)"
        else
            echo "[KTEST] cui8-stress FAIL (diff $BUILD/cui8-det-1.txt $BUILD/cui8-det-stress.txt)"
            cui8_det_diff "$BUILD/cui8-det-1.txt" "$BUILD/cui8-det-stress.txt"
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
    rm -f "$ROOT/build/proskrnl-test.hdd"
    local img
    img="$(test_image_copy "$ROOT/build/tests/cui9.hdd")" || exit 1

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

# The Net-1 acceptance (docs/02 "Net-1 Done when"; docs/24 §6b): the wire
# proven without AFD existing. The standard test image boots with a slirp
# NIC, a filter-dump pcap — networking's screendump: QEMU's own device
# model records every frame, so the wire convicts the kernel's account of
# itself (Art. 6) — and the port of a host-loopback echo server carried in
# over fw_cfg. The guest's kmt suite reports the MAC, binds DHCP, writes
# the lease, and drives an in-kernel TCP echo through lwIP's raw API; the
# leg then asserts the serial<->wire cross-checks as CONTENT, never
# timing (docs/19 §11c): our MAC as Ethernet source, the DISCOVER/REQUEST
# exchange, the ACK's yiaddr equal to the serial-reported lease, and the
# echo payload in both directions.
#
# Gate zero is netsmoke (docs/24 §6c, the fontsmoke lesson): a QEMU
# without slirp FAILS the leg loudly — a silently absent backend would
# turn every later verdict false.
net() {
    if ! "$ROOT/tools/qemu.sh" --probe-slirp; then
        echo "[KTEST] netsmoke FAIL — this QEMU offers no '-netdev user' (slirp)."
        echo "        Re-run tools/setup_linux.sh: the pinned build configures --enable-slirp"
        echo "        (libslirp-dev), and a slirp-less tree is detected as stale there."
        return 1
    fi
    echo "[KTEST] netsmoke PASS"
    make -C "$ROOT" >/dev/null || exit 1

    # The echo server: host loopback, ephemeral port, killed with the leg.
    local portfile="$BUILD/netecho.port"
    rm -f "$portfile"
    python3 "$ROOT/tests/run/netecho.py" "$portfile" &
    local echopid=$!
    # shellcheck disable=SC2064
    trap "kill $echopid 2>/dev/null" RETURN
    local waited=0
    while [[ ! -s "$portfile" ]]; do
        sleep 0.1
        waited=$((waited + 1))
        if [[ "$waited" -gt 100 ]]; then
            echo "== net: FAIL (echo server never bound) =="
            return 1
        fi
    done
    local echoport
    echoport="$(cat "$portfile")"

    # The boot. TCG on a loaded runner makes DHCP+echo slow, never
    # different (every in-guest bound is guest-clocked); an EMPTY serial
    # log is the launch-infra flake, retried once (the cui8 pattern).
    local pcap="$BUILD/net.pcap" netlog="$BUILD/net-serial.log"
    local attempt
    for attempt in 1 2; do
        rm -f "$pcap"
        NET_PCAP="$pcap" NET_ECHO_PORT="$echoport" LOG="$netlog" \
            TIMEOUT="${TIMEOUT:-900}" GUEST_GUI=0 \
            "$ROOT/tools/qemu.sh" "$(test_image)" \
            >"$BUILD/net-qemu.log" 2>&1 || true
        [[ -s "$netlog" ]] && break
        echo "net: empty serial log (attempt $attempt); see $BUILD/net-qemu.log" >&2
    done

    local fails=0
    # (a) DHCP bound, and the serial line carries the address (docs/02:
    # "[KTEST] net dhcp carries the address").
    local dhcpline addr
    dhcpline="$(grep -E '^\[KTEST\] net dhcp ' "$netlog" | head -1 | tr -d '\r' || true)"
    addr="$(sed -nE 's/^\[KTEST\] net dhcp ([0-9.]+).*/\1/p' <<<"$dhcpline")"
    if [[ -n "$addr" ]]; then
        echo "[KTEST] net-dhcp PASS ($dhcpline)"
    else
        echo "[KTEST] net-dhcp FAIL (no '[KTEST] net dhcp' line; see $netlog)"
        fails=$((fails + 1))
    fi
    # (b) the in-kernel verdicts: lease readback and the echo round trip.
    local verdict
    for verdict in 'net lease PASS' 'net echo PASS'; do
        if grep -q "\[KTEST\] $verdict" "$netlog"; then
            echo "[KTEST] ${verdict// PASS/} PASS"
        else
            echo "[KTEST] ${verdict// PASS/} FAIL (see $netlog)"
            fails=$((fails + 1))
        fi
    done
    # (c) the stats line rides the leg output — recorded facts with two
    # floors (frames actually moved both ways; docs/24 §6e).
    local statsline
    statsline="$(grep -E '^\[KTEST\] net stats ' "$netlog" | head -1 | tr -d '\r' || true)"
    if [[ -n "$statsline" ]]; then
        echo "$statsline"
        local rx tx
        rx="$(sed -nE 's/.* rx=([0-9]+).*/\1/p' <<<"$statsline")"
        tx="$(sed -nE 's/.* tx=([0-9]+).*/\1/p' <<<"$statsline")"
        if [[ -z "$rx" || -z "$tx" || "$rx" -eq 0 || "$tx" -eq 0 ]]; then
            echo "[KTEST] net-stats FAIL (rx/tx floor: '$statsline')"
            fails=$((fails + 1))
        fi
    else
        echo "[KTEST] net-stats FAIL (no stats line; see $netlog)"
        fails=$((fails + 1))
    fi
    # (d) the pcap content assertions, cross-checked against the serial
    # report (the MAC and the lease address both appear in the wire's own
    # record, or one of the two is lying).
    local mac
    mac="$(sed -nE 's/^\[KTEST\] net mac ([0-9a-f:]+).*/\1/p' "$netlog" | head -1 | tr -d '\r')"
    if [[ -z "$mac" || -z "$addr" ]]; then
        echo "[KTEST] net-pcap FAIL (no serial mac/addr to cross-check)"
        fails=$((fails + 1))
    elif python3 "$ROOT/tests/run/netpcap.py" "$pcap" --src-mac "$mac" \
            --dhcp-yiaddr "$addr" --payload "proskrnl-net-echo-payload"; then
        echo "[KTEST] net-pcap PASS"
    else
        echo "[KTEST] net-pcap FAIL (pcap: $pcap)"
        fails=$((fails + 1))
    fi
    if [[ "$fails" -ne 0 ]]; then
        echo "== net: FAIL ($fails failing) =="
        return 1
    fi
    echo "== net: PASS =="
    return 0
}

# Net-3 (docs/02 "an off-the-shelf tool completes an HTTPS fetch over
# virtio-net — content-hash and exit-code verdicts"; docs/24 §6f): the
# harness serves HTTPS on host loopback behind a fresh test CA, the guest
# runs UNMODIFIED curl.exe (bundled LibreSSL) against slirp's 10.0.2.2
# host alias, and the verdicts are the tool's exit code off serial plus
# the sha256 of the fetched bytes extracted from the image. The fetch
# NAME (net3.test) rides a per-run hosts-file row, so the leg is
# offline-deterministic (docs/24 §7 authorizes exactly this scoping while
# the DNS client's wire behavior is convicted by the resolvunit corpus).
# The certificate's notBefore is NOW — a machine still answering the
# retired frozen-clock base date fails the handshake (docs/22's armed
# conviction).
net3() {
    if ! "$ROOT/tools/qemu.sh" --probe-slirp; then
        echo "[KTEST] netsmoke FAIL — this QEMU offers no '-netdev user' (slirp)."
        return 1
    fi
    echo "[KTEST] netsmoke PASS"
    if [[ ! -f "$ROOT/third_party/curlwin/bin/curl.exe" ]]; then
        echo "[KTEST] net3 FAIL — third_party/curlwin/bin/curl.exe is absent."
        echo "        Re-run tools/setup_linux.sh: the pinned acceptance tool is a"
        echo "        purchase there (sha256-pinned), and judging this leg without"
        echo "        it would be a silent no-op (the netsmoke lesson)."
        return 1
    fi
    test_image >/dev/null || { echo "== net3: FAIL (build) =="; return 1; }

    local work="$BUILD/net3" off=2097152    # mkimage.sh ESP_OFF
    rm -rf "$work"
    mkdir -p "$work"

    # The test CA and the server's leaf: minted per run, notBefore = now.
    openssl req -x509 -newkey rsa:2048 -keyout "$work/ca.key" -out "$work/ca.pem" \
        -days 3 -nodes -subj "/CN=proskrnl net3 test CA" 2>/dev/null
    openssl req -newkey rsa:2048 -keyout "$work/srv.key" -out "$work/srv.csr" \
        -nodes -subj "/CN=net3.test" 2>/dev/null
    printf 'subjectAltName=DNS:net3.test,IP:10.0.2.2\n' > "$work/ext.cnf"
    openssl x509 -req -in "$work/srv.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
        -CAcreateserial -out "$work/srv.pem" -days 3 -extfile "$work/ext.cnf" 2>/dev/null

    # The content: unique per run, so a stale image can never answer.
    head -c 4096 /dev/urandom > "$work/content.bin"
    local want_hash
    want_hash="$(sha256sum "$work/content.bin" | cut -d' ' -f1)"

    # The HTTPS server, host loopback, ephemeral port.
    python3 - "$work" > "$work/port.txt" <<'PYSRV' &
import http.server, ssl, sys, os
os.chdir(sys.argv[1])
httpd = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("srv.pem", "srv.key")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
PYSRV
    local srvpid=$!
    # shellcheck disable=SC2064
    trap "kill $srvpid 2>/dev/null" RETURN
    local waited=0
    while [[ ! -s "$work/port.txt" ]]; do
        sleep 0.1
        waited=$((waited + 1))
        [[ "$waited" -gt 100 ]] && { echo "== net3: FAIL (server never bound) =="; return 1; }
    done
    local port
    port="$(cat "$work/port.txt")"

    # The per-run job, mcopy'd into a COPY of the image (the baked image
    # stays virgin; the probe file exists only on this boot).
    local img
    img="$(test_image_copy "$work/net3-run.hdd")" || return 1
    cat > "$work/job.txt" <<JOB
url = "https://net3.test:$port/content.bin"
cacert = "C:/net3/ca.pem"
output = "C:/net3/out.bin"
retry = 10
retry-delay = 2
retry-all-errors
silent
show-error
JOB
    mcopy -o -i "$img@@$off" "::/windows/system32/drivers/etc/hosts" "$work/hosts.base" 2>/dev/null || : > "$work/hosts.base"
    { cat "$work/hosts.base"; printf '\n10.0.2.2 net3.test\n'; } > "$work/hosts"
    mmd -i "$img@@$off" ::/net3
    mcopy -i "$img@@$off" "$work/job.txt" ::/net3/job.txt
    mcopy -i "$img@@$off" "$work/ca.pem" ::/net3/ca.pem
    mcopy -o -i "$img@@$off" "$work/hosts" ::/windows/system32/drivers/etc/hosts

    # The boot: slirp + pcap (the wire's own record), guest-clocked bounds.
    local pcap="$work/net3.pcap" netlog="$work/net3-serial.log"
    NET_PCAP="$pcap" LOG="$netlog" TIMEOUT="${TIMEOUT:-900}" \
        PASS_RE='\[KTEST\] net3 exit' GUEST_GUI=0 GUEST_LEG=net3 \
        "$ROOT/tools/qemu.sh" "$img" >"$work/net3-qemu.log" 2>&1 || true

    local fails=0
    # (a) the tool's exit code, off serial: status 0, exit 0.
    if grep -qE '\[KTEST\] net3 exit \(status=0x0, exit=0x0\)' "$netlog"; then
        echo "[KTEST] net3-exit PASS"
    else
        echo "[KTEST] net3-exit FAIL ($(grep -aE '\[KTEST\] net3' "$netlog" | head -1 | tr -d '\r'); see $netlog)"
        fails=$((fails + 1))
    fi
    # (b) the fetched content, by hash, extracted from the image itself.
    local got_hash=absent
    if mcopy -o -i "$img@@$off" ::/net3/out.bin "$work/out.bin" 2>/dev/null; then
        got_hash="$(sha256sum "$work/out.bin" | cut -d' ' -f1)"
    fi
    if [[ "$got_hash" == "$want_hash" ]]; then
        echo "[KTEST] net3-hash PASS ($want_hash)"
    else
        echo "[KTEST] net3-hash FAIL (want $want_hash got $got_hash)"
        fails=$((fails + 1))
    fi
    if [[ "$fails" -ne 0 ]]; then
        echo "== net3: FAIL ($fails failing) =="
        return 1
    fi
    echo "== net3: PASS (an off-the-shelf HTTPS fetch over virtio-net) =="
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui.sock" log="$dir/gui.log" ppm="$dir/gui.ppm"
    mkdir -p "$dir"
    # The log too: qemu.sh truncates it, but not before this function starts
    # polling it, and a previous run's markers would satisfy every await
    # instantly -- screendumping a framebuffer the guest has not painted yet.
    rm -f "$sock" "$ppm" "$log"

    # The guest never powers itself off (it must hold the painted frame for
    # the screendump), so this leg always ends the guest itself.
    #
    # The budget is gui2's below, and for its reason: this leg boots a
    # VIRGIN image, so the marker it waits for is behind the whole firstboot
    # INF pass, and that pass is minutes on a host without KVM. It used to
    # be 300/180 -- sized when the seeded registry was one time-zone row
    # rather than the whole 139-zone table, which grew the hive 63 KiB ->
    # 237 KiB and, since every mutation rewrites the hive whole
    # (kernel/cm/hive.c, the Art. 3 writeback model), grew the pass with it.
    # Under TCG that put the paint marker past 180 s, and this was the only
    # GUI leg never re-budgeted for it.
    #
    # Deliberately gui2's numbers rather than gui3/gui4/gui5's larger ones:
    # CI overrides both upward for TCG (test.yml), so what the default buys
    # is how long a KVM developer waits on a genuinely WEDGED guest -- 97 s
    # is the measured KVM cost here, so 600 s still refuses a wedge in ten
    # minutes instead of fifteen.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] gui input PASS' \
        GUEST_GUI=0 GUEST_LEG=gui \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    # Wait for a marker to appear in the serial log, or give up.
    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-600}))
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

# AUD-1 (docs/02 "a guest client plays a deterministic S16 pattern and the
# harness finds it sample-exact in the WAV that QEMU's -audiodev wav
# recorded"; docs/23 §6a). The gui() shape with the WAV as the screendump:
# boot the audio image with a virtio-snd device backed by the wav audiodev,
# wait for the kmt SND suite's verdict (the device contract) and the
# client's play verdict, end the guest over QMP so the recording closes
# cleanly, and check the WAV against what the guest said it played.
#
# The audiodev is pinned to exactly what the client negotiates (s16, 48 kHz,
# stereo) so QEMU's mixeng conversion is the identity and the span is
# sample-exact — the wav backend refuses float and 32-bit formats, which is
# why the verdict path is S16 end-to-end (docs/23 §6a).
#
# No oracle leg, for the same reason gui() has none — \Device\Snd0 is a
# HACK device NT does not have (HACK-007; docs/23 §6e). What stands in for
# the oracle is QEMU: the WAV is written by its audio backend from what its
# device model consumed, neither of which the kernel controls (Art. 6).
audio() {
    local dir="$ROOT/build/tests"
    local img
    img="$(test_image_copy "$dir/audio.hdd")" || exit 1
    local sock="$dir/audio.sock" log="$dir/audio.log" wav="$dir/audio.wav"
    mkdir -p "$dir"
    # The gui() rationale: a previous run's markers or recording must not
    # satisfy any await or check below.
    rm -f "$sock" "$wav" "$log"

    # The guest never powers itself off (the client parks so the host owns
    # the recording's tail), so this leg always ends the guest itself. The
    # budget is gui()'s, for gui()'s reason: a virgin image puts the verdict
    # behind the whole firstboot INF pass.
    QMP_SOCK="$sock" LOG="$log" \
        EXTRA_DEVICES="virtio-sound-pci,audiodev=wav0" \
        AUDIODEV="wav,id=wav0,path=$wav,out.frequency=48000,out.channels=2,out.format=s16" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] audio PASS' \
        GUEST_GUI=0 GUEST_LEG=audio \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${AUDIO_DEADLINE:-600}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    audio_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== audio: FAIL ($1; see $log) =="
        return 1
    }

    # The kmt SND suite runs on this boot (the device exists here and
    # nowhere else) and reports before smss starts the client; its verdict
    # is grepped HERE because kmtcheck.sh deliberately covers only the
    # standard image (tests/run/kmtcheck.sh SCOPE).
    if ! await '\[KTEST\] SND (PASS|FAIL)'; then
        audio_fail "the kmt SND suite never reported"; return 1
    fi
    if ! await '\[KTEST\] audio (PASS|FAIL)'; then
        audio_fail "no client verdict"; return 1
    fi

    # End the guest CLEANLY before reading the WAV: the wav backend patches
    # the RIFF sizes at teardown (the checker still reads the data chunk to
    # EOF, because the grace-kill can outrun this quit).
    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! grep -qE '\[KTEST\] SND PASS' "$log"; then
        echo "== audio: FAIL (kmt SND suite; see $log) =="; return 1
    fi
    if ! grep -qE '\[KTEST\] audio PASS' "$log"; then
        echo "== audio: FAIL (client half; see $log) =="; return 1
    fi
    if ! python3 "$ROOT/tests/audio/check_audio.py" --log "$log" --wav "$wav"; then
        echo "== audio: FAIL (recording does not contain what the guest played) =="; return 1
    fi

    # --- the WASAPI half (AUD-2, docs/23 §6c): the SAME pattern through the
    # whole PE audio stack — the mmdevapi seam, winevsnd.drv, the feeder —
    # recorded by the same wav audiodev and checked by the same
    # property-based reader. The verdict line carries the driver's underrun
    # counter as a NUMBER (docs/19 §8.4's rule): 0 on an unloaded host, the
    # measured glitch count on a starved TCG runner — reported either way,
    # asserted never (docs/23 §6d).
    local img2
    img2="$(test_image_copy "$dir/wasapi.hdd")" || return 1
    sock="$dir/wasapi.sock" log="$dir/wasapi.log" wav="$dir/wasapi.wav"
    rm -f "$sock" "$wav" "$log"
    QMP_SOCK="$sock" LOG="$log" \
        EXTRA_DEVICES="virtio-sound-pci,audiodev=wav0" \
        AUDIODEV="wav,id=wav0,path=$wav,out.frequency=48000,out.channels=2,out.format=s16" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] audio PASS' \
        GUEST_GUI=0 GUEST_LEG=wasapi \
        "$ROOT/tools/qemu.sh" "$img2" >/dev/null 2>&1 &
    qemu_wrapper=$!
    if ! await '\[KTEST\] audio (PASS|FAIL)'; then
        audio_fail "no WASAPI client verdict"; return 1
    fi
    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    if ! grep -qE '\[KTEST\] audio PASS underruns=[0-9]+' "$log"; then
        echo "== audio: FAIL (WASAPI half: no PASS carrying an underrun count; see $log) =="
        return 1
    fi
    if ! python3 "$ROOT/tests/audio/check_audio.py" --log "$log" --wav "$wav"; then
        echo "== audio: FAIL (WASAPI recording does not contain what the guest played) =="
        return 1
    fi

    # --- the capture half (AUD-3, docs/23 §4a "Capture is the mirror"): a
    # third boot whose audiodev is `none` — the one backend WITH an input
    # side, which supplies silence at the correct cadence (audio/noaudio.c
    # no_read). The wav audiodev CANNOT carry this half: it has no input
    # voices (audio/wavaudio.c max_voices_in = 0), so on the two boots
    # above rx buffers would only ever return at the RELEASE flush — do
    # not "simplify" this back onto a wav boot. cap_smoke.exe finds the
    # capture node by its own direction claim and blocking-reads full
    # periods of zeros; the verdict asserts content and accounting, never
    # cadence speed (docs/19 §11c).
    local img3
    img3="$(test_image_copy "$dir/capture.hdd")" || return 1
    sock="$dir/capture.sock" log="$dir/capture.log"
    rm -f "$sock" "$log"
    QMP_SOCK="$sock" LOG="$log" \
        EXTRA_DEVICES="virtio-sound-pci,audiodev=snd0" \
        AUDIODEV="none,id=snd0" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] audio capture PASS' \
        GUEST_GUI=0 GUEST_LEG=capture \
        "$ROOT/tools/qemu.sh" "$img3" >/dev/null 2>&1 &
    qemu_wrapper=$!
    # The kmt SND suite runs here too — same device, third backend shape —
    # and its capture cases must hold under `none` exactly as under wav
    # (the pre-START hold + RELEASE flush envelope is backend-agnostic).
    if ! await '\[KTEST\] SND (PASS|FAIL)'; then
        audio_fail "the kmt SND suite never reported (capture boot)"; return 1
    fi
    if ! await '\[KTEST\] audio capture (PASS|FAIL)'; then
        audio_fail "no capture client verdict"; return 1
    fi
    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    if ! grep -qE '\[KTEST\] SND PASS' "$log"; then
        echo "== audio: FAIL (kmt SND suite on the capture boot; see $log) =="; return 1
    fi
    if ! grep -qE '\[KTEST\] audio capture PASS periods=[0-9]+ pos=[0-9]+' "$log"; then
        echo "== audio: FAIL (capture half; see $log) =="; return 1
    fi

    # --- the WASAPI capture half (AUD-3, docs/23 §6c): event-driven capture
    # through the whole PE audio stack — the seam's capture endpoint,
    # winevsnd.drv's capture thread, the get_capture_buffer legs — on the
    # same `none` backend, with the packet count on the verdict line as a
    # NUMBER (docs/19 §8.4's rule).
    local img4
    img4="$(test_image_copy "$dir/wasapi_cap.hdd")" || return 1
    sock="$dir/wasapi_cap.sock" log="$dir/wasapi_cap.log"
    rm -f "$sock" "$log"
    QMP_SOCK="$sock" LOG="$log" \
        EXTRA_DEVICES="virtio-sound-pci,audiodev=snd0" \
        AUDIODEV="none,id=snd0" \
        TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] audio capture PASS' \
        GUEST_GUI=0 GUEST_LEG=wasapicap \
        "$ROOT/tools/qemu.sh" "$img4" >/dev/null 2>&1 &
    qemu_wrapper=$!
    if ! await '\[KTEST\] audio capture (PASS|FAIL)'; then
        audio_fail "no WASAPI capture client verdict"; return 1
    fi
    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    if ! grep -qE '\[KTEST\] audio capture PASS packets=[0-9]+ frames=[0-9]+' "$log"; then
        echo "== audio: FAIL (WASAPI capture half; see $log) =="; return 1
    fi

    echo "== audio: PASS (device contract + sample-exact playback, direct and via WASAPI," \
         "$(grep -oE 'underruns=[0-9]+' "$dir/wasapi.log" | tail -1)," \
         "$(grep -oE 'capture PASS periods=[0-9]+ pos=[0-9]+' "$dir/capture.log" | tail -1)," \
         "$(grep -oE 'capture PASS packets=[0-9]+ frames=[0-9]+' "$log" | tail -1)) =="
    return 0
}

# WOW64 audio (docs/23 §6f; §6a's recording check, the wow64gui milestone's
# bitness): the WASAPI half again, with the SAME source built i386 and run
# as a WOW64 guest. A 32-bit client reaches mmdevapi by name through wow64.dll's file
# redirector, so every dll it loads — mmdevapi, winmm, oleaut32, and
# winevsnd.drv, which the seam LdrLoadDll's INTO the 32-bit process — is
# syswow64's copy, while the kernel below sees one \Device\Snd0 contract
# from either bitness (drivers/sndproto.h is pointer-free by construction).
#
# Its own leg rather than a fourth half of audio(): this boot needs the
# whole 32-bit shelf on the image and twice the memory (a second Wine stack
# that shares no image master with the 64-bit one — CUI-9 keys masters on
# the file), and audio() is already four boots long.
#
# The verdict is the same recording check as the 64-bit half plus the
# client's OWN bits= report: the image could carry either build under that
# name, so which one produced the samples is measured, not inferred.
wow64aud() {
    local dir="$ROOT/build/tests"
    local img sock="$dir/wow64aud.sock" log="$dir/wow64aud.log" wav="$dir/wow64aud.wav"
    mkdir -p "$dir"
    rm -f "$sock" "$wav" "$log"
    img="$(test_image_copy "$dir/wow64aud.hdd")" || return 1

    # The 32-bit client has a LEG of its own (`wasapi32`) and is baked under
    # its own name. It used to be baked over the 64-bit one's name, because
    # the session manager picked its foreground by probing for that name and
    # a second row could not be selected — so nothing on the image said which
    # bitness was about to run, which is exactly what this leg measures. MEM
    # is wow64gui's, for wow64gui's reason.
    QMP_SOCK="$sock" LOG="$log" \
        EXTRA_DEVICES="virtio-sound-pci,audiodev=wav0" \
        AUDIODEV="wav,id=wav0,path=$wav,out.frequency=48000,out.channels=2,out.format=s16" \
        MEM="${MEM:-2048M}" TIMEOUT="${TIMEOUT:-900}" PASS_RE='\[KTEST\] audio PASS' \
        GUEST_GUI=0 GUEST_LEG=wasapi32 \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    await() {
        local pattern="$1" deadline=$((SECONDS + ${AUDIO_DEADLINE:-600}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    wow64aud_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== wow64aud: FAIL ($1; see $log) =="
        return 1
    }

    if ! await '\[KTEST\] audio (PASS|FAIL)'; then
        wow64aud_fail "no 32-bit client verdict"; return 1
    fi
    # End the guest cleanly: the wav backend patches the RIFF sizes at
    # teardown (the audio() rationale).
    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! grep -qE '\[KTEST\] audio PASS underruns=[0-9]+ bits=32' "$log"; then
        echo "== wow64aud: FAIL (no 32-bit PASS carrying an underrun count; see $log) =="
        return 1
    fi
    if ! python3 "$ROOT/tests/audio/check_audio.py" --log "$log" --wav "$wav"; then
        echo "== wow64aud: FAIL (recording does not contain what the 32-bit guest played) =="
        return 1
    fi
    echo "== wow64aud: PASS (a 32-bit app played sample-exact through syswow64's WASAPI," \
         "$(grep -oE 'underruns=[0-9]+ bits=[0-9]+' "$log" | tail -1)) =="
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
# Every gui leg's last check: how many faults did win32u CONTAIN?
#
# user/wine/dlls/win32u/glue.c returns the exception code to the caller for an
# access violation taken inside win32u, which is what Wine's syscall boundary
# does (docs/03 "GUI-2 notes"). That containment is load-bearing and also
# dangerous: a proskrnl divergence that shows up as an AV inside win32u would
# be swallowed into a 0xc0000005 return, and a leg whose verdict is "a window
# appeared" could stay green over it — the fabricated-plausible-answer shape
# Art. 6 exists to prevent. So the COUNT is pinned per leg: every leg expects
# zero, except gui3, whose client deliberately triggers one to prove the
# containment works at all. A new contained fault fails the leg that found it,
# by name, with the serial line quoted.
assert_contained_faults() {   # $1 = log, $2 = expected count, $3 = leg name
    local seen
    seen=$(grep -c 'prsk_contain_win32u_fault' "$1" 2>/dev/null || true)
    [[ "$seen" == "$2" ]] && return 0
    echo "== $3: FAIL (win32u contained $seen faults, expected $2 -- a contained fault is"
    echo "   still a defect, it is just not the caller's death; see $1) =="
    grep 'prsk_contain_win32u_fault' "$1" 2>/dev/null | sort -u | head -5
    return 1
}

gui2() {
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui2.hdd")" || exit 1
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
        GUEST_GUI=0 GUEST_LEG=gui2 \
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
    assert_contained_faults "$log" 0 gui2 || return 1
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui3.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui3.sock" log="$dir/gui3.log" ppm="$dir/gui3.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # More memory than gui2: no COW, and this image runs THREE Wine processes
    # (the server plus two clients), each copying the images it maps.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-1536M}" \
        TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI3-NEVER' \
        GUEST_GUI=0 GUEST_LEG=gui3 \
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
    # A's fault-containment probe, before its ready marker: a win32u fault
    # that escapes into the caller kills A silently, and the next await would
    # then blame B for a death that was A's. Gated by name so the regression
    # is the missing LINE, not a timeout somewhere downstream.
    if ! await '\[KTEST\] gui3 win32u fault contained PASS'; then
        gui3_fail "a fault inside win32u reached its caller (glue.c containment)"; return 1
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
    assert_contained_faults "$log" 1 gui3 || return 1
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui4.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui4.sock" log="$dir/gui4.log"
    local ppm1="$dir/gui4-before.ppm" ppm2="$dir/gui4-after.ppm" ppm3="$dir/gui4-cursor.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm1" "$ppm2" "$ppm3" "$log"

    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM="${MEM:-1536M}" TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI4-NEVER' \
        GUEST_GUI=0 GUEST_LEG=gui4 \
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
    assert_contained_faults "$log" 0 gui4 || return 1
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui5.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui5.sock" log="$dir/gui5.log" ppm="$dir/gui5.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # gui3's sizing reasoning: no COW and four Wine processes across the leg
    # (the server, fontdiff, then the two clients).
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-1536M}" \
        TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI5-NEVER' \
        GUEST_GUI=0 GUEST_LEG=gui5 \
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
    assert_contained_faults "$log" 0 gui5 || return 1
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
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui5con.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui5con.sock" log="$dir/gui5con.log"
    local ppm1="$dir/gui5con-before.ppm" ppm2="$dir/gui5con-after.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm1" "$ppm2" "$log"

    # An interactive GUEST (the shell session smss starts only for a human)
    # under a headless HOST: this leg types through QMP and reads its verdict
    # off $log, so GUEST_INTERACTIVE is set and INTERACTIVE is not.
    QMP_SOCK="$sock" LOG="$log" GUEST_INTERACTIVE=1 \
        EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM="${MEM:-1536M}" TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI5CON-NEVER' GUEST_SHELL=1 \
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
    assert_contained_faults "$log" 0 gui5con || return 1
    echo "== gui5con: PASS (windowed conhost: typed, ^C-interrupted, files proven) =="
    return 0
}

# The WOW64 GUI acceptance (docs/02 WOW64 + docs/07): a 32-bit .exe, typed at
# the same windowed console a person would type it at, puts a window on the
# desktop the 64-bit applets share.
#
# It runs on the gui5con image, which since this change carries both bitnesses
# of the GUI shelf, because that IS the thing under test: `make rungui` is the
# session, and the leg is that session driven by the harness instead of by
# hand. No image of its own — a second one would be a second payload list to
# keep in step, and the interactive one is the one that must not rot.
#
# The verdict is check_wow64gui.py's three halves (bitness, geometry, pixels);
# everything here is choreography. Note what makes it a WOW64 verdict rather
# than a GUI one: the client asks the KERNEL whether it is a WOW64 process
# (ProcessWow64Information) and prints sizeof(void *) beside the answer, so a
# leg that somehow ran a 64-bit binary fails instead of passing quietly.
#
# The guest does not power itself off (the client parks pumping so its window
# is still on the scanout when the dump is taken), so the leg ends QEMU — the
# gui3/gui4 arrangement, not gui5con's `exit`.
wow64gui() {
    local img
    img="$(test_image_copy "$ROOT/build/tests/wow64gui.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/wow64gui.sock" log="$dir/wow64gui.log"
    local ppm1="$dir/wow64gui-before.ppm" ppm2="$dir/wow64gui-after.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm1" "$ppm2" "$log"

    # More memory than gui5con's: the 32-bit child brings up a SECOND Wine
    # stack whose images share nothing with the 64-bit one already resident
    # (CUI-9 masters are keyed on the file, and syswow64's are other files),
    # on top of a session that has the whole GUI userland up.
    QMP_SOCK="$sock" LOG="$log" GUEST_INTERACTIVE=1 \
        EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" \
        MEM="${MEM:-2048M}" TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-WOW64GUI-NEVER' GUEST_SHELL=1 \
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
    wow64gui_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== wow64gui: FAIL ($1; see $log) =="
        return 1
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }

    await '\[KTEST\] gui5con conhost mode=window' || { wow64gui_fail "the windowed conhost never picked window mode"; return 1; }
    await 'starting cmd\.exe' || { wow64gui_fail "the interactive cmd never started"; return 1; }
    await '\[KTEST\] gui2 input READY' || { wow64gui_fail "no keyboard reader"; return 1; }
    await '\[KTEST\] gui4 mouse READY' || { wow64gui_fail "no pointer reader"; return 1; }

    # The console window, found on the scanout the way gui5con finds it. The
    # dump that finds it is also the BEFORE dump: nothing has been typed yet,
    # so the client's colour must be absent from it.
    local located="" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
    while ((SECONDS < deadline)); do
        qmp screendump "$ppm1" >/dev/null 2>&1 || true
        if located=$(python3 "$ROOT/tests/gui/check_gui5con.py" --locate \
                --log "$log" --ppm "$ppm1" 2>/dev/null); then
            break
        fi
        located=""
        kill -0 "$qemu_wrapper" 2>/dev/null || { wow64gui_fail "QEMU died while waiting for the window"; return 1; }
        sleep 3
    done
    [ -n "$located" ] || { wow64gui_fail "no console window ever appeared on the scanout"; return 1; }
    local cx cy w h maxx maxy
    cx=$(sed -E 's/.*center=([0-9]+),[0-9]+$/\1/' <<<"$located")
    cy=$(sed -E 's/.*center=[0-9]+,([0-9]+)$/\1/' <<<"$located")
    w=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    h=$(grep -oE '\[KTEST\] gui2 mode w=[0-9]+ h=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxx=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    maxy=$(grep -oE 'mouse READY abs=[0-9]+\.\.[0-9]+,[0-9]+\.\.[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    if [ -z "$w" ] || [ -z "$maxx" ]; then
        wow64gui_fail "could not parse guest geometry"; return 1
    fi

    # One activation click in the console window (the gui5con arithmetic), so
    # the typing below reaches it.
    qmp absmove $(( (cx * maxx + w - 2) / (w - 1) )) $(( (cy * maxy + h - 2) / (h - 1) ))
    sleep 1
    qmp button left down && qmp button left up
    sleep 2

    qmp type 'c:\wow64gui.exe
'
    await '\[KTEST\] wow64gui painted' || { wow64gui_fail "the 32-bit client never painted"; return 1; }
    # The paint marker is the client's; the flush that carries those pixels to
    # the scanout is the driver's and comes after it.
    await '\[KTEST\] gui2 window rect=420,420,360x240' || { wow64gui_fail "the client's window was never flushed"; return 1; }
    sleep 2
    qmp screendump "$ppm2" || { wow64gui_fail "screendump failed"; return 1; }

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true

    if ! python3 "$ROOT/tests/gui/check_wow64gui.py" --log "$log" \
            --before "$ppm1" --after "$ppm2"; then
        echo "== wow64gui: FAIL (the 32-bit window's verdict; see $log) =="
        return 1
    fi
    assert_contained_faults "$log" 0 wow64gui || return 1
    echo "== wow64gui: PASS (a 32-bit GUI app ran on the shared desktop) =="
    return 0
}

# GUI-6 (docs/02 "Desktop"): Wine's explorer owns the desktop. The image
# carries explorer.exe, which flips wineserver-lite's desktop fixtures off
# (shim.c probe_explorer): smss runs `explorer /desktop=shell,1280x800` with
# a trailing `explorer.exe C:\shelf`, so explorer creates and owns the desktop —
# wallpaper rectangle, taskbar-mode systray — and its own CreateProcessW
# child puts the file window over it, landing on desktop "shell" through
# connect-time inheritance.
#
# The verdict is the golden image the earlier GUI checkers deferred to this
# milestone: an EXACT compare of QEMU's screendump against
# tests/gui/golden/desktop.ppm (check_gui6.py). Determinism is built into
# the leg, not tolerated by the checker: no tablet is attached (no cursor
# overlay is ever drawn), the scanout has one fixed mode the golden pins,
# and the poll below waits until the dump MATCHES — a settling frame
# (caret, late repaints) fails only the deadline, not the leg.
#
# No oracle leg, for the same reason gui() has none — \Device\Fb0 is a HACK
# device NT does not have (docs/03 "GUI-1 notes", the G5 adaptation), and
# the pinned oracle Wine is built --without-x, so no oracle can render this
# frame. What stands in is QEMU's own device model rendering the pixels back
# (Art. 6), plus the fact that everything above the driver is unmodified
# Wine: explorer, shell32, user32, gdi32 are the pinned tree's own binaries.
#
# Re-blessing (GUI6_BLESS=1): after a deliberate change to what the desktop
# looks like, the same leg waits for two consecutive IDENTICAL dumps (the
# settled-frame rule) and writes them to tests/gui/golden/desktop.ppm, to be
# committed WITH the change that moved the pixels.
gui6() {
    local img
    img="$(test_image_copy "$ROOT/build/tests/gui6.hdd")" || exit 1
    local dir="$ROOT/build/tests"
    local sock="$dir/gui6.sock" log="$dir/gui6.log" ppm="$dir/gui6.ppm"
    local golden="$ROOT/tests/gui/golden/desktop.ppm"
    mkdir -p "$dir"
    rm -f "$sock" "$ppm" "$log"

    # gui3's memory reasoning, plus shell32: three Wine processes (server,
    # desktop explorer, file-window explorer), no COW, each copying what it
    # maps.
    QMP_SOCK="$sock" LOG="$log" EXTRA_DEVICES="virtio-keyboard-pci" MEM="${MEM:-2048M}" \
        TIMEOUT="${TIMEOUT:-1200}" PASS_RE='PRSK-GUI6-NEVER' \
        GUEST_GUI=0 GUEST_LEG=gui6 GUEST_SHELL=1 \
        "$ROOT/tools/qemu.sh" "$img" >/dev/null 2>&1 &
    local qemu_wrapper=$!

    # smss says so when explorer exits. Every wait below has to end on it:
    # a dead desktop prints no further marker, so without this the leg
    # reports the marker it was still waiting for -- "the explorer browser
    # window never flushed" -- for a desktop that died a minute earlier.
    # That is exactly how the GUI-6 desktop close read (docs/03 "GUI-6
    # notes (the desktop's lifetime)"): explorer exited 0, smss named it on
    # the very next line, and the leg said something else.
    desktop_died() { grep -qaE '\[KTEST\] gui6 FAIL' "$log" 2>/dev/null; }

    # 0 the marker arrived, 1 the deadline (or QEMU) ended it, 2 the desktop
    # died -- which names itself and is never the caller's missing marker.
    await() {
        local pattern="$1" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        while ((SECONDS < deadline)); do
            grep -qE "$pattern" "$log" 2>/dev/null && return 0
            desktop_died && return 2
            kill -0 "$qemu_wrapper" 2>/dev/null || return 1  # QEMU died first
            sleep 1
        done
        return 1
    }
    # Wait, or fail by the true reason: the death when there was one, the
    # caller's missing marker otherwise.
    await_or_fail() {
        local status=0
        await "$1" || status=$?
        ((status == 0)) && return 0
        if ((status == 2)); then
            gui6_fail "explorer exited (the [KTEST] gui6 FAIL line names the status)"
        else
            gui6_fail "$2"
        fi
        return 1
    }
    gui6_fail() {
        python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
        wait "$qemu_wrapper" 2>/dev/null || true
        echo "== gui6: FAIL ($1; see $log) =="
        return 1
    }
    qmp() { python3 "$ROOT/tests/gui/qmpctl.py" "$sock" "$@"; }

    await_or_fail '\[KTEST\] gui3 server READY' \
        "wineserver-lite never published its transport" || return 1
    # The probe's own answer: mis-baked image (no explorer) is named, not
    # diagnosed from which desktop arrangement limped further.
    await_or_fail '\[KTEST\] wineserver-lite: explorer\.exe present' \
        "the server never saw explorer.exe on the image" || return 1
    # Firstboot can auto-launch an explorer of its own (wineboot's rundll32
    # creates windows; win32u answers with the stock launch), and its
    # Default-desktop paint satisfies the generic markers below — so anchor
    # the SESSION phase first or the polls bless/match a firstboot frame.
    await_or_fail '\[KTEST\] firstboot PASS' "firstboot never completed" || return 1
    # Printed from EXPLORER's process: winefb's pSetDesktopWindow sized the
    # desktop window, so explorer owns it and the fixtures stayed off.
    await_or_fail '\[KTEST\] gui2 desktop w=' \
        "explorer never created the desktop window" || return 1
    # The browser window's own first flush — the one surface unique to the
    # session desktop (the firstboot explorer shows no browser), and the
    # last paint of the arrangement, so polling starts at a frame that can
    # only still be missing the taskbar button repaint.
    await_or_fail '\[KTEST\] gui2 window rect=0,0,640x480 flush=1' \
        "the explorer browser window never flushed" || return 1

    # The same death check guards both loops below: a dead desktop is a
    # perfectly SETTLED frame, so neither may bless or match a corpse.

    if [ -n "${GUI6_BLESS:-}" ]; then
        # Settled-frame rule: two consecutive identical dumps, then bless.
        local prev="$dir/gui6-bless-prev.ppm" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
        rm -f "$prev"
        while ((SECONDS < deadline)); do
            sleep 5
            if desktop_died; then gui6_fail "explorer exited (the [KTEST] gui6 FAIL line names the status)"; return 1; fi
            qmp screendump "$ppm" >/dev/null 2>&1 || true
            if [ -s "$prev" ] && [ -s "$ppm" ] && cmp -s "$prev" "$ppm"; then
                mkdir -p "$(dirname "$golden")"
                cp "$ppm" "$golden"
                python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
                wait "$qemu_wrapper" 2>/dev/null || true
                echo "== gui6: BLESSED $golden (commit it with the change that moved the pixels) =="
                return 0
            fi
            cp -f "$ppm" "$prev" 2>/dev/null || true
            kill -0 "$qemu_wrapper" 2>/dev/null || { gui6_fail "QEMU died while blessing"; return 1; }
        done
        gui6_fail "the frame never settled (no two consecutive dumps agreed)"; return 1
    fi

    if [ ! -f "$golden" ]; then
        gui6_fail "no golden at $golden — run GUI6_BLESS=1 tests/run/run.sh gui6 and commit it"
        return 1
    fi

    # Poll until the dump matches the golden: the self-verifying wait — a
    # still-settling frame is not a verdict, only the deadline is.
    local matched="" deadline=$((SECONDS + ${GUI_DEADLINE:-900}))
    while ((SECONDS < deadline)); do
        sleep 5
        if desktop_died; then gui6_fail "explorer exited (the [KTEST] gui6 FAIL line names the status)"; return 1; fi
        qmp screendump "$ppm" >/dev/null 2>&1 || true
        if [ -s "$ppm" ] && python3 "$ROOT/tests/gui/check_gui6.py" \
                --golden "$golden" --ppm "$ppm" >/dev/null 2>&1; then
            matched=1
            break
        fi
        kill -0 "$qemu_wrapper" 2>/dev/null || { gui6_fail "QEMU died while waiting for the match"; return 1; }
    done

    if [ -z "$matched" ]; then
        # Grade once more, loudly, so the log carries the diff stats.
        python3 "$ROOT/tests/gui/check_gui6.py" --golden "$golden" --ppm "$ppm" || true
        gui6_fail "the screendump never matched the golden (last dump kept at $ppm)"
        return 1
    fi

    python3 "$ROOT/tests/gui/qmpctl.py" "$sock" quit >/dev/null 2>&1 || true
    wait "$qemu_wrapper" 2>/dev/null || true
    assert_contained_faults "$log" 0 gui6 || return 1
    echo "== gui6: PASS (the desktop matches tests/gui/golden/desktop.ppm) =="
    return 0
}

# The compositor's unit verdict (tests/winefb/): the REAL compose.c/blit.c
# objects -- the same ones linked into win32u.dll -- driven against a mocked
# seam, with Wine's real region engine (gdi32, under the pinned wine) doing
# the algebra. No QEMU, no boot: it runs in about a second. Every compositor
# POLICY bug gets a case here, not a leg of its own -- the winemine close
# afterimage, the desktop erasing the console, the hidden window's late
# flush are all pinned inside (tests/winefb/winefb_unit.c names each). The
# gui legs stay the end-to-end umbrella over the whole stack.
winefbunit() {
    make -C "$ROOT" winefb-unit >/dev/null || { echo "== winefbunit: FAIL (build) =="; return 1; }
    local out rc=0
    out=$("$WINE" "$ROOT/build/tests/winefb_unit.exe" 2>/dev/null) || rc=$?
    if [ "$rc" != 0 ] || ! grep -q "\[KTEST\] winefbunit PASS" <<<"$out"; then
        echo "$out"
        echo "== winefbunit: FAIL (exit=$rc) =="
        return 1
    fi
    echo "== winefbunit: PASS (compositor policy against the mocked seam) =="
    return 0
}

# The wsresolv unit corpus (tests/resolv/resolv_unit.c, `make resolv-unit`):
# the DNS parser under canned/adversarial replies through its transport
# seam, the literal parsers, and the registry-free unixlib packing paths.
# Hermetic — no prefix state and no network; the ws2_32:protocol pair is
# the boundary judge above it.
resolvunit() {
    make -C "$ROOT" resolv-unit >/dev/null || { echo "== resolvunit: FAIL (build) =="; return 1; }
    local out rc=0
    out=$("$WINE" "$ROOT/build/tests/resolv_unit.exe" 2>/dev/null) || rc=$?
    if [ "$rc" != 0 ] || ! grep -q "\[KTEST\] resolvunit PASS" <<<"$out"; then
        echo "$out"
        echo "== resolvunit: FAIL (exit=$rc) =="
        return 1
    fi
    echo "== resolvunit: PASS (the DNS corpus and the packing paths) =="
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
    # The oracle's display goes first: it outlives nothing, and a leaked Xvfb
    # would hold a display number for the next run to trip over. Its audio
    # server goes with it, for the same reason.
    stop_xvfb
    stop_pulse
    # Swept even on a red leg: a leg that failed for its own reason may also
    # have swallowed a kernel fault, and that is the finding worth keeping.
    "$ROOT/tests/run/uacheck.sh" --since "$UACHECK_MARKER" "$ROOT/build" || status=1
    exit "$status"
}
trap uacheck_sweep EXIT

# Started HERE rather than beside the RUNS_WINE computation so a usage error
# never leaves a server behind, and once for the whole invocation rather than
# per leg: every oracle process in this run then shares one screen, exactly as
# a developer's would.
(( RUNS_WINE )) && { start_xvfb; start_pulse; }

case "$MODE" in
    oracle)   oracle ;;
    proskrnl) proskrnl ;;
    winetest) winetest ;;   # SUBTESTS filters manifest pairs (see the header)
    prebuild) prebuild ;;   # a BUILD step, not a leg: no verdict comes out of it
    fuzz)     fuzz "${@:2}" ;;
    persist)  persist ;;
    firstboot) firstboot ;;
    wow64)    wow64 ;;
    console)  console ;;
    scm)      scm ;;
    procs)    procs ;;
    files)    files ;;
    cui6)     cui6 ;;
    cui7)     cui7 ;;
    cui8)     cui8 ;;
    cui9)     cui9 ;;
    net)      net ;;
    net3)     net3 ;;
    fatinterop) fatinterop ;;
    fatstress) fatstress ;;
    tornwrite) tornwrite ;;
    gui)      gui ;;
    audio)    audio ;;
    wow64aud) wow64aud ;;
    gui2)     gui2 ;;
    gui3)     gui3 ;;
    gui4)     gui4 ;;
    gui5)     gui5 ;;
    gui5con)  gui5con ;;
    wow64gui) wow64gui ;;
    gui6)     gui6 ;;
    winefbunit) winefbunit ;;
    resolvunit) resolvunit ;;
    guiwtest) guiwtest ;;
    *) echo "usage: $0 {oracle [subtest...]|proskrnl [subtest...]|winetest [pair...]|prebuild|fuzz [fuzz.py options]|persist|firstboot|console|scm|procs|files|cui6|cui7|cui8|cui9|net|net3|fatinterop|fatstress|tornwrite|gui|audio|wow64aud|gui2|gui3|gui4|gui5|gui5con|wow64gui|gui6|winefbunit|resolvunit|guiwtest}" >&2
       echo "       subtest = a tests/ntapi test's base name, or a glob over base names" >&2
       echo "       pair    = a winetest <module>[:<subtest>] (ntdll, printf, ntdll:env), or a glob" >&2
       echo "                 (iteration only — the gate is the unfiltered run)" >&2
       exit 2 ;;
esac
