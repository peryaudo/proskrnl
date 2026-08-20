#!/usr/bin/env bash
#
# fulltest.sh — the whole CI suite on this machine, in parallel (`make fulltest`).
#
#   make fulltest                 every leg, the full verdict
#   make fulltest FULLTEST_ARGS="gui4 cui8"     a subset, for iteration only
#   tools/fulltest.sh -j 12       same, with an explicit fan-out width
#
# WHAT IT RUNS. Exactly the legs .github/workflows/test.yml runs, one leg per
# CI step: the blocking-frontier check, `make test`, the differential fuzzer,
# the three FAT batteries, the ntapi oracle and its proskrnl twin, the winetest
# sweep, the registry legs, the nine CUI acceptances, the six GUI legs and the
# user32:msg trophy. Nothing here is a lighter or a differently-configured
# version of a CI step: a green fulltest is the same set of verdicts a green
# `all-green` is, which is the only property that makes waiting for CI optional.
#
# WHY IT IS FAST. CI spreads 26 legs over 7 shards because a hosted runner has
# two cores and no KVM; a dev box has neither limitation, so every leg is its
# own unit and the wall clock is the LONGEST leg rather than the sum of a
# shard's. Nothing about a leg is made cheaper — the fan-out is the speed-up.
#
# WHY EVERY LEG NEEDS A SANDBOX. The legs were written to run one at a time and
# they say so in the tree: each calls `make -C $ROOT test-img` (two makes in one
# build directory race over the same object files), `cui8` boots the master
# image in place — QEMU writes into it — and three legs `rm -f` that master to
# force a virgin one before copying it, which is a guaranteed corrupt read for
# any neighbour copying it at that moment. Widening
# every one of those into a shared-nothing design would be a rewrite of
# tests/run/run.sh, and a rewrite of the harness is the last thing that should
# ride along with "make the harness faster".
#
# So each leg gets a VIEW instead: a directory whose entries are symlinks to
# this tree's (kernel/, tests/, third_party/, Makefile, …) and whose build/ is a
# real copy of the build outputs. $ROOT resolves to the view, so a leg's makes,
# images, serial logs, wineprefixes and mutated disks are all its own, and the
# leg's own source is untouched — the isolation is in the filesystem, not in the
# tests. The view's root is a real directory and only its entries are links, so
# `cd $view/tests/run/../..` is the view (bash keeps logical paths); the probe
# in make_view() asserts exactly that rather than trusting it, because if it
# ever stopped holding, every leg would quietly run in the real tree again.
#
# WHAT IS COPIED AND WHAT IS NOT. build/ is copied minus:
#   *.hdd    every leg already makes the image it boots, so copying 512 MiB of
#            disk images per view would buy files that leg's own make replaces;
#   *.log/*.ppm/*.sock and tests/wineprefix*/ and tests/ntapi/out/
#            outputs of a PREVIOUS run — a stale verdict artifact must never be
#            reachable from a fresh one, and run.sh's own comment forbids a
#            COPIED wineprefix (a copy answers STATUS_OBJECT_NAME_NOT_FOUND for
#            `\??\C:`, deterministically).
# Objects, modules, winestrip, wtests and the prebuilt tests/ntapi/*.exe are
# copied, not linked: a copy is what makes a rebuild inside a view — should one
# ever be triggered — write to the view instead of through a symlink into the
# shared tree. It is ~100 MiB a leg from page cache, which is noise next to a
# QEMU boot.
#
# WINEPREFIXES are therefore per view and FRESH every run — run.sh's own default
# ($BUILD/wineprefix, plus one per oracle worker), landing inside the view and
# dying with it. Persisting them across runs would be faster and would be wrong
# twice over: CI creates them fresh, so a reused prefix is a way for this to
# answer green where CI answers red, and reused prefix state has already
# produced a false verdict here (issue #117 — `delete_on_close` fails on any
# SECOND oracle run in the same prefix). Measured cost of the freshness: the
# oracle leg is 19 s cold against 18 s warm, for ~13 GiB of prefix that the
# view cleanup below then takes away again.
#
# A GREEN leg's view is DELETED when it reports and a RED leg's is kept — a
# whole-suite run is ~22 GiB of views, almost none of which anyone will ever
# look at, and the ones worth keeping are exactly the ones with a failure in
# them. FULLTEST_KEEP_VIEWS=1 keeps them all (to poke at a passing leg's image).
#
# HOW WIDE. -j defaults to a QUARTER of the cores, not all of them. Every leg is
# a single-vCPU guest (the kernel is uniprocessor by mandate), so the box could
# hold far more at once — but four of these legs measure the MACHINE rather than
# the boundary (the oracle's `times` case reads the host idle counter; cui8
# asserts a park under a throttled disk; procs and gui5con have choreography
# with sleeps in it), and a machine with every core saturated is a different
# machine. A quarter is where the two terms of the wall clock meet: 26 legs are
# ~1089 s of work whose longest single leg is 114 s (the table below), so at
# -j8 the schedule finishes in 150 s and no width can do better than ~120 s.
# Buying that last 20% with a saturated box would be paying in false reds.
# FULLTEST_JOBS or -j overrides it.
#
# DO NOT TOUCH THE TREE WHILE IT RUNS. The views symlink the sources, so an edit
# mid-run reaches every leg at once — including an edit to run.sh or to this
# file, where a shell re-reads a script whose byte offsets just moved underneath
# it. Same rule a single hand-run leg has always had (a leg bakes its image from
# the live tree); the fan-out only raises the cost of one careless save from one
# verdict to twenty-six. The lock below stops a second RUN, not a second EDIT.
#
# WHAT IT DOES NOT COVER, said honestly. Three things, and only the first is
# about speed:
#
#   1. CI is a slower machine — two cores, TCG, a virgin cache — so it can see
#      failures settled by machine SPEED that this cannot. The user32:msg budget
#      is sized for the slowest machine that runs the suite, which is why that
#      leg is advisory on PRs there (docs/03 "GUI-5 winetest notes").
#   2. CI tests the COMMITTED tree; this tests the WORKING tree. A required file
#      that was never `git add`ed is green here and red there — this script's
#      own first draft was exactly that file. The summary says so when the tree
#      is dirty; it cannot say so for you.
#   3. CI builds from nothing; the views copy this tree's incremental build/. A
#      stale object or a missing Makefile dependency is invisible here.
#
# Everything SEMANTIC, this answers. It is also not `make format` — that
# rewrites source, so it is a fixer, not a verdict, and stays a separate step.
# (A leg cannot run it either: a view is symlinks onto this tree, so a fixer
# inside one edits the real files mid-run.) CI's `style` shard gates it the
# only way a checker can — run it on a clean checkout, demand no diff — so an
# unformatted tree is green here and red there. Run it BEFORE this, not after.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FT="$ROOT/build/fulltest"

# A parent `make -j64 fulltest` hands its jobserver down through MAKEFLAGS; the
# builds below are our own top-level makes, not that make's children, and an
# inherited jobserver they cannot reach only produces a warning and a serial
# build. Ours is the only -j that governs them.
unset MAKEFLAGS MFLAGS MAKELEVEL

# A leg must get the environment CI hands it, not the one this shell happens to
# be carrying. Every name below is a knob run.sh or qemu.sh reads with
# `: "${VAR:=default}"`, so an exported value silently reaches all 26 legs at
# once — and the first of them is the worst case there is: an inherited
# $WINEPREFIX puts eight concurrent legs in ONE prefix, which is the reused-
# prefix false verdict this script goes out of its way to avoid (issue #117).
# The rest are the same shape: one path or deadline, shared by everything. Host
# toolchain selection ($QEMU, $WINE, $CC_ORACLE, $ACCEL) is deliberately NOT in
# this list — that is a choice about the machine, not about a leg.
unset WINEPREFIX LOG PASS_RE TIMEOUT GRACE MEM GUI_DEADLINE \
      QMP_SOCK SERIAL_SOCK WRITE_LOG DRIVE_THROTTLE EXTRA_DEVICES \
      INTERACTIVE GUI_DISPLAY WTEST_NO_ORACLE FONTDIFF_REFRESH \
      NET_PCAP NET_ECHO_PORT

NPROC="$( (nproc || sysctl -n hw.ncpu) 2>/dev/null || echo 4)"

# The legs, LONGEST FIRST. The order is what the fan-out dispatches in, so a
# long leg started last is wall clock nobody can win back. Measured on a
# 32-core KVM box at -j8, seconds, which is also what the summary table this
# script prints reports — re-order from a run of your own if these drift:
#
#   guiwtest 114  winetest 78  wow64gui 76  gui5con 72  tornwrite 66  gui4 62
#   cui8 61  gui3 57  gui5 56  gui2 54  cui9 46  scm 39  proskrnl 38  firstboot 36
#   persist 34  cui7 34  gui 32  procs 31  files 30  console 30  boot 30
#   cui6 29  oracle 19  fatstress 19  fuzz 14  fatinterop 8  frontier 0
#
# wow64aud has no row yet: it is a wow64gui-class boot (the same 32-bit
# second stack, on a bigger image), so it is scheduled beside it until a
# run of your own measures it.
#
# 1165 s of legs; 150 s of wall clock. The floor is guiwtest at 114 s, so the
# schedule is already within a third of the best any width could do.
ALL_LEGS=(guiwtest winetest wow64gui wow64aud winefbunit gui5con gui6 tornwrite gui4 cui8 gui3 gui5 gui2 cui9
          scm proskrnl firstboot persist cui7 gui audio procs files console boot
          cui6 net oracle wow64 fatstress fuzz fatinterop frontier)

usage() {
    cat >&2 <<EOF
usage: $0 [-j N] [leg...]
       legs: ${ALL_LEGS[*]}
       with no leg named, every leg runs — that is the verdict; a subset is
       for iteration only and says so.
EOF
    exit 2
}

# ---------------------------------------------------------------------------
# The view (see the header).

# Directories that must be REAL in the view rather than symlinks to this tree:
# every script under them derives $ROOT from its own location, and a real parent
# is what makes that derivation independent of whether the shell resolves paths
# logically or physically.
VIEW_REAL_DIRS=(tests tools)

make_view() {   # $1 = leg name; creates $FT/views/<leg>
    local leg="$1" view="$FT/views/$1" entry base
    rm -rf "$view"
    mkdir -p "$view/build"
    for entry in "$ROOT"/* "$ROOT"/.[!.]*; do
        [[ -e "$entry" ]] || continue
        base="$(basename "$entry")"
        case "$base" in build|.git) continue ;; esac
        ln -s "$entry" "$view/$base"
    done
    for base in "${VIEW_REAL_DIRS[@]}"; do
        rm -f "$view/$base"
        (cd "$ROOT/$base" && find . -type d -exec mkdir -p "$view/$base/{}" \; \
                          && find . ! -type d -exec ln -s "$ROOT/$base/{}" "$view/$base/{}" \;)
    done
    tar -C "$ROOT/build" -cf - \
        --exclude=./fulltest --exclude='*.hdd' --exclude='*.log' \
        --exclude='*.ppm' --exclude='*.sock' \
        --exclude='./tests/wineprefix*' --exclude='./tests/ntapi/out' . \
        | tar -C "$view/build" -xpf -
    # The property the whole sandbox rests on: a leg's own $ROOT must be the
    # view. If it ever resolved to the real tree the legs would silently race
    # each other again, so this is asserted, not assumed.
    local probe
    probe="$(cd "$view/tests/run" && cd ../.. && pwd)"
    if [[ "$probe" != "$view" ]]; then
        echo "fulltest: view $view does not hold its own \$ROOT (got $probe) — refusing" >&2
        return 1
    fi
    echo "$view"
}

# ---------------------------------------------------------------------------
# One leg, in its own view. Re-entered as `$0 --leg <name>` by the fan-out
# below, so each leg is a process whose environment is its own.

run_leg() {
    local leg="$1" view="" rc=0 start=$SECONDS secs
    local log="$FT/logs/$leg.log"
    mkdir -p "$FT/logs" "$FT/status"
    printf '[fulltest] start   %s\n' "$leg"

    # $WINEPREFIX is deliberately NOT set: run.sh's default puts it inside the
    # view, where it is created fresh and dies with the view (header).
    #
    # The oracle leg's own fan-out. It is short-lived processes rather than
    # guests, so it may oversubscribe its share; it is also the leg whose tail
    # (the `times` case) wants the box quiet, which is what caps it.
    export ORACLE_JOBS="${FULLTEST_ORACLE_JOBS:-$(( NPROC / 2 > 4 ? NPROC / 2 : 4 ))}"

    local -a cmd
    case "$leg" in
    frontier)
        # Pure python over the call graph — no toolchain, no build, no view.
        cmd=(python3 "$ROOT/tools/blocking_frontier.py" --check)
        ;;
    *)
        view="$(make_view "$leg")" || { echo "$leg: view failed" >"$log"; rc=1; }
        case "$leg" in
        boot)
            # A VIRGIN image runs the whole CUI-1 firstboot INF pass, which
            # qemu.sh's default kill would cut short (the CI comment).
            export TIMEOUT=600
            cmd=(make -C "$view" test)
            ;;
        gui2|gui3|gui4|gui5|gui5con|wow64gui)
            export TIMEOUT=1200 GUI_DEADLINE=900
            cmd=("$view/tests/run/run.sh" "$leg")
            ;;
        wow64aud)
            # CI's budget for this leg (.github/workflows/test.yml), so the
            # same boot is not judged on a smaller one here.
            export TIMEOUT=1200 AUDIO_DEADLINE=900
            cmd=("$view/tests/run/run.sh" "$leg")
            ;;
        winefbunit)
            # The compositor unit suite: no QEMU, seconds. Kept a leg so a
            # policy regression names itself in the same summary table.
            cmd=("$view/tests/run/run.sh" "$leg")
            ;;
        guiwtest)
            export TIMEOUT=3600
            cmd=("$view/tests/run/run.sh" "$leg")
            ;;
        *)
            cmd=("$view/tests/run/run.sh" "$leg")
            ;;
        esac
        ;;
    esac

    if (( rc == 0 )); then
        # A backstop with the same job as CI's timeout-minutes, and the same
        # meaning: every leg bounds its own guests (qemu.sh always does), so
        # this only catches a harness that wedged outside them. It must never
        # be tight enough to cut a slow-but-live leg short.
        timeout -k 30 "${FULLTEST_LEG_TIMEOUT:-5400}" "${cmd[@]}" >"$log" 2>&1 || rc=$?
    fi

    secs=$(( SECONDS - start ))
    printf '%s %s\n' "$rc" "$secs" >"$FT/status/$leg"
    # Timed BEFORE the cleanup: the number reported is the leg, not the rm.
    if (( rc == 0 )) && [[ -n "$view" && -z "${FULLTEST_KEEP_VIEWS:-}" ]]; then
        rm -rf "$view"
    fi
    if (( rc == 0 )); then
        printf '[fulltest] PASS    %-10s %4ds\n' "$leg" "$secs"
    else
        printf '[fulltest] FAIL    %-10s %4ds (rc=%d)  %s\n' "$leg" "$secs" "$rc" "$log"
    fi
    return 0   # a red leg must not stop the fan-out; the summary is the verdict
}

if [[ "${1:-}" == "--leg" ]]; then
    run_leg "$2"
    exit 0
fi

# ---------------------------------------------------------------------------
# The run.

# One run at a time, decided before anything is printed. Two overlapping runs —
# the usual shape being a full run still going while its owner starts a subset
# to iterate — would wipe each other's logs and status files and re-create a
# view out from under a live leg, and the damage would surface as a leg that
# "failed" for no reason anyone can reconstruct. Cheaper to refuse.
mkdir -p "$ROOT/build"   # a fresh clone has none, and mkdir would fail ENOENT
if ! mkdir "$FT.lock" 2>/dev/null; then
    # Which failure it was, not the likelier-sounding one: on a tree where the
    # lock could not be created at all, "another run holds it" is a plausible
    # answer to a question nobody asked — the shape G12 forbids in the kernel.
    if [[ -d "$FT.lock" ]]; then
        echo "fulltest: another run holds $FT.lock — wait for it, or remove that" >&2
        echo "          directory if no fulltest is running." >&2
    else
        echo "fulltest: cannot create the lock $FT.lock — check permissions on" >&2
        echo "          $ROOT/build." >&2
    fi
    exit 2
fi
trap 'rmdir "$FT.lock" 2>/dev/null || true' EXIT

JOBS="${FULLTEST_JOBS:-$(( NPROC / 4 > 4 ? NPROC / 4 : 4 ))}"
LEGS=()
while (( $# )); do
    case "$1" in
    -j) JOBS="${2:?-j needs a number}"; shift 2 ;;
    -j*) JOBS="${1#-j}"; shift ;;
    -h|--help) usage ;;
    -*) usage ;;
    *)
        # A named leg that does not exist is a TYPO, not an empty run — the
        # rule run.sh's check_subtests states: a sweep that ran nothing must
        # never print a green-looking summary.
        found=0
        for l in "${ALL_LEGS[@]}"; do [[ "$1" == "$l" ]] && found=1; done
        (( found )) || { echo "fulltest: no such leg '$1'" >&2; usage; }
        LEGS+=("$1"); shift ;;
    esac
done
if (( ${#LEGS[@]} )); then
    echo "== fulltest: SUBSET run (${LEGS[*]}) — NOT the gate; run unfiltered for a verdict =="
else
    # Dispatch order is the ALL_LEGS order, not the order the user typed.
    LEGS=("${ALL_LEGS[@]}")
fi

rm -rf "$FT/logs" "$FT/status"
mkdir -p "$FT/logs" "$FT/status" "$FT/views"

echo "== fulltest: ${#LEGS[@]} legs, -j$JOBS, $NPROC cores, accel=$("$ROOT/tools/qemu.sh" --print-accel) =="

# Phase 1: build everything every leg needs, ONCE, with the whole box. The legs
# each call `make` for their own targets; with the tree already built those
# calls are no-ops, which is what makes them safe to run at the same time (a
# view isolates the build directory, but nothing would make 26 concurrent cold
# builds a good idea).
echo "== fulltest: build =="
BUILD_START=$SECONDS
# `all` is the test image, which is what every leg boots — it carries the
# whole userland, every client and the whole ntapi/winetest payload, so this
# ONE target replaces the eight per-leg image targets that used to be listed
# here. The rest are what the oracle-side legs build for themselves.
make -C "$ROOT" -j"$NPROC" \
    all ntapi-tests wtests \
    build/modules/torn_workload.bin \
    >"$FT/logs/build.log" 2>&1 \
    || { echo "fulltest: build FAILED — see $FT/logs/build.log" >&2; tail -30 "$FT/logs/build.log" >&2; exit 1; }
echo "== fulltest: build done ($(( SECONDS - BUILD_START ))s) =="

# Phase 2: the fan-out. xargs rather than `wait -n` so this still runs on the
# bash 3.2 a macOS host has; each leg is a fresh process (`--leg`), so a leg's
# exported TIMEOUT cannot reach its neighbours.
#
# An interrupt must take the whole tree with it. This script is not a process
# group leader (it is usually make's child), so there is no group to signal:
# left alone, killing it leaves eight QEMUs holding KVM, ~10 GiB of guest
# memory and their views, which is exactly what happened the first time it was
# interrupted. So the trap walks the tree it started — xargs, the `--leg`
# processes, their `timeout`, run.sh, qemu.sh, QEMU — and kills it depth-first.
kill_tree() {   # $1 = pid; children before parents, so nothing respawns behind us
    local pid="$1" child
    for child in $(pgrep -P "$pid" 2>/dev/null); do kill_tree "$child"; done
    kill -9 "$pid" 2>/dev/null || true
}
START=$SECONDS
printf '%s\n' "${LEGS[@]}" | xargs -P "$JOBS" -n1 "$ROOT/tools/fulltest.sh" --leg &
FANOUT=$!
trap 'echo; echo "== fulltest: interrupted — stopping every leg ==" >&2
      kill_tree "$FANOUT"; rmdir "$FT.lock" 2>/dev/null || true; exit 130' INT TERM
wait "$FANOUT" || true
trap - INT TERM
TOTAL=$(( SECONDS - START ))

# ---------------------------------------------------------------------------
# The verdict. A leg with no status file did not report — that is a failure of
# the harness, and it counts as red: a verdict nobody reached must never read
# as a verdict that passed (the all-green job's rule).

leg_rc() {   # $1 = leg; echoes "<rc> <secs>"
    if [[ -f "$FT/status/$1" ]]; then cat "$FT/status/$1"; else echo "127 0"; fi
}

echo
echo "== fulltest: ${TOTAL}s wall clock (-j$JOBS) =="
fails=0
table=""
for leg in "${LEGS[@]}"; do
    read -r rc secs < <(leg_rc "$leg")
    if (( rc == 0 )); then
        table+="$(printf '  PASS %4ds %s' "$secs" "$leg")"$'\n'
    else
        table+="$(printf '  FAIL %4ds %s (rc=%d)' "$secs" "$leg" "$rc")"$'\n'
        fails=$(( fails + 1 ))
    fi
done
printf '%s' "$table" | sort -k2 -n -r

# What this run judged is the WORKING tree; what CI will judge is the COMMITTED
# one. Nothing here can close that gap — a required file nobody `git add`ed is
# green in every leg above — so the run says which tree it just answered for
# rather than letting a green table imply the other one. Counted, not listed:
# the point is the fact, and `git status` is right there.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    dirty="$(git -C "$ROOT" status --porcelain --untracked-files=normal 2>/dev/null | grep -cv '^$' || true)"
    if (( dirty > 0 )); then
        echo "   (working tree not clean: $dirty changed/untracked path(s) — CI tests the"
        echo "    COMMITTED tree, so commit before reading this as CI's answer)"
    fi
fi

if (( fails )); then
    echo
    for leg in "${LEGS[@]}"; do
        read -r rc _ < <(leg_rc "$leg")
        (( rc == 0 )) && continue
        echo "--- $leg (last 25 lines of $FT/logs/$leg.log) ---"
        tail -25 "$FT/logs/$leg.log" 2>/dev/null || echo "(no log)"
        echo "    serial logs under: $FT/views/$leg/build/"
    done
    echo
    echo "== fulltest: $fails/${#LEGS[@]} legs FAILED =="
    exit 1
fi
echo "== fulltest: all ${#LEGS[@]} legs PASS =="
