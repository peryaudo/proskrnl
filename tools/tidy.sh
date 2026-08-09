#!/bin/sh
# proskrnl — parallel clang-tidy driver for `make format` (docs/15).
#
# clang-tidy is one process per translation unit and 90-odd TUs cost minutes
# single-file; this fans the read-only pass out over every core. Two passes,
# because --fix is NOT safe to run in parallel: a header matched by
# HeaderFilterRegex is rewritten by every TU that includes it, and two
# concurrent rewriters silently clobber each other's edits.
#
#   1. parallel, read-only: every TU, --warnings-as-errors. Its output is
#      discarded — with 32 interleaving writers it would be unreadable, and a
#      clean tree has nothing to say. The exit code is the whole verdict.
#   2. serial, --fix: only the TUs that had a finding — normally the file you
#      just edited. Its output is what you see; fixing a shared header in one
#      TU is picked up by the next, which is why this pass is ordered.
#
# The run then FAILS even though it fixed what it could: a warning it just
# fixed is a warning you introduced, and that failure is what makes it a gate.
# Re-run to see the tree green, and `git diff` for what it did.
#
# usage: tools/tidy.sh <clang-tidy> <compile-flags-as-one-word> <file.c>...
# env:   TIDY_JOBS — parallelism (default: online CPUs)
set -u

TIDY_BIN=$1
shift
TIDY_CFLAGS=$1
shift
[ $# -gt 0 ] || exit 0

JOBS=${TIDY_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
TIDY_TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TIDY_TMP"' EXIT HUP INT TERM
export TIDY_BIN TIDY_CFLAGS TIDY_TMP

echo "clang-tidy: $# files, $JOBS jobs"
# Largest TU first (`ls -S`): with more files than cores the run is as long as
# whatever starts last, so the big ones must not be the tail.
#
# $0 inside `sh -c` is the file xargs substituted; $TIDY_CFLAGS is unquoted on
# purpose (it is a flag list, not one word). A finding names itself in
# $TIDY_TMP/failed — the appends are single short writes to O_APPEND, so they
# do not interleave.
ls -S -- "$@" | xargs -P "$JOBS" -n1 sh -c '
    "$TIDY_BIN" --quiet --warnings-as-errors="*" "$0" -- $TIDY_CFLAGS \
        >/dev/null 2>&1 || printf "%s\n" "$0" >>"$TIDY_TMP/failed"
'

[ -f "$TIDY_TMP/failed" ] || exit 0

set -- $(sort -u "$TIDY_TMP/failed")
echo "clang-tidy: findings in $# file(s) — re-running those with --fix"
for f in "$@"; do
    "$TIDY_BIN" --quiet --warnings-as-errors='*' \
        --fix --fix-notes --format-style=file "$f" -- $TIDY_CFLAGS
done
exit 1
