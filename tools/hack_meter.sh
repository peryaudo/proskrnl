#!/usr/bin/env bash
# hack_meter.sh — the project's "hack meter" (docs/06, Art. 10 / gate G9):
# the third_party/wine submodule diff between the pinned fork commit and its
# winehq base. The base is the fork's own `master` branch, which mirrors the
# winehq commit `proskrnl-target` is based on — a pin bump fast-forwards
# master to the new base in the same push that rebases proskrnl-target onto
# it, so the meter needs no separately-recorded SHA. The local submodule
# clone is shallow; the base ref is fetched (once, one commit) on first use.
#
#   tools/hack_meter.sh           one-line summary (the meter)
#   tools/hack_meter.sh --stat    per-file breakdown
#   tools/hack_meter.sh --diff    the full reviewable diff
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WINE="$ROOT/third_party/wine"

if ! git -C "$WINE" rev-parse --verify --quiet origin/master >/dev/null; then
    git -C "$WINE" fetch --quiet --depth 1 origin master:refs/remotes/origin/master || {
        echo "hack_meter: cannot fetch the fork's master (the winehq base) — offline?" >&2
        exit 1
    }
fi

case "${1:---shortstat}" in
    --stat)  git -C "$WINE" diff --stat origin/master..HEAD ;;
    --diff)  git -C "$WINE" diff origin/master..HEAD ;;
    *)       git -C "$WINE" diff --shortstat origin/master..HEAD ;;
esac
