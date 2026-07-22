#!/bin/bash
# SessionStart hook (Claude Code on the web): restore the pinned third_party
# builds (qemu/wine/limine) from the third-party-cache GitHub release instead
# of building them from source (tools/fetch_third_party.sh).
#
# Runs in the harness's async hook mode: the '{"async": ...}' line below tells
# Claude Code to let the session start while this script keeps running in the
# background. Do NOT self-background with `nohup ... &` — the harness kills
# the hook's process group as soon as the hook command returns, which orphans
# and kills the child mid-download (that failure mode is why this file exists).
#
# Progress / result: tail -f /tmp/fetch_third_party.log
set -euo pipefail

# Web sessions only; local checkouts manage third_party themselves.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ] || [ "$(uname)" != "Linux" ]; then
    exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

# Fully restored already (marker = wine pass-2 test exe, the same marker
# setup_linux.sh and fetch_third_party.sh key on) and every submodule
# initialized -> nothing to do; exit synchronously without going async.
if [ -e third_party/wine/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe ] \
    && ! git submodule status 2>/dev/null | grep -q '^-'; then
    exit 0
fi

echo '{"async": true, "asyncTimeout": 1800000}'

# fetch_third_party.sh is idempotent per component, so a rerun after a partial
# restore (or a resumed session) picks up where it left off.
tools/fetch_third_party.sh >/tmp/fetch_third_party.log 2>&1
