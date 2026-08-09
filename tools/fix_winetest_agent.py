#!/usr/bin/env python3
"""tools/fix_winetest_agent.py - drive /fix-cui-winetest in a loop.

The CUI winetest frontier is closed one manifest item at a time, and
`.claude/skills/fix-cui-winetest/SKILL.md` is deliberately a ONE-item
workflow: pick, pin, implement, measure, gate-check, merge, stop. Closing the
frontier therefore means invoking it again and again, each time on a fresh
context, until the manifest has no `# TODO: Implement` block left.

This script is that outer loop, built on the Claude Agent SDK:

    while <a checker agent says the manifest still has workable items>:
        run /fix-cui-winetest on a fresh Opus 5 context

Each iteration is an independent `query()` call, so it starts with an empty
context exactly as a fresh `/fix-cui-winetest` invocation in the CLI would -
which is what the skill asks for ("run it in your own context, on purpose").
Tools are auto-approved (`--permission-mode bypassPermissions`, the SDK
equivalent of Claude Code's auto mode), because the skill's own header
pre-approves its tool set so an hour-long run does not stall on a prompt.

Guard rails, all of them there because the skill says so:

  * ONE INSTANCE AT A TIME. Test legs bake disk images from the live working
    tree, so two of these running at once corrupt each other's images. A
    lockfile enforces it.
  * CLEAN TREE BETWEEN ITERATIONS. `make fulltest` judges the working tree
    and CI judges the committed one; a dirty tree left behind by a previous
    iteration means that iteration did not finish, and starting another on
    top of it is how a half-done change gets measured as if it were done.
  * STALL DETECTION. An iteration that lands nothing leaves `main` where it
    was. Two of those in a row means the loop is spinning, not working.

Usage - `uv run` fetches the SDK into a cached throwaway env, so there is no
venv to create or activate first:

    R="uv run --with claude-agent-sdk tools/fix_winetest_agent.py"
    $R                    # loop until the frontier is closed
    $R --max-iterations 3 # bounded run
    $R --check-only       # just ask whether work remains
    $R --item W8          # pass an argument to the skill

Any interpreter that already has `claude-agent-sdk` installed runs it the
same way (`python3 tools/fix_winetest_agent.py ...`). Either way it also
needs the `claude` CLI on PATH, plus whatever credentials that CLI uses.
"""

import argparse
import asyncio
import contextlib
import errno
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        ResultMessage,
        TextBlock,
        query,
    )
except ImportError:  # pragma: no cover - dependency check, not logic
    sys.exit(
        "claude_agent_sdk is not installed. Re-run it under uv:\n"
        "    uv run --with claude-agent-sdk tools/fix_winetest_agent.py ...\n"
        "or install it into this interpreter (`pip install claude-agent-sdk`).\n"
        "It also needs the `claude` CLI on PATH."
    )

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "tests" / "winetest" / "manifest.txt"
LOCKFILE = REPO_ROOT / "build" / "fix_winetest_agent.lock"

# Both agents run with the Claude Code preset + the repo's own settings, so
# CLAUDE.md, CLAUDE.local.md and .claude/skills/ are loaded exactly as they
# are in an interactive session. Without this the SDK loads no filesystem
# settings at all and /fix-cui-winetest would not exist.
SETTING_SOURCES = ["user", "project", "local"]
SYSTEM_PROMPT = {"type": "preset", "preset": "claude_code"}

VERDICT_RE = re.compile(r"^VERDICT:\s*(WORK_REMAINING|NONE_LEFT)\s*$", re.MULTILINE)

CHECKER_PROMPT = """\
You are the loop condition for an automated runner of the `/fix-cui-winetest`
skill. Decide ONE thing: does the CUI winetest manifest still contain an
item that skill would be willing to work?

The skill's own definition of "workable" (see
`.claude/skills/fix-cui-winetest/SKILL.md` Step 1) is a commented-out pair
whose triage block ends with the marker `# TODO: Implement`. Blocks without
that marker are category 2 - not reachable without a human reversing a
recorded decision - and do NOT count.

Run exactly this, from the repository root:

    grep -A1 '^# TODO: Implement$' tests/winetest/manifest.txt \\
      | grep -E '^# [a-z0-9_.]+\\.exe:' | sed 's/^# //'

Read the surrounding blocks of anything it prints to confirm they really are
parked-for-a-kernel-reason entries rather than stale markers, and say so.

Do not modify any file. Do not start the work. Report only.

Finish your reply with a machine-readable verdict as the LAST line, exactly
one of:

VERDICT: WORK_REMAINING
VERDICT: NONE_LEFT

Before that line, list the candidate pairs you found (or state that there are
none) in at most five lines.
"""

FIX_PROMPT_TEMPLATE = "/fix-cui-winetest{args}"


def log(message):
    """Timestamped runner line, distinct from anything the agents print."""
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[loop {stamp}] {message}", flush=True)


def git(*args):
    """Run a git command in the repo and return its stripped stdout."""
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@contextlib.contextmanager
def single_instance():
    """Refuse to run twice: concurrent runs corrupt each other's test images.

    O_EXCL creation is the whole mechanism - a stale lock from a killed run
    has to be removed by hand, which is the right amount of friction for
    something whose failure mode is a silently wrong test result.
    """
    LOCKFILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(LOCKFILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
        holder = LOCKFILE.read_text().strip() or "unknown"
        sys.exit(
            f"another run holds {LOCKFILE} ({holder}).\n"
            "Test legs bake disk images from the live working tree, so two "
            "runs would corrupt each other. If no run is alive, delete the "
            "lockfile."
        )
    try:
        os.write(fd, f"pid {os.getpid()} started {datetime.now(timezone.utc).isoformat()}\n".encode())
        os.close(fd)
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            LOCKFILE.unlink()


def describe_block(block):
    """One line for a streamed content block, or None to print nothing."""
    if isinstance(block, TextBlock):
        text = block.text.strip()
        return text or None
    # ToolUseBlock / ThinkingBlock and friends are matched structurally so
    # this keeps working across SDK versions that add or rename block types.
    name = getattr(block, "name", None)
    if name is not None:
        payload = getattr(block, "input", {}) or {}
        detail = payload.get("command") or payload.get("file_path") or payload.get("pattern") or ""
        detail = " ".join(str(detail).split())
        if len(detail) > 160:
            detail = detail[:157] + "..."
        return f"  -> {name}({detail})" if detail else f"  -> {name}"
    return None


async def run_agent(prompt, options, quiet=False):
    """Run one agent to completion, streaming as it goes.

    Returns (transcript, result_message). `query()` raises after yielding an
    error result (the CLI exits non-zero), so the raise is caught here and
    reported like any other outcome - the loop decides what to do about it.
    """
    transcript = []
    result = None
    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    line = describe_block(block)
                    if line is None:
                        continue
                    if isinstance(block, TextBlock):
                        transcript.append(line)
                    if not quiet:
                        print(line, flush=True)
            elif isinstance(message, ResultMessage):
                result = message
                if message.result:
                    transcript.append(str(message.result))
    except Exception as exc:  # the SDK surfaces error results as a plain Exception
        log(f"agent ended with an error: {exc}")
    return "\n".join(transcript), result


def result_summary(result):
    if result is None:
        return "no result message"
    parts = [f"subtype={result.subtype}"]
    reason = getattr(result, "terminal_reason", None)
    if reason:
        parts.append(f"terminal_reason={reason}")
    cost = getattr(result, "total_cost_usd", None)
    if cost is not None:
        parts.append(f"cost=${cost:.2f}")
    return ", ".join(parts)


async def check_work_remaining(model, timeout):
    """Ask an agent whether the manifest still has an unparkable item."""
    options = ClaudeAgentOptions(
        cwd=str(REPO_ROOT),
        model=model,
        permission_mode="bypassPermissions",
        setting_sources=SETTING_SOURCES,
        system_prompt=SYSTEM_PROMPT,
        allowed_tools=["Bash", "Read", "Grep", "Glob"],
        disallowed_tools=["Write", "Edit", "NotebookEdit"],
        max_turns=12,
    )
    coro = run_agent(CHECKER_PROMPT, options)
    transcript, result = await (asyncio.wait_for(coro, timeout) if timeout else coro)
    log(f"checker finished ({result_summary(result)})")

    matches = VERDICT_RE.findall(transcript)
    if not matches:
        raise RuntimeError(
            "checker produced no VERDICT line; refusing to guess whether work "
            "remains. Re-run with --check-only to see its output."
        )
    return matches[-1] == "WORK_REMAINING"


async def run_fix_iteration(model, effort, item, timeout):
    """Invoke /fix-cui-winetest once, on a fresh context."""
    options = ClaudeAgentOptions(
        cwd=str(REPO_ROOT),
        model=model,
        permission_mode="bypassPermissions",
        setting_sources=SETTING_SOURCES,
        system_prompt=SYSTEM_PROMPT,
        skills="all",
        **({"effort": effort} if effort else {}),
    )
    prompt = FIX_PROMPT_TEMPLATE.format(args=f" {item}" if item else "")
    log(f"invoking {prompt!r} on {model}")
    coro = run_agent(prompt, options)
    _, result = await (asyncio.wait_for(coro, timeout) if timeout else coro)
    log(f"iteration finished ({result_summary(result)})")
    return result


def assert_clean_tree(allow_dirty):
    dirty = git("status", "--porcelain")
    if not dirty:
        return
    if allow_dirty:
        log("working tree is dirty; continuing because --allow-dirty was given")
        return
    sys.exit(
        "working tree is not clean:\n"
        + dirty
        + "\n\nThe skill's Step 8 requires `git status --porcelain` to be empty "
        "before a merge, so a dirty tree means the previous iteration did not "
        "finish. Resolve it by hand, or pass --allow-dirty if you know better."
    )


async def main_async(args):
    if not MANIFEST.exists():
        sys.exit(f"{MANIFEST} not found - is {REPO_ROOT} the proskrnl checkout?")

    if args.check_only:
        remaining = await check_work_remaining(args.checker_model, args.checker_timeout)
        log("work remains" if remaining else "frontier is closed")
        return 0 if remaining else 1

    stalls = 0
    iteration = 0
    started = time.monotonic()

    while args.max_iterations is None or iteration < args.max_iterations:
        iteration += 1
        log(f"=== iteration {iteration} ===")
        assert_clean_tree(args.allow_dirty)

        try:
            remaining = await check_work_remaining(args.checker_model, args.checker_timeout)
        except asyncio.TimeoutError:
            log("checker timed out; stopping")
            return 1
        except RuntimeError as exc:
            log(str(exc))
            return 1

        if not remaining:
            log("checker reports no unparkable item left - frontier closed. Stopping.")
            break

        before = git("rev-parse", "HEAD")
        try:
            await run_fix_iteration(args.model, args.effort, args.item, args.iteration_timeout)
        except asyncio.TimeoutError:
            log(f"iteration exceeded --iteration-timeout ({args.iteration_timeout}s); stopping")
            return 1

        after = git("rev-parse", "HEAD")
        if after == before:
            stalls += 1
            log(f"HEAD did not move ({before[:12]}); stall {stalls}/{args.max_stalls}")
            if stalls >= args.max_stalls:
                log(
                    "the loop is spinning without landing anything - stopping so a "
                    "human can read the last iteration's output."
                )
                return 1
        else:
            stalls = 0
            log(f"landed {before[:12]} -> {after[:12]}")

        # `--item` names ONE item; re-running the loop with it would work the
        # same entry forever. Honour it for the first iteration only.
        args.item = None
    else:
        log(f"reached --max-iterations ({args.max_iterations})")

    elapsed = time.monotonic() - started
    log(f"done after {iteration} iteration(s), {elapsed / 60:.1f} min")
    return 0


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run /fix-cui-winetest repeatedly until the CUI winetest frontier is closed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[1] if "Usage:" in __doc__ else None,
    )
    parser.add_argument(
        "--model",
        default="claude-opus-5",
        help="model for the /fix-cui-winetest iterations (default: %(default)s)",
    )
    parser.add_argument(
        "--checker-model",
        default="claude-sonnet-5",
        help="model for the cheap read-only loop-condition agent (default: %(default)s)",
    )
    parser.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        default=None,
        help="reasoning effort for the fix iterations (default: the model's own)",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="stop after N iterations (default: run until the frontier is closed)",
    )
    parser.add_argument(
        "--max-stalls",
        type=int,
        default=2,
        help="stop after N consecutive iterations that land nothing (default: %(default)s)",
    )
    parser.add_argument(
        "--item",
        default=None,
        help="argument for the first invocation, e.g. a pair (ntdll:virtual) or a docs/21 item (W8)",
    )
    parser.add_argument(
        "--iteration-timeout",
        type=int,
        default=4 * 60 * 60,
        help="seconds before an unattended iteration is abandoned; 0 disables (default: %(default)s)",
    )
    parser.add_argument(
        "--checker-timeout",
        type=int,
        default=10 * 60,
        help="seconds before the checker agent is abandoned; 0 disables (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="do not refuse to start on a dirty working tree",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="run the checker once and exit (0 = work remains, 1 = frontier closed)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    with single_instance():
        try:
            return asyncio.run(main_async(args))
        except KeyboardInterrupt:
            log("interrupted")
            return 130


if __name__ == "__main__":
    sys.exit(main())
