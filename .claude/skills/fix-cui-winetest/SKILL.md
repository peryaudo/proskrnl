---
name: fix-cui-winetest
description: Take ONE `# TODO: Implement` work item from the CUI winetest manifest (tests/winetest/manifest.txt, planned in docs/21), pin it against the oracle, implement it, re-measure, un-park the pair if it is green, then gate-check, open a PR, wait for CI and rebase-merge. Refuses when no unparkable item is left. Invoke manually with /fix-cui-winetest; never triggered automatically.
argument-hint: [pair-or-W-item]
disable-model-invocation: true
context: fork
agent: general-purpose
background: false
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill, WebFetch, TaskCreate, TaskUpdate, TaskList
---

# fix-cui-winetest

Close **one** entry on the CUI winetest frontier, end to end: pick it, pin it,
build it, prove it, land it.

You are running in a forked subagent with the full tool set. `$ARGUMENTS`, if
present, names the pair (`ntdll:virtual`) or the docs/21 item (`W8`) to work;
otherwise you choose. Work **one** item. Finishing one item properly beats
starting three.

> **You have full access, on purpose, and every frontmatter field is part of
> that.** `agent: general-purpose` is the agent type with the complete tool
> set. `background: false` keeps it: a *backgrounded* fork is restricted to
> the narrower background-subagent tools, which would cost you Write and
> Edit. `allowed-tools` pre-approves the lot so the run does not stall on a
> permission prompt half an hour in. The cost of `background: false` is that
> this blocks the invoking turn, including the CI wait — that is the intended
> trade; do not "fix" it by backgrounding the fork.
>
> Full access means you can push to a remote and merge to `main` with nobody
> watching. The steps below are what keeps that safe — the unfiltered gate
> runs before any commit, and the hard stop at Step 8 on a red check. Run
> them; do not shortcut them because you are confident.

## Before anything: read the rules

`CLAUDE.md`, `docs/09-constitution.md` and `docs/CONTRIBUTING.md` are gates,
not advice, and this workflow touches the areas they guard hardest. Read
`docs/21-winetest-frontier.md` in full — §4 "Traps" exists to stop you losing
a day, and the manifest header explains why a pair is parked.

Also honour `CLAUDE.local.md` for the `make -j` flag on this machine.

**One instance at a time.** Test legs bake disk images from the *live working
tree*, so a checkout, stash or edit while a leg is running corrupts that
leg's image. Never mutate the tree while `run.sh` or `make test` is in
flight, and do not run two of these skills concurrently.

## Step 1 — Pick an item, or REFUSE

List what is unparkable. An item is unparkable iff its manifest block ends
with `# TODO: Implement` — that marker is the manifest's own statement that
the pair is red for a *kernel* reason (category 1). Blocks without it are
category 2: not reachable without reversing a recorded decision.

```sh
grep -A1 '^# TODO: Implement$' tests/winetest/manifest.txt \
  | grep -E '^# [a-z0-9_.]+\.exe:' | sed 's/^# //'
```

**If that command prints nothing, STOP and refuse.** Say that the CUI
winetest frontier has no unparkable item left, that every remaining
commented-out pair is category 2 (name a couple with their deciding
constraint), and that re-parking one of those needs a human decision to
reverse the constraint, not an implementation. Do not invent work, do not
widen the manifest, and do not pick a category-2 pair "because it looks
fixable". Exit.

Otherwise choose one, honouring `$ARGUMENTS` when given. Cross-reference
docs/21's W-items for the planned approach and the article risks; prefer an
item docs/21 has already scoped. Avoid what docs/21 §4 names as traps.

## Step 2 — MEASURE the pair before you believe its block

The manifest's counts are re-measured whenever a pair is touched, but a pair
that **stops** — panics, or is killed by a fault — has not been measured at
all past the stop. Its recorded count is a **lower bound**, and reading one
as "nearly green" is how an hour-long item gets scheduled as a one-liner.
docs/21 §4 records this trap because it was paid for.

Temporarily un-comment the pair and measure it:

```sh
tests/run/run.sh winetest <module>:<subtest>     # both legs
```

Then read the serial log — `build/tests/wtest-subset-serial.log`, stripping
ANSI escapes — and count failures per source line so you know the real
clusters and their sizes. If the oracle leg is red, the pair cannot convict
the kernel (Art. 6): re-park it with that finding and pick another item.

Re-scope now if the measurement disagrees with the block. Say so plainly
later rather than quietly working a different item.

## Step 3 — Pin first (G5), and let the oracle correct you

Write a `tests/ntapi/<bucket>/<name>.c` case for the behaviour you are about
to build, following the neighbours' style and header conventions.

```sh
tests/run/run.sh oracle <name>
```

Iterate until it is **green on the oracle** before touching the kernel.

- **Expect to be refuted.** When the oracle disagrees with your expectation,
  the oracle is right (Art. 6) — change the assertion to what was measured
  and record *that* in the comment. Never bend the kernel to your original
  guess, and never weaken an assertion just to get green.
- **Where the pinned Wine answers `STATUS_NOT_IMPLEMENTED` it has nothing to
  say.** That is a gap in the oracle, not a ceiling: build against NT's
  documented contract in a `beyond_oracle { }` block naming the Microsoft
  page. **Never assert `STATUS_NOT_IMPLEMENTED` in a test** (G12).
- The test harness's `printf` has **no `%I` length modifier** — use `%llx`
  with an `(unsigned long long)` cast for `SIZE_T`. A bad specifier prints
  literally and silently, so you will only notice when an assertion fires.
- Cover the cases an implementation could get *plausibly* wrong, not just the
  happy path: exact-extent rules, "which range does this apply to", and state
  that cannot be inferred from what a query reports.

## Step 4 — Implement, then prove it

Write the kernel change. While doing so:

- **Extend the existing engine; never add a second one** (Art. 11/G10). If
  you find yourself writing a loop that resolves names, allocates handles,
  mints ids, or splits a structure a second way, route through the one
  authority instead — even if the two would behave identically today.
- **Refuse loudly, never plausibly** (Art. 12/G12). An unserviceable case
  gets its specific NT failure, implemented and pinned. `STATUS_NOT_IMPLEMENTED`
  from a ring-3 syscall is a panic and must stay one.
- **Mirror the pinned oracle's order of checks** and cite it by path+symbol.
  Do not recall constants; `abi/` is generated (`/gen-abi`).
- **Do not claim more in a comment than you measured.** An overclaiming
  comment is the same defect G8 forbids in a constant.

Then prove it, in this order, and do not proceed past a failure:

```sh
make -j<N>                                  # per CLAUDE.local.md
tests/run/run.sh proskrnl <name>            # the new pin, on the kernel
tests/run/run.sh winetest <module>:<subtest># re-measure the pair
tests/run/run.sh oracle                     # unfiltered — the spec gate
tests/run/run.sh proskrnl                   # unfiltered — the regression gate
make -j<N> test
make -j<N> tidy
python3 tools/blocking_frontier.py --check
```

A subset run is for iteration only; only the **unfiltered** legs are a
verdict.

## Step 5 — Un-park only if it is actually green

- **Green on both legs** → un-comment the pair. It is now part of the gate.
- **Still red** → leave it commented out and **rewrite its triage block**
  with the numbers you just measured: total failures, the dominant clusters
  with counts and source lines, and what each one actually is. Keep
  `# TODO: Implement`.

Never activate a red pair. The active list is a pass/fail signal, and a
permanently-red entry teaches the next person to ignore the gate — the
manifest header says so.

Update `docs/21` for the item: mark it DONE, or record what it turned out to
be. **If the measurement contradicts something docs/21 asserts, fix the
assertion and say why it was wrong** — that correction is often worth more
than the code.

Add the `docs/03-nt-deviations.md` note for any behaviour that deviates or
that a future reader would otherwise have to re-derive, and update
`docs/16-syscall-status.md` if a refusal became an implementation.

## Step 6 — Gate-check

Review the full diff against the gates and **resolve what it finds**. Be
adversarial with your own work: G11's ownership audit and G12's loud-refusal
hunt are the two that most often catch a real defect. If a fix falls out of
it, re-run the affected legs from Step 4.

`gate-check` is itself a forked skill, and you are already a fork — nesting
may not be available here. So: try invoking it, and **if that fails, read
`.claude/skills/gate-check/SKILL.md` and apply it yourself**. The gates are
what matter; which mechanism ran them does not. Reviewing your own diff is
weaker than a fresh reviewer doing it, so lean harder on the evidence: for
every finding, cite `file:line` and state the concrete failure, not the
category.

## Step 7 — Commit as meaningful units (G13)

One logical change per commit, each buildable alone, subject naming the
department(s), body stating what / why / how verified. The order is not
negotiable:

1. `tests/ntapi: <pin>` — the oracle pin **precedes** the kernel commit; that
   ordering is the only proof the test was green before the code existed.
2. `<dept>: <behaviour>` — the kernel change plus its `docs/03` (and
   `docs/16`) notes.
3. `tests/winetest+docs/21: <bookkeeping>` — the manifest and docs/21.

No WIP or fixup commits. Squash and reorder locally first.

## Step 8 — PR, CI, merge

Push a feature branch and open a PR whose body states: what landed, whether
the pair went green (and if not, the measured residue), what the oracle
refuted, and the verification you ran.

Wait for CI.

**All checks green** → `gh pr merge <n> --rebase`. Done.

**A check is red or cancelled** → re-run the failed job once (some legs are
genuinely flaky). If it goes green, merge. If it stays red, you must decide
whether the failure belongs to this branch, and the answer decides the
outcome:

### Proving a failure is NOT the branch's

The bar is **positive evidence**, not absence of a connection. "I can't see
how my change would cause this" is not evidence — it is the thing every
author believes right before they are wrong. Produce at least one of:

1. **The same signature on `main`.** Find a recent `main` run of the *same
   job* that failed the *same way* — same failure mode, same test named, and
   for a hang/timeout the same orphan-process list or the same last log line.
   A `main` run contains none of your commits, so this is conclusive. Cite
   the run ID and both timestamps.
2. **A mechanical impossibility, stated concretely.** Not "unrelated" but
   *why*: e.g. "the ntapi **oracle** leg executes test binaries under Wine and
   runs no kernel code at all, and this branch changes only `kernel/`" — and
   then account for anything the branch *did* add to that leg. Adding a
   `tests/ntapi` case changes worker sharding, so it can perturb *timing*
   even when it cannot perturb *semantics*; say which one the failure needs.
3. **A green local run of that same leg on this branch**, unfiltered, plus a
   named cause elsewhere. This is the weakest of the three and never stands
   alone.

Known pre-existing failures, which still need their signature matched rather
than being assumed:

- the ntapi **oracle** leg can wedge on `io_teardown` and die at the
  60-minute cap, leaving no output but an orphan-process list (issue #118);
- `delete_on_close` fails on any second oracle run in the same wineprefix
  (issue #117).

### Never merge on red when

- the failing check is one this diff is *about* — the ntapi **proskrnl**
  (regression) leg, the winetest leg for a kernel change, `boot`, or
  `frontier`;
- the failure names a file, test, or subsystem the diff touches;
- the job failed on a real assertion rather than a hang/timeout/infrastructure
  error, and you cannot point to that same assertion failing on `main`;
- you have suspicion but not one of the three proofs above.

In any of these, **STOP and report**. Say what is red, what you ruled out,
and what evidence would settle it. Handing back an unmerged PR with a clear
question is a good outcome; merging a defect into `main` is not.

### When it IS proven unrelated

Then it is a defect in the project that happens to be blocking you, and the
record matters more than the merge:

1. **Search first** — `gh issue list --state open` — and do not duplicate.
   If an issue already covers it (e.g. #117, #118), use that one.
2. **Otherwise file it**, with: the signature, the reproduction, the evidence
   that it is pre-existing (the `main` run ID), which CI job it blocks and
   how often, and a suggested fix if you have one. An issue nobody can act on
   is barely better than no issue.
3. **Record the decision on the PR** — a comment naming the red check, the
   issue, and the `main` run that proves it pre-existing. A merge over a red
   check must never look silent to whoever reads the history later.
4. **Then** `gh pr merge <n> --rebase`.

Note what this is not: permission to merge because CI is inconvenient. It is
permission to merge when you have *proved* the red check is measuring
something other than your change — and the issue you file is the proof,
written down.

Finally, report: the item, whether the pair is now in the gate, the residue
if not, anything the oracle refuted, and any unrelated defect you found on
the way (file it as a GitHub issue with its reproduction).
