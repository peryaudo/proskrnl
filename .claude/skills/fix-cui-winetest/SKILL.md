---
name: fix-cui-winetest
description: Take ONE `# TODO: Implement` work item from the CUI winetest manifest (tests/winetest/manifest.txt, planned in docs/21), pin it against the oracle, implement it, re-measure, un-park the pair if it is green, then gate-check, prove it with `make fulltest`, open a PR and rebase-merge. Refuses when no unparkable item is left. Invoke manually with /fix-cui-winetest; never triggered automatically.
argument-hint: [pair-or-W-item]
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill, WebFetch, TaskCreate, TaskUpdate, TaskList
---

# fix-cui-winetest

Close **one** entry on the CUI winetest frontier, end to end: pick it, pin it,
build it, prove it, land it.

You run this yourself, in the main conversation — do **not** hand it to a
subagent. `$ARGUMENTS`, if present, names the pair (`ntdll:virtual`) or the
docs/21 item (`W8`) to work; otherwise you choose. Work **one** item.
Finishing one item properly beats starting three.

> **Run it in your own context, on purpose.** The work below is a long
> single-threaded loop — pin, build, measure, land — where each step reads the
> last step's output, and the user watches it happen and can steer mid-run. A
> subagent would hide all of that behind one summary at the end. `allowed-tools`
> pre-approves the tool set so the run does not stall on a permission prompt
> half an hour in. The cost is that this occupies the session for the whole
> run — that is the intended trade; do not "fix" it by delegating or
> backgrounding the work.
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
leg's image. `make fulltest` does not change this — its sandboxes symlink the
sources, so an edit mid-run reaches every leg at once. Never mutate the tree
while `run.sh`, `make test` or `make fulltest` is in flight, and do not run two
of these skills concurrently.

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
make -j<N> tidy                             # REWRITES source — so, before the verdict
make fulltest                               # THE verdict — every leg CI runs, ~3 min
```

The first three are ITERATION: a subset run is never a verdict. `make fulltest`
(`tools/fulltest.sh`, docs/08) is — it runs the same 26 legs
`.github/workflows/test.yml` runs, sandboxed one per leg and fanned out over
this box: the unfiltered oracle and proskrnl legs, the whole winetest sweep,
`make test`, the fuzzer, the FAT batteries, every CUI and GUI leg, the
user32:msg trophy and the blocking-frontier check. It prints a PASS/FAIL table
and exits non-zero if any leg is red; read the table, not the exit code alone.

`tidy` runs *before* it, never after: it rewrites source in place, and a verdict
taken on a tree that then changed is not a verdict on what you push (Step 8,
precondition 2). Same rule for any other edit — re-run rather than reason about
whether it mattered.

**A red leg is yours until proven otherwise.** The one standing exception on a
KVM developer box is the `winetest` leg going red on the ORACLE half of
`kernel32:version` — 36 failures, all at `version.c:1087`, `CreateProcessA`
returning `ERROR_FILE_NOT_FOUND`. That residue is host-local, pre-existing and
documented in the manifest header; it is green on CI. Accept it only when the
signature matches *exactly* (that line, that count, the oracle half) and the
kernel half of the pair passed. Any other red — including a different count on
that same pair — is a stop.

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
it, re-run Step 4 — `make fulltest` in full, not the legs you guess are
affected: it is three minutes, and the guess is the part that goes wrong.

Invoke `gate-check` — running in the main conversation, you get its fork for
free, and a reviewer that has not seen you write the diff catches more than
you reviewing yourself. **If the invocation fails, read
`.claude/skills/gate-check/SKILL.md` and apply it yourself**; the gates are
what matter, not which mechanism ran them. Self-review is the weaker path, so
lean harder on the evidence there: for every finding, cite `file:line` and
state the concrete failure, not the category.

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

## Step 8 — PR and merge; the local suite is the gate, not CI

Push a feature branch and open a PR whose body states: what landed, whether
the pair went green (and if not, the measured residue), what the oracle
refuted, and the verification you ran — quote the `make fulltest` summary
line, and name the host-local exception if you accepted one.

Then merge: `gh pr merge <n> --rebase`. **Do not wait for CI.** CI runs the
same 26 legs `make fulltest` just ran; waiting adds half an hour and no
information. Merge only with all three of these true:

1. `make fulltest` green — or red *only* on the documented `kernel32:version`
   oracle residue, signature matched as Step 4 describes;
2. the commits are exactly the tree you tested, and `git status --porcelain` is
   empty. fulltest judges the WORKING tree and CI judges the COMMITTED one, so
   an unadded file is green in all 26 legs and red on CI — and any edit after
   the run, including a "trivial" comment fix, invalidates it. Re-run rather
   than reason about whether it mattered;
3. `make tidy` clean and the Step 6 gate-check resolved.

What skipping the wait costs, honestly: CI is a slower machine (two cores,
TCG, virgin cache), so the failures it can see that fulltest cannot are the
ones settled by machine SPEED rather than by semantics — which is why the
user32:msg leg is advisory on PRs there (docs/03 "GUI-5 winetest notes").
Everything semantic, fulltest has already answered. CI still runs on `main`
after the merge and remains the project's record; if a leg fulltest passed
goes red there, that is a real finding — either a machine-speed divergence or
a hole in fulltest's fidelity — and it is yours to chase, not to ignore.

### When fulltest is red

**STOP and report.** A red leg is this branch's until proven otherwise, and
the proof bar is *positive evidence*, not absence of a connection — "I can't
see how my change would cause this" is what every author believes right before
they are wrong. Produce one of:

1. **The same signature with the change removed.** With nothing in flight
   (the stash itself would corrupt a running leg), `git stash` — or check out
   the merge base — re-run that one leg with `tools/fulltest.sh <leg>`, and get
   the identical failure. Nothing is faster or more conclusive, and locally it
   costs a minute.
2. **A mechanical impossibility, stated concretely.** Not "unrelated" but
   *why*: e.g. "the ntapi **oracle** leg runs test binaries under Wine and
   executes no kernel code at all, and this branch changes only `kernel/`" —
   then account for anything the branch *did* add to that leg. A new
   `tests/ntapi` case changes worker sharding, so it can perturb *timing* even
   when it cannot perturb *semantics*; say which one the failure needs.

Known host-local failures, which still need their signature matched rather
than assumed: the `kernel32:version` oracle residue (Step 4), and the ntapi
oracle wedging on `io_teardown` (issue #118 — now bounded by the per-case
timeout, so it shows up as one named case, not a dead leg).

**Never merge on red when** the failing leg is one this diff is *about*
(`proskrnl`, `winetest`, `boot`, `frontier`), when the failure names a file,
test or subsystem the diff touches, when it is a real assertion rather than a
hang or an infrastructure error, or when you have suspicion but not one of the
two proofs above. Handing back an unmerged PR with a clear question is a good
outcome; merging a defect into `main` is not.

If a red IS proven pre-existing, file it (`gh issue list --state open` first —
do not duplicate) with the signature, the reproduction and the evidence, note
it on the PR so the merge is not silent in the history, and then merge.

Finally, report: the item, whether the pair is now in the gate, the residue
if not, anything the oracle refuted, and any unrelated defect you found on
the way (file it as a GitHub issue with its reproduction).
