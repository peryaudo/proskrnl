---
name: fix-winetest
description: Take ONE `# TODO: Implement` work item from either winetest manifest — CUI (tests/winetest/manifest.txt, run.sh winetest) or GUI (tests/winetest/manifest-gui.txt, run.sh winetest-gui) — pin it against the oracle, implement it, re-measure, un-park the pair if it went green, then gate-check, prove it with `make fulltest`, and rebase-merge to main. The goal is PROGRESS toward every winetest passing — a change that clears assertions but leaves the pair red, or that reveals a wedge or a past false green, still lands. Refuses when no unparkable item is left. Invoke manually with /fix-winetest; never triggered automatically.
argument-hint: [pair-or-W-item]
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Skill, WebFetch, TaskCreate, TaskUpdate, TaskList
---

# fix-winetest

Close **one** entry on the winetest frontier, end to end: pick it, pin it,
build it, prove it, land it. **Either frontier** — the CUI manifest
(`tests/winetest/manifest.txt`, leg `winetest`) or the GUI one
(`manifest-gui.txt`, leg `winetest-gui`). They are one workflow with two
manifests and two legs; every step below says which it means when it matters,
and the differences are collected under "The two frontiers" just after this.

You run this yourself, in the main conversation — do **not** hand it to a
subagent. `$ARGUMENTS`, if present, names the pair (`ntdll:virtual`,
`user32:win`) or the docs/21 item (`W8`) to work; otherwise you choose. Work
**one** item.
Finishing one item properly beats starting three.

## The two frontiers

Same grammar, same graders, same rules. Below: the differences that change
what you type, then the one that changes what you may conclude.

| | CUI — `manifest.txt` | GUI — `manifest-gui.txt` |
|---|---|---|
| leg | `tests/run/run.sh winetest [pair...]` | `tests/run/run.sh winetest-gui [pair...]` |
| machine | `Gui=0` boot (audio pairs get their own `Gui=1` boot with virtio-snd) | `Gui=1` boot: win32u, wineserver-lite, winefb, a desktop |
| modules | ntdll, kernel32, msvcrt, ucrtbase, cmd, ws2_32, mmdevapi, winmm | user32, plus the CUI-module pairs whose subject NEEDS a desktop (`ntdll:om`, `ntdll:rtl`, `kernel32:toolhelp`) |
| serial log | `build/tests/wtest-subset-serial.log` | `build/tests/winetest-gui-subset-serial.log`, plus `winetest-gui-subset-msg.log` — the assertion text replayed through `tools/unscreen.py`, because this leg's console is an 80-column screen diff that mangles it (the `-msg` name is historical: it holds whichever pairs the run selected) |
| budgets | every active pair is 0 (green or parked) | `user32:msg` carries a budget; everything else is 0 |

Both manifests speak `<exe>:<subtest>[:<budget>][:<timeout_s>]`, both legs
grade through the same `wtest_grade`, and both demand the ORACLE half green —
a budget is a ceiling over OUR divergences, and on unmodified Wine nothing is
ours. `tools/check_wtest_manifests.py` (via `make gen-check`) keeps both files
exhaustive over the pin, so a pair you delete instead of parking is a gate
failure, not a silent hole.

**The GUI leg is slower and its subset filter is what makes it workable.**
Unfiltered it runs `user32:msg`, an hour under TCG. Always name your pair
(`run.sh winetest-gui user32:win`) while iterating; the unfiltered run is for
the verdict, and `make fulltest` takes it anyway.

**On the GUI frontier, a failure is only yours once the desktop is ruled
out.** These pairs run above win32u, wineserver-lite and winefb, so an
assertion can fail for a compositor or message-path reason that is not an
`Nt*` divergence at all. Two habits follow: read `winetest-gui-subset-msg.log`
by SITE (cluster the failures by `<subtest>.c:NNNN`) before believing any
single one, and check whether the same assertion fails on the ORACLE half — that
half runs the same PE binaries over winex11.drv, so a divergence between the
two halves is localized to the display seam by construction, and one that
fails on BOTH is Wine's or the suite's, never the kernel's (Art. 6).

## The goal is PROGRESS toward every winetest passing, not a green pair today

Read this before Step 5 talks you out of landing something.

The frontier is closed by many items over many sessions. A single item almost
never turns a pair green, and **that is not the bar**. The bar is:

1. the pin is **oracle-green**, and
2. the pin is **proskrnl-green with the implementation**, and
3. something **measurably improved** — assertions cleared, a panic removed, a
   cause eliminated, a false record corrected, and
4. `make fulltest` is clean.

Meet those four and **land it**. Do not invent a fifth.

**Progress routinely looks like regress, and you must land it anyway.** Every
one of these is a real, repeated outcome, not a hypothetical:

- **A panic becomes many failing assertions.** The panic was hiding them; the
  count going 0 → 1199 is the pair being *measured for the first time*
  (`docs/21` §4 trap 2, paid for by W5). Land it.
- **A fix reveals a WEDGE.** Zero failed assertions and a timeout is the same
  `FAIL` as five-and-a-timeout, so the pair's verdict does not move — but the
  assertions really are fixed and the next item starts from there. Land it,
  and record the wedge as the next item.
- **A fix reveals a past FALSE GREEN.** An assertion that only passed because
  an earlier stop never reached it, or a count that was only low because the
  log was read wrong. Correcting the record *is* the deliverable. Land it.
- **The count goes UP because a wrong suppression is removed.** Removing
  something that was accidentally hiding failures is an improvement even
  though the number worsens. Land it, and say why the number moved.

**The one thing that is never acceptable is a change you cannot justify by
the four criteria above** — and "the pair's verdict did not flip" is not a
disqualification. A session was lost to exactly this: an implementation that
took a pair's last five assertions to zero was written, measured, and then
REVERTED because the pair still timed out. That reverted a good change,
briefly left the pin red on the proskrnl leg (a pin without its
implementation is a broken gate, not a cautious one), and had to be redone.
**A pin and its implementation land together or not at all.**

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

**docs/21 plans the CUI frontier only.** Its W-items are CUI pairs, and the
GUI frontier has no equivalent document: for a GUI item the manifest block IS
the plan, and §4's traps still apply because they are about measuring, not
about which manifest. Do not invent a W-number for a GUI item; if the work
turns out to deserve a written plan, say so in the report and let the user
decide whether docs/21 grows a GUI half. For the GUI machine itself, read
`docs/03` "GUI-5 winetest notes" — it is where that leg's policy lives.

Also honour `CLAUDE.local.md` for the `make -j` flag on this machine.

**One instance at a time.** Test legs bake disk images from the *live working
tree*, so a checkout, stash or edit while a leg is running corrupts that
leg's image. `make fulltest` does not change this — its sandboxes symlink the
sources, so an edit mid-run reaches every leg at once. Never mutate the tree
while `run.sh`, `make test` or `make fulltest` is in flight, and do not run two
of these skills concurrently.

## Step 1 — Pick an item, or REFUSE

List what is unparkable, **in both manifests**. An item is unparkable iff its
block ends with `# TODO: Implement` — that marker is the manifest's own
statement that the pair is red for a *kernel* reason (category 1). Blocks
without it are category 2: not reachable without reversing a recorded
decision.

```sh
for m in tests/winetest/manifest.txt tests/winetest/manifest-gui.txt; do
  echo "== $m"
  grep -A1 '^# TODO: Implement$' "$m" \
    | grep -E '^# [a-z0-9_.]+\.exe:' | sed 's/^# //'
done
```

**If BOTH print nothing, STOP and refuse.** Say that neither winetest frontier
has an unparkable item left, that every remaining commented-out pair is
category 2 (name a couple with their deciding constraint), and that re-parking
one of those needs a human decision to reverse the constraint, not an
implementation. Do not invent work, do not widen a manifest, and do not pick a
category-2 pair "because it looks fixable". Exit.

If only one manifest prints items, work that one and say so. The GUI list's
`user32` blocks are UNMEASURED — they say so — so picking one means Step 2 is
the whole first half of the job rather than a confirmation; that is expected,
and writing the first real measurement into the block is itself a deliverable
worth landing.

Otherwise choose one, honouring `$ARGUMENTS` when given. Cross-reference
docs/21's W-items for the planned approach and the article risks; prefer an
item docs/21 has already scoped. Avoid what docs/21 §4 names as traps.

## Step 2 — MEASURE the pair before you believe its block

The manifest's counts are re-measured whenever a pair is touched, but a pair
that **stops** — panics, or is killed by a fault — has not been measured at
all past the stop. Its recorded count is a **lower bound**, and reading one
as "nearly green" is how an hour-long item gets scheduled as a one-liner.
docs/21 §4 records this trap because it was paid for.

Temporarily un-comment the pair — a parked pair is not in the active list, so
neither leg's filter can select it — and measure it on ITS leg:

```sh
tests/run/run.sh winetest     <module>:<subtest>   # CUI: both halves
tests/run/run.sh winetest-gui <module>:<subtest>   # GUI: both halves
```

Then read that leg's serial log and count failures per source line so you know
the real clusters and their sizes:

- CUI — `build/tests/wtest-subset-serial.log`, stripping ANSI escapes.
- GUI — `build/tests/winetest-gui-subset-msg.log`, which is already the
  assertion text (`tools/unscreen.py` replays it out of the console screen
  diff; grepping the raw serial log finds it shredded into fragments). The
  `[KTEST]` VERDICT still comes from `winetest-gui-subset-serial.log`.

If the ORACLE half is red, the pair cannot convict the kernel (Art. 6):
re-park it with that finding and pick another item. On the GUI frontier check
this first and read it carefully — an oracle-red assertion there is Wine's or
the suite's, and chasing it in `kernel/` is the trap that frontier has that
the CUI one does not.

**Put the pair back the way you found it before you go on.** A measurement run
leaves the manifest edited; if you now decide to work something else, or the
oracle refutes the item, restore the comment in the same breath — an
accidentally-activated red pair fails the gate for everyone.

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
make -j<N>                                   # per CLAUDE.local.md
tests/run/run.sh proskrnl <name>             # the new pin, on the kernel
tests/run/run.sh winetest <module>:<subtest> # re-measure the pair — or
tests/run/run.sh winetest-gui <module>:<subtest>   # ...its leg, if it is a GUI pair
make format                                  # REWRITES source — so, before the verdict
make fulltest                                # THE verdict — every leg CI runs, ~3 min
```

The first three are ITERATION: a subset run is never a verdict. `make fulltest`
(`tools/fulltest.sh`, docs/08) is — it runs the same 26 legs
`.github/workflows/test.yml` runs, sandboxed one per leg and fanned out over
this box: the unfiltered oracle and proskrnl legs, the whole CUI winetest
sweep, `make test`, the fuzzer, the FAT batteries, every CUI and GUI leg, and
the `winetest-gui` leg — which is where an unfiltered GUI verdict comes from,
including the `user32:msg` budget ratchet, and which is the floor of the
suite's wall clock at ~2 minutes. It prints a PASS/FAIL table
and exits non-zero if any leg is red; read the table, not the exit code alone.

`format` runs *before* it, never after: it rewrites source in place, and a verdict
taken on a tree that then changed is not a verdict on what you push (Step 8,
precondition 2). Same rule for any other edit — re-run rather than reason about
whether it mattered.

**A red leg is yours until proven otherwise, and there is no longer a
standing exception.** `make fulltest` should be **26/26**. The one residue
this skill used to tell you to accept — the `winetest` leg going red on the
ORACLE half of `kernel32:version`, host-local to a KVM developer box — is
now PARKED in the manifest rather than tolerated, so the leg does not run it
at all. If you see that pair again, someone un-parked it; read its block
before deciding anything.

Treat every red leg as a stop. A suite with a permanently-accepted red is a
suite people stop reading, which is exactly how a real failure gets skimmed
past — the same argument the manifest header makes for never activating a
red pair. If you find a NEW host-local residue, do what was done for
`kernel32:version`: park it with its signature written down and a sentence
saying what would un-park it. Do not add a second standing exception here.

## Step 5 — Un-park only if it is actually green (but LAND it either way)

**Un-parking is about the manifest, not about whether to commit.** The change
lands on the four criteria at the top of this file; this step only decides
whether the pair joins the active gate.

- **Green on both halves** → un-comment the pair, in the manifest it lives in.
  It is now part of that leg's gate.
- **Still red** → leave it commented out and **rewrite its triage block**
  with the numbers you just measured: total failures, the dominant clusters
  with counts and source lines, and what each one actually is. Keep
  `# TODO: Implement`. **Commit the kernel change anyway** — it met the bar.

**Do not reach for a budget to activate a red pair.** The grammar lets any
pair carry one, and exactly one does: `user32:msg`, whose remaining failures
are named one by one, attributed to a family, and ratcheted down commit by
commit — read its block to see the standard. A budget is a ceiling over
divergences you have TRIAGED, never a way to make a count you have not
explained stop failing the leg; that is what parking is for. If you believe a
pair genuinely needs one, that is a decision to put to the user with the
measured breakdown, not a number to write while landing an item.

Never activate a red pair. The active list is a pass/fail signal, and a
permanently-red entry teaches the next person to ignore the gate — the
manifest header says so.

**Write the number honestly, including when it got worse.** The block is the
next person's yardstick, so a count that moved for a reason other than
"fewer bugs" has to say so in the same breath:

- a panic removed and a four-figure count appearing → say the pair was never
  measured past the stop, and that the new number is the first real one;
- a wedge appearing behind cleared assertions → say the verdict did not move
  and why, so nobody reads `FAIL (timeout)` as "the work did nothing";
- a count going UP because a wrong suppression was removed → say which
  suppression, so the increase is not mistaken for a regression;
- a count that was simply wrong before → say how it was got wrong. "The
  count was read by grepping `Test failed` without reading the verdict line
  beside it" is worth more to the next reader than the corrected number.

**Never let the block claim more than the run showed.** Read the `[KTEST]`
verdict line, not just the assertion count — a pair can end `FAIL (timeout)`
with zero failed assertions, and reporting that as "reaches its summary line"
is a false green of your own making.

Update `docs/21` for the item: mark it DONE, or record what it turned out to
be. **If the measurement contradicts something docs/21 asserts, fix the
assertion and say why it was wrong** — that correction is often worth more
than the code. (A GUI item has no W-number to mark; its record is the manifest
block you just rewrote, plus a `docs/03` "GUI-5 winetest notes" line when the
finding is about the leg or the GUI stack rather than about one pair.)

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
3. `tests/winetest+docs/21: <bookkeeping>` — the manifest (whichever of the
   two the pair lives in) and docs/21.

No WIP or fixup commits. Squash and reorder locally first.

## Step 8 — PR and merge; the local suite is the gate, not CI

Push a feature branch and open a PR whose body states: what landed, whether
the pair went green (and if not, the measured residue), what the oracle
refuted, and the verification you ran — quote the `make fulltest` summary
line, and name the host-local exception if you accepted one.

Then merge. **Do not wait for CI.** CI runs the same 26 legs `make fulltest`
just ran; waiting adds half an hour and no information. Merge only with all
three of these true:

1. `make fulltest` green — all 26 legs. There is no tolerated residue any
   more (Step 4); a red leg is a stop;
2. the commits are exactly the tree you tested, and `git status --porcelain` is
   empty. fulltest judges the WORKING tree and CI judges the COMMITTED one, so
   an unadded file is green in all 26 legs and red on CI — and any edit after
   the run, including a "trivial" comment fix, invalidates it. Re-run rather
   than reason about whether it mattered;
3. `make format` clean and the Step 6 gate-check resolved.

### How to actually merge — `gh pr merge` is not the only door

Try `gh pr merge <n> --rebase` first; it is the tidiest. **But it is often
refused** (the harness's permission classifier blocks it, or the token lacks
the scope), and a refusal there is NOT a reason to leave the work unmerged.
**You have push access to `origin/main`.** Rebase-merge it yourself:

```sh
git fetch origin
git checkout -B merge-stack origin/<your-branch>
git rebase --onto origin/main <merge-base>   # replay onto current main
git diff --stat origin/<your-branch> merge-stack   # MUST be empty
git push origin merge-stack:main
```

Three things this sequence is doing, none of them optional:

- **`--onto origin/main <merge-base>` rather than a plain rebase**, because
  `main` may already carry REBASED copies of commits your branch still has
  under their original hashes (that is what a previous rebase-merge leaves
  behind). Pass the old tip of the already-merged part as `<merge-base>` so
  those duplicates are dropped instead of replayed as conflicts.
- **The empty `git diff` is the whole safety argument.** A rebase writes new
  commits, so CI's verdict does not automatically transfer to them. An
  identical tree is what carries it across. If that diff is non-empty, STOP —
  something in the replay changed content and you no longer have a tested
  tree.
- **`git push origin merge-stack:main`**, never a merge commit. `main` is
  linear.

Afterwards, GitHub will **not** auto-close the PRs — the rebase rewrote the
hashes, so it cannot see its own commits landing. Close each one with a
comment naming the pushed range and the identical-tree check, so the history
does not look like the PR was abandoned.

**Stacked branches merge as a stack.** If several items are in flight, the
last branch already contains all the earlier ones; rebasing and pushing that
one lands them all at once. Then rebase any still-open branch onto the new
`main` (`--onto origin/main <old-base-tip>`), force-push it with
`--force-with-lease`, and retarget its PR base with `gh pr edit <n> --base
main` — otherwise its diff shows every already-merged commit and CI runs
against the wrong base.

**Only merge branches whose CI is green** when you go this route, and check
it per branch (`gh pr checks <n>`), because you are bypassing the mechanism
that would have enforced it.

What skipping the wait costs, honestly: CI is a slower machine (two cores,
TCG, virgin cache), so the failures it can see that fulltest cannot are the
ones settled by machine SPEED rather than by semantics — which is why the
`msg` shard (the `winetest-gui` leg) is advisory on PRs there and blocking on
main (docs/03 "GUI-5 winetest notes"). If your item IS on the GUI frontier,
that advisory status is not cover: the leg you just changed is the one whose
CI verdict you are choosing not to wait for, so quote your local
`winetest-gui` numbers in the PR and watch main's run after the merge.
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

One known flake, and it is a flake rather than a residue: `sem_ps/times`, a
timing assertion that can trip on a loaded box and clears on a re-run.
Matching its signature is what lets you RE-RUN; it is not what lets you
merge on red.

(The ntapi oracle's `io_teardown` wedge, issue #118, is fixed and no longer
belongs on any list here. If a leg wedges, it is new.)

**Never merge on red when** the failing leg is one this diff is *about*
(`proskrnl`, `winetest`, `winetest-gui`, `boot`, `frontier`), when the failure names a file,
test or subsystem the diff touches, when it is a real assertion rather than a
hang or an infrastructure error, or when you have suspicion but not one of the
two proofs above. Handing back an unmerged PR with a clear question is a good
outcome; merging a defect into `main` is not.

If a red IS proven pre-existing, file it (`gh issue list --state open` first —
do not duplicate) with the signature, the reproduction and the evidence, note
it on the PR so the merge is not silent in the history, and then merge.

Finally, report: the item, **what moved and in which direction** (assertions
cleared, a panic removed, a wedge or a false green revealed — and if a count
went UP, why), whether the pair is now in the gate, the residue if not,
anything the oracle refuted, whether the merge landed and by which route,
and any unrelated defect you found on the way (file it as a GitHub issue
with its reproduction).

A run that cleared assertions without turning a pair green is a **success**,
and should be reported as one. The frontier closes by many such runs.
