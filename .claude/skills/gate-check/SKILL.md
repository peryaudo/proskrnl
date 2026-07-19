---
name: gate-check
description: Review the current diff against proskrnl's constitution (docs/09-constitution.md) and the G1-G9 PR gates (docs/CONTRIBUTING.md), flagging boundary violations before commit. Use before committing kernel/abi/driver changes, or when the user asks to "check the gates" / "is this constitutional".
---

# gate-check

Review the working-tree diff for violations of proskrnl's hard gates. LLM contributors violate these by default, so be adversarial — assume a violation is present and try to find it.

## Steps

1. Get the diff: `git diff HEAD` (and `git diff --cached` if staged). If the user passed `$ARGUMENTS`, treat it as a path/ref to scope the review.
2. Read `docs/09-constitution.md` and `docs/CONTRIBUTING.md` for the current canonical wording — do not rely on memory of the gates.
3. Evaluate the diff against each gate below. For each, output **PASS** / **FAIL** / **N/A** with a one-line reason and `file:line` evidence.

## Gates

- **G1 — Boundary only.** Does it reproduce NT behavior *exactly* only at the observable boundary (`Nt*` semantics Wine uses; PEB/TEB/RTL_USER_PROCESS_PARAMETERS/KUSER_SHARED_DATA; NT file semantics)? Flag any Microsoft-compatible reproduction of *non-boundary* internals.
- **G2 — No NT-absent entities in core.** Anything NT lacks entering `kernel/`, `abi/`, `arch/`, `fs/`, or the `Nt*` surface? Watch for IRQL, a separate cache manager (`Cc`), DPCs, fine-grained locks, PnP/IRP, POSIX idioms. The only allowed NT-absent additions are new devices/processes at the *outside* of the boundary, and each must have a `docs/10-hacks-ledger.md` entry (see `/log-hack`).
- **G3 — Stupidly correct.** Any copy-on-write, page eviction / deferred writeback, multiple dispatcher locks, SMP/preemption assumptions, or Paged/NonPaged pool split? Each must be justified in `docs/03-nt-deviations.md` against user-observable semantics — never performance.
- **G4 — Generated contract.** Any hand-typed or model-recalled numeric constant in `abi/` (NTSTATUS, info-class numbers, struct offsets, flags)? These must come from `tools/gen_abi.py` over Wine headers, with `static_assert(offsetof(...) == ...)`. Flag magic numbers.
- **G5 — Test first.** Does new boundary behavior have a `tests/ntapi/` test that is green on Wine/Windows *preceding* the kernel code? Flag kernel behavior added without a prior test.
- **G6 — Conviction by differential test.** Is any fix justified only by "sanitizer/assert went quiet" rather than a passing differential/conformance test?
- **G7 — Additive & removable.** Is any out-of-core feature (GUI, WOW64, ROS shell) wired in such that deleting its directories would not restore the core intact?
- **G8 — Constants cite a trusted source.** Does the diff introduce a hand-typed numeric constant whose value is fixed by an external contract (hardware register numbers/bit positions, MSRs, on-disk format fields, NT magic addresses/limits) without a comment in the same file naming a trusted source to re-verify it against (pinned Wine tree path + symbol, official MS docs, vendor spec — Intel SDM / datasheet / virtio — or the pinned QEMU tree)? Where feasible, actually re-verify the value against the cited source (grep `third_party/wine` / `third_party/qemu`) rather than trusting the comment. Purely internal choices (pool bases, KASAN shadow, our own syscall numbers) are exempt — but check they are not silently load-bearing for an external contract.
- **G9 — Wine patched only at the unixlib seam.** Does the diff bump the `third_party/wine` submodule pin or touch Wine build glue? If so: inspect the submodule diff vs. the winehq base (`tools/hack_meter.sh`; the base is the fork's `master` branch, which a base bump fast-forwards in the same push that rebases `proskrnl-target`) — does any change alter PE-side observable behaviour rather than unixlib plumbing or build glue? **Dormancy (docs/06 "One tree, three roles"):** does any fork-commit hunk touch shared PE code *outside* a `!__wine_unix_call_dispatcher` guard? Does any change mutate a `server/` (or other) file that enters a binary the oracle executes, rather than adding a new file/build target? Does each commit header state its dormancy mechanism? Does any change exist to make a failing proskrnl differential test pass — i.e. does it edit the oracle instead of the kernel (cross-check Art. 6)? Is any Wine modification carried outside the fork (a patches directory, vendored diffs, build-time patching)? All Wine changes must be commits on the fork's `proskrnl-target` branch, each carrying the required header (what it changes / why the seam is the right place / upstream disposition: `upstreamable`, `proskrnl-only`, `temporary`-until-named-feature). Does the PR description report the old → new hack-meter line counts with a justification for any growth, and state that `tests/run/run.sh oracle` was re-run green against the new pin (the dormancy proof)?

## Provenance (also fail-worthy — see docs/11-licensing.md)

- GPL-source translation into kernel/drivers (drivers must come from public specs).
- Kernel reference material other than Wine headers + official MS docs (no ReactOS/leaked source/model memory).
- Missing `docs/provenance.md` entry for a new borrowed component.

## Output

End with a verdict: **READY** (all applicable gates pass) or **BLOCKED** (list the failing gates). Be concrete and cite lines; do not soften a real violation.
