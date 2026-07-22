# 09 — The Constitution

These are **hard rules**, not guidance. They exist because the difficulty of this project
is not writing code — it is *not eroding the boundary that makes it tractable*. A human or
an LLM will, by default and with good intentions, violate every one of these. Read this
before writing a line. When a rule and a convenience conflict, the rule wins.

---

## Article 1 — The boundary is sacred

**Reproduce exactly** the observable boundary: the `Nt*` semantics Wine uses, the
`PEB`/`TEB`/`RTL_USER_PROCESS_PARAMETERS`/`KUSER_SHARED_DATA` layouts, and NT file
semantics. **Change nothing else in Microsoft-compatible form.** If a behaviour is not
observable from an unprivileged `.exe`, it is not part of the boundary and you are free.

## Article 2 — Do not grow NT-absent entities in the core

Never add to `kernel/`, `abi/`, `arch/`, `fs/`, or the existing `Nt*` surface anything NT
does not have. The LLM is trained on Linux and will, unprompted, add IRQL, split the cache
(Cc), or import POSIX idioms. **Reject these.** The permitted exception, for the
interactive console (M9) and GUI only, is a *downgrade* of this rule, not a repeal:
NT-absent things may be added **only as new devices or new processes at the outside of the
boundary** (e.g. the serial console backend, `\Device\Fb0`, wineserver-lite), never inside
existing `Nt*` or Wine PE code. Every such addition is logged in
`docs/10-hacks-ledger.md`.

## Article 3 — Stupidly correct before anything else

The following are **mandates**, not choices, for the initial implementation:

- **No copy-on-write.** Private/image mappings copy fully on map.
- **No eviction. Immediate writeback.** The page cache never pages out.
- **One dispatcher lock. Uniprocessor. No kernel preemption.** Context switches occur only
  at explicit waits and at user-mode return.
- **One pool.** No Paged/NonPaged split.

Rationale: every hard bug in Mm/Ke is a *concurrency or optimization* bug, and every one of
those is unobservable from user mode — i.e. not a contract. Removing them removes ~90% of
the difficulty and, crucially, makes the un-reviewable code un-buggy. **A bug that cannot
exist needs no review.** Optimizations (COW, eviction, SMP) are added later, behind the
same tests, only if genuinely needed — which for a CUI-in-a-VM target is doubtful.

Any deviation from Article 3 must be recorded in `docs/03-nt-deviations.md` and justified
against user-observable semantics — never against performance.

## Article 4 — Generate the contract; never recall it

Every numeric value in `abi/` (NTSTATUS, info-class numbers, structure offsets, flags) is
**generated from Wine's headers** via `tools/gen_abi.py`. **No hand-typed constants. No
values from an LLM's memory.** The model's plausible-but-approximate constants are more
dangerous than wrong ones because they hide. Structure layouts carry
`static_assert(offsetof(...) == ...)` so a mismatch fails at compile time.

The same instinct applies **outside `abi/`**, where constants cannot be generated but can
be cited. Any hand-typed constant whose value is fixed by an external contract — hardware
register numbers and bit layouts (x86_64 MSRs, LAPIC, page tables, UART, PIT, virtio…),
on-disk formats (PE/COFF, FAT32), NT magic addresses and limits — must be
**cross-checked against a trusted source at introduction time, and that source named in a
comment in the same file** so a reader can re-verify the value without trusting the
author. Trusted sources are: the pinned Wine tree (`third_party/wine`, path + symbol),
official Microsoft documentation, the vendor specification (Intel SDM section, device
datasheet, the virtio spec), or the pinned QEMU tree (`third_party/qemu`, the device
model we actually run against) as a runtime cross-check. A bare number recalled from
model memory is a violation **even when it happens to be right** — an uncited constant is
indistinguishable from a hallucinated one.

## Article 5 — Tests precede kernel code

For any boundary behaviour, a `tests/ntapi/` test that is **green on the Wine/Windows
oracle** exists *before* the kernel implements it. "Done" is defined by that test passing on
proskrnl, not by the code compiling. This is a per-milestone discipline, not an upfront
phase: each milestone adds only the cases for the `Nt*` it implements, and the proskrnl run
is gated by a `todo_proskrnl` manifest so it stays green-or-regression (see `docs/08`).
Contract-shaped behaviour (event/IOSB ordering, wait semantics, share modes) *must* be
tested first, or the implementation certifies its own bug. Semantic bugs caught in M3 cost
hours; the same bug found at GUI-3 costs months and is un-triageable across four suspects.

## Article 6 — Only a differential test convicts

Sanitizers, asserts, and unit tests **name suspects**. Only a passing differential/
conformance test (against Windows or Wine) is a **conviction**. "The sanitizer went quiet"
is never a completion criterion. Do not accept a fix that silences a report without a test
proving the contract now holds.

**Wine is the operative oracle; a divergence from Wine is a proskrnl bug, full stop.**
Wine is "approximate" only relative to real Windows — but proskrnl's boundary consumer is
not real Windows, it is **Wine's own PE user-mode stack**, which was written against, and
continuously tested against, exactly the behaviour Wine's ntdll observes. Matching Wine at
the boundary is therefore the definition of correct for this project; if Wine and real
Windows ever disagree, that is Wine's upstream bug to fix on Wine's schedule, and proskrnl
tracks Wine (the pinned `third_party/wine`) either way. So there is no "maybe real Windows
differs" escape hatch for leaving a divergence open: do not spend time re-verifying Wine
against Windows before accepting a divergence as a bug, and never park a divergence as
"awaiting real-Windows triage". Real Windows remains useful the other way around — as a
*third* triangulation point when Wine's own behaviour is unstable across versions — but a
tie between proskrnl and Wine is always broken in Wine's favour.

## Article 7 — Additive and removable

Every feature outside the CUI core (all of GUI, WOW64, the optional ReactOS shell) must be
**subtractable** without touching the core. If deleting a feature's directories does not
restore the M10 kernel intact, the feature was built wrong. This is what makes hacks safe:
they are addition, never mutation.

## Article 8 — Fix the license before it fixes you

Fixed: the kernel is **GPL-2.0** (see `LICENSE`), settled well before GUI-3 — before any
Wine/ReactOS-derived code could enter the kernel image under route (b), and before the
LLM-provenance risk materializes. The provenance discipline of `docs/11` (reference
material limited to Wine headers + MS docs, generated `abi/`, drivers from public specs)
applies unchanged.

## Article 9 — Debugging is infrastructure, built first

On the M1 day, build a **thick panic handler** (register dump, stack trace via forced frame
pointers, last syscall number) and structured, machine-greppable log prefixes. Under
LLM-driven development the panic dump *is* the debugger and the logs are the model's only
eyes. A cheap panic handler is the most expensive omission.

## Article 10 — Wine is patched only at the unixlib seam

Modifying Wine is permitted for exactly one thing: replacing the **unixlib side** — the
host-facing plumbing under each PE DLL — with syscall stubs into proskrnl, plus the build
glue the partial build needs (`docs/06`). The PE side's observable behaviour is **never**
patched. Concretely:

- **All Wine modifications are commits on the fork — there is no patches directory.**
  Every change is committed to the fork's `proskrnl-target` branch and pinned by the
  `third_party/wine` submodule; the pin is the whole truth. No vendored diffs, no
  build-time patching, no `patches/` anywhere in the superproject: the submodule diff
  against the winehq merge-base is the complete, reviewable record of every deviation
  from upstream Wine.
- **Never patch Wine to mask a kernel divergence.** Art. 6 makes a divergence from Wine a
  proskrnl bug, full stop. A patch that changes what Wine's PE code does so that proskrnl
  passes is fixing the *oracle* instead of the kernel — the one edit that silently
  invalidates the entire verification story. Fix the kernel.
- **NT-absent additions stay out of Wine PE code** (Art. 2). GUI-route additions are *new,
  removable files* (e.g. `winefb.drv`), governed by Arts. 2 and 7 — additions, never
  mutations of existing Wine code.
- **Every fork commit is dormant under regular Wine.** The pinned tree is simultaneously
  the oracle, the shipped-userland source, and the `abi/` contract source (`docs/06` "One
  tree, three roles"), so a seam change must be invisible when a unixlib is present:
  either runtime-dormant (behind `!__wine_unix_call_dispatcher` — the sanctioned pattern)
  or additive-by-construction (a new file / new build target the oracle never executes;
  wineserver-lite is a new target, never an in-place stripping of `server/`). The
  compile-time `PROSKRNL_TARGET` hatch (`docs/06`) may be enacted only together with the
  split-build amendment there. A green `tests/run/run.sh oracle` on the new pin is
  required evidence for every pin bump — the oracle running the patched tree IS the
  dormancy check.
- **Each modification is one logical commit** on `proskrnl-target` whose message states
  what it changes, why the unixlib seam (and not the kernel) is the right place, and its
  upstream disposition: `upstreamable` (generic enough for winehq), `proskrnl-only`
  (permanently tied to our transport), or `temporary` (until a named kernel feature
  lands — then it is deleted).
- **The minimal-diff principle is enforced in review (the hack meter).** The hack meter
  is the line count of the submodule diff between the pinned commit and its winehq
  merge-base. A PR that bumps the pin states the old and new meter and justifies any
  growth; unjustified growth is rejected, exactly like an uncited constant.
- **On a Wine base bump**, `proskrnl-target` is rebased onto the new winehq base with
  each commit's justification re-checked; one that no longer applies is re-derived from
  its message's rationale, never force-merged blind.

Licensing: the fork is derivative of Wine (LGPL) and its DLLs run in user mode, on the
far side of the process boundary; nothing from it enters the kernel image (Art. 8,
`docs/11`).

## Article 11 — One authority: engines, identities, lifetimes

The executive's shared mechanisms exist exactly once, and every consumer goes through
them. Three concrete forms, each learned from a shipped bug:

- **No parallel engines.** An operation a shared engine already performs — name
  resolution and the create/open access checks (Ob), handle allocation (Ob), identity
  minting (Ps) — is never reimplemented by a second code path, even a specialized one. A
  parallel path is a defect *even while its behaviour is identical*, because two
  implementations of one rule drift apart silently: Cm's private name-resolution walked
  past the zero-access refusal Ob's open engine already enforced, and the divergence was
  invisible until the fuzzer sampled it (`a53dd04`). Extend the engine (a parse hook, a
  flag) rather than bypassing it.
- **One source of truth per identity value.** Every identity value — thread and process
  ids, cookies, handle values, any number with a contract meaning — has exactly one
  allocation site and one authoritative home; every other appearance is a copy taken
  from the authority at a defined point. Two independent writers of "the same" value is
  the split-brain shape that gave a thread a TEB id its own ETHREAD disagreed with
  (`4fc732c`).
- **Lifetimes are held by named references.** For every kernel object, "who keeps this
  alive right now" has an explicit answer at every point in its life — including against
  the earliest legal handle close and against the owning thread exiting first. An object
  reachable by running code must be pinned by a reference that running code cannot lose:
  a live thread's ETHREAD was once deleted out from under it by the first caller that
  closed its handles promptly (`edf9f0b`).

These rules are cheap at introduction time and nearly unenforceable after the fact — a
second engine or a second writer looks locally correct in every later diff, and both
departments stay self-consistent while disagreeing with each other. Gates G10 and G11
therefore check for them at review time, per diff.

## Article 12 — Unbuilt behaviour refuses loudly

Every not-yet-implemented service, info class, ioctl/fsctl verb, or glue stand-in
**refuses loudly**: a distinct failure status (`STATUS_NOT_IMPLEMENTED`, or the refusal
the oracle itself shapes for the case) plus a serial line naming what was asked for —
the `KI_SYSCALL_MISSING` pattern, which is why the M7 bring-up could see exactly which
`Nt*` an unmodified ntdll wanted next. **Never fabricate a plausible answer to let
callers proceed.** The project's bug history is unambiguous on this: every loud stub
surfaced instantly and harmlessly, while every stub that answered something plausible
became a deferred bug that a later milestone paid for —

- `NtResumeThread` as a silent success no-op made CreateProcess impossible (`1d6dafd`);
- `ThreadBasicInformation` always described the caller and reported `STILL_ACTIVE`
  forever (`7cd6189`);
- `ProcessBasicInformation.ExitStatus` hardwired `STATUS_PENDING` (`87bb03e`);
- the M7 alert-by-tid accept-and-timeout fakes turned the first contended heap lock into
  a busy spin (`4fc732c`);
- conhost's `VkKeyScanW` stand-in returning −1 inserted a literal `^M` instead of ending
  the line (`15e72d8`);
- `FileFsDeviceInformation` hardwired `FILE_DEVICE_DISK` for every device (`3ce0031`).

The test is observability: if a caller could not distinguish the stub from a real
implementation except by things going wrong later, the stub is a planted bug. A loud
refusal is distinguishable immediately, at the exact point of first contact, and turns
the missing feature into a visible work item instead of a latent divergence.

One carve-out, sharply bounded: a **fixed answer that is the pinned oracle behaviour is
an implementation, not a stub** — Wine itself answers `NtQueryTimerResolution` with a
fixed triple, and matching that is correct. The distinction is provenance: a fixed value
is legitimate only when it is pinned by a `tests/ntapi/` case green on the oracle
(Art. 5) or recorded in `docs/03-nt-deviations.md` — a value *invented so callers keep
going* is a violation regardless of how reasonable it looks.

---

## The through-line

Every article is the same instinct applied to a different target: **avoid the dirty
boundary, take the clean one.** T1 avoids the driver ABI; T2 avoids win32k's temporal
protocol; Article 3 avoids the concurrency swamp; Article 4 avoids the model's unreliable
memory; T7 avoids the undocumented shell seam; Article 10 avoids quietly reshaping the
oracle to fit the kernel; Article 11 avoids the second implementation that drifts;
Article 12 avoids the plausible answer that defers the bug. The project succeeds exactly
insofar as these boundaries hold. Guard them.
