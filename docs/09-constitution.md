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
(Cc), or import POSIX idioms. **Reject these.** The permitted exception, for GUI only, is a
*downgrade* of this rule, not a repeal: NT-absent things may be added **only as new devices
or new processes at the outside of the boundary** (e.g. `\Device\Fb0`, wineserver-lite),
never inside existing `Nt*` or Wine PE code. Every such addition is logged in
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
hours; the same bug found at M13 costs months and is un-triageable across four suspects.

## Article 6 — Only a differential test convicts

Sanitizers, asserts, and unit tests **name suspects**. Only a passing differential/
conformance test (against Windows or Wine) is a **conviction**. "The sanitizer went quiet"
is never a completion criterion. Do not accept a fix that silences a report without a test
proving the contract now holds.

## Article 7 — Additive and removable

Every feature outside the CUI core (all of GUI, WOW64, the optional ReactOS shell) must be
**subtractable** without touching the core. If deleting a feature's directories does not
restore the M10 kernel intact, the feature was built wrong. This is what makes hacks safe:
they are addition, never mutation.

## Article 8 — Fix the license before it fixes you

Fixed: the kernel is **GPL-2.0** (see `LICENSE`), settled well before M13 — before any
Wine/ReactOS-derived code could enter the kernel image under route (b), and before the
LLM-provenance risk materializes. The provenance discipline of `docs/11` (reference
material limited to Wine headers + MS docs, generated `abi/`, drivers from public specs)
applies unchanged.

## Article 9 — Debugging is infrastructure, built first

On the M1 day, build a **thick panic handler** (register dump, stack trace via forced frame
pointers, last syscall number) and structured, machine-greppable log prefixes. Under
LLM-driven development the panic dump *is* the debugger and the logs are the model's only
eyes. A cheap panic handler is the most expensive omission.

---

## The through-line

Every article is the same instinct applied to a different target: **avoid the dirty
boundary, take the clean one.** T1 avoids the driver ABI; T2 avoids win32k's temporal
protocol; Article 3 avoids the concurrency swamp; Article 4 avoids the model's unreliable
memory; T7 avoids the undocumented shell seam. The project succeeds exactly insofar as
these boundaries hold. Guard them.
