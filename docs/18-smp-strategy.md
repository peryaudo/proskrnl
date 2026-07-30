# 18 — SMP Strategy (giant lock), and the I/O-overlap prerequisite

**Nothing in this document is built.** Article 3 mandates "one dispatcher lock,
**uniprocessor**, no kernel preemption" (`docs/09-constitution.md`, T4 in
`docs/01-tradeoffs.md`). This document records the design we would use if that mandate is
amended, why a **giant lock** is the minimal and constitutionally coherent form of the
amendment, what it does *not* buy, the hard prerequisite it has, and — most importantly —
how the project's verification model survives.

Companion documents: **`docs/19-io-strategy.md`** — the block-layer I/O-overlap work, a
hard prerequisite for this one (§7) and an independent prerequisite for Net-1, and
therefore the first of the three to build; and `docs/17-cow-strategy.md` (§11 there, §6b
here: write-protect becomes a shootdown site).

---

## 1. Why this document exists

Measured against **xv6** — a teaching kernel — proskrnl is behind on five machine-level
axes:

| | xv6 | proskrnl today |
|---|---|---|
| SMP | multi-core, real spinlocks, per-CPU state | uniprocessor |
| other threads run during I/O | sleeps on the disk interrupt | **spins**; the machine stops (§7) |
| devices | interrupt-driven | polled throughout (`drivers/virtio/pci.c`: "a polling driver needs none of them") |
| FS crash consistency | write-ahead log + recovery | none; write-through, non-atomic rename (`docs/03` CUI-5) |
| kernel preemption | yes | no; one preemption point at return to ring 3 (`kernel/ke/sched.c:216`, CUI-4) |

Against the `Nt*` boundary — namespace, dispatcher objects, sections, registry, tokens,
completion protocol, SEH dispatch — proskrnl is an order of magnitude beyond xv6. The
asymmetry is deliberate and follows one criterion consistently: **is it observable from
ring 3?** Everything observable is built exactly; everything unobservable is not built at
all.

Two of the five rows above show that criterion leaking, and both are worth recording:

- **FS crash consistency is not a performance property.** A torn rename is observable
  after a reboot. It is documented as a deviation (`docs/03` CUI-5 notes, bounded by the
  fatstress/tornwrite fsck oracle), but it is not covered by "unobservable". **A
  journalling strategy is out of scope for this document** and would need its own.
- **Slowness has already cost us test verdicts.** The GUI-5 notes record that up to
  twelve remaining `user32:msg` failures are "decided by how slow TCG is rather than by
  any semantics of ours". A property that stops a suite from reaching a verdict is a
  verification problem, not a performance problem — see §9.

## 2. The starting point, measured

The single most important fact about adding SMP here:

```c
/* kernel/ke/sched.c:32 */
uint64_t KiAcquireDispatcherLock(void)
{ __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) : : "memory"); return flags; }
```

**The "dispatcher lock" is not a lock. It is interrupt disable.** On more than one CPU it
provides nothing. And the state it nominally protects is, elsewhere, protected by nothing
at all:

- `ObfReferenceObject` is a plain `header->pointerCount++` (`kernel/ob/object.c:32`) — not
  atomic.
- `kernel/mm/pool.c` contains **no lock of any kind**.
- `fs/fat32/` contains none either, and says why: *"a pure memory sweep: no blocking, so
  it is atomic **under the no-preemption model**"* (`fs/fat32/fat.c:676`).
- `KeGetCurrentThread()` is `return KiCurrentThread;` (`kernel/ke/sched.c:72`) — a global,
  not per-CPU.
- 55 `KiAcquireDispatcherLock` call sites; 21 `KiIsDispatcherLockHeld` assertions.

**Concurrency in this kernel is not a design that needs extending; it is an absence that
is currently sound.** Its soundness rests on exactly one sentence: *only one thread is
inside the kernel at a time, and it cannot be interrupted out of a state transition.*

## 3. Why not fine-grained locking

Preserving that sentence is the whole game. Fine-grained locking discards it and requires
re-deriving, per subsystem, who protects what — across `kernel/` (27 kloc), `fs/` (4
kloc) and `drivers/`, in a tree whose shared-state mutations are mostly *unlocked by
design*. That is an M7-sized effort plus a **permanent tax on every future commit**, and
`docs/12-llm-workflow.md` already marks `mm/`, `ke/wait`, `ps/usermode` and `arch/*.S` —
all of which it touches — as the dangerous region.

Empirical calibration: GUI-5 hit a lock-order inversion with **two locks, in user space**
(the winefb flush took win32u's user lock under the surface mutex). Extrapolating to
dozens of locks inside the kernel is not encouraging.

But the disqualifying objection is not effort — it is **Article 6**. "Only a differential
test convicts." A race cannot be pinned by an oracle-green test: the only instrument that
sees it is a sanitizer, and "the sanitizer went quiet" is explicitly not a fix. Fine-grained
SMP would put the project's central verification rule permanently out of reach.

## 4. The giant lock

**One lock, acquired on entry to the kernel and released on exit.** The invariant is one
sentence, unchanged in spirit from §2: *kernel state is touched only with the giant lock
held.*

This is the historically proven path (Linux 2.0's BKL, FreeBSD's Giant), and here it is
also the **minimal constitutional amendment**. Article 3 says "one dispatcher lock,
uniprocessor, no kernel preemption":

- "one dispatcher lock" — **preserved literally**;
- "no kernel preemption" — **preserved literally**;
- "uniprocessor" — the single word retired.

It also does not import the failure mode Article 3 warns about by name: the LLM reflex to
add fine-grained locks. The giant lock forbids them.

### What it protects for free

Everything in §2 stays correct **as written**:

- `kernel/mm/pool.c` with no lock — correct.
- `fs/fat32/fat.c:676`'s "no blocking, so it is atomic under the no-preemption model" —
  **the premise is preserved**. Under the giant lock, "I did not block" still implies "no
  one else ran".
- non-atomic refcounts, the Ob handle table, the Cm hive, the page cache — correct.
- the 55 `cli` sites become "acquire giant, then `cli`" mechanically.

The 27-kloc audit of §3 largely evaporates. This is the entire value proposition.

### The soundness argument, stated precisely

Two properties must hold, and both are cheap here:

1. **Blocking releases the lock.** Every wait must drop the giant lock and re-take it on
   wake. `KeWaitFor*` (`kernel/ke/wait.c`, 542 lines) is already the single choke point
   for blocking, so this is one place, not many.
2. **Code may not assume state is unchanged across a block.** It already cannot: under
   today's non-preemptive model, blocking means another thread runs. **The giant lock
   preserves exactly the existing invariant**, which is why existing code remains correct
   without review. That equivalence is the load-bearing claim of this document; any
   design that weakens it (e.g. dropping the lock at points that are not blocking waits)
   forfeits it and lands back in §3.

## 5. What the giant lock does not buy

The giant lock does **not** deliver kernel scalability, and that is fine — it is the one
axis Article 3 instructs us not to care about. What it *must not* be allowed to hide is
that five items remain genuinely unprotected by it. Those are §6.

## 6. The real remaining work

### a. Per-CPU state — and the groundwork already exists

```c
/* arch/x86_64/gdt.h:39 — GS points here in kernel mode; trap.S:68 does the swapgs */
typedef struct { uint64_t kernelRsp; uint64_t userRsp; } KIPCR;
extern KIPCR KiPcr;
```

The structurally awkward part — a GS-based per-CPU area, with `swapgs` at the ring
crossing — **is already in place and merely singleton**. The work is therefore wide but
mechanical:

- make `KiPcr` an array, one per CPU;
- move `currentThread` into the PCR and delete the `KiCurrentThread` global
  (`kernel/ke/sched.c:72` and its users in `ke/thread.c`, `ke/wait.c`, `init/panic.c`);
- per-CPU TSS (`KiTss` is a single static, `arch/x86_64/gdt.c:57`) and GDT;
- a per-CPU idle thread (`KiIdleThread` is likewise singleton, and `KiReadyThread`
  panics if it is ever queued);
- the ready queues may stay global under the giant lock — no per-CPU run queues, no load
  balancing. That is the Article 3-correct choice.

**Caution:** `arch/x86_64/gdt.c:40` welds `KIPCR` field offsets into `entry.S` with
`_Static_assert`. Any layout change is a two-file change by construction; keep the asserts.

### b. TLB shootdown — the lock cannot help

The hazard is a **hardware cache, not a data race**, so mutual exclusion is irrelevant:
another CPU can hold a stale translation for a mapping this CPU just changed. An IPI
mechanism is unavoidable. Sites: every unmap path, process teardown, guard-page
manipulation, and — if `docs/17` lands — every COW write-protect.

The Article 3-correct version is **broadcast to all CPUs and wait for acknowledgement**.
No tracking of which CPUs have the address space active, no targeted shootdown, no
optimization. A few hundred lines, and the subtlest item on this list.

### c. AP bringup

INIT-SIPI-SIPI, a real-mode/long-mode trampoline, per-CPU LAPIC initialization. `arch/*.S`
is on `docs/12`'s danger list, but this is a bounded, write-once, Intel-SDM-cited (G8) job,
and the LAPIC register plumbing already exists (`arch/x86_64/lapic.c`). IPI send is needed
here for both (b) and reschedule; in the xAPIC window that is the two-register ICR
(0x310 destination first, then 0x300), not x2APIC's single 64-bit write.

This is also the one item that could want x2APIC back. It buys nothing below 256 logical
CPUs — which is far past where a single dispatcher lock stops being defensible — so
switching modes is not part of this work. If it ever is, it is its own commit carrying the
CPU count that justified it, and it must stay behind a CPUID check with the xAPIC path
intact: firmware that hands off in compatibility mode is common enough that x2APIC-only
cost us bare-metal boots once already.

### d. Interrupts versus the giant lock — a policy decision

Today the lock *is* `cli`: cross-CPU exclusion and self-CPU interrupt exclusion are the
same mechanism. SMP splits them, and both are needed. An interrupt handler that touches
dispatcher state must either spin for the giant lock or defer its work to a flag the
lock-holder drains. Spinning is acceptable **only if nothing spins for I/O while holding
the lock** — which is exactly §7. Decide the policy explicitly and assert it; this is the
classic BKL-in-interrupt-context question and it will not resolve itself.

### e. User-space concurrency gets exposed for the first time

The giant lock says nothing about user mode — correctly, since NT semantics put that
burden on the program. But two of our own user-mode components have never actually run
concurrently:

- `wineserver-lite` and its clients over the shared session section
  (`\KernelObjects\__wine_session`), and
- `win32u.dll`'s in-process server halves plus `winefb.drv`.

GUI-5's lock-order inversion is the precedent. Expect real bugs here, expect them to be
in Wine's object model and our glue rather than in the kernel, and note that **the
`-smp 4` leg is the only thing that will find them**.

## 7. Hard prerequisite: overlap I/O in the block layer

**The design lives in `docs/19-io-strategy.md`.** Only the SMP-specific consequence belongs
here:

```c
/* drivers/virtio/virtqueue.c — VioSubmitAndPoll, holding the "lock" */
for (uint64_t spins = 0; spins < 1000000000ULL; spins++) { ... __asm__ volatile("pause"); }
```

A file transfer submits and **spins**, with queue depth structurally 1. Today that stalls
the machine, which is merely bad. **Under a giant lock it stalls every CPU at the kernel
gate**, so SMP would deliver nothing at all — and §6d's "an interrupt handler may spin for
the giant lock" policy is only bounded if nothing spins for I/O while holding it.

So `docs/19` is not an adjacent improvement; it is a gate on item 2 of §12. It is also
required by Net-1 on its own account (an AFD `accept`/`recv` may never complete), which is
why it should be built whether or not this document's amendment is ever made.

Its determinism story is *better* than this document's: because the completion drain point
is chosen by us, the single-interleaving behaviour of today's runs is preserved, so
`docs/19` needs none of §8's machinery.


## 8. Testability under a giant lock — the strongest argument

A fine-grained kernel has interleavings at arbitrary instruction boundaries. **A giant
lock reduces them to a countable set of named points**: the giant lock's
acquire/release — i.e. syscall entry/exit and blocking waits. Kernel state transitions
remain fully serialized; the only nondeterminism left is *which CPU takes the lock next*.

That is effectively cooperative scheduling with a nondeterministic order at named points,
and it has a decisive consequence:

> **Make the lock's hand-off order a seeded decision, and races become deterministically
> reproducible.** A failure can be replayed, minimized, and pinned — so **Article 6
> survives**: a differential test can convict a concurrency bug.

Two corollaries:

- We do **not** need QEMU record/replay for this. (Which is fortunate: QEMU's rr requires
  `-icount` and does not combine with multi-threaded TCG. **Verify that before betting on
  it** — but the seeded hand-off makes it unnecessary either way.)
- **Fine-grained locking forfeits this property.** It is not a detail of the giant-lock
  approach; it is the reason to choose it.

### Test legs

The harness already has many legs (`files`, `console`, `scm`, `gui`…`gui5con`,
`guiwtest`, `fuzz`), so this fits its existing shape:

- **`-smp 1` stays the permanent gate for every existing suite.** Never retire it: it is
  what lets any failure bisect into "concurrency or not".
- **`-smp 4` as a second leg** over the same suites.
- **a schedule-seed fuzz leg**, varying lock hand-off order.
- A KTSAN-style happens-before shadow (~the size of the existing KASAN, `kernel/mm/kasan.c`)
  is *optional* under a giant lock and would only earn its keep if fine-grained locking is
  ever attempted. Under Article 6 it names suspects; the seeded replay is what convicts.

### What is at risk if this is skipped

The project's most valuable asset is that **bugs reproduce deterministically**. It is what
makes the differential fuzzer able to minimize (down to ~13 calls, `docs/03` M3 notes) and
what makes the GUI-5 consistency-sweep detector *sound* — the README states the dependency
outright: "Art. 3's atomic snapshot making 'every thread parked on its own tid-alert
latch' a sound verdict". That asset cannot be recovered by later work. Buy the replay
mechanism in the same milestone as the second CPU, not after it.

## 9. The cost, and how the amendment is justified

The cost is that kernel-heavy workloads do not scale — the single axis Article 3 tells us
to ignore. So the justification cannot be "faster", and does not need to be:

**The motivating evidence is a verification argument.** The GUI-5 notes record up to twelve
`user32:msg` failures "decided by how slow TCG is rather than by any semantics of ours" —
i.e. the suite cannot reach a verdict on its own terms. Under multi-threaded TCG, guest
vCPUs map to host threads, and the workload in question is user-mode compute, which is
exactly what a giant-lock kernel still parallelizes. Recovering those verdicts is a
semantics outcome, not a speed outcome.

This is the same argument shape as `docs/17` §2 (COW justified by an observable RAM
ceiling, not by memory efficiency). Both are available only with a measurement in hand, so
**the amendment's evidence is a measurement, not this paragraph**: which of the timing-lost
`guiwtest` assertions recover when the same suite is given more wall-clock, and whether
multi-threaded TCG on this host actually converts extra vCPUs into throughput for a
user-mode-bound guest. If the answer is that the failures are not timing-bound after all,
the justification collapses and the amendment should not be made.

## 10. Kernel preemption is not a separate item

Making kernel code preemptible is small in code — identify the non-reentrant regions
(pool, page cache, FAT caches, Ob handle table, Cm hive) and give the lock a real nesting
discipline. But its only benefit is **latency inside long kernel operations**, which is
the one justification Article 3 refuses outright, and the two user-visible symptoms people
reach for it to fix are already addressed elsewhere: user-mode time-slicing exists via the
ring-3-return preemption point (`kernel/ke/sched.c:216`), and stalling-during-I/O is §7.

**Do not raise it as its own milestone.** If it is ever wanted, it is a sub-item of SMP.

## 11. Guidance for LLM-driven implementation

The three items in this document sit at opposite ends of the LLM risk scale, and the
giant lock is what moves SMP from one end toward the other.

- **The I/O overlap work (`docs/19`) is LLM-friendly** — existing engine to copy, mechanical
  driver change, determinism preserved. `docs/19` §6 and §9 carry the guidance.
- **§10 (kernel preemption) has fine-grained SMP's risk with almost none of its payoff.**
  Do not let it be taken as a standalone task.
- **§6 (SMP) is only tractable because the invariant is one enforceable sentence.** An
  LLM's strength is mechanical breadth — converting 55 `cli` sites, array-ifying `KiPcr`,
  replacing `KiCurrentThread` — and all of that is exactly what the giant lock asks for.
  Its weakness is inventing and holding a *distributed* invariant: which field is under
  which lock, what may block while holding what, lock ordering. Fine-grained locking is
  all weakness and no strength; the giant lock is the reverse.

The decisive asymmetry against fine-grained work is not difficulty but **feedback**: its
bugs do not reproduce deterministically, so the normal loop of "write a failing test,
convict, fix" is unavailable, and Article 6 cannot be satisfied. §8's seeded hand-off
exists to give SMP that loop back; treat it as part of the implementation, not tooling.

Items that will be dropped unless named explicitly in the task: **§6b** (shootdown — it is
not a data race, so a lock-focused reading of the work misses it entirely), **§6d** (the
interrupt-context policy), and **§8** (the replay seed, because everything appears to work
without it).

## 12. Build order and size

This work is milestone **CUI-10** (`docs/02`), last on the CUI path. CUI-8 (`docs/19`) is a
hard dependency; CUI-9 (`docs/17`) is not, but if it landed first its write-protect sites
join step 4's enumeration.

1. **Block-layer overlap** (`docs/19`, §7 here) — required by Net-1 too; land it
   independently of any SMP decision.
2. **Per-CPU state** (§6a) — `KiPcr` array, `KiCurrentThread` retired, per-CPU TSS/GDT/idle.
3. **AP bringup + IPI** (§6c).
4. **TLB shootdown, broadcast form** (§6b).
5. **Interrupt-versus-lock policy** (§6d), asserted.
6. **Test legs**: `-smp 4`, seeded schedule replay, schedule fuzz (§8) — in the same
   milestone, not after.

**Size:** roughly **1.5 CUI-consolidation milestones, with no permanent audit tax** —
because the invariant stays one sentence. This **supersedes** the fine-grained estimate of
§3 (M7-sized plus an ongoing tax); the two are estimates of different projects.

## 13. Entry conditions

Do not start item 2 until all four hold:

1. **`docs/19` is done** (§7). Otherwise the giant lock stalls every CPU at the kernel gate
   and SMP delivers nothing.
2. **The Article 3 amendment exists**, with the §9 measurement behind it and a `docs/03`
   entry. Under the current constitution this work is simply not writable.
3. **The `-smp 1` permanent gate and the `-smp 4` leg exist in the harness.**
4. **The seeded lock hand-off / replay mechanism is designed** (§8). It is the thing that
   keeps Article 6 reachable, and it is not retrofittable in spirit — once failures are
   irreproducible, the habit of convicting them with tests is gone.

## 14. Interaction with COW (`docs/17`)

`docs/17` §11 carries the joint text. In short: COW's write-protect is a shootdown site,
the giant lock does not cover it (§6b), and whichever feature lands second inherits the
join. Also note that `docs/17`'s hazard A (kernel-side writes bypassing the write-protect
via `MiCopyToUserRange`) is unaffected by SMP — it is a design error either way, and its
single-authority fix is the same.
