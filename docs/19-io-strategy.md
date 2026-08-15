# 19 — Asynchronous I/O Strategy

Unlike `docs/17` and `docs/18`, this document is **not** an argument for amending the
constitution. Article 3's "everything completes before the syscall returns" already
*narrows* here rather than forbidding — `kernel/io/async.c` says so in its own header —
and the surface this describes is NT-present, boundary-observable, and consumer-driven in
the ordinary Article 5 way. This is the design for work that will be built.

It is also the **first** of the three to build: `docs/18` §7 depends on it, Net-1 depends
on it independently, and neither dependency is discoverable from the milestone list today.

---

## 1. What the NT contract actually is

This section exists because its absence keeps re-opening the same argument ("is synchronous
completion a deviation?"). It is not. The contract has five parts, and "the operation
pended" is not one of them.

1. **`STATUS_PENDING` is permitted, never required.** Real NT completes I/O inline
   whenever it can (the fast-I/O path); a caller that treats a synchronous completion as a
   protocol error is broken on Windows too. What the caller is entitled to is that the
   return value discriminates: a non-`STATUS_PENDING` return means the IOSB is already
   final; `STATUS_PENDING` means the IOSB is *not yet valid* and the caller must wait for
   the completion signal.
2. **The IOSB is visible before any completion signal fires.** Implemented and commented
   as the contract order (`kernel/io/file.c:183`, `IopCompleteRequest`), and again on the
   pended path — the IOSB goes into the owner's address space *strictly before* the event
   is set (`kernel/io/async.c`, `IopCompletePendingRequest`).
3. **Completion delivery has three legs, and the IOSB precedes all of them**: the optional
   event; a user `ApcRoutine`, queued at completion and invoked by
   `KiUserApcDispatcher` at the caller's next *alertable* wait as
   `PIO_APC_ROUTINE(ApcContext, iosb, reserved)` (`kernel/io/rw.c:19`, pinned on the oracle
   by `tests/ntapi/sem_file/apc_completion.c`); and an I/O completion port, when the handle
   is associated with one.
4. **Synchronous versus asynchronous handles are different contracts.**
   `FILE_SYNCHRONOUS_IO_*` at create (`kernel/io/file.c:373` → `file->synchronousIo`) means
   the kernel owns the file position (`rw.c:107`, updated at `rw.c:225`/`342`), operations
   on the handle serialize, and the handle itself is the waitable object. Without it the
   caller supplies the offset, the kernel keeps no position, and the operation may pend.
   The flag is reported back through `FileModeInformation` (`kernel/io/query.c:269`).
5. **The IOSB belongs to the caller until completion.** For a pended request this is a
   cross-context obligation, and `kernel/io/io.h` already states the answer to the G11
   ownership audit for it: the issuer resolves everything context-dependent up front (the
   event *body*, not a handle; the owning process), the parking filesystem holds the only
   pointer and always completes the request — client attach, cancel, or the owning handle's
   cleanup, whichever comes first — and handles close before the owner's address space
   dies, so the IOSB write cannot hit a torn-down space.

**Consequence.** Today's "all data transfers complete inline" is a *legal point inside this
contract*, not a deviation, **for devices that always complete in bounded time**. It stops
being legal the moment a device may never complete on its own — which is exactly the Net-1
case (§4).

## 2. What exists today (measured)

**The protocol is built and pinned.** Completion ordering (§1.2), the event leg, the APC
leg, `NtRead/WriteFile{Scatter,Gather}` answering `STATUS_PENDING` in the oracle's shape
(`kernel/io/rw.c:674`), I/O completion ports as real Ob objects (`kernel/io/completion.c`)
with `IopPostCompletionPacket` as the **single posting authority** (Art. 11 — job
lifecycle packets already ride it), `NtCancelIoFile(Ex)` with the wineserver-pinned shape
(thread-scoped succeeds even when nothing pends; the Ex form answers `STATUS_NOT_FOUND`;
any object handle resolves), and `NtCancelSynchronousIoFile` with its cancellable park
`IoWaitCancellable`.

**The pending engine is built**, with two consumers: `FSCTL_PIPE_LISTEN` on asynchronous
handles (CUI-3 — rpcrt4's `ncacn_np` server loop deadlocks on a blocking listen) and
`NtNotifyChangeDirectoryFile` (CUI-5). npfs's blocking read/write/`FSCTL_PIPE_WAIT` and
condrv's reads block in their own way.

**The data pending is now built too (CUI-8, landed).** The historical measurement this
section used to carry — a 10⁹-iteration submit-and-spin, structural queue depth 1, a
machine single-threaded for the duration of every transfer — described the pre-CUI-8
driver and is preserved in history. What is measured today:

- `drivers/virtio/blk.c` owns per-request control slots, `VIO_BLK_MAX_INFLIGHT` chains in
  flight, and a head-descriptor cookie map; `VioBlkDrain` is the single harvest authority
  (Art. 11), and the depth verdict of §8.4 is emitted and gated (floor 8,
  `tests/kmt/cui8_async.c`).
- An issuer that outlives its bounded pre-park spin **parks** (`VioBlkAwait` →
  `KeWaitForSingleObject`); other threads run while the device works. The §8.3 acceptance
  test (`progress_during_io`) is green, including under an absolute drive throttle.

**The harvest is now interrupt-driven too (§11, built).** The polled harvest this
section previously measured — a tick-tail drain flooring a parked issuer's wake at up to
a millisecond, and an idle loop that had to spin `sti; pause` instead of `hlt` while a
transfer was in flight because no completion interrupt existed to cut a `hlt` short —
is deleted. Completions are discovered at the blk MSI-X ISR (`kernel/ke/irq.c`,
`BLK_VECTOR`) and by **thread-context waiters** (the pre-park spin, the post-park
poll-home, and the submit-side full-ring retries); idle `hlt`s unconditionally. The
delivery and idle-sleep verdicts (§11e) gate both properties in `tests/kmt/cui8_async.c`.

## 3. The gaps, and the consumer that convicts each

| Gap | Convicting consumer | State today |
|---|---|---|
| Genuine pending on file data | **Net-1** (`\Device\Afd`: an `accept`/`recv` may never complete); overlapped file I/O | not built |
| Queue depth > 1 / per-request buffers | any overlap at all | not built (§2) |
| `FileCompletionInformation` (port↔file association) | `BindIoCompletionCallback` consumers — **not baked**; the threadpool drives ports directly via `NtSetIoCompletion` | refuses loudly (G12); hook point is `IopPostCompletionPacket` (Art. 11) |
| Directory-watch buffering across the re-arm window | winetest change pairs parked on it | deviation recorded (`docs/03` CUI-5) |
| Cancellation beyond npfs | a console read that a caller wants to cancel — no baked caller yet | condrv/serial/`\Device\Input*` waits stay uncancellable (`docs/03` CUI-5) |
| Interrupt-driven device completion | the idle loop could not `hlt` with I/O in flight; parked issuers woke on the next tick, not on completion | **built** (§11): blk MSI-X → the same drain; verdicts §11e |

Note the shape: **only the first two rows are blocking anything.** The rest are recorded,
loud, and waiting for a consumer, which is the Article 5 steady state and not debt.

## 4. Why this is the first thing to build

Three independent reasons, any one of which is sufficient:

1. **Net-1 cannot be written on top of it.** An AFD `accept`/`recv` does not complete
   until a peer acts. A polled-synchronous socket path deadlocks by construction — not
   slowly, but immediately. The block-layer work is the hidden cost inside the Net-1
   estimate.
2. **SMP is worthless without it** (`docs/18` §7): a spin under a giant lock stalls every
   CPU at the kernel gate, destroying the only thing SMP was for.
3. **It is the one place where the "unobservable" claim is thinnest.** Latency is not a
   contract, but "no APC can be delivered and `^C` cannot be seen while the disk is busy"
   is a functional property that survives only because the disk is currently fast.

## 5. Design

### a. virtio-blk: per-request buffers and depth

Retire the global control/bounce singletons in favour of per-request state, allowing more
than one descriptor chain in flight. Revisit the 8-sector chunking at the same time, and
the bounce `memcpy` where the target pages can be described to the device directly.
Spec-cited per constant as today (G8).

### b. Completion harvest on the idle/timer path first; interrupts as the follow-on

`VioTryPopUsed` (`drivers/virtio/virtqueue.c`) already exists as a non-blocking harvest and
is used by virtio-input. Drain from the idle path and the timer tick. The original text
here said **do not add an interrupt path in this work**, for two reasons that were true at
the time and are now discharged:

- *"It drags in the interrupt-versus-lock policy question (`docs/18` §6d)."* On the
  uniprocessor the question is degenerate: the dispatcher lock **is** interrupt disable
  (`docs/18` §2), so a device ISR is excluded from every lock hold by construction —
  landing the ISR now *answers* §6d for the current machine (state the policy, assert it)
  rather than deferring it to SMP.
- *"Polling from idle already recovers all of the overlap."* It does — at the price of an
  idle loop that must busy-spin instead of `hlt` whenever a transfer is in flight
  (`kernel/ke/sched.c`, the `sti; pause` arm), and a wake latency floored at the tick when
  the machine is not idle. Those are structural costs of the polling harvest itself, not
  of any NT semantics, and they grow with every future device class that would otherwise
  inherit a poll-and-nap loop.

The closing sentence — *"if a consumer ever convicts the latency, it is a separate change
against the same drain seam"* — is the charter for §11: the interrupt is exactly that
separate change, and the drain seam (`IoDrainDeviceCompletions`, docs/20 R2's bracketed
harvest-and-wake) is unchanged. Note what the interrupt is **not** justified by: Article 3
refuses *performance* as a reason to deviate from the simplest correct thing, but
interrupt-driven completion is not a deviation from anything — it is the mechanism the
virtio spec defines for exactly this, it is how NT's own storage stack completes I/O, and
the polling harvest was itself carrying a latency workaround (the idle busy-poll exists
only to dodge `hlt`'s full-tick penalty). The interrupt deletes complexity of that kind;
it does not add an optimization.

### c. FS/Io: park and pend

Route file read/write through the existing `IOP_PENDING_REQUEST` engine: park, return
`STATUS_PENDING`, complete from the drain point. The FCB and the page-cache page need
in-flight state so a second thread entering the same file finds it.

### d. Generalize the pended-request ownership rule

`kernel/io/io.h`'s G11 answer (§1.5) was written for npfs's parked listen. Make it the
device-independent convention, stated once, and assert it — every future pending verb
inherits it rather than re-deriving it. This is an Art. 11 one-authority move.

### e. What deliberately stays unbuilt

No completion-port file association (no consumer); no I/O scheduling, reordering,
elevator or readahead (Art. 3 — correctness only); no fine-grained locking (`docs/18`
§3). Interrupt-driven completion for **blk** is §11; virtio-input and the serial console
keep their poll-and-nap shape until a consumer convicts it (§11f).

## 6. Re-entrancy is the actual work

The driver change is mechanical. The difficulty is that **an operation can now be in
flight while another thread enters the same object**, and a large amount of existing code
is lock-free *because that could not happen*. The archetype:

```c
/* fs/fat32/fat.c:893 */
/* Count free clusters off the in-pool FAT (a pure memory sweep: no
 * blocking, so it is atomic under the no-preemption model). */
```

There are 35 such "no preemption / uniprocessor" justifications across `kernel/`, `fs/`
and `drivers/`, and they are greppable. **Each one becomes a claim to re-check**: is it
still true when the thread that used to hold the CPU is now parked on a pended request?

**Deliverable order matters here:** the enumeration of paths that can be re-entered
mid-flight is written *before* the code that makes re-entry possible, as its own artifact.
That list, not the virtqueue diff, is what makes the change reviewable.

## 7. Semantics that must be decided and pinned

All of these are observable at the boundary, so Article 5 applies: pin on the oracle before
implementing.

- **Does a file read on an asynchronous handle pend, or complete inline?** Both are legal
  (§1.1). The choice is visible in the *return value* even when the final result is
  identical, so pick one and pin it — including the case where the data is already in the
  page cache and no device round trip is needed (inline completion is the obvious answer
  there, and NT's fast path does exactly that).
- **Cancellation of a pended file read**: what `NtCancelIoFile(Ex)` does to it, what the
  IOSB ends up holding (`STATUS_CANCELLED`), and whether the transfer already issued to the
  device can be abandoned or must be awaited.
- **Ordering between two operations issued back-to-back on one handle.** On a synchronous
  handle the kernel-owned position serializes them; on an asynchronous handle NT promises
  no ordering. Decide, pin, and make sure the fuzzer's op model knows.
- **EOF and short transfers under pend** — the same values as the inline path, arriving
  later.
- **Process or thread teardown with a request in flight** — §5d's rule, tested, not just
  asserted.
- **`FileModeInformation`** must keep reporting what the create actually established.

## 8. Testability

### 8.1 Determinism survives, because we choose the drain point

Draining only at explicit points preserves today's single-interleaving behaviour exactly; a
knob that varies drain aggressiveness gives a stress leg without making the default runs
nondeterministic. Neither the differential fuzzer's minimization nor the GUI-5
consistency-sweep deadlock detector loses its premise (contrast `docs/18` §8, where the
premise must be bought back).

That is a claim about the design, so **check it rather than assert it**: the existing run
legs' serial verdicts must be unchanged, and the aggressiveness knob must default to off.
A stress leg that leaks into the default runs takes the project's most valuable property
with it.

### 8.2 The regression net that already exists

Oracle-green today, and every one of them is a guard on this work:
`tests/ntapi/sem_file/read_write.c`, `sem_file/apc_completion.c`, `sem_pipe/async_listen.c`,
`sem_pipe/cancel_sync.c`, `sem_file/notify_change.c`, `sem_mm/file_coherence`.

**None of it convicts a re-entrancy bug**, which is the milestone's actual risk. Every one
of these runs single-threaded — `docs/02` M6 says so of `file_coherence` explicitly — so
they guard the semantics an in-flight operation must not break, not the in-flight state
itself. §8.3 is what has to be built.

### 8.3 Three tests this milestone has to add

1. **The acceptance test — progress during I/O.** The property §4 exists for is that the
   machine is no longer single-threaded while the disk is busy, and no test states it.
   Thread A issues a large read; thread B must observably advance before A completes — a
   counter, a delivered APC, a `^C` reaching a console read. Assert B advanced. This, not
   the depth counter, is the milestone's acceptance: the counter measures the driver, this
   measures the kernel.
2. **A concurrent `file_coherence`.** The existing stress becomes multi-threaded against
   one file: two threads interleaving mapped-view stores, `NtReadFile` and `NtWriteFile`
   over the same FCB and the same page-cache page, with a transfer in flight. This is the
   direct guard on §6, and it is the test the re-entrancy enumeration is written *for* —
   each entry on that list should name the interleaving here that would catch it.
3. **The fuzzer must learn that operations can be in flight.** Today
   `tests/fuzz/interp.c:440` is explicit: *"Single-threaded and drained only at the explicit
   `test_alert` op"* — so the differential instrument is blind to this entire milestone.
   The op model needs issue-now/collect-later ops (and cancel interleaved with them) so a
   divergence in pended-completion behaviour can be *minimized and pinned*. Under Article 6
   this is not optional garnish: KASAN and asserts will name a re-entrancy suspect, and only
   this can convict one.

### 8.4 The win must be a verdict, not an inference

An implementation that pends correctly but never actually overlaps — depth still 1, drain
immediately after submit — **passes every semantic test above**, because it is
behaviourally today's kernel. Same failure shape as `docs/17` §8. Pin the win:

- maximum and mean in-flight request depth, emitted as a `[KTEST]` verdict under a
  workload that issues concurrent I/O;
- and/or wall-clock of a two-thread read workload against a committed budget.

### 8.5 The winetest spine

`docs/02` makes every CUI milestone grow the winetest manifest by unparking pairs blocked
on its surface. CUI-8 adds no `Nt*`, so the expected answer is **no unparks** — but that
must be *recorded* rather than left implied, and it is worth re-checking the parked list
once pending is real: a pair parked on overlapped-I/O behaviour rather than on a missing id
would be invisible in today's list.

## 9. Build order

1. **Pin the §7 decisions on the oracle** (Art. 5), before kernel code.
2. **The re-entrancy enumeration** (§6) — its own artifact, from the 35 justifications,
   each entry naming the interleaving in §8.3's concurrent stress that would catch it.
3. **The concurrent `file_coherence`** (§8.3) — written and green *before* anything can
   re-enter, so it is a regression guard rather than a post-hoc check.
4. **virtio-blk per-request buffers + depth** (§5a), still submit-and-wait: no behaviour
   change, purely structural. Own commit.
5. **Drain point** (§5b) + the depth verdict (§8.4) + the determinism check (§8.1).
6. **FS/Io park + `STATUS_PENDING`** (§5c) and the generalized ownership rule (§5d).
7. **The progress-during-I/O acceptance test** (§8.3) — the milestone's actual verdict.
8. **The fuzzer's in-flight op model** (§8.3), so a pended-completion divergence can be
   convicted rather than merely suspected.
9. **Widen cancellation** to the newly pended verbs; revisit the console-read gap only if
   a consumer convicts it. Record the winetest answer (§8.5).

## 10. Relationship to the other two strategy documents

- **`docs/18` (SMP)** lists this work as a hard prerequisite and defers to this document
  for the design.
- **`docs/17` (COW)** is independent of it. The one shared theme is §8's failure mode: in
  both cases a correct-but-inert implementation passes every semantic test, so both must
  pin their win as a machine verdict.
- **Net-1** (`docs/02`) carries an explicit dependency on this work, alongside CUI-1's
  clock — its transport assumption is unbuildable until this lands.
- **This work is milestone CUI-8** (`docs/02`), the first of the three machine-level
  milestones that close the CUI path; COW is CUI-9 and SMP is CUI-10.

## 11. The interrupt path (the §5b follow-on)

CUI-8 built the park and the drain; the harvest stayed polled. This section is the
"separate change against the same drain seam" §5b reserved: virtio-blk completions are
signalled by a device interrupt, and the two polling costs §2 measures — the idle loop's
`sti; pause` busy-spin while I/O is in flight, and the tick-quantized wake of a parked
issuer — are deleted rather than tuned.

### a. Mechanism: MSI-X, one vector, straight to the LAPIC

**MSI-X, not INTx.** The kernel has no IOAPIC and no 8259 routing (the PIC is hard-masked
at boot, `arch/x86_64/lapic.c`), and an INTx pin would need one or the other brought up
plus the level-triggered/shared-line discipline (ISR-status read-to-clear, virtio 1.2
§4.1.4.5). An MSI-X message is a DMA write to the LAPIC's `0xFEE00000` window (Intel SDM
Vol. 3 §11.11): edge-delivered, per-queue, unshared, and it needs **no new interrupt
hardware brought up at all**. Constants land under G8 as everywhere else: the MSI-X
capability layout from PCI Local Bus 3.0 §6.8.2, the message address/data format from the
SDM, `queue_msix_vector`/`VIRTIO_MSI_NO_VECTOR` from virtio 1.2 §4.1.4.3 — each cited at
the definition, cross-checked against the pinned QEMU device model.

Concretely:

- `drivers/pci.c` grows the tree's one **generic** capability walker (Art. 11: today's
  walker, `VioFindCapability`, hard-filters on the virtio vendor id and cannot see cap
  0x11) plus the `INTERRUPT_LINE`-adjacent config fields it needs; virtio's walker becomes
  a client of it or stays as the vendor-specific specialization — one walk authority.
- `drivers/virtio/pci.c` maps the MSI-X table BAR through the existing `VioMapMmio`
  window (still before `MiFreezeKernelPml4`, same as every other virtio mapping), programs
  one table entry, sets MSI-X Enable, and writes `queueMsixVector` for the request queue
  **after** `queueSelect`, checking the `VIRTIO_MSI_NO_VECTOR` readback (§4.1.4.3). The
  config-change vector stays `VIRTIO_MSI_NO_VECTOR` — nothing consumes config interrupts.
- **Failure is loud (G12).** If the capability is absent or the device answers
  `VIRTIO_MSI_NO_VECTOR`, the device is refused (`VioPciSetFailed`) exactly like a
  read-only disk at §5.2.3 — there is no silent fall-back to polling, because a silent
  fall-back is a masked regression (§11d.4).
- The blk request queue gets **one vector** (the next free one above `TIMER_VECTOR`; the
  thunk table in `arch/x86_64/trap.S` grows one entry). virtio-input keeps polling
  (§11f), so no vector-allocation machinery is built for one static assignment.

### b. The handler is the drain, and the lock policy is now explicit

The ISR body is `KiEndOfInterrupt()` plus the existing `IoDrainDeviceCompletions()` —
nothing else. That function is already the single harvest authority (Art. 11), already
brackets itself with the no-block region and the `KiInCompletionDrain` allocator
prohibition (docs/20 R2), and already promises harvest-store-wake and nothing more. The
interrupt adds a *when*, not a *what*: the same drain, at a new entry.

This answers `docs/18` §6d for the uniprocessor, explicitly, as that section demands:

> **Policy: the dispatcher lock is interrupt-disable, so a device ISR takes the lock by
> arriving.** Every lock hold excludes the ISR by construction; the ISR runs with IF off
> (interrupt gate) and therefore holds the lock for its whole body; it readies threads
> and never context-switches — the identical contract `kernel/ke/irq.c` states for the
> clock tick, now shared by two vectors. Asserted, not assumed: the ISR entry lands in
> the same `KiEnterNoBlockRegion` bracket, and the new dispatch arm joins
> `tools/blocking_frontier.py`'s `MUST_NOT_BLOCK` set **in the same commit** (G14).

When SMP splits "lock held" from "interrupts off" (`docs/18` §6d), this ISR is the first
concrete instance the split policy must cover; the section gains that cross-reference
rather than re-deriving the answer.

### c. What is deleted, what stays

**Deleted, once the interrupt is proven live (§11e):**

- the idle loop's `sti; pause` arm — idle becomes `sti; hlt` unconditionally, because a
  completion now cuts `hlt` short like any other interrupt;
- the tick-tail `IoDrainDeviceCompletions()` call in `KiUpdateClock` — the tick goes back
  to time and timers.

Deleting them is not housekeeping; it is the **§8.4 discipline applied to this change**.
A kernel that wires the interrupt but keeps the polling backstops passes every test even
if the interrupt never fires once — the correct-but-inert failure shape again. The
backstops go away so that the interrupt path is load-bearing, and a broken one fails the
delivery verdict (§11e) and, at runtime, the existing 10 s park panic — loudly.

**Stays, deliberately:**

- Thread-context drains: the bounded pre-park spin (`VioBlkAwait` — it still saves the
  park's context-switch round trip for microsecond completions, and the kmt suites still
  zero it to force the park deterministically), the post-park poll-home for terminating
  threads (docs/20 R4 — a dying thread cannot park, and its progress must not depend on
  interrupt delivery), and the submit-side full-ring retry drains (they run under one
  `cli` hold, where the ISR by definition cannot run for them).
- `VIRTQ_AVAIL`/`VIRTQ_USED` suppression flags stay zero and `VIRTIO_F_EVENT_IDX` stays
  unnegotiated: the device may interrupt per completion, and we do not build coalescing
  we cannot convict a need for (Art. 3 — that *would* be the latency/throughput axis).

### d. Regression risks, enumerated

1. **A new asynchronous drain instant.** The drain could already run at any instruction
   boundary with IF on — the tick has called it every millisecond since CUI-8 — so the
   ISR adds **no new execution-context class**: docs/20 §1's F2 ("a third execution
   context") and every R1–R5 rule cover it as written. What changes is *frequency and
   correlation*: drains now cluster at completion instants instead of tick edges. The
   risk is code that was accidentally safe because drains were rare; the guard is that
   all queue/request bookkeeping already lives under the dispatcher lock (one `cli`
   hold per submit, F2), which excludes the ISR wholesale.
2. **Ready-never-switch must survive a second vector.** The wake the ISR performs is
   `KeSetEvent` → `KiWaitTest` readying, with the switch deferred to
   `KiPreemptAtUserReturn` or the next explicit wait/yield — the identical edge the tick
   drives. A future "helpful" context-switch-from-ISR would break Art. 3's no-preemption
   mandate; the no-block bracket plus the frontier check make that structural.
3. **Lost-wake races.** Two are closed by existing structure, one by x86: (i) the parked
   waiter — `KeSetEvent` and the park serialize under the dispatcher lock, and an event
   set before the park satisfies the wait immediately; (ii) a drain that harvested the
   ring before the MSI arrives — the ISR then drains an empty ring, which is idempotent;
   (iii) idle's check-then-`hlt` — `sti; hlt` is race-free because `sti` takes effect
   after the following instruction, so an interrupt arriving in the window still ends
   the `hlt`.
4. **A dead interrupt path masked by leftover polling.** Risk #1 of the whole change,
   handled by deleting the backstops (§11c) and by the delivery verdict (§11e): a
   miswired vector, a wrong MSI-X table entry, or a `NO_VECTOR` readback that went
   unchecked must fail a `[KTEST]` line in CI, not surface as "latency seems ticky".
5. **Early or spurious interrupts.** The vector's gate and dispatch arm are installed
   before MSI-X Enable is set, so no window exists where the message targets a vector
   that panics as unexpected; an interrupt before `DRIVER_OK`, or after a harvest
   already emptied the ring, runs one empty drain — harmless by R2 (harvest-store-wake
   only, no allocation, no FS).
6. **Determinism of the test legs (§8.1 revisited).** The claim "we choose the drain
   point" was already only as strong as the tick's asynchrony; the run legs' verdicts are
   filtered for timing-dependent lines and diffed across boots (the cui8 stages (c)/(d)).
   Completion-correlated drains reshuffle wake *timing*, and may not reshuffle filtered
   *verdicts* — that is a claim, so it is **checked, not asserted**: both determinism
   stages re-run green at every commit of this work, and a verdict line that becomes
   timing-sensitive is a test bug to fix, never a filter to widen.
7. **Depth-verdict flakiness.** Faster harvest can shrink observed queue depth below the
   gated floor of 8: the fat32 batch loop (`FatBatchTransfer`) submits with interrupts
   **on** between requests — each `VioBlkSubmitPrepared` takes and releases the lock
   itself — so the ISR may harvest between submits 3 and 4 of a 16-deep batch, where
   today's tick could interleave only at millisecond edges. Measured, not argued: stage
   (a)'s `max >= 8` gate is re-run repeatedly (KVM and TCG) when the ISR lands, and if
   the floor wobbles the fix is a true single-hold batch submit (one lock acquire for
   the whole batch — which *makes* the mid-batch harvest impossible), never a lowered
   floor or a widened tolerance.
8. **G14 mechanics.** The new dispatch arm is a must-not-block region; forgetting the
   `MUST_NOT_BLOCK` entry makes `blocking_frontier.py --check` blind to it. The entry
   lands in the same commit as the arm (the check enforces reachability, the dict entry
   is the declaration).

### e. Testing strategy

- **The delivery verdict (the §8.4 rule again: a verdict, not an inference).** A counter
  incremented only in the ISR dispatch arm, emitted as a `[KTEST] blk irq …` line and
  asserted nonzero by a kmt test that forces the park (`VioBlkSetAwaitSpinBound(0)`) and
  runs a cold multi-chunk transfer. It joins the existing `CUI8` suite, so
  `tests/run/kmtcheck.sh` needs no new enrollment — and it is written and failing-red
  against the polled kernel *first* (Art. 5 shape, with the kernel itself as the unit
  under test since no oracle sees a kernel-internal property).
- **The existing cui8 leg is the regression net, all four stages**: (a) full boot +
  depth floor, (b) the throttled `progress_during_io` boundary run (an interrupt can only
  widen its margin — confirmed by run, not by argument), (c) two-boot determinism diff,
  (d) stress-boot byte-identity against (c). Stages (c)/(d) are the direct check on risk
  §11d.6.
- **The idle-sleep property gets a verdict too**: after the §11c deletion, a forced-park
  cold read from the test thread leaves idle as the only runnable context, and an idle
  `hlt` counter must advance across the read (`delta > 0`). That is the honest limit of
  what a counter can assert — wake *attribution* ("the ISR ended this `hlt`") is not
  observable and is not claimed; the structural half is the deletion itself, and the
  counter guards against a quietly reintroduced poll arm, which would keep idle out of
  `hlt` during in-flight windows and zero the delta.
- **`make test` green at every commit** (kmtcheck's full suite list), `make fulltest`
  before the PR — the `cui8` and `frontier` legs are the ones this work can move.
- **Negative paths by inspection + assert**, since QEMU always offers MSI-X: the
  `NO_VECTOR` readback refusal and the absent-capability refusal are G12-loud code paths
  reviewed against §4.1.4.3, each with an `ASSERT`/`DbgPrint` naming itself.
- **Tests that observe a parked window from another thread need the window held.** The
  ISR completes a park at device speed, so "the issuer is parked and I can look" stopped
  being a consequence of `VioBlkSetAwaitSpinBound(0)` alone — the cancel test rode the
  old tick-drain latency and became a hang-shaped race under TCG. The fix is another
  §8.1-class knob, not a tolerance: `VioBlkSetCompletionHold` defers the harvest so the
  window is a controlled state again (the driver's own forward-progress paths — submit
  retries, the terminating thread's poll-home — bypass it, so it can never wedge the
  machine), and the watcher pumps completions manually until the span it wants to cancel
  into appears.

### f. What this deliberately does not do

No INTx/IOAPIC bring-up; no interrupt for virtio-input or the serial console (their
poll-and-nap loops are convicted by no consumer — a 1 kHz input poll is not a cost the
way a per-transfer busy-spin is, and `docs/20` §6 keeps their queues single-reader); no
`VIRTIO_F_EVENT_IDX`/suppression negotiation (§11c); no interrupt coalescing, threading,
or DPC split — the drain stays a plain top half (`docs/03`: no IRQL, no DPCs). Each of
these is a separate change against the same seam if a consumer ever convicts it.

### g. Build order (G13: one meaningful unit per commit)

1. **The delivery verdict, red** — the kmt test asserting ISR-path harvests occur,
   failing against the polled kernel (the §11e first bullet).
2. **Generic PCI capability walk + MSI-X plumbing** in `drivers/pci.c` /
   `drivers/virtio/pci.c`, constants G8-cited; MSI-X enabled with the queue vector
   programmed; the ISR wired (`trap.S` thunk, gate, `irq.c` arm calling the drain,
   `MUST_NOT_BLOCK` entry, G14 baseline if it moves). The verdict from (1) turns green.
   Tick drain and idle busy-poll still present — behaviour otherwise unchanged, so the
   commit is bisectable to "interrupts arrive".
3. **Delete the backstops** (§11c): the tick-tail drain call and the idle `sti; pause`
   arm, with the stale comments they carried (`sched.c`, `virtio.h`, `virtqueue.c`,
   `pci.c` "a polling driver needs none of them"); docs/18 §6d and docs/20 §6 rows
   updated to point here. The four cui8 stages and the idle-sleep verdict prove the
   interrupt is now load-bearing.
4. **README status line** per the milestone rule, if this is judged milestone-worthy;
   otherwise the docs/19 §2/§3 rows above are the record.
