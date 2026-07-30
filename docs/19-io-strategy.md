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
(`kernel/io/rw.c:593`), I/O completion ports as real Ob objects (`kernel/io/completion.c`)
with `IopPostCompletionPacket` as the **single posting authority** (Art. 11 — job
lifecycle packets already ride it), `NtCancelIoFile(Ex)` with the wineserver-pinned shape
(thread-scoped succeeds even when nothing pends; the Ex form answers `STATUS_NOT_FOUND`;
any object handle resolves), and `NtCancelSynchronousIoFile` with its cancellable park
`IoWaitCancellable`.

**The pending engine is built**, with two consumers: `FSCTL_PIPE_LISTEN` on asynchronous
handles (CUI-3 — rpcrt4's `ncacn_np` server loop deadlocks on a blocking listen) and
`NtNotifyChangeDirectoryFile` (CUI-5). npfs's blocking read/write/`FSCTL_PIPE_WAIT` and
condrv's reads block in their own way.

**What is not built is the pending itself, for data.** Every file read and write completes
inside the syscall, down to the metal:

- `VioSubmitAndPoll` (`drivers/virtio/virtqueue.c`) submits and **spins** up to 10⁹
  iterations; no interrupt is negotiated at all (`drivers/virtio/pci.c`: "a polling driver
  needs none of them").
- Queue depth is **structurally 1**: `drivers/virtio/blk.c` owns one global control header
  and one bounce buffer (`VioBlkControlPhysical` / `VioBlkDataBounce`), with a `memcpy` per
  transfer. There is nowhere to put a second in-flight request.
- Transfers are chunked at 8 sectors, so a large read is *N* synchronous round trips.

While a transfer is outstanding the system is effectively single-threaded: no other thread
runs, no APC is delivered, a console `^C` is not seen. This is invisible today only because
QEMU serves the image from the host page cache in microseconds; on a slower backing store —
or real hardware — the same code is a machine-wide stall of tens of milliseconds.

## 3. The gaps, and the consumer that convicts each

| Gap | Convicting consumer | State today |
|---|---|---|
| Genuine pending on file data | **Net-1** (`\Device\Afd`: an `accept`/`recv` may never complete); overlapped file I/O | not built |
| Queue depth > 1 / per-request buffers | any overlap at all | not built (§2) |
| `FileCompletionInformation` (port↔file association) | `BindIoCompletionCallback` consumers — **not baked**; the threadpool drives ports directly via `NtSetIoCompletion` | refuses loudly (G12); hook point is `IopPostCompletionPacket` (Art. 11) |
| Directory-watch buffering across the re-arm window | winetest change pairs parked on it | deviation recorded (`docs/03` CUI-5) |
| Cancellation beyond npfs | a console read that a caller wants to cancel — no baked caller yet | condrv/serial/`\Device\Input*` waits stay uncancellable (`docs/03` CUI-5) |
| Interrupt-driven device completion | none | deliberately absent (§5b) |

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

### b. Completion harvest on the idle/timer path — not interrupts

`VioTryPopUsed` (`drivers/virtio/virtqueue.c`) already exists as a non-blocking harvest and
is used by virtio-input. Drain from the idle path and the timer tick. **Do not add an
interrupt path in this work**: it buys latency (the axis Article 3 refuses), it drags in
the interrupt-versus-lock policy question (`docs/18` §6d) that does not otherwise arise
yet, and polling from idle already recovers all of the overlap. If a consumer ever
convicts the latency, it is a separate change against the same drain seam.

### c. FS/Io: park and pend

Route file read/write through the existing `IOP_PENDING_REQUEST` engine: park, return
`STATUS_PENDING`, complete from the drain point. The FCB and the page-cache page need
in-flight state so a second thread entering the same file finds it.

### d. Generalize the pended-request ownership rule

`kernel/io/io.h`'s G11 answer (§1.5) was written for npfs's parked listen. Make it the
device-independent convention, stated once, and assert it — every future pending verb
inherits it rather than re-deriving it. This is an Art. 11 one-authority move.

### e. What deliberately stays unbuilt

No completion-port file association (no consumer); no interrupt-driven devices (§5b); no
I/O scheduling, reordering, elevator or readahead (Art. 3 — correctness only); no
fine-grained locking (`docs/18` §3).

## 6. Re-entrancy is the actual work

The driver change is mechanical. The difficulty is that **an operation can now be in
flight while another thread enters the same object**, and a large amount of existing code
is lock-free *because that could not happen*. The archetype:

```c
/* fs/fat32/fat.c:676 */
/* Count free clusters off the in-pool FAT (a pure memory sweep: no
 * blocking, so it is atomic under the no-preemption model). */
```

There are 21 such "no preemption / uniprocessor" justifications across `kernel/`, `fs/`
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

**Determinism survives, because we choose the drain point.** Draining only at explicit
points preserves today's single-interleaving behaviour exactly; a knob that varies drain
aggressiveness gives a stress leg without making the default runs nondeterministic.
Neither the differential fuzzer's minimization nor the GUI-5 consistency-sweep deadlock
detector loses its premise (contrast `docs/18` §8, where the premise must be bought back).

The regression net already exists and is oracle-green: `tests/ntapi/sem_file/read_write.c`,
`sem_file/apc_completion.c`, `sem_pipe/async_listen.c`, `sem_pipe/cancel_sync.c`,
`sem_file/notify_change.c`, and the `sem_mm/file_coherence` mapped-view/read-write stress —
the last one being the direct guard on §6's re-entrancy.

### The win must be a verdict, not an inference

An implementation that pends correctly but never actually overlaps — depth still 1, drain
immediately after submit — **passes every semantic test above**, because it is
behaviourally today's kernel. Same failure shape as `docs/17` §8. Pin the win:

- maximum and mean in-flight request depth, emitted as a `[KTEST]` verdict under a
  workload that issues concurrent I/O;
- and/or wall-clock of a two-thread read workload against a committed budget.

## 9. Build order

1. **Pin the §7 decisions on the oracle** (Art. 5), before kernel code.
2. **The re-entrancy enumeration** (§6) — its own artifact, from the 21 justifications.
3. **virtio-blk per-request buffers + depth** (§5a), still submit-and-wait: no behaviour
   change, purely structural. Own commit.
4. **Drain point** (§5b) + the depth verdict (§8).
5. **FS/Io park + `STATUS_PENDING`** (§5c) and the generalized ownership rule (§5d).
6. **Widen cancellation** to the newly pended verbs; revisit the console-read gap only if
   a consumer convicts it.

## 10. Relationship to the other two strategy documents

- **`docs/18` (SMP)** lists this work as a hard prerequisite and defers to this document
  for the design.
- **`docs/17` (COW)** is independent of it. The one shared theme is §8's failure mode: in
  both cases a correct-but-inert implementation passes every semantic test, so both must
  pin their win as a machine verdict.
- **Net-1** (`docs/02`) should carry an explicit dependency on this document; today its
  entry does not mention that its transport assumption is currently unbuildable.
