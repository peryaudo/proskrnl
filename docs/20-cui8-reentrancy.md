# 20 — CUI-8 Re-entrancy Enumeration

This is the artifact `docs/19` §6/§9.2 requires **before** the code that makes re-entry
possible: the census of every place whose correctness argument is "nothing else can run
here", re-checked against the two facts CUI-8 introduces. It is written against the tree
at the commit that adds it; symbols are the stable reference, line numbers the courtesy.

## 1. The two new facts

- **F1 — a thread can block mid-FS-operation.** A data transfer parks the issuer
  (`KeWaitForSingleObject` on the request's event) instead of spinning in
  `VioSubmitAndPoll`, so another ready thread runs *while a FAT volume operation is
  half-done*. Every "atomic because no blocking" claim inside `fs/` and every caller
  that assumed a syscall's FS work was one indivisible step is exposed to this.
- **F2 — a completion drain runs outside thread context.** `IoDrainDeviceCompletions`
  is called from the timer tick (`KiUpdateClock`, dispatcher lock implicitly held) and
  from the idle loop. It is a third execution context that touches driver queue state
  concurrently-in-time with any thread the tick interrupted — including one that was
  mid-`MiAllocatePool`.

## 2. The five rules that answer them

Every BROKEN row below is repaired by one of these; the rules are stated once here and
asserted in code where statable.

- **R1 — the volume gate.** All fat32 `IO_VFS_OPS` entry points that can touch the
  disk, the FAT, or FCB/directory metadata serialize on `FAT_VOLUME.ioGate` (a
  synchronization event born signalled — a binary semaphore over existing dispatcher
  machinery; no new lock kind, `docs/18` §3). Internal fat32 functions never take it
  (no recursion); the cache-hot read path never reaches it (`cacheLoaded`
  double-check, R5).
- **R2 — the drain does almost nothing.** Drain context only harvests the used ring,
  stores each request's result, and sets its event (`KeSetEvent` under the dispatcher
  lock — the same wake the timer-expiry loop already performs). It never allocates or
  frees pool/pages (asserted: `KiInCompletionDrain` in `mm/pool.c`/`mm/phys.c`), never
  touches user memory, never calls into a filesystem.
- **R3 — no faultable user access under the gate.** A ring-0 fault on a user address
  unwinds to the service dispatcher's recovery frame *without running cleanup*
  (`kernel/syscall/uaccess.h`), which would leak the gate. All direct user copies in
  the data path happen before the gate is taken or after it is released — `rw.c`'s
  probes and `MiCacheRead`/`MiCacheWrite` sit outside `GetCache`/`WritebackRange`
  already; inputs a gated op consumes are captured to kernel memory first (the
  volume-label capture in `kernel/io/query.c`), and an op that fills a caller buffer
  in place (`QueryName`) stays ungated, which its non-blocking pure-memory body
  permits. The one legal user touch under the gate is `MiCopyToUserRangeChecked`
  (dir-watch completion reached from `FatReportChange`): the checked walk fails
  gracefully on a missing frame instead of faulting, so no unwind can occur.
- **R4 — the issuer's frame owns the request.** In-flight `VIO_BLK_REQUEST`s are
  caller-embedded (stack or batch array). No path — success, device error, cancel,
  thread termination — unwinds past an outstanding submission: the exits poll-drain
  their own requests to completion first. This is `docs/19` §5d's ownership rule made
  device-independent (the npfs statement in `kernel/io/io.h` is the origin).
- **R5 — in-flight state is findable.** `fcb->cacheLoaded` transitions only under the
  gate; the check-acquire-recheck shape means a second thread entering a cold file
  parks on the gate rather than double-loading, and a thread entering a hot file never
  parks at all.

The convicting instruments are `tests/ntapi/sem_mm/file_coherence_mt.c` (two threads,
one file: disjoint page ranges under a fixed-seed op mix, whole-file cross reads, an
event-serialized handoff phase with extend/truncate — "MT:" rows name the leg that
would catch a violation) and the kmt CUI-8 suite ("KMT:" rows), which can hold the
in-flight window open deterministically from kernel mode.

## 3. Directly broken by F1 — repaired by a rule

| Site | The claim | Verdict → repair |
|---|---|---|
| `fs/fat32/file.c` `FatEnsureCache` | *(uncommented)* whole-file sector loop, `cacheLoaded` set only after; implicitly atomic | **BROKEN** → R1+R5. MT: A parks mid-cold-fill, B reads the same file — without the gate B sees a half-filled cache as authoritative. |
| `fs/fat32/file.c` `FatWritebackRange` | *(uncommented)* sector loop over `cache.frames[]` + chain walk; implicitly atomic | **BROKEN** → R1. MT: A parks mid-writeback, B truncates/extends the same file — the chain walk crosses a moving cluster chain. |
| `fs/fat32/fat.c:893` `FatQueryVolumeInfo` | "pure memory sweep: no blocking, so it is atomic under the no-preemption model" | **BROKEN** (the `docs/19` archetype) → R1. MT: free-cluster sweep vs. B's extend allocating clusters mid-sweep. |
| `fs/fat32/fat.c:218` `FatWalkChain` | cycle bound sound because "the walk never blocks, so nothing else ever runs" | **BROKEN** as stated → R1 (walks happen under the gate; the ≤ chain-length bound stays as defence). MT: walk vs. concurrent relink. |
| `fs/fat32/file.c:139` zero-fill on extend | "zero-fill on disk immediately (Art. 3 immediate writeback)" — now a blocking loop inside set-EOF | **BROKEN** without R1 → R1. MT: extend parks mid-zero-fill, B reads the gap. |
| `kernel/syscall/uaccess.h:4-15`, `uaccess.c:2` | probe-then-copy: "present ⟺ accessible at the moment of the walk" | **ALREADY ANSWERED** — the header itself says the recovery frame, not the probe, carries the contract since M7; F1 widens the window, the mechanism holds. R3 adds the gate-safety corollary. MT: B unmaps A's read buffer while A is parked (the recovery frame turns it into `STATUS_ACCESS_VIOLATION`). |
| `kernel/io/file.c:576,643` transient rename/link handles | "Art. 3's no-preemption mandate closes the window… this outlives it" | **STILL TRUE** — written defensively for exactly this; the window stays closed because rename/link run under R1 and the transient handle is created/closed inside one gated op. KMT: cancel during rename leaves no transient handle behind (R4). |
| `kernel/cm/registry.c:510` | "node pointers stay valid without references: … nothing here blocks (Art. 3 cooperative kernel)" | **STILL TRUE** — Cm takes `CmpHiveMutex` around hive persistence (`hive.c:448`) and registry code never calls into fat32 data paths; no CUI-8 blocking point enters Cm node walks. Re-check if hives ever move onto the FAT volume. |
| `kernel/ps/thread.c:249` `PspParkCurrentThreadAndTerminate` | "safe only because nothing runs between the park and the switch" | **STILL TRUE** — that park is under the dispatcher lock; F1 blocking points are ordinary waits, not this path. KMT: terminate-with-request-in-flight exercises the neighbouring path (R4). |

## 4. Park/wake handshakes — re-checked against F1/F2

| Site | The claim | Verdict |
|---|---|---|
| `fs/npfs/pipe.c:14,103,143-144,478-479` | "nothing can slip between the condition check and the clear/park, so no wakeup is lost" | **STILL TRUE** — the check and the park both run in thread context with no blocking between them; F1 adds blocking only inside *fat32* ops, and F2's drain never touches npfs state. |
| `kernel/io/async.c:5` | "one dispatcher lock, no preemption: park and completion never interleave mid-update" | **STILL TRUE**, now load-bearing for a third completer: the drain wakes data-path waiters under the same dispatcher lock the engine already relies on. |
| `kernel/ke/wait.c:8`, `kernel/ke/apc.c:9` | wait/APC queues are plain state machines under the one lock | **STILL TRUE** — the drain readies threads via `KeSetEvent`→`KiWaitTest`, the same edge timer expiry already drives at tick time. No new entry point into either queue. |
| `kernel/ob/wait.c:66` `NtSignalAndWaitForSingleObject` | "no other thread can run between the signal and the wait's arming" | **STILL TRUE** — both halves under one lock hold; F1 does not enter Ob. |
| `kernel/io/completion.c:10,59` | packet FIFO under the dispatcher lock | **STILL TRUE** — `IopPostCompletionPacket` remains thread-context-only; the drain does not post packets (no port association exists, `docs/19` §5e). |

## 5. Lock-free reads and snapshots — re-checked against F1

These claims survive because the code in question never blocks *itself* and its
mutators never block mid-update; a mutator that now CAN block (an FS op) does so only
under R1, outside these structures.

| Site | The claim | Verdict |
|---|---|---|
| `kernel/ob/ob.h:11` (+ `namespace.c`) | Ob state touched only from thread context; plain code atomic between blocking points | **STILL TRUE** with a sharpened premise: Ob mutations never span a blocking point today, and CUI-8 adds no blocking inside Ob. The fat32 parse/create path *does* block inside `ops->Create` — but Ob's own bookkeeping around it (handle slot, header init) completes before/after, not across. KMT: two threads create/open the same fat32 name concurrently. |
| `kernel/ob/sync.c:380` | "no preemption: the check cannot go stale before the call" (semaphore limit) | **STILL TRUE** — check and call are adjacent under thread context, no blocking between. |
| `kernel/ps/query.c:870` two-pass process list | "no blocking between the passes, so the same list is seen" | **STILL TRUE** — the passes are pure memory sweeps; CUI-8 adds no blocking inside them. |
| `kernel/ps/thread.c:687,924` | target thread cannot be reclaimed between lookup and set | **STILL TRUE** — same shape: no blocking point between the two. |
| `kernel/ps/process.c:1360` sibling reaping | siblings reap themselves at ring-3 edges; `KeDelayExecutionThread` is the yield | **STILL TRUE** — more yields exist now (any file op), which this path tolerates by construction. |
| `kernel/init/verify.c:4,48,93,233` consistency sweeps | idle/lock-held sweep sees every thread parked at a blocking point — an atomic snapshot | **STILL TRUE and newly load-bearing**: threads now park mid-FS-op with a request in flight, and the sweep runs concurrently-in-time with the device. The sweep must not assert about in-flight FS state beyond what R4 guarantees (requests owned by parked frames). KMT: the sweep runs while a request is provably in flight. |
| `kernel/init/initrd.c:5`, `initrd.h:31` | RAM-disk cache needs no locking | **STILL TRUE** — initrd never reaches virtio; no blocking added. |
| `kernel/init/bootvid.c:54`, `panic.c:172`, `trace.h:28` | single-flag exclusion / panic-path soundness / reentrant trace lock | **STILL TRUE** — none sit on a new blocking path; the trace lock is take-under-cli, compatible with drain context. |
| `kernel/cm/hive.c:33` + `cm.h:140` | one hive mutation at a time via `CmpHiveMutex` | **STILL TRUE** — already a real lock, the pre-CUI-8 precedent for R1. |

## 6. F2 — what the drain context may touch

| Site | The claim | Verdict → repair |
|---|---|---|
| `kernel/mm/phys.c`, `kernel/mm/pool.c` | *(uncommented)* free lists mutated with no lock — sound because all callers were thread context | **BROKEN by F2** → R2. The tick can interrupt a thread mid-`MiAllocatePool`; a drain that freed pool there corrupts the list. Repair is prohibition, not locking: the drain frees nothing (`KiInCompletionDrain` asserts). KMT: drain runs at tick with allocator churn on the interrupted thread. |
| `drivers/virtio/virtqueue.c:6,86` | free list "always intact" because the driver is fully synchronous; `VioSubmitAndPoll` asserts `used id == head` | **BROKEN by design** (depth > 1) → per-request rework: terminated out-of-order free list, head→request cookie map, `used->idx` made volatile (the compiler may otherwise hoist the load in a drain loop — the spin loop only survived by accident of its asm barrier). KMT: N requests completing out of submission order. |
| `drivers/virtio/virtio.h:8-14` | "polling, uniprocessor, no-MSI-X driver… a consequence of this driver, not a kernel-wide rule" | **SUPERSEDED for blk** — the blk queue gains exactly one additional reader (the drain, under the dispatcher lock); input/serial keep the poll-and-nap shape (`input.c:17`, `condrv.c:24` unchanged). |
| `arch/x86_64/lapic.c:5`, `kernel/ke/irq.c` | the clock tick "advances time and readies threads but never context-switches" | **STILL TRUE and relied upon** — the drain readies threads, switches nothing; `KiPreemptAtUserReturn`/idle pick them up, exactly like timer expiry. |
| `kernel/ke/ke.h:185,193,267,278,283`, `sched.c:5,164,223`, `entry.S:13`, `gdt.h:6` | model statements (one lock = cli, one switch site, self-reaping, one PCR) | **UNCHANGED** — CUI-8 lifts nothing Art. 3 mandates; the drain lives inside the existing lock discipline. |

## 7. Boundary reports and simplicity statements (not atomicity claims)

`kernel/ps/query.c:1314,1482,1797,1805,1892` (uniprocessor facts the boundary reports —
unchanged, still one CPU); `kernel/mm/{pagecache.h:9, section.c:127,528, pecoff.c:23,
fault.h:3, kasan.c:10, pool.h:3}`, `kernel/cm/registry.c:38,1687`, `fs/fat32/fat.h:8`,
`kernel/io/{vfs.h:132, rw.c:10, io.h:13}`, `arch/x86_64/mmu.c:4,196` — statements of
the no-COW/no-eviction/immediate-writeback/one-pool mandates or of chosen simplicity.
CUI-8 changes none of them: writeback stays immediate (it just parks the writer), the
cache still never evicts, and view/read coherence stays structural because the frames
are still the same frames. The one nuance: "immediate writeback" now means *durable
before the syscall returns*, not *durable without yielding the CPU* — the fsck/torn-write
legs and `file_coherence_mt` hold the former, which is the only observable half.

## 8. What this enumeration commits the implementation to

1. R1-R5 are implemented in exactly the commits `docs/19` §9 orders (gate before the
   first park; drain rules with the drain; ownership rule with the pend).
2. `file_coherence_mt` lands green **before** the first park exists, so every MT row
   above is a regression guard, not a post-hoc check.
3. The kmt CUI-8 suite drives the KMT rows deterministically (drain suppression makes
   the in-flight window a controlled state, not a race).
4. Any future blocking point added to a path in §5's STILL-TRUE tables re-opens that
   row — the table is the checklist for the next milestone that adds one (Net-1's AFD
   is expected to; SMP re-opens every row, which is `docs/18`'s own §6).

## 9. Post-review addenda (PR #95)

The milestone PR's review convicted places where the rules above were applied too
narrowly to the milestone's *own new code*; each repair extends an existing rule:

- **R1 covered each FS op, not decisions spanning ops.** `NtWriteFile`'s
  append/extend placement was decided from a pre-park size snapshot and pushed
  through `SetEndOfFile` (which shrinks) — two concurrent writers truncated each
  other. Repair: `PrepareWrite` (`kernel/io/vfs.h`) resolves placement grow-only in
  one gate hold.
- **Teardown can land between one syscall's gated steps.** Delete-on-close cleanup
  runs when the last handle closes — including while another thread's write is
  parked between its ops on that file. Every re-enterable gated step now refuses
  `STATUS_FILE_CLOSED` off `entryDeleted` instead of asserting or resurrecting the
  freed slot.
- **Io-layer state sat outside the enumeration.** `FILE_OBJECT.currentByteOffset`
  is also mutated across parks: NT's file-object lock (`syncIoLock`,
  `KiAcquireEventGate`) now serializes synchronous-handle I/O — pinned by
  `sem_file/shared_handle_offset.c`.
- **R3's probes go stale across the data path's own parks.** Post-park copies
  re-probe with no park between probe and copy, so a sibling's unmap surfaces as
  `STATUS_ACCESS_VIOLATION` through the cleanup path; the recovery frame is a
  backstop again, never the only line.
- **Cancel vs. the §7 write-through invariant.** A landed cancel is honored only
  before the cache mutates; from `MiCacheWrite` on, the range goes out regardless
  (there is no dirty tracking to reconcile a cache/disk divergence later).
- **The gate's terminating-thread fallback must queue.** A try/yield retry loop
  starves against the holder under strict priority scheduling; the rundown park
  (`rundownWait`) makes every acquirer a queued waiter.

## 10. The independent re-sweep

§1–§8 were written alongside the implementation, so their premises are the
implementation's own. This section records a second sweep of `kernel/`, `fs/`,
`drivers/` and `arch/`, run against the branch at `33d024f` by readers who were not
permitted to read §1–§8 — so its rows are derived from the code rather than from this
doc's framing. It is kept separate from §9 because §9 records what the PR *review*
convicted; this records what a blind re-derivation convicted, and the two overlap in a
way worth preserving (§10.6).

**The sweep's base has moved.** Between `33d024f` and this commit, §9's repairs closed
four rows the sweep raised independently: the write-placement composition
(`eef8d5d`), `currentByteOffset` serialization (`d045fba`), the idle loop's stale
`inFlight` (`eb1612d`), and the gate's starving try/yield fallback (`43c7e14`). Those
rows are deliberately **not** restated below — a census that lists repaired defects as
live is worse than no census. What follows is only what was re-verified as still
standing at this commit.

### 10.1 One correction to §1 that §9 does not cover

**The blocking frontier is wider than F1 says.** F1 names the park inside a data
transfer. It omits that *closing a handle* parks: `IoFileObjectType.closeProcedure =
IopCloseFileObject` (`kernel/io/file.c:74`) → `ops->Cleanup` → `FatVfsCleanup` →
`FatAcquireVolumeGate`, and likewise `deleteProcedure` → `FatVfsClose`. Therefore
`NtClose`, `ObDereferenceObject` on any last reference, `ObpCloseAllHandles`, and
process exit are all blocking points.

This is why §3–§6 contain no Ob rows and no `NtClose` row: the frontier was drawn at
`fs/`, and Ob was never asked the question. It should have been — Ob is what invokes
the FS on teardown, so Ob is where the frontier actually is.

(§9's first bullet — R1 covering each op rather than decisions spanning ops — was
reached independently by this sweep as well. It is not restated; §9 states it, and
`PrepareWrite` repairs it.)

### 10.2 CONFIRMED and still live at this commit

| Site | The claim | Verdict → repair | Convicting interleaving | Test leg |
|---|---|---|---|---|
| `kernel/io/file.c:398` `IopCreateFile` → `FatVfsCreate` | R3 itself: *"All direct user copies in the data path happen before the gate is taken or after it is released"* | **BROKEN → R3a.** R3 enumerated `rw.c`'s probes, `MiCacheRead`/`MiCacheWrite`, the label capture and `QueryName`, and missed the create path — the most-used FS entry in the kernel. `e9a4436` repaired the *data* path and the label capture; `IopCreateFile` is untouched, so this row survives §9. | `fsPath = *attributes->ObjectName` takes the caller's ring-3 buffer for a `RootDirectory`-relative open, and `ObpLookupParseObject`'s contract (`kernel/ob/namespace.c:262-264`) says the remaining name points into the caller's buffer. That pointer is dereferenced by `FatResolveParent`/`FatLookup` **under the gate**, across a sector-read park. Thread B unmaps the page; A resumes, faults in ring 0 on a user address; `KiCallServiceGuarded` (armed for the whole service, `kernel/syscall/table.c:107`) unwinds without cleanup (`uaccess.h:78-82`). `FatReleaseVolumeGate` never runs. The gate has no owner, so **every later file op on the volume parks forever**. Ring-3 triggerable; unreachable pre-CUI-8. | Needed: kmt leg, spin bound 0 — one thread looping `NtCreateFile`, one unmapping the path page; the verdict is that a *subsequent* open on the volume still completes. |
| `kernel/ps/query.c:585-601` `PspMakeProcessSystem` | (commented) *"this handle value lands on the kernel stack first and only its VALUE is copied out through the probed caller buffer"* | **BROKEN → R7.** A §10.1 consequence. Repair is one line: move the deref after the store; the mint uses the current process's table and needs no reference. | `ObDereferenceObject(process)` (:587) can be the last reference → `PspDeleteProcess` → `ObpDeleteHandleTable` → a file close → **park**. B unmaps `buffer`; A resumes, mints the handle (:595), faults at the store (:601), unwinds. The side effects are already permanent: the process is system-marked, `PspLiveUserProcessCount` is decremented (possibly signalling global shutdown), and a `SYNCHRONIZE` handle to the shutdown event sits in A's table that A never learns of and never closes. | `sem_ps` leg where the target handle is the last reference to a dead process holding an open file, with a sibling unmapping the out-pointer. |
| `drivers/virtio/blk.c:88,405,407` `VioBlkDataBounce` | (uncommented) the one driver-global bounce page is exclusively held for the duration of a transfer | **BROKEN as an invariant, not yet as a defect → assert it.** | Every *production* caller reaches it through `FatReadSector`/`FatWriteSector` under R1, so the page is genuinely serialized today. What is broken is that a driver-global buffer's exclusivity is enforced entirely by a distant module with no local assert, and `tests/kmt/m6_blk.c` already calls the sector API with no gate at all. R1 is load-bearing for `drivers/` and neither file says so. | `ASSERT(VioBlkBounceOwner == 0)` at `VioBlkTransfer` entry — a second entrant panics loudly (Art. 12) instead of silently swapping payloads. |

### 10.3 Rules added

- **R3a — the gate may not see a user pointer, including the path.** R3's data-path
  clause extends to every argument reachable under the gate. `IopCreateFile` must
  capture `fsPath` into kernel memory before `ops->Create`, as
  `IopSetRenameInformation` and the volume-label capture (`kernel/io/query.c`) already
  do — the precedent existed and was not applied here. The FS entry points should
  assert no user address is reachable from their arguments.
- **R7 — no object dereference under the gate, and none before a user store.** A
  dereference can now run a whole FS teardown (§10.1). Under the gate it can re-enter
  a gated wrapper and self-deadlock on a binary semaphore; before a user store it
  leaves a probed pointer stale. Both are prohibitions with a stated assert, not
  locks.

### 10.4 What the re-sweep confirmed sound

Recorded because a census's negative results carry the same weight as its rows, and
because these were the properties most likely to be wrong:

- **R1's coverage is complete.** All 13 `IO_VFS_OPS` entries that touch disk, FAT, or
  FCB/directory metadata have gated wrappers. The two ungated shapes are deliberate
  and correct: `FatVfsQueryName` (non-blocking pure-memory walk) and the `GetCache`
  hot path (R5's double check).
- **R1 cannot recurse from within.** Every `FatVfs*Locked` is static with exactly one
  caller — its wrapper — and no fat32 code calls a gated wrapper. The only re-entry
  risk is outward, through an Io/Ob/Ps callback (§10.5).
- **R2 is airtight.** The drain's entire reach was re-traced: `VioHarvestUsed`, result
  stores, `KeSetEvent` → `KiWaitTest` → `KiUnwaitThread` → `KiRemoveTimer`/
  `KiReadyThread`. Nothing allocates, and the bracket cannot nest or leak because
  every drain caller runs with interrupts off.
- **R4 is intact.** `FatBatchFlush`/`FatBatchTransfer` were re-checked against every
  early return, error path and cancel break: no path returns past a non-empty batch,
  `count` increments only on a successful submit, and `VioBlkAwait` polls the request
  home when a dying thread's park is refused.
- **npfs survives F1/F2 whole.** No park between any condition test and its
  `KeClearEvent`; no npfs state reachable from the drain; listen-queue entries are
  unlinked before completion; cross-space IOSB writes use the checked copier.

### 10.5 Raised but NOT confirmed — leads, not findings

None of these was driven to ground, and none is addressed by §9. Listed so the next
reader starts here instead of re-deriving them.

1. **`FatReportChange` under the gate → self-deadlock.** `IopCompleteDirWatch`
   (`kernel/io/notify.c`) dereferences the watch's owner EPROCESS while the gate is
   held. If that is a last reference, `PspDeleteProcess` → `MiDeleteAddressSpace` →
   `MipDeleteSection` → `IopSectionBackingReleased` → `FatVfsSectionsReleased`
   re-acquires the gate the caller holds. R7 closes the shape regardless; what is
   unproven is whether the last-reference case is reachable in a shipped
   configuration. Needs an audit of EPROCESS reference holders.
2. **Directory enumeration is gated per entry, not per buffer**
   (`FatVfsReadDirectory`). A rename into a slot behind the cursor can drop a file
   from a listing or list it twice. Needs an oracle experiment first — NT's true
   enumeration-atomicity contract is not obvious, and this may be a `docs/03` entry
   rather than a bug.
3. **`CmpSaveHive` discards its mutex wait status**, and the hive write is now
   abortable mid-`NtWriteFile`. Both depend on whether an aborted wait can reach
   `KeReleaseMutex` unowned. Needs `kernel/ke/mutex.c` read against the abort path.
4. **The idle sweep vs. mid-FS parks.** §5 already flags `verify.c` as newly
   load-bearing. The sweep sharpened it to a state nobody has tested:
   `ObpUnlinkObjectName` runs *after* the parking `closeProcedure`, so a named object
   sits with `handleCount == 0` and `parentDirectory != 0` for the duration of an FS
   park. Whether `ObpVerifyNamespace` asserts on that combination is unknown — and a
   spurious sweep assert is a panic.

### 10.6 The methodological correction — amends §8.4

§8.4 makes §5's STILL-TRUE tables the checklist for the next milestone that adds a
blocking point. Necessary, not sufficient. Almost every row this sweep and §9's review
convicted is a **composition** — a value sampled before a park and used after, two
gated ops in sequence, a gate held across a callback into another department, a user
pointer carried into a gated region. None is a false claim at a single line, so a
site-by-site census walks past all of them however honestly it is done.

The checklist therefore gains a fifth question, asked alongside §1's two facts:

> **What spans more than one gated operation, and who guarantees that span?**

Two procedural notes. First, §9 and §10 were produced independently and convicted four
of the same rows — that agreement is the strongest evidence available that the method
finds real defects rather than plausible ones, and the disagreement (this section's
three survivors) is where the value was. Second, §1–§8 were written by the same hands
as the implementation, and the sweep that convicted them was blind to them by
construction. That blindness is the active ingredient: a reviewer who has read the
census re-derives the census. Any future amendment should be produced the same way.
