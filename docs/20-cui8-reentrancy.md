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
