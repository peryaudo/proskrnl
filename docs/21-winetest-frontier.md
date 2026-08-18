# CUI winetest frontier — the plan for closing it

> Status: **live**. This document is the plan and the record for the
> non-GUI winetest gate (`tests/run/run.sh winetest`,
> `tests/winetest/manifest.txt`). Every claim here is a measurement, and
> where the author could not verify something by reading, §7 says so
> instead of guessing. Read `docs/09-constitution.md` before executing any
> item — the per-item "risk to an article" notes are the point of this
> document, not decoration.

**Where the numbers live.** Per-pair failure counts and their triage live
in `tests/winetest/manifest.txt`, above each commented-out pair, and they
are re-measured whenever a pair is touched. This file does NOT duplicate
them: it holds the work items, the article risks, and the decisions. If a
count here and a count there disagree, the manifest is right.

---

## 0. Scope

The winetest gate is COVERAGE, not curation (`docs/03` "M10 winetest
notes"; the manifest header). Everything below is scoped to pairs that are
**green on the pinned oracle and red on proskrnl** — i.e. real gaps under
Art. 6. A pair that fails on both convicts nothing and is excluded with its
reason, not worked.

---

## 1. The one structural fact that shapes the whole plan

Art. 12 arms `STATUS_NOT_IMPLEMENTED` as a **kernel panic** for every
ring-3 syscall, with no exemption. The winetest suites are written the
other way round: they *tolerate* a refusal and move on. The canonical
instance is `third_party/wine/dlls/kernel32/tests/thread.c`,
`test_thread_info()` — a class sweep that does

```c
status = pNtQueryInformationThread(thread, i, buf, info_size[i], &ret_len);
if (status == STATUS_NOT_IMPLEMENTED) continue;
if (status == STATUS_INVALID_INFO_CLASS) continue;
if (status == STATUS_UNSUCCESSFUL) continue;
```

over every class. On the oracle that loop skips the classes Wine genuinely
refuses. On proskrnl the same answer stops the machine.

**Three consequences every work item inherits:**

1. **"The oracle also refuses" is never a resting place.** For a swept
   class, proskrnl must answer *either* the implemented value *or* a
   specific NT failure.
2. **The specific NT failure is a behaviour, and it needs a pin.**
   `STATUS_INVALID_INFO_CLASS` / `STATUS_INFO_LENGTH_MISMATCH` /
   `STATUS_INVALID_DEVICE_REQUEST` are implementations, pinned like
   anything else. Where the oracle refuses, the pin goes in a
   `beyond_oracle { }` block naming the Microsoft page it is written
   against.
3. **This is the difference between a work item and a frozen hole.** A
   `tests/ntapi` case asserting `STATUS_NOT_IMPLEMENTED` fails G12
   outright, and so does any `KiPinnedNotImplemented`-shaped escape. If an
   item cannot be finished it stays red — it does not get pinned.

This was item **W1** and it is **DONE**: the refusal split is in
`NtQuerySystemInformation`, `NtQueryInformationThread`,
`NtSetInformationThread` and `NtQueryInformationProcess`. A class number
outside the enum answers `STATUS_INVALID_INFO_CLASS` (an implementation,
pinned by `tests/ntapi/sem_ps/info_class_range.c`); a class inside it that
is unbuilt keeps `STATUS_NOT_IMPLEMENTED`, names itself on serial, and
stays fatal. Bounds come from each enum's own `Max*InfoClass` sentinel in
`abi/`.

---

## 2. The work items

Commit shape for every item, per G13: **(1)** the `tests/ntapi` pin
(oracle-green, or `beyond_oracle` with its MS citation) → **(2)** the
kernel change + its `docs/03` note → **(3)** `abi/` regen if any constant
moved (`/gen-abi`, never hand-typed) → **(4)** the manifest bookkeeping.
The pin commit precedes the kernel commit in history, always.

Items are listed roughly by leverage. Their per-pair counts are in the
manifest.

### W2 — The query surfaces (**DONE**)

`NtQueryInformationThread`, `NtQuerySystemInformation`,
`NtQueryInformationProcess`, `NtPowerInformation`. Landed across several
sessions; `kernel32:thread`, `kernel32:power` and the fixed-class half of
`ntdll:info` are green.

Two findings worth carrying forward:

- **`KeNumberProcessors` is the one statement of the processor count**
  (`kernel/ke/ke.h`). Under Art. 3's uniprocessor mandate a one-bit
  affinity mask is the TRUTH, not a placeholder — which is what separates
  it from the fabricated answers G12 forbids.
- **`OBJECT_TYPE` grew an optional `mapAccess` hook**, applied inside
  `ObpMapDesiredAccess` (the one grant site). But the limited right is NOT
  a skeleton key: only `ThreadBasicInformation`, `ThreadTimes`,
  `ThreadAmILastThread` and `ThreadPriorityBoost` are readable through a
  `THREAD_QUERY_LIMITED_INFORMATION` handle. Classes whose VALUE needs no
  thread state still owe the check — a class that answers without
  validating answers a caller that was never entitled to ask, and only a
  test opening a deliberately weak handle can see it.

### W3 — The path and name surface (**DONE**)

`ntdll:path`, `ntdll:directory` (to its FAT floor), `kernel32:path` and
`kernel32:drive` are green.

The last piece was NT path-component syntax: NT does not TIDY a path, it
REFUSES a malformed one. `FatValidateNtPath` transcribes the oracle's
component loop (the block at the head of `lookup_unix_name`,
`dlls/ntdll/unix/file.c`) and runs once over the whole path before the walk
starts. Position was the content: a per-component check inside the walk
cannot see an empty component, because by then the walk has already decided
whether an empty tail means "open this directory" or "malformed".

Pinned by `tests/ntapi/sem_file/nt_path_syntax.c`.

### W4 — The completion legs

**W4a — the ioctl APC leg (DONE).** `IopIoctlApcUnsupported` is gone.
`NtDeviceIoControlFile`/`NtFsControlFile` allocate the completion APC before
the verb runs, through the same `IopPrepareCompletionApc` engine `rw.c` and
`notify.c` use — so a verb that pends cannot fail to complete later for want
of memory, and there is no second `KAPC` allocation site (Art. 11). Pinned by
`tests/ntapi/sem_pipe/listen_apc.c`.

The pended path was the interesting half and it resolved more simply than
this item expected: the APC block **moves into the `IOP_PENDING_REQUEST`**,
and `IopCompletePendingRequest` queues it to the **issuer** after the IOSB is
written and the event signalled. That needs no new bookkeeping because npfs
already funnels *every* way a park can end — a client attaching,
`NtCancelIoFile`, the owner's cleanup — through that one function, so "queued
or freed exactly once" falls out. The single path that neither pends nor
completes (a refusal that never wrote the IOSB) frees the block explicitly.

- **G14 was the predicted risk and it did not materialise.**
  `blocking_frontier.py --check` is clean: `IopQueueCompletionApc` reduces to
  a list insert, so completing from a drain cannot park. No frontier row, no
  re-opened `docs/20` §8.4 table.
- **G11 is where this item nearly shipped a use-after-free, and gate-check
  caught it, not a test.** Queueing the APC to `IOP_PENDING_REQUEST.issuer`
  turned a field that had been *compared and never dereferenced* into one
  that gets read and inserted into — while the request held **no reference**
  to that thread. `docs/03` "CUI-3 SCM notes" records that a pending listen
  is **not** swept at its issuer's exit, so the thread can die with the
  request still parked and a later client connect would complete into freed
  pool. The fix is the one `IOP_DIR_WATCH` already uses: hold a referenced
  `ETHREAD` (`issuerObject`) for exactly as long as the request can queue to
  it. The lesson generalises — *changing what a field is used for changes
  what it must own*, and no assertion in the pin could have seen it.

**What it revealed, and what then closed.** `ntdll:pipe` ran through
`test_overlapped` into the completion tests and surfaced two things that had
never been reached — and both are now built too:

- `pipe.c:413`: an ioctl refused **on the spot** still leaves the caller's
  completion event CLEAR with the IOSB untouched, which the returned status
  alone cannot satisfy because the test reads event and IOSB together.
  Routed through `IopAbandonRequest`, the authority the transfer paths use.
- class 41, `FileIoCompletionNotificationInformation`, in both directions —
  per-**handle** state on the `FILE_OBJECT` — with
  `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` honoured in `IopCompleteTransfer`.
  The oracle refuted the obvious guess here: the mode bits **accumulate**, a
  second set ORs in, and nothing can clear one.

Both pinned by `tests/ntapi/sem_pipe/ioctl_event.c`.

**`ntdll:pipe` no longer panics anywhere**, and the completion-packet rules
behind that are built too: `ioctl.c` now completes through `rw.c`'s
`IopCompleteTransfer`, so an ioctl posts a packet exactly as a transfer
does, and `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` is honoured. That takes the
pair's five remaining assertions to **zero**
(`tests/ntapi/sem_pipe/completion_packet.c`).

**The flag's axis is the part worth carrying forward, because its NAME
misleads and its failure mode is a hang.** The packet is skipped when the
call did not **return `STATUS_PENDING`** — not when it succeeded. The
oracle's guards carry no status term at all (`server/fd.c`
`add_fd_completion`'s `req->async ||`, `server/async.c` `async_set_result`'s
`async->pending ||`); the `!NT_ERROR` sitting beside the second is the
separate outer question of whether to signal completion at all. Keyed on
`NT_SUCCESS` inside `IopCompleteTransfer` — which runs *before*
`IopAsyncReturnShape` converts success into pending — an async port-bound
handle would answer `STATUS_PENDING` and post nothing, hanging
`GetQueuedCompletionStatus` forever. So the caller passes the answer down
(`IopWillReportPending`, which is `IopAsyncReturnShape`'s own predicate).

**The pair's verdict still does not move, and that is not a hedge.** Zero
failed assertions and then the same wedge reads `FAIL (timeout)` exactly as
five-and-a-wedge did.

**W4c — the pended packet (DONE), the wedge it was predicted to be (it is
not), and the pended READ that the wedge actually was (DONE).** This document said the wedge's "shape is known":
`IopCompletePendingRequest` never posting a packet, while the rule above says
a request that PENDED always does. The defect was real and is now fixed —
`IopCompletePendingRequest` posts through `rw.c`'s `IopPostRequestPacket`,
the same site the inline tail uses, so there is one statement of "which port"
and "what value" rather than two; the `IOP_PENDING_REQUEST` holds a
**referenced FILE_OBJECT** and reads the port at COMPLETION rather than
capturing it at issue, because the oracle re-reads
(`add_async_completion`'s `if (async->fd && !async->completion)`) and that is
measurable: binding a port *after* an async listen has pended still posts its
packet. `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` never applies here and a
CANCELLED listen posts its cancel — the guards are `req->async || …` and
`async->pending || !NT_ERROR(status)`, so pendedness alone satisfies both.
Pinned by `tests/ntapi/sem_pipe/pending_packet.c`.

**The prediction was still wrong about the wedge, and the correction is the
more valuable half.** With the packet built, `ntdll:pipe` is bit-for-bit
where it was: zero failed assertions, `FAIL (timeout)`, same place. The wedge
was then measured rather than inferred, with a two-runner probe: **npfs data
reads never pend.** `NpfsRead` (`fs/npfs/pipe.c`) parks the calling thread in
`NpfsWait` on an ASYNCHRONOUS handle instead of answering `STATUS_PENDING`,
and `pipe.c:1578` issues exactly that read on an empty pipe through an
overlapped handle, then satisfies it from the SAME thread at `:1583`. The
oracle returns `0x103` immediately with the IOSB untouched; proskrnl does not
return at all. Recorded in `docs/03` "CUI-8 async notes".

**The pended READ is now BUILT, and it unwedged three pairs at once.** The
estimate above was right about the parts and wrong about the size: the
pending-request engine grew the buffer/length legs `kernel/io/io.h`
anticipated (`docs/19` §5d), the completion copies into the owner's address
space through `MiCopyToUserRangeChecked` immediately before the IOSB, and the
FILE_OBJECT's signalled state did join the contract. All of it is one commit
in `kernel/io/{async,rw,notify,query}.c` + `fs/npfs/pipe.c`, pinned by
`tests/ntapi/sem_pipe/pended_read.c` (ten cases, oracle-green first).

- **`ntdll:pipe`**: the 5-minute timeout is gone. The pair now runs about
  five minutes further and PANICS at `NtQueryInformationFile` class 8
  (`FileAccessInformation`) with **23** failed assertions behind it. `0 → 23`
  is §4 trap 2's arithmetic — none of the 23 is new, every one is past
  `pipe.c:1578` where nothing had ever executed.
- **`kernel32:virtual`**: was `FAIL (timeout)` stopping at `virtual.c:1465`,
  one function short of `test_write_watch` (whose pipe leg is the same
  same-thread overlapped read). It now runs to the END of the module and dies
  at an unhandled `0xc0000005` after `:4735`, with **4** failures — the
  `:1465` todo floor plus `test_far_regions`' `DuplicateHandle → 6` and its
  two dependents.
- **`kernel32:pipe`**: the overlapped echo server's own five
  (`:1059/:1077/:1083/:1101/:1106`) are gone. `28-34 → 29`, still killed by
  the test's own 20 s watchdog — and since that watchdog is a DEADLINE, the
  total moves with where it cuts, so only the per-line breakdown compares.
  **And the block's diagnosis of the rest was refuted**: it called the 5×N
  client-open cluster "a consequence" of those five; the five are fixed and
  the cluster stands.

**Two rules came with it that nothing had convicted before**, both pinned in
the same file and both worth carrying forward because each reads as a bug:

- **Exactly ONE of the caller's event and the FILE OBJECT is signalled at
  completion**, and the object is cleared at park *unconditionally*
  (`server/async.c` `queue_async` + `async_set_result`). So a read that
  pended WITH an event leaves the handle down through its own completion.
  The other half of that rule — any INLINE completion on the handle puts it
  back UP, with the read still parked (`pipe.c:1678`) — was built, measured,
  and **deliberately removed**: condrv borrows the file object as its own
  readiness signal, so re-signalling from the completion tail spins
  conhost's poll loop and cost `kernel32:virtual` most of its run. One
  assertion, recorded in `docs/03`, and the exit is an event of condrv's own.
- **`FILE_SKIP_SET_EVENT_ON_HANDLE` freezes that state in both directions**,
  where `docs/16` had it filed as unbuilt. The order is the content: the
  oracle clears the handle *before* recording the bit, and its
  `set_fd_signaled` is a no-op afterwards, so the one clear that ever happens
  is that one. Written the other way round the clear is a no-op and the
  handle stays signalled forever.

**The trap this item actually paid, and it is worth more than the code.**
`STATUS_PENDING` was already a FINAL status for one device — `condrv`'s
server fetch returns it to mean "nothing deliverable" — so reading it as
"the device parked a request" in `NtReadFile` leaked conhost's bounce buffer
on every poll of an idle console. What that looked like was **not** a pipe
bug: `cui9`'s process ceiling fell 319 → 79 with per-process memory up 3×,
because the pool exhaustion behind the leak stopped the COW image masters
from being built. Three behaviour-level bisections all came back "still
fails" before a file-level one found it. The fix is NT's own:
`IoMarkIrpPending` as a FLAG on the request (`IO_CONTROL_CONTEXT.pended`),
set by the ENGINE at the one place a park is created, so no device can park
and forget — and no status can be read for two things. **The lesson
generalises past this item: a status that a second producer already uses for
something else is not a channel, and the failure will surface somewhere with
no visible connection to the change.**

**What is deliberately NOT built** (Art. 5 — no consumer convicts it): an
asynchronous WRITE over quota still parks its caller.

**W4d — the BLOCKING request's signalled state is DONE** (`ntdll:pipe` 23 →
**12**), and this document's estimate was right for once: it predicted 12 in
one step and the step was 13, because `:1678` came with it instead of staying
a cost. A request that PARKS ITS CALLER owes the caller's event and the file
object exactly what a pended one does — the oracle queues a blocking async
through the same code, and `async->blocking = !is_fd_overlapped( fd )`
(`server/async.c` `create_async`) decides only how the CALLER waits. So the
event is reset at issue, the handle goes down for the duration, and exactly
one of the two goes back up at the end (`kernel/io/async.c`
`IopBeginBlockingRequest` / `IopEndBlockingRequest`, driven from `rw.c`'s
device branch and its flush; pinned by
`tests/ntapi/sem_pipe/blocking_signal.c`).

Four things worth carrying:

- **The one-assertion "deliberate cost" at `:1678` was not a cost, it was an
  UNDECLARED exception charged to every other device.** condrv borrows the
  file object as its own readiness signal, so the Io layer paid for that by
  never re-signalling ANY file object on an inline completion. Saying it out
  loud instead — `FILE_OBJECT.deviceManagedSignal`, tested inside the one
  transition every producer already goes through (`IopFileSignalSuppressed`,
  which `FILE_SKIP_SET_EVENT_ON_HANDLE` was already using) — removed the
  exception and the assertion together. **A deviation whose reason is one
  device is a property OF THAT DEVICE; recording it as a rule about the
  layer makes every other consumer pay.** The `todo_proskrnl` in
  `sem_pipe/pended_read.c` reported "unexpectedly passed" the moment it
  landed, which is the whole reason it was a tag and not a dropped case.
- **`:1753` is a blocking FLUSH, not a read**, and the manifest block had
  guessed a write. `NtFlushBuffersFile` has no event parameter at all, so it
  can only ever take the file-object arm — which is why the rule had to live
  in an engine both `rw.c`'s transfers and its flush could call rather than
  in the transfer tail.
- **"Did it park" is a real question with a cheap engine answer.** The three
  outcomes differ only for a FAILING request: one that was QUEUED reaches the
  oracle's signal block even when it fails (`async->pending ||
  !NT_ERROR(status)`) and takes the same event-or-handle arm a success takes
  — *a failing read signals the caller's event* — while one refused above
  `queue_async` reaches nothing and leaves the handle as it found it. Both
  measured (`blocking_signal.c` cases 5–7, and the first draft pinned neither).
  `KTHREAD.syncIoParked` is set by `IoWaitCancellable`, the one place the Io
  layer's own blocking park happens, so no device has to remember to say so —
  the same argument `IO_CONTROL_CONTEXT.pended` made for the pended half.
- **The event reset and the handle clear are separate statements in the
  oracle and are merged here on purpose**, and that merge is where BOTH of
  gate-check's findings landed. `create_async` resets the event a frame above
  `pipe_end_read`'s state checks; `queue_async` clears the fd below them. The
  split shows only for a request the device refuses without parking, and
  `IopRequestRefused` restores the handle for exactly that — one place rather
  than a boundary every device has to know. **"Restores" is the load-bearing
  word and the first draft wrote "signals"**: a handle can already be DOWN
  when the refused request arrives (the previous read completed through an
  event), and every case measuring a refusal against a fresh, born-signalled
  handle passes either spelling. The other finding is the same shape one
  direction over — the WRITE tail's unconditional `IopAbandonRequest` reset
  the event `IopRequestFailedParked` had just set, so reads got the rule and
  writes got its inverse, with no case in the pin on the write side at all.
  **Both were found by reading the diff against its own stated rule, not by a
  failing assertion**, which is now the fourth item in this document with that
  provenance; each has a case in `blocking_signal.c` now.

**The methodological lesson, third instance of §4 trap 4 in this item.** A
predicted cause written from the code was checked, built, and turned out to
be a real bug that was not the reported symptom's cause. The cheap step that
settled it was a throwaway `tests/ntapi` probe run on BOTH runners — three
minutes — not more reading. Predict from the code, but never write the
prediction into a triage block as though it had been measured.

**W4b — change-notify: DONE.** `ntdll:change` and `kernel32:change` are both
green. Three rules landed, all pinned:

- the completion FILTER belongs to the HANDLE, not the call — the first arm
  fixes it and every later arm reuses it (the server's "assign it once",
  `sem_file/notify_sticky.c`);
- an error completion writes the IOSB when the watch carries no event
  (same pin);
- the whole notification STATE belongs to the handle, not the request
  (`sem_file/notify_queue.c`) — which closed the `docs/03` CUI-5 deviation
  rather than working around it.

**The old block here was wrong about the diagnosis, and about the size.** It
said 33 failures in "three separate producers" — a rename emitting one record
where two were owed, directory create/remove "not reported at all", and
unwritten `Internal`/`InternalHigh`. Re-measured, the pair had **14**
failures, directory create and remove WERE reported, and all fourteen were one
subject: the notification state lives on the DIRECTORY HANDLE
(`server/change.c`, `struct dir`), and proskrnl kept it per-request. Changes
queue on the handle whether or not a watch is parked; a later arm drains the
whole queue into one chained completion. The rename's second record was not a
missing producer — `fs/fat32` emitted it all along — it was a one-shot watch
consuming the first and dropping the second. `Internal`/`InternalHigh` were
not unwritten either; they were written with the wrong answer, because
`want_data` is sticky too and the handle in question had first been armed with
a NULL buffer.

**The lesson is §4 trap 4 one level up.** Every one of those three "separate
producers" was a real observation of a symptom, and grouping them by symptom
produced three work items where there was one cause. The block was written
from the failure TEXT; the cause was only visible in the server's data
structure.

**A stale pin fell out of it, and it is worth recording how.**
`sem_file/notify_change.c` carried the subtree case in a `beyond_oracle`
block, on the finding that "the pinned Wine's recursive inotify watch never
delivers in the oracle environment". It delivers fine. That handle had simply
been armed non-recursive earlier in the same test, and the subtree flag is
sticky — so the measurement was real and its explanation was invented. Moved
to `sem_file/notify_queue.c` on a fresh handle, where it is oracle-green and
no longer beyond anything.

### W5 — Mm: placeholder reservations (**DONE**) and `SEC_RESERVE` sections (**DONE**)

The placeholder half is built: `MEM_RESERVE_PLACEHOLDER` /
`MEM_REPLACE_PLACEHOLDER` on `NtAllocateVirtualMemoryEx` and
`MEM_PRESERVE_PLACEHOLDER` / `MEM_COALESCE_PLACEHOLDERS` on
`NtFreeVirtualMemory`, pinned by `tests/ntapi/sem_mm/placeholder.c`. A VAD
carries the oracle's own two bits (`MI_VAD_PLACEHOLDER`,
`MI_VAD_FREE_PLACEHOLDER`), and the pair is not redundant: the FREE bit says
the range is an empty placeholder *now*, the other says it is a real
allocation that *came from* one, and only the second can be released back
into a placeholder. Nothing else can tell them apart — a placeholder and a
`PAGE_NOACCESS` reservation report identically through
`MEMORY_BASIC_INFORMATION`.

**The claim this item used to make was wrong, and the way it was wrong is
the lesson.** It said placeholders were "the only thing standing between
`ntdll:virtual` and green", on the strength of the pair showing zero failed
assertions before its panic. That zero was an artefact of the panic itself:
the process stopped on page one, so nothing behind it had ever been counted.
With the panic gone the pair reaches its end and reports **1199** failures,
1102 of them the thread-STACK contract (`docs/21` has no item for it yet; the
manifest block has the triage). **A crash count is not a failure count**, and
this document should not treat "zero assertions before the stop" as evidence
about anything past the stop again — the same reasoning applies to every
other panicking pair listed here.

**`MemoryRegionInformation` is DONE** (`MiQueryVirtualMemoryRegion`, pinned
by `tests/ntapi/sem_mm/region_info.c`), which took `ntdll:virtual` from 1199
to **1129** — all 70 of the class's assertions. It is the same VAD walk
`MiQueryVirtualMemoryBasic` does, asked a different question, so it extends
that engine rather than adding one. Three parts of it are not guessable from
the class name and were transcribed from the oracle
(`dlls/ntdll/unix/virtual.c` `get_memory_region_info`) and measured:

- a **free address is a refusal** (`STATUS_INVALID_ADDRESS`) where
  `MemoryBasicInformation` describes the hole — and the caller's buffer is
  left untouched on it, which is a separate promise from the status;
- the **length rule is stated in the struct's own field offsets**, not as one
  size: short of `CommitSize`'s offset is `STATUS_INFO_LENGTH_MISMATCH`,
  anything from there up succeeds and fills what fits — and `ReturnLength` is
  the WHOLE struct however short the buffer was;
- **`CommitSize` counts a MAPPED view's pages only when they are write-copy**,
  while a private allocation's every committed page counts. The same section
  mapped `PAGE_READONLY` reports 0 and mapped `PAGE_WRITECOPY` reports the
  whole view. That one is why the pin covers both mappings: the read-only
  case alone would have "passed" an implementation that just summed committed
  pages.

`RegionType` is reported as **zero, every bit** — the oracle sets it to 0 with
a FIXME and the winetest asserts each flag clear even for a mapped view, so
that is a measured answer and not an unfilled field.

**`MemoryImageInformation` is DONE too, and it closes the region cluster**
(`MiQueryVirtualMemoryImage`, pinned by `tests/ntapi/sem_mm/image_info.c`).
The visible move is one assertion — `ntdll:virtual` 1128 → 1127 — and the
measurement behind it is worth more than the number: `:3095`'s `win_skip`
returned early out of `test_query_image_information`, and the **58 assertions
it was hiding all pass** (3699 tests executed before, 3757 after, no new
failure). That is §4 trap 2 with the unusual outcome — the body behind an
early-out was already sound — which is only knowable by removing the early-out.
(The manifest's "1129" did not reproduce either: the merge base measures 1128
on this box today with the same binary.)

Three rules came from the oracle (`dlls/ntdll/unix/virtual.c`
`get_memory_image_info` plus `server/mapping.c`
`DECL_HANDLER(get_image_view_info)`) and none follows from the class name:

- a **mapped-but-not-image address is a SUCCESS with an all-zero struct**, not
  a refusal. A private allocation, a data view and a pagefile view all answer
  that way; only a FREE address refuses. An implementation that refused
  everything non-image passes every image case and fails only this one;
- the struct is **zeroed before the lookup**, so the caller's buffer comes back
  zeroed even on the `STATUS_INVALID_ADDRESS` refusal — the exact opposite of
  `MemoryRegionInformation`, which leaves every byte intact on its. The pin
  first asserted the region class's rule here and **the oracle refuted it**;
- an address above the user range is `STATUS_INVALID_ADDRESS`, where the region
  class answers `STATUS_INVALID_PARAMETER` for the same address: the oracle's
  fall-back folds every basic-info error into one status. Reusing the region
  class's range check verbatim fails exactly this assertion and nothing else.

**One field the two runners are allowed to disagree on, and it is deliberate.**
The oracle writes `ImageSigningLevel = 12` for every image view
unconditionally; proskrnl leaves it 0, because nothing here validates a
signature and 12 would be a claim about a check that never ran. The winetest
accepts either at all five of its image queries, so 0 is inside the boundary's
own tolerance rather than a divergence — the pin asserts the PAIR and says so,
and `docs/03` carries the trade. `ImagePartialMap` stays clear for a different
reason: `MipMapImageView` maps the whole `SizeOfImage` whatever view size is
asked for, so no view this kernel produces is partial. That accepted-and-
ignored view size is itself an unbuilt case — but it is unbuilt on **both**
sides (the winetest wraps its `size == 0x4000` and `ImagePartialMap`
assertions in `todo_wine`), so the bit is an accurate report of the views that
exist rather than one nobody computed. When partial image views are built, the
bit is part of that item, not this one.

**The capability probe it handed back is DONE too** (`ntdll:virtual` 1127 →
**1126**). `ntdll:virtual:3339` was W6's shape a second time:
`NtSetInformationProcess(ProcessManageWritesToExecutableMemory)` **succeeded**
on proskrnl, so the test concluded it was on an ARM64EC host and skipped the
whole of `test_exec_memory_writes`. Both classes — process 83 and thread 48 —
now answer `STATUS_NOT_SUPPORTED`, the pinned oracle's own off-ARM64 arm
(`dlls/ntdll/unix/process.c` / `unix/thread.c`, whose entire non-`__aarch64__`
body is that one return). Pinned by `tests/ntapi/sem_ps/manage_exec_writes.c`.

Three things it settles:

- **The refusal is about the MACHINE, not the arguments, and that ordering is
  the pinnable part.** It precedes every check the ARM64EC arm makes, so a
  wrong length, a wrong `Version`, the mutually-exclusive flag, a NULL buffer
  and a junk handle all get `STATUS_NOT_SUPPORTED` — never the
  `INFO_LENGTH_MISMATCH` / `REVISION_MISMATCH` / `INVALID_PARAMETER` that the
  same inputs get on ARM64EC (`virtual.c:3527-:3554`). An implementation that
  validated first would pass the probe and fail the matrix; the pin measures
  the matrix.
- **The hidden cost was zero, and this is the trap-2 shape with the OTHER
  answer.** An early-out hides its body, so removing one is the only way to
  learn what is behind it — here the body is `#ifdef __aarch64__`-shaped on
  both sides, so the test now returns at the same point for the right reason.
  3757 tests executed before and after, one failure fewer, one skip fewer. The
  cost of a lying probe is not always a hidden test body; sometimes it is only
  the lie.
- **Where the defect lived is the generalisable half.** Neither class was
  parsed, dropped or stubbed: they fell into `NtSetInformationProcess`'s
  **accept-as-a-no-op default arm** (`docs/16` "The one inverted case"). That
  arm is safe exactly while a class's answer carries no information, and this
  class's answer IS the information. So the rule to carry is narrower and
  sharper than "sweep for dropped words": **a no-op success is a fabricated
  answer whenever the caller reads the STATUS rather than a later query.**

**The zero_bits cluster on the mapping path is DONE** (`ntdll:virtual` 1126 →
**1115**, eleven assertions at `:1517`/`:1530`). `NtMapViewOfSection` validated
`zero_bits` and then never passed it to placement; it now hands
`MiZeroBitsLimit(zeroBits)` to `MiMapViewOfSectionEx` as `limitHigh`, i.e. the
same bounded-placement mechanism `MEM_ADDRESS_REQUIREMENTS` uses, so there is
one ceiling engine rather than two (Art. 11). Pinned by
`tests/ntapi/sem_mm/map_zero_bits.c`.

**This is the THIRD accepted-and-dropped input in this one pair**, after
`MEM_EXTENDED_PARAMETER_EC_CODE` (W6) and the two capability classes above —
and the first of the three that a status table could never have shown, because
the syscall's answer was `STATUS_SUCCESS` and correct in every field. Only an
assertion about WHERE the view landed can see it. The sweep for
accepted-and-dropped words is now the best-evidenced hunt in this document by
some distance.

Three things it settles, none guessable from the argument's name:

- **The invalid band is not the allocation path's band.** `NtMapViewOfSection`
  refuses only 22..31, so `33` — which `NtAllocateVirtualMemory` refuses with
  `STATUS_INVALID_PARAMETER_3` — is here a legal MASK with a 63-byte ceiling and
  answers `STATUS_NO_MEMORY`. An implementation that reused the allocation
  path's validation passes every other case and fails this one.
- **A named base keeps the constraint**, where the allocation path drops it. The
  oracle passes `get_zero_bits_limit( zero_bits )` down unconditionally, so
  `map_view` tests the view's whole EXTENT: based under the ceiling, ending above
  it, is `STATUS_CONFLICTING_ADDRESSES`. And the two halves of `map_view`
  disagree about the ceiling by one byte — the search uses it inclusive
  (`end = limit_high + 1`), the named-base guard exclusive
  (`base + size > limit_high`) — so a named view whose LAST BYTE is exactly the
  ceiling is refused. `MiRangeWithinLimits` transcribes that rather than tidying
  it, and the pin measures it: the first draft asserted the inclusive reading.
- **The IMAGE arm needed the limits too, and gate-check is what said so.** No
  winetest assertion reaches it and the pin as first written did not either —
  the review found a boundary change (`MipMapImageView` newly bounded) landing
  unmeasured, which is a G5 failure however defensible the code is. Pinning it
  then refuted the obvious guess: a ceiling below 64 KiB is
  `STATUS_INVALID_PARAMETER` for an image view, not the `STATUS_NO_MEMORY` the
  data arm gives for the same `zero_bits`, because `map_image_view` raises
  `limit_low` to `address_space_start` first and `map_view` refuses
  `limit_low >= limit_high`. The same review caught a comment citing
  `map_image_view` for an ordering it does not have (it never sees a
  caller-supplied address at all — G8), and `MiFindFreeViewBase` left dead by
  the change.
- **The pin had to derive its addresses, and the reason is worth carrying.** The
  first draft wrote them down (a base of `0x10000`, a scratch reservation under a
  `2^20` ceiling) and was oracle-green while measuring almost nothing: the
  reservation answered `STATUS_NO_MEMORY` and every assertion behind it was
  skipped. Two facts, both measured, make hard-coded low addresses wrong here —
  proskrnl's lowest free hole in a test process is **0x7c0000**, not `0x10000`;
  and an UNCONSTRAINED reservation on the oracle comes back at
  `0x7ffffe8c0000`, because a limit is what selects the low-address search over
  a plain anonymous mmap. The pin now probes for the lowest hole (with a
  deliberately loose `zero_bits 1`), takes the next power of two above it, and
  sizes a section so a view based there ends exactly at that ceiling — one bit
  either side then gives `STATUS_INVALID_PARAMETER_4` and `STATUS_SUCCESS`. **A
  `SUCCESS || NO_MEMORY` assertion in front of a block is a way to run green
  without measuring**, which is §4 trap 2 in miniature.

What it did NOT change is worth stating too: the executed count falls 3757 →
3737 because the sweep's two inner `ok()`s sit under `if (status ==
STATUS_SUCCESS)` and ten maps now correctly refuse — 10 × 2, exactly the
difference — and a before/after diff of the failing-assertion histogram shows
those two lines removed and no other line moved.

That is now two accepted-and-dropped capability probes in this one pair
(`MEM_EXTENDED_PARAMETER_EC_CODE` was the first), which still makes "sweep the
boundary for accepted-and-dropped words" a better-evidenced hunt than any
single item left here — and `docs/16`'s serial line
(`ps: NtSetInformationProcess class N accepted as a no-op`) is where that sweep
starts, because it named this one in the winetest log all along.

**The KUSER_SHARED_DATA / cpu-fields group is DONE** (`ntdll:virtual` 1115 →
**1111**), and it is the smallest item in this section with the largest reach
outside the pair. Four fields the page's `memset` had left at zero —
`NumberOfPhysicalPages`, `ActiveProcessorCount`, `ActiveGroupCount` and the
whole `ProcessorFeatures` array — now describe the machine
(`kernel/ps/peb.c` + `arch/x86_64/cpu.c`, pinned by
`tests/ntapi/sem_ps/shared_machine.c`). Three things are worth carrying:

- **A zeroed field on this page is not a missing value, it is a WRONG answer
  to a question user mode asks constantly.** Wine's PE ntdll implements
  `RtlIsProcessorFeaturePresent` as a plain load from `ProcessorFeatures`
  (`dlls/ntdll/signal_x86_64.c`), so the array was answering "this machine
  can do nothing" to every library that asks — msvcrt and ucrtbase pick
  string and math routines from it. The winetest sees one assertion of that
  (`:2085`, RDTSC); the surface behind it is every capability query in the
  stack. **It is the accepted-and-dropped-input shape (W5, W6) with the
  input coming from the CPU instead of from a caller.**
- **The one place it must NOT transcribe the oracle is where the oracle is
  describing a different kernel.** `init_shared_data_cpuinfo` sets the AVX
  bits straight from CPUID, which is safe on Linux because Linux always
  enables XSAVE; proskrnl's context switch is an FXSAVE image, so
  CR4.OSXSAVE is clear and a VEX instruction raises #UD. Reporting AVX would
  be Art. 12's fabricated answer expressed as a bit. The gate is
  `PF_XSAVE_ENABLED` (CPUID.1:ECX.27, the OS-enable bit — *not* ECX.26, the
  CPU's own XSAVE bit), and the oracle already applies exactly this shape to
  `PF_RDWRFSGSBASE_AVAILABLE`, which it ANDs with the host kernel's
  `AT_HWCAP2` bit. `docs/03` "Processor features" has the trade and the
  instruction for whoever enables XSAVE later (the gate becomes the XCR0
  state test, it is not deleted).
- **The pin had to measure the RULE, not the box.** The developer host, CI's
  TCG guest and the oracle's host are three different CPUs, so naming a
  feature set would have made the pin's colour a property of the machine —
  the host-dependence the manifest header spends its longest paragraph on.
  Every optional entry is instead checked against CPUID *executed by the
  test*, which ring 3 can do on both runners, and only the bits x86-64
  mandates are asserted outright. The same pin fixed a real Art. 11 defect
  the winetest could not see: class 154 had its own CPUID derivation
  (reading ECX bit **26** where the oracle reads 27, i.e. claiming xstate on
  a kernel that never enabled it) and class 1's `FeatureBits` was a hardwired
  zero. Both now compose from the array through one function, and the pin
  asserts the two classes agree.

Two smaller corrections fell out of it. The manifest called this group **5**
assertions; it is **4** — `:2039` was miscounted into it and belongs to
`MemExtendedParameterImageMachine`. And nothing was hiding behind it: 3737
tests executed and 148 todo markers before and after, with the xstate block
at `:2104` still correctly skipped, so this is a case where §4 trap 2's
"an early-out hides its body" does **not** apply and saying so is part of the
measurement.

**The thread-STACK contract is DONE, and it was never an `mm/` item**
(`ntdll:virtual` 1111 → **46**, and `kernel32:fiber` is **GREEN**). This
document and the manifest agreed for three revisions that the 1102-assertion
cluster was the NT stack shape — "proskrnl commits what it reserves and has no
guard band" — i.e. `mm/` design work in the file `docs/12` calls the top danger
zone. **Nothing in `mm/` was touched.** The shape has been built since M5
(`PspAllocateUserStack` / `PspAllocateThreadStack`: one reservation, a
committed slice at the top, one `PAGE_GUARD` page that `mm/fault.c` walks
down). What was missing was two fields nobody wrote, and one syscall class
nobody implemented:

- **`TEB.DeallocationStack` was left at the `memset`'s zero.** It is the
  stack's third corner and the only fixed one — `StackBase` and `StackLimit`
  bracket the committed slice and both move — so `StackBase -
  DeallocationStack` is the only way user mode can state the RESERVE.
  `test_stack_size_thread` computes exactly that and then queries
  `MEMORY_BASIC_INFORMATION` **at** `DeallocationStack`, so one unwritten field
  failed 16 assertions per thread across 61 threads: **976** of the 1102.
  Fixed in `kernel/ps/peb.c` `PspBuildTeb` (which now takes all three
  addresses), pinned by `tests/ntapi/sem_ps/teb_stack.c`. **A zero here is not
  a missing value, it is the claim that every stack reaches address 0** — and
  Wine's PE side reads the field directly in four places
  (`GetCurrentThreadStackLimits`, `SetThreadStackGuarantee`,
  `dlls/kernel32/virtual.c` `badptr_handler`'s guard re-arm, and
  `SwitchToFiber`, which swaps it).

- **`NtSetInformationProcess(ProcessThreadStackAllocation)` — class 41 — was
  in the accept-as-a-no-op default arm**, and it is the ONLY kernel call
  `RtlCreateUserStack` makes. **This is the accepted-and-dropped shape at its
  worst, because the dropped thing is an OUTPUT.** The class's answer is a
  pointer it writes into the caller's buffer, and that buffer is a plain
  uninitialised local (`third_party/wine` `dlls/ntdll/thread.c`,
  `PROCESS_STACK_ALLOCATION_INFORMATION alloc;`). A no-op success therefore
  handed ntdll a garbage `StackBase`, which it committed a guard page and a
  stack at and reported as the new stack's `DeallocationStack`. Implemented in
  `kernel/ps/query.c`, pinned by `tests/ntapi/sem_ps/thread_stack_alloc.c`; it
  cost `ntdll:virtual` 47 assertions (:1351/:1352 and the ZeroBits bands at
  :1403/:1424) — and `kernel32:fiber`'s fatal page fault, because
  `CreateFiberEx` takes the same route (`dlls/kernelbase/thread.c`).
  **`docs/16`'s rule generalises one step: a no-op is safe only for a class
  the caller reads NOTHING back from**, not merely one whose status carries no
  information.

- **`TEB.Tib.FiberData` is seeded `0x1e00`** on every non-fiber thread, which
  is what took `kernel32:fiber` from "1 failure and then a kill" to 32985
  tests, 0 failures. Nothing dereferences it — kernelbase gates every fiber
  path on `HasFiberData` — but `fiber.c:203` asserts it on a plain thread. It
  is written by `init_teb` (`dlls/ntdll/unix/virtual.c`), one line below the
  `ActivationContextStack` furniture `PspBuildTeb` already mirrored: **W12's
  "replacing a layer means inheriting what that layer did", third instance,
  and the tell was a TEB constructor that copies SOME of `init_teb`.** Pinned
  by `tests/ntapi/sem_ps/teb_fiber_data.c`.

Three things worth carrying beyond the fields themselves:

- **This is `§4` trap 4 at its most expensive so far.** The manifest block was
  written from the failure TEXT — "got reserve 0xad0000 where 0x200 was
  asked", "the region below the stack reports MEM_FREE" — and both readings
  were accurate observations of a consequence. They pointed three sessions'
  worth of planning at `mm/section.c` and `mm/fault.c`. The cause was two
  assignments in `kernel/ps/peb.c` and one `if` in `kernel/ps/query.c`.
- **A crash count is still not a failure count, and now the inverse is true
  too**: 1111 was a real, measured number and it was still 24× the size of the
  work. Nothing was hidden behind the cleared assertions — 3737 executed, 148
  todos and 2 skips before and after — so `§4` trap 2 does not apply here, and
  saying so is part of the measurement.
- **`ZeroBits` is now stated once.** `MiZeroBitsPlacementLimit`
  (`kernel/mm/virtual.c`) holds the classic entry point's two invalid bands
  and the ceiling a valid value names; `NtAllocateVirtualMemory` and class 41
  both go through it, because the oracle implements the class BY CALLING that
  syscall and a second transcription would be a second authority for one rule
  (Art. 11).

**`NtCreateThreadEx`'s own ZeroBits is DONE** (`ntdll:virtual` 46 → **11**, the
35 at `:1411`/`:1431`). The syscall opened with `(void)zeroBits;`, so every
value in `test_stack_size`'s 32-count / 27-mask sweep answered
`STATUS_SUCCESS`. It now refuses `zeroBits > 21 && zeroBits < 32` with
`STATUS_INVALID_PARAMETER_3` and passes `MiZeroBitsLimit(zeroBits)` down as the
stack reservation's placement ceiling (`PSP_THREAD_OPTIONS.stackLimitHigh` →
`PspAllocateThreadStack` → `MiAllocateVirtualMemoryEx`). Pinned by
`tests/ntapi/sem_ps/thread_zero_bits.c`.

**This document told the next reader to reuse the wrong ladder, and that is
the part worth carrying.** The block above said the bands "are already stated
once in `mm/virtual.c` `MiZeroBitsPlacementLimit`". They are not this entry
point's bands. On x86-64 `NtCreateThreadEx` has **one** invalid band where
`NtAllocateVirtualMemory` has **two**: the oracle's `zero_bits >= 32` refusal
is inside `#ifndef _WIN64`, and its `> 32 && < granularity_mask` band has no
counterpart in `dlls/ntdll/unix/thread.c`. So `ZeroBits 33` is
`STATUS_INVALID_PARAMETER_3` through `ProcessThreadStackAllocation` — which
really is implemented by *calling* `NtAllocateVirtualMemory`, so it inherits
that ladder — and here it is a legal MASK naming a 63-byte ceiling, i.e.
`STATUS_NO_MEMORY`. **An implementation that took this document's advice
passes all 35 winetest assertions and answers the wrong status for the whole
band**, because the winetest accepts `NO_MEMORY` and `INVALID_PARAMETER_3`
interchangeably there. Art. 11's answer is not "share the ladder" but "share
the part that is one rule": `MiZeroBitsLimit`, the count-or-mask resolution,
which both entry points already call.

**Two other things it settles, both measured:**

- **A late refusal leaves a handle in the caller's slot, and the pin's first
  draft was refuted for saying otherwise.** The oracle creates the thread
  object first and reserves the stack second (`create_server_thread`, then
  `init_thread_stack`, then `done: if (status) { NtClose( *handle ); … }`), so
  a `NO_MEMORY` refusal *closes* the handle and leaves its stale value where
  the caller can read it. The pin states that and does not pin it — a closed
  handle value is not something a caller can use — while the argument arm,
  where nothing is created and the slot really is untouched, is pinned. The
  ordering *is* pinned in the other direction too: the band check precedes the
  process-handle resolution, so a bad `ZeroBits` is reported for a handle that
  names nothing.
- **The executed count fell 3737 → 2235 and that is the item working, not
  coverage lost.** `test_stack_size_thread` runs once per create that
  SUCCEEDS, and the sweep exists because most of them must not. proskrnl now
  runs **18** of those bodies where it ran 44; the ORACLE runs **24** (2527
  executed, 112 todo, 0 failures), so the pair moved from *above* the oracle's
  count to *below* it. The 18 is exactly what this kernel's lowest free hole predicts —
  the pin prints it at `0x7c0000`, so a 1 MiB stack needs a ceiling of at
  least `0x8bffff`, which only counts 0..8 and masks `~0u >> 0..8` provide:
  9 + 9. (**The 18 is a prediction and the count is 17**, measured per line by
  the next item below; the arithmetic was never checked against the log.) The
  oracle serves counts 0..11 because its lowest hole is lower:
  12 + 12. Every one of those six extra bodies is a create the winetest
  accepts as `STATUS_NO_MEMORY`, so the remaining gap costs coverage and no
  failures. What did NOT reconcile is the old run's arithmetic — 26 fewer
  bodies × 35 `ok()`s is 910 where 1502 assertions went, and the old run
  showed 44 bodies from 59 successful creates. Both new counts are predicted
  exactly by the two runners' lowest holes, so the residue is in behaviour
  this item removed; it is recorded rather than explained. The reachable-set
  half of this — which ceilings a kernel can meet at all — is in `docs/03`
  "`ZeroBits`: the rule is exact, the reachable set is the address space's",
  because it outlives this pair.

**The DEFAULT thread-stack reserve is DONE** (`ntdll:virtual` 11 → **9**, the 2
at `:1050`/`:1068`). `PspCreateUserThread` opened with `reserve =
options->stackReserve != 0 ? options->stackReserve : 0x100000;`, so the one
number an image gets to state about its threads was parsed, retained on
`EPROCESS.imageInformation` and then ignored. An unnamed reserve is now the
image's `SizeOfStackReserve` and an unnamed commit the image's
`SizeOfStackCommit`, through `PspResolveStackGeometry` — **one function for the
main thread and for every `NtCreateThreadEx` thread**, which is the Art. 11
half of the item: the rule already existed in three places with three different
floors (1 MiB in `thread.c`, 16 KiB in one `process.c` path, 4 pages in the
other), all of them disagreeing with the oracle's `if (size < 1024 * 1024)`.
Pinned by `tests/ntapi/sem_ps/thread_stack_default.c`.

Three things worth carrying:

- **The discriminating case is the one no failing assertion asked for.** "Use
  the image's reserve" and "use the LARGER of the image's and the caller's"
  agree on every case the winetest exercises; they part only when a caller
  names a reserve BELOW the image's, and NT gives the caller the smaller
  number. An implementation reaching for a tidy `max()` passes `ntdll:virtual`
  and the pin's other three cases. The pin also refuses to be satisfied by a
  hardwired 1 MiB: it asserts that the running image's declared reserve is not
  NT's floor before it concludes anything, because otherwise every case is
  green against the very default the item is removing (§4 trap 2 in miniature).
- **This is the accepted-and-dropped-input shape again, with the input coming
  from the PE header** — the fifth instance in this pair after
  `MEM_EXTENDED_PARAMETER_EC_CODE`, the two capability classes, and the mapping
  path's `zero_bits`. Same tell each time: a value parsed faithfully, stored,
  and never read. `EPROCESS.imageInformation.MaximumStackSize` had a comment
  saying it was retained for the query surface, and it was true.
- **The pair's executed count fell 2235 → 2200 and the reason is a leak this
  item did not cause but did make visible.** That is exactly one
  `test_stack_size_thread` body (35 `ok()`s, 2 of them todo), counted per line
  — `virtual.c:1049` is marked todo 17 times before and 16 after, with every
  other todo line unchanged. The lost body is one of the `ZeroBits` sweep's
  creates, now `STATUS_NO_MEMORY`, because the two threads ahead of it reserve
  2 MiB each where they reserved 1 MiB **and this kernel never releases a dead
  thread's stack** (`PspDeleteThread` frees the name, the token and the
  KTHREAD, and nothing frees the reservation) — issue #152. The winetest
  accepts `NO_MEMORY` there, so it costs coverage and no failures. The
  mechanism is read off the code and consistent with the arithmetic; which
  sweep index moved was not measured, and the block says so.

**This document's own "18 bodies" was arithmetic, not a count**, and `docs/03`
copied it. It came from the two runners' lowest free holes (9 counts + 9
masks). The serial log says **17** before this change and **16** after. Both
documents now carry the counted number — §4 trap 4's smaller sibling, the same
one W13's "one 10 ms tick" was: a quantity nobody measured, written into a
triage block as though somebody had.

**`MemExtendedParameterImageMachine` is DONE** (`ntdll:virtual` 9 → **8**, the
singleton at `:2039`). `MiCaptureExtendedParams` captured the word into
`MI_EXTENDED_PARAMS.machine` and nothing ever read it, so a map naming
`IMAGE_FILE_MACHINE_R3000` over an x86-64 DLL answered `STATUS_SUCCESS`. The
rule is one line of the oracle's `map_image_into_view`
(`dlls/ntdll/unix/virtual.c`: `if (machine && machine != nt->FileHeader.Machine)`
→ `STATUS_NOT_SUPPORTED`), now in `MipMapImageView` and pinned by
`tests/ntapi/sem_mm/map_image_machine.c`. **`map_image_into_view` is not
`map_image_view`**, which sits 300 lines below it in the same file and is what
this document already cites for the image arm's `limit_low` floor; gate-check
caught the first draft naming the floor's function for the machine's rule in
five places, which is G8's "cite where to re-verify" failing in the way that is
hardest to notice — a real symbol, in the right file, one frame off.

**This is the accepted-and-dropped-input shape a SIXTH time in this one pair**,
after `MEM_EXTENDED_PARAMETER_EC_CODE`, the two capability classes, the mapping
path's `zero_bits` and the image's `SizeOfStackReserve` — same tell every time:
a value parsed faithfully, stored in a named field, and never read. The hunt
that finds them is a grep for a captured field with one writer and no readers,
and it is still the best-evidenced hunt in this document.

Four things the pin measures that the parameter's name does not give you, each
of them a way an implementation reaching for the obvious guard answers wrongly:

- **ZERO is "no constraint", not "the machine must be zero".** The winetest's
  own probe at `:2016` maps with `ULong = 0` and requires a success before it
  concludes the parameter is supported at all — so an implementation that read
  zero as a constraint would `win_skip` the whole block and score `:2039` as
  passing;
- **a DATA section takes the same word and IGNORES it.** The oracle's `machine`
  reaches `map_image_into_view` and nothing else, so a guard written one level
  up — in the shared parameter parser — refuses a data mapping the oracle
  admits. Exactly the position argument `sem_mm/map_ex.c` makes for
  `MEM_EXTENDED_PARAMETER_EC_CODE`, with the arms the other way round: that bit
  belongs to the allocation engine, this word to the mapping engine's image arm,
  and neither belongs to `MiCaptureExtendedParams`;
- **placement is decided first.** `virtual_map_image` places the view with
  `map_image_view` and only then calls `map_image_into_view`, whose machine
  check is its last act before the relocation — so an impossible ceiling plus a
  wrong machine answers the ceiling's `STATUS_NO_MEMORY` and never reaches the
  comparison. The pin derives that ceiling from the image's own measured extent
  rather than writing one down, and the two runners show why: the same
  `ntdll.dll` is `0x41a000` on the oracle and `0xba000` on proskrnl, so any
  hard-coded number would have measured one runner and skipped the other (§4
  trap 2 in miniature, the shape `map_zero_bits` paid for above);
- **the winetest's whole block maps into a CHILD, and the pin nearly did not.**
  Every call at `:2016-:2039` passes `create_target_process("sleep")`'s handle,
  and on the oracle the word then rides an APC into that process
  (`call.map_view_ex.machine`) rather than being applied by the caller. The
  first draft measured only the same-process arm; gate-check said so, and the
  remote arm is now pinned alongside it. On proskrnl both arms are the one
  `MiMapViewOfSectionEx` reached through `MiReferenceProcessByHandle` — but
  "they must agree" was an argument, not a measurement, which is exactly what
  §4 trap 4 keeps punishing.

**Nothing was hiding behind it, and saying so is part of the measurement**: 2200
tests executed, 96 todo markers and 2 skips before and after, one failure fewer.
§4 trap 2 does not apply here.

**The `old_prot` pair is DONE** (`ntdll:virtual` 8 → **6**, `:2679` and
`:2686`). A FAILED `NtProtectVirtualMemory` still writes the caller's
`*old_prot`, and what it writes is `PAGE_NOACCESS`; `kernel/mm/virtual.c` wrote
the slot on success only. One line of the oracle
(`dlls/ntdll/unix/virtual.c` `NtProtectVirtualMemory`'s closing `else *old_prot
= PAGE_NOACCESS;`), pinned by `tests/ntapi/sem_mm/protect_old_prot.c`.

**This document called it "a one-line item" and the line was right; the
CONTRACT around it is four statements, and three of them are about where the
rule STOPS.** That is the transferable part, because each is a way an
implementation reaching for the obvious `else` diverges while passing the
winetest:

- **The slot is written for every failure of the OPERATION.** An unserviceable
  protection, an uncommitted range and a free address all write
  `PAGE_NOACCESS` — and none of the three *has* a previous protection to
  report, which is the point: the contract is "always answered", not "answered
  when there is an answer".
- **`*base` and `*size` are not written with it.** The oracle rounds them into
  locals and copies them back on success only, so a failed call leaves the
  caller's own unrounded values alone. An implementation that reports its
  rounding unconditionally satisfies every `old_prot` assertion in the pair and
  still diverges; the pin passes a deliberately unaligned address and a size of
  1 to see it.
- **It does NOT cover a failure to REACH the operation.** A junk process handle
  and a real handle without `PROCESS_VM_OPERATION` both return above the
  `else` — on the oracle because `server_queue_process_apc`'s failure returns
  `status` directly. So "write `PAGE_NOACCESS` at every non-success return of
  the syscall" is wrong in exactly those two cases and right everywhere else,
  which no winetest assertion can see.
- **It holds through the REMOTE arm**, which on the oracle is a second,
  textually separate assignment reached by an APC. A real handle to the
  caller's own process takes that arm — `process != NtCurrentProcess()` is what
  selects it, not the target being a different process — so the second site is
  measurable without a child, and "the two arms must agree" stayed a
  measurement rather than becoming an argument (§4 trap 4).

**The pin then convicted a THIRD status that no winetest assertion can see, and
finding it is the reusable half of this item.** The two failures the pin adds
around the slot — a free address, and a range running off the end of a view —
answered `STATUS_INVALID_ADDRESS` on proskrnl where the oracle answers
`STATUS_INVALID_PARAMETER`. `ntdll:virtual` cannot convict that: upstream's own
comment at `virtual.c:2677` records that Wine and Windows disagree there
(`STATUS_CONFLICTING_ADDRESSES` on win64), so the assertion is a bare
`ok(status, ...)`. **What makes it a defect rather than a third opinion is one
step past the status**: Wine's PE-side `RtlNtStatusToDosError` maps `c0000141`
to `ERROR_UNEXP_NET_ERR` (59) (`dlls/ntdll/error.h:686`), so `VirtualProtect`
over a free address reported an *unexpected network error* where both
authorities report an address or parameter problem. Where two authorities
disagree the pinned oracle is the arbiter (Art. 6), so it is the oracle's status
now, pinned both ways; `docs/03` "What a FAILED `NtProtectVirtualMemory`
answers" has the table. **The generalisable tell is that a status nobody asserts
is still observable through the error mapping** — gate-check found this by
walking `RtlNtStatusToDosError` for the status the diff's own docs entry was
about to bless, which is a cheap check to run on any NTSTATUS a pin declines to
pin.

**And then the ORDER, which is the fourth defect this one small item turned up
and the one with the longest reach.** `MiProtectVirtualMemory` validated the
protection on the way IN; the oracle validates it LAST — `find_view`, then
`get_committed_size`, then `set_protection`, which is where `get_vprot_flags`
refuses. So a bad protection over a free address must report the ADDRESS and
over a reserved range the COMMIT, and proskrnl reported the protection for both.
Same shape as W11's finding that "every defect in this item was an ORDER or a
MASK, not a value", and the same discovery route: gate-check reading the two
ladders side by side, not a failing assertion. **Validating arguments before
resolving the object is the reflex to distrust** — it is what a careful
implementation does everywhere else, and NT's syscalls routinely do not.

**Then the same review asked what `size == 0` does, and that was a FIFTH
divergence — found by holding the new comment to its own claim.** The kernel
comment had just declared the ladder to be the oracle's three questions, and an
`end <= base` guard sat above all three. The oracle has no size guard at all, so
a zero-size protect is an ordinary trip down the ladder: success over a
committed page (reporting that page's protection, `*size` 0), `NOT_COMMITTED`
over a reserved range, `INVALID_PARAMETER` over a free address,
`INVALID_PAGE_PROTECTION` with a bad protection. proskrnl answered
`STATUS_INVALID_PARAMETER` to all four. Measured with print-only probes first
and pinned once measured, which is the cheap order for a corner nobody asserts.
**The transferable part is the review move**: a comment that states a rule is a
claim the diff can be checked against, and the check found a defect the comment
itself had made visible. Four of this item's five findings came out of
gate-check rather than out of a failing assertion.

**Nothing was hiding behind the two winetest assertions** — 2200 executed,
96 todo, 2 skips before and after — so §4 trap 2 does not apply.

**The image-offset view is DONE, and `ntdll:virtual` is GREEN — un-parked, in
the gate** (6 → **0**; 2205 tests executed, 96 todo, 1 skipped, 0 failures,
against the oracle's own 2527/112/0). Two rules, and the prediction this
document made about them was right about the mechanism and wrong about which
half was the work:

- **The offset trims the image's HEAD.** `MipMapImageView` takes the offset and
  builds the VAD over the tail — `base + offset`, `SizeOfImage - offset`, the
  head left FREE — where the oracle maps the whole image and then
  `free_pages`es the front (`virtual_map_image`). Same extent, without mapping
  pages only to unmap them. `offset >= SizeOfImage` is
  `STATUS_INVALID_PARAMETER` and is the first thing the oracle's image path
  does, above the fd and above placement; the whole image is still what gets
  PLACED, so a ceiling bounds `SizeOfImage` and not the tail. This half really
  was mechanical.
- **An image section is relocated ONCE and every view shares that copy.** This
  is the half the document called "a question about where an image section's
  relocation base comes from", and the answer reverses a recorded design
  decision: `docs/17` §6F said to put the mapped base in the master's key,
  calling the alternative "the worst bug available in this design". The oracle
  refutes the premise (Art. 6) — it relocates to the mapping's own dynamic base
  rather than to where the view landed (`map_image_into_view`'s `delta =
  image_info->map_addr - image_info->base`; the server says the same in
  `DECL_HANDLER(map_image_view)`'s at-base test), and two views of one section
  are byte-identical on the pinned Wine. `MI_IMAGE_MASTER` is keyed on the
  identity alone now, with `base` demoted to *what the copy was relocated for*.

Both pinned by `tests/ntapi/sem_mm/map_image_offset.c`, which measures the
remote arm as well as the local one — the winetest reaches the memcmp only
through a child, and "both arms reach the same engine" is the argument §4 trap 4
keeps punishing.

Five things worth carrying:

- **The surviving half of §6F is the sentence one step over, and it is what
  makes the reversal safe.** A view that does not sit at the copy's base has a
  residual, and the PE loader fixes it — keyed off the `ImageBase` the copy
  stamps into its own header (`dlls/ntdll/loader.c` `perform_relocations`:
  `if (module == base) return STATUS_SUCCESS;`). So the corruption §6F named is
  real and its cause is *a stamp that disagrees with the copy*, not *a base
  absent from the key*. `tests/kmt/cui9_cow.c` was asserting the old rule
  outright (`ok(f1 != f2, "views at different bases share a header frame")`);
  it now convicts the shared frames instead, and the stamp moved to
  `tests/kmt/m5_section.c` `test_image_relocation`, which holds the preferred base so
  the copy must actually be relocated — at the preferred base the delta is zero and
  the assertion cannot fail. **A kmt test that encodes a design
  decision has to be re-aimed when measurement moves the decision — it cannot
  be left as the reason not to move it.**
- **The change made a FALSE SKIP visible, and this is §4 trap 2 with the good
  outcome.** `virtual.c:2244` maps the running module afresh and `memcmp`s its
  first page against the loaded copy; with a per-base master the two headers
  differed, so the test `skip`ped its whole body. The body passes — 2200 → 2205
  executed, skips 2 → 1 — and the next thing it does is call
  `perform_relocations( ptr, delta )` itself, i.e. user mode fixing up exactly
  the residual described above. **The upstream test is a second, independent
  statement of the rule**, and it had been sitting one skip away the whole time.
- **The trim needed one new relation and exactly one place to state it.** The
  master's frames are indexed by image RVA, the VAD's pages by view offset;
  `MipVadMasterIndex` (`kernel/mm/virtual.c`) is the only place the two meet, so
  the COW arm and the §8 shared-PTE sweep cannot disagree with the commit path
  about which frame a page holds (Art. 11). Every one of its three call sites is
  an `ASSERT` — which is to say the bias is invisible until it is wrong, and
  then it is fatal at the right line.
- **It exposed a ring-3-triggerable PANIC, and that is the most valuable thing this
  item found.** Sharing one copy across bases lowered the per-process cost enough to
  move the `cui9` ceiling 317 → 319 — and the create that then failed lost its race at
  a page-table allocation instead of at a frame allocation the loader reports, so
  `MiEnsureTable` panicked where the leg used to see `ERROR_NOT_ENOUGH_MEMORY`.
  `MiMapUserPage` is infallible by contract and its page tables were an uncharged
  allocation inside that promise, so **the graceful refusal at the ceiling had always
  been one arbitrary allocation ordering away from a kernel panic**; a memory change of
  2 processes in 319 was enough to collect. Fixed by charging the tables at the two
  commit sites that can refuse (`docs/03` "Page tables are CHARGED"). The lesson is
  about the leg, not the bug: `cui9` is a *ceiling* test, so any change to per-process
  cost re-rolls which allocation loses — treat it as a first-class consumer of every
  sharing change, not as an unrelated leg.
- **The lookup-then-build window is safe for a reason worth writing down.**
  Placement runs between "does this identity have a copy?" and "build one", and
  a park in there would let a second copy appear — two relocation bases for one
  section, which is the defect this whole item removes. Nothing there parks:
  placement walks the VAD list, and the raw-byte source is resident by Art. 3
  (`MiAcquireImageRawBytes`: "memcpy, never I/O"). The mandate is load-bearing
  here rather than merely simplifying.

**The page-protection MODIFIER BITS are DONE** (`kernel32:virtual` 12 → **4**), and this
is the item where the block's own grouping was wrong in the *helpful* direction: it listed
"WriteProcessMemory (3)" and "a MEMORY_BASIC_INFORMATION protect group (5)" as two of its
four subjects, and they are **one cause** — how much of a `PAGE_*` word each entry point
reads. `docs/03` "The page-protection modifier bits" has the table and the five things it
settles; three belong here:

- **The mask is not uniform across the boundary, and the tidy rule is the wrong one.**
  `get_vprot_flags` reads `protect & 0xff` plus `PAGE_GUARD`; `NtCreateSection` reads
  `protect & 0xff`; `NtMapViewOfSection` reads the word **whole** and refuses any modifier —
  `PAGE_GUARD` included. So "canonicalize wherever a protection is captured" passes every
  assertion in the pair and admits a view the oracle refuses. Same shape as W11's "every
  defect in this item was an ORDER or a MASK, not a value", and the discriminating case is
  again one no winetest makes.
- **`PAGE_NOCACHE` is a property of the RESERVATION, and the oracle refuted the first
  draft.** The pin asserted it was dropped with the others; it is kept, in the *view's* word,
  written once in the reserve arm and readable neither out nor in afterwards. That single bit
  was five failures — and only two of them read as protections: `:517`'s "wrong size 1000" is
  the same cause one step out, a re-protected page differing from its neighbour by the
  `PAGE_NOCACHE` bit alone and splitting the reported region run. **A per-page store for a
  per-view property shows up as a region-size bug.**
- **Widening the validation is half the fix.** `MEMORY_BASIC_INFORMATION.Protect` is read
  back out of the stored protection, so a kernel that accepts the caller's word and keeps it
  answers every status correctly and then reports a value no NT produces. The oracle rebuilds
  the reported protection from the flags it kept, and that is the part an implementation
  written from a status table misses.

**The partial-write COUNT went with it** (the other two of the eight): `NtWriteVirtualMemory`
reports the prefix it managed where `NtReadVirtualMemory` reports zero, an asymmetry that
lives entirely in two adjacent PE-side functions. `MiCopyToUserRangeChecked` already returned
the byte-accurate number; the syscall wrote the caller's slot on full success only. Pinned by
`tests/ntapi/sem_ps/virtual_memory.c`.

**And the measurement corrected two things this document and the manifest both had wrong,
which is worth more than the four assertions.** `kernel32:virtual` **PANICS** — `virtual.c:869`
creates a `SEC_RESERVE` mapping and `mm/section.c` has answered `STATUS_NOT_IMPLEMENTED`
there since M5 — so it is a *stopped* pair and every count it has ever carried (4148, 40, 12,
4) is a lower bound over the same measured prefix. §4 trap 2 lists the panicking pairs by
name and this one is not among them. The manifest's "~285 seconds, the slowest in the
manifest" does not reproduce either: both legs together are ~10 s on this box, because the
proskrnl leg stops after ~5 s of guest time. **A pair that stops fast reads like a pair that
is nearly green, and this one had been read that way for three revisions.** (The panic is
gone as of the `SEC_RESERVE` item below, and the "4" was indeed a lower bound: the pair now
reports **96** and wedges. The tense above is left as it was measured.)

What is left under this heading:

- **`SEC_RESERVE` sections are DONE** (`kernel/mm/section.c`,
  `kernel/mm/virtual.c`; pinned by `tests/ntapi/sem_mm/reserve_section.c`,
  `docs/03` "A `SEC_RESERVE` section's commit ledger"). The contract was the
  bigger one this item predicted: the commit ledger belongs to the SECTION, so
  an anonymous reserve section's frame array doubles as it (`0` =
  uncommitted), `MI_SECTION.viewListHead` names every live view, and a
  `MEM_COMMIT` through one view fills the ledger and maps the new frames into
  every view at once — eagerly, because Art. 3's "a committed page is present"
  is a contract `uaccess.c` reads. `SEC_RESERVE` handed a file handle drops to
  `SEC_FILE` the way `get_mapping_flags` does, which is the half an
  implementation routing the flag instead of the (handle, flag) pair gets
  wrong.
  **It removed the pair's stop, and what that exposed is the point of the
  item**: `kernel32:virtual` went from *4 failures then a panic at
  `virtual.c:869`* to **96 failures and a wedge**, i.e. it was measured past
  page one for the first time (§4 trap 2 again, third time in this document).
  The manifest block has the decomposition; two of its three causes are new
  work and neither is a `SEC_RESERVE` residue.
- **The out-handle clear is DONE** (`kernel32:virtual` 96 → **25**), and it was
  worth 71 assertions rather than the 67 this document scheduled. A
  handle-producing `Nt*` call writes 0 into the caller's slot as its FIRST act,
  above every validation; `kernelbase`'s `CreateFileMappingW`
  (`dlls/kernelbase/sync.c:1037`) declares `HANDLE ret;` uninitialized and
  `return ret`s on every path including the failing ones, so a create proskrnl
  refused CORRECTLY handed the test stack garbage — and the test then closed
  it, which closes whatever unrelated object that value names. One authority
  (`ObpClearOutHandle`, `kernel/ob/handle.c`, beside the one site that already
  writes a handle out), pinned by `tests/ntapi/sem_ob/out_handle.c`; `docs/03`
  "What a REFUSED handle-producing call leaves in the caller's slot" has the
  table.

  Four things it settles, and two of them are corrections to what this
  document and the manifest asserted:

  - **It is NOT a `beyond_oracle` pin, and the instruction to write one was
    wrong.** Both documents said "the oracle's own ntdll leaves `*handle` alone
    too and only its stack happens to hold zero". It does not: every
    create/open on that surface opens with `*handle = 0;`
    (`dlls/ntdll/unix/{sync,file,registry,process,thread,security,server}.c`).
    The rule was readable in the oracle the whole time; the claim that it was
    not is what made the item look like a judgement call. **A sentence saying
    the oracle cannot answer something is a claim about the oracle, and it is
    one `grep` away from being checked.**
  - **The "4 that have not moved for two revisions" were the same bug**, and
    the manifest sent the next person to bisect a sequence with nothing wrong
    with it. `virtual.c:758`/`:764`/`:770` are
    `ok( !mapping, "CreateFileMapping … succeeded" )` — assertions about the
    returned HANDLE. The error checks are the NEXT lines (`:759`/`:765`/`:771`)
    and were passing all along, which is exactly what the block's own probe had
    measured when it "eliminated the WIN32 path". §4 trap 4 in its purest
    form: the failure TEXT said precisely what happened and was read as a
    statement about the refusal instead of about the slot. A triage block that
    quotes a line number should quote the line.
  - **The rule is per-entry-point, and that is the load-bearing half.** Three
    creates deliberately do NOT clear — `NtCreateThreadEx`,
    `NtCreateUserProcess` and `NtFilterToken` — so it cannot be hoisted into
    the system-service dispatcher or into `ObpCreateObjectWithHandle`. The pin's
    last two cases are exactly those entry points, because an implementation
    that hoisted it passes every positive case and diverges only there.
    proskrnl had in fact drifted the *other* way: `NtFilterToken` cleared where
    the oracle does not, via a `Se`-local copy of the rule.
  - **The rule already existed in the tree three times, in three spellings,
    and that is why the item was invisible.** `kernel/se/token.c`'s
    `SepPreZeroHandle` (with the oracle citation), `kernel/cm/registry.c`'s two
    `*keyHandle = 0; /* as wine ntdll */` lines, and nothing anywhere else.
    Art. 11's tell is not "two functions that do the same thing" but **a rule
    written down wherever somebody happened to hit it** — each copy correct,
    none of them a statement that the *surface* owes this.
- **The SEC_\* MODIFIER flags on a section are DONE** (`kernel32:virtual` 25 →
  **1**, and the 1 is the `:1465` todo floor). This item was scheduled as
  "the same one-field shape as `MI_VAD.noCache`, on the section instead". It
  is not one field: `server/mapping.c` `get_mapping_flags` is twenty lines
  that decide **three** things at once, proskrnl had the first and neither of
  the other two, and the three are not separable — the anonymous arm's
  `return flags` is simultaneously the refusal ladder's early exit and the
  "which bits survive" answer. Transcribed whole as `MipMappingFlags`
  (`kernel/mm/section.c`), pinned by `tests/ntapi/sem_mm/section_sec_flags.c`,
  table in `docs/03` "The SEC_\* modifier flags on a section".

  Four things worth carrying, and the first two are what a per-flag reading
  of this item would have got wrong:

  - **The refusals are per-ARM, not per-flag, and the discriminating case is
    the one the winetest never asks.** `SEC_LARGE_PAGES` refuses on an image,
    on any file-backed section and on an anonymous `SEC_RESERVE` — and
    **succeeds, keeping the bit**, on an anonymous `SEC_COMMIT`, because that
    is the single arm whose `return` sits above the guard. All five of the
    pair's `ERROR_INVALID_PARAMETER` rows carry `SEC_LARGE_PAGES` or
    `SEC_WRITECOMBINE`, so "these two flags are unsupported" passes the whole
    44-row matrix and diverges exactly there. Same shape as W5's
    `zero_bits`: *the invalid band is not the other entry point's band.*
  - **What survives differs by arm too, and `SEC_IMAGE | SEC_NOCACHE` is the
    one accepted-and-DROPPED combination on the surface.** That single row is
    what separates an implementation reading the section's **resolved**
    attributes from one reading the flags its caller passed — both answer
    every other case in the matrix, and only a view of such a section can
    see it. It is why the kernel's view half reads
    `MI_SECTION.attributes` rather than the create call's word.
  - **The order was wrong and no winetest assertion could say so.**
    `get_mapping_flags` runs above `create_mapping`'s `get_file_obj`, so a
    refused combination is reported for a file handle that names nothing;
    proskrnl resolved the backing first and answered
    `STATUS_INVALID_HANDLE`. Fourth instance in this document of "a
    validation placed where a careful implementation would put it, where NT
    does not" (W11's guards, W5's `NtProtectVirtualMemory` ladder, W16's
    share-mode escape).
  - **17 assertions were hiding behind the value this item was fixing, and
    they all pass** — `virtual.c:1017` is
    `if (section_info.Attributes & SEC_NOCACHE)`, guarding the whole
    view-reports-`PAGE_NOCACHE` block. §4 trap 2 with the good outcome, and
    the *self-referential* variant of it: the gate reads exactly the field
    rule 2 was answering wrongly, so the pair could not measure the second
    half of the item until the first half landed.

  What did NOT move *at the time*: the pair still ended `FAIL (timeout)` in
  the same place (the W4c wedge in `test_write_watch`), and 1 was a lower
  bound like every count this pair has ever carried. **W4c has since unlocked
  it**: the pair now runs to the end of the module and dies at an unhandled
  `0xc0000005`, with 4 failures — the `:1465` todo floor plus
  `test_far_regions`' `DuplicateHandle -> 6` and its two dependents. Which is
  what "no known kernel work left inside its measured prefix" was worth: the
  prefix grew.
- **Placeholder MAPPING** — `MEM_REPLACE_PLACEHOLDER` in
  `NtMapViewOfSectionEx` and `MEM_PRESERVE_PLACEHOLDER` in
  `NtUnmapViewOfSectionEx` still refuse loudly. Mapping a section *into* a
  placeholder is a larger contract than replacing one with private memory,
  and no baked consumer reaches it.

**This is still the item to be most careful with.** `docs/12` names
`mm/{section,fault,pagecache}.c` the top danger zone: plausible code, unit
tests pass, then it corrupts silently under Wine's real load. Design before
writing.

- **Art. 3.** Commit-on-demand is *not* a mandate violation — the mandates
  are no eviction, one dispatcher lock/uniprocessor, one pool (the no-COW
  clause was amended at CUI-9, image sections only), and the list is
  closed. Fault-time commit of a reserved page is none of those. But it
  *touches the fault path*, which is where an eviction reflex — or COW
  beyond its amended image-only scope — will try to enter. `docs/17` §10
  was COW's only door and CUI-9 took it as a commit of its own; §10 step 6
  is the only door left (file-backed data writecopy).
- **G12.** Partial placeholder support that silently succeeds where it
  should split is `1d6dafd` (`NtResumeThread` as a no-op success). The
  built half refuses `STATUS_CONFLICTING_ADDRESSES` for every extent it
  cannot serve exactly, which is the specific NT failure and not a stub.

### W6 — The exception/context cluster (**`ntdll:unwind` is GREEN; `ntdll:exception` is not frontier**)

This item grouped two pairs on the strength of their shared symptom — both
died with an unhandled user-mode `0xc0000005` — and predicted one cause for
both: `NtSetContextThread` ignoring `ContextFlags` selectivity. **Both halves
of that were wrong, and neither was wrong in the way the shape suggested.**

**`ntdll:unwind` is GREEN on both legs, and its cause was two subsystems
away from `arch/`.** The pair's block said "unwinding is PE-side, so a kernel
failure under it points at exception dispatch or context capture in `arch/`".
Nothing in `arch/` was involved. `test_virtual_unwind_arm64`
(`dlls/ntdll/tests/unwind.c`) opens by asking

```c
param.ULong64 = MEM_EXTENDED_PARAMETER_EC_CODE;
if (!pNtAllocateVirtualMemoryEx || pNtAllocateVirtualMemoryEx( ..., &param, 1 )) return;
```

— the allocation IS the "am I an ARM64EC host?" probe. The oracle refuses it
(`allocate_virtual_memory`'s `if (!arm64ec_view && (attributes &
MEM_EXTENDED_PARAMETER_EC_CODE)) return STATUS_INVALID_PARAMETER;`) and the
whole ARM64EC block is skipped. proskrnl captured the attribute word in
`MiCaptureExtendedParams` and then **dropped it**, so the probe answered
"yes", and the test ran ARM64 unwind opcodes over an x86_64 code buffer until
it died. The same probe appears a second time at `unwind.c:3960`, gating
`test_dynamic_unwind`'s ARM64EC metadata block, so one refusal closes both.
Implementing it (`kernel/mm/virtual.c`, pinned by `sem_mm/alloc_ex.c` +
`sem_mm/map_ex.c`) took the pair from a kill to **455166 tests executed, 0
failures — the oracle's count exactly.**

**Three things worth carrying forward:**

1. **This is §4 trap 4 again, at its widest reach yet.** The loudest failure
   was a fatal fault deep in unwind machinery; the cause was one accepted-and-
   dropped input bit in `mm/`. Grouping by symptom put the item under
   "exception/context" and pointed the next reader at the two files
   (`ps/usermode.c`, `arch/x86_64/*.S`) `docs/12` calls danger zones. It was
   a fifteen-line fix in neither of them.
2. **It is also W10's lesson 1, in the surface `docs/12` calls SAFE.** "A
   dropped flag does not fail an assertion" — there it deadlocked, here it
   crashed. The `MEM_EXTENDED_PARAMETER` word had a parser that *validated
   its structure faithfully* and then discarded its content, which is the
   most convincing possible way to hide a dropped input: the ladder above it
   is pinned line-for-line against the oracle (`sem_mm/alloc_ex.c` predates
   this by a milestone) and every one of those assertions passed.
3. **Where the guard lives is the load-bearing part.** It cannot go in
   `MiCaptureExtendedParams`, because `NtMapViewOfSectionEx` takes the same
   attribute word and *ignores* it; it cannot go in the syscall wrapper,
   because the oracle's guard is below `allocate_virtual_memory`'s
   working-set test and an oversized EC_CODE request must still answer
   `STATUS_WORKING_SET_LIMIT_RANGE`. So it is in the allocation engine, and
   both boundaries are pinned rather than argued.

**`ntdll:exception` is NOT frontier, and this document scheduled it wrongly.**
§0 scopes the backlog to pairs green on the pinned oracle. Measured, this
one's ORACLE leg is red: 25 failures, then the oracle's own process dies at
`0xc0000005` with no summary line. 23 of the 25 need `syswow64` (the oracle
is built `--enable-win64`, so `test_debug_registers_wow64` and
`test_wow64_context` cannot start their 32-bit helpers) and two are
`RegisterClassA`/`CreateWindowA` under `--without-x`. Re-parked as manifest
category (b) with no TODO: re-opening it is a decision about the oracle
BUILD, not a kernel change.

**Correction, measured when the oracle got a display.** The `syswow64` half of
that was right and the WOW64 milestone fixed it. The display half was not: the
oracle is now `--with-x` on the runner's Xvfb, and the two `0x78`s did not
move. On that oracle the *pinned tree's own* `ntdll_test.exe` runs the module
green (5915 tests, 0 failures), while the CUI gate's standalone binary still
answers four — the difference being `tests/winetest/glue/user32_stubs.c`,
which returns `ERROR_CALL_NOT_IMPLEMENTED` (`0x78`) for every window entity by
design, because user32 is off the CUI image (Art. 7). `nodrv_CreateWindow`
sets the same error, which is how our own stub's number was read as the
display driver's. So this pair is not gated on the oracle build at all;
`manifest.txt`'s block carries the corrected triage. **The shape is §4 trap
2's again — a symptom attributed to the first plausible cause in the log,
where two causes produce the identical number.**

That also disposes of the `RIP=0` hypothesis this item was built on — not by
refuting it, but by removing the only evidence for it. Worth noting anyway
that `ContextFlags` selectivity **is** implemented on both directions
(`kernel/ps/usermode.c` `KiTrapFrameToContext` / `KiContextToTrapFrame`,
whose comments record the `docs/review-2026-07` §9 fix that made the
documented get-modify-set idiom stop writing `Rip`/`Rsp` as zero), so the
prediction was probably stale when it was written. **§4 trap 2's sibling:
a symptom read off a leg nobody had checked was oracle-green is not a
measurement at all.**

- **Art. 1 / G1** still applies to whatever reopens the context surface:
  `CONTEXT` layout and `ContextFlags` semantics are squarely on the boundary,
  and every offset comes from `abi/` with `static_assert`, never from memory.
- **Trap 5 (DR0–7 and `EFLAGS.TF`) is now unreachable rather than merely
  low-value** — the only pair that wanted them cannot convict.

### W15 — The BaseNamedObjects links (**DONE**)

`\Sessions\<id>\BaseNamedObjects` existed; the three names *inside* it did
not. NT (and the pinned oracle, `server/directory.c` `create_session`) puts
three symlinks there — `Global` → the root `\BaseNamedObjects`, `Local` →
**its own parent**, `Session` → `\Sessions\BNOLINKS`, which carries one link
per session id back to that session's directory. Landed in
`kernel/ob/namespace.c`, pinned by `tests/ntapi/sem_ob/bno_links.c`.

Nothing special-cases the words `Local\` or `Global\`: kernelbase hands the
whole name, prefix included, to the object manager relative to the session's
directory (`dlls/kernelbase/sync.c` `BaseGetNamedObjectDirectory`), so the
prefix is an ordinary path component and a missing link is
`ERROR_PATH_NOT_FOUND`.

**It took `kernel32:virtual` from 40 failures to 12, and that is the lesson
rather than the code.** The 28 it cleared spanned `virtual.c:790-:862` and
read like a section bug — the manifest block called them "NtCreateSection
refusing/accepting wrongly at :758-:790", folding them in with three
assertions that really are a section-access gap and survive. They
were the *consequence*: one `OpenFileMapping` on a `"Local\Foo"` name
returned `ERROR_PATH_NOT_FOUND`, and every assertion downstream of the handle
it never returned failed behind it. **§4 trap 4, paid for a third time** —
and this instance is the sharpest, because the failing assertions named a
subsystem (`NtQuerySection`, `MapViewOfFile`) that had nothing wrong with it.

The remaining 12 are four small subjects and the manifest block has them.

### W7 — Volume furniture (**PARTLY DONE**)

`\DosDevices`, `\Device\MountPointManager` and the boot volume's
`\??\Volume{...}` name have landed. `kernel32:drive` is green and
`kernel32:volume` dropped by four fifths. Pinned by
`tests/ntapi/sem_file/mountmgr.c`; the ioctl ABI is generated
(`abi/ntmountmgr.h`).

What is left under this heading is **open-by-file-id**
(`FILE_SUPPORTS_OPEN_BY_FILE_ID` plus the `FILE_OPEN_BY_FILE_ID` open),
which `kernel32:volume` and `ntdll:file` both want, and
`GetVolumePathNamesForVolumeNameW`'s multi-string form.

**Open-by-file-id is NOT an implementation item — it is a decision, and this
document was wrong to schedule it as work.** The oracle itself does not
report `FILE_SUPPORTS_OPEN_BY_FILE_ID` for FAT or FAT32:
`dlls/ntdll/unix/file.c` gives `MOUNTMGR_FS_TYPE_FAT32` only
`FILE_CASE_PRESERVED_NAMES`, and reserves the flag for its NTFS default arm.
`kernel32:volume`'s oracle leg passes solely because Wine's C: is a Linux
directory and takes that default arm. NT on a real FAT32 volume has no
file-id index and answers the way proskrnl does.

proskrnl's FAT32 *could* serve it — the id is already stable
(`(dirCluster << 32) | sfnSlot`, `fs/fat32/fat.h` `FatFileId`) and
resolution would be a tree scan, which is exactly the Art. 3 "stupidly
correct" shape. It needs no on-disk extension, so this is **not** the same
floor as reparse points or DACLs, where FAT has nowhere to put the data.
The question is narrower and it belongs to a human: **may a volume that
reports its filesystem name as `FAT32` advertise a capability NT's FAT32
never advertises?** Answering yes makes proskrnl more capable than the thing
it names itself after; answering no parks `kernel32:volume:2022` and
`ntdll:file:467` permanently. Until it is answered, do not implement it, and
do not read the oracle's green leg as a spec for a FAT32 volume — it is a
measurement of Wine-on-ext4.

**The raw-device half is real kernel work, and it is bigger than its count.**
`kernel32:volume`'s remaining `:632`/`:675` are each a `win_skip` standing in
front of a whole test function, so the manifest's failure count hides ~31
assertions behind two. `:632` (`\\.\c:`) is additionally **blocked on a
name-parser change**: `kernel/ob/namespace.c` hands the FS an empty remainder
for both `\??\C:` and `\??\C:\`, so nothing downstream can tell the volume
device from its root directory. `:675` (`\\.\PhysicalDrive0`) needs no parser
change but carries a pin hazard — the name exists on the oracle only because
wineserver enumerated the *host's* disks. The manifest block has the full
triage.

**G2 note for whoever takes the rest:** these are NT-present names, so
adding them is not an NT-absent addition — but the SHAPE matters. A
symbolic link created through Ob's one namespace engine is fine; a special
case in the parser is a G10 failure.

### W8 — Mailslots

`NtCreateMailslotFile` plus the mailslot device plus classes 26/27.
Unblocks `ntdll:file` and `kernel32:mailslot`, the second of which measures
nothing at all today: `CreateMailslot` returns `INVALID_HANDLE_VALUE` and
the test's next call panics on class 26.

**A documentation contradiction to resolve first.**
`docs/16-syscall-status.md` files `NtCreateMailslotFile` under "no consumer
in the baked stack". The winetest gate is now a baked consumer. Either the
row moves or the pairs are excluded under manifest rule (a) with a recorded
decision — and `docs/03`'s own G5 policy for winetest ("the winetest
subtest IS the oracle-pinned differential test") argues the row must move.

**Art. 5's second limit is the real question here.** The article says
`beyond_oracle` is "a permission, not an instruction to go build every
service Wine lacks". Mailslots are the clearest place in this backlog to
ask whether the test suite counts as "something real". My reading: for this
project it does, because `docs/02` makes the winetest manifest the
verification spine of every CUI milestone. But it is a judgement call and
it belongs to the human.

### W9 — The write-then-load-an-image cluster (**triage-first**)

`kernel32:actctx`, `kernel32:resource`, and part of `ntdll:rtl`. All three
write a PE to disk at runtime and then map or execute it, and all three
fail at the map. That would be **one** bug — a section/page-cache coherence
or file-size-visibility problem on the `SEC_IMAGE` path — worth three
pairs.

**I am explicitly unsure of this.** It is a pattern across three logs, not
a diagnosis. Do not schedule the fix; schedule the triage.

### W10 — The three wedges (**one of the three is DONE — and they are NOT one bug**)

`ntdll:sync`, `ntdll:thread` and `ntdll:threadpool` all hung to their
per-pair timeout. This item used to say "they are probably one bug and
should be triaged together". **They were measured separately and that guess
is refuted**: `ntdll:thread`'s wedge is fixed, and the other two are
unchanged by the fix.

**`ntdll:thread`'s wedge — DONE.** It was
`THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE` (0x40), and the shape is worth
carrying forward. The flag exempts one THREAD from its process's freeze, in
both directions — the server reads `!thread->bypass_proc_suspend` in each
of the two fanouts (`third_party/wine` `server/process.c`,
`DECL_HANDLER(suspend_process)` / `DECL_HANDLER(resume_process)`) and stores
the bit at birth (`server/thread.c` `create_thread`). proskrnl accepted the
flag in `NtCreateThreadEx`'s word and dropped it. So in
`test_thread_bypass_process_freeze` (`dlls/ntdll/tests/thread.c`) the
created thread — which calls `NtSuspendProcess` on its own process and is
then the ONLY thread able to call `NtResumeProcess` — froze itself, and the
main thread's join never returned. Fixed in `kernel/ps/thread.c` +
`kernel/ps/process.c`, pinned by
`tests/ntapi/sem_ps/bypass_process_freeze.c`.

**Two lessons, both about *shape* rather than about this flag:**

1. **A dropped flag does not fail an assertion — it deadlocks.** G12's
   rule is about a stub fabricating an answer; this was the same defect one
   layer down, an accepted *input* silently dropped. There was nothing on
   serial for 300 s because a wedge names nothing. The other silently
   accepted create flags (`SKIP_THREAD_ATTACH`, `LOADER_WORKER`,
   `SKIP_LOADER_INIT`, `INITIAL_THREAD`) are the same class of risk and none
   of them is pinned.
2. **The pin must not be able to hang.** `test_thread_bypass_process_freeze`
   suspends its OWN process, so a wrong kernel wedges it. The `tests/ntapi`
   pin freezes a CHILD instead and measures each thread's progress by a file
   length, so a wrong kernel FAILS AN ASSERTION rather than costing the leg
   its timeout — the same technique `sem_ps/suspend_process.c` already used
   for the unexempted half.

**What `ntdll:thread` is now.** Not green: the pair runs on and panics at
the missing `NtQueueApcThreadEx` (`test_NtQueueApcThreadEx`), with
`NtAllocateReserveObject` and the `MemoryReserveObjectType*` reserve objects
behind it. Both sit in `docs/16`'s "Superseded / legacy forms — no consumer
in the baked stack" row, which the winetest gate now contradicts **exactly
the way it does for mailslots (W8)** — so this pair inherits W8's judgement
call rather than needing a new one. Everything past that panic is unmeasured
(§4 trap 2).

**The other two are still open, and each is now its own item.** Both were
re-measured after the fix and neither moved:

- `ntdll:sync` prints its own summary — "0 tests executed … 0 failures" —
  and only THEN hangs. The subtest body finishes; the PROCESS does not. That
  is a much narrower question than "it wedges".
- `ntdll:threadpool`'s old block ("a HANG with no output at all, not one
  assertion runs") was **stale**: it reaches `threadpool.c:1622` with two
  todo markers behind it before hanging.

They remain disproportionately expensive — each costs its full per-pair
timeout on every sweep — and `docs/03` records that the sweep ABORTS on
timeout rather than running more pairs against a wedged console.

**Art. 6 applies with full force**: `docs/12` names `ke/{wait,apc}.c` as
the "subtly wrong yet still runs" zone with multi-month bug latency. A
change that makes the hang stop is not a fix; only a differential test
convicts.

### W11 — npfs (**the create/open/listen refusals are DONE**)

`ntdll:pipe`'s 19 failures were **five refusals npfs never made**, and all
five are now implemented and pinned by
`tests/ntapi/sem_pipe/create_refusals.c`:

- `FSCTL_PIPE_LISTEN` on the **client** end is `STATUS_ILLEGAL_FUNCTION`, not
  `STATUS_INVALID_PARAMETER` — listening is a verb that end does not *have*,
  which is a different statement from "your arguments were wrong";
- the pipe's **share mask bounds the CLIENT's access**, which is the inverse
  of the usual share-mode reading: a `FILE_SHARE_READ` pipe is
  `FILE_PIPE_OUTBOUND`, readable by the client and never writable;
- create with **sharing 0** is `STATUS_INVALID_PARAMETER` — a pipe must NAME
  a direction, and zero is malformed rather than "share nothing";
- `FilePipeLocalInformation` needs **`FILE_READ_ATTRIBUTES` on the handle**;
- `FILE_CREATE` on an **existing** pipe is `STATUS_ACCESS_DENIED`, not the
  `OBJECT_NAME_COLLISION` a file create gives, and it is checked *after* the
  instance limit so a full pipe still reports `INSTANCE_NOT_AVAILABLE`.

The pair measured **zero failed assertions** afterwards — and then panicked
at `NtFsControlFile` with a user `ApcRoutine`, i.e. **it is now a W4a item,
not an npfs one**. Everything past that panic is unmeasured (§4 trap 2).

**Two things this item corrects.**

1. **The two pipe pairs were never one subject.** This block used to name
   them together. `kernel32:pipe` did not move with the npfs refusals except
   for the two assertions that *are* this rule (`:758`, `:778`); its
   remaining 94 are a client-read scenario repeated 76 times plus an
   overlapped-server cluster, and the create surface is not in either.
2. **`kernel32:pipe`'s "93" was never reproducible.** The merge base
   measures **96** with the same binary. Part of that pair is timing-bound —
   `pipe.c:845` is the test's own watchdog (`alarmThreadMain`), so it is a
   consequence of the overlapped cluster and not a finding (§4 trap 3) — so
   its per-line breakdown is the yardstick and its total is not.

**Every defect in this item was an ORDER or a MASK, not a value.** All five
statuses were right the first time; three of the four things that went wrong
were about *where* a guard sits, and the fourth about *which* access word it
reads. Worth carrying, because none of it is visible in a status table:

- **Length, then access.** The pin first asserted that a too-short buffer on
  an unentitled handle still reports `ACCESS_DENIED`, reasoning from the
  server guard's own order. It reports `STATUS_INFO_LENGTH_MISMATCH`: the
  class's fixed size is validated in `NtQueryInformationFile` itself, before
  the pipe object is reached (the oracle's `info_sizes[]` table,
  `dlls/ntdll/unix/file.c`). Reading a *server* guard's order as the
  *syscall's* order is how that was got wrong — **the oracle refuted it.**
- **No listener, then access.** The client-open guard was first placed above
  the listening-instance search, so a busy pipe opened with a disallowed
  access answered `ACCESS_DENIED` where the oracle answers
  `STATUS_PIPE_NOT_AVAILABLE`. Not cosmetic: `ERROR_PIPE_BUSY` is what drives
  a `WaitNamedPipe`-and-retry loop and `ERROR_ACCESS_DENIED` ends it.
- **Sharing and access, then disposition.** The create guard was first placed
  below the pre-existing disposition check, so a zero-access request carrying
  a bad disposition reported the disposition. The oracle's guard block
  precedes its disposition switch.
- **The RAW access word, not the granted mask.** The client rule is about a
  caller that EXPLICITLY names a direction, and `ObpMapDesiredAccess` folds
  `GENERIC_READ`, `GENERIC_ALL` and `MAXIMUM_ALLOWED` onto overlapping masks.
  Checking the mapped mask refused a `MAXIMUM_ALLOWED` open of an OUTBOUND
  pipe — an ordinary `CreateFile` pattern the oracle admits. `FILE_OBJECT`
  now carries the caller's own word (`docs/03`), which is the same thing NT
  hands an FSD.

**The last three were caught by GATE-CHECK, not by a test**, and that is the
lesson with the longest reach: a twelve-case matrix built from the failing
winetest assertions used only `GENERIC_*` masks against freshly-listening
pipes, so every one of those three defects passed it. The pin now measures
them (`test_client_open_precedence`) because review said to go measure, not
because the failure count did.

**`kernel32:pipe`'s big cluster is DONE and it was a FLUSH** (110 →
**28-34**, ~80 assertions; the spread is the pair's own 20 s deadline and the
manifest block explains it). The pair's block called those 76 assertions "fs/npfs
territory … the overlapped half is async-completion shaped", and both halves
of that were wrong: the cluster begins in `serverThreadMain1` and
`serverThreadMain2`, which are `PIPE_WAIT` byte echo servers with no overlap
in them, and every server-side assertion in both was already passing. On a
pipe `NtFlushBuffersFile` must not return until the PEER has consumed what
this end wrote (`server/named_pipe.c` `pipe_end_flush`); `kernel/io/rw.c`
answered a no-op `STATUS_SUCCESS` for every cache-less device, so
`FlushFileBuffers(hnp); DisconnectNamedPipe(hnp)` **discarded the echo**
before the client's `ReadFile` ran. Landed as an optional `IO_VFS_OPS.Flush`
slot plus `NpfsFlush` (`fs/npfs/pipe.c`), pinned by
`tests/ntapi/sem_pipe/flush_buffers.c`, table in `docs/03` "What a pipe's
`NtFlushBuffersFile` waits for".

Four things worth carrying:

- **This is Art. 12's fabricated-plausible answer with no stub anywhere in
  it**, the same shape as W12's `ObjectNameInformation`. `IopFlushBuffers`
  had a considered, commented reason for its early return — "a cache-less
  stream device (M9) has nothing to flush" — which is TRUE of a console and
  false of a pipe. **A no-op that is right for the device you had in mind is
  still a fabricated answer for the one you did not**, and nothing convicts
  it until an ordering somewhere else falls apart three subsystems away.
- **The failure landed in the CLIENT and the cause was in the SERVER's
  previous call**, §4 trap 4 again: the failing assertion is
  `ReadFile from client end of pipe`, the working code is
  `FlushFileBuffers`, and the four assertions BETWEEN them all passed.
- **The first implementation was correct about the wait and wrong about the
  ANSWER, and only the pair could see it.** Parking until the queue drains
  fixed the ordering — the client's reads started passing — and then all 24
  flushes returned `STATUS_PIPE_BROKEN`, because the echo clients read and
  CLOSE back to back and the parked flusher is not scheduled in between. The
  oracle decides a parked flush's status *at the transition that satisfies
  it* (`reselect_read_queue` terminates the async inside the read), so
  nothing later can change it; `NPFS_QUEUE.drainSeq` is that instant, and a
  re-check that merely asked "is the queue empty now" could not tell a drain
  from the disconnect's own `NpfsFlushQueue`. **The pin as first written did
  not cover it** — the case only appears when the drain and the close land
  before the flusher runs — and it does now (`test_flush_drain_then_peer_close`).
- **GATE-CHECK found a second, larger defect that no winetest assertion
  reaches, and it is the one worth carrying.** The new park sat OUTSIDE a
  synchronous-I/O span, and proskrnl's cancel is a per-THREAD flag that only
  `IopEnterSyncIo` resets. So a thread whose blocking pipe read had just been
  cancelled answered `STATUS_CANCELLED` to its next flush, and a parked flush
  could not be cancelled at all (`NtCancelSynchronousIoFile` needs
  `syncIoActive`, so it answered `STATUS_NOT_FOUND` and left the caller
  stuck). Both were then MEASURED on the kernel with the span removed rather
  than argued, and both are pinned. **Every new blocking point in the Io layer
  is a place the previous request's cancel can leak into**, and nothing in the
  type system says so — the flush was simply the first blocking pipe operation
  whose wrapper had no span. The same review also claimed the parked-then-
  failed flush writes `{status, 0}` into the caller's IOSB; **the oracle
  refuted that** — a failing flush leaves the block untouched whether it
  parked or not, which is what the pin now says.
- **A failing case can lie about which case failed, and this pin did.** With
  one set of globals behind the worker thread, the flush left parked by a
  broken kernel wrote its answer into the NEXT case's assertion — so the
  measurement above first read as "the flush inherited the read's cancel
  (status `STATUS_PIPE_BROKEN`)", naming the wrong subject entirely. Each
  flush now owns a state block that is never reused. **A test whose failure
  path lies is worse than one that merely fails**, and the tell is any
  worker-thread pin whose bounded wait can time out.
- **The pair was a STOPPED pair the whole time and no block said so.** `:845`
  is the test's own watchdog, and what it does after `ok(FALSE, "alarm")` is
  `ExitProcess(1)`: the run is killed 20 s in and prints no summary line. So
  every total this pair has carried — 93, 96, 94, 110 — is a lower bound over
  whatever prefix fitted in 20 seconds, which is why they drifted without a
  matching kernel change. §4 trap 2's list did not name it; it does now.

What was left was called **one subject**: the overlapped server
(`serverThreadMain3`), i.e. the W4c pended-read item, "plus the 20
consequences of the client it never lets connect". **W4c landed and that
grouping was wrong.** The overlapped server's own five are gone; the
client-open cluster is unchanged at 24. It is a second bug, not a
consequence — §4 trap 4 in its other direction, where the loudest cluster
gets attributed to the cause that happens to be nearby. Which server's
`exerciseServer` it belongs to is NOT established (only `serverThreadMain2`
traces unconditionally), and the manifest block says so rather than guessing
again.

**The `FilePipeInformation` SET LADDER is DONE** (`ntdll:pipe` 12 → **0**
inside its measured prefix), and it is the third item in this document whose
whole content was ORDER rather than value — after W11's own create refusals and
W5's `NtProtectVirtualMemory` ladder. The class is two `ULONG`s; proskrnl had
one of the five rungs. `docs/03` "The `FilePipeInformation` SET ladder" has the
table; four things belong here:

- **The ladder is SPLIT across the two halves of the oracle, and the split is
  the content.** Length and range are decided in `dlls/ntdll/unix/file.c`,
  above the `set_named_pipe_info` call and therefore above the handle; the
  handle, the access, the disconnect and the byte-pipe rule are decided in
  `server/named_pipe.c`. An out-of-range value passed through a handle that
  names no pipe reports the *value*, which no implementation that validates
  after resolving the object can answer. **This is W12's "replacing a layer
  means inheriting what that layer did", fourth instance** — and the sharpest
  one yet, because what proskrnl inherited is not a behaviour but a POSITION.
- **The SERVER end's `FILE_WRITE_ATTRIBUTES` is nobody's stated rule; it falls
  out of the handler's two-lookup retry.** The end is looked up as a server
  *with* the access, and only `STATUS_OBJECT_TYPE_MISMATCH` makes it retry as a
  client with an access of **0** — and `get_handle_obj` tests the type before
  the access, so a client handle never has its access word examined at all. So
  the check cannot be the class's required access in `kernel/io/query.c` the
  way the query direction's `FILE_READ_ATTRIBUTES` is: which end this is is not
  knowable before the file object is resolved. **A rule read off a data-flow
  accident rather than off a guard is one a status table can never show**, and
  the winetest cannot show it either — every client handle it uses carries
  `GENERIC_READ | GENERIC_WRITE`, so only a pin that opens a client without the
  bit discriminates.
- **The first implementation asked the wrong OBJECT the right question, and
  gate-check caught it rather than a test.** It read
  `FILE_OBJECT.grantedAccess`, which is the access of the original OPEN — while
  the oracle reads `entry->access`, the access of the HANDLE IN THE CALLER'S
  HAND. `NtDuplicateObject` grants specific bits verbatim, so a duplicate that
  drops `FILE_WRITE_ATTRIBUTES` names the same file object through a weaker
  handle and separates the two. **Every case in the pin was green either way**,
  because every handle in it was the original open; the fix is to resolve the
  handle a second time asking for the bit, so Ob's one check site decides it
  (G10), and the pin now weakens a duplicate to measure it. The generalisable
  tell is that *"the access" is ambiguous whenever more than one handle can name
  one object*, and a file object is exactly such a thing.
- **Five of the twelve were CONSEQUENCES in a subsystem with nothing wrong with
  it** (§4 trap 4 again). `:888/:896/:907/:918/:936` are all
  `Unexpected CompletionMode` out of `check_pipe_handle_state`, i.e. the QUERY
  direction reporting a wrong value — and the query was right throughout. A set
  that should have been refused had really changed the server end's mode, so
  every later read-back was accurate about a state that should never have
  existed. The manifest block had already grouped them correctly as one item;
  what it could not say is that only three of the twelve name the defect.
- **The pin was oracle-green on the first run, which is exactly when W16's
  reachability lesson applies.** A `PROBE` print in the two helpers every case
  goes through — three minutes, thrown away afterwards — showed all 29
  set/query calls executing with the four distinct statuses, which is what
  makes "green on the oracle" mean something for a file whose cases are all
  straight-line. It also caught a weak assertion the run could not: the
  "server end unmoved by the client's set" case had both ends at `(1, 1)`, so
  it would have passed a kernel that stored the mode on the shared instance
  instead of on the end. The server is created byte-read-mode on a
  message-type pipe now, so the two states differ.

**And the QUERY direction owed the disconnect rule too**, in both pipe classes.
`FilePipeLocalInformation` is the one that reads as a judgement call — it *has*
a `NamedPipeState` field, so reporting `FILE_PIPE_DISCONNECTED_STATE` in it is
the plausible answer, and that is what proskrnl did. The oracle refuses the
whole query. No winetest assertion reaches it; it was found by reading the
oracle's arm for the rule the SET side was being written against, and pinned
because it was found, not because anything failed.

**`FileAccessInformation` (class 8) is DONE and the PANIC IS GONE.**
`test_filepipeinfo` runs to its end and `ntdll:pipe` now stops five test
functions later, still with **zero** failed assertions. Landed in
`kernel/io/query.c`, pinned by `tests/ntapi/sem_file/access_info.c`; the table
is in `docs/03` "`FileAccessInformation` (class 8) asks Ob".

**This document called the item "a small one: the class reports the granted
access of the handle, which `FILE_OBJECT.grantedAccess` already holds", and the
second clause is false.** It is the *handle entry's* access — `entry->access`,
read by `get_handle_access` (`server/fd.c` `default_fd_get_file_info`) — and
`FILE_OBJECT.grantedAccess` is the OPEN's. A weakened `NtDuplicateObject`
duplicate names the same file object through a smaller mask and reports the
smaller mask; a duplicate made with an access of **zero** is a legal handle,
reports zero, and the query still succeeds. **An implementation that took this
document's advice passes every winetest assertion in the pair** — every handle
`ntdll:pipe` queries is the original open — and answers the create's mask
through every duplicate. It is the fifth item here whose real content was
*which* object a question is asked of rather than what the answer is, and the
second time in this section specifically (`FilePipeInformation`'s SET ladder
read `grantedAccess` where the oracle reads `entry->access`, and gate-check
caught it there; here the estimate had written the same error down as the
plan). `IopReferenceFileByHandle` grew Ob's own optional
`OBJECT_HANDLE_INFORMATION` out-parameter, so the entry's word comes from the
one resolver and `FileAllInformation` reports the same word from the same
place.

**The other half is an ORDER, and it is the inverse of every class this file
already had.** `info_sizes[FileAccessInformation]` is 0
(`dlls/ntdll/unix/file.c`), so ntdll makes NO length check and the size guard
lives inside the fd op, *below* the handle lookup — a too-short buffer through
a handle that names nothing reports the HANDLE, where `FilePipeInformation`
with the same two mistakes reports the LENGTH. Both are measured in one place
in the pin, because an implementation with a single length gate ahead of a
single handle gate cannot answer them both. The class also demands **no
access** (`get_handle_fd_obj(..., 0)`), which is what makes `pipe.c:1015`'s
`SYNCHRONIZE`-only client a success rather than an `ACCESS_DENIED`.

**The `:3187` wedge is DONE, and the code-read suspect the last revision
refused to record as a finding turned out to be right.** It was a
`FSCTL_PIPE_LISTEN` parked on a `FILE_SYNCHRONOUS_IO_ALERT` handle with a user
APC already queued: proskrnl folded `ALERT` into `NONALERT` everywhere below
`FileModeInformation`, so `IoWaitCancellable` waited non-alertably for both and
a listen with no client coming never returned. The pair runs **five functions
further** — through `test_alertable`, `test_nonalertable`, `test_cancelio` and
into `test_cancelsynchronousio` — and goes **0 → 1** failed assertion. Landed in
`kernel/{ke/ke.h,io/{async,ioctl,rw,file}.c}` + `fs/npfs/pipe.c`, pinned by
`tests/ntapi/sem_pipe/alertable_park.c`; `docs/03`
"`FILE_SYNCHRONOUS_IO_ALERT`: the park is alertable".

**Recording the suspect as a suspect was still the right call, and measuring it
was still cheap** — but it is worth noting which way it went: §4 trap 4 says
the loudest failure is usually the consequence, and here the code-read
prediction was simply correct. The rule is not "predictions are wrong", it is
"a prediction is not a measurement"; three minutes of two runners is what
converted it, and it also found two things the prediction did not contain.

Three things worth carrying:

- **The oracle states the whole rule in one argument, and the exception is a
  SERVICE not a handle.** `server_read_file`, `server_write_file` and
  `server_ioctl_file` all pass `options & FILE_SYNCHRONOUS_IO_ALERT` to
  `wait_async` (`dlls/ntdll/unix/file.c:5746/:5781/:5823`), but
  `NtFlushBuffersFileEx` passes a literal `FALSE` (`:6876`) — so a flush blocks
  through a queued APC whatever the handle says. The first draft made the flush
  alertable on the strength of "it is the handle's rule"; that is W4d's lesson
  in reverse, and it is stated at the flush site rather than as a rule about
  the layer.
- **An INTERRUPTED request completes NOTHING, and returns an NT_SUCCESS
  status.** The oracle's async is still QUEUED — only the client stopped
  waiting — so no IOSB is written, no completion routine runs and no event is
  signalled; the call returns `STATUS_USER_APC`. Because that is an
  `NT_SUCCESS` value, it is carried as an engine FLAG (`KTHREAD.syncIoAlerted`,
  set at the one place a park happens) and never read off a device's return —
  W4c's `STATUS_PENDING` lesson applied before it could be paid twice. Windows
  CANCELS instead and answers `STATUS_CANCELLED`, which the winetest marks
  `todo_wine`: **matching NT here would score a failure for being closer to
  NT**, which is Art. 6 with teeth.
- **npfs was a second `FILE_OBJECT` construction site and it had ALREADY
  drifted.** `NtCreateNamedPipeFile`'s comment says it builds the object
  "exactly as `IopCreateFile` does"; it set `synchronousIo` and nothing else,
  so every pipe handle reported a zero `FileModeInformation` whatever it was
  opened with, its `syncIoLock` was never initialised, and the bit this item
  keys on was invisible. Both sites go through `IopCaptureCreateOptions` now.
  Art. 11's "parallel paths drift even while currently equivalent" was not a
  prediction here — **a comment claiming two paths agree is the tell**, and
  only a test that needed one of the dropped bits found it.

**The `:747` wedge is DONE, and `ntdll:pipe` is MEASURED for the first time:
1 → 123 failures across 2386 tests executed** (33 todo, 0 flaky, 0 skipped),
against the oracle's 2378/35/0. The wedge was `pipe.c:747`'s
`while ((ret = WaitForSingleObject(ctx.pipe, 0)) == WAIT_OBJECT_0) Sleep(1);` —
a spin waiting for a blocking `FSCTL_PIPE_LISTEN` to take the pipe HANDLE down,
which nothing did, because W4d built the rule for `rw.c`'s transfers and the
alertable item stopped at the EVENT half for ioctls. Landed in
`kernel/io/{async,ioctl,rw}.c` + `kernel/ke/ke.h`, pinned by
`tests/ntapi/sem_pipe/ioctl_signal.c`; `docs/03` "An IOCTL clears the handle at
its PARK".

**`1 → 123` is §4 trap 2's arithmetic and not a regression**, third instance in
this document after `ntdll:virtual`'s 0 → 1199 and `kernel32:virtual`'s 4 → 96.
The 1 was a lower bound over a prefix that ended three test functions into
`test_cancelsynchronousio`. The pair now prints its SUMMARY LINE — which no
revision of its block has ever had — so from here its executed count is
comparable; it also runs in ~11 s instead of consuming the full 300 s timeout,
which the sweep pays for on every run. The manifest block has the per-line
histogram; the largest clusters are the `\Device\NamedPipe` device-root surface
(35), `FSCTL_PIPE_PEEK`'s state matrix and `FileStandardInformation` on a pipe
(32 + 6), and `FSCTL_PIPE_TRANSCEIVE`, which npfs refuses loudly (12).

**The transferable half is that the obvious transcription was WRONG and the
oracle said so before a line of kernel code existed.** rw.c's engine clears the
handle at ISSUE and restores it if the device refuses — correct for a TRANSFER,
because `pipe_end_read`/`pipe_end_write` queue every request they SERVE (their
state refusals return above the queue too, but neither has an arm that answers a
caller without queueing), so for a served transfer "issued" and "queued" are one
instant. An IOCTL's verb is decided **above**
`queue_async`: `pipe_server_ioctl` answers `STATUS_PIPE_CONNECTED` before it and
`FSCTL_PIPE_PEEK` never queues at all. So an inline peek carrying an event
leaves the handle UP on the oracle, which a clear-at-issue cannot do, and a
refusal leaves it exactly as found whether it was up or down. The pin measured
both before the implementation chose (`ioctl_signal.c` cases 3-5), and the
timing is now the caller's to state (`IOP_BLOCKING_CLEAR`) with the clear itself
made by the ENGINE at `IoWaitCancellable` — the same argument
`IO_CONTROL_CONTEXT.pended` and `KTHREAD.syncIoParked` already make: a device
that has to remember where the boundary is eventually forgets. **"Reuse the
engine" and "reuse the engine's PARAMETERS" are different claims**, and only the
second one was wrong.

**And gate-check found a second defect in the branch this item created, which is
the fourth entry in this document with that provenance.** The failure arm now
splits on "was it queued" for the event and the handle — but both tails still
FREED the completion routine's block on every failure, and the oracle decides
all three inside *one* guard (`async->pending || !NT_ERROR( status )`). So a
cancelled blocking listen, and a parked read broken by its peer, dropped a
callback the oracle delivers — with an IOSB nobody wrote as its only argument,
which is why the guess that it must be suppressed looks so reasonable. Stated
once as `IopEndFailedRequestApc` and measured on both tails. The generalisable
tell: **a pin that measured one arm of a branch reads as coverage of the
branch** — `sem_pipe/listen_apc.c` had measured the REFUSAL and its citation sat
at the site as though it covered the failure path. The pair is bit-for-bit the
same across that second fix (123 failures / 2386 executed before and after), so
nothing in `ntdll:pipe` can see it; it is pinned because it was found.

The pair's smallest remaining item is unchanged: `pipe.c:725` wants
`STATUS_ACCESS_VIOLATION` from `NtCancelSynchronousIoFile(GetCurrentThread(),
NULL, (IO_STATUS_BLOCK *)0xdeadbeef)` and gets `STATUS_DATATYPE_MISALIGNMENT`,
because `KiProbeForWrite` tests alignment before accessibility — a probe-ORDER
item, not a pipe one.

**THE PIPE'S OWN FILE INFORMATION IS DONE** (`ntdll:pipe` 123 → **99**), and
the size of it is the finding: 24 assertions across four test functions came
out of one `NpfsGetInfo` that returned zeros, plus one constant. The oracle
routes the UNIVERSAL classes to the pipe device — a pipe end has no unix fd
(`alloc_pseudo_fd`), so `server_get_unix_fd` answers `STATUS_BAD_DEVICE_TYPE`
and ntdll hands the whole class to `server/named_pipe.c`
`pipe_end_get_file_info` instead of to its own `fstat`. Landed in
`fs/npfs/pipe.c` + `kernel/io/query.c`, pinned by
`tests/ntapi/sem_pipe/pipe_file_info.c` and
`tests/ntapi/sem_file/name_info_length.c`; `docs/03` "A pipe end's own file
information" and "`FileNameInformation`'s length floor".

Four things worth carrying:

- **The two numbers answer different questions and the winetest asks in the
  one state where that shows.** `AllocationSize` is `outsize + insize` — a
  CAPACITY, the same at both ends and unmoved by traffic — while `EndOfFile`
  is `pipe_end_get_avail( pipe_end )`, so the two ends of one pipe disagree
  the moment either writes. An implementation reading the first as "how much
  is buffered" passes an empty pipe and fails `:2160` in every state that has
  data. The pin writes in one direction only, and gives the two quotas
  different values, so neither a swap nor a sum can pass by accident.
- **A universal class cannot state a required access that only one device
  has, and that is where the FILE_READ_ATTRIBUTES demand had to go.** The
  oracle's arm opens with `get_handle_access( ... ) & FILE_READ_ATTRIBUTES`,
  and no other backend demands anything for `FileStandardInformation` because
  every other backend answers it inside ntdll. `kernel/io/query.c` cannot know
  which device a handle names before Ob resolves it, so the bit is asked by
  resolving that handle a SECOND time — the shape `NpfsSetPipeInfo` already
  uses for its own server/client asymmetry, which keeps the decision at Ob's
  one check site (G10). The order is measurable and is pinned: an orphaned end
  held through an unentitled handle reports ACCESS_DENIED for
  `FileStandardInformation` and PIPE_DISCONNECTED for `FileNameInformation`,
  because only the first arm has an access guard.
- **The orphan's refusal is ONE statement because the oracle's is too.**
  *Every* arm of `pipe_end_get_file_info` carries the same `if (!pipe)`. Put
  in `NpfsGetInfo` — which every class reading this backend's facts comes
  through — `FileNameInformation` inherits it (`:2181`, `:2447`) with no
  second transcription, and so would any class added later.
- **The count moved DOWN in two places and both are the item working.** 2386
  → 2376 executed and 33 → 31 todo markers are exactly the two
  DISCONNECTED-client calls no longer running
  `test_pipe_with_data_state`'s `if (!status)` block (5 `ok()`s each, one of
  them the `:2165` todo) against a query that should have refused. Nothing was
  hidden behind them, and a line-by-line histogram diff shows only the six
  fixed lines removed.

**One residual is recorded rather than fixed, and it is older than this item.**
(SUPERSEDED — it is fixed; see "THE PIPE'S OWN LIFETIME IS DONE" below.)
proskrnl drops `NPFS_INSTANCE.pipe` when the SERVER's handle closes, where the
oracle's client holds its own reference until destroy — so a CLIENT that
outlives its server describes a pipe that is no longer there (zeros). That is
`ntdll:pipe`'s remaining `test_pipe_local_info` five (`:2356`-`:2369`), it is a
LIFETIME question and not a fill, and it is tagged `todo_proskrnl` in the pin so
it reports itself the day it is fixed.

**`FSCTL_PIPE_PEEK`'s STATE LADDER is DONE** (`ntdll:pipe` 99 → **80**), and the
manifest block had it filed as two items in two clusters — "the peek state
matrix" under `test_pipe_with_data_state` and "peek's `STATUS_BUFFER_OVERFLOW`"
under `read_pipe_test` — where it is one function. `NpfsPeek` is now
`server/named_pipe.c` `pipe_end_peek` transcribed whole; pinned by
`tests/ntapi/sem_pipe/peek_state.c`, table in `docs/03` "What `FSCTL_PIPE_PEEK`
answers, by state and by the PIPE's type".

Three things worth carrying, and two of them are shapes this document has
already paid for:

- **The overflow's axis is the PIPE's TYPE, and proskrnl had keyed it on the
  reading END's MODE.** `pipe_end->pipe->message_mode` is fixed at create;
  `FILE_PIPE_*_MODE` does not appear in the oracle's function at all. The two
  agree on every pipe whose type and read mode match — which is every pipe the
  older pin `sem_pipe/byte_mode.c` builds and every one the earlier winetest
  clusters reach — and part only for a MESSAGE-type pipe read in BYTE mode,
  which is exactly what `read_pipe_test` builds at `:1197`. **The discriminating
  case is one no rule ABOUT the reply's size can produce**; it comes out of
  asking which object the oracle asks. Fifth instance in this document of
  "*which* object a question is asked of", after `FileAccessInformation`'s
  `entry->access`, `FilePipeInformation`'s SET ladder, and the two before them.
- **The ladder's CLOSING arm asks about DATA, and its DISCONNECTED arm asks
  which END.** `if (!list_empty( &pipe_end->message_queue )) break;` makes the
  QUEUE the discriminator rather than the state word, so one handle answers
  `STATUS_SUCCESS` and then `STATUS_PIPE_BROKEN` across the single read that
  empties it — the pin measures that pair through one handle because "CLOSING
  means the peer is gone" passes every other row. And
  `pipe_end->pipe ? INVALID_PIPE_STATE : PIPE_DISCONNECTED` splits the
  disconnecting SERVER from its client, which proskrnl had folded into one
  answer through `NpfsEndDisconnected`. **The per-end fact had to be asked
  FIRST rather than folded into the switch**, because proskrnl's state word
  belongs to the INSTANCE where the oracle's belongs to the END: a re-listened
  instance moves back to CONNECTED under an end that was orphaned off it.
- **`NumberOfMessages` moved from a real count to the oracle's literal 0**,
  which is the rarer direction and is the same trade `DeletePending` already
  records. The oracle hardwires it under a FIXME; where the oracle answers at
  all it is the spec (Art. 6), and nothing on the boundary reads the field —
  `PeekNamedPipe` reports `MessageLength` and drops it. Pinned with two
  messages queued, which is the one state a real count would show in.

**The executed count rose 2376 → 2377 and the +1 is the item, counted per
line**: `test_pipe_state`'s `if (!status)` block ran 8 times and now runs 4
(four peeks correctly stopped succeeding), while `test_pipe_with_data_state`'s
`if (status == STATUS_BUFFER_OVERFLOW)` block ran 0 times and now runs 5. Todo
markers 31 before and after, so `§4` trap 2 does not apply here.

**The one assertion this item could not reach is the lifetime residual above**
(SUPERSEDED — that item is DONE below), and finding that out was the useful
half of scoping it: `:2205`'s last failure
is `in client state 4`, a CLOSING client whose `instance->pipe` is already gone,
so it forgets the pipe's TYPE and gives a byte pipe's answers. That makes the
lifetime item **six** assertions rather than five, and it now has a
`todo_proskrnl` case in two pins instead of one.

**`FSCTL_PIPE_TRANSCEIVE` is DONE** (`ntdll:pipe` 80 → **68**), and it is the
first item in this section whose subject was a whole UNBUILT VERB rather than a
rule inside a built one — `npfs` refused it `STATUS_NOT_SUPPORTED` and named
itself on serial, which is exactly what Art. 12's loud refusal is for: the
manifest block could point at the verb and the twelve assertions it owed.
`NpfsTransceive` is `server/named_pipe.c` `pipe_end_transceive` transcribed
whole; pinned by `tests/ntapi/sem_pipe/transceive.c`, table in `docs/03` "What
`FSCTL_PIPE_TRANSCEIVE` writes, and what it refuses".

Four things worth carrying, and the first two are shapes this document has paid
for before:

- **Eleven of the twelve assertions are REFUSALS, and the verb's own work is
  one.** `test_pipe_state`'s eight are the state ladder
  (`pipe_end->pipe ? STATUS_INVALID_PIPE_STATE : STATUS_PIPE_DISCONNECTED`,
  the same split `FSCTL_PIPE_PEEK`'s ladder makes and asked through the same
  `end->orphaned`), and `test_transceive`'s four are the round trip. So the
  cluster was mostly a LADDER wearing a verb's name — which is why it landed in
  one session where a "whole unbuilt verb" reads like several.
- **The discriminating case is one no winetest assertion asks for, and it is
  the one that decides the implementation's SHAPE.** `pipe_end_read` opens with
  a `NAMED_PIPE_NONBLOCKING_MODE` arm answering `STATUS_PIPE_EMPTY`;
  `pipe_end_transceive` has no counterpart. So a NOWAIT-mode end refuses a read
  and PENDS a transceive in the same state, and an implementation that
  tail-calls its own read path — the obvious one, and the one that reuses the
  most code — fails exactly that and nothing else. `NpfsAwaitRead` takes it as
  its single parameter rather than growing a second loop (Art. 11), which is
  also what makes the two share one request queue: both oracle paths end in
  `queue_async( &pipe_end->read_q, async )`, so a read issued behind a parked
  transceive cannot take the first reply.
- **The oracle refuted the pin's account of that same NOWAIT arm.** The first
  draft expected the read BEHIND a parked transceive to pend "because the
  transceive is ahead of it"; it is refused exactly as it would be with nothing
  outstanding, because the arm tests `list_empty( &pipe_end->message_queue )` —
  BUFFERED DATA, never outstanding requests. The queue-order claim was true and
  belonged in its own case on a handle where nothing refuses; measuring the two
  in one place would have passed a kernel that had neither rule.
- **The pended arm is what finally gave `kernel/io/ioctl.c` its DATA LEGS**, and
  the comment it replaces was an accurate statement that had become false: "an
  ioctl carries no data leg (its output travels in outBounce)". True while no
  ioctl could park with a reply outstanding, and this is the verb that can — so
  the output buffer and its bounce now travel in the `IO_CONTROL_CONTEXT`
  exactly as `rw.c`'s transfers' do, with the same ownership rule and the same
  single completer. `kernel/io/io.h`'s `IOP_PENDING_REQUEST` comment expected the
  legs' next consumer to be "a future genuinely pended DATA transfer (Net-1's
  AFD is the expected consumer)"; it is an FSCTL instead, which is `docs/19`
  §5d's point rather than a miss — the ownership rule was made
  device-independent precisely so a verb nobody listed inherits it. **Three more
  comments in `vfs.h`, `io.h` and `ioctl.c` naming "the npfs read" as the only
  data-leg consumer were true when written and are false after this diff**, and
  gate-check found all three rather than a test: they are corrected in the same
  commit, which is this bullet's own defect class applied to itself.

The write half is the one place it deliberately does NOT reuse the neighbouring
path: `NpfsAppendBuffer` directly rather than `NpfsWrite`, because the oracle
says *"transaction never blocks on write, so just queue a message without
async"* — an ordinary write past the peer's quota parks its caller and a
transceive of the same bytes over the same full queue does not. That is measured
(`transceive.c` §5), and it is the one case whose failure mode is a HANG rather
than an assertion, which is why it runs on an asynchronous handle and asserts the
one answer a parked writer cannot give.

**The pair's executed count is unchanged at 2377 with 31 todo markers**, and a
line-by-line histogram diff shows only `:1450`/`:1456`/`:1457`/`:1458` and
`:2069`×8 removed with no other line moved — so `§4` trap 2 does not apply here
and nothing was hiding behind the twelve.

**The PORT-versus-APC refusal is DONE** (`ntdll:pipe` 68 → **60**, the eight at
`:3094`), and it is the first item in this section whose subject is not npfs at
all: it is the one refusal the whole asynchronous surface makes about its own
arguments. A handle bound to an I/O completion port and a call carrying an
`ApcRoutine` are `STATUS_INVALID_PARAMETER` — `create_async`'s last statement
(`server/async.c`, `if (async->completion && data->apc)`), landed as
`IopPortApcConflict` (`kernel/io/{io.h,async.c}`) and pinned by
`tests/ntapi/sem_port/port_apc.c`; the table is in `docs/03` "A completion PORT
and a completion APC ROUTINE are mutually exclusive".

Four things worth carrying, and the first two are the ones an implementation
written from the status alone gets wrong:

- **Its REACH is the requests the SERVER queues, not the syscall's arguments,
  and the oracle serves the other arm ITSELF.** A regular disk file's transfer
  never reaches wineserver (`dlls/ntdll/unix/file.c` `NtReadFile` `pread()`s it
  locally), so the same combination is *admitted* there and ntdll resolves the
  conflict the other way — `cvalue = apc ? 0 : (ULONG_PTR)apc_user`, the APC
  runs and no packet is posted, which `IopPostRequestPacket` has implemented
  since CUI-8. So the refusal belongs to `rw.c`'s DEVICE branch, `ioctl.c` and
  `notify.c`'s watch arm; hoisted into `NtReadFile` it passes every pipe case
  in the pin and refuses a disk read the oracle serves. The pin measures the
  disk arm for exactly that reason — **a rule whose two arms disagree is one
  the pin has to walk, not one it may reason about** (§4 trap 4's smaller
  sibling, and the same argument `map_ex.c` made for
  `MEM_EXTENDED_PARAMETER_EC_CODE`).
- **WHERE it sits is as measurable as what it answers, and proskrnl had merged
  the two statements it sits between.** The oracle resets the caller's EVENT
  above the guard and clears the FILE OBJECT below it, in `queue_async` — so a
  refused request leaves the event DOWN and the handle UP.
  `IopBeginBlockingRequest` is where W4d merged those two on purpose, which is
  what made the placement obvious rather than delicate: the refusal goes
  *inside* that function, between its halves, and needs no
  `IopEndBlockingRequest` to put anything back. **A merge that was chosen for
  one item paid for itself in the next one**, which is the opposite of the usual
  outcome for a merge.
- **The rule is about the ROUTINE, never the CONTEXT**, and the context is what
  every overlapped Win32 caller passes — it IS the packet's value. An
  implementation keyed on `apcContext` refuses the ordinary case and passes
  nothing but the winetest's own rows, since `test_async_cancel_on_handle_close`
  varies both.
- **It precedes every verb**, because it is made when the request is CREATED.
  `FSCTL_PIPE_PEEK` is answered inline and never queues, and it is refused just
  the same — which is the case that says the guard belongs at the issue point
  and not in a device.

**The pair's executed count is unchanged at 2377, with 31 todo markers and 0
skipped before and after**, and a line-by-line histogram diff shows only `:3094`
removed with no other line moved — so `§4` trap 2 does not apply and nothing was
hiding behind the eight.

**And the pair's LARGEST cluster is now measured per line rather than read off
the oracle, which is worth more than the eight.** The manifest called
`test_empty_name`'s 35 one item, "the `\Device\NamedPipe` device-root surface".
It is three, and the biggest of them is a NAME-RESOLUTION item rather than an
npfs one: **25 of the 35 are consequences of `NtCreateNamedPipeFile` refusing a
`RootDirectory` that names a FILE**. It resolves its attributes through
`ObpLookupParseObject` alone (`fs/npfs/pipe.c`) where `IopCreateFile` has taken
a relative FILE root since M6, so `:2842` (an UNNAMED pipe created with an empty
name under a `\Device\NamedPipe\` handle) and `:2932` (a pipe whose name carries
a separator, `"test3\pipe"`, under the same handle) both answer
`STATUS_OBJECT_TYPE_MISMATCH`, and the 23 assertions behind them are querying,
opening, writing and reading the null handles those two never returned. §4 trap
4 again. The other two items are `:2810` — the same call one line earlier, where
a NAMED create under the DEVICE handle must be `STATUS_OBJECT_NAME_INVALID`, so
the work is "tell the device from its directory" and not merely "accept a file
root" — and the nine-assertion device-root ioctl ladder (`:2751`×8 plus
`:2787`). The manifest block has all three with their statuses.

**THE RELATIVE-ROOT CREATE AND OPEN ARE DONE** (`ntdll:pipe` 60 → **37**), and
this is the rare entry where the previous revision's triage was right in every
particular: one cause, 23 consequences, and the histogram diff removes exactly
those 23 lines with nothing else moved. `NtCreateNamedPipeFile` takes a relative
root now, and `NpfsVfsCreate` takes one that names a pipe END. Landed in
`fs/npfs/pipe.c` + `kernel/io/file.c`, pinned by
`tests/ntapi/sem_pipe/pipe_root.c`; the table is in `docs/03` "What ROOT a
named-pipe create and a pipe-relative open accept".

Four things worth carrying, and the first is the one that makes the item bigger
than "accept a File root":

- **The oracle decides the two names in two different PLACES, and that is the
  content.** An EMPTY name is decided in the handler — "pipes need a root
  directory even without a name" — where the root is resolved with
  `get_handle_obj( process, rootdir, 0, NULL )` (any type, no access) and then
  never read, because `create_named_object`'s empty-name arm allocates an
  UNLINKED object. A NAMED create is decided in the LINK, `named_pipe_link_name`,
  which folds the device's root directory onto the device and refuses every
  other parent. So the same call has **an any-root rule and a one-root rule**
  depending on a field that is not the root, and an implementation with one gate
  over both answers half the matrix wrongly whichever gate it picks. `pipe_root.c`
  walks it: an event is a legal root for the unnamed create and
  `STATUS_OBJECT_NAME_INVALID` for the named one.
- **`STATUS_OBJECT_TYPE_MISMATCH` is the answer to THREE unrelated questions
  here**, which is why the pin measures each through its own root: `FILE_OPEN`
  of an empty name (the root resolves to itself and is not a `named_pipe`), an
  `NtCreateFile` empty-name open under the device's root directory
  (`named_pipe_dir_open_file`'s `if (dir->fd) return no_open_file(...)` — it is
  already a file object), and an empty-name open under a CLIENT end
  (`no_lookup_name`'s NULL arm). The fourth arm of that last function gives
  `STATUS_OBJECT_NAME_NOT_FOUND` for a NON-empty name, so one oracle function
  produces two statuses and only a pin that asks both can tell an
  implementation that returns one for the whole end.
- **The unnamed pipe is reachable only through its own server end, and that is
  what forced the Art. 11 split.** `pipe_server_open_file` is a bare tail call
  onto `named_pipe_open_file`, so the by-name client open and the by-end one are
  the same function on the oracle; `NpfsAttachClient` is the one transcription
  both proskrnl callers use. Writing the by-end arm as its own attach loop would
  have been shorter and would have drifted at the first change to the listener
  search — which is the failure mode Art. 11 names, arriving here as "the pipe
  the winetest reads from is the one nothing can look up".
- **The failure MODE of `:2810` changed and its count did not**, and saying so
  is the honest half of this entry. proskrnl used to refuse every File root, so
  the one assertion that wants a refusal passed by accident of a wrong rule;
  it now accepts where NT refuses. Telling `\Device\NamedPipe` from
  `\Device\NamedPipe\` needs `ObpLookupName` to report the trailing separator it
  currently swallows — which is **the same change W7's `\\.\c:` is blocked on**,
  so those two are one `kernel/ob` item and neither is an npfs one.

**Two items are left in this cluster and neither is npfs's.** `:2810` is the
parser item above. `:2849`/`:2881` are `NtQueryObject(ObjectNameInformation)` on
an unnamed pipe end, which owes `STATUS_OBJECT_PATH_INVALID`
(`named_pipe_get_full_name` refusing when `default_get_full_name` finds no name)
and answers SUCCESS with an EMPTY name — **for every FILE handle in the system,
not just this one**, because `IoFileObjectType` has no `OBJECT_TYPE.queryName`
hook and Ob's generic walk finds no name for an object that was never linked
into the namespace. That is the same defect W12 convicted for registry keys,
one type over, and it is deliberately not scoped with this item: the fix changes
what a FAT file, a console handle and a device handle all answer.

**Nothing was hiding behind the 23** — 2377 tests executed, 31 todo markers and
0 flaky before and after — so `§4` trap 2 does not apply here.

**THE DEVICE-ROOT FSCTL LADDER IS DONE** (`ntdll:pipe` 37 → **29**, the eight at
`:2751`), and the first thing to record is that **the paragraph above said "two
items are left in this cluster and neither is npfs's" and there were three, the
largest of them npfs's.** The revision one step back had counted the ladder
correctly — "the nine-assertion device-root ioctl ladder (`:2751`×8 plus
`:2787`)" — and the sentence written after the relative-root item landed dropped
it. Nothing measured changed in between; a summary was rewritten from the two
items its author had just been thinking about. **A "what is left" sentence is a
claim with a number in it, and it is one histogram away from being checked.**

`NpfsDeviceControl`'s root arm is `server/named_pipe.c` `named_pipe_device_ioctl`
transcribed whole; pinned by `tests/ntapi/sem_pipe/device_ioctl.c`, table in
`docs/03` "What the named-pipe DEVICE ROOT answers to each pipe FSCTL".

Three things worth carrying:

- **The three answers do not collapse into "wrong object for this verb", and
  that reading is what proskrnl had.** `STATUS_ILLEGAL_FUNCTION` is a statement
  that the object does not HAVE the verb (LISTEN, IMPERSONATE);
  `STATUS_PIPE_DISCONNECTED` is a STATE the device is not in (DISCONNECT,
  TRANSCEIVE); `STATUS_INVALID_PARAMETER` is about the ARGUMENTS
  (QUERY_CLIENT_PROCESS) and is decided above any look at them. One switch, three
  kinds of sentence — which is only visible as a MATRIX. A status table shows the
  values and hides that they are answers to different questions.
- **`FSCTL_PIPE_PEEK` is the discriminating row and no winetest assertion
  convicts it.** It is as much a per-instance verb as LISTEN, so
  `ILLEGAL_FUNCTION` is what a ladder grouped by meaning gives, and proskrnl gave
  it; the oracle never names PEEK in the switch, so it falls to
  `default_fd_ioctl`'s unknown-verb default. `pipe.c:2721` asks exactly that call
  and is `todo_wine` (it wants NT's `INVALID_PARAMETER`), so the row is pinned
  because the oracle answers it — the same provenance as the four `docs/03` rules
  in this section that came out of reading the oracle's arm rather than out of a
  failing assertion.
- **What is NOT transcribed is stated rather than absorbed.** The four verbs
  `default_fd_ioctl` handles specially (`FSCTL_DISMOUNT_VOLUME` →
  `STATUS_BAD_DEVICE_TYPE` off the pseudo fd, the three reparse ones →
  `STATUS_OBJECT_TYPE_MISMATCH` for want of a `unix_name`) fold into the
  `NOT_SUPPORTED` default, which keeps its serial line for exactly that reason.
  A default arm that is simultaneously an implemented answer and an unbuilt
  corner is the one place Art. 12's loud refusal earns its noise.

**Two items are left in this cluster and neither is npfs's**, which is now a
counted statement: `:2810` and `:2787` are one `kernel/ob` parser item (the
device told from its root directory — `FSCTL_PIPE_WAIT` is the single arm where
`named_pipe_dir_ioctl` does not tail-call the device's ladder), and
`:2849`/`:2881` are the `ObjectNameInformation` item above.

**Nothing was hiding behind the eight** — 2377 tests executed, 31 todo markers
and 0 flaky before and after, and a line-by-line histogram diff removes exactly
`:2751`×8 with no other line moved — so `§4` trap 2 does not apply here.

**THE PIPE'S OWN LIFETIME IS DONE** (`ntdll:pipe` 29 → **22**), and the finding
is that a pipe has TWO lifetimes where proskrnl had one. The OBJECT is
referenced by every END (`server/named_pipe.c` `init_pipe_end`'s `grab_object`,
released in `pipe_end_destroy`); the NAME goes with the last INSTANCE
(`pipe_server_destroy`'s `if (!--pipe->instances) unlink_named_object`).
proskrnl freed the whole `NPFS_PIPE` at the last server end's cleanup, so a
client that outlived its server described a pipe that was gone — zeroed type,
configuration, instance limit, quotas and `AllocationSize`, and a byte pipe's
peek because the TYPE had gone too. The pointer moved onto the end
(`NPFS_END.pipe`, over a reference count) with the two teardowns separated:
`NpfsUnlinkPipe` at `instanceCount` 0, `NpfsDereferencePipe` per end. Landed in
`fs/npfs/pipe.c`, pinned by `tests/ntapi/sem_pipe/pipe_lifetime.c`; `docs/03`
"How long a pipe outlives its NAME".

Four things worth carrying:

- **Six of the seven are a fix and the seventh is a TRADE, and the honest half
  of this entry is saying which.** The manifest scoped this at six assertions;
  it moved seven. The extra one is `:2185`, filed as "cannot go green while
  proskrnl is the more NT-correct runner" — and that note was RIGHT. The oracle
  refuses `FileNameInformation` on a closing client under its own
  `/* FIXME: We should be able to return on unlinked pipe */`, the winetest
  wraps the `STATUS_SUCCESS` assertion in a `todo_wine_if` because real NT
  reports the name, and proskrnl reported it. Adopting the oracle's refusal
  moved that line FARTHER from NT and took a failure off the count for doing
  so. It is the same trade `docs/03` records for `DeletePending` and this
  document records for `STATUS_USER_APC` (Art. 6 with teeth), and it is forced
  besides: the "report the name" answer is un-pinnable — the oracle refuses, so
  no G5 case can be green on it, and `beyond_oracle` is barred by its own
  definition for behaviour Wine DOES implement. **What the old block missed was
  not the ceiling, it was the CAUSE**: `:2185` is the NAME half of the very
  lifetime the other six are the OBJECT half of, so it belonged in this
  cluster whatever was then done about it. A "cannot go green" note is a
  verdict on the answer and never an excuse to stop asking what produces it.
- **A second field saying the same thing as a pointer is Art. 11's hazard
  before it is a bug.** `NPFS_END.orphaned` was a bit meaning exactly
  `pipe_end->pipe == NULL`, kept beside a pipe pointer that lived one level up
  on the INSTANCE — three `docs/03` sections said so in prose. Moving the
  pointer to the end deleted the bit, and every `if (!pipe)` the oracle's
  handler makes is now that one field. Nothing was broken by the duplication;
  it simply made a lifetime question unaskable, which is the failure mode
  "parallel paths drift even while currently equivalent" describes for state
  rather than for code.
- **`CurrentInstances` is the one field that must NOT follow the object**, and
  the winetest was passing it for the wrong reason. It is `pipe->instances`,
  which really does fall to zero when the last server leaves, so a surviving
  client owes five real values and a zero — an implementation that keyed all
  six on one liveness bit answers all six the same way, and a zeroed struct
  passed `:2358` while failing the five beside it.
- **The unlink follows the INSTANCE COUNT, not "a server end closed", and no
  winetest assertion reaches that.** With a second instance open the name stays
  in the namespace, the client of the closed instance reports
  `CurrentInstances 1` and its own name, and a further open by that name still
  connects. `pipe_lifetime.c` §3 is the case; §2 is its complement, where the
  same handle reports the pipe's quotas and refuses its name in the same
  instant, and an implementation that merely stopped FREEING the pipe hands a
  later client the dead one.

**The two counts that moved are accounted for per line, and one of them is the
trade rather than the item.** 2377 → 2378 executed is
`test_pipe_with_data_state`'s `if (status == STATUS_BUFFER_OVERFLOW)` inner
`ok()` now RUNNING for the closing client — the peek used to answer `SUCCESS` —
and it passes. 31 → 32 todo markers is `:2185` moving from "succeeded inside
todo", which counts as a failure, to a todo that fails as expected: that is the
`todo_wine` trade above, so **read the pair as 29 → 23 on the fix and one more
off the top for matching the oracle where it differs from NT**. A line-by-line
histogram diff removes exactly
`:2185`/`:2205`/`:2356`/`:2357`/`:2359`/`:2366`/`:2369` with no other line moved.

**What is left is four items and the largest of them is now `test_security_info`
(10), which is UNTRIAGED.** The oracle serves it off the PIPE object
(`pipe_end_get_sd`: `if (pipe_end->pipe) return default_get_sd(
&pipe_end->pipe->obj )`), so it is a `Se` question asked through a pipe handle
rather than an npfs one — but which of the ten are causes and which are
consequences has not been measured, and this document is not going to guess
(§4 trap 4).

**WHAT A FILE HANDLE IS CALLED IS DONE** (`ntdll:pipe` 22 → **20**, the two at
`:2849`/`:2881`), and it is the smallest item in this section with the widest
reach: `NtQueryObject(ObjectNameInformation)` answered SUCCESS with an EMPTY
name for **every file handle in the system**. `IoFileObjectType` now carries
`OBJECT_TYPE.queryName` — W12's hook applied to the fourth type, as this
document predicted — and `docs/03` "What a FILE handle is called in the object
namespace" has the rules. Pinned by `tests/ntapi/sem_pipe/object_name.c`.

Four things worth carrying, and the first is where the design decision was:

- **The composition belongs to the Io layer, not to each filesystem.** A
  `FILE_OBJECT` is never in the Ob namespace; the DEVICE is, and everything past
  it belongs to that device. So `IopQueryFileObjectName` is the one place that
  concatenates the device's own name with the volume-relative path
  `IO_VFS_OPS.QueryName` **already** builds for `FileNameInformation`, and a
  filesystem's whole say is a boolean — `namedInObjectNamespace`. The
  alternative, a per-FS "full name" op, would have been a second name source for
  one fact (Art. 11) and would have let the two spellings of "what is this file
  called" drift.
- **A default that looks like a gap and is the measured answer.** Devices that
  do NOT opt in keep reporting the empty name, and that is right: the oracle's
  `no_get_full_name` (every console object carries it) returns NULL with no error
  set, which `DECL_HANDLER(get_object_name)` turns into a zero-length reply. So
  the hook's contract had to grow a third outcome — a name, a refusal, or "this
  kind of object has no name" — where W12's had two, and the "a hook that
  succeeds owes a name" assertion moved from the generic arm into
  `CmpQueryKeyObjectName`, which is the type that can promise it.
- **The too-short status is a property of WHICH `get_full_name` answered.** A
  file gets `STATUS_BUFFER_OVERFLOW` where a registry key gets
  `STATUS_INFO_LENGTH_MISMATCH` for the same mistake — every file-ish arm in the
  oracle sets it explicitly and the generic walk does not. It is invisible except
  for a buffer between the fixed struct's size and the full size, and the pin
  measures exactly that band.
- **The prefix of a DISK file's name is a runner disagreement, and saying so is
  the honest half.** The oracle reports `\??\C:\prstest\objname.txt` (its fd's
  captured name); proskrnl composes `\Device\HarddiskVolume1\...`, which is NT's
  answer. A pin asserting either spelling would have been tuning to a runner, so
  §6 pins what both satisfy — the name ends with the file's path, the directory's
  name is the file's minus its last component, and the length protocol — and
  `docs/03` carries the trade.

**GATE-CHECK found a ring-3 panic in the first draft, and it is the fifth item
in this document with that provenance.** The hook's length was a `USHORT`
because `OBJECT_NAME_INFORMATION.Name.Length` is one, with an
`ASSERT(total <= 0xffff)` and a comment reasoning about FAT depth. But a pipe's
name is the CALLER's `ObjectName`, bounded only by `UNICODE_STRING`'s own
`USHORT` — so 32760 characters relative to `\Device\NamedPipe` composes to
65556 and stopped the machine. The review derived it by reading; the pin then
measured it, and the measurement is what decided the fix. A too-small buffer had
to keep the oracle's ordinary `STATUS_BUFFER_OVERFLOW` (65574, measured on both
runners), so the length is a `ULONG` all the way to the fill arm and only the
answer that cannot EXIST is refused — `STATUS_NAME_TOO_LONG`, in `kernel/ob/`
rather than per type, because it is a property of the answer's shape. Above that
buffer the oracle answers SUCCESS with `Length` **20**: 65556 truncated into the
`USHORT`, i.e. a different object's name, which is why §7 is `beyond_oracle`
against the documented `UNICODE_STRING` contract and not a divergence from
something Wine implements. **The transferable half is the one the assert's own
comment got wrong: a bound argued from the SHALLOWEST producer is not a bound.**

**Two records this item corrects, both of which were true when written.** The
manifest's "`:2810` and `:2787` need the device told from its root DIRECTORY"
survives the hook untouched, and that was worth checking rather than assuming:
proskrnl now reports `\Device\NamedPipe\` for the device root exactly as the
oracle does, because it composes the DIRECTORY's answer — the one spelling it
has. And `docs/03`'s GUI-2 notes still said proskrnl's
`ObjectNameInformation` "returns an object's leaf name rather than NT's full
path", with "making the name query answer full paths is NT-correct and unbuilt"
beside it; it has answered the full path since `docs/review-2026-07` §9. The
sentence had been read as a live constraint for two milestones.

**Nothing was hiding behind the two** — 2378 tests executed, 32 todo markers and
0 flaky before and after, and a line-by-line histogram diff removes exactly
`:2849`/`:2881` with no other line moved — so `§4` trap 2 does not apply here.

**WHOSE SECURITY DESCRIPTOR A PIPE HANDLE REPORTS IS DONE** (`ntdll:pipe`
20 → **10**), and the manifest's guess about it was right for once: the ten
assertions of `test_security_info` were ONE subject, and the subject was not
npfs. A pipe **END has no descriptor of its own** — the oracle's
`pipe_end_get_sd` and `pipe_end_set_sd` are both
`if (pipe_end->pipe) return default_{get,set}_sd( &pipe_end->pipe->obj )`
(`server/named_pipe.c`) — so both ends of every instance of one name read and
write a single blob, and an end whose pipe is gone REFUSES with
`STATUS_PIPE_DISCONNECTED`. proskrnl kept it on the `FILE_OBJECT`, i.e. one per
open handle. Pinned by `tests/ntapi/sem_pipe/pipe_security.c`; `docs/03` "Whose
security descriptor a pipe handle reports".

- **The defect's shape is the one this document keeps meeting from the other
  side: a per-handle answer to a per-SUBJECT question.** It is
  `notify_queue.c`'s "the notification state belongs to the HANDLE, not the
  request" (W4b) one level up, and `object_name.c`'s "the NAME belongs to the
  PIPE, not the end" (above) asked through a different syscall. The tell is the
  same each time — every set-then-query-*the-same-handle* case passes, and the
  storage is only convictable by a SECOND observer. **Nine of the ten winetest
  assertions are a second observer**; the tenth is a create-time descriptor.
- **The fix is a REDIRECT, not a second get/set** (Art. 11).
  `OBJECT_TYPE.securityStorage` answers *which slot*, never *what it says*, so
  Se keeps its one capture/merge/filter path and the type that redirects gains
  no reading of an SD; `IO_VFS_OPS.SecurityStorage` is the same question one
  layer down, so the Io layer does not grow a per-device branch. The refusal
  sits BELOW the handle's access check for free, because a hook is only reached
  once the handle resolved — which is the oracle's own order
  (`server/handle.c` resolves with the per-info-bit access, *then* calls
  `get_sd`) and is the only thing an under-privileged query on a disconnected
  end can tell apart.
- **The create-time descriptor was a SECOND authority hiding behind a comment
  claiming there was one.** `SeCaptureObjectSecurity`'s header said it was "the
  ONE create-time SD site (G11)" and stored the caller's blob RAW, with
  "token-defaulting of missing parts is `NtSetSecurityObject`'s job (no baked
  create passes a partial SD)" beside it. The oracle defaults at create too —
  `create_object`/`create_named_object` call `default_set_sd( obj, sd,
  OWNER|GROUP|DACL|SACL )`, which is `set_sd_defaults_from_token` — and the
  winetest's `CreateNamedPipeA(..., &sec_attr)` passes exactly the partial SD
  the comment said nobody passes. Giving the pipe its own create-time capture
  would have made the comment false; routing both through the merge made it
  true. Pinned for the Ob half by `sem_se/se_secobj.c`, because that half moved
  for every object type, not just for pipes.
- **Nothing was hiding behind the ten** — 2378 tests executed, 32 todo markers
  and 0 flaky before and after, and a line-by-line histogram diff removes
  exactly `:2605`/`:2611`/`:2620`/`:2621`/`:2625`/`:2632`/`:2638`/`:2641`/
  `:2643`/`:2664` with no other line moved, so `§4` trap 2 does not apply.

**WHAT A CLOSE DOES TO A PARKED REQUEST IS DONE** (`ntdll:pipe` 10 → **5**),
and the subject is not npfs and not the packet path: it is what the OBJECT
MANAGER owes the Io layer at a handle close. A process that closes the last
handle IT holds on a pipe end — while another process's duplicate keeps the end
alive — has the requests it left parked there cancelled for it. proskrnl had an
answer for the last handle in the SYSTEM (the filesystem's cleanup) and none at
all for the moment in between, so the request stayed parked forever with the
caller's IOSB unwritten and `GetQueuedCompletionStatus` waiting on a packet
nobody would post. Landed in `kernel/ob/{ob.h,handle.c}` +
`kernel/io/{io.h,async.c,file.c,vfs.h}` + `fs/npfs/pipe.c`, pinned by
`tests/ntapi/sem_pipe/close_cancel.c`; `docs/03` "What CLOSING a handle does to
the requests that process left parked".

Four things worth carrying:

- **`OBJECT_TYPE.closeProcedure` grew NT's own signature, and that is the whole
  design decision.** `async_close_obj_handle` asks two counts —
  `obj->handle_count` and `get_obj_handle_count( process, obj )`, both including
  the handle being closed — and proskrnl's hook fired only at 1 → 0, so the
  question "is this the last handle THIS PROCESS holds" was not merely
  unanswered but unaskable. NT's `OB_CLOSE_METHOD` fires on every close and
  takes exactly that pair (`ProcessHandleCount` / `SystemHandleCount`), and
  NT's own `IopCloseFile` answers two different questions off it. So the hook
  became NT's, and the three types that only ever wanted the last-handle moment
  (job, debug object, registry key) now open with `if (systemHandleCount != 1)
  return;` — **the statement they had been making by being called nowhere
  else**. A hook whose *moment* is implied by where the engine calls it cannot
  grow a second moment; one that is told which moment it is, can.
- **"Was this request port-bound" and "which port gets the packet" are the same
  field read at two different INSTANTS, and only a pin can tell them apart.**
  W4c established that the packet's port is re-read at completion, so a bind
  landing while a request is parked still posts (`sem_pipe/pending_packet.c`
  §4). This predicate reads `async->completion` — what `create_async` captured
  at ISSUE — and never re-reads it, so the same late bind does **not** arm the
  sweep. `IOP_PENDING_REQUEST.portBoundAtIssue` exists for that one difference;
  an implementation that reused the late read passes §1–§5 of the pin and fails
  only §6. Sixth instance in this document of "*which* object (or instant) a
  question is asked of" being the item's real content.
- **Where the rule STOPS is decided by which devices can PARK, and no branch
  names a device.** The sweep goes through `IO_VFS_OPS.CancelPending`, which
  only a filesystem that queues requests implements — so npfs is swept and
  fat32 is not, exactly as the oracle hangs the op off the pipe-end and socket
  object types. Directory watches are deliberately NOT swept (`server/change.c`
  `dir_close_handle` releases a cache entry and nothing else), and that falls
  out of the same fact rather than out of a second rule.
- **An EVENT disarms the sweep, which reads as a bug and is the contract.** The
  thing a caller is most likely to be waiting on is exactly what stops the
  cancel. Eleven of the pin's cases are negative for that reason: the winetest
  runs sixteen rows and exactly one reaches a cancel, so the fifteen that do not
  are as much of the rule as the one that does.

**The manifest's note on `:3111` was true about the assertion and wrong about
the count, and the distinction is the honest half of this entry.** It said the
succeeded-todo "cannot go green while proskrnl is the more NT-correct runner",
and it still cannot — it did not go green. It stopped being a FAILURE: the
cancel writes the caller's IOSB the way the oracle does, so the `todo_wine_if`
now fails as expected. Windows leaves the block untouched until
`NtRemoveIoCompletion`. Adopting the oracle's answer moved that one line
FARTHER from NT and took a failure off the count for doing so — the same trade
the pipe-lifetime item's `:2185` records, and the same one `STATUS_USER_APC`
does (Art. 6 with teeth). **Read the pair as 10 → 6 on the fix and one more off
the top for matching the oracle where it differs from NT.**

**Nothing was hiding behind the five** — 2378 tests executed, 0 flaky and 0
skipped before and after, todo markers 32 → 33 (exactly `:3111` crossing from
"succeeded inside todo" to a todo that fails), and a line-by-line histogram diff
removes exactly `:3111` and `:3114`×4 with no other line moved — so `§4` trap 2
does not apply here.

**One thing this item read off the oracle and did NOT measure, recorded as a
suspect rather than as a finding (`§4` trap 4).** When the last handle in the
SYSTEM closes, wineserver terminates the end's queued asyncs with
`STATUS_HANDLES_CLOSED` (`server/async.c` `free_async_queue`, reached from
`pipe_end_destroy`), where proskrnl's `NpfsVfsCleanup` completes them
`STATUS_CANCELLED`. No assertion in `ntdll:pipe` reaches it and this item did
not touch that path. It is a candidate next item, and it is a code read, not a
measurement.

### W12 — Registry (**triaged; the fold, the license furniture and the namespace rules are DONE — everything left is ONE DATA QUESTION**)

`ntdll:reg`, now **156** failures across 1042 tests, down from 192 across
1050. The manifest block has the full breakdown; five things belong here.

**This item's own diagnosis of its largest cluster was wrong.** It said the
24 failures at `reg.c:1354` were "`NtCreateKey` answering
`STATUS_OBJECT_PATH_SYNTAX_BAD` … a NAME question, which W3 has just made
cheaper to reason about". Measured, none of that holds: the call is
`NtOpenKey` (the assertion's message text says `NtCreateKey` and is simply
wrong), and the refusal is **right** — its `RootDirectory` is a handle an
earlier failed open left at zero, so the kernel is asked to resolve a
relative name with no root, which is exactly that status on both runners.
**§4 trap 4, from reading the failure TEXT instead of the test's helper.**
What stops the cluster is registry furniture the image does not carry
(`Software\Classes\Interface`, `Software\Wow6432Node`) — §4 trap 6, and a
question with a decision inside it rather than an implementation: may a
kernel with no WOW64 carry a `Wow6432Node` key? Roughly 156 of the
remaining 172 are that one question asked in four places.

**The name fold is a TABLE now, not a rule (DONE).**
`RtlUpcaseUnicodeChar` reads the NLS upcase trie generated from the pinned
tree's own `nls/l_intl.nls` (`kernel/lib/upcase.h`, `tools/gen_upcase.py`),
which is the same data BOTH halves of the oracle fold through — Wine's PE
ntdll maps it (`dlls/ntdll/unix/env.c` `init_environment`) and wineserver
reads the lowercase half for `memicmp_strW` (`server/unicode.c`), which is
what compares a registry key name. Total over the BMP, per 16-bit code unit.
Pinned by `tests/ntapi/sem_reg/key_name_fold.c` and
`sem_file/name_case_fold.c`; `docs/03` "Name case folding" carries the trade.

Four things worth carrying forward:

- **One missed fold cost twenty assertions, in three test functions that
  are not about folding.** `reg.c:346` creates a key whose name reaches
  Latin Extended-A and Greek, `:353` re-opens it upper-cased, `:357` deletes
  it. The open missed, so the delete got a null handle, so the subkey
  OUTLIVED its test — and only a leaf key is deletable, so its parent
  (`\Registry\User\<SID>\WineTest`) could never be deleted again.
  `test_NtDeleteKey`'s entire deleted-key contract (`:821-:851`), the
  symlink test's delete, `NtRenameKey`'s subkey enumeration and
  `RtlQueryRegistryValues`' call count all failed behind it. This is §4
  trap 4 with a new twist: the consequence was not merely *louder* than the
  cause, it was in a different SUBJECT, and it persisted across test
  functions because the leak was in the registry rather than in a variable.
  The evidence is unusually direct — `:2380` printed the leftover by name.
- **A rule is a claim; a table is not.** `docs/03` recorded this fold as a
  hand-written rule twice, each time judging the unfolded remainder
  "unobservable", and user mode reached past it both times (`ntdll:directory`
  for Latin-1, `ntdll:reg` for the rest). The generalisable form: when the
  oracle carries DATA and proskrnl carries a rule that approximates it, the
  deviation is not "the part nobody uses" — it is "the part nobody has used
  YET", and the cost of being wrong is paid in a subject far from the fold.
- **The table is not Unicode's simple uppercase, and the pin says so.**
  U+03C2 folds to itself where U+03C3 folds to U+03A3; U+0131 folds to
  itself; U+01C5 folds to itself where U+01C6 folds to U+01C4. An
  implementation written from the Unicode character database passes every
  other case here and fails those three.
- **And it is per code UNIT.** `reg.c:350` requires the low surrogates
  U+DC00 and U+DC28 — the two cases of one astral code point — to stay
  different names. Decoding surrogate pairs before folding is the "more
  correct" thing to do and fails exactly there.

**The executed count fell with the failure count (1050 → 1042) and that is
not a loss:** six of the cleared assertions were per-iteration over a subkey
list with one stale entry in it, so removing the entry removes 4 iterations
× 2 `ok()`s — 4 that were failing and 4 that were passing.

**The four singleton assertions are DONE** (`ntdll:reg` 160 → **156**), and
they were three unrelated rules that only looked like one item because each
was small. `docs/03` "M8 Cm notes" carries all three; the manifest block has
the numbers. What belongs here is what each one says about *where to look
next*:

- **`:550`/`:557` — "always case-insensitive" was half-implemented, and the
  code comment saying otherwise was the reason.** A registry path is resolved
  by two engines: `\Registry` is an **Ob** name (whose walk honours
  `OBJ_CASE_INSENSITIVE`) and everything under it is a Cm subkey (whose
  compare ignores the flag entirely). A caller passing `Attributes = 0` was
  therefore asking for a case-SENSITIVE match on the single component Cm never
  compares. The oracle folds it in `dlls/ntdll/unix/registry.c` — **the half
  proskrnl replaces at the unixlib seam** — and `kernel/cm/registry.c` had
  cited that exact file as the reason the kernel needed no code for it. The
  citation was correct; the conclusion was self-refuting. **Replacing a layer
  means inheriting what that layer did**, and this is the second instance of
  the shape after W1's `STATUS_NOT_IMPLEMENTED` split, which is the same seam
  read the other way. A sweep of `dlls/ntdll/unix/` for behaviour that is
  *performed there* rather than merely *forwarded* is now an evidenced hunt,
  and the tell is a kernel comment that cites `unix/` for why something is
  absent. Pinned by `sem_reg/root_case.c`, with the negative controls doing
  the real work — the oracle refuted the first draft, where a create under
  `\REGISTRY` manufactured the very name the next open was meant to miss.
- **`:854` — the winetest could only see the DELETED case of a defect that
  covered every case.** `NtQueryObject(ObjectNameInformation)` answered success
  with an empty name for *any* key handle, because keys are Cm tree nodes and
  Ob's walk sees only the one namespace object. That is Art. 12's
  fabricated-plausible answer with no stub anywhere in it, and the assertion
  that convicted it is about deletion, not about naming. Fixed with an
  `OBJECT_TYPE.queryName` hook — the oracle's own `key_ops.get_full_name`
  shape, answering from the same `CmpBuildFullPath` `KeyNameInformation` uses
  (Art. 11), refusing before the buffer-size protocol. **This is the third
  optional `OBJECT_TYPE` hook** after `mapAccess` (W2) and the type's generic
  mapping, and all three exist for the same reason: a type whose behaviour the
  oracle keeps in its own `*_ops` table needs a place to put it that is not a
  second engine.
- **`:1312` — the refusal was right and the STATUS was wrong.** A symlink loop
  answered `STATUS_OBJECT_NAME_NOT_FOUND`, which says the name is absent; every
  name in a loop is present and it is the *request* that cannot be served. The
  oracle says `STATUS_INVALID_PARAMETER`, and its bound is on the same quantity
  with the same value (`server/object.c` `lookup_named_object`'s
  `recursion_count > 32`). The pin covers **two** loop shapes and that is the
  transferable part: a self-extending target grows the path one component per
  follow, so a LENGTH bound stops it, while a two-link cycle keeps the path a
  constant size and only a FOLLOW-COUNT bound stops that. A pin with only the
  first would pass an implementation that hangs on the second.

**With those gone the pair has no small items left**, and that is the useful
statement about it: all 156 remaining failures are the `Software\Classes\Interface`
and `Software\Wow6432Node` furniture — one data question carrying one human
decision (may a kernel with no WOW64 carry a `Wow6432Node` key?). Nothing here
is triage any more.

**The license furniture is DONE** (`ntdll:reg` 172 → **160**, the 12 at
`reg.c:1009-:1032`). `wine.inf`'s `[LicenseInformation]` writes **eleven**
values into `Software\Wine\LicenseInformation` — not the three this document
said, which counted only the `Kernel-MUI-*` rows and missed the eight
`Shell-*InBoxGames*` ones below them — and `CmInitialize` seeded exactly one
by hand, so `Kernel-MUI-Number-Allowed` answered
`STATUS_OBJECT_NAME_NOT_FOUND`. The seed is now the WHOLE section, generated
out of the pinned `wine.inf` (`kernel/cm/license.h`, `tools/gen_license.py`,
the `gen_upcase`/`gen_sysini` shape: checked in, with a Makefile `--check`
that catches a pin bump editing the section). Pinned by
`tests/ntapi/sem_reg/license_value.c`.

Three things worth carrying forward, none of them about license values:

- **The advice to generate rather than transcribe was right for a reason
  this item then demonstrated.** The transcribed seed was not merely a
  maintenance risk in the abstract — it was *already wrong when written*,
  and by more than the winetest could see: it carried one of eleven values.
  A hand-copied subset is a claim about which lines matter, and the claim is
  invisible in the code that makes it. The generator's whole value is that
  its claim ("the key is what the INF writes") is checkable.
- **`docs/16` had a stale row and the winetest gate had already falsified
  it.** `NtQueryLicenseValue` sat under "no consumer in the baked stack"
  while `table.inc` carried a `KI_SYSCALL` row for it — implemented a
  session earlier, for this very pair. Corrected: 202/264 → **203/264**,
  61 missing. It is the same shape as W8's and W10's open question (the
  winetest gate IS a baked consumer), except here the id was already built
  and only the record disagreed. Worth a sweep next time that document is
  re-derived: the recipe at its head is exactly what would have caught it.
- **What the pin measures is the SECOND value, not the first.** Every
  assertion in the existing `license_value.c` passed on a kernel that knew
  one name and one type, because `type` and `retlen` are read out of the
  stored value. The added block asks the same size/type protocol of a
  `REG_DWORD` value — which is the general form: a pin over a keyed lookup
  measures the LOOKUP only if it asks for more than one key.

### W13 — Time-zone data, then a clock (**DONE — `kernel32:time` is GREEN**)

The table is seeded whole and generated: 139 zone keys plus their 92
`Dynamic DST` subkeys, 2576 values, parsed out of the pinned kernelbase's own
WINE_REGISTRY resource (`dlls/kernelbase/kernelbase.rgs`) by
`tools/gen_timezones.py` into `kernel/cm/timezones.h`, seeded by
`CmInitialize`. Pinned by `tests/ntapi/sem_reg/timezone_keys.c`; the manifest
block has the numbers.

**The source was one layer further in than "the pinned prefix", and finding
it is the reusable part.** This item said the data "must come from the pinned
prefix rather than from memory". The prefix is a *rendering*, not a source —
`wineboot --init` writes it — and generating from `build/tests/wineprefix`
would have made the kernel's table depend on a directory the build does not
own. The actual pin is a `WINE_REGISTRY` resource compiled into kernelbase and
applied by `dlls/setupapi/fakedll.c` `register_resource` through atl's
`IRegistrar`, so the generator parses the *registrar script grammar*
(`dlls/atl/registrar.c` `get_word` / `do_process_key`) — including the two
things a from-the-format-docs parser gets wrong: `d` is `wcstoul(..., 10)`, so
`d 2000` is decimal and not hex, and `''` inside a quoted word is one literal
quote. Byte-for-byte agreement with the prefix's own 231 keys was then checked
row by row, which is the confirmation that the resource is where the prefix
came from rather than a parallel copy of it.

**The item's other half was not in the item, and the manifest block had it
wrong.** Four failures at `:990-:1008` were filed here as "downstream of the
same gap". They were `tzres.dll` missing from the baked image — §4 trap 6, the
same shape as W14's `win.ini`, one directory over from the hive this item was
about. What makes them *visible* rather than harmless is an asymmetry inside
kernelbase: `GetDynamicTimeZoneInformation` and `GetTimeZoneInformationForYear`
resolve the same `MUI_Std` through the same `RegLoadMUIStringW` and disagree
about its FAILURE — the first ignores the error and leaves the raw
`@tzres.dll,-22000`, the second falls back to the zone's plain `Std`. So a
missing resource file does not degrade both APIs equally; it makes them
contradict each other, and the test compares them. **A shared resolver is not
a shared answer when the callers differ in how they handle its failure.**

**The last assertion was a CLOCK, and it is now built: the pair is GREEN on
both legs** (2358 tests executed, 0 failures, the oracle's count exactly).
`time.c:843` wants `GetSystemTimePreciseAsFileTime` to advance by under 1 ms
between two calls that report different values; it is `RtlGetSystemTimePrecise`,
which on this kernel is `NtQuerySystemTime` (the fork's arm in
`dlls/ntdll/time.c`), so it moved in whole ticks. `KiTickFraction`
(`kernel/ke/timer.c`) adds the TSC-measured fraction of the tick in progress,
calibrated on the same PIT gate that sets the LAPIC timer's period — one
measurement, two consumers, so the subdivision cannot disagree with the thing
it subdivides. Pinned by `tests/ntapi/sem_ps/precise_time.c`; `docs/03`
"Sub-tick system time" carries the trade.

**This block said "one 10 ms tick" and the tick is 1 ms** — `KI_100NS_PER_TICK`
is 10000 and `arch/x86_64/lapic.c` programs the LAPIC periodic at 1 ms. Nobody
had measured it: the winetest prints no delta, and the figure was written from
the *shape* of the failure rather than from a number. The pin prints one, and
it read exactly 10000 (100 ns units) eight times out of eight. Harmless here —
1 ms fails `< 1 ms` just as 10 ms does — but it is §4 trap 4's smaller sibling:
a quantity nobody measured, recorded in a triage block as though somebody had.

**What made the design safe is the CLAMP, not the counter**, and that is the
half worth carrying to any future hardware clock. The fraction is capped one
unit short of a whole tick, so a reading can never reach the value the next
tick will publish — monotonicity survives a TSC that runs fast, drifts with
P-states, or is calibrated wrong, and each tick re-bases the error. So no
invariant-TSC probe is made and no second time base exists; the tick remains
the clock and this only subdivides it. The same clamp is what keeps the
conversion from overflowing, because it is applied in TSC units *before* the
multiply.

**Two things the change did NOT do, both deliberate.** The shared page stays
tick-granular — a mirror published once per tick cannot be refreshed by writing
an interpolated value into it — so a query now reads up to one tick ahead of
`KUSER_SHARED_DATA.SystemTime`, which is the relation Windows has and the
direction every ordering pin here already wanted. And no Wine patch was
needed: `GetSystemTimeAsFileTime` and `GetSystemTimePreciseAsFileTime` both
land on `NtQuerySystemTime` on this kernel (`dlls/kernelbase/file.c`), so
making the syscall precise moves both together and `test_GetSystemTimeAsFileTime`'s
ordering assertions keep comparing one clock with itself. **A precise clock
reachable only through a second, differently-sourced entry point would have
failed exactly those** — which is why the pin measures coarse-against-precise
agreement as well as resolution.

**Two things a finer clock made VISIBLE rather than created, and both are
open items rather than parts of this one.** Neither is convicted by anything
today, and neither gets bent to fit without a pin first (Art. 5):

- **A relative wait can expire slightly early.** `KiComputeDueTime` arms off
  the tick while the clock that measures the wait is now sub-tick, so a
  1 ms wait armed 0.9 ms into a tick can be timed at ~0.1 ms. That was
  always true; only the measuring instrument changed. NT rounds the other
  way. Arming off the fraction instead is a one-line change that moves every
  timeout up to a tick LATER, which is why it needs a pin on a wait's lower
  bound before it lands — the tree has none.
- **`NtQuerySystemTime` runs ahead of the shared page**, where on NT it *is*
  the page. `docs/03` "Sub-tick system time" has the bound, the direction and
  the one upstream assertion that points the other way. The real fix is the
  Windows arrangement — a QPC baseline in `KUSER_SHARED_DATA` that user mode
  interpolates for itself — which is a layout item, not a clock item.

**Where the pin could not point, and why.** The resolution assertions go
through `RtlGetSystemTimePrecise` rather than straight at `NtQuerySystemTime`,
because the ORACLE's `NtQuerySystemTime` picks `CLOCK_REALTIME_COARSE` whenever
the host reports it at 1 ms or better (`dlls/ntdll/unix/sync.c`). Aiming the
assertion at the syscall would have made the pin's colour depend on the
developer box's `CONFIG_HZ` — a host-local residue manufactured by the test,
which is the thing the manifest header spends its longest paragraph on.

**A note for the next generated seed, because there will be one.** A 3600-line
generated header is not `make format`-stable: clang-format reflows the byte
table and aligns the `#define`s, which rewrites a checked-in generated file and
breaks its own `--check` on the next run. The generator emits
`// clang-format off`. `kernel/cm/license.h`'s header already warned about this
hazard for a single identifier; at table scale it is not a warning, it is a
requirement.
### W14 — `kernel32:profile` (**DONE — and it closes, without going green**)

Never a numbered item here; it sat in the manifest as "the smallest item on
the board, 6 failures". It measured **7**, and worked to its floor it was
**two** subjects, neither of them the one the block guessed at. (The
uncounted seventh, profile.c:229, is a `todo_wine` that PASSES on proskrnl;
winetest scores a succeeded todo as a failure, and a log scanned for "Test
failed" does not show it. §4's trap 2 has a sibling here: a count is only
worth what the way it was read is worth.)

- **Three of the seven were the IMAGE, not the kernel.** profile.c:95/:101
  and :229 all read `%windir%\win.ini`, which the wtest image did not have:
  it carries no `wineboot.exe`, so smss skips firstboot and the `wineboot
  --init` pass that writes `win.ini`/`system.ini` (wine.inf `[SystemIni]`)
  never ran — while the oracle leg runs in a wineprefix where it did. The
  image now bakes both, generated from that same `[SystemIni]` payload
  (`tools/gen_sysini.py`, `--check` proves it byte-identical to a prefix).
- **The remaining four are the FAT floor** and the pair is now category (2),
  with no `TODO`. `test_profile_directory_readonly` needs a volume that
  stores and enforces a directory DACL; FAT32 has nowhere to put one, and
  `fs/fat32/fat.c` says so by reporting no `FILE_PERSISTENT_ACLS`. NT on FAT
  answers this test the way proskrnl does. `docs/03` M6 has the note.

The confirming measurement was already in the tree and nobody had connected
it: `docs/03` "M10 winetest notes" records that running the ORACLE as an
ordinary user instead of root took `kernel32:profile` "from 4 to 0". Same
count, same mechanism (unix permission bits standing in for the DACL) —
which is what makes "the volume must enforce ACLs" a measurement rather
than a hypothesis. That run logged the count and not the line numbers, so
the two sets being the SAME four is an inference from count plus mechanism;
they are the whole of this subtest's failing assertions either way.

### W16 — What a live SECTION holds against a later OPEN (**DONE**)

`kernel32:file` **164 → 38**, one subject, 126 assertions. NT models a section as a
pseudo-open of its file carrying magic access bits (`FILE_MAPPING_ACCESS` /
`_IMAGE` / `_WRITE`, `third_party/wine` `server/file.h:303-305`, set in
`server/mapping.c` `create_mapping`) which `server/fd.c` `check_sharing` reads back
as four rules. proskrnl had **one** of the four, and had it reading the wrong access
bit. Landed in `kernel/io/file.c` (three `IO_FCB` counters, applied inside
`IoCheckShareAccess`), pinned by `tests/ntapi/sem_mm/section_file_hold.c`; the table
and the five non-obvious parts are in `docs/03` "What a live SECTION holds against a
later OPEN".

Five things worth carrying beyond the rules themselves:

- **The gate ran BELOW the escape it needed to be above, and that is where 96 of the
  126 lived.** proskrnl's `IoCheckShareAccess` opened with NT's "an attribute-only
  open ignores share modes" early-out, which is correct *for share modes* and is why
  the mapping rules never saw an opener asking for nothing. The oracle's ladder puts
  all four section rules above that escape and between `check_sharing`'s two
  share-mode directions — so the fix was not a new check, it was **moving an existing
  return three statements down**. Same shape as W11's "every defect in this item was
  an ORDER or a MASK, not a value", and W5's `NtProtectVirtualMemory` ladder: a
  validation placed where a careful implementation would put it, where NT does not.
- **The image rule is `FILE_WRITE_DATA` alone, and the tidy grouping is the bug.**
  Every other share-mode rule in NT reads `FILE_WRITE_DATA | FILE_APPEND_DATA`, and
  proskrnl's image gate reused that pair — costing exactly the two append-only
  columns × eight sharing modes = the 16 at `file.c:2663`. `docs/03`'s CUI-9 hazard-F
  paragraph had *stated* the wider scope as though it were measured; it was not, and
  the oracle refuted it. **A residual recorded in prose is a claim**, and this one had
  been sitting in `docs/03` for a milestone — alongside a second claim in the same
  paragraph ("a `DELETE`-access open of a live image still passes") that this item
  half-closed.
- **Six of the 126 were outside `test_file_sharing` and read as three unrelated Win32
  symptoms.** `CopyFile` onto a mapped destination (`:847`/`:848`), the same through
  `CopyFile2` (`:1174`/`:1175`), and `DeleteFile` of a mapped image
  (`:1931`/`:1932`). The first two are `CREATE_ALWAYS` and the third is an open
  carrying `FILE_DELETE_ON_CLOSE`, so all three are the truncate and delete rules in
  Win32 spelling. §4 trap 4 with the consequence landing in an API whose name says
  nothing about sections — the manifest had filed two of the three under "a handful
  around CopyFile of a mapped or self-named file" and did not list the third at all.
- **The counting itself was the item's third measurement defect, and it is the one
  most likely to recur.** The manifest said 152; the merge base measures **164** with
  the same binary. Two independent ways to get it wrong, both paid for here: grepping
  `Test failed` misses the 14 `Test succeeded inside todo block` lines (W14's lesson,
  again), and **the proskrnl leg's console REDRAWS a wrapped line** — the location
  prefix, a bare CR, then the whole line — so a per-line counter that does not drop
  the empty first draft reports one assertion twice. An earlier draft of this entry
  said 166 → 39 for exactly that reason. Any triage block quoting a serial-log count
  should say which parser produced it.
- **The pin's own reachability had to be measured, because it was green first try.**
  28 opens across six blocks, every one behind an `if (section != NULL)`, is a shape
  that runs green while measuring a fraction of itself (§4 trap 2 in miniature). A
  throwaway `ntapi_printf` in the one helper every case goes through printed 28 lines
  and the four distinct statuses, which is what makes "green on the oracle" mean
  something here. Cost: one three-minute run.

**A second defect fell out of gate-check and is its own commit.**
`IopSectionFileAccess` — the new one-authority function — was documented as "the
oracle's protection switch" while implementing only two of its three rows:
`PAGE_EXECUTE` and `PAGE_NOACCESS` demand **no file access at all**
(`dlls/ntdll/unix/sync.c` `NtCreateSection`, `:2999-:3001`), so a
`CreateFileA(name, 0, …)` handle can back a `PAGE_NOACCESS` section, and proskrnl
answered `STATUS_ACCESS_DENIED`. No winetest assertion reaches it; the existing pin
`sem_mm/section_file_access.c` had the row in its own HEADER and no `ok()` for it,
which is how a citation came to claim coverage that did not exist. **A comment that
names a pin is a claim about that pin, and it is checkable** — this is the third time
in this document that gate-check convicted a citation rather than a behaviour.

**What it did NOT do:** the pair still stops in exactly the same place, the panic at
`file.c:3338`'s `CreateMailslotW` (W8), so 38 is a lower bound like every other
stopped pair's and 164 → 38 is a like-for-like comparison of the same measured
prefix. `ntdll:virtual`'s lesson applies unchanged — nothing past the stop has ever
been counted.

**What is left there, and some of it is not work.** 16 at `:3208` (FindFirstFile's
`"*."` pattern, a FAT short-name question) is the largest item; 14 are succeeded-todo
markers where proskrnl is the more NT-correct of the two runners, which is the
`kernel32:volume:186` shape and needs reading before it is scheduled; 3 are
`CopyFile`/`CopyFile2` of a file to ITSELF failing to report
`ERROR_SHARING_VIOLATION`, a plain share-mode question with no section in it and the
cheapest thing on the board; 5 are singletons.

### W17 — The user profile (**DONE — `kernel32:environ` is GREEN**)

`kernel32:environ` **1 → 0**, un-parked, in the gate. Its single failure was
`environ.c:74`, `GetUserProfileDirectoryA` answering `ERROR_FILE_NOT_FOUND`,
and the fix is furniture in the `win.ini` / time-zone / LicenseInformation
line: `ProfileList\ProfilesDirectory` + a per-SID `ProfileImagePath` in
`kernel/cm/registry.c`, `USERPROFILE` in `kernel/ps/peb.c`'s default
environment, and `C:\users\wine` baked by `tools/mkimage.sh`. `docs/03` "The
USER PROFILE is seeded" has the table; pinned by
`tests/ntapi/sem_reg/user_profile.c`.

Three things worth carrying:

- **It is three statements of one fact, and any two of them are worse than
  none.** userenv COMPOSES its answer (`ProfilesDirectory` + `\` + the account
  name) and the winetest asserts that answer equals `%USERPROFILE%`, so
  seeding the registry alone moves the failure from "no profile" to "the two
  disagree" — same count, new triage block, no progress. The account name is
  the third leg and it was already fixed: `LookupAccountSidW`'s RID-1000 arm
  is `GetUserNameW`, which Wine implements as
  `GetEnvironmentVariableW(L"WINEUSERNAME")` (`dlls/advapi32/advapi.c`), and
  CUI-2 had put `WINEUSERNAME=wine` in that same default environment for the
  same reason. **A furniture item's unit is the whole chain a consumer walks,
  not the value the failure names.**
- **The pin had to measure the RULE, not the path**, for the reason W5's
  `shared_machine.c` did. The two runners disagree about the user name by
  construction — the oracle's `WINEUSERNAME` comes from the host account
  (`dlls/ntdll/unix/env.c`), proskrnl's is fixed — so `C:\users\wine` is a
  pin on one developer's box. What holds on both is
  `USERPROFILE == ProfilesDirectory\<name>`, which is exactly the equality
  `environ.c:80` asserts through two different APIs. Measured on both runners:
  the oracle composes `C:\users` + `tetsui`, proskrnl `C:\users` + `wine`, and
  the SID naming the subkey is `S-1-5-21-0-0-0-1000` on both.
- **§4 trap 2 with the good outcome, and it is worth stating.** `:74`'s
  failure early-outs past `:78` and `:80`, so those two had never run. They
  run now and pass: 430 executed / 1 failure / 3 skipped → **432 / 0 / 2**,
  which is exactly the two assertions and the skip that reported them. Nothing
  else was hiding.

**What is deliberately NOT seeded**, and the reason is the LicenseInformation
lesson pointing the other way: `Flags` beside `ProfileImagePath`, and
`Public`/`ProgramData` beside `ProfilesDirectory`. The whole-section argument
that generator applies is about a payload a consumer INDEXES by name; these are
three values nobody in the baked stack reads, and the last two would also owe
directories and the `ALLUSERSPROFILE`/`PUBLIC` variables the oracle mints from
them (`add_registry_environment`) — i.e. seeding them describes folders that
are not there. Art. 5: no consumer convicts them.

### W18 — The 8.3 alias's leading run (**DONE — `kernel32:file` 38 → 22**)

Sixteen assertions, one character, and the whole item is which leading run
`FatGenerateShortName` (`fs/fat32/dir.c`) strips before it picks the alias's
extension separator: **leading dots, and not leading spaces**. Pinned by
`tests/ntapi/sem_file/short_names.c` §7-8; `docs/03` "The 8.3 alias's leading
run" has the rule.

The pair is still parked — it panics at `CreateMailslotW` (W8) exactly where
it did before, 34 todo markers before and after — so this is a like-for-like
38 → 22 over the same measured prefix, not a verdict that moved.

Four things worth carrying:

- **All sixteen failures were one file, sixteen times.** Every `:3208`
  message read "found incorrectly ' .a'" and **missed nothing**. A cluster
  whose every member names the same wrongly-INCLUDED item is one bug by
  arithmetic, and reading the messages was the whole triage — the shape §4
  trap 4 keeps asking for.
- **The triage block named the right subject and the wrong half of it.** It
  said "FindFirstFile with the `*.` pattern — a FAT short-name question",
  which pointed at the MATCHER. The matcher is right: every one of the
  sixteen masks reduces to `<` or `a<` through kernelbase's `fixup_mask`, and
  `<` correctly refuses to reach any alias carrying a dot. What was wrong was
  the ALIAS ` .a` was matched against. **"Short-name question" was true and
  still sent the reader to the wrong file.**
- **A value the two runners cannot share can still have a shared BIT, and
  this file had recorded the opposite.** `short_names.c` said the
  value-dependent truth-table cells "can only ever be checked by the winetest
  pair itself", because the oracle hashes an eight-character base and FAT
  uses a numeric tail. They agree exactly on whether the alias carries an
  extension, which is the only property `<` reads — so the cells are
  pinnable after all, and are. The general form: **before recording a value
  as unpinnable, ask which PROJECTION of it the consumer actually reads.**
- **The negative control was worth the thirty seconds.** The new section was
  oracle-green on its first run, which is exactly what a vacuous assertion
  looks like (§4 trap 2 in miniature). Inverting two of the cases and
  re-running the oracle proved they were live before any kernel code was
  written.

**A correction to `kernel32:file`'s other item fell out of it.** The block
called the CopyFile-to-itself trio "a plain share-mode question"; it is not
one. `copy_file`'s only producer of `ERROR_SHARING_VIOLATION` is
`is_same_file()`, i.e. two `NtFsControlFile(FSCTL_GET_OBJECT_ID)` calls
compared byte-for-byte, and proskrnl implements no such fsctl. That is read
off the code and consistent with the failure text (`ret=1 err=0`), not
probed, and the manifest says so. It also is not free work: the oracle answers
the fsctl for every file while NT on a FAT volume refuses it, which is the
same decision `kernel32:volume:2022` is parked behind.

### W19 — A pseudo-handle as a duplication SOURCE (**DONE — `kernel32:virtual` 4 → 1**)

`kernel32:virtual`'s three real failures were one call, and the pair now has
no failing assertion left that is not the todo floor. `NtDuplicateObject`
looked its SOURCE handle up in the source process's TABLE and nowhere else,
so `DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS)` — the documented
way to turn a pseudo-handle into a real one, and the first line of
`test_ReadProcessMemory` — was `ERROR_INVALID_HANDLE`, with the two
`ReadProcessMemory` assertions behind it reading through the handle it never
got. Fixed in `kernel/ob/handle.c`, pinned by `tests/ntapi/sem_ob/dup_pseudo.c`
plus one case in `sem_ob/dup_cross_process.c`; `docs/03` "A magic pseudo-handle
as a duplication SOURCE" has the four rules.

Three things worth carrying:

- **It is an Art. 11 defect with a completely ordinary tell: a second lookup
  path.** `ObReferenceObjectByHandle` had resolved the magic handles since
  CUI-2 and `NtDuplicateObject` called `ObpEntryInTable` directly, so the two
  agreed about every handle that was in a table and about nothing else. The
  server has exactly ONE such site (`get_magic_handle` inside
  `get_handle_obj`), which is why the fix is to extract
  `ObpReferencePseudoHandle` and have both ask it rather than to add the
  range test twice. **The tell generalises: a syscall that reads a handle
  TABLE rather than calling the resolver is a parallel path even when the
  reason it does so is good** — here it was, the duplication genuinely needs
  the source ENTRY's rights and attributes.
- **What a pseudo source is WORTH is separate from what it names, and both
  are synthesised.** No entry means no recorded rights, so the server invents
  them: `map_access( obj, GENERIC_ALL )`, i.e. the type's whole mask, and no
  attributes. That is the `DUPLICATE_SAME_ACCESS` value ONLY — an
  implementation that stamped it onto every duplicate passes the winetest and
  over-grants every specific-rights duplication, which is why the pin asks for
  `PROCESS_VM_READ` alone and asserts it comes back holding exactly that.
- **The magic handles resolve against the CALLER, not against the process the
  caller named.** `get_magic_handle` takes no process argument. So
  `NtDuplicateObject(childProcess, NtCurrentProcess(), …)` yields the CALLER's
  process — measured on both runners rather than reasoned about, in the file
  whose subject is already "which process does each end name".

**The block's diagnosis was wrong twice and the count was right**, which is §4
trap 4 in its cheapest form: it named `test_far_regions` and "the
cross-process leg", and the failing function is `test_ReadProcessMemory` with
all three ends of the call naming the caller's own process. Both readings came
from the assertion TEXT ("DuplicateHandle failed 6"); one `grep` of the line
number settled it. **Trap 3 also ran backwards here**: the block called the
`0xc0000005` behind these three a cascade of them, and it is not — the crash
is bit-for-bit unchanged with the three fixed.

**The crash is diagnosed and is the pair's next item**, and it is `mm/`, not
`ob/`. That item is W20 below, and it is DONE.

### W20 — Which region the guard-page fault path GROWS (**DONE — `kernel32:virtual` reaches its summary line, and the pair is now category 2**)

`kernel32:virtual`'s `0xc0000005` is gone and the pair runs to the end of the
module for the first time: **30865 tests executed, 142 todo, 1 skipped, 1
failure**, exit `0x1`. The one failure is the `:1465` todo floor W19 left —
a `todo_wine` proskrnl passes — so **there is no kernel work left in this pair
and its manifest block no longer carries `# TODO: Implement`.** The
deciding constraint is G9: the only changes that would turn it green are
dropping the `todo_wine` in the pinned tree (patching the oracle to make a
divergence pass — Art. 10 forbids it) or regressing
`NtAreMappedFilesTheSame`.

The cause was exactly as W19 diagnosed it, which is worth saying because this
document more often records the opposite: `:4735` returns into
`test_stack_commit`, which reserves 4 MiB, commits only the top page
`PAGE_GUARD`, **rewrites its own TEB**
`DeallocationStack`/`StackBase`/`StackLimit` at it and runs a function there
(`virtual.c:2486-:2499`). `MiHandleUserFault` answered "is this a stack?" from
`ETHREAD.stackAllocationBase`/`stackBase`, so the guard touch was refused, and
delivering that exception wrote one page below the guard and faulted for real.
It now reads `DeallocationStack` and `Tib.StackBase` out of the FAULTING
thread's TEB and applies the oracle's own comparison (`is_inside_thread_stack`,
`dlls/ntdll/unix/virtual.c`: `ptr > start && ptr <= end` on the fault address
rounded down). Pinned by `tests/ntapi/sem_mm/teb_stack_growth.c`; `docs/03`
"Which region the guard-page fault path GROWS" has the rules.

Four things worth carrying:

- **"Believing the TEB is believing user mode" is true and is not an
  objection**, which is the half W19 left open as a decision. The entire
  action behind the growth arm is committing one page of the caller's OWN
  address space and writing the caller's OWN TEB — both things the caller can
  do for itself with `NtAllocateVirtualMemory`. There is no privilege on the
  other side of the trust, so the "authority" being conceded is only a
  process's right to say where its own stack is, which is the only definition
  NT has of one. The generalisable form: **an authority question is only a
  security question when the two answers differ in what the caller could have
  done alone.**
- **The trap-2 arithmetic came back the OTHER way, and that is a measurement,
  not luck.** A pair that stops has not been measured, and this document's own
  rule of thumb is that the real count is an order of magnitude above the
  reported one. Here it is 1 → 1: the histogram has the same single line, the
  142 todo markers are identical per line, and everything `test_stack_commit`
  and the rest of the module execute was already correct. The crash was the
  only thing standing there. Removing a stop is still the only way to know
  that — the prediction was worth exactly as much as it usually is.
- **The oracle refuted the pin's first draft, and what it refuted was the test
  design rather than a rule.** The draft used four-page regions, so its touch
  landed inside the oracle's GUARANTEED SPACE — `grow_thread_stack` splits on
  `page >= start + page_size + max(TEB.GuaranteedStackBytes, 2 * page_size)`
  and the low arm commits the guarantee and raises **`STATUS_STACK_OVERFLOW`**
  instead of pushing another guard. The draft's handler did not answer that
  code, so the SEH dispatcher ran, found the registration chain outside the
  synthetic stack the TEB was claiming, and killed the process with no output
  at all. proskrnl does not implement that arm (`docs/03`, and nothing in the
  frontier convicts it — `test_stack_commit` stops one page above where the
  guarantee begins); the pin's cases now sit clear of it and count the code
  separately so they cannot drift back in.
- **A test that lies about its own stack has to keep the lie SHORT, and the
  reason is the kernel it is testing.** Inside the window the real stack is
  not a stack, so any call that reaches a fresh page takes the refusal arm —
  on a kernel that grows on demand, that is a fault whose delivery writes to
  the page that was not committed. The pin touches the frames it will use
  before opening the window, and asserts nothing until it has closed it.

---

## 3. What needs a constitutional amendment

**Nothing in this backlog does.** One collision was found by measurement
and it has been **decided rather than amended**:

### `ntdll:info` — bounded, and G12 is NOT amended

`ntdll:info` asks `NtQuerySystemInformation(SystemFirmwareTableInformation)`
with `ProviderSignature = 0` and asserts `status == STATUS_NOT_IMPLEMENTED`
with no `broken()` guard (`info.c:1623`). So that status is not a Wine gap
here — it is measured Windows behaviour for an unknown provider, and G12's
premise ("nobody depends on this status") is measurably false for this one
call. Implementing ACPI/FIRM does not reach it: the assertion is about
provider *zero*, which is not a provider.

**The project took the bounded loss.** The exemption would buy one pair.
What it would spend is the one property that makes G12 work at all — that
it has no door. An article with a narrow exemption is an article every
future stub author can argue their way into, and the bug history says that
argument gets made. One unreachable pair is a bounded, visible loss; a
widened G12 is an unbounded, invisible one.

So `KiPinnedNotImplemented` is NOT to be added. Anyone reaching this
collision again should read it as settled — and note what is NOT settled by
it: this covers `SystemFirmwareTableInformation` with provider zero and
nothing else. A SECOND call found to pin `NOT_IMPLEMENTED` as Windows
behaviour would be new evidence, and two of them would be a real argument
for revisiting. One is not.

Otherwise:

- **No COW work is needed.** Image-section COW is built (CUI-9); nothing
  here touches `docs/17` §10 step 6's one remaining door (file-backed data
  writecopy).
- **No SMP is needed.** `docs/18` §13's four gates are not touched. Nothing
  in the backlog is a throughput problem. The nearest thing used to be
  `kernel32:virtual`'s 285-second runtime, and that number is stale: with its
  wedge and its crash gone the pair finishes the whole 30865-test module
  inside a 9.6 s boot (W20). Slowness only becomes a constitutional argument
  when it stops a suite from reaching a verdict, and this one no longer does.
  What SMP *would* buy here is coverage, not speed: `virtual.c:4735` skips
  `test_store_buffer`'s litmus tests on a single-processor system, which is
  the pair's whole 71-test gap to the oracle — a uniprocessor kernel cannot
  run them, and that is Art. 3 working as intended rather than a defect.
- **No second allocator is needed.** Every snapshot and ledger above comes
  from the one pool.
- **No amendment is needed for async, and it is important to say why.**
  Art. 3's list is **closed** and synchronous I/O is not on it; inline
  completion is a legal point inside the NT contract (`docs/19` §1). W4 is
  ordinary Art. 5 work. **Citing Art. 3 to justify or to block W4 is itself
  a gate violation** — an article cited for a clause it does not contain,
  which Art. 3's own text equates to G8's uncited constant.

| Hypothetical | Amendment it would need |
|---|---|
| Genuine pending on file **data** (queue depth > 1, drain from idle) | **None.** CUI-8, already planned, `docs/19` §5 — and not required by any pair here. |
| Fine-grained locking to make a process walk "safe" | Art. 3's uniprocessor row, which has no exit other than `docs/18` §13's four SMP gates. **Do not go here** — the uniprocessor model is precisely what makes such a walk trivially atomic. |
| Demand paging / eviction to back W5's commit ledger | Art. 3's "no eviction" row, whose table entry reads *"unbuilt; no consumer, no design"*. **W5 does not need this** — commit-on-demand of a reserved range is not eviction. If an implementation starts to need it, that is the signal W5 has been designed wrong. |

---

## 4. Traps

Pairs and framings that will consume effort and unblock nothing.

1. **`kernel32:locale` (94 failures) is data, not kernel.** 72 of the 94
   are `LCMAP_SORTKEY` and `CompareStringEx` collation, resolved entirely
   PE-side out of `sortdefault.nls`, which IS on the boot volume. If a
   collation table is missing or stale this is a bake-time fix; if it is
   present, the failure is in Wine PE code, is **not proskrnl's to fix**,
   and G9 forbids patching Wine for exactly this purpose. **Measure whether
   the pair is oracle-green under the same NLS set before spending an hour
   on it.**

2. **A pair that STOPS has not been measured.** W5 paid for this one: a
   panicking pair reports the assertions it reached, and reading that as its
   failure count says "nearly green" about a pair with four figures of work
   behind the stop. `ntdll:virtual` went from an apparent 0 to a measured
   1199 the moment its panic was removed, and nothing about it changed for
   the worse. Every pair here that ends in a PANIC or a kill —
   `ntdll:{info,file}`, `kernel32:{mailslot,fiber}` — carries the same
   unknown, and their counts are lower bounds. **`kernel32:pipe` belongs on
   it too and is a THIRD spelling of the trap**: it neither panics nor is
   killed from outside — the test's own 20 s watchdog calls `ExitProcess(1)`
   (`pipe.c:845`, `alarmThreadMain`), so the run has a DEADLINE rather than a
   crash point, and its total drifted 93 → 96 → 94 → 110 across sessions
   because the deadline cut it in a different place each time. A count that
   moves without a kernel change is the tell. **`kernel32:virtual` was on
   that list too and was not named on it for three revisions**: it panicked
   at `virtual.c:869`'s `SEC_RESERVE` mapping, having executed 13 of the
   module's tests where the oracle executes 30936, and its block read as a
   nearly-green pair with four small subjects left. Its panic is now gone
   (W5) and the count went **4 → 96** — the second pair in this document to
   pay the trap in full, after `ntdll:virtual`'s 0 → 1199. **`ntdll:pipe` is
   the third and it paid it as a WEDGE rather than a crash**: it stopped
   spinning on `pipe.c:747` at 1 failed assertion and, with the spin ended
   (W11), reports **123** across 2386 executed tests. Three for three: assume
   a stopped pair's real count is an order of magnitude above what it reports.
   **The fourth measurement came back 1 → 1** (`kernel32:virtual`'s crash,
   W20), so the rule of thumb is a prior and not a law — what does not change
   is that only removing the stop can tell you which case you are in.

3. **A crash is usually a cascade, not the bug — and "zero failures before
   the crash" does not make it one.** `kernel32:volume` and
   `kernel32:resource` both `0xc0000005` *after* a run of `ok()` failures
   where an API had already returned NULL. Chasing the crash rather than
   the first failing `ok()` wastes the day. This trap used to name
   `ntdll:unwind` as the counter-example, "the crash IS the finding",
   precisely because it had zero failed assertions before it. **Measured, it
   was a cascade too** — of a single dropped allocation attribute that made a
   host-capability probe answer "yes" (W6). An empty assertion log before a
   fault says only that the test never *checked* anything on the way in, and
   the last thing a winetest does before running a feature block is ask
   whether the feature is there. `kernel32:fiber` was the same shape a second
   time and is now GREEN: one failed `ok()`, then a fault deep inside a
   fiber's own stack, and the cause was the uninitialised `StackBase` that
   `NtSetInformationProcess` class 41's no-op arm left `CreateFiberEx`
   holding (W5). Its triage block had named `mm/fault.c`'s guard-page path as
   the suspect on the strength of where the fault landed.

4. **The loudest failure in a cluster is usually the consequence.** This
   trap has been paid for three times. An earlier revision of this document
   named `kernel32:thread`'s `OpenThread` assertion as a cause on the
   strength of its access mask; the actual cause was a self-suspend four
   assertions earlier. Read the test's helper before believing the assertion
   text — **and do not believe the assertion's message either.** W12's
   largest cluster was triaged for a milestone as "`NtCreateKey` →
   `STATUS_OBJECT_PATH_SYNTAX_BAD`" because that is what the failure printed;
   the failing call is `NtOpenKey`, the message string is wrong in the
   upstream test, and the refusal was correct. The same item's other half
   showed the consequence landing in a different SUBJECT entirely: a key the
   fold failed to open was never deleted, and the failures were in
   `NtDeleteKey`, `NtRenameKey` and `RtlQueryRegistryValues` two thousand
   lines later.

5. **Hardware debug registers (DR0–7) and `EFLAGS.TF` unblock nothing.**
   They were only ever wanted by `ntdll:exception`, which is now re-parked as
   oracle-red (W6): its leg cannot convict the kernel at all until the oracle
   build gains a WoW64 arch and a display. Do not schedule them.

6. **The wtest image is NOT a wineboot-initialised prefix, and the
   difference reads as a kernel divergence.** The oracle leg runs in a
   wineprefix that `wineboot --init` populated; the proskrnl image is baked
   by hand and carries no `wineboot.exe`, so everything wine.inf would have
   written is absent unless something bakes it. That is why the full NLS set
   is baked (`run.sh` says a missing `c_932.nls` reads as a mass divergence)
   and why `win.ini`/`system.ini` now are (W14 — three of
   `kernel32:profile`'s failures were nothing but that file's absence).
   **Before diagnosing a pair that reads a file out of `%windir%` or the
   registry, check the oracle's prefix for it.** `kernel32:time`'s time-zone
   keys (W13) are the same shape one layer down, in the hive rather than on
   the volume, and `ntdll:reg` is the largest instance measured so far:
   **all 156** of its remaining failures are `Software\Classes\Interface` and
   `Software\Wow6432Node`, which `wine.inf` writes and the baked hive does
   not carry, and the license values it also writes were 12 more until this
   sweep's own item seeded them (W12). One `grep` of
   `build/tests/wineprefix/system.reg` answers it, and `NtCreateKey` creating
   only the LAST component is what turns one missing key into a whole test
   function's worth of failures.

7. **The manifest is READ BY THE KERNEL-SIDE SWEEP, and it has a size
   bound.** `user/smss/session.c` slurps `C:\wtests\manifest.txt` into a
   static buffer. Writing a long triage block — which this whole document
   tells you to do — took the file past that buffer, and the sweep then
   skipped itself as "not a wtest image": all 49 active pairs reported FAIL
   with **nothing on serial** saying why, on a change that touched no kernel
   code any pair runs. Measured, not hypothesised; the buffer is now 256 KiB
   and the over-capacity case names itself instead of reading as an absent
   feature. The transferable part is not the number: **a documentation file
   that is also an input has a failure mode documentation files do not**, and
   this one's failure looked exactly like a mass kernel regression.

8. **Pairs excluded under manifest rules (a)/(b)/(c) are not frontier.**
   `ntdll:om`, `kernel32:{console,process,loader,module,debugger,toolhelp}`,
   `ntdll:{alpc,wow64}` and `cmd.exe_test:batch` fail identically on both
   runners, or depend on the standalone link rather than the boundary, or
   need the GUI stack on the CUI volume. Re-litigating any of them is pure
   loss. Note the asymmetry the manifest header documents: being
   *unimplemented* is not a reason to comment a pair out — only "never
   implementing it" or "the oracle cannot serve as the spec" are.

---

## 5. Where I am explicitly unsure

- **W9's shared cause** is a pattern across three logs, not a diagnosis.
- ~~**The three wedges being one bug** (W10) is a guess from their shape.
  They may be three.~~ **Measured and refuted.** `ntdll:thread`'s wedge was
  `THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE`; fixing it left `ntdll:sync`
  and `ntdll:threadpool` bit-for-bit where they were. Three shapes that all
  end in a timeout are not evidence of one cause — the timeout is the
  harness, not the bug.
- **The change-notify IOSB rule** (W4b) is measured on both sides but not
  explained: two oracle-green tests park a watch, cancel it and read the
  IOSB, and differ only in whether an event was supplied — one sees
  `STATUS_CANCELLED`, the other sees the block untouched. The kernel
  reproduces both. *Why* the event changes the answer has not been traced
  through the oracle's async path, and someone should.
- ~~**Subtree stickiness** (W4b). The server stores the subtree flag in the
  same "assign it once" block as the filter, so symmetry suggests it is
  sticky too — but nothing on either side measures a re-arm that changes
  it, and proskrnl deliberately leaves it per-call.~~ **Measured and
  confirmed.** `kernel32:change` convicts it at change.c:558-:597, and
  `sem_file/notify_queue.c` now pins it oracle-green on a fresh handle.
  The symmetry argument was right, and the reason it went unmeasured for a
  milestone was a test that could not see it — the only case aimed at the
  subtree flag re-armed a handle already fixed non-recursive.

---

## 6. Critical files

- `kernel/io/` — `ioctl.c` + `rw.c` + `async.c` (W4a, W4c), `query.c`,
  `mountmgr.c` (W7). (`notify.c` was W4b and is done.)
- `fs/npfs/pipe.c` — `NpfsRead` pends (W4c, done); `NpfsWrite` still blocks,
  and is the same shape if a consumer ever convicts it. **It grew the
  `IOP_PENDING_REQUEST` engine; do not add a second one.**
- `kernel/mm/` — `virtual.c` and `section.c` (W5), `fault.c` (W20, done).
  **Danger zone.**
- `kernel/ps/usermode.c`, `arch/x86_64/*.S` — **danger zone**, but no longer
  a W6 file: W6's live half turned out to be `kernel/mm/virtual.c` and its
  dead half is re-parked.
- `kernel/ke/{wait,apc}.c` — W10. **Danger zone.**
- `fs/npfs/pipe.c` — W11. `kernel/cm/registry.c` — W12, W13.
- `tests/winetest/manifest.txt` — the counts and the triage, always.
