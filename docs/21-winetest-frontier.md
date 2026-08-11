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

**W4c — the pended packet (DONE), and the wedge it was predicted to be (it
is not).** This document said the wedge's "shape is known":
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

**That is the next item and it is not small.** The pending-request engine has
no buffer/length legs yet (`kernel/io/io.h` anticipates exactly this
consumer), the completion has to copy into the owner's address space, and the
FILE_OBJECT's signalled/unsignalled state joins the contract
(`pipe.c:1607-:1617`). `docs/19` is the plan to read first.

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
- **`NtCreateSection` does not zero the caller's handle on a refusal**, and
  that is now the pair's LARGEST single cause — 67 of the 96. `kernelbase`'s
  `CreateFileMappingW` (`dlls/kernelbase/sync.c:1037`) declares `HANDLE ret;`
  uninitialized, passes `&ret` to `NtCreateSection`, and `return ret`s on
  every path including the failing ones; proskrnl's `NtCreateSection` returns
  its refusals before writing `*handle`, so `CreateFileMapping` hands the test
  a stack-garbage handle for a create it correctly refused. It shows up as the
  refusal *appearing to succeed* (`virtual.c:1616`) and then
  `NtQuerySection` answering `STATUS_INVALID_HANDLE` on the result
  (`:1636`, `:1638`). The read is from both sides' source plus the exact
  agreement of the index sets; **the confirming pin is one line** — pass a
  garbage-initialized `HANDLE` to a `NtCreateSection` that must fail and
  assert it comes back `NULL` — and it is the first thing the next item should
  write, since the oracle's own ntdll leaves `*handle` alone too and only its
  stack happens to hold zero.
- **The SEC_* MODIFIER flags on a section** — `SEC_NOCACHE`, and now also
  `SEC_WRITECOMBINE` and `SEC_LARGE_PAGES`, which the same measurement added
  to this item. A section created with any of them keeps none: the flag is
  neither reported by `NtQuerySection` nor refused where NT refuses it
  (`SEC_LARGE_PAGES` and `SEC_WRITECOMBINE` are `ERROR_INVALID_PARAMETER`
  combinations for NT and succeed here). 24 of `kernel32:virtual`'s 96, which
  is the first winetest evidence for a bullet that used to say "no winetest
  assertion reaches it". `docs/03` carries the `SEC_NOCACHE` deviation; the
  private-memory half is built and pinned, and this is the same one-field
  shape as `MI_VAD.noCache`, on the section instead.
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
  are no COW, no eviction, one dispatcher lock/uniprocessor, one pool, and
  the list is closed. Fault-time commit of a reserved page is none of
  those. But it *touches the fault path*, which is where a COW or eviction
  reflex will try to enter. `docs/17` §10 is the only door for COW and it
  is a commit of its own.
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

- **No COW is needed.** `docs/17` §10's entry conditions are not touched.
- **No SMP is needed.** `docs/18` §13's four gates are not touched. Nothing
  in the backlog is a throughput problem. The nearest thing is
  `kernel32:virtual`'s 285-second runtime, and slowness only becomes a
  constitutional argument when it stops a suite from reaching a verdict.
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
   unknown, and their counts are lower bounds. **`kernel32:virtual` was on
   that list too and was not named on it for three revisions**: it panicked
   at `virtual.c:869`'s `SEC_RESERVE` mapping, having executed 13 of the
   module's tests where the oracle executes 30936, and its block read as a
   nearly-green pair with four small subjects left. Its panic is now gone
   (W5) and the count went **4 → 96** — the second pair in this document to
   pay the trap in full, after `ntdll:virtual`'s 0 → 1199. Two for two:
   assume a stopped pair's real count is an order of magnitude above what it
   reports.

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
- `fs/npfs/pipe.c` — `NpfsRead`/`NpfsWrite`, the next item's subject (the
  pended data path). **Grows the `IOP_PENDING_REQUEST` engine; do not add a
  second one.**
- `kernel/mm/` — `virtual.c` and `section.c` (W5). **Danger zone.**
- `kernel/ps/usermode.c`, `arch/x86_64/*.S` — **danger zone**, but no longer
  a W6 file: W6's live half turned out to be `kernel/mm/virtual.c` and its
  dead half is re-parked.
- `kernel/ke/{wait,apc}.c` — W10. **Danger zone.**
- `fs/npfs/pipe.c` — W11. `kernel/cm/registry.c` — W12, W13.
- `tests/winetest/manifest.txt` — the counts and the triage, always.
