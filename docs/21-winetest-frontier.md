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

### W5 — Mm: placeholder reservations (**DONE**) and `SEC_RESERVE` sections

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

What is left under this heading:

- **`MemoryImageInformation`** (`ntdll:virtual:3095`), the next unbuilt class
  in the same syscall and now the region cluster's only survivor. It is a
  `win_skip`, so it returns early and everything behind it is unmeasured.
- **`SEC_RESERVE` sections** (`kernel/mm/section.c`), which `kernel32:virtual`
  wants. Untouched by the above.
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

### W6 — The exception/context cluster (**triage-first, not build-first**)

`ntdll:exception` and `ntdll:unwind`. Both die with an unhandled user-mode
`0xc0000005` rather than with a missing class.

`ntdll:exception`'s is measured and points somewhere specific: the process
is killed at `RIP=0 RSP=0` immediately after `NtSetContextThread` on the
CURRENT thread. That is a context *restore* that zeroed `RIP`/`RSP`.
**Strong hypothesis: `NtSetContextThread` is not honouring `ContextFlags`
selectivity** — a caller setting only some flags gets its whole context
overwritten. Cheap to confirm, cheap to fix, and a genuine boundary
contract. The DR0–7 and `EFLAGS.TF` work sits *behind* it.

**Deliverable ordering: one triage commit-series (no kernel change — a
`tests/ntapi` case isolating `NtSetContextThread` with a partial
`ContextFlags`, oracle-green) BEFORE any kernel work.** If the hypothesis
is wrong the item is re-scoped and we have lost a day instead of a week.

- **`docs/12` names `ps/usermode.c` and `arch/x86_64/*.S` as danger
  zones.** Do not let an agent write this one unsupervised.
- **Art. 1 / G1.** `CONTEXT` layout and `ContextFlags` semantics are
  squarely on the boundary and must be reproduced exactly; every offset
  comes from `abi/` with `static_assert`, never from memory.

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

### W12 — Registry

`ntdll:reg`, 192 failures. A quarter of them are one cluster:
`NtCreateKey` answering `STATUS_OBJECT_PATH_SYNTAX_BAD` 24 times, with
`NtQueryValueKey` failing behind it on the handle that create never
produced. That cluster is a NAME question, which W3 has just made cheaper
to reason about, and it is the place to start.

### W13 — Time-zone data

`kernel32:time`: 13 of its 19 failures are one line, and it is data rather
than logic. `kernel/cm/registry.c` seeds exactly ONE time-zone key (UTC),
because that is the one kernelbase requires to boot. Mechanical, but a
large data set, and it must come from the pinned prefix rather than from
memory (G8).
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
   unknown, and their counts are lower bounds.

3. **A crash is usually a cascade, not the bug.** `kernel32:volume` and
   `kernel32:resource` both `0xc0000005` *after* a run of `ok()` failures
   where an API had already returned NULL. Chasing the crash rather than
   the first failing `ok()` wastes the day. The two crashers where the
   crash IS the finding are `ntdll:unwind` (zero failed assertions before
   it) and `ntdll:exception` (whose crash has a named syscall behind it).

4. **The loudest failure in a cluster is usually the consequence.** This
   trap has been paid for twice. An earlier revision of this document named
   `kernel32:thread`'s `OpenThread` assertion as a cause on the strength of
   its access mask; the actual cause was a self-suspend four assertions
   earlier. Read the test's helper before believing the assertion text.

5. **Hardware debug registers (DR0–7) and `EFLAGS.TF` are the lowest-value
   item in the plan.** They unblock only `ntdll:exception`, and only
   *after* W6's `NtSetContextThread` fix — which may unblock it alone. Do
   W6's triage, then re-ask.

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
   the volume.

7. **Pairs excluded under manifest rules (a)/(b)/(c) are not frontier.**
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
- `kernel/ps/usermode.c`, `arch/x86_64/*.S` — W6. **Danger zone.**
- `kernel/ke/{wait,apc}.c` — W10. **Danger zone.**
- `fs/npfs/pipe.c` — W11. `kernel/cm/registry.c` — W12, W13.
- `tests/winetest/manifest.txt` — the counts and the triage, always.
