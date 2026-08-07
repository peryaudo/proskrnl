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

**W4a — the ioctl APC leg.** `kernel/io/ioctl.c`'s `IopIoctlApcUnsupported`
still returns `STATUS_NOT_IMPLEMENTED` for a user `ApcRoutine`, and
`dlls/ntdll/tests/pipe.c`'s `listen_pipe()` passes one. `kernel/io/rw.c`
already has the authority — `IopCompleteTransfer` writes the IOSB, posts
the port packet, then calls `IopQueueCompletionApc`. Extend that ONE
function to serve the ioctl path (Art. 11); a second APC-queueing site
inside `ioctl.c` is the wrong shape. For a PENDED listen the APC must be
queued at `IopCompletePendingRequest` and to the **issuer** thread.

- **G14 — the sharpest gate risk in the plan.** The completion drain is a
  declared must-not-block region. Queueing an APC from the drain must not
  be able to park; if it can, `tools/blocking_frontier.py` will say so, and
  per `docs/20` §8.4 a new blocking point re-opens every STILL-TRUE table.
- **Art. 11 / G11.** The APC object outlives the syscall on the pended
  path. `docs/03` "CUI-3 SCM notes" records that a pending listen is *not*
  cancelled at its issuer thread's exit — that narrowness now has an APC
  attached to it and must be re-answered, not inherited.

**W4b — change-notify: PARTLY DONE.** `ntdll:change` is green. Two rules
landed, both about what a request that returned `STATUS_PENDING` owes its
caller, and both pinned by `tests/ntapi/sem_file/notify_sticky.c`:

- the completion FILTER belongs to the HANDLE, not the call — the first arm
  fixes it and every later arm reuses it (the server's "assign it once");
- an error completion writes the IOSB when the watch carries no event.

`kernel32:change` is still red, and it is now clear that the watch ENGINE
is not the suspect: what fails is what the engine is TOLD about. A rename
must emit two chained records, directory create/remove are not reported at
all, and the OVERLAPPED `Internal`/`InternalHigh` fields are unwritten.
Those are `kernel/io/notify.c` producers plus the completion path.

The `docs/03` CUI-5 deviation (changes are not buffered between watches)
is still open and still the right next question for this item.

### W5 — Mm: `SEC_RESERVE` sections and placeholder reservations

**Now the only thing standing between `ntdll:virtual` and green.** That
pair has zero failed assertions and stops on a PANIC:
`NtAllocateVirtualMemoryEx` refuses `MEM_RESERVE_PLACEHOLDER` /
`MEM_REPLACE_PLACEHOLDER` by name. `kernel32:virtual` wants `SEC_RESERVE`
sections (`kernel/mm/section.c`).

**This is the item to be most careful with.** `docs/12` names
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
  should split is `1d6dafd` (`NtResumeThread` as a no-op success). Refuse
  loudly until the split/coalesce rules are complete.

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

### W10 — The three wedges

`ntdll:sync`, `ntdll:thread` and `ntdll:threadpool` now all hang with
nothing named on serial. `ntdll:thread` is the newest arrival: its two
assertion failures were fixed this session and what remains is only the
hang, so the three are probably one bug and should be triaged together.

They are disproportionately expensive — each costs its full per-pair
timeout on every sweep — and `docs/03` records that the sweep ABORTS on
timeout rather than running more pairs against a wedged console.

**Art. 6 applies with full force**: `docs/12` names `ke/{wait,apc}.c` as
the "subtly wrong yet still runs" zone with multi-month bug latency. A
change that makes the hang stop is not a fix; only a differential test
convicts.

### W11 — npfs

`ntdll:pipe` and `kernel32:pipe`. `kernel32:pipe`'s 93 failures are one
scenario repeated ~26 times (`pipe.c:1404`-:1406, reading from the client
end), not 93 bugs. `ntdll:pipe`'s dominant cluster is `pipe.c:344` wanting
`STATUS_ILLEGAL_FUNCTION` twelve times. Related to W4a but not the same
item.

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

2. **A crash is usually a cascade, not the bug.** `kernel32:volume` and
   `kernel32:resource` both `0xc0000005` *after* a run of `ok()` failures
   where an API had already returned NULL. Chasing the crash rather than
   the first failing `ok()` wastes the day. The two crashers where the
   crash IS the finding are `ntdll:unwind` (zero failed assertions before
   it) and `ntdll:exception` (whose crash has a named syscall behind it).

3. **The loudest failure in a cluster is usually the consequence.** This
   trap has been paid for twice. An earlier revision of this document named
   `kernel32:thread`'s `OpenThread` assertion as a cause on the strength of
   its access mask; the actual cause was a self-suspend four assertions
   earlier. Read the test's helper before believing the assertion text.

4. **Hardware debug registers (DR0–7) and `EFLAGS.TF` are the lowest-value
   item in the plan.** They unblock only `ntdll:exception`, and only
   *after* W6's `NtSetContextThread` fix — which may unblock it alone. Do
   W6's triage, then re-ask.

5. **Pairs excluded under manifest rules (a)/(b)/(c) are not frontier.**
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
- **The three wedges being one bug** (W10) is a guess from their shape.
  They may be three.
- **The change-notify IOSB rule** (W4b) is measured on both sides but not
  explained: two oracle-green tests park a watch, cancel it and read the
  IOSB, and differ only in whether an event was supplied — one sees
  `STATUS_CANCELLED`, the other sees the block untouched. The kernel
  reproduces both. *Why* the event changes the answer has not been traced
  through the oracle's async path, and someone should.
- **Subtree stickiness** (W4b). The server stores the subtree flag in the
  same "assign it once" block as the filter, so symmetry suggests it is
  sticky too — but nothing on either side measures a re-arm that changes
  it, and proskrnl deliberately leaves it per-call. If a test ever
  convicts, that is where to look.

---

## 6. Critical files

- `kernel/io/` — `notify.c` (W4b), `ioctl.c` + `rw.c` + `async.c` (W4a),
  `query.c`, `mountmgr.c` (W7).
- `kernel/mm/` — `virtual.c` and `section.c` (W5). **Danger zone.**
- `kernel/ps/usermode.c`, `arch/x86_64/*.S` — W6. **Danger zone.**
- `kernel/ke/{wait,apc}.c` — W10. **Danger zone.**
- `fs/npfs/pipe.c` — W11. `kernel/cm/registry.c` — W12, W13.
- `tests/winetest/manifest.txt` — the counts and the triage, always.
