# M10-W — closing the winetest frontier

> Status: **plan**, written after the first full per-pair sweep of the
> non-GUI manifest. Every measurement cited here comes from
> `build/perpair/*.serial.log` or from the pinned tree at `third_party/wine`;
> where the author could not verify something by reading, §7 says so instead
> of guessing. Read `docs/09-constitution.md` before executing any item —
> the per-item "risk to an article" notes are the point of this document,
> not decoration.


---

## 0. Scope, and what this plan does not re-plan

The winetest gate is live and is COVERAGE, not curation (`docs/03` "M10 winetest notes"; `tests/winetest/manifest.txt` header). 74 pairs are active, 9 are commented out with a cause that falls under exclusion rule (a) or (b). Already landed and out of scope here: the harness defects (oracle locale + non-root), `\Device\Null`, the UTC time-zone seed, the `FileBasicInformation` set-access rule, the `NtWriteFile` bad-buffer status, the failure-path event reset, the `-2` `FILE_USE_FILE_POINTER_POSITION` offset, the `NtCreateKey`/`NtOpenKey` NULL args, the timer use-after-free, the `NtQueryKey` sizing UB, and `NtSetInformationFile(FileCompletionInformation)` (landed while this plan was being written).

Everything below is scoped to pairs that are **green on the pinned oracle and red on proskrnl**, i.e. real gaps under Art. 6.

**Evidence base.** Every claim in §2–§4 was read out of `build/perpair/*.serial.log` (ANSI-stripped) and cross-checked against the pinned tree at `third_party/wine`. Where I could not verify something by reading, I say so explicitly rather than guessing.

---

## 1. The one structural fact that shapes the whole plan

Art. 12 arms `STATUS_NOT_IMPLEMENTED` as a **kernel panic** for every ring-3 syscall, with no exemption. The winetest suites are written the other way round: they *tolerate* a refusal and move on. The canonical instance is `third_party/wine/dlls/kernel32/tests/thread.c`, `test_thread_info()` — the class sweep at line 2351 does

```c
status = pNtQueryInformationThread(thread, i, buf, info_size[i], &ret_len);
if (status == STATUS_NOT_IMPLEMENTED) continue;
if (status == STATUS_INVALID_INFO_CLASS) continue;
if (status == STATUS_UNSUCCESSFUL) continue;
```

over `i = 0 … ThreadHideFromDebugger`. On the oracle that loop skips `ThreadPriority`, `ThreadBasePriority`, `ThreadImpersonationToken`, `ThreadEventPair_Reusable`, `ThreadZeroTlsCell`, `ThreadPerformanceCount` and `ThreadSetTlsArrayAddress`, which `dlls/ntdll/unix/thread.c` (the `default:` arm of `NtQueryInformationThread`, at the block ending in `FIXME( "info class %d not supported yet\n", class ); return STATUS_NOT_IMPLEMENTED;`) genuinely refuses. On proskrnl the same answer stops the machine.

**Three consequences that every work item below inherits:**

1. **"The oracle also refuses" is never a resting place.** For a swept class, proskrnl must answer *either* the implemented value *or* a specific NT failure. `STATUS_NOT_IMPLEMENTED` cannot survive in a class a suite sweeps.
2. **The specific NT failure is a behaviour, and it needs a pin.** Art. 12's last paragraph and G12's last sentence say so: `STATUS_INVALID_INFO_CLASS` / `STATUS_INFO_LENGTH_MISMATCH` / `STATUS_ACCESS_DENIED` are implementations, pinned like anything else. Where the oracle refuses, the pin goes in a `beyond_oracle { }` block (`tests/ntapi/ntapi.h`) naming the Microsoft page it is written against — Art. 5's second half, and the *only* legal route here.
3. **This is the difference between a work item and a frozen hole.** A `tests/ntapi` case asserting `STATUS_NOT_IMPLEMENTED` FAILS G12 outright, and so does any `KiPinnedNotImplemented`-shaped escape. If an item below cannot be finished, it stays red — it does not get pinned.

This is item **W1**, and it comes before everything else because W2 and W3 are unbuildable without the rule being settled in one place.

---

## 2. Corrected backlog map (measured, not assumed)

The brief's backlog list is close but stale in five places. What the per-pair logs actually say:

| Pair | Measured cause (from `build/perpair`) | Brief said |
|---|---|---|
| `ntdll:info` | first check of the file: `NtQuerySystemInformation(-1, …)` — `dlls/ntdll/tests/info.c:149` expects `STATUS_INVALID_INFO_CLASS`; proskrnl answers `NOT_IMPLEMENTED` and panics | "unbuilt classes" — true, but the *first* blocker is the refusal shape |
| `kernel32:thread` | `NtQueryInformationThread` class **2** (`ThreadPriority`) — the sweep loop above | "unbuilt classes" ✔ |
| `ntdll:thread` | class **17** (`ThreadHideFromDebugger`) | ✔ |
| `kernel32:time` | `NtQuerySystemInformation` class **0x53 = 83** (`SystemProcessorIdleCycleTimeInformation`) | ✔ |
| `kernel32:mailslot` | `NtQueryInformationFile` class **26** (`FileMailslotQueryInformation`) | ✔ |
| `ntdll:directory` | `NtQueryInformationFile` class **59** (`FileIdInformation`) + the sort order at `directory.c:324` | ✔ |
| `ntdll:pipe` | **not an FsControl verb** — `kernel/io/ioctl.c:18` `IopIoctlApcUnsupported` refuses a user `ApcRoutine`, and `dlls/ntdll/tests/pipe.c:205` `listen_pipe()` passes one | "NtFsControlFile verbs" ✘ |
| `ntdll:virtual` | `NtAllocateVirtualMemoryEx` exists; `kernel/mm/virtual.c:1626` refuses `MEM_RESERVE_PLACEHOLDER` / `MEM_REPLACE_PLACEHOLDER` | "NtAllocateVirtualMemoryEx" — partially ✘ |
| `kernel32:virtual` | `NtCreateSection` with **`SEC_RESERVE`** — `kernel/mm/section.c:123` | "NtCreateSection flags" ✔ |
| `kernel32:power` | `NtPowerInformation` level **5 = `SystemBatteryState`** (`include/winnt.h:5770` enum) | ✔ |
| `kernel32:sync`, `kernel32:file`, `kernel32:pipe`, `ntdll:threadpool` | all four died at `NtSetInformationFile` with the class not yet named on serial. `FileCompletionInformation` is the overwhelmingly likely class and it is **now implemented (uncommitted)** | listed as untriaged |
| `kernel32:toolhelp` | **135 failures**, all cascading from `toolhelp.c:132` "couldn't find self and/or sub-process in process list" — this is `SystemProcessInformation` (class 5), i.e. the *same* work as `ntdll:info` | listed as untriaged |
| `kernel32:drive` | 12 failures. `dlls/kernelbase/volume.c:495` `GetLogicalDrives` opens **`\DosDevices`** via `NtOpenDirectoryObject`; `grep -rn DosDevices kernel/` returns **nothing** | listed as untriaged |
| `ntdll:exception` | crash with `RIP=0 RSP=0`, `last_syscall=0xe4` = **`NtSetContextThread`** (`abi/syscall_numbers.h:97`) | "debug registers + TF" — those are in there too, but a zeroed context restore comes first |
| `ntdll:rtl` | `rtl.c:3408` "Failed to load library: **126**" (ERROR_MOD_NOT_FOUND) on the extracted `TESTDLL`, then an unhandled `0xc0000005` | untriaged |
| `kernel32:resource` | `GetFileMUIInfo` fails **193** (ERROR_BAD_EXE_FORMAT) repeatedly, then an unhandled `0xc0000005` | untriaged |
| `kernel32:actctx` | 39 failures, 26 of them at `actctx.c:4354`, the `subtest_manifest_res()` loop that writes an EXE+DLL pair to disk and runs them | untriaged |
| `kernel32:fiber` | user `#PF` err=**0x7** (present, **write**, user) at `CR2=0x4498c0`, i.e. a write to a *present but read-only* page on a fiber's own stack | untriaged |
| `kernel32:volume` | open-by-file-id unsupported (`FILE_SUPPORTS_OPEN_BY_FILE_ID` clear) + `\\.\MountPointManager` missing (error 2), then a cascade crash | untriaged |
| `ntdll:sync` | **hangs** — `wtest ntdll_test.exe:sync FAIL (timeout)` at 300 s with "0 tests executed". Not a missing class; a wedge | untriaged |
| `ntdll:unwind` | unhandled `0xc0000005` after the `unwind.c:2993` epilogue-decoder block | untriaged |
| `kernel32:locale` | 94 failures: 72 at `locale.c:3809`/`:3813` (`LCMAP_SORTKEY` + `CompareStringEx` collation), 11 at `:2308` | untriaged |
| `kernel32:profile` | 7 failures (`profile.c:95`, `:559`–`:568`) — **not in the brief's backlog at all**; a genuine new finding | — |
| `kernel32:path` | 11 failures, **all** `GetShortPathName` 8.3 (`path.c:233`, `:245`) — a FAT32 short-name question, unrelated to `ntdll:path` | grouped with `ntdll:path` ✘ |

---

## 3. The work items

Commit shape for every item, per G13: **(1)** the `tests/ntapi` pin (oracle-green, or `beyond_oracle` with its MS citation) → **(2)** the kernel change + its `docs/03` note → **(3)** `abi/` regen if any constant moved (`/gen-abi`, never hand-typed) → **(4)** the manifest/`docs/16` bookkeeping. The pin commit precedes the kernel commit in history, always.

---

### W0 — Re-measure the sweep. No kernel change.

**Unblocks:** possibly `kernel32:{sync,file,pipe}` and `ntdll:threadpool` outright (4 pairs, zero work), and it is the only way to size W2/W3 honestly.

**Why first.** The per-pair map in `build/perpair` predates the last five commits. Two of those specifically invalidate it: `d4e3b9e` ("unbuilt info classes name themselves on serial") means the next sweep will *name every class* instead of leaving `NtSetInformationFile a1=0x20f970` to be guessed at, and the uncommitted `FileCompletionInformation` is the class those four pairs most plausibly wanted. Re-planning W2/W3 off a stale map is exactly the "park a pair without re-measuring" mistake `docs/03` already made once with the eight host-parked pairs.

**Deliverable:** one full per-pair sweep; then a single `docs/03` amendment commit rewriting the "Still red, and genuinely proskrnl's" bullet from the new measurement. Also re-run the oracle leg — `kernel32:profile`'s 7 failures are unaccounted for and may be the ninth host-parked pair.

**Risk:** none to any article. The only trap is skipping it.

**Effort:** ~1 day, mostly wall-clock (`kernel32:virtual` alone ran 285 s).

---

### W1 — The refusal shape: `INVALID_INFO_CLASS` is a behaviour; `NOT_IMPLEMENTED` is a hole

**Unblocks:** the first check of `ntdll:info`; a hard precondition for W2 and W3.

**Boundary surface:** the `default:` arm of every info-class dispatcher — `kernel/io/query.c` (lines 141, 248, 627, 1027, 1406), `kernel/ps/query.c` (489, 970, 1548, 1629, 1961, 2206), `kernel/mm/section.c`, `kernel/ke/*`.

**Oracle source of truth (verified):**
- `third_party/wine/dlls/ntdll/unix/system.c`, `NtQuerySystemInformation`'s `default:` arm — it returns `STATUS_INVALID_INFO_CLASS` and carries the comment explaining why ("in 95% of the cases it's STATUS_INVALID_INFO_CLASS, so use this as the default").
- `third_party/wine/dlls/ntdll/unix/thread.c`, `NtQueryInformationThread` — `ThreadIdealProcessor` and `ThreadEnableAlignmentFaultFixup` get an explicit `return STATUS_INVALID_INFO_CLASS;`, while the `default:` group returns `STATUS_NOT_IMPLEMENTED`. Wine distinguishes the two deliberately; so must we.
- `third_party/wine/dlls/ntdll/tests/info.c:149–151` — the consumer.

**Shape of the change.** Introduce (in the shared syscall-refusal helper, one authority, not per-file) an explicit two-way split at each dispatcher:
- **class out of the enum's valid range, or documented as never-queryable** → `STATUS_INVALID_INFO_CLASS`, pinned, and it is an *implementation*;
- **class real, in range, and simply unbuilt** → `STATUS_NOT_IMPLEMENTED` + the `KI_SYSCALL_MISSING`-shaped serial line, which panics. Unchanged.

**Risk to an article.**
- **Art. 12 / G12 — this is the article's own dividing line, and getting it backwards is the worst outcome in the plan.** Making the default `INVALID_INFO_CLASS` for *everything* would convert every unbuilt class into a plausible-looking refusal that a caller cannot distinguish from a real one. That is `3ce0031` (`FileFsDeviceInformation` hardwiring `FILE_DEVICE_DISK`) with a status instead of a value. The split must be per-class and explicit, never a blanket default.
- **Art. 4 / G8** — the "valid range" bound is a number fixed by an external contract. It comes from `abi/` via `/gen-abi` off `include/winternl.h`, never typed.
- **Art. 5** — each `INVALID_INFO_CLASS` answer needs a pin. Where the oracle answers it, an ordinary `tests/ntapi` case; where the oracle answers `NOT_IMPLEMENTED`, `beyond_oracle` + the MS citation.

**Effort:** 1 commit-series, ~1–2 days. High leverage per line.

---

### W2 — The query surfaces: thread, system, process, power

**Unblocks:** `ntdll:thread`, `kernel32:thread`, `ntdll:info`, `kernel32:time`, **`kernel32:toolhelp` (135 failures)**, `kernel32:power`. Six pairs — the single highest-leverage item in the backlog. (`kernel32:process` shares the surface but stays commented out for the console reason (b); do not count it.)

**Boundary surface:** `NtQueryInformationThread`, `NtQuerySystemInformation`, `NtQueryInformationProcess`, `NtPowerInformation`.

**Oracle source of truth (verified paths):**
- `dlls/ntdll/unix/thread.c` — `NtQueryInformationThread` (the function header comment sits at line 2148); every arm from `ThreadBasicInformation` down to `ThreadPriorityBoost`.
- `dlls/ntdll/unix/system.c` — `NtQuerySystemInformation`; the `case` labels carry their numeric class in a trailing comment (`SystemProcessInformation: /* 5 */`, `SystemProcessorIdleCycleTimeInformation: /* 83 */`), which is the answer key.
- `dlls/ntdll/unix/system.c` — `NtPowerInformation` (function header at line 4571); `SystemBatteryState` is one of its arms, and the unhandled tail is `WARN( "Unimplemented NtPowerInformation action: %d\n", level )`.
- Enums: `include/winternl.h:2313+` (`THREADINFOCLASS`), `include/winnt.h:5770+` (`POWER_INFORMATION_LEVEL`).
- Consumers: `dlls/kernel32/tests/thread.c` `test_thread_info` (the `info_size[]` sweep), `dlls/ntdll/tests/info.c`, `dlls/kernel32/tests/toolhelp.c:132`.

**Shape of the change.** Three sub-series:

- **W2a — thread classes 0…17 complete.** Build the queryable ones; give `ThreadPriority`, `ThreadBasePriority`, `ThreadImpersonationToken`, `ThreadEventPair_Reusable`, `ThreadZeroTlsCell`, `ThreadPerformanceCount`, `ThreadSetTlsArrayAddress` the documented NT refusal via W1's split, pinned `beyond_oracle`. `ThreadHideFromDebugger` is a real stored per-thread flag with a documented quirk the oracle spells out in a comment (it touches `*ret_len` *before* any other check, so an unwritable `ret_len` yields `STATUS_ACCESS_VIOLATION` first) — reproduce that ordering; it is boundary-observable.
- **W2b — `SystemProcessInformation` (5) with real enumeration**, plus the `ntdll:info` shape checks and class 83 for `kernel32:time`.
- **W2c — `NtPowerInformation(SystemBatteryState)`.** Small.

**Risk to an article.**
- **Art. 11 / G10 — the sharpest risk in the item.** `SystemProcessInformation` and toolhelp's thread list must walk the **Ps authority's own process/thread lists**. A second enumeration index maintained alongside them is the `a53dd04` shape exactly, and it will drift silently because both halves stay self-consistent.
- **Art. 11 / G11 ownership audit — mandatory here.** Enumerating processes means holding references to objects whose owning thread may exit at the earliest legal moment; this is the `edf9f0b` shape. The PR must answer: who holds the reference on each ETHREAD/EPROCESS while the snapshot is built, and what happens if a process exits mid-walk.
- **Art. 12 / G12.** `SystemBatteryState` is where the temptation to fabricate is highest — Wine itself is a semi-stub for `SystemPowerCapabilities` with hand-picked values. That is legitimate *for us* only as pinned oracle behaviour: match what the pinned tree returns, cite it, pin it. A value invented "so the test passes" fails G12 even if the test goes green.
- **Art. 3.** A single-CPU `SystemProcessorPerformanceInformation` array of length 1 is **honest**, not a stub — uniprocessor is a mandate, so one entry is the truth. Record it in `docs/03` as an Art. 3 consequence, not as a deviation.
- **G14.** Building a process snapshot allocates. If any of it lands on a path a must-not-block region can reach, `tools/blocking_frontier.py --check` will say so; regenerate the baseline **in the same commit** with a body sentence, per G14.2.

**Effort:** 3 commit-series, ~5–8 days. This is `io/query.c`-shaped info-class filling, which `docs/12` names the single best LLM task in the tree — but the Ps enumeration half is not, and should be designed before it is written.

---

### W3 — The path and name surface

**Unblocks:** `ntdll:path` (16 failures), `ntdll:directory`, `kernel32:drive` (12). Partial credit on `kernel32:volume`. **Not** `kernel32:path` — see §5.

**Boundary surface:** Ob name parsing on the file-open path, `NtQueryDirectoryFile` ordering, `NtQueryInformationFile(FileIdInformation)`, the `\DosDevices` namespace entry.

**Oracle source of truth (verified):**
- `dlls/ntdll/tests/path.c` — the table-driven `root` + `name` open loop, `ok()` at `path.c:736`, with entries like `{ L"\\??\\C:\\windows\\", L".", STATUS_OBJECT_NAME_INVALID }` and `{ L"C:\\", …, STATUS_OBJECT_PATH_SYNTAX_BAD }`. This table *is* the spec; the pin is a transcription of it.
- `dlls/ntdll/tests/directory.c` — the enumeration loop at lines ~304–324: entry 0 must be `.`, entry 1 must be `..`, and from index 3 on, `RtlCompareUnicodeString(prev, name, TRUE) < 0` — strictly increasing, case-insensitive. proskrnl currently returns FAT order (measured: `NTDLL.DLL` then `KERNEL32.DLL`).
- `dlls/kernelbase/volume.c:495` `GetLogicalDrives` — `NtOpenDirectoryObject(L"\\DosDevices")` then `NtQueryDirectoryObject`, bitmask by `ObjectName.Buffer[1] == ':'`.
- Class 59 = `FileIdInformation` (`include/winternl.h:1389`); the size table is `info_sizes[]` inside `NtQueryInformationFile`, `dlls/ntdll/unix/file.c`.

*I did not verify which Wine function performs the directory sort* — Wine's unix side reads through `getdents` and orders it somewhere in `dlls/ntdll/unix/file.c`'s dir-data machinery, but I did not read that code and will not name a function I have not seen. The **test** is the authority we need and it is unambiguous; find the Wine function during implementation if you want a second opinion on tie-breaking.

**Shape of the change.** Three sub-series:
- **W3a — the NT open-path table.** Trailing slash, doubled slash, `.`/`..` components, `\??/` mixed separators, and `RootDirectory`-relative opens each get their documented status. This belongs in the **one** Ob parse path, extended — not in a file-system-side pre-pass.
- **W3b — enumeration order.** Sort the directory listing case-insensitively per `RtlCompareUnicodeString` semantics, stable across the resume calls (`NextEntryOffset == 0` → next `NtQueryDirectoryFile` continues the *same* ordering).
- **W3c — `\DosDevices` + `FileIdInformation`.**

**Risk to an article.**
- **Art. 11 / G10 is the whole risk of W3a.** The path table is exactly the surface where a second resolver gets written "just for the edge cases". `a53dd04` was Cm doing this. Route through Ob's existing resolution and add a flag/hook if it cannot express a case; a parallel path here would be a rejection even while equivalent.
- **Art. 11 / G11 for W3b.** A sorted snapshot is state with a lifetime — per-open, freed at handle close, and it must survive the caller closing at the earliest legal moment. Answer the audit.
- **Art. 3 (one pool).** The snapshot allocates from the one pool. Fine. What is *not* fine is arguing for the sort on performance grounds or against it on memory grounds — the justification is user-observable ordering, per Art. 3's closing sentence.
- **G14.** A per-open snapshot buffer allocated inside a path a drain can reach is a frontier question. Check, don't assume.
- **G2.** `\DosDevices` is NT-present (real NT has it as a symbolic link at the namespace root), so it is not an NT-absent addition. Say so in the commit body so the gate reviewer does not have to.

**Effort:** 3 commit-series, ~4–6 days. W3a is the largest single chunk of transcription work in the plan and is very well suited to the test-first loop.

---

### W4 — The completion legs: the ioctl APC, and change-notify buffering

**Unblocks:** `ntdll:pipe`, `ntdll:change` (9 failures), `kernel32:change` (33).

**Boundary surface:** `NtFsControlFile`/`NtDeviceIoControlFile` completion; `NtNotifyChangeDirectoryFile` buffering.

**Oracle source of truth (verified):**
- `dlls/ntdll/tests/pipe.c:199–206` — `listen_pipe()` calls `pNtFsControlFile(hPipe, hEvent, use_apc ? &ioapc : NULL, …, FSCTL_PIPE_LISTEN, …)`; `test_overlapped()` (line 365) asserts `STATUS_PENDING`, then that the IOSB is untouched until the client connects, then `ok(ioapc_called)` only *after* a `SleepEx(0, TRUE)` alertable wait. That ordering is the contract, and it is already `docs/19` §1.3.
- `kernel/io/ioctl.c:16–21, 38` — `IopIoctlApcUnsupported()` returns `STATUS_NOT_IMPLEMENTED` for exactly this.
- `dlls/ntdll/tests/change.c:106, 112, 143, 154, 304` — "should timeout" / "information wrong", the buffered-window model. Recorded already as a deviation in `docs/03` "CUI-5 Io-completion notes" and `docs/19` §3.

**Shape of the change.**
- **W4a — the ioctl APC leg.** `kernel/io/rw.c` already has the authority: `IopCompleteTransfer()` writes the IOSB, posts the port packet, then calls `IopQueueCompletionApc(KeGetCurrentThread(), apc)`. Extend that one function to serve the ioctl path (Art. 11: extend the engine). For the **pended** listen, the APC must be queued at `IopCompletePendingRequest` and to the **issuer** thread, not the completing one — `kernel/io/io.h` already states the resolve-up-front rule for the pended request's context, and this extends it to the APC.
- **W4b — change-notify buffering.** Give the directory-watch a queue on the directory *handle* (Wine's model) so a change occurring between completion and re-arm is not lost, and retire the `docs/03` CUI-5 deviation in the same commit.

**Risk to an article.**
- **Art. 11 / G10 — W4a's entire point.** The wrong shape here is a second APC-queueing site inside `ioctl.c`. There must be exactly one.
- **Art. 11 / G11.** The APC object outlives the syscall on the pended path. Who owns it if the issuer thread exits first? `docs/03` "CUI-3 SCM notes" already records that a pending listen is *not* cancelled at its issuer thread's exit — that narrowness now has an APC attached to it, so it must be re-answered, not inherited.
- **G14 — the sharpest gate risk in the plan.** The completion drain is a declared must-not-block region. Queueing an APC from the drain must not be able to park. If it can, `tools/blocking_frontier.py` will catch it — and per §8.4 of `docs/20`, a new blocking point re-opens every STILL-TRUE table. Budget for that; it is the CUI-8 C1 defect's exact shape.
- **Art. 3 — a trap to name explicitly.** W4b will tempt someone to reach for "real async". It does not need it. A queue on the handle is bookkeeping; the pending engine already exists (`kernel/io/async.c`, two consumers). And per Art. 3's own closing clause plus `docs/19` §1, **Art. 3 must not be cited about synchronous I/O at all** — citing it here is the same defect G8 forbids in a constant.

**Effort:** W4a 1 commit-series ~2 days; W4b 1 commit-series ~3–4 days (it retires a recorded deviation, so it needs the `docs/03` edit and a `sem_file/notify_change.c` rewrite that no longer drains the oracle's queue by hand).

---

### W5 — Mm: `SEC_RESERVE` sections and placeholder reservations

**Unblocks:** `ntdll:virtual`, `kernel32:virtual`.

**Boundary surface:** `NtCreateSection` allocation attributes; `NtAllocateVirtualMemoryEx` / `NtMapViewOfSection` placeholder types.

**Oracle source of truth:** `dlls/ntdll/unix/virtual.c` for both (I read the *proskrnl* refusal sites, not the Wine implementations — `kernel/mm/section.c:123` for `SEC_RESERVE` and `kernel/mm/virtual.c:1626` for `MEM_RESERVE_PLACEHOLDER`/`MEM_REPLACE_PLACEHOLDER`; both carry a comment naming their own scope decision). The consumer failures are `virtual.c:862` "NtQuerySection wrong size" (kernel32) and `virtual.c:184` (ntdll).

**Shape of the change.** A commit-on-demand ledger for `SEC_RESERVE` — the thing `section.c:123`'s comment says nothing before M7+ needed — plus placeholder VAD types and the split/coalesce rules `VirtualAlloc2` exposes.

**Risk to an article. This is the item to be most careful with.**
- **`docs/12` names `mm/{section,fault,pagecache}.c` the top danger zone**: plausible code, unit tests pass, then it corrupts silently under Wine's real load. Design before writing.
- **Art. 3.** Commit-on-demand is *not* a mandate violation — the mandates are no COW, no eviction, one dispatcher lock/uniprocessor, one pool, and the list is closed. Fault-time commit of a reserved page is none of those. But it *touches the fault path*, which is where a COW or eviction reflex will try to enter. `docs/17` §10 is the only door for COW and it is a commit of its own.
- **Art. 3 (one pool).** The commit ledger is one pool. No pagefile, no second allocator.
- **G12.** Partial placeholder support that silently succeeds where it should split is `1d6dafd` (`NtResumeThread` as a no-op success). Refuse loudly until the split/coalesce rules are complete.

**Effort:** 2 commit-series, ~5–7 days, and the highest variance in the plan. Consider deferring behind W2/W3/W4 on those grounds alone; it unblocks 2 pairs for the risk of 6.

---

### W6 — The exception/context cluster (**triage-first, not build-first**)

**Candidate pairs:** `ntdll:exception`, `ntdll:unwind`, `ntdll:rtl`, `kernel32:fiber`, `kernel32:volume`, `kernel32:resource` — every one dies with an **unhandled user-mode `0xc0000005`** that terminates the process, not with a missing class.

**What is measured, per pair:**
- **`ntdll:exception`** — `RIP=0, RSP=0`, `err=0x14` (not-present, user, instruction fetch), `last_syscall=0xe4 = NtSetContextThread`. That is a context *restore* that zeroed `RIP`/`RSP`. **Strong hypothesis: `NtSetContextThread` is not honouring `ContextFlags` selectivity** — a caller setting only `CONTEXT_DEBUG_REGISTERS` or `CONTEXT_INTEGER` gets its whole context overwritten. Cheap to confirm, cheap to fix, and it is a genuine boundary contract. The DR0–7 and `EFLAGS.TF` work the brief names sits *behind* this.
- **`kernel32:fiber`** — `err=0x7` = present + **write** + user, at an address one word below `RSP`. A write to a page that is mapped but **not writable**. That is a protection question on a fiber's stack allocation, not an unmapped-page question. Concrete and small if the hypothesis holds.
- **`ntdll:unwind`, `ntdll:rtl`, `kernel32:volume`, `kernel32:resource`** — all four crash *after* a run of ordinary `ok()` failures. For `volume` and `resource` the crash is visibly a **cascade** (a NULL deref after an API that had already failed), so they do not belong in this item at all — they belong to W7 and W8. `unwind` and `rtl` are genuinely unresolved.

**Why this is one item anyway:** they share a single diagnostic question — *does proskrnl deliver a user exception to the user's handler correctly, and does it restore context faithfully?* — and the answer is one `tests/ntapi` investment either way.

**Oracle source of truth:** `dlls/ntdll/tests/exception.c` and `dlls/ntdll/tests/unwind.c` are the spec; the `CONTEXT`/`ContextFlags` contract is documented by Microsoft and is a legitimate `beyond_oracle` citation where the oracle's own answer is host-signal-shaped.

**Risk to an article.**
- **`docs/12` names `ps/usermode.c` and `arch/x86_64/*.S` as danger zones** — assembly and stack-layout exactness, "the model lies in the details". Do not let an agent write this one unsupervised; per `docs/12`'s division of labour, design it, then delegate the writing.
- **Art. 1 / G1.** `CONTEXT` layout and `ContextFlags` semantics are squarely on the boundary, so they must be reproduced *exactly* — and every offset comes from `abi/` with `static_assert`, never from memory (Art. 4).
- **Art. 9.** Whatever is built here, the panic dump must get *more* informative, not less. A change that degrades diagnostics is a regression under `docs/CONTRIBUTING` "Debugging expectations".

**Deliverable ordering:** one triage commit-series (no kernel change: a `tests/ntapi` case that isolates `NtSetContextThread` with a partial `ContextFlags`, oracle-green) **before** any kernel work. If the hypothesis is wrong, the item is re-scoped, and we have lost a day instead of a week.

**Effort:** triage ~1 day; the `NtSetContextThread` fix probably 1 commit-series ~1–2 days; DR0–7 + `EFLAGS.TF` a further ~3–4 days and possibly not worth it (see §5).

---

### W7 — Ob/volume furniture: `\DosDevices`, open-by-file-id, MountPointManager

**Unblocks:** `kernel32:drive` (with W3c), partial `kernel32:volume`.

**Measured:** `volume.c:2022` wants `FILE_SUPPORTS_OPEN_BY_FILE_ID` set; `:2060` "failed to open mountmgr, error 2". Both are namespace/attribute furniture rather than new mechanism.

**Risk:** **G2 is the live question here.** `\DosDevices` and `\Device\MountPointManager` are NT-present, so adding them is not an NT-absent addition — but the *shape* matters: a symbolic link created through Ob's one namespace engine is fine; a special case in the parser is a G10 failure. If any part of it turns out to be genuinely NT-absent, it must go through `/log-hack` into `docs/10-hacks-ledger.md`, and per Art. 2 that carve-out only exists for GUI/console, so it would more likely be a "don't build it" answer.

**Effort:** 1 commit-series, ~2 days. `kernel32:volume` will likely still be red afterwards (open-by-file-id is the larger half).

---

### W8 — Mailslots (`NtCreateMailslotFile` + the mailslot device)

**Unblocks:** `ntdll:file`, `kernel32:mailslot`.

**Boundary surface:** a whole new device. `grep -rln ailslot kernel/ fs/ drivers/ user/` returns exactly one hit: `kernel/syscall/table.inc`, i.e. the id exists and nothing behind it does.

**Oracle:** `dlls/ntdll/unix/file.c` — `NtCreateMailslotFile` (function header at line 4763); classes 26/27 (`FileMailslotQueryInformation` / `FileMailslotSetInformation`, `include/winternl.h:1356–1357`).

**A documentation contradiction to resolve first.** `docs/16-syscall-status.md` currently files `NtCreateMailslotFile` under "**No consumer in the baked stack**" (13 ids). The winetest gate is now a baked consumer — `ntdll:file` calls it and panics. Either the row moves, or the pair is excluded under manifest rule (a) with a recorded decision. **Decide this before writing code**, and note that `docs/03`'s own G5 policy for winetest ("the winetest subtest IS the oracle-pinned differential test") argues the row must move.

**Risk:** **Art. 5's second limit.** The article says `beyond_oracle` is "a permission, not an instruction to go build every service Wine lacks — the loud refusal stays the right answer until something real needs the case." Mailslots are the clearest place in this backlog to ask whether the test suite counts as "something real". My reading: for this project it does, because `docs/02` makes the winetest manifest the verification spine of every CUI milestone. But it is a judgement call and it belongs to the human, not to the plan.

**Effort:** 2 commit-series, ~4–6 days. Lowest leverage-per-day of the buildable items (2 pairs for a new device).

---

### W9 — The write-then-load-an-image cluster (**triage-first**)

**Candidate pairs:** `ntdll:rtl` (`rtl.c:3408`, LoadLibrary → **126**), `kernel32:actctx` (26 failures in `subtest_manifest_res()`, which writes an EXE+DLL pair to disk and runs them), `kernel32:resource` (`GetFileMUIInfo` → **193** ERROR_BAD_EXE_FORMAT).

**The hypothesis worth one day of triage:** all three write a PE to disk at runtime and then map it as an image, and all three fail at the map. That would be **one** bug — a section/page-cache coherence or file-size-visibility problem on the `SEC_IMAGE` path — worth 3 pairs. `docs/19` §8.2 lists `sem_mm/file_coherence` as an existing oracle-green guard, and `docs/12` names `mm/pagecache.c` a danger zone, which is consistent with a bug living there and being invisible to everything single-threaded.

**I am explicitly unsure of this.** It is a pattern across three logs, not a diagnosis. Do not schedule the fix; schedule the triage.

**Risk:** if it *is* pagecache/section, it is `docs/12`'s top danger zone, and `docs/19` §6's re-entrancy question ("35 greppable no-preemption justifications, each a claim to re-check") is adjacent. Design first.

**Effort:** triage ~1 day. Fix: unknown until triaged; could be 1 day or 2 weeks.

---

### W10 — `ntdll:sync` wedges (a hang, not a gap)

`wtest ntdll_test.exe:sync FAIL (timeout)` at 300 s, with "0 tests executed" from a **child** process. This is a deadlock or a lost wakeup, and it is the only pair in the backlog that can wedge the console and abort the whole sweep (`docs/03`: "the sweep ABORTS on timeout rather than running more pairs against a wedged console"). That makes it disproportionately expensive to leave alone.

**Risk:** `docs/12` names `ke/{wait,apc}.c` as the "subtly wrong yet still runs" zone with multi-month bug latency. A hang here is exactly that class. **Art. 6 applies with full force**: a change that makes the hang stop is not a fix; only a differential test convicts.

**Effort:** unknown. Triage ~1 day to establish whether the wedge reproduces and where. Then reassess.

---

## 4. What needs a constitutional amendment

**Nothing in this backlog does.** That is a real finding and it should be stated in the milestone entry so nobody re-opens the question.

Specifically:

- **No COW is needed.** `docs/17` §10's entry conditions are not touched by anything above. `docs/09`'s table already records COW as **amended at CUI-9** for image-section masters; nothing here asks for more.
- **No SMP is needed.** `docs/18` §13's four gates are not touched. Nothing in the backlog is a throughput problem. The nearest thing is `kernel32:virtual`'s 285-second runtime, and slowness only becomes a constitutional argument when it stops a suite from reaching a verdict (`docs/09` Art. 3's uniprocessor row) — it has not.
- **No second allocator is needed.** W3b's sort snapshot, W2b's process snapshot and W5's commit ledger all come from the one pool.
- **No amendment is needed for async, and it is important to say why.** Art. 3's list is **closed** and synchronous I/O is not on it; inline completion is a legal point inside the NT contract (`docs/19` §1). W4 is ordinary Art. 5 work. **Citing Art. 3 to justify or to block W4 is itself a gate violation** — an article cited for a clause it does not contain, which Art. 3's own text equates to G8's uncited constant.

**Where an amendment *would* be required, if someone proposed it:**

| Hypothetical | Amendment text it would need |
|---|---|
| Genuine pending on file **data** (queue depth > 1, drain from idle) | **None.** This is CUI-8, already planned, `docs/19` §5 — not an amendment, and it is not required by any pair in this backlog. |
| Fine-grained locking to make W2b's process walk "safe" | Art. 3's "one dispatcher lock, uniprocessor, no kernel preemption" row. There is no exit condition written for it other than `docs/18` §13's four gates for SMP. **Do not go here** — the uniprocessor model is precisely what makes W2b's snapshot walk trivially atomic. |
| Demand paging / eviction to back W5's commit ledger | Art. 3's "no eviction, immediate writeback" row, whose table entry reads *"unbuilt; no consumer, no design"*. An amendment would have to supply both, plus a measurement, plus the `docs/03` entry, as its own commit. **W5 does not need this** — commit-on-demand of a reserved range is not eviction. If an implementation starts to need it, that is the signal W5 has been designed wrong. |

---

## 5. Low-value items and traps

**Traps — pairs that will consume effort and unblock nothing:**

1. **`kernel32:path` is not part of W3.** All 11 failures are `GetShortPathName` 8.3 generation (`path.c:233`, `:245`). That is a FAT32 short-name question in `fs/`, entirely disjoint from the NT open-path table. Grouping them, as the brief's backlog does, will make W3 look unfinished when it is done. Split it out and schedule it separately or not at all.

2. **`kernel32:locale` (94 failures) is data, not kernel.** 72 of the 94 are at `locale.c:3809`/`:3813` — `LCMAP_SORTKEY` and `CompareStringEx` collation, which is a `sortdefault.nls` question resolved entirely inside Wine's PE side. `docs/03` already records that the wtest image **provisions** the full NLS set. If a collation table is missing or stale this is a bake-time fix; if it is present, the failure is in Wine PE code and **is not proskrnl's to fix** and probably not fixable without patching Wine, which G9 forbids for exactly this purpose. **Measure whether the pair is oracle-green under the same NLS set before spending an hour on it.**

3. **`kernel32:profile` (7 failures) is not in the brief's backlog and may be a host artefact.** `docs/03`'s own eight-pair correction lists `kernel32:profile` as one of the pairs that went from 4 failures to 0 when the oracle stopped running as root. It is now red on *proskrnl* with 7. Re-measure the oracle leg first (W0). If it is a ninth host-parked pair, the fix is in `tests/run/run.sh`, not the kernel.

4. **`kernel32:volume` and `kernel32:resource` crashes are cascades, not bugs.** Both `0xc0000005`s occur after a run of `ok()` failures where an API already returned NULL/garbage. Chasing the crash rather than the first failing `ok()` wastes the day. `volume.c:2017` (open failed, error 123) and `resource.c:695` (`GetFileMUIInfo`, error 193) are the real entry points.

5. **Hardware debug registers (DR0–7) and `EFLAGS.TF` are the lowest-value item in the plan.** They unblock only `ntdll:exception`, and only *after* W6's `NtSetContextThread` fix, which may unblock it alone. `docs/03` already records debug objects as permanently out of scope (ADR 0011) — DR0–7 are a different surface, but the same "who actually needs this" question applies, and no baked binary does. **Do W6's triage, then re-ask.**

6. **`ntdll:om`, `kernel32:{console,process,loader,module,debugger}`, `ntdll:{alpc,wow64}`, `cmd.exe_test:batch` stay commented out.** They fail identically on both runners, or depend on the standalone link rather than the boundary (`kernel32:module` asserts the test binary's own import list — 2 failures on the oracle, identical on proskrnl). Re-litigating any of them is pure loss. Note the asymmetry the manifest header already documents: being *unimplemented* is not a reason to comment a pair out — only "never implementing it" (a) or "the oracle cannot serve as the spec" (b) are.

**Low value but cheap — do them anyway:** W2c (`SystemBatteryState`), W3c (`\DosDevices`). Both are hours, not days, and each closes a pair or moves one materially.

---

## 5a. Execution log (update this as items land)

**W1 — DONE.** The refusal split is in `NtQuerySystemInformation`,
`NtQueryInformationThread`, `NtSetInformationThread` and
`NtQueryInformationProcess`: a class number outside the enum answers
`STATUS_INVALID_INFO_CLASS` (an implementation, pinned by
`tests/ntapi/sem_ps/info_class_range.c`); a class inside it that is unbuilt
keeps `STATUS_NOT_IMPLEMENTED`, names itself on serial and stays fatal.
Bounds come from each enum's own `Max*InfoClass` sentinel in `abi/`. The
fork's private classes (1000-and-up) sit ABOVE those sentinels and are real,
so they are excluded from the range test by name — `gen_abi.py` had to stop
dropping `THREADINFOCLASS`'s `__WINESRC__` branch for the kernel to be able
to name them.

**W2a — IN PROGRESS.** The `NtQueryInformationThread` sweep now runs to
completion. Landed: `ThreadHideFromDebugger` and `ThreadPriorityBoost` (both
were accept-and-drop stubs — set succeeded, query could never see it),
`ThreadAffinityMask`, `ThreadDescriptorTableEntry` (the reachable GDT half;
LDT selectors stay loudly unbuilt), `ThreadIsIoPending` (matching the
oracle's own declared stub), and `ThreadIdealProcessor` /
`ThreadEnableAlignmentFaultFixup` as `INVALID_INFO_CLASS` — which the oracle
calls invalid too, and is the evidence that W1's split is the boundary's
distinction rather than ours. On the process side: `ProcessPriorityBoost`
and `ProcessAffinityMask`.

Two findings from W2a worth carrying forward:

- **`KeNumberProcessors` is now the one statement of the processor count**
  (`kernel/ke/ke.h`). It was spelled `1` in the PEB stamp and in
  `SystemBasicInformation` already; the affinity classes would have been a
  third. Under Art. 3's uniprocessor mandate a one-bit mask is the TRUTH,
  not a placeholder — which is what separates it from the fabricated
  answers G12 forbids.
- **`OBJECT_TYPE` grew an optional `mapAccess` hook**, applied inside
  `ObpMapDesiredAccess` (the one grant site). The thread type carries NT's
  implications verbatim from `server/thread.c thread_map_access`. But the
  limited right is NOT a skeleton key: only `ThreadBasicInformation`,
  `ThreadTimes`, `ThreadAmILastThread` and `ThreadPriorityBoost` are
  readable through a `THREAD_QUERY_LIMITED_INFORMATION` handle, and
  everything else must be `STATUS_ACCESS_DENIED`. Classes whose VALUE needs
  no thread state still owe the check (`PspCheckThreadAccess`) — a class
  that answers without validating answers a caller that was never entitled
  to ask, and only a test opening a deliberately weak handle can see it.

**Suspend/resume on an exited thread: FIXED.** `thread.c:551`/`:554` are
green. The rule is asymmetric and the asymmetry is the point — a
TERMINATED thread refuses `NtSuspendThread` with `STATUS_ACCESS_DENIED`
(the oracle's server says exactly that status, not one about the thread's
state), while `NtResumeThread` has no such guard at all and succeeds with a
count of 0. Pinned by `tests/ntapi/sem_ps/suspend_exited.c`.

**The suspend cluster: FIXED, and the root cause was in Ob.**
`ObReferenceObjectByHandle` resolved only the TOKEN pseudo-handles; `-1`
and `-2` fell through to the table and returned `STATUS_INVALID_HANDLE`.
`threadFunc3`'s `SuspendThread(GetCurrentThread())` therefore failed
silently and the child never parked. Resolved in Ob beside the token
handles (bypassing the ACCESS check, keeping the TYPE check), which
cleared `thread.c:585`, `:590`, `:598` and `:601` at once. **Seven
per-site `handle != NtCurrentThread()` dances in `kernel/ps/` are now
redundant** — left in place deliberately, to be retired as their classes
are next touched rather than in a drive-by (G13).

**Thread priority: DONE.** The Set/Get round-trip goes through
`ThreadBasePriority` and `ThreadBasicInformation.BasePriority` and nothing
else; the set was dropped and the query returned the SCHEDULER's priority.
Both halves fixed, plus the range check
(`THREAD_BASE_PRIORITY_MIN..MAX`, with `IDLE`/`TIME_CRITICAL` always legal)
whose absence made `SetThreadPriority` succeed on a bad argument and never
set an error — the test caught that by reading its own `0xDEADBEEF` poison
back out of `GetLastError`, which is worth remembering as a detection
technique. `thread.c:697`, `:717`, `:719`, `:738`, `:739`, `:743` all pass.

**Affinity: DONE.** The set NARROWS to the system mask rather than
validating against it (that is what makes `SetThreadAffinityMask(t, -1)`
mean "every processor"), and `ThreadBasicInformation.AffinityMask` is
filled — kernel32 RETURNS that field as the previous mask, so leaving it
at its memset zero made every call read as a failure with nothing wrong on
the set path at all. `:909` and `:915` clear.

**Two left on `kernel32:thread`:**

```
thread.c:800  rc=1 error=5 disabled=0                (SetThreadPriorityBoost)
thread.c:937  Unexpected return value 4294967295     (SetThreadIdealProcessor)
thread.c:960  Unexpected return value 4294967295     (same, WOW64 arm)
```

`:937` is worth a careful look rather than a guess. kernelbase's
`SetThreadIdealProcessor` returns `~0u` ONLY when
`NtSetInformationThread(ThreadIdealProcessor)` fails, and that class is
still in this kernel's accept-and-drop group on the SET side, so it should
be returning STATUS_SUCCESS. Either it is not reaching that arm or the
length/probe path in front of it is refusing — confirm which before
changing anything, because the obvious reading (that the class is unbuilt)
is contradicted by the code. Note also that the QUERY side of the same
class answers STATUS_INVALID_INFO_CLASS by design (the oracle does too);
do not "fix" the set by making the pair symmetric.

**Previously here:**

```
thread.c:800  rc=1 error=5 disabled=0            (priority boost)
thread.c:909  SetThreadAffinityMask failed
thread.c:915  SetThreadAffinityMask(thread,-1) failed to request all
thread.c:937  Unexpected return value 4294967295
```

`:909`-`:937` are one item: `NtSetInformationThread(ThreadAffinityMask)`.
The QUERY side is done (one CPU, one bit); the set is unbuilt. `-1` means
"all processors" and must be accepted and narrowed to the system mask —
the return is the PREVIOUS mask, and `4294967295` at `:937` is a `-1`
leaking through unnarrowed. `:800` is `SetThreadPriorityBoost`, adjacent
to the flag already stored.

**Superseded note:** `SetThreadPriority`/`GetThreadPriority`
are a round-trip through `ThreadBasePriority` and
`ThreadBasicInformation.BasePriority` and nothing else
(`dlls/kernelbase/thread.c`); the set was dropped and the query returned
the SCHEDULER's priority, so `:717`/`:719` failed for every value. Now
stored. Three assertions remain on that pair:

```
thread.c:697  GetThreadPriority Failed                    (expects THREAD_PRIORITY_NORMAL == 0)
thread.c:738  SetThreadPriority passed with a bad argument
thread.c:739  SetThreadPriority error -559038737, expected ERROR_INVALID_PARAMETER
thread.c:743  GetThreadPriority didn't return min_priority
```

`:738`/`:739` are one thing: `NtSetInformationThread(ThreadBasePriority)`
accepts any LONG and must instead REJECT out-of-range values so
`SetThreadPriority` fails and `GetLastError` reports
`ERROR_INVALID_PARAMETER` — note `-559038737` is `0xDEADBEEF`, i.e. the
test's poison, meaning the call succeeded and never set an error at all.
Find the accepted range from `dlls/kernelbase/thread.c`'s
`SetThreadPriority` and the server's `set_thread_info` before choosing
one. `:697` and `:743` want checking after that lands — they may be
consequences of the same missing validation.

**The earlier note, now superseded:** `kernel32:thread` is one bug, not four. The remaining
failures cluster:

```
thread.c:585  SuspendThread did not work        <-- START HERE
thread.c:590  OpenThread returned an invalid handle
thread.c:598  Thread did not really suspend
thread.c:601  Resume thread returned an invalid value
thread.c:697  GetThreadPriority Failed
```

**SELF-SUSPENSION is the cause.** `threadFunc3` (thread.c:253) is four
lines and its whole body is `SuspendThread( GetCurrentThread() )`. The
parent then polls `SuspendThread(child)` waiting to observe a previous
count of **1** — i.e. it is waiting for the child to have parked ITSELF.
If a thread that suspends itself does not actually stop, the child runs to
completion instead, the poll never sees 1, and everything after is
downstream: `:590`'s `OpenThread(threadId)` then fails because the thread
is *gone*, not because of its NT4-era access mask, and `:598`/`:601` are
asking about a thread that already exited.

*(An earlier revision of this note named `:590` as the cause on the
strength of its access mask. That was wrong, and it is left recorded
because it is the exact trap this section warns about elsewhere: the
loudest-looking failure in a cluster is usually the consequence. Read the
test's helper before believing the assertion text.)*

**DIAGNOSED, not yet fixed.** The parking machinery is fine — a closed
suspend gate is honoured on the syscall return path
(`kernel/syscall/table.c:231` calls `KiProcessPendingUserSignals` whenever
the frame is returning to ring 3, and that parks on the gate). The bug is
one step earlier: `NtSuspendThread` resolves its handle with a plain
`ObReferenceObjectByHandle`, and **Ob does not resolve the
`NtCurrentThread` pseudo-handle**. `ObReferenceObjectByHandle`
(`kernel/ob/handle.c:270`) special-cases only the TOKEN pseudo-handles
`~3`/`~4`/`~5`; `-1` (current process) and `-2` (current thread) fall
through to the table lookup and come back `STATUS_INVALID_HANDLE`. So
`threadFunc3`'s `SuspendThread(GetCurrentThread())` fails outright, the
child never parks, and the whole cluster follows.

Two ways to fix it, and the choice is a real one:

1. *Per-site*, as every other class in `kernel/ps/thread.c` already does
   (`if (threadHandle != 0 && threadHandle != NtCurrentThread())`). Small
   and consistent with what is there — but it is the eighth copy of that
   idiom, and G10's objection to parallel paths applies even while they
   agree.
2. *In Ob*, beside the token pseudo-handles it already resolves, which is
   where NT puts it and where Art. 11 points. Broader blast radius: every
   caller of `ObReferenceObjectByHandle` starts accepting `-1`/`-2`, which
   is correct but wants a sweep of the sites that currently reject them on
   purpose.

Option 2 is the right answer and should be taken deliberately, with the
per-site copies retired in the same commit. Do not do option 1 "for now" —
that is how the seven existing copies happened.

**W2a is DONE for `NtQueryInformationThread`/`NtSetInformationThread`.**
`kernel32:thread` no longer panics anywhere in the class sweep — every
class it touches now answers either its value or a specific NT failure.
The private `ThreadWineNativeThreadName` was resolved as
`STATUS_INVALID_INFO_CLASS` (beyond_oracle): it names a HOST thread
identity proskrnl does not have, since here the NT thread is the native
thread and its name is already stored by `ThreadNameInformation` one line
earlier in the same caller.

**What `kernel32:thread` fails on now** — real assertions, no longer
missing surface. All eight are the SUSPEND/RESUME counter and the handle
it is driven through:

```
thread.c:551  SuspendThread returned 0, expected -1
thread.c:554  ResumeThread returned 1, expected 0
thread.c:585  SuspendThread did not work
thread.c:590  OpenThread returned an invalid handle
thread.c:598  Thread did not really suspend
thread.c:601  Resume thread returned an invalid value
thread.c:609  wrong return code: 0
thread.c:610  unexpected error code: 87
```

The first pair is the giveaway: `SuspendThread` on an ALREADY-TERMINATED
thread must return -1 and `ResumeThread` 0, and proskrnl returns a live
count instead — so the suspend counter is not being retired at thread
exit. `:590`'s invalid handle from `OpenThread` is likely the same
lifetime question seen from the other end. Start there rather than at
`:585`, which is a consequence.

**The earlier state, for reference:** `kernel32:thread` has
cleared the whole `NtQueryInformationThread` range and now blocks on
`NtSetInformationThread` class **1000**, `ThreadWineNativeThreadName` — the
fork's own private class, which `RtlSetThreadName` calls unconditionally
(`third_party/wine dlls/ntdll/thread.c`) and whose result it discards.

*This one needs a decision, not an implementation, and it should not be
guessed at.* On the oracle the class names the underlying UNIX thread; on
proskrnl the NT thread IS the native thread, and its name is now stored by
`ThreadNameInformation` (see below). So there are three defensible answers
and they are not interchangeable: accept-and-store-nothing (a drop, and
therefore G12-forbidden unless something observes it),
`STATUS_INVALID_INFO_CLASS` pinned `beyond_oracle` on the grounds that there
is no second name to set here, or a real second stored string. Pick by
asking what a caller could observe, and pin whichever is chosen — the one
thing that must not happen is a bare `return STATUS_SUCCESS`, which is the
shape five classes in this item have already had to be rescued from.

Also visible now that the class sweep runs to completion: `kernel32:thread`
has real assertion failures beyond the info classes — `thread.c:551`/`:554`
(`SuspendThread`/`ResumeThread` counts), `:585` and `:590` (`OpenThread`
returning an invalid handle). Those are separate work from W2a.

**The earlier blocker, now closed:** `kernel32:thread` blocks on
`NtQueryInformationThread` class 38, `ThreadNameInformation`. Its SET side
currently returns `STATUS_SUCCESS` without storing anything — the comment
there says ntdll keeps the name in the TEB and the kernel does not observe
it, which was true until the QUERY side became reachable. It is now the
fourth accept-and-drop stub this item has found, and closing it means the
kernel must actually own the string: a pool-allocated per-thread name, set
under the `THREAD_SET_LIMITED_INFORMATION` rules, freed at thread delete,
and returned as a `THREAD_NAME_INFORMATION` whose `Buffer` points just past
the struct (the oracle's shape — see `dlls/ntdll/unix/thread.c`, and note
it answers `STATUS_BUFFER_TOO_SMALL` for a NULL `info` rather than an access
violation). That is an ownership question, so design it before writing it.

### `kernel32:thread` is green (915 tests, 43 todo, 0 failures)

The pair closed on its last defect, and the defect is worth recording
because it was one I had *already fixed once, wrongly*. `thread.c:800`
wanted a process-wide boost-disable to show through the thread's query;
I made the thread query read `thread->flag || process->flag` and the
assertion went green. Nine lines further on, `thread.c:809` clears the
THREAD's flag while the process's stays set and requires the thread to
read 0 — which an OR can never report.

The oracle had said so plainly the whole time (`server/process.c`
`set_process_disable_boost`): the process value is *assigned into* every
thread on the process's thread list, and a new thread copies it at
creation. Propagation and lookup agree on the case I tested and disagree
on the case I had not yet reached, which is the general shape of a wrong
fix that passes: **the assertion I aimed at was satisfiable by two
different models, and I picked the one I could write without reading the
server.** The habit that catches it is the one this file keeps
re-learning — read the oracle's implementation, not just the assertion
that is currently red.

Also landed alongside: `KeNumberProcessors` → `KE_NUMBER_PROCESSORS`.
`make tidy` does not report a macro-case violation, it *rewrites the
definition*, leaving every call site pointing at a name that no longer
exists. Worth knowing before the next NT-spelled macro goes in.

### The backlog map was re-measured, and two of its entries were wrong

The map in §2 was taken before roughly twenty kernel fixes, and one boot
per pair now says something different. Of the 73 manifest pairs, **43 pass
and 30 fail**; all of `msvcrt` (10/10) and `ucrtbase` (8/8) are green.

Two corrections matter more than the counts, because both were *inferences
recorded as measurements*:

- **`kernel32:toolhelp` does not carry `SystemProcessInformation` work, and
  never did.** §2 attributed its 135 failures to class 5 on the strength of
  the message text ("couldn't find self and/or sub-process in process
  list"). The actual cause is one line in the pair's *sub-process*:
  `if (!LoadLibraryA("shell32.dll")) ExitProcess(WAIT_ABANDONED);`. shell32
  imports user32 and gdi32, so the child cannot start on a CUI volume, the
  parent's wait times out at `toolhelp.c:649`, and all 134 remaining
  failures are downstream of that. The enumeration the pair is nominally
  about answers *correctly* for the three processes that do exist. The pair
  is now excluded from the manifest as category (c), needs-the-GUI-image,
  with that measurement written down. **The lesson is the cheap one: a
  failure message names the assertion, not the cause.**

- **`FileIdInformation` was a PANIC, not a set of failures.** `ntdll:directory`
  was recorded as ~86 failures. It was in fact dying: class 59 is unbuilt,
  the armed boot turns `STATUS_NOT_IMPLEMENTED` into a panic by design, and
  everything after `directory.c:1461` never ran. Implementing the class
  (a join of `FileInternalInformation`'s id and `FileFsVolumeInformation`'s
  serial — no third source, Art. 11) took the pair from *dead* to 5199
  tests executed with 407 failures. Which is to say the "failure count" of a
  pair that panics is not a measurement of anything.

Then `NtQueryDirectoryFile`'s IOSB rule took it 407 → **285**. That rule is
worth restating because neither obvious implementation is right: the class
writes the caller's IOSB on failure too, with exactly one exemption
(`if (status != STATUS_NO_SUCH_FILE) io->Status = status;`).

### W3a — 8.3 short names (the next item, and the biggest single lever)

203 of `ntdll:directory`'s remaining 285 failures are one assertion,
`directory.c:620` — the wildcard truth table of ~77 masks against 18 files.
It is tempting to read that as "the wildcard matcher is wrong", and a
scratch harness that replays the table against the current matcher does
show 49 disagreements, all involving DOS_STAR `<`. But the matcher is not
the root cause: the oracle matches the mask against the long name **and,
on failure, against the 8.3 short name**, and proskrnl has no short names
at all. `ShortName` in `FILE_BOTH_DIRECTORY_INFORMATION` is likewise left
empty, on a comment claiming the oracle leaves it empty too — a claim the
oracle disproves by passing `directory.c:654`.

FAT32 *stores* real short names on disk; they simply are not carried out
through `IO_DIR_ENTRY`. The differential wrinkle to design around is that
the short name FAT stores and the one Wine synthesizes are different
strings, so the pins can assert the *property* (non-empty, 8.3-shaped, also
matched by the mask) but not the value.

### W3 landed: `ntdll:directory` 285 → 46, and the framing above was wrong

A planning pass computed the truth table offline — all 77 masks x 18 files
— instead of trusting the reading in the section above, and the answer
reordered the work. The short-name leg is worth **9** of the 203 failures
at `directory.c:620`, not most of them. What the rest were:

1. **The mask binds at scan start, not on every call** (~150 of the 203,
   and all 34 at `:265`). `NtQueryDirectoryFile` rebound the handle's mask
   whenever a non-empty one arrived; the oracle rebuilds the filtered
   snapshot only `if (cached && restart_scan && mask && mask differs)`
   (`get_cached_dir_data`). `ntdll:directory` passes a matches-nothing
   `dummy_mask` on every continuation call (`directory.c:241`), so proskrnl
   rebound to it and lost the rest of every directory. One `if`.
   **285 → 94.**

2. **DOS_STAR** (~40). `<` could only stop at or before the final dot, so
   `<tmp` matched nothing ending in `.tmp`. It walks dot-segments now, and
   is *spent* past the final dot — the constraint that keeps `<a` from
   matching `.aa`. **94 → 46**, with `:620` at exactly 9.

3. **8.3 short names** (the 9, plus `:654`, plus `kernel32:path`'s 11
   `GetShortPathName` failures — the largest external beneficiary and the
   real reason to do the item).

**The method is the lesson, not the ordering.** The offline harness
replayed the table against a candidate matcher in a second, so four wrong
algorithms were discarded before one reached a boot; the surviving one
predicted "48 → 9, and here are the 9" before the kernel was touched, and
the measurement matched exactly. A truth table in a third-party suite is a
*specification you can execute*, and executing it beats reasoning about it
— the first two hypotheses this session's author formed by reading the
oracle's code were both wrong, and both were disproved in seconds by the
harness rather than in twenty minutes by a boot.

Sequencing consequence worth keeping: **short names first would have
measured as zero**, because the 9 cells were invisible behind the
dummy-mask truncation. When several defects stack on one assertion, fix
the one that hides the others first, or the useful work looks worthless.

### W3a landed: short names. `directory.c:620` is at ZERO, `kernel32:path` is green

`RtlIsNameLegalDOS8Dot3` is the one legality authority; `IO_DIR_ENTRY`
carries the SFN FAT already had in hand; `IopFillShortName` decides once,
for both Both-shaped classes, whether the boundary shows it; and
`IopEntryMatchesMask` gives the mask its second leg.

**`ntdll:directory` 46 → 36**, with all 1386 truth-table cells and `:654`
passing. **`kernel32:path` 11 → 0** — 202,636 tests green. That pair was
listed in §5 as a trap to "schedule separately or not at all"; it was the
largest beneficiary and it cost nothing extra.

Three things worth keeping:

- **The predicate is not the storage rule, and `lower.txt` proves it.** The
  oracle reports NO short name for `lower.txt`, so 8.3-legality is
  case-insensitive — while FAT stores a short entry for it precisely
  *because* a bare 8.3 entry cannot hold lower case. Two questions, two
  functions; merging them makes one answer wrong. "Report whatever the
  volume stored" passes every other assertion in the pin and fails that one.

- **A first attempt made the pair WORSE** (`:620` 9 → 10) because FAT's
  generated names had the wrong shape: `.a` became `_~1.A`, and a short
  name carrying a dot cannot be reached by DOS_STAR. Stripping leading dots
  and spaces before choosing the extension fixed it, per Microsoft's
  8.3-generation rules.

- **One constant was fitted, and then measured instead.** Three cells need
  a generated name at least four characters wide (a three-DOS_QM mask must
  match nothing). Padding the base to two characters satisfies them and
  produces `A~~1`, which no real FAT driver emits — fitting to a table
  through a mechanism that might not be Windows'. Measuring the oracle
  first gave the actual property: its hashed names are ≥ 8 characters, so a
  short DOS_QM run can never match one *there*. Reproducing the WIDTH via a
  zero-padded numeric tail (`A~01`) is the same property, readable, and
  licensed by the FAT specification §7.4. The pin asserts ≥ 4, the widest
  bound both runners can satisfy.

The offline harness earned its keep twice more: it reproduced the measured
10 exactly before any fix, and scored six candidate name-generation rules
in a second.

### `ntdll:directory` is at its FAT floor: 5 failures, one cause

The pair went **dead → 6393 tests, 5 failures** across this series. The
last five are not five defects; they are one, and it is not fixable on this
backend:

`directory.c:1446` fails `FSCTL_SET_REPARSE_POINT` with
`STATUS_INVALID_DEVICE_REQUEST`, so the file never becomes a reparse point
— and the four `EaSize` assertions at `:1568`–`:1593` are checking the
reparse TAG, because `EaSize` aliases `ReparsePointTag` in the directory
classes for a file that has one. Fix the first and the other four follow;
without it they cannot pass.

Reparse points are an NTFS construct. FAT32 has nowhere to put one, and
inventing an on-disk extension would be writing a filesystem the public
spec does not describe. So **5 is this pair's floor** while the backend is
FAT, and those assertions convict nothing.

Two other things this stretch settled:

- **`:389` and `:421`–`:464` were one contract, not two.** The threshold
  below which a class complains about LENGTH is
  `align8(offsetof(FileName[1]))`, not `offsetof(FileName)` — a buffer
  holding just the fixed part is still too small. And three classes
  (`FileObjectIdInformation`, `FileQuotaInformation`,
  `FileReparsePointInformation`) size-check BEFORE refusing, so
  "supported?" is answered after "big enough?" — which is what separates
  known-but-unsupported from unknown.

- **A recorded deviation came due.** `docs/03`'s "Name case folding" row
  said ASCII-only upcasing was "unobservable until user mode invents
  non-ASCII object names". Three fixes later the enumeration sort reached a
  directory holding U+00E9 and U+00C9 and the row was wrong. The fold now
  covers Latin-1 — as a switch, not `c - 0x20`, because U+00FF maps to
  U+0178 and a bare subtract would make y-diaeresis and sharp-s the same
  NAME in Ob, FAT lookup and Cm alike. **A deviation note is a debt, not a
  dismissal.**

### W2b in progress: `ntdll:info`, and the refusal split that was too coarse

`ntdll:info` was recorded as a wedge. It is not — it **panics**, on the
first `NtQuerySystemInformation` class it reaches that proskrnl has not
built, and then the pair ends. Clearing it is a walk: build one class, the
pair advances to the next. 114, then 62, then 4, then 21 so far.

Class 4 exposed a real defect in the refusal split rather than a missing
class. The rule was "outside the enum is INVALID, inside it and unbuilt is
NOT_IMPLEMENTED and panics". But of `SYSTEM_INFORMATION_CLASS`'s **262
enumerators the oracle serves 37** — the other 225 reach its default arm
and get `STATUS_INVALID_INFO_CLASS`. For those, INVALID_INFO_CLASS is not a
guess, it is *the answer*, and giving it is an implementation rather than
the plausible-stub Art. 12 forbids. Being in the enum was never the right
test; being served by the oracle is.

So `kernel/ps/query.c` now carries the narrower set **as a list**: the
classes the ORACLE implements and proskrnl does not. Those keep the loud
refusal, because there a quiet one really would hide a hole. Listing them
rather than deriving the 225 is deliberate — the list is the honest
inventory of what the call still owes, and a class leaving it is a visible
edit in the commit that builds it.

**The inventory is in the code** (`kernel/ps/query.c`, the default arm) and
shrinks by one entry per commit that builds a class. It began at 16; ten
remain:

    SystemExtendedHandleInformation(64)   SystemLogicalProcessorInformation(73)
    SystemModuleInformationEx(77)         SystemProcessorIdleCycleTimeInformation(83)
    SystemProcessIdInformation(88)        SystemCodeIntegrityInformation(103)
    SystemProcessorBrandString(105)       SystemLogicalProcessorInformationEx(107)
    SystemCpuSetInformation(175)          SystemSupportedProcessorArchitectures2(230)

Six landed in two batches (35, 37, 62, 154, 206, then 21, 58, 63, 149, 250)
plus `SystemExtendedProcessInformation` (57). That last one is the shape the
remaining extended classes will follow: **57 is class 5 with a wider
per-thread record, not a second enumeration.** The record size is threaded
through the sizing pass, the fill and the name offset, and the per-thread
slot is addressed by stride rather than array index — which is how the
oracle does it too (`get_system_process_info` takes the class and picks
`thread_info_size`). Class 64 is the same relationship to class 16 and
should be built the same way; writing a parallel walk for it would be the
Art. 11 defect this file keeps re-learning.

Five landed alongside it (35, 37, 62, 154, 206) as one batch, and their pin
records the thing that makes such a batch safe: these classes answer with
*shape plus a constant*, which is simultaneously the correct implementation
and the classic silent stub. What separates them is only that every value
was read off the oracle and pinned. Two are values the oracle itself calls
a stub — reproducing a stub's OUTPUT is not stubbing, since Art. 6 makes
the oracle the spec and no caller can tell.

`SystemProcessorFeaturesInformation` is the one that is not a constant, and
it is worth the extra care it got: the base word is architecturally
guaranteed on any x86_64, but the optional bits (SSE3, CMPXCHG16B, XSAVE,
RDRAND, vendor) are read from CPUID rather than assumed, because a caller
told it has `cx16` on a machine without it takes a fault. That is the
failure mode a fabricated answer actually produces.

**Next**: continue the `ntdll:info` walk through the 16 above; then
`ntdll:file`, which panics for the same reason on a different surface
(`NtCreateMailslotFile`, W8); then the rest of §2's red list, re-measured —
several of those numbers were recorded while the pair was still dying
rather than failing, and a dying pair's failure count measures nothing.

*The `abi/` header trap, now resolved and worth remembering.*
`ThreadGroupInformation` returns a `GROUP_AFFINITY` whose `Mask` is a
`KAFFINITY`, and that typedef sat in `abi/ntpebteb.h` while the struct
generates into `abi/ntpsapi.h` — which does not include it, and cannot,
because `ntpebteb.h` already includes `ntpsapi.h` and the reverse would
cycle. The fix was to move the typedef down to `abi/ntdef.h`, the header
both already include, in `gen_abi.py` rather than by hand. The rule this
illustrates for the classes still to come: when a generated struct needs a
type from a sibling `abi/` header, move the type — do not hand-write the
layout to route around it (Art. 4), and do not add an include without
checking the direction first.

## 6. Sequencing and effort

| # | Item | Pairs unblocked | Series | Rough effort | Depends on |
|---|---|---|---|---|---|
| **W0** | Re-measure the sweep | up to 4, for free | 1 (docs only) | 1 d | — |
| **W1** | Refusal shape: `INVALID_INFO_CLASS` vs `NOT_IMPLEMENTED` | enables W2/W3 | 1 | 1–2 d | W0 |
| **W2** | Query surfaces (thread / system / power) | **6** | 3 | 5–8 d | W1 |
| **W3** | Path & name surface (open-path table, dir order, `FileIdInformation`) | **3** | 3 | 4–6 d | W1 (for W3c) |
| **W4** | Completion legs (ioctl APC; change-notify buffering) | **3** | 2 | 5–6 d | — |
| **W6t** | Exception/context **triage** | — | 1 (test only) | 1 d | — |
| **W6** | `NtSetContextThread` `ContextFlags` (+ fiber stack protection) | 1–2 | 1–2 | 2–4 d | W6t |
| **W7** | `\DosDevices`, open-by-file-id, mountmgr | 1 (+partial) | 1 | 2 d | W3c |
| **W9t** | Write-then-load-image **triage** | — | 1 (test only) | 1 d | — |
| **W5** | Mm `SEC_RESERVE` + placeholders | 2 | 2 | 5–7 d, high variance | — |
| **W8** | Mailslot device | 2 | 2 | 4–6 d | a `docs/16` scope decision |
| **W10t** | `ntdll:sync` wedge triage | — | — | 1 d | — |
| **W9** | Whatever W9t convicts | up to 3 | ? | unknown | W9t |

**Recommended order:** `W0 → W1 → W2 → W3 → W4 → (W6t, W9t, W10t as one triage block) → W6 → W7 → W5 → W8 → W9`.

**Rationale for the order:**
- W0 before anything, because the map is stale and W0 may hand back 4 pairs for free.
- W1 before W2/W3 because both depend on the refusal split existing in one place; doing it per-dispatcher afterwards is the G10 shape.
- W2 first among the build items: 6 pairs, and it is `io/query.c`-flavoured info-class filling, which `docs/12` calls the best LLM task in the tree.
- The three triages batched *after* W4 and *before* W5/W6/W8: each is a day, each can collapse or explode its item, and knowing which lets the back half be re-planned on evidence rather than on this document.
- W5 late because it is the highest-variance item and touches `docs/12`'s top danger zone for 2 pairs.
- W8 last among buildable items: lowest leverage per day, and it needs a human scope decision first.

**Expected outcome if W0–W7 land:** roughly **17–20 of the ~26 currently-red pairs** go green, with the residue concentrated in W5, W8, W9, W10 and the §5 traps.

**Milestone completion duties** (`CLAUDE.md` "Workflow"): update the README Status line; re-derive `docs/16-syscall-status.md`'s partial-service table (it goes stale at every milestone — W2 and W3 will move several rows, and W8 moves `NtCreateMailslotFile` out of "no consumer"); confirm `make test` green.

---

## 7. Where I am explicitly unsure

- **Which Wine function performs the directory sort.** I read the *test's* requirement (`dlls/ntdll/tests/directory.c`, the `RtlCompareUnicodeString(prev, name, TRUE) < 0` assertion) and did not read the unix-side implementation. The test is sufficient authority for the pin; I did not want to name a function I had not opened.
- **Whether `kernel32:{sync,file,pipe}` and `ntdll:threadpool` were blocked on `FileCompletionInformation`.** The logs show `NtSetInformationFile` with the class not printed. It is the most probable class and the timing fits, but W0 is what settles it.
- **W9's shared-root-cause hypothesis.** Three logs showing three different image-load failures is a pattern, not a diagnosis.
- **`ntdll:sync`'s wedge.** I know it times out at 300 s with a child that ran zero tests. I do not know why, and I would not guess about `ke/wait`.
- **`kernel32:locale`.** I did not verify whether the required collation tables are present on the baked image, so I cannot say whether it is a provisioning fix or unreachable.

### Critical files for implementation

- `/home/user/proskrnl/kernel/io/query.c` — the file/volume info-class dispatchers; W1's split, W3c's `FileIdInformation`, and the existing `NOT_IMPLEMENTED` sites (141, 248, 627, 1027, 1258, 1296, 1336, 1372, 1406)
- `/home/user/proskrnl/kernel/ps/query.c` — thread/process/system query surface; W2's whole body, and W1's split at 489, 970, 1548, 1629, 1961, 2206
- `/home/user/proskrnl/kernel/io/ioctl.c` — W4a; `IopIoctlApcUnsupported` at line 18 and its refusal at line 38 are the exact code to delete, routing instead through `kernel/io/rw.c`'s `IopCompleteTransfer` / `IopQueueCompletionApc`
- `/home/user/proskrnl/tests/winetest/manifest.txt` — the gate's own definition of the frontier; unparks and exclusion causes land here
- `/home/user/proskrnl/docs/03-nt-deviations.md` — "M10 winetest notes"; W0's amendment, W4b's retired CUI-5 deviation, and every kernel commit's paired note