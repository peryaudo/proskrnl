# 16 — Syscall status (the boundary, measured)

A snapshot of the `Nt*` surface, id counts re-derived at **CUI-9**: every id
either has a kernel service, is in scope and unbuilt, or is missing by decision.
Alongside `docs/02` Net-1 (sockets, a new subsystem), the build plan on the
boundary is the **ten in-scope ids** below.

**The in/out-of-scope line was re-drawn against the oracle.** It used to be drawn
purely on "does a baked CUI consumer reach this id" (Art. 1). That test is still
what decides *when* an id gets built, but it is not what decides whether the id
is buildable at all: the second, independent question is whether the pinned Wine
tree implements the id **for real** on its unix side. Where it does, there is an
oracle to pin against (G5) and a known-good shape to reproduce; where Wine itself
answers with a FIXME stub — `STATUS_NOT_IMPLEMENTED`, or worse a fabricated
`STATUS_SUCCESS` — there is nothing to measure a proskrnl implementation
*against*, and G12 says an oracle answering `STATUS_NOT_IMPLEMENTED` is unbuilt,
not authoritative. Re-derived on that criterion, **ten of the previous 57 are in
scope**: Wine implements them, mostly straight through wineserver, so they are
unbuilt work rather than permanent exclusions. The other 47 stay out of scope —
in every one of those cases Wine is a stub too, so "out of scope" now rests on
two independent legs instead of one. None of the ten has a baked consumer today,
so none is urgent, and each still refuses loudly (`KI_SYSCALL_MISSING`) until it
is built.

The id tally moved by ONE after CUI-9, and how it went unnoticed is the reason
the re-derivation recipe below says never to trust the prose: `NtQueryLicenseValue`
was built for the winetest frontier (`docs/21` W12) and stayed listed as missing
under "no consumer in the baked stack" — a row whose premise the winetest gate had
already falsified. Otherwise CUI-8 and CUI-9 changed *how* built ids behave — async
parking, COW image masters — not *which* ids exist. What does move between
milestones is the partial-service list at the bottom, which is the part of this
document worth re-deriving most often.

**How to re-derive this (never trust the prose over the table):** the id space is the
pinned Wine tree's own 64-bit syscall table, generated into `kernel/syscall/table.inc`
by `tools/gen_syscalls.py` (Art. 4 — extracted, never retyped). Count `^KI_SYSCALL(0x`
vs. `^KI_SYSCALL_MISSING(0x` rows there — anchor the pattern and include the `0x`, or
the file's own header comment (which spells both macro names) inflates each count by
one. Find live callers by grepping the missing names
across `third_party/wine/dlls/*.c` and `programs/*.c`, excluding `ntdll/unix/` (the
unixlib we replaced), `signal_arm64ec.c` / `wow64/` (not x64 CUI paths), `.spec`
thunk tables, and `*/tests/`. Kernelbase/kernel32 `.spec` forwards count as callers
(`GetCurrentProcessorNumber` and `FlushProcessWriteBuffers` forward straight to
ntdll). This document goes stale at every milestone completion and every Wine pin
bump; re-run the count then.

## Headline numbers

| | count |
|---|---|
| Wine x64 syscall ids (pinned tree, `dlls/ntdll/ntsyscalls.h`) | **264** |
| Implemented (`KI_SYSCALL` rows) | **207** |
| Missing (`KI_SYSCALL_MISSING` → serial log + `STATUS_NOT_IMPLEMENTED`, G12) | **57** |
| …of the missing: permanently out of scope (below) | **47** |
| …of the missing: in scope, to be built (Wine implements them) | **10** |

**The WOW64 milestone closed four ids**, each because a gate consumer
depended on it and for no other reason: `NtCreateDebugObject`,
`NtDebugActiveProcess` and `NtRemoveProcessDebug` (ADR 0011's attach-only
amendment — the event queue stays refused), and `NtSetLdtEntries`, whose
per-process LDT was built because `STATUS_NOT_IMPLEMENTED` is never an
answer proskrnl may give and the winetest's sweep reaches it.

**CUI-7 closed its 29 ids** — the registry hive surface (`NtLoadKey`,
`NtLoadKey2`, `NtLoadKeyEx`, `NtUnloadKey`, `NtSaveKey`, `NtRestoreKey`,
`NtReplaceKey`, `NtRenameKey`, `NtNotifyChangeKey`,
`NtNotifyChangeMultipleKeys`, `NtSetInformationKey`,
`NtQueryMultipleValueKey`), the modern memory family
(`NtAllocateVirtualMemoryEx`, `NtCreateSectionEx`, `NtMapViewOfSectionEx`,
`NtUnmapViewOfSectionEx`, `NtFlushVirtualMemory`, `NtLockVirtualMemory`,
`NtUnlockVirtualMemory`, `NtGetWriteWatch`, `NtResetWriteWatch`,
`NtSetInformationVirtualMemory`) and the locale/system furniture
(`NtQueryDefaultUILanguage`, `NtQueryInstallUILanguage`,
`NtSetDefaultUILanguage`, `NtSetDefaultLocale`, `NtSetSystemTime`,
`NtSetSystemInformation`, `NtShutdownSystem`) — after CUI-6's 14 and CUI-5's
12 (`docs/02`; deviations in `docs/03` "CUI-7 Cm-2/Mm-2/system notes").

Sub-surface refusals that remain are decisions, recorded where they live:
placeholder MAPPING (`MEM_REPLACE_PLACEHOLDER` in `NtMapViewOfSectionEx`,
`MEM_PRESERVE_PLACEHOLDER` in `NtUnmapViewOfSectionEx`) refuses loudly inside
the implemented `*Ex` ids (no baked consumer; `docs/03`) — placeholder
ALLOCATION is built (`docs/21` W5) — and `NtSetSystemInformation` serves
exactly the one class the baked stack issues.

## The 57 missing syscalls by area

47 are decisions; 10 are unbuilt work. ★ = a live caller exists in the
currently-baked CUI userland (ntdll PE side, kernelbase, kernel32, advapi32)
— none of the 57 carries one on a real path, in scope or out.

**How to re-derive the in/out line:** for each `KI_SYSCALL_MISSING` name, find
its unix-side definition in the pinned tree
(`^NTSTATUS\s+WINAPI\s+<name>\s*\(` across `third_party/wine/dlls/ntdll/unix/*.c`)
and read the body. Three outcomes, and only the first is in scope:

1. **Real** — the body issues a `SERVER_START_REQ` (or genuinely delegates to an
   id we already implement). Wine can answer, so it is an oracle.
2. **Stub** — the body is a `FIXME(... "stub")` returning `STATUS_NOT_IMPLEMENTED`,
   or fabricating `STATUS_SUCCESS` / a fixed status over an untouched output
   buffer. Not an oracle either way (G12): a refusal is unbuilt, and a fabricated
   success is the exact failure mode G12 exists to forbid — pinning against it
   would be pinning a lie.
3. **No entry point at all** — the name is `SYSCALL_STUB(...)` in
   `dlls/ntdll/unix/syscall.c` (via `ALL_SYSCALL_STUBS`), which raises rather
   than dispatching. There is no Wine implementation to read.

A "semi-stub" — Wine's own FIXME wording for a body that does the real work but
ignores one argument — counts as case 1 for the part it implements, and the
ignored argument is named in the row.

### In scope, unbuilt — 10

Wine implements these for real, so each has an oracle to pin against (G5) before
a kernel service exists. **None has a baked consumer**, so none is scheduled;
Art. 1 still decides *when*, and until then each keeps its loud
`KI_SYSCALL_MISSING` row (G12). What changed is only the claim this document
makes about them: they are unbuilt, not excluded.

| id | Wine unix-side implementation | note |
|---|---|---|
| `NtWaitForDebugEvent` | `unix/sync.c` — `wait_debug_event` server request, full `DBGUI_WAIT_STATE_CHANGE` marshalling | debug event queue |
| `NtDebugContinue` | `unix/process.c` — `continue_debug_event` server request | debug event queue |
| `NtSetInformationDebugObject` | `unix/sync.c` — validates the class/length, then `set_debug_obj_info` | debug event queue |
| `NtCreateToken` | `unix/security.c` — marshals user/groups/privs/DACL into `create_token` | conflicts with CUI-2's one fixed identity; buildable, not wanted yet |
| `NtCreateMailslotFile` | `unix/file.c` — `create_mailslot` server request | needs a mailslot device; no baked consumer |
| `NtAllocateReserveObject` | `unix/server.c` — `allocate_reserve_object` server request | pairs with `NtQueueApcThreadEx2`'s reserve arm, itself a partial service below |
| `NtQueueApcThreadEx` | `unix/thread.c` — unpacks the flag bits folded into the reserve handle, then calls `NtQueueApcThreadEx2` | the delegate is already implemented; this is the legacy calling form over it |
| `NtAlpcCreatePort` | `unix/alpc.c` — validates port attributes, then `alpc_create_port` | the ONE ALPC id Wine implements; every other ALPC/LPC id is a stub, so a port that can be created and never used is of no use on its own |
| `NtOpenKeyTransacted` | `unix/registry.c` — forwards to `NtOpenKeyTransactedEx` | semi-stub: the transaction handle is ignored |
| `NtOpenKeyTransactedEx` | `unix/registry.c` — FIXME "semi-stub", then a real `NtOpenKeyEx` | semi-stub: the transaction handle is ignored, so the oracle's behaviour is plain `NtOpenKeyEx` |

Two of these rows cross a decision recorded elsewhere, and moving the row does
**not** overturn it — building them would need the ADR amended first, in its own
commit:

- The three debug-queue ids are ADR 0011's refused half (`docs/03` "Debug
  objects"). ADR 0011's argument is not "Wine can't do this" — it is that a
  queue makes every debuggee thread block until a debugger answers, i.e. a
  second stop/continue authority beside the dispatcher (Art. 11), for a
  consumer that does not exist. That argument is untouched by this
  re-derivation. What this table corrects is the *reason* the ids were filed
  under: they were listed as if unimplementable, when in fact they are
  implemented upstream and refused here by design.
- `NtCreateToken` mints an identity, and CUI-2 fixed proskrnl on exactly one.
  Wine implements it, so it is buildable; it is not wanted until something asks.

### Permanently out of scope — 47

Never implemented, and that is correct under Art. 1 (boundary only — no baked
consumer) and G12 (they refuse loudly forever, they don't fake success). **Every
one of the 47 is also a stub in the pinned Wine tree** — no oracle to pin
against, so the exclusion rests on two independent legs. The `wine` column
records which stub shape (case 2 or case 3 above), because the two fail
differently: a `STATUS_NOT_IMPLEMENTED` stub is honest, while a fabricating one
would silently pass a test written against it.

| group | count | ids | why | wine |
|---|---|---|---|---|
| LPC + ALPC | 19 | `NtAcceptConnectPort` `NtCompleteConnectPort` `NtConnectPort` `NtSecureConnectPort` `NtListenPort` `NtCreatePort` `NtImpersonateClientOfPort` `NtReplyPort` `NtReplyWaitReceivePort` `NtReplyWaitReceivePortEx` `NtRequestWaitReplyPort` `NtReadRequestData` `NtWriteRequestData` `NtRegisterThreadTerminatePort` `NtAlpcConnectPort` `NtAlpcAcceptConnectPort` `NtAlpcDisconnectPort` `NtAlpcSendWaitReceivePort` `NtAlpcImpersonateClientOfPort` | Wine's local RPC is named pipes over M9's npfs, never ALPC (`docs/03` "CUI-3 SCM notes") | all 19 are FIXME stubs returning `STATUS_NOT_IMPLEMENTED` (`unix/sync.c`, `unix/alpc.c`). `NtAlpcCreatePort` LEFT this row — Wine implements it, so it moved above |
| KTM + transacted registry | 4 | `NtCreateTransaction` `NtCommitTransaction` `NtRollbackTransaction` `NtCreateKeyTransacted` | ktmw32 is not baked; no CUI consumer | `NtCreateKeyTransacted` refuses; the other three **fabricate** (`unix/sync.c`: success plus a hardwired handle value `1`, success, and a bare `STATUS_ACCESS_VIOLATION`). The transacted *open* pair left this row — semi-stubs that do real work, above |
| Driver / platform machinery | 4 | `NtLoadDriver` `NtUnloadDriver` `NtCreatePagingFile` `NtMapUserPhysicalPagesScatter` | no Windows driver ABI, no paging (Art. 3), no AWE. `NtSetLdtEntries` LEFT this row at WOW64: `ntdll:wow64` sets two descriptors and reads them back, so the LDT is built (`kernel/ps/ldt.c`) | the two driver ids refuse (`unix/system.c`); `NtCreatePagingFile` fabricates success (`unix/virtual.c`); `NtMapUserPhysicalPagesScatter` has no entry point (`SYSCALL_STUB`) |
| Audit + token minting | 5 | `NtAccessCheckAndAuditAlarm` `NtAccessCheckByTypeAndAuditAlarm` `NtCloseObjectAuditAlarm` `NtCreateLowBoxToken` `NtCompareTokens` | one fixed identity (CUI-2), no audit subsystem, no AppContainer | the alarms and `NtCompareTokens` refuse (`unix/security.c`, `unix/server.c`); `NtCreateLowBoxToken` fabricates success over a NULL handle. `NtCreateToken` LEFT this row — Wine implements it, above |
| Superseded / legacy forms | 4 | `NtCreateProcessEx` `NtCreateThread` `NtWaitForMultipleObjects32` `NtWorkerFactoryWorkerReady` | Wine uses `NtCreateUserProcess`/`NtCreateThreadEx`/`NtQueueApcThreadEx2`; thread pool is user-mode in Wine | `NtCreateProcessEx` and `NtWaitForMultipleObjects32` have no entry point (`SYSCALL_STUB`); the other two refuse (`unix/thread.c`). `NtAllocateReserveObject` and `NtQueueApcThreadEx` LEFT this row — both implemented upstream, above |
| No consumer in the baked stack | 11 | `NtTraceEvent` `NtTraceControl` `NtSetIntervalProfile` `NtSystemDebugControl` `NtSetDebugFilterState` `NtQuerySystemEnvironmentValue` `NtQuerySystemEnvironmentValueEx` `NtApphelpCacheControl` `NtInitiatePowerAction` `NtAllocateUuids` `NtRaiseHardError` | ETW, profiling, kernel-debug control, UEFI variables, apphelp, slc, powrprof — none reachable from a baked CUI binary's real path | `NtTraceEvent` and `NtApphelpCacheControl` have no entry point (`SYSCALL_STUB`); the environment pair, `NtInitiatePowerAction` and `NtRaiseHardError` refuse; `NtTraceControl`, `NtSetIntervalProfile`, `NtSetDebugFilterState` fabricate success, `NtAllocateUuids` fabricates it over four untouched output buffers, and `NtSystemDebugControl` answers a fixed `STATUS_DEBUGGER_INACTIVE`. `NtCreateMailslotFile` LEFT this row — Wine implements it, above |

An id in either table still gets its loud `KI_SYSCALL_MISSING` row (G12) — "out
of scope" means we never *implement* it, and "in scope" means not yet; neither
ever fakes success. The `wine` column is also a standing reminder of why the
oracle leg matters: ten of the 47 answer a *fabricated* status — eight of them a
fabricated `STATUS_SUCCESS` — so a `tests/ntapi/` case written against Wine for
one of those would go green against nothing at all.

## Partial services (implemented ids that refuse the case real apps ask for)

These read as "implemented" in any id tally and are what an off-the-shelf CUI app
trips over *first*. Each refusal is loud (the dispatcher's `syscall PARTIAL` line,
`kernel/syscall/table.c`), and under the default-on
`KiPanicOnNotImplemented` arming (`docs/03` "Panic-on-STATUS_NOT_IMPLEMENTED
boot") a ring-3 caller reaching one panics rather than limps — so this list is
also the list of ways a new consumer can take the machine down loudly.

**How to re-derive this section:** a partial service is an implemented id that can
still return `STATUS_NOT_IMPLEMENTED` from some arm. Grep
`STATUS_NOT_IMPLEMENTED` across `kernel/`, `drivers/`, and `fs/`, drop the
dispatcher/arming machinery in `kernel/syscall/` and `kernel/init/main.c` and the
prose in comments, and map each remaining site to its enclosing service. Do not
grep for the id list instead — a partial id is `KI_SYSCALL`, indistinguishable
from a complete one in `table.inc`. **The table below is that derivation, run at
CUI-9; it goes stale the same way the id counts do.** Grouped by shape, not
ranked — blast radius depends on which consumer is baked next.

### Info-class switches with a refusing `default:`

The bulk of the partial surface: the class arms a baked consumer asks for are
built, the rest refuse.

| service | built arms | refusal site |
|---|---|---|
| `NtQuerySystemInformation` | 14: `SystemProcessInformation`, `SystemBasicInformation`, `SystemHandleInformation`, `SystemModuleInformation`, `SystemProcessorPerformanceInformation`, `SystemCpuInformation`, `SystemTimeAdjustmentInformation`, `SystemTimeOfDayInformation`, `SystemCurrentTimeZoneInformation`, `SystemDynamicTimeZoneInformation`, `SystemPerformanceInformation`, `SystemInterruptInformation`, `SystemFirmwareTableInformation`, `SystemWineVersionInformation` | `kernel/ps/query.c:1540` |
| `NtQuerySystemInformationEx` | 1: `SystemSupportedProcessorArchitectures` | `kernel/ps/query.c:1620` |
| `NtQueryInformationProcess` | 12 | `kernel/ps/query.c:484` |
| `NtQueryInformationThread` | — | `kernel/ps/thread.c:1416` |
| `NtSetInformationThread` | — | `kernel/ps/thread.c:1536` |
| `NtQueryInformationToken` | — | `kernel/se/token.c:1126` |
| `NtSetInformationToken` | — | `kernel/se/token.c:1575` |
| `NtQueryInformationJobObject` | — | `kernel/ps/job.c:675` |
| `NtSetInformationJobObject` | — | `kernel/ps/job.c:320` |
| `NtSetInformationObject` | 1: `ObjectHandleFlagInformation` | `kernel/ob/handle.c:452` |
| `NtQuerySection` | 2: `SectionBasicInformation`, `SectionImageInformation` | `kernel/mm/section.c:1283` |
| `NtQueryVirtualMemory` | 3: `MemoryBasicInformation`, `MemoryRegionInformation`, `MemoryImageInformation` | `kernel/mm/virtual.c:2605` |
| `NtPowerInformation` | 1: `ProcessorInformation` | `kernel/ps/query.c:1949` |
| `NtQueryInformationFile` | — | `kernel/io/query.c:141` |
| `NtSetInformationFile` | — | `kernel/io/query.c:596` |
| `NtQueryVolumeInformationFile` | — | `kernel/io/query.c:1342` |

Two narrower gaps sit *inside* an arm that counts as built:
`SystemFirmwareTableInformation` serves only the `RSMB` provider and one action,
and refuses outright when firmware published no SMBIOS (`kernel/ps/query.c:962`,
`:980`, `:986` — `docs/03` "`SystemFirmwareTableInformation` (76)");
`NtQueryInformationFile`'s `FileInternalInformation` refuses on a backing with no
file identity rather than inventing one (`kernel/io/query.c:248`).
`NtQueryVolumeInformationFile` additionally refuses per-class on handles with no
volume behind them — pipes and the console (`kernel/io/query.c:1194`, `:1232`,
`:1272`, `:1308`).

### Argument-shape gaps (the verb is built, one calling form is not)

- **`FileIoCompletionNotificationInformation` (class 41) — the verb and ONE
  of the three modes are built.** Both directions work
  (`kernel/io/query.c`): the word lives on the `FILE_OBJECT`, accumulates,
  masks unknown bits, and refuses a synchronous handle with
  `STATUS_INVALID_PARAMETER` — all measured
  (`tests/ntapi/sem_pipe/ioctl_event.c`).
  `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` is **honoured**
  (`IopCompleteTransfer`, pinned `tests/ntapi/sem_pipe/completion_packet.c`),
  and its axis is worth stating because the flag's NAME misleads: the packet
  is skipped when the call did **not return `STATUS_PENDING`**, not when it
  succeeded. The oracle's guards carry no status term at all
  (`server/fd.c` `add_fd_completion`'s `req->async ||`, `server/async.c`
  `async_set_result`'s `async->pending ||`). Keyed on `NT_SUCCESS` instead, an
  async port-bound handle would answer `STATUS_PENDING` and post nothing,
  hanging `GetQueuedCompletionStatus` forever.
  `FILE_SKIP_SET_EVENT_ON_HANDLE` is **honoured** too, since CUI-8's pended
  reads gave the file object's signalled state something to say: setting the
  bit clears the handle once and freezes it there for good (the guard lives
  inside the transition, `kernel/io/async.c` `IopFileSignalFrozen`, exactly
  where `server/fd.c` `set_fd_signaled` keeps it). Pinned by
  `tests/ntapi/sem_pipe/pended_read.c`; `ntdll:pipe` `pipe.c:1680-:1702` is
  the winetest consumer.
  Still **unbuilt**: `FILE_SKIP_SET_USER_EVENT_ON_FAST_IO` (accepted and
  inert, because there is no fast path to suppress — every completion goes
  through `IopCompleteRequest`; the oracle accepts it with a FIXME for the
  same reason).
- **User APCs on I/O — now a SPLIT row, and the line numbers it used to carry
  had drifted off their guards.** The completion-APC form is **built** for
  `NtDeviceIoControlFile`/`NtFsControlFile` (`kernel/io/ioctl.c`, pinned
  `tests/ntapi/sem_pipe/listen_apc.c`, docs/21 W4a) — including the pended
  case, where the block travels in the `IOP_PENDING_REQUEST` and is queued to
  the issuer at completion. It is also built on the scatter/gather and
  transfer paths (`IopCompleteTransfer`, pinned
  `tests/ntapi/sem_file/apc_completion.c`).
  It still **refuses** for the plain `NtReadFile`/`NtWriteFile` entry
  (`kernel/io/rw.c`, the `apc != 0 && UserMode` guard) and for
  `NtQueryDirectoryFile` (`kernel/io/query.c`), where no baked caller passes
  one — kernelbase sends NULL and uses the event/key legs. Unbuilt refuses
  loudly (Art. 12); the engine those two would use already exists
  (`IopPrepareCompletionApc`/`IopQueueCompletionApc`), so what is missing is
  the pin, not the plumbing.
- `NtLockFile` — a non-NULL apc, iosb, or key (`kernel/io/lock.c:158`);
  `NtUnlockFile` — the keyed form (`kernel/io/lock.c:227`).
- `NtSetTimer` — a timer APC routine; nothing on the CUI path arms one
  (`kernel/ob/sync.c:569`).
- `NtQueueApcThreadEx2` — a non-NULL reserve handle (`kernel/ps/thread.c:790`).
- `NtOpenProcess` — a named open, i.e. anything but the toolhelp path
  (`kernel/ps/process.c:1221`).
- `NtCreateUserProcess` — any process flag beyond inherit-handles / suspended /
  breakaway (`kernel/ps/process.c:1506`).
- `NtGetContextThread` / `NtSetContextThread` — a target with no ring-3 trap frame
  (`kernel/ps/usermode.c:751`).

### Mm flag gaps

What is left of the CUI-7 placeholder decisions after `docs/21` W5 built the
allocation half: `MEM_REPLACE_PLACEHOLDER` in `NtMapViewOfSectionEx`
(`kernel/mm/section.c`), `MEM_PRESERVE_PLACEHOLDER` in
`NtUnmapViewOfSectionEx` (`kernel/mm/section.c`). Mapping a section into a
placeholder is a larger contract than replacing one with private memory, and
no baked consumer reaches it; `NtAllocateVirtualMemoryEx`'s and
`NtFreeVirtualMemory`'s placeholder flags are no longer on this list.
`SEC_RESERVE` in `NtCreateSection`/`NtCreateSectionEx` left it too — it is
implemented (`docs/03` "A `SEC_RESERVE` section's commit ledger", pinned by
`tests/ntapi/sem_mm/reserve_section.c`).

### Refusing in full, by design

`NtCallbackReturn` (`kernel/ps/query.c:2194`) is an implemented id that refuses
every call. `PEB->KernelCallbackTable` is null, so it is unreachable; the refusal
exists so that if the unreachability argument ever breaks, the panic net says so
instead of a hardwired plausible status hiding it.

### Below the syscall line

Reachable through `NtDeviceIoControlFile`, and partial in the same sense: the
framebuffer's ioctl default (`drivers/fb.c:167`) and the HID pointer's
(`drivers/hid.c:194`). `PsPropagateConsoleCtrlEvent` serves only `CTRL_C_EVENT`
and `CTRL_BREAK_EVENT` (`kernel/ps/process.c:1128`), matching the delivery
wineserver's `propagate_console_signal` implements.

### The one inverted case — worth knowing about

`NtSetInformationProcess` (`kernel/ps/query.c` `NtSetInformationProcess`) is the
opposite shape. After six explicit classes
(`ProcessManageWritesToExecutableMemory`, `ProcessWineMakeProcessSystem`,
`ProcessThreadStackAllocation`, `ProcessPriorityBoost`,
`ProcessDefaultHardErrorMode`, `ProcessPriorityClass`)
its default **accepts as a
no-op** and returns `STATUS_SUCCESS`, naming the class on serial. That is
deliberate — the classes ntdll sets at startup have no observable effect here —
but it means this service never trips the `syscall PARTIAL` line or the armed
panic, so it reads as complete in any tally while being the one place a class
whose effect *does* matter could pass silently. The serial line is the entire
safety net; it is what caught `ProcessWineMakeProcessSystem` and the hard-error
mode, both of which then became real implementations. Treat an unexplained
`ps: NtSetInformationProcess class N accepted as a no-op` in a boot log as a
suspect, not noise.

It has now caught a third, and that one is worth naming because its cost was
invisible in a tally: `ProcessManageWritesToExecutableMemory` (83) is a
**capability probe**, not a setting. A caller reads its status to decide whether
it is on an ARM64EC host, so the no-op arm's `STATUS_SUCCESS` was an answer of
"yes" on an x86_64 machine. It is now an explicit `STATUS_NOT_SUPPORTED` — what
the pinned oracle answers off ARM64 — with the thread-side twin
`ThreadManageWritesToExecutableMemory` (48) beside it in `kernel/ps/thread.c`
(pinned by `tests/ntapi/sem_ps/manage_exec_writes.c`). **A no-op is only safe for
a class whose answer carries no information**; the moment the STATUS itself is
the value the caller wanted, accepting is fabricating.

It has caught a fourth, and it is the sharpest instance yet because the status
was never the value at all. `ProcessThreadStackAllocation` (41) is the one
kernel call `RtlCreateUserStack` makes, and its answer is a pointer it WRITES
into the caller's buffer — a buffer that is an uninitialised local in the
caller (`third_party/wine` `dlls/ntdll/thread.c`). The no-op arm returned
`STATUS_SUCCESS` over it, so ntdll committed a guard page and a stack at
whatever was in that stack slot, and `CreateFiberEx` ran fibers on it. It is
now a real reservation (`kernel/ps/query.c`, pinned by
`tests/ntapi/sem_ps/thread_stack_alloc.c`). So the rule above generalises one
step further: **a no-op is only safe for a class the caller reads NOTHING
back from** — not merely one whose status carries no information.
