# 16 — Syscall status (the boundary, measured)

A snapshot of the `Nt*` surface, id counts re-derived at **CUI-9**: the buildable
surface is **complete** — every id either has a kernel service or is missing by
decision, not debt. The one remaining build plan on the boundary is `docs/02` Net-1
(sockets, a new subsystem).

The id tally has not moved since CUI-7 (CUI-8 and CUI-9 changed *how* built ids
behave — async parking, COW image masters — not *which* ids exist). What does move
between milestones is the partial-service list at the bottom, which is the part of
this document worth re-deriving most often.

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
| Implemented (`KI_SYSCALL` rows) | **202** |
| Missing (`KI_SYSCALL_MISSING` → serial log + `STATUS_NOT_IMPLEMENTED`, G12) | **62** |
| …of the missing: permanently out of scope (below) | **62** |
| …of the missing: to be built | **0** |

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

## The 62 missing syscalls by area

Every one is a decision, not debt. ★ = a live caller exists in the
currently-baked CUI userland (ntdll PE side, kernelbase, kernel32, advapi32)
— none of the remaining ids carries one on a real path.

### Permanently out of scope — 62

Never implemented, and that is correct under Art. 1 (boundary only — no baked
consumer) and G12 (they refuse loudly forever, they don't fake success):

| group | count | ids | why |
|---|---|---|---|
| LPC + ALPC | 20 | `NtAcceptConnectPort` `NtCompleteConnectPort` `NtConnectPort` `NtSecureConnectPort` `NtListenPort` `NtCreatePort` `NtImpersonateClientOfPort` `NtReplyPort` `NtReplyWaitReceivePort` `NtReplyWaitReceivePortEx` `NtRequestWaitReplyPort` `NtReadRequestData` `NtWriteRequestData` `NtRegisterThreadTerminatePort` `NtAlpcCreatePort` `NtAlpcConnectPort` `NtAlpcAcceptConnectPort` `NtAlpcDisconnectPort` `NtAlpcSendWaitReceivePort` `NtAlpcImpersonateClientOfPort` | Wine's local RPC is named pipes over M9's npfs, never ALPC (`docs/03` "CUI-3 SCM notes") |
| Debug objects | 6 | `NtCreateDebugObject` `NtDebugActiveProcess` `NtDebugContinue` `NtRemoveProcessDebug` `NtWaitForDebugEvent` `NtSetInformationDebugObject` | ADR 0011: no baked consumer (a debugger is a tool, not an app), and native Windows debuggers expect PDB symbol flow where proskrnl's toolchain is DWARF end-to-end (`docs/03` "Debug objects") |
| KTM + transacted registry | 6 | `NtCreateTransaction` `NtCommitTransaction` `NtRollbackTransaction` `NtCreateKeyTransacted` `NtOpenKeyTransacted` `NtOpenKeyTransactedEx` | ktmw32 is not baked; no CUI consumer |
| Driver / platform machinery | 5 | `NtLoadDriver` `NtUnloadDriver` `NtSetLdtEntries` `NtCreatePagingFile` `NtMapUserPhysicalPagesScatter` | no Windows driver ABI, x64-only (no LDT), no paging (Art. 3), no AWE |
| Audit + token minting | 6 | `NtAccessCheckAndAuditAlarm` `NtAccessCheckByTypeAndAuditAlarm` `NtCloseObjectAuditAlarm` `NtCreateToken` `NtCreateLowBoxToken` `NtCompareTokens` | one fixed identity (CUI-2), no audit subsystem, no AppContainer |
| Superseded / legacy forms | 6 | `NtCreateProcessEx` `NtCreateThread` `NtWaitForMultipleObjects32` `NtWorkerFactoryWorkerReady` `NtAllocateReserveObject` `NtQueueApcThreadEx` | Wine uses `NtCreateUserProcess`/`NtCreateThreadEx`/`NtQueueApcThreadEx2`; thread pool is user-mode in Wine |
| No consumer in the baked stack | 13 | `NtTraceEvent` `NtTraceControl` `NtSetIntervalProfile` `NtSystemDebugControl` `NtSetDebugFilterState` `NtQuerySystemEnvironmentValue` `NtQuerySystemEnvironmentValueEx` `NtApphelpCacheControl` `NtQueryLicenseValue` `NtInitiatePowerAction` `NtCreateMailslotFile` `NtAllocateUuids` `NtRaiseHardError` | ETW, profiling, kernel-debug control, UEFI variables, apphelp, slc, powrprof, mailslots — none reachable from a baked CUI binary's real path |

An id in this table still gets its loud `KI_SYSCALL_MISSING` row (G12) — "out of
scope" means we never *implement* it, not that it ever fakes success.

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
  (`server/fd.c` `set_fd_completion`'s `req->async ||`, `server/async.c`
  `async_terminate`'s `async->pending ||`). Keyed on `NT_SUCCESS` instead, an
  async port-bound handle would answer `STATUS_PENDING` and post nothing,
  hanging `GetQueuedCompletionStatus` forever.
  Still **unbuilt**: `FILE_SKIP_SET_EVENT_ON_HANDLE` (stored, reported, does
  nothing) and `FILE_SKIP_SET_USER_EVENT_ON_FAST_IO` (accepted and inert,
  because there is no fast path to suppress — every completion goes through
  `IopCompleteRequest`; the oracle accepts it with a FIXME for the same
  reason).
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
allocation half: `SEC_RESERVE` in `NtCreateSection`/`NtCreateSectionEx`
(`kernel/mm/section.c`), `MEM_REPLACE_PLACEHOLDER` in `NtMapViewOfSectionEx`
(`kernel/mm/section.c`), `MEM_PRESERVE_PLACEHOLDER` in
`NtUnmapViewOfSectionEx` (`kernel/mm/section.c`). Mapping a section into a
placeholder is a larger contract than replacing one with private memory, and
no baked consumer reaches it; `NtAllocateVirtualMemoryEx`'s and
`NtFreeVirtualMemory`'s placeholder flags are no longer on this list.

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

`NtSetInformationProcess` (`kernel/ps/query.c:621`) is the opposite shape. After
three explicit classes (`ProcessWineMakeProcessSystem`,
`ProcessDefaultHardErrorMode`, `ProcessPriorityClass`) its default **accepts as a
no-op** and returns `STATUS_SUCCESS`, naming the class on serial. That is
deliberate — the classes ntdll sets at startup have no observable effect here —
but it means this service never trips the `syscall PARTIAL` line or the armed
panic, so it reads as complete in any tally while being the one place a class
whose effect *does* matter could pass silently. The serial line is the entire
safety net; it is what caught `ProcessWineMakeProcessSystem` and the hard-error
mode, both of which then became real implementations. Treat an unexplained
`ps: NtSetInformationProcess class N accepted as a no-op` in a boot log as a
suspect, not noise.
