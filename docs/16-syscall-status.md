# 16 — Syscall status (the boundary, measured)

A snapshot of the `Nt*` surface after **CUI-4**: what is implemented, what is missing,
what will never be built, and where the gaps that bite real software actually are. The
build plan that closes the closable part lives in `docs/02` (CUI-5…CUI-7, Net-1).

**How to re-derive this (never trust the prose over the table):** the id space is the
pinned Wine tree's own 64-bit syscall table, generated into `kernel/syscall/table.inc`
by `tools/gen_syscalls.py` (Art. 4 — extracted, never retyped). Count `KI_SYSCALL(`
vs. `KI_SYSCALL_MISSING(` rows there; find live callers by grepping the missing names
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
| Implemented (`KI_SYSCALL` rows) | **147** |
| Missing (`KI_SYSCALL_MISSING` → serial log + `STATUS_NOT_IMPLEMENTED`, G12) | **117** |
| …of the missing: permanently out of scope (below) | **62** |
| …of the missing: to be built (docs/02 CUI-5…CUI-7) | **55** |
| …of the missing: with a live caller in the baked x64 CUI DLL set | **~43** |
| End state once CUI-5…CUI-7 land | **202 / 264** |

The missing-id count **understates** the gap: a second dimension — implemented
services that refuse most of their info classes — bites real software harder than any
missing id. See "Partial services" at the bottom; those items ride the same CUI-5…7
milestones as the ids do.

## The 117 missing syscalls by area

★ = a live caller exists in the currently-baked CUI userland (ntdll PE side,
kernelbase, kernel32, advapi32), i.e. an off-the-shelf app can hit it today.

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

### To be built — 55 (the plan: docs/02 CUI-5…CUI-7)

**File / I/O — 12 → CUI-5**
★`NtNotifyChangeDirectoryFile` (`ReadDirectoryChangesW` — every file watcher and many
build tools) · ★`NtCancelSynchronousIoFile` · ★`NtReadFileScatter`
★`NtWriteFileGather` · `NtFlushBuffersFileEx` · `NtDeleteFile` · `NtQueryEaFile`
`NtSetEaFile` · `NtSetVolumeInformationFile` · ★`NtQueryDirectoryObject`
(kernelbase's volume enumeration) · `NtOpenIoCompletion` · `NtSetIoCompletionEx`

**Object manager / sync / process — 10 → CUI-6**
★`NtSetInformationObject` (**`SetHandleInformation`** — the stdio-redirect idiom) ·
★`NtCompareObjects` (`CompareObjectHandles`; ntdll's own self-handle checks) ·
★`NtSignalAndWaitForSingleObject` (`SignalObjectAndWait`) · ★`NtOpenTimer`
(`OpenWaitableTimer`) · `NtMakePermanentObject` · ★`NtQueueApcThreadEx2`
(`QueueUserAPC2`) · `NtAlertResumeThread` · ★`NtFlushProcessWriteBuffers` (kernel32/
kernelbase `.spec` forward) · ★`NtGetCurrentProcessorNumber` (`.spec` forward +
`ntdll/rtl.c`) · ★`NtSetThreadExecutionState`

**Security / tokens — 4 → CUI-6**
★`NtSetInformationToken` (`SetTokenInformation`) · ★`NtFilterToken`
(`CreateRestrictedToken`) · ★`NtAdjustGroupsToken` · ★`NtImpersonateAnonymousToken`

**Registry — 12 → CUI-7**
★`NtLoadKey` `NtLoadKey2` `NtLoadKeyEx` ★`NtUnloadKey` ★`NtSaveKey` `NtRestoreKey`
`NtReplaceKey` (`reg save/load`, hive attach) · ★`NtRenameKey` · ★`NtNotifyChangeKey`
`NtNotifyChangeMultipleKeys` (`RegNotifyChangeKeyValue` — services and settings
watchers block on it) · `NtSetInformationKey` · `NtQueryMultipleValueKey`

**Memory — 10 → CUI-7**
★`NtAllocateVirtualMemoryEx` ★`NtCreateSectionEx` ★`NtMapViewOfSectionEx`
★`NtUnmapViewOfSectionEx` (the modern `VirtualAlloc2`/`MapViewOfFile3`/
`CreateFileMapping2` family kernelbase routes through) · ★`NtFlushVirtualMemory`
(`FlushViewOfFile`) · ★`NtLockVirtualMemory` ★`NtUnlockVirtualMemory`
(`VirtualLock/Unlock`) · ★`NtGetWriteWatch` ★`NtResetWriteWatch` (write-watch heaps;
GC-style runtimes) · ★`NtSetInformationVirtualMemory` (`PrefetchVirtualMemory`)

**Locale / system — 7 → CUI-7**
★`NtQueryDefaultUILanguage` ★`NtQueryInstallUILanguage` (`ntdll/locale.c` +
kernelbase — `GetUserDefaultUILanguage`, MUI resource loading) ·
`NtSetDefaultUILanguage` · `NtSetDefaultLocale` · ★`NtSetSystemTime` ·
★`NtSetSystemInformation` · `NtShutdownSystem`

## Partial services (implemented ids that refuse the class real apps ask for)

These read as "implemented" in any id tally and are what an off-the-shelf CUI app
trips over *first*. Each refusal is loud (the dispatcher's `syscall PARTIAL` line,
`kernel/syscall/table.c`). Ranked roughly by blast radius:

- **`NtSetInformationFile`: no `FileRenameInformation(Ex)` / `FileLinkInformation`**
  — `MoveFile`/`ren`/`move` and every write-tmp-then-rename tool fail; rename does
  not exist anywhere in `kernel/`, `fs/`, or `drivers/`. The single largest hole on
  either list. → CUI-5.
- **`NtQueryObject`: no `ObjectHandleFlagInformation`** — `GetHandleInformation`
  fails (pairs with the missing `NtSetInformationObject` above). → CUI-6.
- **`NtQueryInformationProcess`** (9 classes today): no `ProcessTimes`
  (`GetProcessTimes`), `ProcessPriorityClass` (`Get/SetPriorityClass`),
  `ProcessHandleCount`, `ProcessImageFileName`. → CUI-6.
- **`NtQueryInformationThread`** (4 classes): no `ThreadTimes`, no
  `ThreadQuerySetWin32StartAddress`. → CUI-6.
- **`NtQuerySystemInformation`** (11 classes): no `SystemHandleInformation`,
  `SystemModuleInformation`, `SystemProcessorPerformanceInformation`. → CUI-6.
- **`NtQueryInformationFile`** (19 classes since GUI-5 built the query side of
  `FileEndOfFileInformation`, which ntdll's activation-context loader asks for):
  no `FileNetworkOpenInformation`,
  `FileAttributeTagInformation`, `FileStreamInformation`; `NtQueryDirectoryFile`
  lacks `FileIdBothDirectoryInformation`; volume queries lack
  `FileFsFullSizeInformation`. → CUI-5.
- **Jobs**: nesting refuses; most limit set/query classes refuse; per-job and
  per-process CPU/IO accounting reads back zero (`docs/03` "CUI-4 notes"). → CUI-6.
- **`NtGetContextThread`/`NtSetContextThread`: self only** — a foreign thread's
  context refuses. Stays wanted for the `SuspendThread`+`GetThreadContext`
  profiler/GC pattern (its debugger consumer is gone with debug objects). → CUI-6,
  slippable to CUI-7.
- **`NtOpenThread` by CLIENT_ID** refuses (only `NtOpenProcess` got the CUI-4
  treatment). → CUI-6.
- **Async I/O is one verb wide** — only `FSCTL_PIPE_LISTEN` pends
  (`docs/03` "CUI-3 SCM notes"); data transfers are synchronous. → CUI-5.
