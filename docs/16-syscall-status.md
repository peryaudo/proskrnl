# 16 — Syscall status (the boundary, measured)

A snapshot of the `Nt*` surface after **CUI-7**: the buildable surface is **complete**
— every id either has a kernel service or is missing by decision, not debt. The one
remaining build plan on the boundary is `docs/02` Net-1 (sockets, a new subsystem).

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
placeholder allocation (`MEM_RESERVE/REPLACE/PRESERVE_PLACEHOLDER`) refuses
loudly inside the implemented `*Ex` ids (no baked consumer; `docs/03`), and
`NtSetSystemInformation` serves exactly the one class the baked stack issues.

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

## Partial services (implemented ids that refuse the class real apps ask for)

These read as "implemented" in any id tally and are what an off-the-shelf CUI app
trips over *first*. Each refusal is loud (the dispatcher's `syscall PARTIAL` line,
`kernel/syscall/table.c`). Ranked roughly by blast radius:

*(CUI-7 closed the `SystemTimeAdjustmentInformation` set/query pair and the
`NtQueryVirtualMemory`-adjacent `*Ex` surface; CUI-6 closed the
process/thread/handle query gaps: `NtQueryObject`'s
`ObjectHandleFlagInformation`; `NtQueryInformationProcess`'s `ProcessTimes`/
`ProcessPriorityClass`/`ProcessHandleCount`/`ProcessImageFileName`;
`NtQueryInformationThread`'s `ThreadTimes`/`ThreadQuerySetWin32StartAddress`;
`NtQuerySystemInformation`'s `SystemHandleInformation`/`SystemModuleInformation`/
`SystemProcessorPerformanceInformation`; jobs finished with nesting + real
accounting; foreign `NtGet/SetContextThread` and `NtOpenThread` by CLIENT_ID.
See docs/03 "CUI-6 handles/identity notes".)*

- **Async I/O is two verbs wide** — `FSCTL_PIPE_LISTEN` (`docs/03` "CUI-3
  SCM notes") and CUI-5's directory watches pend; data transfers stay
  synchronous, and no consumer has convicted a wider surface
  (`FileCompletionInformation` port association stays unbuilt — `docs/03`
  "CUI-5 Io-completion notes").
