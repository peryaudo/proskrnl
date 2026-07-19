/*
 * sem_ps/util.h — shared declarations for the Ps/Ke query tests (M7).
 *
 * Same two-mode arrangement as the other buckets: oracle mode leans on the
 * system headers (winternl.h already declares NtQueryInformationProcess /
 * NtQuerySystemInformation and the *_BASIC_INFORMATION structs) and declares
 * only the prototypes it omits; proskrnl mode gets everything from generated
 * abi/. The tests touch only fields present under both spellings
 * (UniqueProcessId, AllocationGranularity), since the ntapi proskrnl target is
 * a flat binary — the PE-only M7 surface (PEB/TEB, the KiUser* return
 * protocol) is exercised by the m7_smoke.exe boot module instead.
 */
#ifndef NTAPI_SEM_PS_UTIL_H
#define NTAPI_SEM_PS_UTIL_H

#include "../ntapi.h"

#if defined(NTAPI_ORACLE)

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* winternl.h omits these; declare them as wine/include/winternl.h does. */
NTSYSAPI NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, const LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtYieldExecution(void);
NTSYSAPI NTSTATUS NTAPI NtTestAlert(void);

#define PS_ProcessBasicInformation   ProcessBasicInformation
#define PS_SystemBasicInformation    SystemBasicInformation
#define PS_PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION
#define PS_SYSTEM_BASIC_INFORMATION  SYSTEM_BASIC_INFORMATION

#elif defined(NTAPI_PROSKRNL)
#include "abi/ntpsapi.h"

#define PS_ProcessBasicInformation   ProcessBasicInformation
#define PS_SystemBasicInformation    SystemBasicInformation
#define PS_PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION
#define PS_SYSTEM_BASIC_INFORMATION  SYSTEM_BASIC_INFORMATION
#endif

#endif /* NTAPI_SEM_PS_UTIL_H */
