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

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* winternl.h omits these; declare them as wine/include/winternl.h does. */
NTSYSAPI NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtCreateJobObject(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtSetInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);

/* The Wine-private info class services.exe and every service process set at
 * startup (wine/include/winternl.h ProcessWineMakeProcessSystem = 1000; the
 * oracle run validates the value — a wrong one would answer
 * STATUS_INVALID_INFO_CLASS there). */
#define PS_ProcessWineMakeProcessSystem ((PROCESSINFOCLASS)1000)
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, const LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtYieldExecution(void);
NTSYSAPI NTSTATUS NTAPI NtTestAlert(void);
NTSYSAPI NTSTATUS NTAPI NtInitializeNlsFiles(void **, LCID *, LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtGetNlsSectionPtr(ULONG, ULONG, void *, void **, SIZE_T *);

/* NtGetNlsSectionPtr's section types, as wine/dlls/ntdll/locale_private.h
 * defines them (winternl.h omits the enum). */
enum nls_section_type
{
    NLS_SECTION_SORTKEYS = 9,
    NLS_SECTION_CASEMAP = 10,
    NLS_SECTION_CODEPAGE = 11,
    NLS_SECTION_NORMALIZE = 12
};

#define IOSB_POISON_STATUS ((NTSTATUS)0x0BADF00D)
static inline void poison_iosb(IO_STATUS_BLOCK *iosb)
{
    iosb->Status = IOSB_POISON_STATUS;
    iosb->Information = (ULONG_PTR)~0ULL;
}

#define PS_ProcessBasicInformation   ProcessBasicInformation
#define PS_SystemBasicInformation    SystemBasicInformation
#define PS_PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION
#define PS_SYSTEM_BASIC_INFORMATION  SYSTEM_BASIC_INFORMATION

#endif /* NTAPI_SEM_PS_UTIL_H */
