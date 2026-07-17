/*
 * sem_mm/util.h — shared helpers for the virtual-memory tests (M4).
 *
 * Same two-mode arrangement as sem_ob/util.h: oracle mode declares the Nt*
 * prototypes winternl.h omits (as Wine's own ntdll tests do) and leans on the
 * system headers for the MEM_ and PAGE_ flags and MEMORY_BASIC_INFORMATION;
 * proskrnl mode gets all of it from the generated abi/ntmmapi.h.
 */
#ifndef NTAPI_SEM_MM_UTIL_H
#define NTAPI_SEM_MM_UTIL_H

#include "../ntapi.h"

#if defined(NTAPI_ORACLE)

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);

/* MemoryBasicInformation; a plain ULONG keeps the declaration above
 * toolchain-independent (some winternl.h flavours lack the enum). */
#define MEMORY_BASIC_INFO_CLASS 0

/* mingw's winternl.h omits the pseudo-handle macro; as wine/include/winternl.h
 * defines it. */
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

#elif defined(NTAPI_PROSKRNL)
#include "abi/ntmmapi.h"

#define MEMORY_BASIC_INFO_CLASS MemoryBasicInformation
#endif

#endif /* NTAPI_SEM_MM_UTIL_H */
