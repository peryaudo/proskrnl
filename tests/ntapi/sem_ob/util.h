/*
 * sem_ob/util.h — shared helpers for the M3 object-manager tests.
 *
 * Wide literals are u"..." (char16_t): 2 bytes per unit in both build modes,
 * where L"..." would be 4 bytes under a Linux-hosted proskrnl build.
 * UNICODE_STRING/OBJECT_ATTRIBUTES are filled by hand so the tests do not
 * depend on which init helpers each mode's headers happen to declare.
 */
#ifndef NTAPI_SEM_OB_UTIL_H
#define NTAPI_SEM_OB_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

#if defined(NTAPI_ORACLE)
/* Prototypes winternl.h omits (declared as Wine's own ntdll tests do). In
 * proskrnl mode these come from abi/ntobapi.h instead. */
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtMakeTemporaryObject(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtOpenEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtResetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtClearEvent(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtPulseEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtQueryEvent(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtOpenMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtReleaseMutant(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtQueryMutant(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
NTSYSAPI NTSTATUS NTAPI NtOpenSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtReleaseSemaphore(HANDLE, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtQuerySemaphore(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, const HANDLE *, ULONG, BOOLEAN,
                                                 PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtCreateSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                                   PUNICODE_STRING);
NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);

/* winternl.h omits WAIT_TYPE (it lives in the WDK's ntdef.h); declared as
 * Wine's ntdef.h defines it. */
#ifndef __WAIT_TYPE_DECLARED
#define __WAIT_TYPE_DECLARED
typedef enum _WAIT_TYPE
{
    WaitAll,
    WaitAny
} WAIT_TYPE;
#endif

/* Info-class values (winternl.h defines the enums on some toolchains but not
 * all; plain ULONGs keep the declarations above toolchain-independent). */
#define EVENT_BASIC_INFO_CLASS     0 /* EventBasicInformation */
#define MUTANT_BASIC_INFO_CLASS    0 /* MutantBasicInformation */
#define SEMAPHORE_BASIC_INFO_CLASS 0 /* SemaphoreBasicInformation */

/* mingw's winternl.h omits the pseudo-handle macro; as wine/include/winternl.h
 * defines it. */
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* mingw's user-mode headers omit a few object rights; values as in
 * wine/include/winnt.h. */
#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif
#ifndef EVENT_MODIFY_STATE
#define EVENT_MODIFY_STATE 0x0002
#endif
#ifndef SEMAPHORE_QUERY_STATE
#define SEMAPHORE_QUERY_STATE 0x0001
#endif

/* mingw's winnt.h has DUPLICATE_SAME_ACCESS/CLOSE_SOURCE but not this one;
 * value as in wine/include/winnt.h. */
#ifndef DUPLICATE_SAME_ATTRIBUTES
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004
#endif

/* mingw's winternl.h has no directory/symlink rights (they live in the
 * WDK's wdm.h); values as in wine/include/ddk/wdm.h. */
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef DIRECTORY_TRAVERSE
#define DIRECTORY_TRAVERSE 0x0002
#endif
#ifndef DIRECTORY_CREATE_OBJECT
#define DIRECTORY_CREATE_OBJECT 0x0004
#endif
#ifndef DIRECTORY_ALL_ACCESS
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif
#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

#elif defined(NTAPI_PROSKRNL)
#include "abi/ntobapi.h"

#define EVENT_BASIC_INFO_CLASS     EventBasicInformation
#define MUTANT_BASIC_INFO_CLASS    MutantBasicInformation
#define SEMAPHORE_BASIC_INFO_CLASS SemaphoreBasicInformation
#endif

/* The tests fill these with snake_case fields and pass them to NtQuery*; the
 * layout matches the generated abi/ntobapi.h structs byte-for-byte (the size
 * the info-class length checks demand), so one definition serves both modes.
 * A static_assert in proskrnl mode keeps that agreement honest. */
typedef struct
{
    LONG event_type; /* EVENT_TYPE */
    LONG event_state;
} ob_event_basic_info;

typedef struct
{
    LONG current_count;
    BOOLEAN owned_by_caller;
    BOOLEAN abandoned_state;
} ob_mutant_basic_info;

typedef struct
{
    ULONG current_count;
    ULONG maximum_count;
} ob_semaphore_basic_info;

#if defined(NTAPI_PROSKRNL)
_Static_assert(sizeof(ob_event_basic_info) == sizeof(EVENT_BASIC_INFORMATION),
               "ob_event_basic_info must match the abi layout");
_Static_assert(sizeof(ob_semaphore_basic_info) == sizeof(SEMAPHORE_BASIC_INFORMATION),
               "ob_semaphore_basic_info must match the abi layout");
#endif

/* Fill a UNICODE_STRING over a NUL-terminated 2-byte-unit string. */
static void init_ustr(UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    str->Length = (USHORT)(len * 2);
    str->MaximumLength = (USHORT)(len * 2 + 2);
    str->Buffer = (PWSTR)(void *)p;
}

/* Fill OBJECT_ATTRIBUTES; ntdll conventionally passes OBJ_CASE_INSENSITIVE. */
static void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name, ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

/* Wait with a zero timeout: STATUS_SUCCESS if signalled now, else
 * STATUS_TIMEOUT. Never blocks; a notification event is not consumed. */
static NTSTATUS wait_now(HANDLE handle)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(handle, FALSE, &zero);
}

#endif /* NTAPI_SEM_OB_UTIL_H */
