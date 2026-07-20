/*
 * sem_mm/util.h — shared helpers for the virtual-memory tests (M4–M5).
 *
 * Same arrangement as sem_ob/util.h: declares the Nt* prototypes winternl.h
 * omits (as Wine's own ntdll tests do) and leans on the system headers for
 * the MEM_/PAGE_/SEC_ flags and the info structs.
 */
#ifndef NTAPI_SEM_MM_UTIL_H
#define NTAPI_SEM_MM_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* The M5 section surface (prototypes as wine/include/winternl.h; mingw's
 * winternl.h omits them). SECTION_INHERIT stays a plain ULONG so the
 * declaration is toolchain-independent. */
NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI NtQuerySection(HANDLE, ULONG, PVOID, SIZE_T, SIZE_T *);

/* MemoryBasicInformation; a plain ULONG keeps the declaration above
 * toolchain-independent (some winternl.h flavours lack the enum). */
#define MEMORY_BASIC_INFO_CLASS 0

/* SECTION_INFORMATION_CLASS values, as wine/include/winternl.h. */
#define SECTION_BASIC_INFO_CLASS 0
#define SECTION_IMAGE_INFO_CLASS 1

/* SECTION_INHERIT values, as wine/include/winternl.h. */
#ifndef ViewShare
#define ViewShare 1
#define ViewUnmap 2
#endif

/* mingw's winternl.h omits the pseudo-handle macro; as wine/include/winternl.h
 * defines it. */
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* The tests fill these with snake_case fields and pass them to NtQuerySection;
 * the layout matches SECTION_BASIC_INFORMATION byte-for-byte. */
typedef struct
{
    PVOID base_address;
    ULONG attributes;
    LARGE_INTEGER size;
} mm_section_basic_info;

/* Fill a UNICODE_STRING over a NUL-terminated 2-byte-unit string. (inline:
 * not every test in this bucket names objects.) */
static inline void init_ustr(UNICODE_STRING *str, const void *wide)
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
static inline void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name,
                             ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

#endif /* NTAPI_SEM_MM_UTIL_H */
