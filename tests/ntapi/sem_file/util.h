/*
 * sem_file/util.h — shared helpers for the M6 file-semantics tests.
 *
 * Same two-mode arrangement as sem_mm/util.h: oracle mode declares the Nt*
 * prototypes mingw's winternl.h omits (as Wine's own ntdll tests do) and
 * leans on the system headers for the FILE_* flags and info structs;
 * proskrnl mode gets all of it from the generated abi/ntioapi.h.
 *
 * Paths: every test works under \??\C:\prstest — on the oracle that is the
 * Wine prefix's writable drive_c, on proskrnl it is the FAT32 boot volume.
 * Each test uses its own subdirectory so the buckets cannot collide.
 */
#ifndef NTAPI_SEM_FILE_UTIL_H
#define NTAPI_SEM_FILE_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

#include <string.h> /* declarations only: the .exe links no CRT; ntapi.c defines them */

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                             PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS,
                                             BOOLEAN, PUNICODE_STRING, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtQueryAttributesFile(const OBJECT_ATTRIBUTES *, FILE_BASIC_INFORMATION *);
NTSYSAPI NTSTATUS NTAPI NtFlushBuffersFile(HANDLE, IO_STATUS_BLOCK *);
NTSYSAPI NTSTATUS NTAPI NtLockFile(HANDLE, HANDLE, PIO_APC_ROUTINE, void *, PIO_STATUS_BLOCK,
                                   PLARGE_INTEGER, PLARGE_INTEGER, ULONG *, BOOLEAN, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtUnlockFile(HANDLE, PIO_STATUS_BLOCK, PLARGE_INTEGER, PLARGE_INTEGER,
                                     ULONG *);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* mingw's winternl.h omits the info-class enumerators for directory queries
 * past FileBothDirectoryInformation as named constants usable here; the enum
 * itself is positional and complete, so nothing extra is needed. It also
 * omits FILE_NAMES_INFORMATION / FILE_DIRECTORY_INFORMATION on some
 * versions; both were checked present in the pinned mingw-w64 header. */

/* Fill a UNICODE_STRING over a NUL-terminated 2-byte-unit string. */
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

/* A poison IOSB: the tests assert whether a call wrote it or left it alone.
 * Both header sets (mingw's winternl.h and the generated abi/ntioapi.h)
 * define the Status/Pointer union anonymously, so .Status works directly. */
#define IOSB_POISON_STATUS ((NTSTATUS)0x0BADF00D)
static inline void poison_iosb(IO_STATUS_BLOCK *iosb)
{
    iosb->Status = IOSB_POISON_STATUS;
    iosb->Information = (ULONG_PTR)~0ULL;
}

/* Open (FILE_OPEN_IF) the shared test root \??\C:\prstest and a per-test
 * subdirectory under it; returns a handle to the subdirectory (synchronous,
 * list+traverse access) or NULL, asserting on the way. */
static inline HANDLE open_test_dir(const void *wide_subdir_path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = NULL;
    NTSTATUS status;

    init_ustr(&name, W("\\??\\C:\\prstest"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateFile(
        &dir,
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "create \\??\\C:\\prstest -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return NULL;
    NtClose(dir);

    init_ustr(&name, wide_subdir_path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    dir = NULL;
    status = NtCreateFile(
        &dir,
        FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "create test dir -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? dir : NULL;
}

/* Create/open one file with the usual synchronous defaults. */
static inline NTSTATUS open_file(HANDLE *handle, HANDLE root, const void *wide_name,
                                 ACCESS_MASK access, ULONG share, ULONG disposition, ULONG options,
                                 IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wide_name);
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, share,
                        disposition, options | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* Delete a leftover file by name so reruns start clean (oracle runs reuse
 * the prefix; proskrnl runs get a fresh image, where this is a no-op).
 *
 * A READ-ONLY leftover is cleared first, or it never goes: FILE_DELETE_ON_CLOSE
 * against one is STATUS_CANNOT_DELETE — what delete_on_close.c pins — so
 * without this a case that marks a file read-only strands it, and every later
 * run in that prefix fails on the leftover instead of on the boundary.
 *
 * The clearing open asks for SYNCHRONIZE and NOTHING ELSE, which is
 * SetFileAttributesW's own mask and the one readonly_attr.c §5 pins as working
 * on a read-only file. A wider mask is what fails: the oracle maps
 * FILE_ATTRIBUTE_READONLY onto unix mode 0444 (server/file.c:254) and the SD it
 * generates from that mode grants the owner no FILE_GENERIC_WRITE
 * (mode_to_sd, server/file.c:362), so even a FILE_WRITE_ATTRIBUTES-only open is
 * refused — measured c0000022. FileBasicInformation itself checks nothing
 * (dlls/ntdll/unix/file.c:5211 fetches the fd with access mask 0). */
static inline void scrub_file(HANDLE root, const void *wide_name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = open_file(&handle, root, wide_name, DELETE | SYNCHRONIZE, 0, FILE_OPEN,
                                FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE, &iosb);
    if (status == STATUS_CANNOT_DELETE)
    {
        FILE_BASIC_INFORMATION basic;

        status = open_file(&handle, root, wide_name, SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                           FILE_NON_DIRECTORY_FILE, &iosb);
        if (!NT_SUCCESS(status))
            return;
        memset(&basic, 0, sizeof(basic));
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        NtSetInformationFile(handle, &iosb, &basic, sizeof(basic), FileBasicInformation);
        NtClose(handle);
        status = open_file(&handle, root, wide_name, DELETE | SYNCHRONIZE, 0, FILE_OPEN,
                           FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE, &iosb);
    }
    if (NT_SUCCESS(status))
        NtClose(handle);
}

#endif /* NTAPI_SEM_FILE_UTIL_H */
