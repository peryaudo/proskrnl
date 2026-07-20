/*
 * sem_pipe/util.h — shared helpers for the M9 named-pipe semantics tests.
 *
 * Same two-mode arrangement as sem_file/util.h: oracle mode declares the
 * pipe surface mingw's headers omit (prototypes as wine/include/winternl.h
 * spells them; FSCTL_PIPE_* / FILE_PIPE_* constants as wine/include/
 * winioctl.h and winternl.h define them — the oracle run itself validates
 * every value, since a wrong verb or mode would fail against the real
 * ntdll); proskrnl mode gets all of it from the generated abi/ntioapi.h.
 *
 * Pipe names live under \??\pipe\prstest_* so the buckets cannot collide
 * (the oracle's wineserver namespace is shared across one run).
 */
#ifndef NTAPI_SEM_PIPE_UTIL_H
#define NTAPI_SEM_PIPE_UTIL_H

#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

#include <string.h>   /* declarations only: the .exe links no CRT; ntapi.c defines them */
#include <winioctl.h> /* CTL_CODE, FILE_DEVICE_NAMED_PIPE */

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                              ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
                                              ULONG, ULONG, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                        ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* The named-pipe FSCTL verbs (wine/include/winioctl.h; mingw's winioctl.h
 * carries CTL_CODE + FILE_DEVICE_NAMED_PIPE but not the pipe verbs). */
#ifndef FSCTL_PIPE_DISCONNECT
#define FSCTL_PIPE_DISCONNECT CTL_CODE(FILE_DEVICE_NAMED_PIPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_PIPE_LISTEN
#define FSCTL_PIPE_LISTEN CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_PIPE_PEEK
#define FSCTL_PIPE_PEEK CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)
#endif
#ifndef FSCTL_PIPE_WAIT
#define FSCTL_PIPE_WAIT CTL_CODE(FILE_DEVICE_NAMED_PIPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* NtCreateNamedPipeFile options + pipe info shapes (wine/include/winternl.h
 * "options for NtCreateNamedPipeFile"; mingw's winternl.h has only
 * FILE_PIPE_LOCAL_INFORMATION). */
#ifndef FILE_PIPE_INBOUND
#define FILE_PIPE_INBOUND     0x00000000
#define FILE_PIPE_OUTBOUND    0x00000001
#define FILE_PIPE_FULL_DUPLEX 0x00000002
#endif
#ifndef FILE_PIPE_TYPE_MESSAGE
#define FILE_PIPE_TYPE_MESSAGE 0x00000001
#define FILE_PIPE_TYPE_BYTE    0x00000000
#endif
#ifndef FILE_PIPE_MESSAGE_MODE
#define FILE_PIPE_MESSAGE_MODE     0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE 0x00000000
#endif
#ifndef FILE_PIPE_COMPLETE_OPERATION
#define FILE_PIPE_COMPLETE_OPERATION 0x00000001
#define FILE_PIPE_QUEUE_OPERATION    0x00000000
#endif
#ifndef FILE_PIPE_SERVER_END
#define FILE_PIPE_SERVER_END 0x00000001
#define FILE_PIPE_CLIENT_END 0x00000000
#endif
#ifndef FILE_PIPE_DISCONNECTED_STATE
#define FILE_PIPE_DISCONNECTED_STATE 0x00000001
#define FILE_PIPE_LISTENING_STATE    0x00000002
#define FILE_PIPE_CONNECTED_STATE    0x00000003
#define FILE_PIPE_CLOSING_STATE      0x00000004
#endif

typedef struct
{
    ULONG ReadMode;
    ULONG CompletionMode;
} SEM_FILE_PIPE_INFORMATION;

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

#define IOSB_POISON_STATUS ((NTSTATUS)0x0BADF00D)
static inline void poison_iosb(IO_STATUS_BLOCK *iosb)
{
    iosb->Status = IOSB_POISON_STATUS;
    iosb->Information = (ULONG_PTR)~0ULL;
}

/* Create one server-end pipe instance with synchronous defaults: 4 KiB
 * quotas, default timeout, blocking (queue) completion. `type_and_mode`
 * applies FILE_PIPE_TYPE_* to the pipe and FILE_PIPE_*_MODE to this end's
 * read mode (0/1 values match, as Wine's CreateNamedPipeW passes them). */
static inline NTSTATUS create_pipe_instance(HANDLE *handle, const void *wide_name, ULONG sharing,
                                            ULONG type, ULONG read_mode, ULONG max_instances,
                                            IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb,
                                 sharing, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, type,
                                 read_mode, FILE_PIPE_QUEUE_OPERATION, max_instances, 4096, 4096,
                                 &timeout);
}

/* Open the client end with synchronous defaults. */
static inline NTSTATUS open_pipe_client(HANDLE *handle, const void *wide_name,
                                        IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* One buffer-less FSCTL verb (LISTEN/DISCONNECT). */
static inline NTSTATUS pipe_fsctl(HANDLE handle, ULONG code, IO_STATUS_BLOCK *iosb)
{
    return NtFsControlFile(handle, NULL, NULL, NULL, iosb, code, NULL, 0, NULL, 0);
}

/* Plain synchronous write/read at the pipe's current position. */
static inline NTSTATUS pipe_write(HANDLE handle, const void *data, ULONG length,
                                  IO_STATUS_BLOCK *iosb)
{
    return NtWriteFile(handle, NULL, NULL, NULL, iosb, data, length, NULL, NULL);
}

static inline NTSTATUS pipe_read(HANDLE handle, void *data, ULONG length, IO_STATUS_BLOCK *iosb)
{
    return NtReadFile(handle, NULL, NULL, NULL, iosb, data, length, NULL, NULL);
}

/* FilePipeLocalInformation snapshot (class 24 in both header sets). */
static inline NTSTATUS query_pipe_local(HANDLE handle, FILE_PIPE_LOCAL_INFORMATION *info)
{
    IO_STATUS_BLOCK iosb;
    memset(info, 0, sizeof(*info));
    return NtQueryInformationFile(handle, &iosb, info, sizeof(*info), FilePipeLocalInformation);
}

#endif /* NTAPI_SEM_PIPE_UTIL_H */
