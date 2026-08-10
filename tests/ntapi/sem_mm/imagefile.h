/*
 * sem_mm/imagefile.h — one way for an mm test to get a real PE of its own.
 *
 * Several section tests need a genuine, relocatable image file that the test
 * OWNS, so the assertion is about the section rules rather than about
 * contending with the loader's own mapping of a system DLL. Copying
 * ntdll.dll into the test's directory is that file; this header is the one
 * statement of how, so two tests cannot drift on the chunk size, the share
 * modes or the "did it actually copy anything" floor.
 *
 * Needs <windows.h> for CreateFileA/ReadFile/GetSystemDirectoryA, which is
 * why it is a separate header rather than a block in sem_file/util.h: the
 * sem_file bucket's tests do not all include the Win32 headers.
 */
#ifndef NTAPI_SEM_MM_IMAGEFILE_H
#define NTAPI_SEM_MM_IMAGEFILE_H

#include "../sem_file/util.h"

#include <windows.h>

/* Copy %SystemRoot%\system32\ntdll.dll to `dir`\`wide_name`, replacing any
 * leftover. Returns non-zero when a plausible image landed; asserts on the
 * way so a failure names itself rather than surfacing as a section error. */
static inline int copy_system_image(HANDLE dir, const void *wide_name)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    HANDLE source, copy = NULL;
    char path[MAX_PATH];
    static char buffer[0x10000];
    NTSTATUS status;
    DWORD moved;

    scrub_file(dir, wide_name);
    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    source = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(source != INVALID_HANDLE_VALUE, "cannot open %s", path);
    if (source == INVALID_HANDLE_VALUE)
        return 0;
    status = open_file(&copy, dir, wide_name, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create image copy -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        CloseHandle(source);
        return 0;
    }
    offset.QuadPart = 0;
    for (;;)
    {
        if (!ReadFile(source, buffer, sizeof(buffer), &moved, NULL) || moved == 0)
            break;
        status = NtWriteFile(copy, NULL, NULL, NULL, &iosb, buffer, moved, &offset, NULL);
        ok(status == STATUS_SUCCESS, "copy chunk -> %08lx", (unsigned long)status);
        if (!NT_SUCCESS(status))
            break;
        offset.QuadPart += moved;
    }
    ok(offset.QuadPart > 0x10000, "copied only %llx bytes", (unsigned long long)offset.QuadPart);
    CloseHandle(source);
    NtClose(copy);
    return offset.QuadPart > 0x10000;
}

#endif /* NTAPI_SEM_MM_IMAGEFILE_H */
