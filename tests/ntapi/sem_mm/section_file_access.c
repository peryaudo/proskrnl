/*
 * sem_mm/section_file_access.c — what NtCreateSection demands of the FILE
 * handle it is given.
 *
 * The rule is a mapping from the requested PAGE protection to a required
 * file access, and it lives in the pinned oracle's NtCreateSection
 * (third_party/wine dlls/ntdll/unix/sync.c), whose switch is:
 *
 *   PAGE_READONLY / PAGE_EXECUTE_READ /
 *   PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY   -> FILE_READ_DATA
 *   PAGE_READWRITE / PAGE_EXECUTE_READWRITE   -> FILE_READ_DATA | FILE_WRITE_DATA
 *                                                (FILE_READ_DATA alone under SEC_IMAGE)
 *   PAGE_EXECUTE / PAGE_NOACCESS              -> 0
 *   anything else                             -> STATUS_INVALID_PAGE_PROTECTION
 *
 * The handle is then referenced WITH that access, so a handle that does not
 * carry it fails STATUS_ACCESS_DENIED before the section exists.
 *
 * kernel32:virtual convicts this three times over with a file opened for NO
 * access at all (virtual.c:758/:764/:770) and once with a read-only file
 * asked for PAGE_READWRITE (:4074). This case pins the whole mapping rather
 * than those four points, because the interesting part is WHICH protections
 * demand write — a matrix an implementation can get plausibly wrong in one
 * cell and pass everything else.
 */
#include "../sem_file/util.h"

#include <windows.h>

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

static const void *file_name = W("prsk_secaccess.bin");

/* Try to build a data section over `file` with `protect`, and report the
 * status. SEC_COMMIT so nothing image-shaped interferes. */
static NTSTATUS try_section(HANDLE file, ULONG protect, ULONG secFlags)
{
    LARGE_INTEGER size;
    HANDLE section = NULL;
    NTSTATUS status;

    size.QuadPart = 4096;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &size, protect, secFlags, file);
    if (NT_SUCCESS(status))
        NtClose(section);
    return status;
}

START_TEST(section_file_access)
{
    IO_STATUS_BLOCK iosb;
    HANDLE dir, writable, readable, noAccess;
    NTSTATUS status;

    dir = open_test_dir(W("\\??\\C:\\prstest\\secaccess"));
    if (!dir)
        return;
    scrub_file(dir, file_name);

    /* A real file with content, opened three ways. */
    status = open_file(&writable, dir, file_name, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create writable -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    {
        char buf[4096];
        memset(buf, 'x', sizeof(buf));
        status = NtWriteFile(writable, NULL, NULL, NULL, &iosb, buf, sizeof(buf), NULL, NULL);
        ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    }

    status = open_file(&readable, dir, file_name, GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open read-only -> %08lx", (unsigned long)status);

    /* EXACTLY the handle CreateFileA(name, 0, 0, ...) produces — the one
     * kernel32:virtual:758 uses. kernelbase does not pass the caller's zero
     * through: it asks for `access | SYNCHRONIZE | FILE_READ_ATTRIBUTES`
     * (dlls/kernelbase/file.c CreateFileW), and the share mode is 0.
     * Spelled out rather than approximated — see the note on the assertions
     * below. */
    status = open_file(&noAccess, dir, file_name, SYNCHRONIZE | FILE_READ_ATTRIBUTES, 0, FILE_OPEN,
                       0, &iosb);
    ok(status == STATUS_SUCCESS, "open no-access -> %08lx", (unsigned long)status);

    /* --- a handle carrying READ and WRITE serves every protection ------- */
    ok(try_section(writable, PAGE_READONLY, SEC_COMMIT) == STATUS_SUCCESS, "rw handle, READONLY");
    ok(try_section(writable, PAGE_READWRITE, SEC_COMMIT) == STATUS_SUCCESS, "rw handle, READWRITE");
    ok(try_section(writable, PAGE_WRITECOPY, SEC_COMMIT) == STATUS_SUCCESS, "rw handle, WRITECOPY");

    /* --- a READ-ONLY handle serves the read protections and refuses the
     * write ones. This is the :4074 cell, and the one that says the rule is
     * about the PROTECTION rather than about "can this file be mapped". */
    status = try_section(readable, PAGE_READONLY, SEC_COMMIT);
    ok(status == STATUS_SUCCESS, "ro handle, READONLY -> %08lx", (unsigned long)status);
    status = try_section(readable, PAGE_WRITECOPY, SEC_COMMIT);
    ok(status == STATUS_SUCCESS, "ro handle, WRITECOPY -> %08lx", (unsigned long)status);
    status = try_section(readable, PAGE_READWRITE, SEC_COMMIT);
    ok(status == STATUS_ACCESS_DENIED, "ro handle, READWRITE -> %08lx", (unsigned long)status);
    status = try_section(readable, PAGE_EXECUTE_READWRITE, SEC_COMMIT);
    ok(status == STATUS_ACCESS_DENIED, "ro handle, EXECUTE_READWRITE -> %08lx",
       (unsigned long)status);

    /* --- a NO-ACCESS handle refuses even the read protections. This is the
     * :758/:764/:770 cluster: three protections, one missing right. */
    status = try_section(noAccess, PAGE_READONLY, SEC_COMMIT);
    ok(status == STATUS_ACCESS_DENIED, "no-access handle, READONLY -> %08lx",
       (unsigned long)status);
    status = try_section(noAccess, PAGE_WRITECOPY, SEC_COMMIT);
    ok(status == STATUS_ACCESS_DENIED, "no-access handle, WRITECOPY -> %08lx",
       (unsigned long)status);
    status = try_section(noAccess, PAGE_READWRITE, SEC_COMMIT);
    ok(status == STATUS_ACCESS_DENIED, "no-access handle, READWRITE -> %08lx",
       (unsigned long)status);

    /* --- ...and serves the two that demand NOTHING. The header's third row
     * (`PAGE_EXECUTE` / `PAGE_NOACCESS` -> 0) was documented here and never
     * asserted, which made the whole "read always" reading of the switch
     * look pinned when only two of its three rows were. An empty required
     * mask is satisfied by a handle carrying no data right at all. */
    status = try_section(noAccess, PAGE_EXECUTE, SEC_COMMIT);
    ok(status == STATUS_SUCCESS, "no-access handle, EXECUTE -> %08lx", (unsigned long)status);
    status = try_section(noAccess, PAGE_NOACCESS, SEC_COMMIT);
    ok(status == STATUS_SUCCESS, "no-access handle, NOACCESS -> %08lx", (unsigned long)status);

    NtClose(noAccess);
    NtClose(readable);
    NtClose(writable);
    scrub_file(dir, file_name);
    NtClose(dir);
}
