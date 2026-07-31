/*
 * sem_mm/section_protect.c — what a file-backed section may be mapped as.
 *
 * A SHARED writable view of a file-backed section writes the file's page
 * cache, and with immediate writeback (Art. 3) that IS a write to the file.
 * proskrnl checked the backing handle's access when the SECTION was created
 * and never again, so opening a file FILE_READ_DATA, creating a section over
 * it, and mapping the section PAGE_READWRITE wrote a file the caller could
 * not write.
 *
 * The gate is the FILE HANDLE's access, not the section's creation
 * protection — which is what the oracle says, and worth pinning explicitly
 * because it is easy to assume the opposite: a PAGE_READONLY section over a
 * read-write handle maps PAGE_READWRITE quite happily.
 */
#include "../sem_file/util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

#define SECTION_VIEW_SHARE 2 /* ViewShare */

static NTSTATUS map_view(HANDLE section, ULONG protect)
{
    PVOID base = NULL;
    SIZE_T size = 0;
    NTSTATUS status = NtMapViewOfSection(section, (HANDLE)(LONG_PTR)-1, &base, 0, 0, NULL, &size,
                                         SECTION_VIEW_SHARE, 0, protect);
    if (NT_SUCCESS(status))
        NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, base);
    return status;
}

START_TEST(section_protect)
{
    HANDLE dir, file, section = NULL;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset, max;
    NTSTATUS status;
    char seed[4096];

    dir = open_test_dir(W("\\??\\C:\\prstest\\secprot"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("s.bin"));

    memset(seed, 'x', sizeof(seed));
    status = open_file(&file, dir, W("s.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create backing file -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(dir);
        return;
    }
    offset.QuadPart = 0;
    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, seed, sizeof(seed), &offset, NULL);
    ok(status == STATUS_SUCCESS, "seed backing file -> %08lx", (unsigned long)status);
    NtClose(file);

    max.QuadPart = 0;

    /* --- a READ-ONLY file handle ------------------------------------------ */
    status = open_file(&file, dir, W("s.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen read-only -> %08lx", (unsigned long)status);

    /* A writable section over it is refused outright. */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max, PAGE_READWRITE, SEC_COMMIT,
                             file);
    ok(status == STATUS_ACCESS_DENIED, "PAGE_READWRITE section over a read-only handle -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(section);

    /* A read-only section is fine -- and may NOT then be mapped writable. */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max, PAGE_READONLY, SEC_COMMIT,
                             file);
    ok(status == STATUS_SUCCESS, "PAGE_READONLY section over a read-only handle -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(map_view(section, PAGE_READONLY) == STATUS_SUCCESS, "read-only view of it");
        status = map_view(section, PAGE_READWRITE);
        ok(status == STATUS_ACCESS_DENIED, "PAGE_READWRITE view of a read-only-backed section "
                                           "-> %08lx",
           (unsigned long)status);
        /* A private copy writes nothing back, so it stays legal. */
        ok(map_view(section, PAGE_WRITECOPY) == STATUS_SUCCESS,
           "PAGE_WRITECOPY view of a read-only-backed section");
        NtClose(section);
    }
    NtClose(file);

    /* --- a READ-WRITE file handle ------------------------------------------
     * The creation protection is NOT the gate: a PAGE_READONLY section over a
     * writable handle maps PAGE_READWRITE. */
    status = open_file(&file, dir, W("s.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen read-write -> %08lx", (unsigned long)status);
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &max, PAGE_READONLY, SEC_COMMIT, file);
    ok(status == STATUS_SUCCESS, "PAGE_READONLY section over a read-write handle -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = map_view(section, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "PAGE_READWRITE view of a read-write-backed section -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }
    NtClose(file);

    scrub_file(dir, W("s.bin"));
    NtClose(dir);
}
