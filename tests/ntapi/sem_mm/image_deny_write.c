/*
 * sem_mm/image_deny_write.c — an image-mapped file refuses write-opens
 * (CUI-9 hazard F, docs/17 §6F: "the image file changing under a live
 * section: close this on the share-mode side (refuse the write) rather
 * than by invalidating masters").
 *
 * Oracle behaviour pinned from the pinned tree (wine server/mapping.c:
 * an image mapping holds the file's fd with sharing that excludes
 * FILE_WRITE_DATA, so a write-open while any image section or mapped view
 * is alive answers STATUS_SHARING_VIOLATION — the same shape NT gives a
 * running .exe). The write-open succeeds again once section and view are
 * both gone.
 *
 * The kernel side is the imageSectionCount gate in IoCheckShareAccess
 * (kernel/io/file.c) — landed ahead of CUI-9's shared masters, because a
 * file mutating under a live relocated master would be cross-process
 * corruption (docs/17 §6F; docs/03 "CUI-9 COW notes").
 */
#include "imagefile.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

START_TEST(image_deny_write)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, reader, writer, section;
    LARGE_INTEGER byte_offset;
    SIZE_T view_size;
    void *view;

    dir = open_test_dir(W("\\??\\C:\\prstest\\mmidw"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* A private copy of ntdll.dll: a real, relocatable PE this test owns,
     * so the deny-write pin never fights the loader's own mapping of the
     * system DLL (imagefile.h — sem_mm/section_file_hold.c wants the same
     * file and the two must not drift). */
    if (!copy_system_image(dir, W("idw.dll")))
        return;

    /* The read handle the section will be built over shares generously, so
     * any later refusal is the image mapping's doing, not this handle's. */
    status = open_file(&reader, dir, W("idw.dll"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open reader -> %08lx", (unsigned long)status);

    /* Sanity: with no image section, a write-open succeeds. */
    status = open_file(&writer, dir, W("idw.dll"), FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "pre-section write-open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(writer);

    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, reader);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    view = NULL;
    view_size = 0;
    byte_offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, &byte_offset, &view_size,
                                ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map image -> %08lx",
       (unsigned long)status);

    /* --- the pin: a write-open under a live image mapping refuses ----------- */
    writer = NULL;
    status = open_file(&writer, dir, W("idw.dll"), FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SHARING_VIOLATION, "write-open under image map -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(writer); /* keep the rest of the test honest if it opened */

    /* --- and succeeds again once section and view are gone ------------------ */
    status = NtUnmapViewOfSection(NtCurrentProcess(), view);
    ok(status == STATUS_SUCCESS, "unmap -> %08lx", (unsigned long)status);
    NtClose(section);
    status = open_file(&writer, dir, W("idw.dll"), FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "post-teardown write-open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(writer);

    NtClose(reader);
    scrub_file(dir, W("idw.dll"));
    NtClose(dir);
}
