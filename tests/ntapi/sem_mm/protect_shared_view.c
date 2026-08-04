/*
 * sem_mm/protect_shared_view.c — what NtProtectVirtualMemory does to a
 * SHARED section view (the pin PR #108's finding-2 fix should have been
 * built on, G5/Art. 5: the oracle decides the shape, then the kernel
 * matches it).
 *
 * The gap this closes. sem_mm/writecopy_query pins the protect ladder on
 * IMAGE views and on data views MAPPED PAGE_WRITECOPY — both of which own
 * their frames (an image view is master-bound with a per-page copy record;
 * a writecopy-mapped data view is an eager private copy). Neither exercises
 * the third shape: a view mapped SHARED (ViewShare + a writable/readonly
 * protection), whose PTEs point straight at the section's or the file
 * cache's frames with no copy engine behind them. On that view a writable
 * protection granted by flipping the hardware bit is a write to every other
 * view and, under immediate writeback, to the FILE — writecopy in name
 * only. What the oracle actually answers there was never pinned, so a
 * kernel-side refusal was an unverified divergence.
 *
 * Four probes, all on the shared shape:
 *   A — a shared ANONYMOUS section view protected PAGE_WRITECOPY: does the
 *       protect succeed, and if it does, does a store stay private to the
 *       protecting view or reach a second view of the same section?
 *   B — a shared FILE-BACKED view over a writable handle, same question,
 *       with the file itself as the second observer.
 *   C — a view over a READ-ONLY handle, mapped PAGE_READONLY, protected
 *       PAGE_READWRITE: the map-time gate (a shared writable view of a file
 *       you cannot write is STATUS_ACCESS_DENIED at map) asked again at
 *       protect time.
 *   D — the same read-only-handle view protected PAGE_WRITECOPY.
 *
 * WHAT THE ORACLE ANSWERED (run first, then pinned — Art. 5; the earlier
 * revision of this file asked these as open questions and printed the
 * results):
 *
 *   A, B — the protect SUCCEEDS on a shared view, anonymous and
 *          file-backed alike (old protection PAGE_READWRITE), and the
 *          grant is SHARED-WRITABLE, not writecopy: the store is visible
 *          through a second view and reaches the FILE. The pinned Wine
 *          realizes a protect-time writecopy as plain PROT_WRITE on the
 *          existing MAP_SHARED mapping — there is no remap to MAP_PRIVATE,
 *          so no copy ever happens. Real NT would privatize the page.
 *          Pinned as the ORACLE's shape per the hazard-D precedent
 *          (docs/03): diverging toward NT turns a green pair red (Art. 6).
 *   C    — PAGE_READWRITE on a view whose backing HANDLE cannot write is
 *          REFUSED, with STATUS_INVALID_PAGE_PROTECTION. This is the one
 *          arm of the finding-2 report the oracle confirms as a genuine
 *          hole: map PAGE_READONLY over a read-only handle, protect
 *          PAGE_READWRITE, and you write a file you could not open for
 *          writing.
 *   D    — PAGE_WRITECOPY on that same read-only-handle view is GRANTED.
 *          The asymmetry with C is the oracle's, and it is what proskrnl
 *          must reproduce.
 *
 * So the correct kernel shape is NOT "refuse writecopy on shared views" —
 * that is a divergence. It is: accept the writecopy flavours everywhere the
 * oracle does, and refuse only the plain-writable protections on a view
 * whose backing handle lacks write access, with the oracle's status.
 */
#include "../sem_file/util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
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
#define MEMORY_BASIC_INFO_CLASS 0

#define PAGE_BYTES 0x1000u
#define VIEW_BYTES (3 * PAGE_BYTES)

static NTSTATUS query(const void *address, MEMORY_BASIC_INFORMATION *info)
{
    SIZE_T returned = 0;
    return NtQueryVirtualMemory(NtCurrentProcess(), address, MEMORY_BASIC_INFO_CLASS, info,
                                sizeof(*info), &returned);
}

static NTSTATUS protect_page(void *page, ULONG new_protect, ULONG *old_protect)
{
    void *base = page;
    SIZE_T size = PAGE_BYTES;
    *old_protect = 0;
    return NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, new_protect, old_protect);
}

START_TEST(protect_shared_view)
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION info;
    ULONG old_protect;

    /* --- A: a shared ANONYMOUS section view, protected PAGE_WRITECOPY ----
     * Two views of one pagefile-backed section. If the protect succeeds,
     * the store through view1 must not appear in view2 — otherwise the
     * "writecopy" the caller was granted is plain shared-writable. */
    {
        HANDLE section = NULL;
        LARGE_INTEGER size, offset;
        char *view1 = NULL, *view2 = NULL;
        SIZE_T size1 = 0, size2 = 0;

        size.QuadPart = VIEW_BYTES;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE,
                                 SEC_COMMIT, NULL);
        ok(status == STATUS_SUCCESS, "A: create anonymous section -> %08lx", (unsigned long)status);
        if (!NT_SUCCESS(status))
            return;

        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                    &size1, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "A: map view1 -> %08lx", (unsigned long)status);
        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                    &size2, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "A: map view2 -> %08lx", (unsigned long)status);
        if (view1 == NULL || view2 == NULL)
            return;

        /* The two views share: a store through one is seen by the other. */
        view1[PAGE_BYTES] = 0x11;
        ok(view2[PAGE_BYTES] == 0x11, "A: shared views do not share (%02x)",
           (unsigned char)view2[PAGE_BYTES]);

        /* THE ANSWER: the oracle GRANTS it (old = PAGE_READWRITE). */
        status = protect_page(view1 + PAGE_BYTES, PAGE_WRITECOPY, &old_protect);
        ok(status == STATUS_SUCCESS && old_protect == PAGE_READWRITE,
           "A: protect shared anonymous view WRITECOPY -> %08lx (old %lx)", (unsigned long)status,
           (unsigned long)old_protect);

        status = query(view1 + PAGE_BYTES, &info);
        ok(status == STATUS_SUCCESS && info.Protect == PAGE_WRITECOPY,
           "A: post-protect Protect %lx", (unsigned long)info.Protect);

        /* ...and the grant is SHARED-WRITABLE, not writecopy: the store is
         * visible through the other view of the same section. Real NT would
         * privatize the page here. The pinned oracle realizes a protect-time
         * writecopy as plain PROT_WRITE on the existing MAP_SHARED mapping
         * (dlls/ntdll/unix/virtual.c set_protection -> mprotect; there is no
         * remap to MAP_PRIVATE), so no copy ever happens. Pinned as the
         * oracle's shape, per the hazard-D precedent (docs/03): diverging
         * toward NT here would turn a green pair red (Art. 6). */
        view1[PAGE_BYTES] = 0x22;
        ok(view2[PAGE_BYTES] == 0x22,
           "A: the oracle's writecopy protect did NOT propagate to the other view (%02x)",
           (unsigned char)view2[PAGE_BYTES]);

        NtUnmapViewOfSection(NtCurrentProcess(), view1);
        NtUnmapViewOfSection(NtCurrentProcess(), view2);
        NtClose(section);
    }

    /* --- B: a shared FILE-BACKED view over a WRITABLE handle ------------
     * Same question with the file as the second observer: a writecopy
     * store must not reach the backing file. */
    {
        HANDLE dir, file = NULL, section = NULL;
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER size, offset;
        static UCHAR pattern[VIEW_BYTES];
        UCHAR page_buffer[PAGE_BYTES];
        char *view = NULL;
        SIZE_T view_size = 0;
        ULONG i;

        dir = open_test_dir(W("\\??\\C:\\prstest\\mmpsv"));
        ok(dir != NULL, "B: test dir");
        if (dir == NULL)
            return;
        scrub_file(dir, W("psv.dat"));
        status = open_file(&file, dir, W("psv.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "B: create psv.dat -> %08lx", (unsigned long)status);
        for (i = 0; i < sizeof(pattern); i++)
            pattern[i] = (UCHAR)(0x5A ^ i);
        offset.QuadPart = 0;
        status =
            NtWriteFile(file, NULL, NULL, NULL, &iosb, pattern, sizeof(pattern), &offset, NULL);
        ok(status == STATUS_SUCCESS, "B: seed psv.dat -> %08lx", (unsigned long)status);

        size.QuadPart = sizeof(pattern);
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE,
                                 SEC_COMMIT, file);
        ok(status == STATUS_SUCCESS, "B: create data section -> %08lx", (unsigned long)status);
        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                    &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "B: map shared RW view -> %08lx", (unsigned long)status);

        if (NT_SUCCESS(status) && view != NULL)
        {
            /* Granted here too, on a FILE-backed shared view. */
            status = protect_page(view + PAGE_BYTES, PAGE_WRITECOPY, &old_protect);
            ok(status == STATUS_SUCCESS && old_protect == PAGE_READWRITE,
               "B: protect shared file view WRITECOPY -> %08lx (old %lx)", (unsigned long)status,
               (unsigned long)old_protect);

            view[PAGE_BYTES] = 0x7E;
            /* And the store reaches the FILE — the same shared-writable
             * realization as A, now observable on disk. proskrnl's shared
             * data views write the file's page cache with immediate
             * writeback (Art. 3), which lands on the same answer. */
            offset.QuadPart = PAGE_BYTES;
            status =
                NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS, "B: re-read psv.dat -> %08lx", (unsigned long)status);
            ok(page_buffer[0] == 0x7E,
               "B: the oracle's writecopy protect did NOT reach the file (%02x, seeded %02x)",
               (unsigned char)page_buffer[0], (unsigned char)pattern[PAGE_BYTES]);
            NtUnmapViewOfSection(NtCurrentProcess(), view);
        }
        NtClose(section);
        NtClose(file);
        scrub_file(dir, W("psv.dat"));
        NtClose(dir);
    }

    /* --- C/D: a view over a READ-ONLY handle ----------------------------
     * The map-time rule (sem_mm + docs/review-2026-07 §11): a SHARED
     * writable view of a file the handle cannot write is refused at map.
     * Asked again at protect time — mapping PAGE_READONLY and then
     * protecting writable is the same request through a second door. */
    {
        HANDLE dir, writer = NULL, reader = NULL, section = NULL;
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER size, offset;
        static UCHAR pattern[VIEW_BYTES];
        char *view = NULL;
        SIZE_T view_size = 0;
        ULONG i;

        dir = open_test_dir(W("\\??\\C:\\prstest\\mmpsv"));
        ok(dir != NULL, "C: test dir");
        if (dir == NULL)
            return;
        scrub_file(dir, W("psvro.dat"));
        status = open_file(&writer, dir, W("psvro.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
        ok(status == STATUS_SUCCESS, "C: create psvro.dat -> %08lx", (unsigned long)status);
        for (i = 0; i < sizeof(pattern); i++)
            pattern[i] = (UCHAR)(0xC3 ^ i);
        offset.QuadPart = 0;
        status =
            NtWriteFile(writer, NULL, NULL, NULL, &iosb, pattern, sizeof(pattern), &offset, NULL);
        ok(status == STATUS_SUCCESS, "C: seed psvro.dat -> %08lx", (unsigned long)status);
        NtClose(writer);

        status = open_file(&reader, dir, W("psvro.dat"), FILE_GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_SUCCESS, "C: read-only open -> %08lx", (unsigned long)status);

        size.QuadPart = sizeof(pattern);
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READONLY,
                                 SEC_COMMIT, reader);
        ok(status == STATUS_SUCCESS, "C: create section over read-only handle -> %08lx",
           (unsigned long)status);

        if (NT_SUCCESS(status))
        {
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_READONLY);
            ok(status == STATUS_SUCCESS, "C: map shared RO view -> %08lx", (unsigned long)status);

            if (NT_SUCCESS(status) && view != NULL)
            {
                /* C — THE REAL GATE: a shared writable view of a file the
                 * handle cannot write is refused at PROTECT time as it is at
                 * map time, and the status is STATUS_INVALID_PAGE_PROTECTION
                 * (not ACCESS_DENIED — the map-time refusal's code). This is
                 * the one arm of the finding-2 report the oracle confirms as
                 * a genuine hole: without it, mapping PAGE_READONLY and
                 * protecting PAGE_READWRITE writes a file you cannot write. */
                status = protect_page(view + PAGE_BYTES, PAGE_READWRITE, &old_protect);
                ok(status == STATUS_INVALID_PAGE_PROTECTION,
                   "C: protect read-only-handle view READWRITE -> %08lx (old %lx)",
                   (unsigned long)status, (unsigned long)old_protect);

                /* D — and WRITECOPY on that same view is granted, because on
                 * the oracle it is a read-only-compatible protection until
                 * something stores through it. The asymmetry with C is the
                 * oracle's, and it is the shape proskrnl must reproduce. */
                status = protect_page(view + PAGE_BYTES, PAGE_WRITECOPY, &old_protect);
                ok(status == STATUS_SUCCESS && old_protect == PAGE_READONLY,
                   "D: protect read-only-handle view WRITECOPY -> %08lx (old %lx)",
                   (unsigned long)status, (unsigned long)old_protect);

                NtUnmapViewOfSection(NtCurrentProcess(), view);
            }
        }
        NtClose(section);
        NtClose(reader);
        scrub_file(dir, W("psvro.dat"));
        NtClose(dir);
    }
}
