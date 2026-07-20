/*
 * sem_mm/file_coherence.c — THE self-checking Mm stress test (docs/02 M6 "Do
 * first", docs/08): write via a mapped view, read via NtReadFile, write via
 * NtWriteFile, read via the view again, verifying a known pattern on every
 * step. Under the unified page cache both paths see the same physical page,
 * so this is the test that convicts mapped-view/read-write coherence bugs —
 * they surface *only* in this form, and reliably do.
 *
 * Single-threaded (no NtCreateThread until M7); sequential interleavings
 * already convict coherence bugs. Fixed-seed PRNG; the iteration number in
 * every ok() locates a failure exactly.
 */
#include "../sem_file/util.h"

/* The section surface (as sem_mm/util.h; redeclared here because this test
 * also needs the file surface from sem_file/util.h). */
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

#define PAGE_BYTES 0x1000u
#define FILE_PAGES 16u /* 64 KiB working file */
#define FILE_BYTES (FILE_PAGES * PAGE_BYTES)
#define ITERS      400u

/* Shadow model: expected value of the first and last byte of each page. */
static UCHAR shadow[FILE_PAGES];

static ULONG rng_state = 0x6D5A17C3u;
static ULONG rng(void)
{
    ULONG x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

START_TEST(file_coherence)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, file, section;
    LARGE_INTEGER offset, section_size;
    SIZE_T view_size;
    char *view;
    unsigned iter, p;
    UCHAR page_buffer[PAGE_BYTES];

    dir = open_test_dir(W("\\??\\C:\\prstest\\mmco"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("coherent.bin"));

    /* Build the file at full size, all zeroes. */
    status = open_file(&file, dir, W("coherent.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create coherent.bin -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    memset(page_buffer, 0, sizeof(page_buffer));
    for (p = 0; p < FILE_PAGES; p++)
    {
        offset.QuadPart = (LONGLONG)p * PAGE_BYTES;
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES, "zero-fill page %u -> %08lx",
           p, (unsigned long)status);
        shadow[p] = 0;
    }

    /* One writable file-backed section + one long-lived view over it all. */
    section = NULL;
    section_size.QuadPart = FILE_BYTES;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                             SEC_COMMIT, file);
    ok(status == STATUS_SUCCESS, "create file section -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    view = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map view -> %08lx", (unsigned long)status);
    ok(view_size >= FILE_BYTES, "view size %lx", (unsigned long)view_size);
    if (status != STATUS_SUCCESS)
        return;

    for (iter = 1; iter <= ITERS; iter++)
    {
        unsigned op = rng() % 4;
        unsigned page = rng() % FILE_PAGES;
        UCHAR value = (UCHAR)(rng() & 0xff);

        switch (op)
        {
        case 0: /* write via the view; the pattern is now the truth */
            view[page * PAGE_BYTES] = (char)value;
            view[page * PAGE_BYTES + PAGE_BYTES - 1] = (char)value;
            shadow[page] = value;
            break;

        case 1: /* write via NtWriteFile */
            memset(page_buffer, value, PAGE_BYTES);
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            poison_iosb(&iosb);
            status =
                NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES,
               "iter %u: NtWriteFile page %u -> %08lx/%lu", iter, page, (unsigned long)status,
               (unsigned long)iosb.Information);
            shadow[page] = value;
            break;

        case 2: /* read via NtReadFile and check against the shadow */
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            poison_iosb(&iosb);
            memset(page_buffer, 0xAA, sizeof(page_buffer));
            status =
                NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES,
               "iter %u: NtReadFile page %u -> %08lx/%lu", iter, page, (unsigned long)status,
               (unsigned long)iosb.Information);
            ok((UCHAR)page_buffer[0] == shadow[page] &&
                   (UCHAR)page_buffer[PAGE_BYTES - 1] == shadow[page],
               "iter %u: NtReadFile page %u saw %02x/%02x want %02x", iter, page,
               (UCHAR)page_buffer[0], (UCHAR)page_buffer[PAGE_BYTES - 1], shadow[page]);
            break;

        default: /* read via the view and check against the shadow */
            ok((UCHAR)view[page * PAGE_BYTES] == shadow[page] &&
                   (UCHAR)view[page * PAGE_BYTES + PAGE_BYTES - 1] == shadow[page],
               "iter %u: view page %u saw %02x/%02x want %02x", iter, page,
               (UCHAR)view[page * PAGE_BYTES], (UCHAR)view[page * PAGE_BYTES + PAGE_BYTES - 1],
               shadow[page]);
            break;
        }
    }

    /* Final sweep: every page agrees through both paths. */
    for (p = 0; p < FILE_PAGES; p++)
    {
        offset.QuadPart = (LONGLONG)p * PAGE_BYTES;
        status = NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS, "final read page %u -> %08lx", p, (unsigned long)status);
        ok((UCHAR)page_buffer[0] == shadow[p] && (UCHAR)view[p * PAGE_BYTES] == shadow[p],
           "final page %u: read %02x view %02x want %02x", p, (UCHAR)page_buffer[0],
           (UCHAR)view[p * PAGE_BYTES], shadow[p]);
    }

    status = NtUnmapViewOfSection(NtCurrentProcess(), view);
    ok(status == STATUS_SUCCESS, "unmap -> %08lx", (unsigned long)status);
    status = NtClose(section);
    ok(status == STATUS_SUCCESS, "close section -> %08lx", (unsigned long)status);
    NtClose(file);
    scrub_file(dir, W("coherent.bin"));
    NtClose(dir);
}
