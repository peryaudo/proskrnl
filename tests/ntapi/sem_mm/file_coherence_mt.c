/*
 * sem_mm/file_coherence_mt.c — the CONCURRENT file_coherence (CUI-8,
 * docs/19 §8.3.2): two threads against ONE file, one FCB, one page cache —
 * interleaving mapped-view stores, NtWriteFile and NtReadFile while (once
 * CUI-8 lands) transfers are genuinely in flight. This is the direct guard
 * on the docs/20 re-entrancy rows: every "MT:" entry there names the
 * interleaving here that would catch its violation.
 *
 * Determinism scheme (both backends, no timing assumptions):
 *   - the file's 16 pages are RANGE-PARTITIONED — the main thread owns
 *     pages 0-7, the worker pages 8-15; each runs the file_coherence op mix
 *     over its own range with its own fixed-seed PRNG and its own private
 *     shadow, so every assertion is deterministic even though the two op
 *     streams interleave arbitrarily in time;
 *   - every 16th iteration each thread also reads the WHOLE file through
 *     the shared FCB and verifies its own range out of the copy — the op
 *     that drags both threads across the same cache fill/writeback
 *     machinery concurrently;
 *   - a final event-serialized handoff phase makes cross-range visibility
 *     deterministic: A writes, signals, B reads and verifies, answers —
 *     including a file extension crossing the threads.
 * The worker never calls ok() (the harness counters are plain ints, and
 * this is the first test with two genuinely hot threads): it folds failures
 * into its own counters, asserted by the main thread after the join.
 */
#include "../sem_file/util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                               FILE_INFORMATION_CLASS);
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

#define PAGE_BYTES 0x1000u
#define FILE_PAGES 16u
#define FILE_BYTES (FILE_PAGES * PAGE_BYTES)
#define HALF_PAGES (FILE_PAGES / 2)
#define ITERS      400u
#define HANDOFFS   32u

static HANDLE mt_dir;
static char *mt_view; /* shared long-lived view over the whole file */

/* Worker-side verdict, folded by the worker and asserted at the join. */
static volatile LONG wk_failures;
static volatile LONG wk_first_iter;
static volatile LONG wk_first_page;
static volatile LONG wk_first_want;
static volatile LONG wk_first_saw;

static void wk_fail(unsigned iter, unsigned page, UCHAR want, UCHAR saw)
{
    if (InterlockedIncrement(&wk_failures) == 1)
    {
        wk_first_iter = (LONG)iter;
        wk_first_page = (LONG)page;
        wk_first_want = want;
        wk_first_saw = saw;
    }
}

/* Handoff rendezvous. */
static HANDLE ev_to_worker, ev_to_main;
static volatile LONG handoff_value;

static ULONG wk_rng_state = 0x51F15EEDu;
static ULONG wk_rng(void)
{
    ULONG x = wk_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return wk_rng_state = x;
}

static DWORD WINAPI coherence_worker(void *param)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    LARGE_INTEGER offset;
    HANDLE file;
    static UCHAR page_buffer[PAGE_BYTES];
    static UCHAR whole[FILE_BYTES];
    UCHAR shadow[HALF_PAGES]; /* worker's private truth for pages 8..15 */
    unsigned iter, p;
    (void)param;

    /* The worker's own handle to the same file: same FCB, same cache. */
    status = open_file(&file, mt_dir, W("coherent_mt.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    if (!NT_SUCCESS(status))
    {
        wk_fail(0, 0, 0, 0);
        return 0;
    }
    for (p = 0; p < HALF_PAGES; p++)
        shadow[p] = 0;

    for (iter = 1; iter <= ITERS; iter++)
    {
        unsigned op = wk_rng() % 4;
        unsigned slot = wk_rng() % HALF_PAGES;
        unsigned page = HALF_PAGES + slot; /* pages 8..15 belong to the worker */
        UCHAR value = (UCHAR)(wk_rng() & 0xff);

        switch (op)
        {
        case 0: /* view store */
            mt_view[page * PAGE_BYTES] = (char)value;
            mt_view[page * PAGE_BYTES + PAGE_BYTES - 1] = (char)value;
            shadow[slot] = value;
            break;
        case 1: /* NtWriteFile */
            memset(page_buffer, value, sizeof(page_buffer));
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            status =
                NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            if (status != STATUS_SUCCESS || iosb.Information != PAGE_BYTES)
                wk_fail(iter, page, value, 0xEE);
            else
                shadow[slot] = value;
            break;
        case 2: /* NtReadFile + verify own page */
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            memset(page_buffer, 0xAA, sizeof(page_buffer));
            status =
                NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            if (status != STATUS_SUCCESS || iosb.Information != PAGE_BYTES)
                wk_fail(iter, page, shadow[slot], 0xEF);
            else if (page_buffer[0] != shadow[slot] || page_buffer[PAGE_BYTES - 1] != shadow[slot])
                wk_fail(iter, page, shadow[slot], page_buffer[0]);
            break;
        default: /* view read + verify own page */
            if ((UCHAR)mt_view[page * PAGE_BYTES] != shadow[slot] ||
                (UCHAR)mt_view[page * PAGE_BYTES + PAGE_BYTES - 1] != shadow[slot])
                wk_fail(iter, page, shadow[slot], (UCHAR)mt_view[page * PAGE_BYTES]);
            break;
        }

        if (iter % 16 == 0)
        {
            /* Whole-file read through the shared FCB; verify OUR half only —
             * the other half is the main thread's moving target. */
            offset.QuadPart = 0;
            status = NtReadFile(file, NULL, NULL, NULL, &iosb, whole, FILE_BYTES, &offset, NULL);
            if (status != STATUS_SUCCESS || iosb.Information != FILE_BYTES)
                wk_fail(iter, 0xFF, 0, 0xF0);
            else
                for (p = 0; p < HALF_PAGES; p++)
                {
                    unsigned pg = HALF_PAGES + p;
                    if (whole[pg * PAGE_BYTES] != shadow[p] ||
                        whole[pg * PAGE_BYTES + PAGE_BYTES - 1] != shadow[p])
                        wk_fail(iter, pg, shadow[p], whole[pg * PAGE_BYTES]);
                }
        }
    }

    /* --- handoff phase: cross-range visibility, event-serialized. ----------
     * Round r: main writes page 7 (view or write path, alternating) with
     * value r, signals; we read page 7 through NtReadFile and answer with
     * value r on page 8; main verifies through the view. Deterministic on
     * both backends because every cross-thread read is ordered by an event. */
    for (iter = 0; iter < HANDOFFS; iter++)
    {
        if (WaitForSingleObject(ev_to_worker, 15000) != WAIT_OBJECT_0)
        {
            wk_fail(1000 + iter, 7, (UCHAR)iter, 0xF1);
            break;
        }
        UCHAR want = (UCHAR)handoff_value;
        offset.QuadPart = 7 * PAGE_BYTES;
        status = NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        if (status != STATUS_SUCCESS || page_buffer[0] != want ||
            page_buffer[PAGE_BYTES - 1] != want)
            wk_fail(1000 + iter, 7, want, page_buffer[0]);
        memset(page_buffer, want, sizeof(page_buffer));
        offset.QuadPart = 8 * PAGE_BYTES;
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        if (status != STATUS_SUCCESS)
            wk_fail(1000 + iter, 8, want, 0xF2);
        SetEvent(ev_to_main);
    }

    /* --- the extension handoff: main extends by one page and fills it; we
     * see the new size and the bytes through our own handle. -------------- */
    if (WaitForSingleObject(ev_to_worker, 15000) == WAIT_OBJECT_0)
    {
        FILE_STANDARD_INFORMATION std;
        status = NtQueryInformationFile(file, &iosb, &std, sizeof(std), FileStandardInformation);
        if (status != STATUS_SUCCESS || std.EndOfFile.QuadPart != (LONGLONG)FILE_BYTES + PAGE_BYTES)
            wk_fail(2000, 16, 0, 0xF3);
        offset.QuadPart = FILE_BYTES;
        status = NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        if (status != STATUS_SUCCESS || page_buffer[0] != 0x5C ||
            page_buffer[PAGE_BYTES - 1] != 0x5C)
            wk_fail(2000, 16, 0x5C, page_buffer[0]);
        SetEvent(ev_to_main);
    }
    else
        wk_fail(2000, 16, 0, 0xF4);

    NtClose(file);
    return 0;
}

START_TEST(file_coherence_mt)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, file, section, worker;
    LARGE_INTEGER offset, section_size;
    SIZE_T view_size;
    char *view;
    unsigned iter, p;
    static UCHAR page_buffer[PAGE_BYTES];
    static UCHAR whole[FILE_BYTES];
    static UCHAR shadow[HALF_PAGES]; /* main's private truth for pages 0..7 */
    ULONG rng_state = 0x6D5A17C3u;
#define MT_RNG()                                                                                   \
    (rng_state ^= rng_state << 13, rng_state ^= rng_state >> 17, rng_state ^= rng_state << 5,      \
     rng_state)

    dir = open_test_dir(W("\\??\\C:\\prstest\\mmco"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("coherent_mt.bin"));
    mt_dir = dir;

    status = open_file(&file, dir, W("coherent_mt.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create coherent_mt.bin -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    memset(page_buffer, 0, sizeof(page_buffer));
    for (p = 0; p < FILE_PAGES; p++)
    {
        offset.QuadPart = (LONGLONG)p * PAGE_BYTES;
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS, "zero-fill page %u -> %08lx", p, (unsigned long)status);
    }
    for (p = 0; p < HALF_PAGES; p++)
        shadow[p] = 0;

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
    if (status != STATUS_SUCCESS)
        return;
    mt_view = view;

    ev_to_worker = CreateEventW(NULL, FALSE, FALSE, NULL);
    ev_to_main = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(ev_to_worker != NULL && ev_to_main != NULL, "handoff events");

    wk_failures = 0;
    worker = CreateThread(NULL, 0, coherence_worker, NULL, 0, NULL);
    ok(worker != NULL, "CreateThread worker");

    /* --- the concurrent phase: main runs the same mix over pages 0..7. ---- */
    for (iter = 1; iter <= ITERS; iter++)
    {
        unsigned op = MT_RNG() % 4;
        unsigned slot = MT_RNG() % HALF_PAGES;
        unsigned page = slot; /* pages 0..7 belong to the main thread */
        UCHAR value = (UCHAR)(MT_RNG() & 0xff);

        switch (op)
        {
        case 0:
            view[page * PAGE_BYTES] = (char)value;
            view[page * PAGE_BYTES + PAGE_BYTES - 1] = (char)value;
            shadow[slot] = value;
            break;
        case 1:
            memset(page_buffer, value, sizeof(page_buffer));
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            poison_iosb(&iosb);
            status =
                NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES,
               "iter %u: NtWriteFile page %u -> %08lx/%lu", iter, page, (unsigned long)status,
               (unsigned long)iosb.Information);
            shadow[slot] = value;
            break;
        case 2:
            offset.QuadPart = (LONGLONG)page * PAGE_BYTES;
            poison_iosb(&iosb);
            memset(page_buffer, 0xAA, sizeof(page_buffer));
            status =
                NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES,
               "iter %u: NtReadFile page %u -> %08lx/%lu", iter, page, (unsigned long)status,
               (unsigned long)iosb.Information);
            ok(page_buffer[0] == shadow[slot] && page_buffer[PAGE_BYTES - 1] == shadow[slot],
               "iter %u: NtReadFile page %u saw %02x/%02x want %02x", iter, page, page_buffer[0],
               page_buffer[PAGE_BYTES - 1], shadow[slot]);
            break;
        default:
            ok((UCHAR)view[page * PAGE_BYTES] == shadow[slot] &&
                   (UCHAR)view[page * PAGE_BYTES + PAGE_BYTES - 1] == shadow[slot],
               "iter %u: view page %u saw %02x want %02x", iter, page,
               (UCHAR)view[page * PAGE_BYTES], shadow[slot]);
            break;
        }

        if (iter % 16 == 0)
        {
            offset.QuadPart = 0;
            status = NtReadFile(file, NULL, NULL, NULL, &iosb, whole, FILE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS && iosb.Information == FILE_BYTES,
               "iter %u: whole-file read -> %08lx/%lu", iter, (unsigned long)status,
               (unsigned long)iosb.Information);
            if (status == STATUS_SUCCESS)
                for (p = 0; p < HALF_PAGES; p++)
                    ok(whole[p * PAGE_BYTES] == shadow[p] &&
                           whole[p * PAGE_BYTES + PAGE_BYTES - 1] == shadow[p],
                       "iter %u: whole-file page %u saw %02x want %02x", iter, p,
                       whole[p * PAGE_BYTES], shadow[p]);
        }
    }

    /* --- handoff phase (see the worker's comment). ------------------------- */
    for (iter = 0; iter < HANDOFFS; iter++)
    {
        UCHAR value = (UCHAR)iter;
        handoff_value = value;
        shadow[7] = value; /* page 7's truth now comes from the handoff */
        if (iter % 2 == 0)
        {
            /* even rounds: through the view */
            memset(view + 7 * PAGE_BYTES, value, PAGE_BYTES);
        }
        else
        {
            /* odd rounds: through NtWriteFile */
            memset(page_buffer, value, sizeof(page_buffer));
            offset.QuadPart = 7 * PAGE_BYTES;
            status =
                NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
            ok(status == STATUS_SUCCESS, "handoff %u: write page 7 -> %08lx", iter,
               (unsigned long)status);
        }
        SetEvent(ev_to_worker);
        ok(WaitForSingleObject(ev_to_main, 15000) == WAIT_OBJECT_0, "handoff %u: worker answered",
           iter);
        /* The worker echoed the value onto page 8; both paths must see it. */
        ok((UCHAR)view[8 * PAGE_BYTES] == value && (UCHAR)view[9 * PAGE_BYTES - 1] == value,
           "handoff %u: view page 8 saw %02x want %02x", iter, (UCHAR)view[8 * PAGE_BYTES], value);
    }

    /* --- extension handoff: grow by one page, fill, let the worker verify. - */
    {
        FILE_END_OF_FILE_INFORMATION eof;
        eof.EndOfFile.QuadPart = (LONGLONG)FILE_BYTES + PAGE_BYTES;
        status = NtSetInformationFile(file, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
        ok(status == STATUS_SUCCESS, "extend to 17 pages -> %08lx", (unsigned long)status);
        memset(page_buffer, 0x5C, sizeof(page_buffer));
        offset.QuadPart = FILE_BYTES;
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS, "fill page 16 -> %08lx", (unsigned long)status);
        SetEvent(ev_to_worker);
        ok(WaitForSingleObject(ev_to_main, 15000) == WAIT_OBJECT_0, "extension: worker answered");
    }

    ok(WaitForSingleObject(worker, 15000) == WAIT_OBJECT_0, "worker never returned");
    CloseHandle(worker);
    ok(wk_failures == 0, "worker saw %ld failures; first at iter %ld page %ld want %02lx saw %02lx",
       (long)wk_failures, (long)wk_first_iter, (long)wk_first_page, (unsigned long)wk_first_want,
       (unsigned long)wk_first_saw);

    /* --- final sweep over the original 16 pages, both paths. --------------- */
    for (p = 0; p < HALF_PAGES; p++)
    {
        offset.QuadPart = (LONGLONG)p * PAGE_BYTES;
        status = NtReadFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS, "final read page %u -> %08lx", p, (unsigned long)status);
        ok(page_buffer[0] == shadow[p] && (UCHAR)view[p * PAGE_BYTES] == shadow[p],
           "final page %u: read %02x view %02x want %02x", p, page_buffer[0],
           (UCHAR)view[p * PAGE_BYTES], shadow[p]);
    }

    status = NtUnmapViewOfSection(NtCurrentProcess(), view);
    ok(status == STATUS_SUCCESS, "unmap -> %08lx", (unsigned long)status);
    NtClose(section);
    NtClose(file);
    CloseHandle(ev_to_worker);
    CloseHandle(ev_to_main);
    scrub_file(dir, W("coherent_mt.bin"));
    NtClose(dir);
}
