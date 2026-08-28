/*
 * sem_mm/view_close_reopen.c — a shared writable view's stores must survive
 * the file being CLOSED and OPENED AGAIN.
 *
 * sem_mm/file_coherence.c already pins the in-flight half of this: while one
 * handle stays open, a store through a shared view and an NtReadFile on the
 * same handle see the same bytes. That test never closes the file, so it
 * cannot see the question this one asks — what a LATER open reads.
 *
 * The distinction is the whole point. proskrnl's page cache hangs off the
 * FCB and the FCB dies with the last handle (fs/fat32/fat.c
 * FatDereferenceFcb), so a reopen refills the cache FROM DISK. NtWriteFile
 * writes through to the device on every call; a store to a mapped page is a
 * plain CPU write with no syscall behind it, so nothing carries it to disk
 * unless the unmap does. Where those stores never reach the device, the file
 * silently reverts to what it held before the view existed — and every
 * assertion inside a single open still passes.
 *
 * CONVICTED BY THE WINETEST GATE, and this is what it looks like from above:
 * kernel32's EndUpdateResource copies the module to a temp file, maps the
 * copy PAGE_READWRITE, writes the whole new .rsrc section THROUGH THE VIEW,
 * unmaps, and copies the temp file back (third_party/wine
 * dlls/kernel32/resource.c write_raw_resources). With the stores lost, the
 * copy-back copies the unmodified original, EndUpdateResource still reports
 * success, and every resource read afterwards sees the pre-update file.
 * kernel32:resource fails that way at resource.c:428/:442/:447/:450, and
 * kernel32:actctx's 26+8 sxs failures are the same call one layer up
 * (add_sxs_dll_manifest writes the dependent assembly's manifest into a DLL
 * that way, so parse_depend_manifests then cannot find it).
 *
 * Oracle-first (G5): every assertion below was green on the pinned Wine
 * before any kernel code was written.
 */
#include "../sem_file/util.h"

/* The section surface (as sem_mm/util.h; redeclared here because this test
 * also needs the file surface from sem_file/util.h — the file_coherence.c
 * arrangement). */
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
#define FILE_PAGES 3u
#define FILE_BYTES (FILE_PAGES * PAGE_BYTES)

/* Case 3 maps at a non-zero section offset, and NtMapViewOfSection demands
 * ALLOCATION-granularity alignment there (STATUS_MAPPED_ALIGNMENT otherwise —
 * measured on the oracle, which is how this constant got here). 64 KiB is the
 * x86-64 value both runners use; the case reads it back rather than assuming
 * it, so the file is sized from what the system reports. */
#define BIG_PAGES 48u /* 192 KiB: three 64 KiB granules */
#define BIG_BYTES (BIG_PAGES * PAGE_BYTES)

/* Where each case pokes, and with what. Two offsets per case: one in the
 * first page and one two pages in, so a fix that only carries the page the
 * view's base lands on is caught. */
#define POKE_LO 0x40u
#define POKE_HI (2u * PAGE_BYTES + 0x80u)

static char page_buffer[PAGE_BYTES];

/* Build `name` at `pages` pages, every byte `fill`. Leaves nothing open. */
static void build_pages(HANDLE dir, const void *name, UCHAR fill, unsigned pages)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS status;
    HANDLE file;
    unsigned p;

    scrub_file(dir, name);
    status = open_file(&file, dir, name, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    memset(page_buffer, fill, sizeof(page_buffer));
    for (p = 0; p < pages; p++)
    {
        offset.QuadPart = (LONGLONG)p * PAGE_BYTES;
        status = NtWriteFile(file, NULL, NULL, NULL, &iosb, page_buffer, PAGE_BYTES, &offset, NULL);
        ok(status == STATUS_SUCCESS && iosb.Information == PAGE_BYTES, "fill page %u -> %08lx", p,
           (unsigned long)status);
    }
    NtClose(file);
}

static void build_file(HANDLE dir, const void *name, UCHAR fill)
{
    build_pages(dir, name, fill, FILE_PAGES);
}

/* Read one byte at `at` through a FRESH open of `name`. */
static UCHAR reread(HANDLE dir, const void *name, ULONG at)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    NTSTATUS status;
    HANDLE file;
    UCHAR got = 0;

    status = open_file(&file, dir, name, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "reopen -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return 0;
    offset.QuadPart = at;
    poison_iosb(&iosb);
    status = NtReadFile(file, NULL, NULL, NULL, &iosb, &got, 1, &offset, NULL);
    ok(status == STATUS_SUCCESS && iosb.Information == 1, "reread at %lx -> %08lx/%lu",
       (unsigned long)at, (unsigned long)status, (unsigned long)iosb.Information);
    NtClose(file);
    return got;
}

START_TEST(view_close_reopen)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset, section_size;
    NTSTATUS status;
    HANDLE dir, file, section;
    SIZE_T view_size;
    char *view;

    dir = open_test_dir(W("\\??\\C:\\prstest\\mmwb"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* --- 1. unmap, close, reopen ------------------------------------------
     * The plain shape, and the one write_raw_resources uses: the stores go
     * in, the view goes away, every handle goes away, and only then does
     * anything ask the file what it holds. */
    build_file(dir, W("plain.bin"), 0x11);
    status =
        open_file(&file, dir, W("plain.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "1: open -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        section = NULL;
        section_size.QuadPart = FILE_BYTES;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                                 SEC_COMMIT, file);
        ok(status == STATUS_SUCCESS, "1: create section -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            view = NULL;
            view_size = 0;
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "1: map -> %08lx", (unsigned long)status);
            if (status == STATUS_SUCCESS)
            {
                view[POKE_LO] = 0x5a;
                view[POKE_HI] = 0xa5;
                status = NtUnmapViewOfSection(NtCurrentProcess(), view);
                ok(status == STATUS_SUCCESS, "1: unmap -> %08lx", (unsigned long)status);
            }
            NtClose(section);
        }
        NtClose(file);
    }
    ok(reread(dir, W("plain.bin"), POKE_LO) == 0x5a, "1: low store survives the close (got %02x)",
       reread(dir, W("plain.bin"), POKE_LO));
    ok(reread(dir, W("plain.bin"), POKE_HI) == 0xa5, "1: high store survives the close (got %02x)",
       reread(dir, W("plain.bin"), POKE_HI));
    /* An untouched byte is still what build_file wrote — a "flush" that
     * wrote the wrong bytes back would pass the two assertions above. */
    ok(reread(dir, W("plain.bin"), POKE_LO + 1) == 0x11, "1: neighbour intact (got %02x)",
       reread(dir, W("plain.bin"), POKE_LO + 1));
    scrub_file(dir, W("plain.bin"));

    /* --- 2. the handles go FIRST, the view goes last -----------------------
     * Same stores, opposite teardown order: the section handle and the file
     * handle are closed while the view is still mapped, so at the moment the
     * view dies the caller holds nothing that names the file. The view's own
     * references are what must keep the write addressable. */
    build_file(dir, W("late.bin"), 0x22);
    status =
        open_file(&file, dir, W("late.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "2: open -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        section = NULL;
        section_size.QuadPart = FILE_BYTES;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                                 SEC_COMMIT, file);
        ok(status == STATUS_SUCCESS, "2: create section -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            view = NULL;
            view_size = 0;
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "2: map -> %08lx", (unsigned long)status);
            NtClose(section);
            NtClose(file);
            if (status == STATUS_SUCCESS)
            {
                view[POKE_LO] = 0x3c;
                view[POKE_HI] = 0xc3;
                status = NtUnmapViewOfSection(NtCurrentProcess(), view);
                ok(status == STATUS_SUCCESS, "2: unmap -> %08lx", (unsigned long)status);
            }
        }
        else
        {
            NtClose(file);
        }
    }
    ok(reread(dir, W("late.bin"), POKE_LO) == 0x3c, "2: low store survives (got %02x)",
       reread(dir, W("late.bin"), POKE_LO));
    ok(reread(dir, W("late.bin"), POKE_HI) == 0xc3, "2: high store survives (got %02x)",
       reread(dir, W("late.bin"), POKE_HI));
    scrub_file(dir, W("late.bin"));

    /* --- 3. a mapped view over a PARTIAL range carries only its own bytes --
     * The view starts one allocation granule in and is one granule long, so
     * a writeback that got the view's FILE offset wrong (its base address
     * rather than its section offset) writes granule 0 and fails here twice
     * over — once for the byte that never arrived and once for the byte that
     * arrived where nothing was written. */
    {
        SYSTEM_INFO si;
        ULONG granule;

        GetSystemInfo(&si);
        granule = si.dwAllocationGranularity;
        ok(granule >= PAGE_BYTES && granule * 3u <= BIG_BYTES, "3: granularity %lu fits the file",
           (unsigned long)granule);

        build_pages(dir, W("part.bin"), 0x33, BIG_PAGES);
        status = open_file(&file, dir, W("part.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "3: open -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            section = NULL;
            section_size.QuadPart = BIG_BYTES;
            status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size,
                                     PAGE_READWRITE, SEC_COMMIT, file);
            ok(status == STATUS_SUCCESS, "3: create section -> %08lx", (unsigned long)status);
            if (status == STATUS_SUCCESS)
            {
                view = NULL;
                view_size = granule;
                offset.QuadPart = granule;
                status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0,
                                            &offset, &view_size, ViewShare, 0, PAGE_READWRITE);
                ok(status == STATUS_SUCCESS, "3: map -> %08lx", (unsigned long)status);
                if (status == STATUS_SUCCESS)
                {
                    view[0x10] = 0x7e;
                    status = NtUnmapViewOfSection(NtCurrentProcess(), view);
                    ok(status == STATUS_SUCCESS, "3: unmap -> %08lx", (unsigned long)status);
                }
                NtClose(section);
            }
            NtClose(file);
        }
        ok(reread(dir, W("part.bin"), granule + 0x10) == 0x7e,
           "3: store at the view base (got %02x)", reread(dir, W("part.bin"), granule + 0x10));
        ok(reread(dir, W("part.bin"), 0x10) == 0x33, "3: granule 0 untouched (got %02x)",
           reread(dir, W("part.bin"), 0x10));
        scrub_file(dir, W("part.bin"));
    }

    /* --- 4. a WRITECOPY view's stores must NOT reach the file --------------
     * The inverse assertion, and the one an over-eager writeback fails: a
     * private copy is exactly the case where a store must go nowhere. It is
     * here because "flush every mapped view at unmap" passes 1-3 and
     * corrupts every copy-on-write mapping in the system. */
    build_file(dir, W("wcopy.bin"), 0x44);
    status =
        open_file(&file, dir, W("wcopy.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "4: open -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        section = NULL;
        section_size.QuadPart = FILE_BYTES;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                                 SEC_COMMIT, file);
        ok(status == STATUS_SUCCESS, "4: create section -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            view = NULL;
            view_size = 0;
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_WRITECOPY);
            ok(status == STATUS_SUCCESS, "4: map writecopy -> %08lx", (unsigned long)status);
            if (status == STATUS_SUCCESS)
            {
                view[POKE_LO] = 0x99;
                view[POKE_HI] = 0x99;
                ok((UCHAR)view[POKE_LO] == 0x99, "4: the private copy took the store");
                status = NtUnmapViewOfSection(NtCurrentProcess(), view);
                ok(status == STATUS_SUCCESS, "4: unmap -> %08lx", (unsigned long)status);
            }
            NtClose(section);
        }
        NtClose(file);
    }
    ok(reread(dir, W("wcopy.bin"), POKE_LO) == 0x44, "4: writecopy store stayed private (got %02x)",
       reread(dir, W("wcopy.bin"), POKE_LO));
    ok(reread(dir, W("wcopy.bin"), POKE_HI) == 0x44,
       "4: high writecopy store stayed private "
       "(got %02x)",
       reread(dir, W("wcopy.bin"), POKE_HI));
    scrub_file(dir, W("wcopy.bin"));

    /* --- 5. a READ-ONLY view changes nothing -------------------------------
     * The cheap third arm: mapping PAGE_READONLY and unmapping must leave
     * the file byte-for-byte where it was, which is what says the writeback
     * is keyed on the view being writable and not on it being file-backed. */
    build_file(dir, W("ro.bin"), 0x55);
    status =
        open_file(&file, dir, W("ro.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "5: open -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        section = NULL;
        section_size.QuadPart = FILE_BYTES;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &section_size, PAGE_READWRITE,
                                 SEC_COMMIT, file);
        ok(status == STATUS_SUCCESS, "5: create section -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            view = NULL;
            view_size = 0;
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view, 0, 0, &offset,
                                        &view_size, ViewShare, 0, PAGE_READONLY);
            ok(status == STATUS_SUCCESS, "5: map readonly -> %08lx", (unsigned long)status);
            if (status == STATUS_SUCCESS)
            {
                ok((UCHAR)view[POKE_LO] == 0x55, "5: the view reads the file");
                status = NtUnmapViewOfSection(NtCurrentProcess(), view);
                ok(status == STATUS_SUCCESS, "5: unmap -> %08lx", (unsigned long)status);
            }
            NtClose(section);
        }
        NtClose(file);
    }
    ok(reread(dir, W("ro.bin"), POKE_LO) == 0x55, "5: file unchanged (got %02x)",
       reread(dir, W("ro.bin"), POKE_LO));
    scrub_file(dir, W("ro.bin"));

    NtClose(dir);
}
