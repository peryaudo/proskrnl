/*
 * sem_mm/section_stress.c — self-checking anonymous-section stress (docs/08).
 *
 * docs/08 calls the self-checking stress test the only reliable guard for Mm
 * consistency. Its full form — write via mapped view, read via NtReadFile,
 * write via NtWriteFile, read via view — needs the M6 I/O manager and is
 * written test-first at the start of M6 (docs/02). This is the M5 slice: it
 * hammers what exists now — SEC_COMMIT sections, many simultaneous views,
 * map/unmap churn, section create/close churn, address-space churn — and
 * verifies a deterministic pattern through every view against a shadow model
 * on every step. It exercises the structures the full test will lean on:
 * section frame sharing and refcounts, VAD insert/remove, and unmap (a view
 * that "sees" pages after unmap+remap of a neighbour convicts stale TLB or
 * frame-reuse bugs).
 *
 * Single-threaded by construction: there is no NtCreateThread until M7, and
 * under Art. 3 (uniprocessor, one dispatcher lock) sequential interleavings
 * already reach the shared state. The PRNG is fixed-seed so a failure
 * reproduces exactly; the iteration number in each ok() locates it.
 */
#include "util.h"

/* 64K NT allocation granularity: SYSTEM_INFO.dwAllocationGranularity (MS
 * "GetSystemInfo" docs); Wine hard-codes it as granularity_mask = 0xffff in
 * third_party/wine/dlls/ntdll/unix/virtual.c. 4K x86-64 page size: Intel SDM
 * Vol. 3A §4.5; same value the existing sem_mm tests map at. */
#define GRAN         0x10000u
#define PAGE_BYTES   0x1000u
#define SEC_GRANS    4u /* each section: 4 * 64K = 256K */
#define SEC_SIZE     (SEC_GRANS * GRAN)
#define SEC_PAGES    (SEC_SIZE / PAGE_BYTES) /* 64 */
#define NUM_SECTIONS 4u
#define NUM_SLOTS    12u /* simultaneous views (across all sections) */
#define ITERS        600u

static HANDLE sections[NUM_SECTIONS];

/* Shadow model: the byte value the first and last byte of every section page
 * must currently hold (pages start zero-filled, so 0 initially). Every
 * verification below compares a view against this — the test never trusts
 * one view to check another directly. */
static UCHAR shadow[NUM_SECTIONS][SEC_PAGES];

static struct view_slot
{
    char *base; /* NULL = slot free */
    unsigned section;
    unsigned offset; /* bytes into the section, GRAN-aligned */
    unsigned size;   /* bytes, GRAN multiple */
} slots[NUM_SLOTS];

/* xorshift32, fixed seed: the whole run is deterministic. */
static ULONG rng_state = 0x1965A11Du;
static ULONG rng(void)
{
    ULONG x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

/* Verify one view against the shadow model; one ok() per call, first
 * mismatch in the message. */
static void check_view(const struct view_slot *s, unsigned iter, const char *what)
{
    unsigned pages = s->size / PAGE_BYTES;
    unsigned first_page = s->offset / PAGE_BYTES;
    unsigned bad = 0, bad_page = 0;
    UCHAR bad_saw = 0, bad_want = 0;

    for (unsigned p = 0; p < pages; p++)
    {
        UCHAR want = shadow[s->section][first_page + p];
        UCHAR lo = (UCHAR)s->base[p * PAGE_BYTES];
        UCHAR hi = (UCHAR)s->base[p * PAGE_BYTES + PAGE_BYTES - 1];
        if (lo != want || hi != want)
        {
            if (bad == 0)
            {
                bad_page = p;
                bad_saw = (lo != want) ? lo : hi;
                bad_want = want;
            }
            bad++;
        }
    }
    ok(bad == 0,
       "iter %u (%s): sec %u view off %x at %p: %u bad pages, first page %u saw %02x want %02x",
       iter, what, s->section, s->offset, (void *)s->base, bad, bad_page, bad_saw, bad_want);
}

static void create_section(unsigned sec, unsigned iter)
{
    LARGE_INTEGER max_size;
    NTSTATUS status;

    max_size.QuadPart = SEC_SIZE;
    sections[sec] = NULL;
    status = NtCreateSection(&sections[sec], SECTION_ALL_ACCESS, NULL, &max_size, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "iter %u: create sec %u -> %08lx", iter, sec,
       (unsigned long)status);
    for (unsigned p = 0; p < SEC_PAGES; p++)
        shadow[sec][p] = 0; /* SEC_COMMIT frames are allocated zeroed */
}

START_TEST(section_stress)
{
    NTSTATUS status;
    unsigned iter, i;

    for (i = 0; i < NUM_SECTIONS; i++)
        create_section(i, 0);

    for (iter = 1; iter <= ITERS; iter++)
    {
        unsigned op = rng() % 100;

        if (op < 30)
        {
            /* --- map: a fresh view must see the section's current content. */
            unsigned slot;
            for (slot = 0; slot < NUM_SLOTS && slots[slot].base != NULL; slot++)
                ;
            if (slot == NUM_SLOTS)
                continue;
            struct view_slot *s = &slots[slot];
            s->section = rng() % NUM_SECTIONS;
            unsigned off_grans = rng() % SEC_GRANS;
            unsigned size_grans = 1 + rng() % (SEC_GRANS - off_grans);
            s->offset = off_grans * GRAN;
            s->size = size_grans * GRAN;

            LARGE_INTEGER offset;
            SIZE_T view_size = s->size;
            offset.QuadPart = s->offset;
            s->base = NULL;
            status = NtMapViewOfSection(sections[s->section], NtCurrentProcess(), (void **)&s->base,
                                        0, 0, &offset, &view_size, ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "iter %u: map sec %u off %x size %x -> %08lx", iter,
               s->section, s->offset, s->size, (unsigned long)status);
            if (status != STATUS_SUCCESS)
            {
                s->base = NULL;
                continue;
            }
            ok(((ULONG_PTR)s->base & (GRAN - 1)) == 0, "iter %u: view %p not 64K aligned", iter,
               (void *)s->base);
            ok(view_size == s->size, "iter %u: view size %lx want %x", iter,
               (unsigned long)view_size, s->size);
            check_view(s, iter, "fresh map");
        }
        else if (op < 45)
        {
            /* --- unmap a view; its range must revert to MEM_FREE. */
            unsigned used[NUM_SLOTS], n = 0;
            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].base != NULL)
                    used[n++] = i;
            if (n == 0)
                continue;
            struct view_slot *s = &slots[used[rng() % n]];
            check_view(s, iter, "pre-unmap");
            status = NtUnmapViewOfSection(NtCurrentProcess(), s->base);
            ok(status == STATUS_SUCCESS, "iter %u: unmap %p -> %08lx", iter, (void *)s->base,
               (unsigned long)status);

            MEMORY_BASIC_INFORMATION mbi;
            mbi.State = 0; /* defined value in the ok() message if the query fails */
            status = NtQueryVirtualMemory(NtCurrentProcess(), s->base, MEMORY_BASIC_INFO_CLASS,
                                          &mbi, sizeof(mbi), NULL);
            ok(status == STATUS_SUCCESS && mbi.State == MEM_FREE,
               "iter %u: unmapped %p query %08lx State %lx", iter, (void *)s->base,
               (unsigned long)status, (unsigned long)mbi.State);
            s->base = NULL;
        }
        else if (op < 75)
        {
            /* --- write through one view; every other view of the section
             * must observe it (shared frames, no COW — Art. 3). */
            unsigned used[NUM_SLOTS], n = 0;
            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].base != NULL)
                    used[n++] = i;
            if (n == 0)
                continue;
            struct view_slot *s = &slots[used[rng() % n]];
            unsigned page = rng() % (s->size / PAGE_BYTES);
            UCHAR value = (UCHAR)(rng() & 0xff);
            s->base[page * PAGE_BYTES] = (char)value;
            s->base[page * PAGE_BYTES + PAGE_BYTES - 1] = (char)value;
            shadow[s->section][s->offset / PAGE_BYTES + page] = value;

            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].base != NULL && slots[i].section == s->section && &slots[i] != s)
                    check_view(&slots[i], iter, "cross-view");
        }
        else if (op < 85)
        {
            /* --- full verify of one view. */
            unsigned used[NUM_SLOTS], n = 0;
            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].base != NULL)
                    used[n++] = i;
            if (n != 0)
                check_view(&slots[used[rng() % n]], iter, "verify");
        }
        else if (op < 95)
        {
            /* --- address-space churn around the views: private commit +
             * release must not disturb any mapping. */
            void *addr = NULL;
            SIZE_T size = ((rng() % 8) + 1) * PAGE_BYTES;
            status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size,
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "iter %u: churn alloc -> %08lx", iter,
               (unsigned long)status);
            if (status == STATUS_SUCCESS)
            {
                *(volatile char *)addr = 0x5a;
                size = 0;
                status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
                ok(status == STATUS_SUCCESS, "iter %u: churn free -> %08lx", iter,
                   (unsigned long)status);
            }
        }
        else
        {
            /* --- section lifetime churn: if a section has no views, close
             * and recreate it. The new section's frames must read as zero —
             * a nonzero byte convicts frame-reuse without re-zeroing. */
            unsigned sec = rng() % NUM_SECTIONS;
            int busy = 0;
            for (i = 0; i < NUM_SLOTS; i++)
                if (slots[i].base != NULL && slots[i].section == sec)
                    busy = 1;
            if (busy)
                continue;
            status = NtClose(sections[sec]);
            ok(status == STATUS_SUCCESS, "iter %u: close sec %u -> %08lx", iter, sec,
               (unsigned long)status);
            create_section(sec, iter);
        }
    }

    /* --- drain: verify and unmap every remaining view. ---------------------- */

    for (i = 0; i < NUM_SLOTS; i++)
    {
        if (slots[i].base == NULL)
            continue;
        check_view(&slots[i], ITERS + 1, "drain");
        status = NtUnmapViewOfSection(NtCurrentProcess(), slots[i].base);
        ok(status == STATUS_SUCCESS, "drain: unmap %p -> %08lx", (void *)slots[i].base,
           (unsigned long)status);
        slots[i].base = NULL;
    }

    /* Final ground truth: one fresh full view per section against the shadow. */
    for (i = 0; i < NUM_SECTIONS; i++)
    {
        struct view_slot full;
        LARGE_INTEGER offset;
        SIZE_T view_size = 0;

        full.section = i;
        full.offset = 0;
        full.size = SEC_SIZE;
        full.base = NULL;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(sections[i], NtCurrentProcess(), (void **)&full.base, 0, 0,
                                    &offset, &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "final: map sec %u -> %08lx", i, (unsigned long)status);
        if (status != STATUS_SUCCESS)
            continue;
        check_view(&full, ITERS + 2, "final");
        status = NtUnmapViewOfSection(NtCurrentProcess(), full.base);
        ok(status == STATUS_SUCCESS, "final: unmap sec %u -> %08lx", i, (unsigned long)status);
        status = NtClose(sections[i]);
        ok(status == STATUS_SUCCESS, "final: close sec %u -> %08lx", i, (unsigned long)status);
    }

    /* --- named create/open/close churn: the namespace under load. ----------- */

    for (i = 0; i < 8; i++)
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        LARGE_INTEGER max_size, offset;
        HANDLE h1, h2;
        char *view1, *view2;
        SIZE_T view_size;

        init_ustr(&name, W("\\BaseNamedObjects\\proskrnl_stress_sec"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);

        max_size.QuadPart = GRAN;
        h1 = NULL;
        status = NtCreateSection(&h1, SECTION_ALL_ACCESS, &attr, &max_size, PAGE_READWRITE,
                                 SEC_COMMIT, NULL);
        ok(status == STATUS_SUCCESS, "named %u: create -> %08lx", i, (unsigned long)status);
        status = NtOpenSection(&h2, SECTION_MAP_READ | SECTION_MAP_WRITE, &attr);
        ok(status == STATUS_SUCCESS, "named %u: open -> %08lx", i, (unsigned long)status);

        view1 = NULL;
        view_size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(h1, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                    &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "named %u: map h1 -> %08lx", i, (unsigned long)status);
        view2 = NULL;
        view_size = 0;
        offset.QuadPart = 0;
        status = NtMapViewOfSection(h2, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                    &view_size, ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "named %u: map h2 -> %08lx", i, (unsigned long)status);

        ok(view1[7] == 0, "named %u: not zero-filled (%02x)", i, (UCHAR)view1[7]);
        view1[7] = (char)(0x40u + i);
        ok((UCHAR)view2[7] == 0x40u + i, "named %u: handles do not share pages (%02x)", i,
           (UCHAR)view2[7]);

        NtUnmapViewOfSection(NtCurrentProcess(), view1);
        NtUnmapViewOfSection(NtCurrentProcess(), view2);
        NtClose(h1);
        NtClose(h2);

        /* The name must be gone the moment the last reference drops. */
        status = NtOpenSection(&h2, SECTION_MAP_READ, &attr);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "named %u: reopen after close -> %08lx", i,
           (unsigned long)status);
    }
}
