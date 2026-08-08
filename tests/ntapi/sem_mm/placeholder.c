/*
 * sem_mm/placeholder.c — the VirtualAlloc2 PLACEHOLDER contract: a reserved
 * hole that can be split, coalesced, and swapped for a real allocation
 * without ever losing its address range (docs/21 W5).
 *
 * A placeholder is not "a reservation with a flag on it". It is a distinct
 * state of a range, and the four flags below are the only transitions
 * between it and ordinary memory:
 *
 *   MEM_RESERVE_PLACEHOLDER   (alloc) create one
 *   MEM_REPLACE_PLACEHOLDER   (alloc) turn one, EXACTLY, into an allocation
 *   MEM_PRESERVE_PLACEHOLDER  (free)  give the range back AS a placeholder
 *   MEM_COALESCE_PLACEHOLDERS (free)  merge adjacent placeholders into one
 *
 * Three properties are what make this worth pinning separately from the
 * ordinary reserve/commit rules (sem_mm/reserve_commit.c), because each is
 * invisible to a test that only checks whether a call succeeded:
 *
 *   1. WHICH range the transition applies to is exact. A replace that does
 *      not cover the whole placeholder, a coalesce whose base is one page
 *      into the run, a coalesce whose size stops mid-placeholder — all
 *      STATUS_CONFLICTING_ADDRESSES, not a partial success.
 *   2. WHETHER the range came from a placeholder is remembered. Releasing
 *      the whole of an ordinary reservation with MEM_PRESERVE_PLACEHOLDER
 *      is refused; releasing the whole of a placeholder REPLACEMENT is how
 *      you get the placeholder back. The two calls are textually identical
 *      and differ only in the range's history.
 *   3. A split leaves REAL, separately-addressable regions. Each piece
 *      reports its own AllocationBase and RegionSize, which is the only way
 *      to see that a split happened at all.
 *
 * Oracle-first (G5): every assertion here is measured on the pinned Wine
 * (dlls/ntdll/unix/virtual.c — allocate_virtual_memory's placeholder arms,
 * free_pages_preserve_placeholder, coalesce_placeholders) before the kernel
 * implements any of it.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, PVOID,
                                                  ULONG);

/* mingw's winnt.h carries all four flags; cross-check against wine
 * include/winnt.h (MEM_REPLACE_PLACEHOLDER 0x00004000, MEM_RESERVE_PLACEHOLDER
 * 0x00040000, MEM_COALESCE_PLACEHOLDERS 0x00000001, MEM_PRESERVE_PLACEHOLDER
 * 0x00000002) — the same values abi/ntmmapi.h generates. */

#define PH_SIZE 0x10000 /* one 64K allocation granule */

static NTSTATUS ph_alloc(void **base, SIZE_T *size, ULONG type, ULONG protect)
{
    return NtAllocateVirtualMemoryEx(NtCurrentProcess(), base, size, type, protect, NULL, 0);
}

static NTSTATUS ph_free(void *base, SIZE_T *size, ULONG type)
{
    void *p = base;
    return NtFreeVirtualMemory(NtCurrentProcess(), &p, size, type);
}

/* MemoryBasicInformation over `p`, reported through the caller's struct so a
 * failing assertion can name the field that disagreed. */
static NTSTATUS ph_query(const void *p, MEMORY_BASIC_INFORMATION *mbi)
{
    SIZE_T got = 0;
    return NtQueryVirtualMemory(NtCurrentProcess(), p, MEMORY_BASIC_INFO_CLASS, mbi, sizeof(*mbi),
                                &got);
}

/* "This range is a placeholder of exactly `size` bytes, standing alone."
 * AllocationBase is the discriminator a split is visible through: after a
 * split each piece is its OWN allocation, not an offset into the original. */
#define expect_placeholder(p, size) expect_region((p), (p), (size), MEM_RESERVE, PAGE_NOACCESS, #p)

/* `allocBase` is separate from `p` because a merged placeholder can report a
 * run that STARTS inside its allocation: RegionSize is the extent of like
 * pages, AllocationBase the extent of the reservation, and the two stop
 * agreeing the moment one allocation holds pages in two states. */
static void expect_region(const void *p, const void *allocBase, SIZE_T size, ULONG state,
                          ULONG allocProtect, const char *what)
{
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS status;

    memset(&mbi, 0, sizeof(mbi));
    status = ph_query(p, &mbi);
    ok(status == STATUS_SUCCESS, "%s: query -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ok(mbi.AllocationBase == allocBase, "%s: AllocationBase %p, want %p", what, mbi.AllocationBase,
       allocBase);
    ok(mbi.RegionSize == size, "%s: RegionSize %llx, want %llx", what,
       (unsigned long long)mbi.RegionSize, (unsigned long long)size);
    ok(mbi.State == state, "%s: State %lx, want %lx", what, (unsigned long)mbi.State,
       (unsigned long)state);
    ok(mbi.Type == MEM_PRIVATE, "%s: Type %lx, want MEM_PRIVATE", what, (unsigned long)mbi.Type);
    ok(mbi.AllocationProtect == allocProtect, "%s: AllocationProtect %lx, want %lx", what,
       (unsigned long)mbi.AllocationProtect, (unsigned long)allocProtect);
}

START_TEST(placeholder)
{
    NTSTATUS status;
    void *base;
    char *p;
    SIZE_T size;

    /* --- the classic entry point has no placeholders at all --------------
     * MEM_RESERVE_PLACEHOLDER is outside NtAllocateVirtualMemory's type
     * mask, so it is a bad flag rather than an unsupported request. The
     * distinction matters: VirtualAlloc2 is the ONLY documented way in, and
     * a caller that reaches for the old entry point must be told the
     * argument is wrong, not that the range is busy. */
    base = NULL;
    size = PH_SIZE;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                     MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_INVALID_PARAMETER, "classic reserve-placeholder -> %08lx",
       (unsigned long)status);

    /* --- creating one ---------------------------------------------------
     * A placeholder describes no memory, so it can carry no access: any
     * protection but PAGE_NOACCESS is refused. This is checked BEFORE the
     * range is looked at (base is still NULL here, so there is no range). */
    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "placeholder PAGE_READWRITE -> %08lx",
       (unsigned long)status);

    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_READONLY);
    ok(status == STATUS_INVALID_PARAMETER, "placeholder PAGE_READONLY -> %08lx",
       (unsigned long)status);

    /* MEM_RESERVE_PLACEHOLDER without MEM_RESERVE: the placeholder bit is a
     * MODIFIER on a reserve, never a request of its own. */
    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_INVALID_PARAMETER, "bare reserve-placeholder -> %08lx",
       (unsigned long)status);

    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "reserve placeholder -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        skip("no placeholder to work with");
        return;
    }
    p = base;
    expect_placeholder(p, PH_SIZE);

    /* --- a placeholder is OCCUPIED, not free ----------------------------
     * Every ordinary way of taking the range is refused with the "somebody
     * already has this" answer, including a second placeholder reserve.
     * A commit is the one that would be easy to get wrong: the range IS
     * reserved, so a commit-into-reservation path that does not know about
     * placeholders would quietly succeed. */
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "re-reserve placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE, PAGE_NOACCESS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "plain reserve over placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "commit into placeholder -> %08lx",
       (unsigned long)status);

    /* --- replacing one --------------------------------------------------
     * MEM_REPLACE_PLACEHOLDER is a modifier too, and it is checked against
     * the flag mask before the range: without MEM_RESERVE it is a parameter
     * error even when the range it names is a perfectly good placeholder. */
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "bare replace-placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER, "commit replace-placeholder -> %08lx",
       (unsigned long)status);

    /* A replacement is all-or-nothing: a sub-range does not split the
     * placeholder, it fails. Splitting is MEM_PRESERVE_PLACEHOLDER's job
     * and it has to be done first. */
    size = 0x1000;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "partial replace -> %08lx", (unsigned long)status);
    expect_placeholder(p, PH_SIZE);

    /* The whole placeholder, committed in the same call. The pages are
     * ordinary private memory afterwards -- writable, and reported with the
     * protection the replacement asked for rather than the placeholder's
     * PAGE_NOACCESS. */
    size = PH_SIZE;
    status =
        ph_alloc(&base, &size, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "replace placeholder -> %08lx", (unsigned long)status);
    expect_region(p, p, PH_SIZE, MEM_COMMIT, PAGE_READWRITE, "replacement");
    memset(p, 0xcc, PH_SIZE);

    /* --- giving it back -------------------------------------------------
     * The replacement remembers what it replaced. Releasing all of it with
     * MEM_PRESERVE_PLACEHOLDER hands the range back in its original state:
     * a placeholder, PAGE_NOACCESS, same base, same size. The memory is
     * genuinely gone -- the next replacement reads zeroes, not 0xcc. */
    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "release-preserve replacement -> %08lx", (unsigned long)status);
    ok(size == PH_SIZE, "release-preserve size %llx", (unsigned long long)size);
    expect_placeholder(p, PH_SIZE);

    size = PH_SIZE;
    status =
        ph_alloc(&base, &size, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "second replace -> %08lx", (unsigned long)status);
    ok(*(volatile unsigned int *)p == 0, "replacement not zeroed: %08x",
       *(volatile unsigned int *)p);

    /* Releasing the WHOLE of a placeholder that is already a placeholder
     * changes nothing, and NT refuses rather than succeeding vacuously. */
    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "release-preserve again -> %08lx", (unsigned long)status);
    expect_placeholder(p, PH_SIZE);

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "release-preserve whole placeholder -> %08lx",
       (unsigned long)status);

    /* A zero size is a parameter error and names WHICH parameter. */
    size = 0;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_INVALID_PARAMETER_3, "release-preserve size 0 -> %08lx",
       (unsigned long)status);
    ok(size == 0, "release-preserve size 0 wrote %llx", (unsigned long long)size);

    /* --- splitting ------------------------------------------------------
     * A sub-range release-preserve is the split primitive. Head, middle and
     * tail each behave differently in how many pieces they leave, and each
     * piece is its own allocation from then on. */
    size = 0x4000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "split head -> %08lx", (unsigned long)status);
    ok(size == 0x4000, "split head size %llx", (unsigned long long)size);
    expect_placeholder(p, 0x4000);
    expect_placeholder(p + 0x4000, 0xc000);

    size = 0x4000;
    status = ph_free(p + 0x8000, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "split middle -> %08lx", (unsigned long)status);
    expect_placeholder(p, 0x4000);
    expect_placeholder(p + 0x4000, 0x4000);
    expect_placeholder(p + 0x8000, 0x4000);
    expect_placeholder(p + 0xc000, 0x4000);

    /* --- coalescing -----------------------------------------------------
     * The inverse, and it is exacting about its range. MEM_COALESCE_
     * PLACEHOLDERS is a modifier on MEM_RELEASE (alone it is a parameter
     * error naming argument 4), the size may not be zero, and the range
     * must start at a placeholder's base and end at a placeholder's end
     * while covering more than one of them. */
    size = PH_SIZE;
    status = ph_free(p, &size, MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_INVALID_PARAMETER_4, "coalesce without release -> %08lx",
       (unsigned long)status);

    size = 0;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_INVALID_PARAMETER_3, "coalesce size 0 -> %08lx", (unsigned long)status);

    size = 0x4000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce one placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE + 0x1000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce past the end -> %08lx",
       (unsigned long)status);

    size = PH_SIZE - 0x1000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce stopping mid-placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE - 0x1000;
    status = ph_free(p + 0x1000, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce from mid-placeholder -> %08lx",
       (unsigned long)status);

    /* Two adjacent pieces, then all four -- proving the merged region is a
     * placeholder again and can be merged FURTHER, rather than a special
     * once-only join. */
    size = 0x8000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_SUCCESS, "coalesce two -> %08lx", (unsigned long)status);
    ok(size == 0x8000, "coalesce two size %llx", (unsigned long long)size);
    expect_placeholder(p, 0x8000);
    expect_placeholder(p + 0x8000, 0x4000);

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_SUCCESS, "coalesce all -> %08lx", (unsigned long)status);
    expect_placeholder(p, PH_SIZE);

    /* --- what is NOT a placeholder --------------------------------------
     * A range whose history has no placeholder in it refuses both verbs,
     * and this is the whole point of tracking the state rather than
     * inferring it from "reserved and PAGE_NOACCESS". The reservation below
     * is indistinguishable from a placeholder in every field
     * MEMORY_BASIC_INFORMATION reports. */
    size = 0x4000;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "replace part of placeholder -> %08lx",
       (unsigned long)status);

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release placeholder -> %08lx", (unsigned long)status);
    ok(size == PH_SIZE, "release placeholder size %llx", (unsigned long long)size);

    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "plain reserve -> %08lx", (unsigned long)status);
    p = base;
    expect_region(p, p, PH_SIZE, MEM_RESERVE, PAGE_NOACCESS, "plain reserve");

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "release-preserve plain reserve -> %08lx",
       (unsigned long)status);
    ok(size == PH_SIZE, "release-preserve plain reserve size %llx", (unsigned long long)size);

    size = 0x4000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "split plain reserve -> %08lx",
       (unsigned long)status);

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release plain reserve -> %08lx", (unsigned long)status);

    /* --- a coalesce needs placeholders on BOTH sides ---------------------
     * A placeholder next to a replacement, and a placeholder next to a
     * hole, are both refused. The second is the one that says the check is
     * "is that range a placeholder", not "is that range not-mine". */
    base = NULL;
    size = PH_SIZE;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "reserve placeholder 2 -> %08lx", (unsigned long)status);
    p = base;

    size = 0x8000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "split in half -> %08lx", (unsigned long)status);

    base = p + 0x8000;
    size = 0x8000;
    status = ph_alloc(&base, &size, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "replace upper half -> %08lx", (unsigned long)status);
    expect_region(p + 0x8000, p + 0x8000, 0x8000, MEM_RESERVE, PAGE_READWRITE, "upper replacement");

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce onto a replacement -> %08lx",
       (unsigned long)status);

    size = 0x8000;
    status = ph_free(p + 0x8000, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release upper half -> %08lx", (unsigned long)status);

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_CONFLICTING_ADDRESSES, "coalesce onto a hole -> %08lx",
       (unsigned long)status);

    size = 0x8000;
    status = ph_free(p, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release lower half -> %08lx", (unsigned long)status);

    /* --- a placeholder created with MEM_COMMIT ---------------------------
     * PAGE_NOACCESS is the only protection a placeholder may carry and
     * MEM_COMMIT does not conflict with it, so this combination is accepted
     * — a placeholder that is nonetheless holding pages. It is worth a case
     * of its own because it breaks the assumption "a free placeholder has
     * nothing committed", which every merge and split here would otherwise
     * be entitled to make: coalescing throws the per-page records of the
     * whole run away, and a page whose last record is discarded is leaked
     * with a live mapping still pointing at it. Splitting and merging it
     * back must therefore behave exactly as for an empty one.
     *
     * The split is also where the ASYMMETRY of MEM_PRESERVE_PLACEHOLDER
     * becomes visible: only the range the caller NAMED is emptied. The
     * remainder keeps its pages and still reports MEM_COMMIT, which is the
     * same rule a partially-preserved replacement follows and the reason
     * this must not be implemented as "decommit the VAD, then split". */
    base = NULL;
    size = PH_SIZE;
    status =
        ph_alloc(&base, &size, MEM_RESERVE | MEM_COMMIT | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "committed placeholder -> %08lx", (unsigned long)status);
    p = base;

    size = 0x8000;
    status = ph_free(p, &size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
    ok(status == STATUS_SUCCESS, "split committed placeholder -> %08lx", (unsigned long)status);
    expect_placeholder(p, 0x8000);
    expect_region(p + 0x8000, p + 0x8000, 0x8000, MEM_COMMIT, PAGE_NOACCESS, "committed remainder");

    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(status == STATUS_SUCCESS, "coalesce committed placeholder -> %08lx", (unsigned long)status);
    /* The merge CARRIES the pages rather than emptying them, so the run
     * still breaks in the middle: one allocation of 0x10000, reserved for
     * the first half and committed for the second. RegionSize reports the
     * run of like pages, not the allocation. */
    expect_region(p, p, 0x8000, MEM_RESERVE, PAGE_NOACCESS, "merged reserved half");
    expect_region(p + 0x8000, p, 0x8000, MEM_COMMIT, PAGE_NOACCESS, "merged committed half");

    /* The merged range is one allocation again, so one release takes it. */
    size = PH_SIZE;
    status = ph_free(p, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release committed placeholder -> %08lx", (unsigned long)status);
    ok(size == PH_SIZE, "release committed placeholder size %llx", (unsigned long long)size);
}
