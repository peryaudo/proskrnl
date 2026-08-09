/*
 * sem_mm/region_info.c — NtQueryVirtualMemory(MemoryRegionInformation).
 *
 * docs/21 W5's tail. The class reports the WHOLE reservation, where
 * MemoryBasicInformation reports the run of like-protected pages inside it —
 * that difference is the class's entire reason to exist, so every case here
 * checks both and asserts they disagree where they should.
 *
 * Transcribed from the pinned oracle's get_memory_region_info
 * (third_party/wine dlls/ntdll/unix/virtual.c), whose order is:
 * length, then address range, then "is there a view here", and whose
 * ReturnLength is ALWAYS sizeof(the whole struct) however short the buffer
 * was.
 */
#include "util.h"

#define MEMORY_REGION_INFO_CLASS 3

/* wine/include/winternl.h _MEMORY_REGION_INFORMATION. Declared locally for
 * the same reason the rest of this bucket declares its shapes: mingw's
 * winternl.h does not carry it. The oracle run validates the layout — a
 * wrong offset would move every field's value. */
typedef struct
{
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG RegionType;
    SIZE_T RegionSize;
    SIZE_T CommitSize;
    ULONG_PTR PartitionId;
    ULONG_PTR NodePreference;
} SEM_MEMORY_REGION_INFORMATION;

#define MRI_OFFSET_REGION_SIZE  ((SIZE_T)16)
#define MRI_OFFSET_COMMIT_SIZE  ((SIZE_T)24)
#define MRI_OFFSET_PARTITION_ID ((SIZE_T)32)

static NTSTATUS query_region(void *addr, SEM_MEMORY_REGION_INFORMATION *info, SIZE_T length,
                             SIZE_T *lengthOut)
{
    memset(info, 0x11, sizeof(*info));
    *lengthOut = 0;
    return NtQueryVirtualMemory(NtCurrentProcess(), addr, MEMORY_REGION_INFO_CLASS, info, length,
                                lengthOut);
}

/* A plain reservation: one VAD, nothing committed. */
static void test_reserved(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size = 0x10000, len = 0;
    void *ptr = NULL;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);

    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region query -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "ReturnLength %llx", (unsigned long long)len);
    ok(info.AllocationBase == ptr, "base %p want %p", info.AllocationBase, ptr);
    ok(info.AllocationProtect == PAGE_READWRITE, "protect %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.RegionSize == 0x10000, "size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0, "commit %llx", (unsigned long long)info.CommitSize);
    /* Every RegionType bit stays clear — the oracle does not classify the
     * region at all, and neither does anything that consumes this. */
    ok(info.RegionType == 0, "region type %lx", (unsigned long)info.RegionType);

    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "basic query -> %08lx", (unsigned long)status);
    ok(mbi.RegionSize == info.RegionSize, "basic %llx region %llx",
       (unsigned long long)mbi.RegionSize, (unsigned long long)info.RegionSize);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

/* A fully committed reservation: CommitSize is the whole thing. */
static void test_committed(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    SIZE_T size = 0x10000, len = 0;
    void *ptr = NULL;
    NTSTATUS status;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "commit -> %08lx", (unsigned long)status);

    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region query -> %08lx", (unsigned long)status);
    ok(info.AllocationBase == ptr, "base %p want %p", info.AllocationBase, ptr);
    ok(info.RegionSize == 0x10000, "size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0x10000, "commit %llx", (unsigned long long)info.CommitSize);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

/* THE case that separates this class from MemoryBasicInformation: reserve a
 * run and commit only part of it. MBI describes the sub-run the address
 * falls in; the region describes the whole reservation, and CommitSize
 * counts only the committed pages — a number MBI cannot express at all. */
static void test_partial_commit(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size = 0x10000, len = 0, commitSize;
    void *ptr = NULL, *commitAt;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);

    commitAt = ptr;
    commitSize = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitAt, 0, &commitSize, MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "commit one page -> %08lx", (unsigned long)status);

    /* MBI at the base stops at the end of the committed page. */
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "basic query -> %08lx", (unsigned long)status);
    ok(mbi.RegionSize == 0x1000, "basic size %llx", (unsigned long long)mbi.RegionSize);
    ok(mbi.State == MEM_COMMIT, "basic state %lx", (unsigned long)mbi.State);

    /* The region does not: it is the whole reservation either way. */
    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region query -> %08lx", (unsigned long)status);
    ok(info.RegionSize == 0x10000, "region size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0x1000, "commit %llx", (unsigned long long)info.CommitSize);

    /* And asking from INSIDE the reservation reports the same region, not a
     * region starting at the queried address (the way MBI's BaseAddress
     * does). */
    status = query_region((char *)ptr + 0x5000, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region query mid -> %08lx", (unsigned long)status);
    ok(info.AllocationBase == ptr, "mid base %p want %p", info.AllocationBase, ptr);
    ok(info.RegionSize == 0x10000, "mid size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0x1000, "mid commit %llx", (unsigned long long)info.CommitSize);

    /* An unaligned address inside the reservation rounds down to its page
     * and answers identically — the address is not required to be aligned. */
    status = query_region((char *)ptr + 0x5123, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region query unaligned -> %08lx", (unsigned long)status);
    ok(info.AllocationBase == ptr, "unaligned base %p want %p", info.AllocationBase, ptr);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

/* The LENGTH rule, which is stated in terms of the struct's own field
 * offsets rather than as one size: short of RegionSize is a mismatch, and
 * anything from RegionSize onwards succeeds while filling only what fits.
 * ReturnLength is the WHOLE struct in every accepted case, even when the
 * buffer could not hold it. */
static void test_length_rule(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    SIZE_T size = 0x10000, len = 0;
    void *ptr = NULL;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);

    status = query_region(ptr, &info, MRI_OFFSET_REGION_SIZE, &len);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "len=offsetof(RegionSize) -> %08lx",
       (unsigned long)status);

    status = query_region(ptr, &info, MRI_OFFSET_COMMIT_SIZE, &len);
    ok(status == STATUS_SUCCESS, "len=offsetof(CommitSize) -> %08lx", (unsigned long)status);
    ok(info.RegionSize == 0x10000, "short-buffer size %llx", (unsigned long long)info.RegionSize);

    status = query_region(ptr, &info, MRI_OFFSET_PARTITION_ID, &len);
    ok(status == STATUS_SUCCESS, "len=offsetof(PartitionId) -> %08lx", (unsigned long)status);
    ok(info.CommitSize == 0, "short-buffer commit %llx", (unsigned long long)info.CommitSize);

    /* A length BETWEEN the two offsets. The fill boundary is the next
     * field's offset, not the buffer's end, so 28 bytes gets RegionSize and
     * NOT four bytes of a half-written CommitSize — the caller's own bytes
     * survive there. An implementation that copied min(length, sizeof)
     * would pass every other case in this file and fail this one. */
    memset(&info, 0x11, sizeof(info));
    len = 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_REGION_INFO_CLASS, &info,
                                  MRI_OFFSET_COMMIT_SIZE + 4, &len);
    ok(status == STATUS_SUCCESS, "len=offsetof(CommitSize)+4 -> %08lx", (unsigned long)status);
    ok(info.RegionSize == 0x10000, "mid-length size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == (SIZE_T)0x1111111111111111ULL, "mid-length commit overwritten %llx",
       (unsigned long long)info.CommitSize);

    /* And the LAST TWO fields are never written at any length, including a
     * full-size buffer: the oracle assigns five fields and returns. */
    memset(&info, 0x11, sizeof(info));
    len = 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_REGION_INFO_CLASS, &info,
                                  sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "full length -> %08lx", (unsigned long)status);
    ok(info.PartitionId == (ULONG_PTR)0x1111111111111111ULL, "PartitionId overwritten %llx",
       (unsigned long long)info.PartitionId);
    ok(info.NodePreference == (ULONG_PTR)0x1111111111111111ULL, "NodePreference overwritten %llx",
       (unsigned long long)info.NodePreference);

    /* A buffer LARGER than the struct is accepted, and ReturnLength still
     * reports the struct. */
    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "len=sizeof -> %08lx", (unsigned long)status);
    ok(len == sizeof(info), "ReturnLength %llx", (unsigned long long)len);

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);
}

/* A FREE address is STATUS_INVALID_ADDRESS — not the "here is a free run"
 * answer MemoryBasicInformation gives — and the caller's buffer is left
 * ALONE, which is a separate promise from the status and is checked here
 * with poison the query must not overwrite. */
static void test_free_address(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T size = 0x10000, len = 0xdead;
    void *ptr = NULL;
    NTSTATUS status;

    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);

    /* MemoryBasicInformation still describes the hole. */
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "basic on free -> %08lx", (unsigned long)status);
    ok(mbi.State == MEM_FREE, "basic state %lx", (unsigned long)mbi.State);

    memset(&info, 0xcc, sizeof(info));
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MEMORY_REGION_INFO_CLASS, &info,
                                  sizeof(info), &len);
    ok(status == STATUS_INVALID_ADDRESS, "region on free -> %08lx", (unsigned long)status);
    ok(info.AllocationBase == (void *)(ULONG_PTR)0xccccccccccccccccULL, "base overwritten %p",
       info.AllocationBase);
    ok(info.AllocationProtect == 0xcccccccc, "protect overwritten %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.RegionType == 0xcccccccc, "type overwritten %lx", (unsigned long)info.RegionType);
}

/* An address above the user range is INVALID_PARAMETER, which is a different
 * refusal from INVALID_ADDRESS — the first says the address cannot be asked
 * about, the second that nothing is mapped there. */
static void test_out_of_range(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    SIZE_T len = 0;
    NTSTATUS status;

    status = query_region((void *)(ULONG_PTR)0x7fffffff0000ULL + 0x100000000000ULL, &info,
                          sizeof(info), &len);
    ok(status == STATUS_INVALID_PARAMETER, "kernel address -> %08lx", (unsigned long)status);
}

/* A section view: the region covers the VIEW, and CommitSize does not count
 * a plain read-only mapping's pages. */
static void test_mapped_view(void)
{
    SEM_MEMORY_REGION_INFORMATION info;
    LARGE_INTEGER sectionSize;
    SIZE_T viewSize = 0, len = 0;
    HANDLE section = NULL;
    void *ptr = NULL;
    NTSTATUS status;

    sectionSize.QuadPart = 0x1000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create section -> %08lx", (unsigned long)status);

    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0, 0, NULL, &viewSize, 1, 0,
                                PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map -> %08lx", (unsigned long)status);

    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region on view -> %08lx", (unsigned long)status);
    ok(info.AllocationBase == ptr, "view base %p want %p", info.AllocationBase, ptr);
    ok(info.AllocationProtect == PAGE_READONLY, "view protect %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.RegionSize == 0x1000, "view size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0, "view commit %llx", (unsigned long long)info.CommitSize);
    ok(info.RegionType == 0, "view region type %lx", (unsigned long)info.RegionType);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "unmap -> %08lx", (unsigned long)status);

    /* THE mapped-view subtlety, and it is not guessable from the read-only
     * case above: the SAME section mapped PAGE_WRITECOPY reports the whole
     * view as committed, where PAGE_READONLY reported none of it. A view's
     * pages count toward CommitSize only when they are write-copy, which is
     * the oracle's `vprot_mask |= PAGE_WRITECOPY for a non-valloc view`
     * (get_memory_region_info). A private allocation has no such condition —
     * every committed page counts (test_committed above). */
    ptr = NULL;
    viewSize = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &ptr, 0, 0, NULL, &viewSize, 1, 0,
                                PAGE_WRITECOPY);
    ok(status == STATUS_SUCCESS, "map writecopy -> %08lx", (unsigned long)status);

    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region on writecopy view -> %08lx", (unsigned long)status);
    ok(info.AllocationProtect == PAGE_WRITECOPY, "writecopy protect %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.RegionSize == 0x1000, "writecopy size %llx", (unsigned long long)info.RegionSize);
    ok(info.CommitSize == 0x1000, "writecopy commit %llx", (unsigned long long)info.CommitSize);

    /* STILL the whole view after a STORE into it. Worth its own assertion
     * because the store is what a copy-on-write implementation would react
     * to: if the write ever transitioned the page's recorded protection away
     * from write-copy, CommitSize would silently drop to 0 here and nowhere
     * else in this file would notice. */
    *(volatile int *)ptr = 1;
    status = query_region(ptr, &info, sizeof(info), &len);
    ok(status == STATUS_SUCCESS, "region after store -> %08lx", (unsigned long)status);
    ok(info.AllocationProtect == PAGE_WRITECOPY, "after-store protect %lx",
       (unsigned long)info.AllocationProtect);
    ok(info.CommitSize == 0x1000, "after-store commit %llx", (unsigned long long)info.CommitSize);

    status = NtUnmapViewOfSection(NtCurrentProcess(), ptr);
    ok(status == STATUS_SUCCESS, "unmap writecopy -> %08lx", (unsigned long)status);
    NtClose(section);
}

START_TEST(region_info)
{
    test_reserved();
    test_committed();
    test_partial_commit();
    test_length_rule();
    test_free_address();
    test_out_of_range();
    test_mapped_view();
}
