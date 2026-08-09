/*
 * sem_ps/thread_stack_alloc.c — NtSetInformationProcess(
 * ProcessThreadStackAllocation) RESERVES a thread stack and hands its base
 * back in the caller's buffer.
 *
 * docs/21 W5 (the ntdll:virtual thread-stack cluster). This class is the one
 * kernel call `RtlCreateUserStack` makes (third_party/wine dlls/ntdll/thread.c):
 *
 *     alloc.ReserveSize = reserve;
 *     alloc.ZeroBits    = zero_bits;
 *     status = NtSetInformationProcess( GetCurrentProcess(),
 *                                       ProcessThreadStackAllocation,
 *                                       &alloc, sizeof(alloc) );
 *     if (!status) { ... commit a guard page at alloc.StackBase + page_size,
 *                        commit the rest, and report alloc.StackBase as the
 *                        stack's DeallocationStack. }
 *
 * `alloc` is an UNINITIALISED local. So a kernel whose NtSetInformationProcess
 * accepts this class as a harmless no-op does not merely lose a reservation:
 * it returns STATUS_SUCCESS over a StackBase the caller never wrote, and the
 * caller then commits pages at, and later runs on, whatever was in that stack
 * slot. That is Art. 12's fabricated answer in its most expensive form — the
 * status is right, every field the caller checks is self-consistent (the
 * reserve is `StackBase - DeallocationStack` by construction), and the lie is
 * only visible by asking the memory manager what is actually AT that address.
 * `CreateFiberEx` takes the same route (dlls/kernelbase/thread.c), so every
 * fiber gets its stack from this call too.
 *
 * The pinned oracle's whole implementation is one MEM_RESERVE allocation
 * (dlls/ntdll/unix/process.c, `case ProcessThreadStackAllocation`), and the
 * three things below are the parts an implementation can plausibly get wrong.
 *
 *   - THE LENGTH SELECTS THE STRUCT, and there are two of them. `size ==
 *     sizeof(PROCESS_STACK_ALLOCATION_INFORMATION_EX)` means the _EX form and
 *     the reservation is described by its embedded AllocInfo; any other size
 *     but the plain struct's is STATUS_INFO_LENGTH_MISMATCH. There is no
 *     version field and no flag — the length IS the discriminator.
 *
 *   - ZeroBits IS THE PLACEMENT CEILING, passed straight to
 *     NtAllocateVirtualMemory, so this class inherits that syscall's whole
 *     zero_bits contract: the 22..31 and 33..0xfffe bands are
 *     STATUS_INVALID_PARAMETER_3, a count below 22 bounds the address, and a
 *     ceiling too low for the requested reserve is STATUS_NO_MEMORY rather
 *     than a parameter error. A kernel that validated ZeroBits and then
 *     dropped it answers every status here correctly and places the stack
 *     anywhere — which is what ntdll:virtual:1403/:1424 measure.
 *
 *   - THE HANDLE IS NEVER READ. The oracle's arm calls
 *     `NtAllocateVirtualMemory( GetCurrentProcess(), ... )` unconditionally,
 *     with no reference to its own `handle` argument, so the reservation is
 *     always in the CALLER and a handle that resolves to nothing is not an
 *     error. That is measured here rather than argued: it is the difference
 *     between this class and every neighbouring one in the same switch, and
 *     an implementation that "tidily" resolved the handle first would refuse
 *     a call the oracle serves.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);

/* wine/include/winternl.h (mingw's _PROCESSINFOCLASS stops short of it); a
 * wrong number would answer STATUS_INVALID_INFO_CLASS on the oracle. */
#define PS_ProcessThreadStackAllocation ((PROCESSINFOCLASS)41)

/* MemoryBasicInformation, as sem_mm/util.h spells it. */
#define PS_MEMORY_BASIC_INFO_CLASS 0

/* wine/include/winternl.h PROCESS_STACK_ALLOCATION_INFORMATION{,_EX}, in the
 * snake_case the tests use for structs the system headers omit. */
typedef struct
{
    SIZE_T reserve_size;
    SIZE_T zero_bits;
    PVOID stack_base;
} ps_stack_alloc;

typedef struct
{
    ULONG preferred_node;
    ULONG reserved0;
    ULONG reserved1;
    ULONG reserved2;
    ps_stack_alloc alloc_info;
} ps_stack_alloc_ex;

/* One megabyte: NT's own minimum stack reserve, and the size
 * RtlCreateUserStack floors every request at. */
#define PS_STACK_RESERVE 0x100000

/* A value no reservation can return, so "the field was not written" is
 * distinguishable from "the field was written with something odd". The
 * winetest uses the same sentinel (dlls/ntdll/tests/info.c test_threadstack). */
#define PS_STACK_POISON ((PVOID)(ULONG_PTR)0xdeadbeef)

/* The whole reservation, exactly as it must look to the memory manager. */
static void check_reservation(PVOID base, SIZE_T reserve, const char *what)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T retlen = 0;
    NTSTATUS status;

    memset(&mbi, 0xcc, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, PS_MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), &retlen);
    ok(status == STATUS_SUCCESS, "%s: query %p -> %08lx", what, base, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ok(retlen == sizeof(mbi), "%s: ReturnLength %llu", what, (unsigned long long)retlen);
    ok(mbi.AllocationBase == base, "%s: AllocationBase %p, wanted %p", what, mbi.AllocationBase,
       base);
    ok(mbi.BaseAddress == base, "%s: BaseAddress %p, wanted %p", what, mbi.BaseAddress, base);
    /* The reservation is ONE region: nothing inside it is committed yet, so
     * the like-state run starting at its base is the whole of it. */
    ok(mbi.RegionSize == reserve, "%s: RegionSize %llx, wanted %llx", what,
       (unsigned long long)mbi.RegionSize, (unsigned long long)reserve);
    ok(mbi.State == MEM_RESERVE, "%s: State %lx", what, (unsigned long)mbi.State);
    /* Reserved-but-uncommitted pages have no protection of their own; the
     * PAGE_READWRITE the reservation was made with survives as the
     * ALLOCATION protection, which is what the guard-page commit above it
     * later inherits. */
    ok(mbi.Protect == 0, "%s: Protect %lx", what, (unsigned long)mbi.Protect);
    ok(mbi.AllocationProtect == PAGE_READWRITE, "%s: AllocationProtect %lx", what,
       (unsigned long)mbi.AllocationProtect);
    ok(mbi.Type == MEM_PRIVATE, "%s: Type %lx", what, (unsigned long)mbi.Type);
}

static void release(PVOID base)
{
    SIZE_T size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
}

/* One call that must be refused, with the caller's StackBase left alone.
 * The oracle writes StackBase only on the success arm — a refusal that
 * scribbled a plausible pointer would be the same defect this file is
 * about, one status further along. */
static void expect_refusal(SIZE_T zeroBits, NTSTATUS wanted, const char *what)
{
    ps_stack_alloc alloc;
    NTSTATUS status;

    alloc.reserve_size = PS_STACK_RESERVE;
    alloc.zero_bits = zeroBits;
    alloc.stack_base = PS_STACK_POISON;
    status = NtSetInformationProcess(NtCurrentProcess(), PS_ProcessThreadStackAllocation, &alloc,
                                     sizeof(alloc));
    ok(status == wanted, "%s -> %08lx, wanted %08lx", what, (unsigned long)status,
       (unsigned long)wanted);
    ok(alloc.stack_base == PS_STACK_POISON, "%s: StackBase written (%p) on a refusal", what,
       alloc.stack_base);
    if (NT_SUCCESS(status))
    {
        release(alloc.stack_base);
    }
}

/* A wrong length, asked of both spellings. */
static void expect_length_mismatch(ULONG length, const char *what)
{
    ps_stack_alloc_ex ex;
    NTSTATUS status;

    memset(&ex, 0, sizeof(ex));
    ex.alloc_info.reserve_size = PS_STACK_RESERVE;
    ex.alloc_info.stack_base = PS_STACK_POISON;
    status =
        NtSetInformationProcess(NtCurrentProcess(), PS_ProcessThreadStackAllocation, &ex, length);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "%s -> %08lx", what, (unsigned long)status);
    ok(ex.alloc_info.stack_base == PS_STACK_POISON, "%s: StackBase written (%p)", what,
       ex.alloc_info.stack_base);
}

START_TEST(thread_stack_alloc)
{
    ps_stack_alloc alloc;
    ps_stack_alloc_ex ex;
    NTSTATUS status;

    /* The lengths below only mean what the oracle means by them if the two
     * structs are the pinned tree's structs. */
    ok(sizeof(alloc) == 24, "PROCESS_STACK_ALLOCATION_INFORMATION is %llu bytes",
       (unsigned long long)sizeof(alloc));
    ok(sizeof(ex) == 40, "PROCESS_STACK_ALLOCATION_INFORMATION_EX is %llu bytes",
       (unsigned long long)sizeof(ex));

    /* --- the call RtlCreateUserStack makes ------------------------------- */
    alloc.reserve_size = PS_STACK_RESERVE;
    alloc.zero_bits = 0;
    alloc.stack_base = PS_STACK_POISON;
    status = NtSetInformationProcess(NtCurrentProcess(), PS_ProcessThreadStackAllocation, &alloc,
                                     sizeof(alloc));
    ok(status == STATUS_SUCCESS, "plain form -> %08lx", (unsigned long)status);
    ok(alloc.stack_base != PS_STACK_POISON, "plain form: StackBase not written");
    ok(alloc.stack_base != NULL, "plain form: StackBase is NULL");
    /* A reservation is granularity-aligned, which is stricter than the page
     * alignment RtlCreateUserStack checks (:1340). */
    ok(((ULONG_PTR)alloc.stack_base & 0xffff) == 0, "plain form: StackBase %p unaligned",
       alloc.stack_base);
    check_reservation(alloc.stack_base, PS_STACK_RESERVE, "plain form");

    /* --- the _EX form, selected by LENGTH alone -------------------------- */
    memset(&ex, 0, sizeof(ex));
    ex.alloc_info.reserve_size = PS_STACK_RESERVE;
    ex.alloc_info.zero_bits = 0;
    ex.alloc_info.stack_base = PS_STACK_POISON;
    status = NtSetInformationProcess(NtCurrentProcess(), PS_ProcessThreadStackAllocation, &ex,
                                     sizeof(ex));
    ok(status == STATUS_SUCCESS, "ex form -> %08lx", (unsigned long)status);
    ok(ex.alloc_info.stack_base != PS_STACK_POISON, "ex form: StackBase not written");
    /* A SECOND reservation, not a re-report of the first: an implementation
     * that read the _EX form's AllocInfo at the wrong offset would either
     * fault or hand back a duplicate. */
    ok(ex.alloc_info.stack_base != alloc.stack_base, "ex form: same base as the plain form (%p)",
       ex.alloc_info.stack_base);
    check_reservation(ex.alloc_info.stack_base, PS_STACK_RESERVE, "ex form");
    release(ex.alloc_info.stack_base);
    release(alloc.stack_base);

    /* --- every other length is a mismatch, for BOTH structs -------------- */
    expect_length_mismatch(sizeof(alloc) - 1, "sizeof - 1");
    expect_length_mismatch(sizeof(alloc) + 1, "sizeof + 1");
    expect_length_mismatch(sizeof(ex) - 1, "sizeof(ex) - 1");
    expect_length_mismatch(sizeof(ex) + 1, "sizeof(ex) + 1");
    expect_length_mismatch(0, "zero length");

    /* --- ZeroBits is NtAllocateVirtualMemory's, band for band ------------ */

    /* 22..31: the count band NtAllocateVirtualMemory refuses outright, and
     * the refusal names ITS third argument even though ZeroBits is a struct
     * field here — the class forwards the status unchanged. */
    expect_refusal(25, STATUS_INVALID_PARAMETER_3, "ZeroBits 25");
    /* 33..0xfffe: the gap between "a count" and "a mask" on the allocation
     * path (the mapping path has no such gap — sem_mm/map_zero_bits.c). */
    expect_refusal(33, STATUS_INVALID_PARAMETER_3, "ZeroBits 33");
    /* A ceiling of 2^20 cannot hold a 1 MiB reservation above the lowest
     * usable address, and running out of room is NOT a parameter error. */
    expect_refusal(12, STATUS_NO_MEMORY, "ZeroBits 12");

    /* A count that CAN be satisfied bounds the whole reservation, last byte
     * included — the ceiling is on the extent, not on the base. */
    alloc.reserve_size = PS_STACK_RESERVE;
    alloc.zero_bits = 4;
    alloc.stack_base = PS_STACK_POISON;
    status = NtSetInformationProcess(NtCurrentProcess(), PS_ProcessThreadStackAllocation, &alloc,
                                     sizeof(alloc));
    ok(status == STATUS_SUCCESS, "ZeroBits 4 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ULONG_PTR last = (ULONG_PTR)alloc.stack_base + PS_STACK_RESERVE - 1;
        ok(last < ((ULONG_PTR)1 << 28), "ZeroBits 4: reservation ends at %llx",
           (unsigned long long)last);
        check_reservation(alloc.stack_base, PS_STACK_RESERVE, "ZeroBits 4");
        release(alloc.stack_base);
    }

    /* --- the handle is not consulted ------------------------------------
     * The oracle's arm allocates in GetCurrentProcess() and never mentions
     * its own `handle`, so a handle that resolves to nothing still reserves
     * a stack — in the CALLER, which is why the query below can find it. No
     * consumer passes a foreign handle (RtlCreateUserStack and CreateFiberEx
     * both pass the pseudo-handle), so this pins the oracle's measured
     * behaviour rather than a contract anything depends on. */
    alloc.reserve_size = PS_STACK_RESERVE;
    alloc.zero_bits = 0;
    alloc.stack_base = PS_STACK_POISON;
    status = NtSetInformationProcess((HANDLE)(ULONG_PTR)0xdeadbeef, PS_ProcessThreadStackAllocation,
                                     &alloc, sizeof(alloc));
    ok(status == STATUS_SUCCESS, "junk handle -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_reservation(alloc.stack_base, PS_STACK_RESERVE, "junk handle");
        release(alloc.stack_base);
    }
}
