/*
 * sem_ps/misaligned_out.c — the time queries WRITE through a 4-aligned
 * pointer.
 *
 * The other half of sem_wait/misaligned_timeout.c's contract: the time
 * queries return their result through a `LARGE_INTEGER *` the CALLER owns,
 * and nothing in the WOW64 path re-aligns it — the pinned Wine's thunks hand
 * the 32-bit pointer straight down (dlls/wow64/sync.c
 * wow64_NtQueryPerformanceCounter, dlls/wow64/system.c
 * wow64_NtQuerySystemTime both just `get_ptr` it). A 32-bit caller's stack
 * LARGE_INTEGER is only 4-byte aligned, so the output address a 64-bit
 * kernel writes is routinely at `addr % 8 == 4`.
 *
 * That is the ORDINARY shape of a WOW64 time query, not a hostile input.
 * This is the divergence that stalled SAFlashPlayer.exe (tests/flash/): the
 * projector's timeline polls NtQueryPerformanceCounter through i386 stack
 * locals, every 4-mod-8 call answered STATUS_DATATYPE_MISALIGNMENT, Wine's
 * PE callers do not check the status, and the movie paced itself off the
 * uninitialized stack garbage left in the buffer.
 *
 * Each case asserts the value was really WRITTEN, not just the status: a
 * counter read through a misaligned pointer must land between two aligned
 * reads bracketing it (the counter is monotone), and the frequency must
 * equal the one an aligned call reports.
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);

/* A 4-mod-8 output slot. Same construction as misaligned_timeout.c: the
 * address is derived from a byte array and read back through memcpy — a
 * `LARGE_INTEGER *` cast of a misaligned address is UB in the TEST too. */
static unsigned char slab[64];

static PLARGE_INTEGER misaligned_slot(unsigned which)
{
    unsigned char *at = (unsigned char *)((((ULONG_PTR)slab + 8) & ~(ULONG_PTR)7) + 4 + which * 16);
    memset(at, 0xa5, sizeof(LARGE_INTEGER)); /* poison: "unwritten" is visible */
    return (PLARGE_INTEGER)at;
}

static LONGLONG slot_value(PLARGE_INTEGER slot)
{
    LONGLONG value;
    memcpy(&value, slot, sizeof(value));
    return value;
}

START_TEST(misaligned_out)
{
    NTSTATUS status;
    LARGE_INTEGER before, after, freqAligned;
    PLARGE_INTEGER counter = misaligned_slot(0);
    PLARGE_INTEGER frequency = misaligned_slot(1);
    PLARGE_INTEGER time = misaligned_slot(2);

    ok(((ULONG_PTR)counter & 7) == 4, "counter slot is 4-mod-8 (%p)", (void *)counter);

    /* NtQueryPerformanceCounter: the counter through a 4-aligned pointer,
     * bracketed by aligned reads so the WRITE is asserted, not the status. */
    status = NtQueryPerformanceCounter(&before, NULL);
    ok(status == STATUS_SUCCESS, "aligned QPC -> %08lx", (unsigned long)status);
    status = NtQueryPerformanceCounter(counter, NULL);
    ok(status == STATUS_SUCCESS, "QPC(counter 4-aligned) -> %08lx", (unsigned long)status);
    status = NtQueryPerformanceCounter(&after, NULL);
    ok(status == STATUS_SUCCESS, "aligned QPC -> %08lx", (unsigned long)status);
    ok(slot_value(counter) >= before.QuadPart && slot_value(counter) <= after.QuadPart,
       "misaligned counter %llx between aligned brackets %llx..%llx",
       (unsigned long long)slot_value(counter), (unsigned long long)before.QuadPart,
       (unsigned long long)after.QuadPart);

    /* The optional frequency out-pointer, 4-aligned, against an aligned call. */
    status = NtQueryPerformanceCounter(&before, &freqAligned);
    ok(status == STATUS_SUCCESS, "aligned QPC+freq -> %08lx", (unsigned long)status);
    status = NtQueryPerformanceCounter(counter, frequency);
    ok(status == STATUS_SUCCESS, "QPC(freq 4-aligned) -> %08lx", (unsigned long)status);
    ok(slot_value(frequency) == freqAligned.QuadPart,
       "misaligned frequency %llx == aligned frequency %llx",
       (unsigned long long)slot_value(frequency), (unsigned long long)freqAligned.QuadPart);

    /* NtQuerySystemTime through a 4-aligned pointer, bracketed the same way
     * (system time is monotone over a bracketed read). */
    status = NtQuerySystemTime(&before);
    ok(status == STATUS_SUCCESS, "aligned NtQuerySystemTime -> %08lx", (unsigned long)status);
    status = NtQuerySystemTime(time);
    ok(status == STATUS_SUCCESS, "NtQuerySystemTime(4-aligned) -> %08lx", (unsigned long)status);
    status = NtQuerySystemTime(&after);
    ok(status == STATUS_SUCCESS, "aligned NtQuerySystemTime -> %08lx", (unsigned long)status);
    ok(slot_value(time) >= before.QuadPart && slot_value(time) <= after.QuadPart,
       "misaligned system time %llx between %llx..%llx", (unsigned long long)slot_value(time),
       (unsigned long long)before.QuadPart, (unsigned long long)after.QuadPart);
}
