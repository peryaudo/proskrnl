/*
 * sem_ps/entropy.c — SystemInterruptInformation as the entropy source
 * (CUI-3). cryptbase's RtlGenRandom (SystemFunction036) fills its pool
 * from this class, and rpcrt4's UuidCreate feeds the SCM's RPC context
 * handles from RtlGenRandom WITHOUT checking for failure — a kernel that
 * refuses the class hands every context handle the same stack garbage as
 * a "UUID", and the client's GUID-keyed context cache
 * (rpcrt4/ndr_contexthandle.c context_entry_from_guid) collides across
 * handles until the SCM's calls die of RPC_X_SS_CONTEXT_MISMATCH.
 *
 * The contract (wine/dlls/ntdll/unix/system.c): length is
 * NumberOfProcessors * sizeof(SYSTEM_INTERRUPT_INFORMATION); an
 * undersized buffer answers INFO_LENGTH_MISMATCH; a sufficient one is
 * filled with RANDOM bytes (the oracle reads /dev/urandom) — pinned here
 * as "two queries never repeat", the property UuidCreate needs.
 */
#include "util.h"

typedef struct
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SEM_SYSTEM_INTERRUPT_INFORMATION;

START_TEST(entropy)
{
    SYSTEM_BASIC_INFORMATION basic;
    NTSTATUS status;
    ULONG returned = 0;

    status = NtQuerySystemInformation(SystemBasicInformation, &basic, sizeof(basic), NULL);
    ok(status == STATUS_SUCCESS, "basic info -> %08lx", (unsigned long)status);
    ULONG cpus = basic.NumberOfProcessors;
    ok(cpus >= 1, "processor count %lu", (unsigned long)cpus);

    ULONG len = cpus * sizeof(SEM_SYSTEM_INTERRUPT_INFORMATION);
    static unsigned char first[256 * sizeof(SEM_SYSTEM_INTERRUPT_INFORMATION)];
    static unsigned char second[sizeof(first)];
    ok(len <= sizeof(first), "buffer covers %lu cpus", (unsigned long)cpus);

    /* Undersized: refused with the full length required. */
    status = NtQuerySystemInformation(SystemInterruptInformation, first, len - 1, &returned);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "undersized -> %08lx", (unsigned long)status);

    /* Two exact-size queries: both succeed and the bytes MOVE — the
     * entropy property RtlGenRandom exists for. */
    memset(first, 0, len);
    memset(second, 0, len);
    status = NtQuerySystemInformation(SystemInterruptInformation, first, len, &returned);
    ok(status == STATUS_SUCCESS, "first query -> %08lx", (unsigned long)status);
    ok(returned == len, "first length %lu (want %lu)", (unsigned long)returned, (unsigned long)len);
    status = NtQuerySystemInformation(SystemInterruptInformation, second, len, NULL);
    ok(status == STATUS_SUCCESS, "second query -> %08lx", (unsigned long)status);
    ok(memcmp(first, second, len) != 0, "consecutive queries differ");

    /* An oversized buffer is fine (the oracle checks size >= len). */
    status = NtQuerySystemInformation(SystemInterruptInformation, first, len + 32, &returned);
    ok(status == STATUS_SUCCESS, "oversized -> %08lx", (unsigned long)status);
    ok(returned == len, "oversized length %lu", (unsigned long)returned);
}
