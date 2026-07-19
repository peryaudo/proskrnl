/*
 * sem_ps/process_query.c — the mechanical M7 Ps/Ke query surface (docs/02).
 *
 * The pieces of M7 a flat binary can reach: process/system information, the
 * performance counter, and the scheduling primitives. Distilled from the
 * behaviour Wine's ntdll relies on at startup (dlls/ntdll/unix/process.c,
 * system.c) and greened on the pinned Wine oracle first (Art. 5). The PE-only
 * M7 surface — the byte-exact PEB/TEB and the KiUser* return protocol — is
 * covered by the m7_smoke.exe boot module, which a flat ntapi binary cannot
 * express.
 */
#include "util.h"

START_TEST(process_query)
{
    NTSTATUS status;

    /* --- ProcessBasicInformation ---------------------------------------- */
    PS_PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, &pbi,
                                       sizeof(pbi), &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(pbi), "return length %lu", (unsigned long)returnLength);
    ok(pbi.UniqueProcessId != 0, "process id nonzero (%lu)", (unsigned long)pbi.UniqueProcessId);

    /* A too-small buffer is STATUS_INFO_LENGTH_MISMATCH. */
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, &pbi,
                                       sizeof(pbi) - 1, NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);

    /* ProcessBasicInformation wants an EXACT length: a LARGER buffer is also
     * STATUS_INFO_LENGTH_MISMATCH (Wine dlls/ntdll/unix/process.c:
     * `if (size > sizeof(PROCESS_BASIC_INFORMATION)) ret = ..._MISMATCH`).
     * Fuzzer-found (sem_ps was previously exact/short only). */
    unsigned char pbi_big[sizeof(pbi) + 16];
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, pbi_big,
                                       sizeof(pbi_big), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "oversized buffer -> %08lx", (unsigned long)status);

    /* --- SystemBasicInformation: allocation granularity ----------------- */
    PS_SYSTEM_BASIC_INFORMATION sbi;
    status = NtQuerySystemInformation(PS_SystemBasicInformation, &sbi, sizeof(sbi), &returnLength);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);
    ok(sbi.AllocationGranularity == 0x10000, "allocation granularity %lu",
       (unsigned long)sbi.AllocationGranularity);

    /* SystemBasicInformation also wants an EXACT length (Wine system.c:
     * `if (size == len) ...; else ret = ..._MISMATCH`) — both under- and
     * over-sized buffers are STATUS_INFO_LENGTH_MISMATCH. */
    unsigned char sbi_big[sizeof(sbi) + 16];
    status = NtQuerySystemInformation(PS_SystemBasicInformation, sbi_big, sizeof(sbi_big), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "system oversized -> %08lx", (unsigned long)status);

    /* --- NtQueryPerformanceCounter: monotonic, nonzero frequency -------- */
    LARGE_INTEGER first, second, frequency;
    status = NtQueryPerformanceCounter(&first, &frequency);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter -> %08lx", (unsigned long)status);
    ok(frequency.QuadPart > 0, "frequency %lld", (long long)frequency.QuadPart);
    status = NtQueryPerformanceCounter(&second, NULL);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(2) -> %08lx", (unsigned long)status);
    ok(second.QuadPart >= first.QuadPart, "counter monotonic (%lld -> %lld)",
       (long long)first.QuadPart, (long long)second.QuadPart);

    /* --- NtDelayExecution: a short relative delay completes -------------- */
    LARGE_INTEGER interval;
    interval.QuadPart = -10000; /* 1 ms, relative (negative = relative 100 ns) */
    status = NtDelayExecution(FALSE, &interval);
    ok(status == STATUS_SUCCESS, "DelayExecution -> %08lx", (unsigned long)status);

    /* A zero delay is a yield (STATUS_SUCCESS or, when there is no other
     * runnable thread, STATUS_NO_YIELD_PERFORMED). */
    interval.QuadPart = 0;
    status = NtDelayExecution(FALSE, &interval);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
       "DelayExecution(0) -> %08lx", (unsigned long)status);

    /* --- NtYieldExecution / NtTestAlert accept and return --------------- */
    status = NtYieldExecution();
    ok(status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED, "YieldExecution -> %08lx",
       (unsigned long)status);

    status = NtTestAlert();
    ok(status == STATUS_SUCCESS, "TestAlert -> %08lx", (unsigned long)status);
}
