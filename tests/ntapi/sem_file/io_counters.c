/*
 * sem_file/io_counters.c — ProcessIoCounters, the class taskmgr reads for
 * every process it lists (third_party/wine/programs/taskmgr/perfdata.c calls
 * GetProcessIoCounters, which is NtQueryInformationProcess(2)).
 *
 * It lives in the FILE bucket rather than in sem_ps because what the class
 * REPORTS is file I/O: the interesting half of the contract is that a read
 * and a write move the counters, and only this bucket has the helpers that
 * do file I/O. The uninteresting half — the length protocol — is pinned
 * against the oracle here too, so both halves stay in one case.
 *
 * The oracle answers this class with a zeroed struct behind a
 * "FIXME : real data" (third_party/wine/dlls/ntdll/unix/process.c,
 * ProcessIoCounters), so it can pin the SHAPE and nothing else; the values
 * are pinned in a beyond_oracle block against Microsoft's own contract.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

static NTSTATUS query_counters(IO_COUNTERS *counters)
{
    return NtQueryInformationProcess(NtCurrentProcess(), ProcessIoCounters, counters,
                                     sizeof(*counters), NULL);
}

START_TEST(io_counters)
{
    IO_COUNTERS counters;
    ULONG returnLength;
    NTSTATUS status;

    /* --- the length protocol (oracle-pinned) ----------------------------- */

    memset(&counters, 0xcc, sizeof(counters));
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessIoCounters, &counters,
                                       sizeof(counters), &returnLength);
    ok(status == STATUS_SUCCESS, "exact size -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(counters), "exact return length %lu", (unsigned long)returnLength);

    /* A buffer SHORTER than IO_COUNTERS is refused, and returnLength still
     * reports the needed size. */
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessIoCounters, &counters,
                                       sizeof(counters) - 1, &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short size -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(counters), "short return length %lu", (unsigned long)returnLength);

    /* A LONGER one is filled and STILL answers STATUS_INFO_LENGTH_MISMATCH
     * (the oracle's `if (size > sizeof(IO_COUNTERS)) ret = ..._MISMATCH`
     * after the copy) — a caller that treats the status as fatal and one
     * that reads the buffer anyway both have to work. Exactly
     * sizeof(IO_COUNTERS) bytes are written: the trailing guard word keeps
     * its poison. */
    struct
    {
        IO_COUNTERS counters;
        ULONGLONG guard;
    } oversized;
    IO_COUNTERS poison;
    memset(&oversized, 0xcc, sizeof(oversized));
    memset(&poison, 0xcc, sizeof(poison));
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessIoCounters, &oversized,
                                       sizeof(oversized), &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "oversized -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(IO_COUNTERS), "oversized return length %lu",
       (unsigned long)returnLength);
    ok(memcmp(&oversized.counters, &poison, sizeof(poison)) != 0, "oversized buffer filled");
    ok(oversized.guard == 0xccccccccccccccccULL, "oversized wrote past IO_COUNTERS (%llx)",
       (unsigned long long)oversized.guard);

    /* An unwritable buffer of adequate size is STATUS_ACCESS_VIOLATION. */
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessIoCounters, NULL,
                                       sizeof(counters), NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL buffer -> %08lx", (unsigned long)status);

    /* --- the values (beyond the oracle) ---------------------------------- */

    IO_STATUS_BLOCK iosb;
    HANDLE dir, handle = NULL;
    static const char payload[100] = "io_counters payload";
    char readback[sizeof(payload)];

    dir = open_test_dir(W("\\??\\C:\\prstest\\iocounters"));
    if (dir == NULL)
        return;
    scrub_file(dir, W("counted.bin"));

    /* The pinned Wine memsets this class to zero behind its own FIXME, so it
     * has nothing to say about what the counters mean; the contract used
     * here is Microsoft's documentation of IO_COUNTERS (learn.microsoft.com,
     * "IO_COUNTERS structure" and GetProcessIoCounters): ReadOperationCount
     * is "the number of read operations performed", ReadTransferCount "the
     * number of bytes read", and the write pair says the same for writes.
     * So one NtWriteFile of N bytes is one write operation and N write
     * bytes, and one NtReadFile that returns N bytes is one read operation
     * and N read bytes. Nothing here pins a TOTAL — only what a single
     * operation adds, which is the part the documentation fixes.
     *
     * The two queries bracket each transfer with nothing between them: a
     * passing ok() prints nothing, so no I/O of the harness's own can land
     * inside a bracket. */
    beyond_oracle
    {
        IO_COUNTERS before, after;
        NTSTATUS beforeStatus, afterStatus, transferStatus;
        LARGE_INTEGER zero;

        status = open_file(&handle, dir, W("counted.bin"), FILE_WRITE_DATA | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

        beforeStatus = query_counters(&before);
        transferStatus =
            NtWriteFile(handle, NULL, NULL, NULL, &iosb, payload, sizeof(payload), NULL, NULL);
        afterStatus = query_counters(&after);
        ok(beforeStatus == STATUS_SUCCESS && afterStatus == STATUS_SUCCESS,
           "write bracket -> %08lx/%08lx", (unsigned long)beforeStatus, (unsigned long)afterStatus);
        ok(transferStatus == STATUS_SUCCESS, "write -> %08lx", (unsigned long)transferStatus);
        ok(after.WriteOperationCount == before.WriteOperationCount + 1,
           "write operations %llu -> %llu", (unsigned long long)before.WriteOperationCount,
           (unsigned long long)after.WriteOperationCount);
        ok(after.WriteTransferCount == before.WriteTransferCount + sizeof(payload),
           "write bytes %llu -> %llu", (unsigned long long)before.WriteTransferCount,
           (unsigned long long)after.WriteTransferCount);
        ok(after.ReadOperationCount == before.ReadOperationCount,
           "a write is not a read (%llu -> %llu)", (unsigned long long)before.ReadOperationCount,
           (unsigned long long)after.ReadOperationCount);
        NtClose(handle);

        status = open_file(&handle, dir, W("counted.bin"), FILE_READ_DATA | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE,
                           &iosb);
        ok(status == STATUS_SUCCESS, "reopen -> %08lx", (unsigned long)status);
        zero.QuadPart = 0;
        beforeStatus = query_counters(&before);
        transferStatus =
            NtReadFile(handle, NULL, NULL, NULL, &iosb, readback, sizeof(readback), &zero, NULL);
        afterStatus = query_counters(&after);
        ok(beforeStatus == STATUS_SUCCESS && afterStatus == STATUS_SUCCESS,
           "read bracket -> %08lx/%08lx", (unsigned long)beforeStatus, (unsigned long)afterStatus);
        ok(transferStatus == STATUS_SUCCESS, "read -> %08lx", (unsigned long)transferStatus);
        ok(after.ReadOperationCount == before.ReadOperationCount + 1,
           "read operations %llu -> %llu", (unsigned long long)before.ReadOperationCount,
           (unsigned long long)after.ReadOperationCount);
        ok(after.ReadTransferCount == before.ReadTransferCount + sizeof(payload),
           "read bytes %llu -> %llu", (unsigned long long)before.ReadTransferCount,
           (unsigned long long)after.ReadTransferCount);
        NtClose(handle);
    }

    scrub_file(dir, W("counted.bin"));
    NtClose(dir);
}
