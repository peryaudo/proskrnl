/*
 * sem_ps/open_process.c — NtOpenProcess by CLIENT_ID.
 *
 * The first thing tasklist/taskkill do with a pid from the toolhelp snapshot:
 * OpenProcess -> NtOpenProcess (dlls/kernelbase/process.c) with a
 * CLIENT_ID.UniqueProcess and a NULL name. Contract from wineserver
 * (server/process.c get_process_from_id / open_process): a live pid resolves
 * to a fresh handle; an id that was never a process is STATUS_INVALID_CID.
 * Green on the pinned Wine oracle first (Art. 5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *,
                                      const CLIENT_ID *);

START_TEST(open_process)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr;
    CLIENT_ID cid;
    HANDLE handle;

    InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);

    /* Open our own process by pid: a fresh, valid handle. */
    memset(&cid, 0, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    handle = NULL;
    status = NtOpenProcess(&handle, PROCESS_QUERY_INFORMATION, &attr, &cid);
    ok(status == STATUS_SUCCESS, "open self by pid -> %08lx", (unsigned long)status);
    ok(handle != NULL, "open self returned a null handle");

    if (handle)
    {
        /* The handle is real: a query through it reports our own pid. */
        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;
        status =
            NtQueryInformationProcess(handle, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
        ok(status == STATUS_SUCCESS, "query the opened handle -> %08lx", (unsigned long)status);
        ok((DWORD)(ULONG_PTR)pbi.UniqueProcessId == GetCurrentProcessId(),
           "opened handle names pid %lu, wanted %lu", (unsigned long)(ULONG_PTR)pbi.UniqueProcessId,
           (unsigned long)GetCurrentProcessId());
        NtClose(handle);
    }

    /* An id that was never a process: STATUS_INVALID_CID. Odd ids can never
     * be process ids (they are 4-aligned on both sides), so this is stable. */
    memset(&cid, 0, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0xfffffffcUL;
    handle = (HANDLE)(ULONG_PTR)0xdead;
    status = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &attr, &cid);
    ok(status == STATUS_INVALID_CID, "open bogus pid -> %08lx", (unsigned long)status);
}
