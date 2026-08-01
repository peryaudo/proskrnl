/*
 * sem_ps/open_thread.c — NtOpenThread by CLIENT_ID (CUI-6).
 *
 * OpenThread's back end. Oracle behaviour pinned from the pinned tree
 * (dlls/ntdll/unix/thread.c NtOpenThread; server/thread.c open_thread /
 * get_thread_from_id): a handle opened by thread id works for
 * NtQueryInformationThread; an unknown id refuses with STATUS_INVALID_CID;
 * only the UniqueThread field is sent (UniqueProcess is not validated);
 * OBJ_INHERIT attributes are honoured. Sibling threads and a child
 * process's thread are both reachable — the id space is machine-wide.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *,
                                     const CLIENT_ID *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif
/* mingw's ntstatus.h may omit it; value as wine/include/ntstatus.h. */
#ifndef STATUS_INVALID_CID
#define STATUS_INVALID_CID ((NTSTATUS)0xC000000B)
#endif

/* winternl.h omits it on some toolchains; as wine/include/winternl.h. */
typedef struct
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} ps_thread_basic_information;
#define ThreadBasicInformation ((THREADINFOCLASS)0)

static HANDLE sibling_ready;
static HANDLE sibling_go;
static volatile LONG sibling_tid;

static DWORD WINAPI sibling_worker(void *param)
{
    (void)param;
    InterlockedExchange(&sibling_tid, (LONG)GetCurrentThreadId());
    SetEvent(sibling_ready);
    WaitForSingleObject(sibling_go, 10000);
    return 0;
}

START_TEST(open_thread)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attr;
    CLIENT_ID cid;
    HANDLE opened;

    InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);

    /* --- open self by id --------------------------------------------------- */
    memset(&cid, 0, sizeof(cid));
    cid.UniqueThread = (HANDLE)(ULONG_PTR)GetCurrentThreadId();
    opened = NULL;
    status = NtOpenThread(&opened, THREAD_QUERY_INFORMATION, &attr, &cid);
    ok(status == STATUS_SUCCESS, "open self by id -> %08lx", (unsigned long)status);
    ok(opened != NULL, "self handle non-null");
    {
        ps_thread_basic_information tbi;
        memset(&tbi, 0, sizeof(tbi));
        status = NtQueryInformationThread(opened, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
        ok(status == STATUS_SUCCESS, "query opened self -> %08lx", (unsigned long)status);
        ok((ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread == GetCurrentThreadId(),
           "opened handle names self");
    }
    NtClose(opened);

    /* --- open a sibling thread by id --------------------------------------- */
    sibling_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    sibling_go = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(sibling_ready && sibling_go, "create sibling events");
    HANDLE sibling = CreateThread(NULL, 0, sibling_worker, NULL, 0, NULL);
    ok(sibling != NULL, "create sibling");
    WaitForSingleObject(sibling_ready, 10000);

    memset(&cid, 0, sizeof(cid));
    cid.UniqueThread = (HANDLE)(ULONG_PTR)(ULONG)sibling_tid;
    opened = NULL;
    status = NtOpenThread(&opened, THREAD_QUERY_INFORMATION, &attr, &cid);
    ok(status == STATUS_SUCCESS, "open sibling by id -> %08lx", (unsigned long)status);
    {
        ps_thread_basic_information tbi;
        memset(&tbi, 0, sizeof(tbi));
        status = NtQueryInformationThread(opened, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
        ok(status == STATUS_SUCCESS, "query sibling -> %08lx", (unsigned long)status);
        ok((ULONG)(ULONG_PTR)tbi.ClientId.UniqueThread == (ULONG)sibling_tid,
           "opened handle names the sibling");
    }
    NtClose(opened);

    /* UniqueProcess is not validated: a wrong (nonzero) process field with
     * the right thread id still opens. */
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0x4;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)(ULONG)sibling_tid;
    opened = NULL;
    status = NtOpenThread(&opened, THREAD_QUERY_INFORMATION, &attr, &cid);
    ok(status == STATUS_SUCCESS, "open sibling with a bogus pid -> %08lx", (unsigned long)status);
    NtClose(opened);

    SetEvent(sibling_go);
    WaitForSingleObject(sibling, 10000);
    CloseHandle(sibling);
    CloseHandle(sibling_ready);
    CloseHandle(sibling_go);

    /* --- unknown id refuses ------------------------------------------------ */
    memset(&cid, 0, sizeof(cid));
    cid.UniqueThread = (HANDLE)(ULONG_PTR)0x7ffffffc;
    opened = (HANDLE)(ULONG_PTR)0xabc;
    status = NtOpenThread(&opened, THREAD_QUERY_INFORMATION, &attr, &cid);
    ok(status == STATUS_INVALID_CID, "unknown id -> %08lx", (unsigned long)status);
}
