/*
 * sem_wait/signal_wait.c — NtSignalAndWaitForSingleObject (CUI-6).
 *
 * SignalObjectAndWait's back end. Oracle behaviour pinned from the pinned
 * tree: a NULL signal handle refuses before anything else
 * (dlls/ntdll/unix/sync.c); the WAIT handle is validated first, then the
 * signal runs — a failing signal aborts the armed wait unconsumed
 * (server/thread.c select_on SELECT_SIGNAL_AND_WAIT); per-type signal
 * checks are event EVENT_MODIFY_STATE, semaphore SEMAPHORE_MODIFY_STATE,
 * mutant ownership (server/{event,semaphore,mutex}.c *_signal), any other
 * type STATUS_OBJECT_TYPE_MISMATCH (server/object.c no_signal); and the
 * signal-then-wait pair is atomic — signalling the very object being
 * waited on satisfies the wait ("check if we woke ourselves up").
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtCreateMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtCreateSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject(HANDLE, HANDLE, BOOLEAN,
                                                       const LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001 /* wine/include/winternl.h */
#endif

static NTSTATUS wait_now(HANDLE handle)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(handle, FALSE, &zero);
}

static NTSTATUS signal_wait_ms(HANDLE signal, HANDLE wait, LONGLONG ms)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -ms * 10000;
    return NtSignalAndWaitForSingleObject(signal, wait, FALSE, &timeout);
}

static HANDLE pp_req, pp_ack;
static volatile LONG pp_worker_rounds;

static DWORD WINAPI pingpong_worker(void *param)
{
    (void)param;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -5000 * 10000LL;
    for (int i = 0; i < 8; i++)
    {
        if (NtWaitForSingleObject(pp_req, FALSE, &timeout) != STATUS_SUCCESS)
        {
            return 1;
        }
        InterlockedIncrement(&pp_worker_rounds);
        NtSetEvent(pp_ack, NULL);
    }
    return 0;
}

START_TEST(signal_wait)
{
    NTSTATUS status;
    HANDLE evA = NULL, evB = NULL, sigOnly = NULL, mutant = NULL, sem = NULL, dir = NULL;
    UNICODE_STRING dirName;
    OBJECT_ATTRIBUTES attr;

    status = NtCreateEvent(&evA, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create evA -> %08lx", (unsigned long)status);
    status = NtCreateEvent(&evB, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create evB -> %08lx", (unsigned long)status);

    /* --- NULL signal handle refuses first -------------------------------- */
    status = signal_wait_ms(NULL, evB, 0);
    ok(status == STATUS_INVALID_HANDLE, "NULL signal -> %08lx", (unsigned long)status);
    /* ...and did not consume the wait-side event. */
    ok(wait_now(evB) == STATUS_SUCCESS, "evB survived NULL signal");
    NtSetEvent(evB, NULL);

    /* --- bad wait handle refuses without signalling ----------------------- */
    status = signal_wait_ms(evA, (HANDLE)(ULONG_PTR)0xdead0, 0);
    ok(status == STATUS_INVALID_HANDLE, "bad wait handle -> %08lx", (unsigned long)status);
    ok(wait_now(evA) == STATUS_TIMEOUT, "evA not signalled by refused call");

    /* --- the basic pair: signal A, wait B (already set) ------------------- */
    status = signal_wait_ms(evA, evB, 1000);
    ok(status == STATUS_SUCCESS, "signal A wait B -> %08lx", (unsigned long)status);
    ok(wait_now(evA) == STATUS_SUCCESS, "A was signalled");
    ok(wait_now(evB) == STATUS_TIMEOUT, "B was consumed");

    /* --- atomic self pair: signal and wait the SAME auto-reset event ------ */
    status = signal_wait_ms(evA, evA, 1000);
    ok(status == STATUS_SUCCESS, "self signal-and-wait -> %08lx", (unsigned long)status);
    ok(wait_now(evA) == STATUS_TIMEOUT, "self pair consumed its own signal");

    /* --- timeout: the signal still lands --------------------------------- */
    status = signal_wait_ms(evA, evB, 50);
    ok(status == STATUS_TIMEOUT, "timeout wait -> %08lx", (unsigned long)status);
    ok(wait_now(evA) == STATUS_SUCCESS, "A signalled despite wait timeout");

    /* --- signal access: EVENT_MODIFY_STATE is required -------------------- */
    status =
        NtDuplicateObject(NtCurrentProcess(), evA, NtCurrentProcess(), &sigOnly, SYNCHRONIZE, 0, 0);
    ok(status == STATUS_SUCCESS, "dup SYNCHRONIZE-only -> %08lx", (unsigned long)status);
    NtSetEvent(evB, NULL);
    status = signal_wait_ms(sigOnly, evB, 0);
    ok(status == STATUS_ACCESS_DENIED, "under-privileged signal -> %08lx", (unsigned long)status);
    ok(wait_now(evB) == STATUS_SUCCESS, "evB survived denied signal");
    NtClose(sigOnly);

    /* --- non-signalable signal type --------------------------------------- */
    {
        static const WCHAR bno[] = L"\\BaseNamedObjects";
        dirName.Buffer = (PWSTR)bno;
        dirName.Length = sizeof(bno) - sizeof(WCHAR);
        dirName.MaximumLength = sizeof(bno);
        InitializeObjectAttributes(&attr, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtOpenDirectoryObject(&dir, DIRECTORY_QUERY, &attr);
        ok(status == STATUS_SUCCESS, "open directory -> %08lx", (unsigned long)status);
        NtSetEvent(evB, NULL);
        status = signal_wait_ms(dir, evB, 0);
        ok(status == STATUS_OBJECT_TYPE_MISMATCH, "directory as signal -> %08lx",
           (unsigned long)status);
        ok(wait_now(evB) == STATUS_SUCCESS, "evB survived type-mismatched signal");
        NtClose(dir);
    }

    /* --- unowned mutant: refuses, wait unconsumed -------------------------- */
    status = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, NULL, FALSE);
    ok(status == STATUS_SUCCESS, "create mutant -> %08lx", (unsigned long)status);
    NtSetEvent(evB, NULL);
    status = signal_wait_ms(mutant, evB, 0);
    ok(status == STATUS_MUTANT_NOT_OWNED, "unowned mutant -> %08lx", (unsigned long)status);
    ok(wait_now(evB) == STATUS_SUCCESS, "evB survived refused mutant release");
    NtClose(mutant);

    /* --- owned mutant releases and the wait proceeds ----------------------- */
    status = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, NULL, TRUE);
    ok(status == STATUS_SUCCESS, "create owned mutant -> %08lx", (unsigned long)status);
    NtSetEvent(evB, NULL);
    status = signal_wait_ms(mutant, evB, 1000);
    ok(status == STATUS_SUCCESS, "owned mutant release + wait -> %08lx", (unsigned long)status);
    /* Released: a second acquire succeeds immediately. */
    ok(wait_now(mutant) == STATUS_SUCCESS, "mutant was released");
    NtClose(mutant);

    /* --- semaphore at its limit: refuses, wait unconsumed ------------------ */
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 1);
    ok(status == STATUS_SUCCESS, "create full semaphore -> %08lx", (unsigned long)status);
    NtSetEvent(evB, NULL);
    status = signal_wait_ms(sem, evB, 0);
    ok(status == STATUS_SEMAPHORE_LIMIT_EXCEEDED, "full semaphore -> %08lx", (unsigned long)status);
    ok(wait_now(evB) == STATUS_SUCCESS, "evB survived refused semaphore release");
    NtClose(sem);

    /* --- cross-thread ping-pong smoke -------------------------------------- */
    status = NtCreateEvent(&pp_req, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create req -> %08lx", (unsigned long)status);
    status = NtCreateEvent(&pp_ack, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create ack -> %08lx", (unsigned long)status);
    HANDLE worker = CreateThread(NULL, 0, pingpong_worker, NULL, 0, NULL);
    ok(worker != NULL, "create worker");
    int rounds = 0;
    for (int i = 0; i < 8; i++)
    {
        if (signal_wait_ms(pp_req, pp_ack, 5000) == STATUS_SUCCESS)
        {
            rounds++;
        }
    }
    ok(rounds == 8, "ping-pong rounds %d", rounds);
    WaitForSingleObject(worker, 5000);
    ok(pp_worker_rounds == 8, "worker rounds %ld", (long)pp_worker_rounds);
    CloseHandle(worker);
    NtClose(pp_req);
    NtClose(pp_ack);
    NtClose(evA);
    NtClose(evB);
}
