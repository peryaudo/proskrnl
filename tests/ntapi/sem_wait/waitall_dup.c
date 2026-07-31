/*
 * sem_wait/waitall_dup.c — a wait-all may not name the same object twice.
 *
 * Contract (Microsoft, WaitForMultipleObjects, lpHandles): "The array ... may
 * not contain multiple copies of the same handle", and such a call fails with
 * ERROR_INVALID_PARAMETER —
 * https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjects
 * That maps to STATUS_INVALID_PARAMETER at the Nt* boundary, and it must be
 * decided BEFORE anything is consumed: a wait-all is atomic, so a refused call
 * leaves every object's state exactly where it was.
 *
 * Why the calls only run on proskrnl. This is the rarer half of Art. 12's
 * "an oracle that is unbuilt has nothing to say": the pinned Wine cannot be
 * asked, because its server carries the same defect proskrnl had — a
 * count-1 semaphore satisfied twice trips
 * `assert( sem->count )` in server/semaphore.c semaphore_sync_satisfied and
 * takes wineserver down with it, so the call does not return a status at all.
 * Where proskrnl once had its own ASSERT here, any unprivileged process could
 * halt the whole machine with two identical handles.
 *
 * WaitAny is the control: it satisfies exactly one object, so duplicates are
 * legal there and must keep working on BOTH legs.
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtQuerySemaphore(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, const HANDLE *, ULONG, BOOLEAN,
                                                 PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef __WAIT_TYPE_DECLARED
#define __WAIT_TYPE_DECLARED
typedef enum _WAIT_TYPE
{
    WaitAll,
    WaitAny
} WAIT_TYPE;
#endif

typedef struct
{
    LONG CurrentCount;
    LONG MaximumCount;
} SEMA_BASIC_INFO;

START_TEST(waitall_dup)
{
    HANDLE sem, event, handles[3];
    LARGE_INTEGER zero;
    NTSTATUS status;

    zero.QuadPart = 0;

    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 4);
    ok(status == STATUS_SUCCESS, "create semaphore -> %08lx", (unsigned long)status);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* The control, on both legs: a duplicate under WaitAny is fine and takes
     * exactly one count. */
    handles[0] = sem;
    handles[1] = sem;
    status = NtWaitForMultipleObjects(2, handles, WaitAny, FALSE, &zero);
    ok(status == STATUS_WAIT_0, "wait-any duplicate -> %08lx", (unsigned long)status);
    status = NtWaitForMultipleObjects(2, handles, WaitAny, FALSE, &zero);
    ok(status == STATUS_TIMEOUT, "wait-any duplicate, count spent -> %08lx", (unsigned long)status);

    NtClose(sem);
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 4);
    ok(status == STATUS_SUCCESS, "recreate semaphore -> %08lx", (unsigned long)status);
    handles[0] = sem;
    handles[1] = event;
    handles[2] = sem;

    if (!ntapi_ctx.on_proskrnl)
    {
        skip("wait-all duplicates: the pinned Wine's server asserts on this input and exits");
    }
    else
        beyond_oracle
        {
            SEMA_BASIC_INFO info;
            ULONG returned = 0;

            handles[0] = sem;
            handles[1] = sem;
            status = NtWaitForMultipleObjects(2, handles, WaitAll, FALSE, &zero);
            ok(status == STATUS_INVALID_PARAMETER, "wait-all, same handle twice -> %08lx",
               (unsigned long)status);

            /* Refused before anything was consumed. */
            info.CurrentCount = -1;
            info.MaximumCount = -1;
            status = NtQuerySemaphore(sem, 0, &info, sizeof(info), &returned);
            ok(status == STATUS_SUCCESS, "query semaphore -> %08lx", (unsigned long)status);
            ok(info.CurrentCount == 1, "count untouched by the refused wait: %ld",
               (long)info.CurrentCount);

            /* A duplicate anywhere in the array, not just adjacent. */
            handles[0] = sem;
            handles[1] = event;
            handles[2] = sem;
            status = NtWaitForMultipleObjects(3, handles, WaitAll, FALSE, &zero);
            ok(status == STATUS_INVALID_PARAMETER, "wait-all, duplicate at 0 and 2 -> %08lx",
               (unsigned long)status);

            /* And the distinct-object wait-all still works. */
            handles[0] = sem;
            handles[1] = event;
            status = NtWaitForMultipleObjects(2, handles, WaitAll, FALSE, &zero);
            ok(status == STATUS_WAIT_0, "wait-all, distinct objects -> %08lx",
               (unsigned long)status);
        }

    NtClose(event);
    NtClose(sem);
}
