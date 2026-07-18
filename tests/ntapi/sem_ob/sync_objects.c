/*
 * sem_ob/sync_objects.c — Nt-level dispatcher-object semantics (M3).
 *
 * M2 proved the Ke dispatcher; this pins the Nt wrappers that move those
 * objects under Ob: previous-state/previous-count out-parameters, the
 * semaphore limit, mutant ownership/recursion errors, the query info
 * classes, and the wait-multiple parameter conventions.
 */
#include "util.h"

START_TEST(sync_objects)
{
    HANDLE event, mutant, sem;
    NTSTATUS status;
    LONG prev;
    ULONG uprev;

    /* Event: NtSetEvent/NtResetEvent report the PREVIOUS state; NtQueryEvent
     * reports type and current state without consuming anything. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)status);
    prev = -1;
    status = NtSetEvent(event, &prev);
    ok(status == STATUS_SUCCESS, "NtSetEvent -> %08lx", (unsigned long)status);
    ok(prev == 0, "previous state %ld, expected 0", (long)prev);
    prev = -1;
    status = NtSetEvent(event, &prev);
    ok(status == STATUS_SUCCESS, "2nd NtSetEvent -> %08lx", (unsigned long)status);
    ok(prev == 1, "previous state %ld, expected 1", (long)prev);
    {
        ob_event_basic_info info;
        info.event_type = -1;
        info.event_state = -1;
        status = NtQueryEvent(event, EVENT_BASIC_INFO_CLASS, &info, sizeof(info), NULL);
        ok(status == STATUS_SUCCESS, "NtQueryEvent -> %08lx", (unsigned long)status);
        ok(info.event_type == SynchronizationEvent, "queried type %ld", (long)info.event_type);
        ok(info.event_state == 1, "queried state %ld, expected 1", (long)info.event_state);
        /* The query must NOT have consumed the synchronization event... */
        ok(wait_now(event) == STATUS_SUCCESS, "query consumed the event");
        /* ...but the satisfied wait must have. */
        ok(wait_now(event) == STATUS_TIMEOUT, "wait did not consume the sync event");
    }
    prev = -1;
    status = NtResetEvent(event, &prev);
    ok(status == STATUS_SUCCESS, "NtResetEvent -> %08lx", (unsigned long)status);
    ok(prev == 0, "reset previous state %ld, expected 0", (long)prev);

    /* NtPulseEvent with no waiters: reports previous state, leaves the event
     * non-signalled. */
    NtSetEvent(event, NULL);
    prev = -1;
    status = NtPulseEvent(event, &prev);
    ok(status == STATUS_SUCCESS, "NtPulseEvent -> %08lx", (unsigned long)status);
    ok(prev == 1, "pulse previous state %ld, expected 1", (long)prev);
    ok(wait_now(event) == STATUS_TIMEOUT, "event still signalled after pulse");
    NtClose(event);

    /* Mutant: created owned, recursive acquire, release count discipline,
     * releasing an unowned mutant fails. */
    status = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, NULL, TRUE);
    ok(status == STATUS_SUCCESS, "NtCreateMutant(owned) -> %08lx", (unsigned long)status);
    ok(wait_now(mutant) == STATUS_SUCCESS, "recursive acquire failed");
    {
        ob_mutant_basic_info info;
        info.current_count = 99;
        info.owned_by_caller = 0;
        info.abandoned_state = 1;
        status = NtQueryMutant(mutant, MUTANT_BASIC_INFO_CLASS, &info, sizeof(info), NULL);
        ok(status == STATUS_SUCCESS, "NtQueryMutant -> %08lx", (unsigned long)status);
        ok(info.current_count == -1, "count %ld, expected -1 (held twice)",
           (long)info.current_count);
        ok(info.owned_by_caller == TRUE, "OwnedByCaller not set");
        ok(info.abandoned_state == FALSE, "AbandonedState set");
    }
    prev = -99;
    status = NtReleaseMutant(mutant, &prev);
    ok(status == STATUS_SUCCESS, "1st NtReleaseMutant -> %08lx", (unsigned long)status);
    ok(prev == -1, "previous count %ld, expected -1", (long)prev);
    prev = -99;
    status = NtReleaseMutant(mutant, &prev);
    ok(status == STATUS_SUCCESS, "2nd NtReleaseMutant -> %08lx", (unsigned long)status);
    ok(prev == 0, "previous count %ld, expected 0", (long)prev);
    status = NtReleaseMutant(mutant, NULL);
    ok(status == STATUS_MUTANT_NOT_OWNED, "over-release -> %08lx", (unsigned long)status);
    NtClose(mutant);

    /* Semaphore: initial/maximum counts enforced, previous count returned,
     * exceeding the limit is STATUS_SEMAPHORE_LIMIT_EXCEEDED and does not
     * disturb the count. */
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 5, 3);
    ok(status == STATUS_INVALID_PARAMETER, "initial>maximum -> %08lx", (unsigned long)status);
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 2);
    ok(status == STATUS_SUCCESS, "NtCreateSemaphore -> %08lx", (unsigned long)status);
    uprev = 99;
    status = NtReleaseSemaphore(sem, 1, &uprev);
    ok(status == STATUS_SUCCESS, "NtReleaseSemaphore -> %08lx", (unsigned long)status);
    ok(uprev == 1, "previous count %lu, expected 1", (unsigned long)uprev);
    status = NtReleaseSemaphore(sem, 1, NULL);
    ok(status == STATUS_SEMAPHORE_LIMIT_EXCEEDED, "over-release -> %08lx", (unsigned long)status);
    {
        ob_semaphore_basic_info info;
        info.current_count = 99;
        info.maximum_count = 99;
        status = NtQuerySemaphore(sem, SEMAPHORE_BASIC_INFO_CLASS, &info, sizeof(info), NULL);
        ok(status == STATUS_SUCCESS, "NtQuerySemaphore -> %08lx", (unsigned long)status);
        ok(info.current_count == 2, "count %lu, expected 2", (unsigned long)info.current_count);
        ok(info.maximum_count == 2, "maximum %lu, expected 2", (unsigned long)info.maximum_count);
    }
    ok(wait_now(sem) == STATUS_SUCCESS, "semaphore wait 1");
    ok(wait_now(sem) == STATUS_SUCCESS, "semaphore wait 2");
    ok(wait_now(sem) == STATUS_TIMEOUT, "semaphore count exceeded its releases");
    NtClose(sem);

    /* NtReleaseSemaphore resolves the HANDLE before it looks at ReleaseCount,
     * and a zero count is a legal no-op — never STATUS_INVALID_PARAMETER. So a
     * bad/wrong-type/under-privileged handle reports the handle error even when
     * count is 0. (Wine semantics; docs/09 Art. 6.) */
    {
        HANDLE roSem, closed, ev;
        status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, NULL, 1, 2);
        ok(status == STATUS_SUCCESS, "create for release checks -> %08lx", (unsigned long)status);

        /* count 0 on a valid handle: success, previous count reported, unchanged. */
        uprev = 99;
        status = NtReleaseSemaphore(sem, 0, &uprev);
        ok(status == STATUS_SUCCESS, "release count 0 -> %08lx", (unsigned long)status);
        ok(uprev == 1, "release-0 previous %lu, expected 1", (unsigned long)uprev);
        status = NtReleaseSemaphore(sem, 0, &uprev);
        ok(uprev == 1, "release-0 did not change the count (%lu)", (unsigned long)uprev);

        /* invalid handle + count 0: INVALID_HANDLE, not INVALID_PARAMETER. */
        status = NtCreateSemaphore(&closed, SEMAPHORE_ALL_ACCESS, NULL, 0, 1);
        ok(status == STATUS_SUCCESS, "create-then-close -> %08lx", (unsigned long)status);
        NtClose(closed);
        status = NtReleaseSemaphore(closed, 0, NULL);
        ok(status == STATUS_INVALID_HANDLE, "release closed handle count 0 -> %08lx",
           (unsigned long)status);

        /* wrong-type handle + count 0: OBJECT_TYPE_MISMATCH, not INVALID_PARAMETER. */
        status = NtCreateEvent(&ev, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
        status = NtReleaseSemaphore(ev, 0, NULL);
        ok(status == STATUS_OBJECT_TYPE_MISMATCH, "release event count 0 -> %08lx",
           (unsigned long)status);
        NtClose(ev);

        /* handle without SEMAPHORE_MODIFY_STATE + count 0: ACCESS_DENIED. */
        status = NtDuplicateObject(NtCurrentProcess(), sem, NtCurrentProcess(), &roSem,
                                   SEMAPHORE_QUERY_STATE, 0, 0);
        ok(status == STATUS_SUCCESS, "duplicate query-only -> %08lx", (unsigned long)status);
        status = NtReleaseSemaphore(roSem, 0, NULL);
        ok(status == STATUS_ACCESS_DENIED, "release without MODIFY_STATE count 0 -> %08lx",
           (unsigned long)status);
        NtClose(roSem);
        NtClose(sem);
    }

    /* Wait-multiple parameter conventions: zero or >MAXIMUM_WAIT_OBJECTS
     * handles is STATUS_INVALID_PARAMETER_1; wait-any reports the INDEX of
     * the satisfying object. */
    {
        HANDLE pair[2];
        HANDLE many[MAXIMUM_WAIT_OBJECTS + 1];
        LARGE_INTEGER zero;
        ULONG i;
        zero.QuadPart = 0;

        status = NtCreateEvent(&pair[0], EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
        ok(status == STATUS_SUCCESS, "pair[0] -> %08lx", (unsigned long)status);
        status = NtCreateEvent(&pair[1], EVENT_ALL_ACCESS, NULL, SynchronizationEvent, TRUE);
        ok(status == STATUS_SUCCESS, "pair[1] -> %08lx", (unsigned long)status);

        status = NtWaitForMultipleObjects(0, pair, WaitAny, FALSE, &zero);
        ok(status == STATUS_INVALID_PARAMETER_1, "count 0 -> %08lx", (unsigned long)status);
        for (i = 0; i < MAXIMUM_WAIT_OBJECTS + 1; i++)
            many[i] = pair[0];
        status = NtWaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS + 1, many, WaitAny, FALSE, &zero);
        ok(status == STATUS_INVALID_PARAMETER_1, "count 65 -> %08lx", (unsigned long)status);

        status = NtWaitForMultipleObjects(2, pair, WaitAny, FALSE, &zero);
        ok(status == STATUS_WAIT_1, "wait-any -> %08lx, expected WAIT_1", (unsigned long)status);
        /* Wait-all with one of two unsignalled: times out, consumes NOTHING. */
        NtSetEvent(pair[1], NULL);
        status = NtWaitForMultipleObjects(2, pair, WaitAll, FALSE, &zero);
        ok(status == STATUS_TIMEOUT, "wait-all half-signalled -> %08lx", (unsigned long)status);
        ok(wait_now(pair[1]) == STATUS_SUCCESS, "failed wait-all consumed a sync event");

        NtClose(pair[0]);
        NtClose(pair[1]);
    }
}
