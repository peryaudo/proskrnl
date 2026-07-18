/*
 * sem_ob/make_temporary.c — NtMakeTemporaryObject access + effect.
 *
 * NtMakeTemporaryObject clears an object's permanent flag, and NT gates that on
 * DELETE access to the handle: a handle without DELETE is STATUS_ACCESS_DENIED,
 * even though the object is reachable. Pinned on the Wine oracle first (docs/09
 * Art. 5/6 — Wine is the operative oracle).
 */
#include "util.h"

#ifndef DELETE
#define DELETE 0x00010000 /* wine/include/winnt.h */
#endif

START_TEST(make_temporary)
{
    NTSTATUS status;
    HANDLE full, roHandle, delHandle, closed;

    /* A full-access handle carries DELETE: make-temporary succeeds. */
    status = NtCreateEvent(&full, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)status);
    status = NtMakeTemporaryObject(full);
    ok(status == STATUS_SUCCESS, "make-temporary with DELETE -> %08lx", (unsigned long)status);

    /* A handle WITHOUT DELETE (query only): STATUS_ACCESS_DENIED, not success. */
    status = NtDuplicateObject(NtCurrentProcess(), full, NtCurrentProcess(), &roHandle,
                               EVENT_QUERY_STATE, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate query-only -> %08lx", (unsigned long)status);
    status = NtMakeTemporaryObject(roHandle);
    ok(status == STATUS_ACCESS_DENIED, "make-temporary without DELETE -> %08lx",
       (unsigned long)status);
    NtClose(roHandle);

    /* DELETE alone is sufficient. */
    status =
        NtDuplicateObject(NtCurrentProcess(), full, NtCurrentProcess(), &delHandle, DELETE, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate DELETE-only -> %08lx", (unsigned long)status);
    status = NtMakeTemporaryObject(delHandle);
    ok(status == STATUS_SUCCESS, "make-temporary with DELETE only -> %08lx", (unsigned long)status);
    NtClose(delHandle);

    /* A closed (invalid) handle is still an invalid-handle error. */
    status = NtCreateEvent(&closed, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent(closed) -> %08lx", (unsigned long)status);
    NtClose(closed);
    status = NtMakeTemporaryObject(closed);
    ok(status == STATUS_INVALID_HANDLE, "make-temporary invalid handle -> %08lx",
       (unsigned long)status);

    NtClose(full);
}
