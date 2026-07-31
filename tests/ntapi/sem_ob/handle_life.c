/*
 * sem_ob/handle_life.c — handle-table lifetime rules (M3, docs/02).
 *
 * NtClose conventions (invalid + double close), use of a closed handle,
 * duplication keeping the object alive after the source closes, and the
 * granted-access rule: a handle opened without a right cannot use it, even
 * with security stubbed to always-allow (the check is on the HANDLE).
 */
#include "util.h"

static const void *event_name = W("\\BaseNamedObjects\\prsk_m3_handle_life");

START_TEST(handle_life)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    HANDLE event, dup;
    NTSTATUS status;

    /* Invalid-handle conventions. */
    status = NtClose(NULL);
    ok(status == STATUS_INVALID_HANDLE, "NtClose(NULL) -> %08lx", (unsigned long)status);
    status = NtClose((HANDLE)(ULONG_PTR)0xdead0);
    ok(status == STATUS_INVALID_HANDLE, "NtClose(garbage) -> %08lx", (unsigned long)status);

    /* Double close: the second close must fail, not crash or free twice. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)status);
    status = NtClose(event);
    ok(status == STATUS_SUCCESS, "1st NtClose -> %08lx", (unsigned long)status);
    status = NtClose(event);
    ok(status == STATUS_INVALID_HANDLE, "2nd NtClose -> %08lx", (unsigned long)status);

    /* Any use of a closed handle is STATUS_INVALID_HANDLE. */
    ok(wait_now(event) == STATUS_INVALID_HANDLE, "wait on closed handle succeeded");
    status = NtSetEvent(event, NULL);
    ok(status == STATUS_INVALID_HANDLE, "set on closed handle -> %08lx", (unsigned long)status);

    /* Duplication: the duplicate keeps the object (and its name) alive after
     * DUPLICATE_CLOSE_SOURCE invalidates the source handle. */
    init_ustr(&name, event_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create named event -> %08lx", (unsigned long)status);
    dup = NULL;
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    ok(status == STATUS_SUCCESS, "NtDuplicateObject -> %08lx", (unsigned long)status);
    /* A freed slot may be recycled for the duplicate, so the old value can
     * only be probed when it is distinct from the new handle. */
    if (dup != event)
        ok(wait_now(event) == STATUS_INVALID_HANDLE, "source survived DUPLICATE_CLOSE_SOURCE");
    ok(wait_now(dup) == STATUS_SUCCESS, "duplicate lost the object's signalled state");
    {
        HANDLE reopened;
        status = NtOpenEvent(&reopened, EVENT_ALL_ACCESS, &attr);
        ok(status == STATUS_SUCCESS, "name died though the duplicate lives: %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(reopened);
    }
    status = NtClose(dup);
    ok(status == STATUS_SUCCESS, "close duplicate -> %08lx", (unsigned long)status);

    /* Granted access is a property of the handle: an EVENT_QUERY_STATE-only
     * handle can be waited on only with SYNCHRONIZE, and cannot modify. */
    status = NtCreateEvent(&event, EVENT_QUERY_STATE, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create query-only event -> %08lx", (unsigned long)status);
    status = NtSetEvent(event, NULL);
    ok(status == STATUS_ACCESS_DENIED, "set without EVENT_MODIFY_STATE -> %08lx",
       (unsigned long)status);
    ok(wait_now(event) == STATUS_ACCESS_DENIED, "wait without SYNCHRONIZE succeeded");
    NtClose(event);

    /* NtDuplicateObject grants the SPECIFIC bits as requested — it maps
     * generic bits but never filters by the object type's valid mask
     * (pinned Wine server/handle.c duplicate_handle -> map_access; fuzzer-
     * found via a directory handle duplicated with event rights). The
     * observable: a directory handle opened without SYNCHRONIZE fails a
     * wait with ACCESS_DENIED, while its SYNCHRONIZE-requesting duplicate
     * gets past the access check (the wait then dies on the second, invalid
     * handle instead). */
    {
        HANDLE dir = NULL, waitable = NULL;
        HANDLE handles[2];
        LARGE_INTEGER zero;
        status = NtCreateDirectoryObject(&dir, DIRECTORY_CREATE_OBJECT, NULL);
        ok(status == STATUS_SUCCESS, "create anonymous directory -> %08lx", (unsigned long)status);
        zero.QuadPart = 0;
        handles[0] = dir;
        handles[1] = NULL;
        status = NtWaitForMultipleObjects(2, handles, WaitAll, FALSE, &zero);
        ok(status == STATUS_ACCESS_DENIED, "wait on no-SYNCHRONIZE dir handle -> %08lx",
           (unsigned long)status);
        status = NtDuplicateObject(NtCurrentProcess(), dir, NtCurrentProcess(), &waitable,
                                   EVENT_MODIFY_STATE | SYNCHRONIZE, 0, 0);
        ok(status == STATUS_SUCCESS, "duplicate with event rights -> %08lx", (unsigned long)status);
        handles[0] = waitable;
        status = NtWaitForMultipleObjects(2, handles, WaitAll, FALSE, &zero);
        /* The duplicate's SYNCHRONIZE gets past the access check on both
         * sides; what happens NEXT is a wineserver-vs-NT wrinkle: wineserver
         * parks any object on a wait queue (a directory just never
         * signals), so the scan reaches the invalid second handle
         * (INVALID_HANDLE); NT — and proskrnl — reject the non-dispatcher
         * object itself (OBJECT_TYPE_MISMATCH). docs/03 "M7 fuzzer notes";
         * baselined in tests/fuzz/known_divergences.txt. */
        todo_proskrnl
        {
            ok(status == STATUS_INVALID_HANDLE, "wait past SYNCHRONIZE duplicate -> %08lx",
               (unsigned long)status);
        }
        NtClose(waitable);
        NtClose(dir);
    }
    /* The wait surface's own ring-3 pointers (2026-07 review section 1a):
     * NtWaitForMultipleObjects reads the handle array directly, and both wait
     * services pass the timeout pointer down to KeWaitFor* which dereferences
     * it. Neither was probed. */
    {
        NTSTATUS bs = NtWaitForMultipleObjects(2, (PHANDLE)(ULONG_PTR)0x10000, WaitAll, FALSE,
                                               NULL);
        ok(bs == STATUS_ACCESS_VIOLATION, "wait bad handle array -> %08lx", (unsigned long)bs);
    }

}
