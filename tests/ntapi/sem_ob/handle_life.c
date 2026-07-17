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
}
