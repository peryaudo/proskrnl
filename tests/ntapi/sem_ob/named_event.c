/*
 * sem_ob/named_event.c — the M3 "done when" contract (docs/02).
 *
 * A named event created in the object namespace and opened from a second
 * place must resolve to ONE object: state changes through either handle are
 * visible through the other. Closing every handle drops the last reference
 * and the (temporary) name disappears from the namespace. Name lookup obeys
 * OBJ_CASE_INSENSITIVE, collides with STATUS_OBJECT_NAME_COLLISION unless
 * OBJ_OPENIF turns the collision into STATUS_OBJECT_NAME_EXISTS, and the
 * missing-leaf vs missing-path NTSTATUS conventions hold.
 */
#include "util.h"

static const void *event_name = W("\\BaseNamedObjects\\prsk_m3_named_event");
static const void *event_name_upcased = W("\\BASENAMEDOBJECTS\\PRSK_M3_NAMED_EVENT");
static const void *missing_leaf = W("\\BaseNamedObjects\\prsk_m3_no_such_object");
static const void *missing_path = W("\\BaseNamedObjects\\prsk_m3_no_such_dir\\x");

START_TEST(named_event)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE first, second, byif;
    NTSTATUS status;

    /* Create a named notification event, initially non-signalled. */
    init_ustr(&name, event_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&first, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent -> %08lx", (unsigned long)status);

    /* Open the same name from a "second place": a distinct handle... */
    status = NtOpenEvent(&second, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtOpenEvent -> %08lx", (unsigned long)status);
    ok(second != first, "open returned the same handle value");

    /* ...onto ONE object: a set through the first handle is visible through
     * the second, a reset through the second is visible through the first. */
    ok(wait_now(second) == STATUS_TIMEOUT, "fresh event must be non-signalled");
    status = NtSetEvent(first, NULL);
    ok(status == STATUS_SUCCESS, "NtSetEvent -> %08lx", (unsigned long)status);
    ok(wait_now(second) == STATUS_SUCCESS, "set via handle 1 not visible via handle 2");
    status = NtResetEvent(second, NULL);
    ok(status == STATUS_SUCCESS, "NtResetEvent -> %08lx", (unsigned long)status);
    ok(wait_now(first) == STATUS_TIMEOUT, "reset via handle 2 not visible via handle 1");

    /* OBJ_CASE_INSENSITIVE: a case-mangled name resolves to the same object. */
    {
        UNICODE_STRING upname;
        OBJECT_ATTRIBUTES upattr;
        HANDLE upper;
        init_ustr(&upname, event_name_upcased);
        init_attr(&upattr, NULL, &upname, OBJ_CASE_INSENSITIVE);
        status = NtOpenEvent(&upper, EVENT_ALL_ACCESS, &upattr);
        ok(status == STATUS_SUCCESS, "case-insensitive open -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            NtSetEvent(upper, NULL);
            ok(wait_now(first) == STATUS_SUCCESS, "case-mangled open bound a different object");
            NtResetEvent(upper, NULL);
            NtClose(upper);
        }
    }

    /* Creating over an existing name collides... */
    status = NtCreateEvent(&byif, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "recreate -> %08lx, expected collision",
       (unsigned long)status);

    /* ...unless OBJ_OPENIF asks for open-if-exists: the informational success
     * STATUS_OBJECT_NAME_EXISTS, and the handle is onto the SAME object. */
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    status = NtCreateEvent(&byif, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_OBJECT_NAME_EXISTS, "create+OPENIF -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtSetEvent(byif, NULL);
        ok(wait_now(first) == STATUS_SUCCESS, "OPENIF handle bound a different object");
        status = NtClose(byif);
        ok(status == STATUS_SUCCESS, "NtClose(byif) -> %08lx", (unsigned long)status);
    }

    /* Closing every handle drops the last reference: the temporary name
     * vanishes and a reopen must fail with STATUS_OBJECT_NAME_NOT_FOUND. */
    status = NtClose(first);
    ok(status == STATUS_SUCCESS, "NtClose(first) -> %08lx", (unsigned long)status);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&byif, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "object died while a handle remains: %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(byif);
    status = NtClose(second);
    ok(status == STATUS_SUCCESS, "NtClose(second) -> %08lx", (unsigned long)status);
    status = NtOpenEvent(&byif, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND,
       "reopen after all handles closed -> %08lx, expected name-not-found", (unsigned long)status);

    /* NTSTATUS conventions: a missing leaf is NAME_NOT_FOUND; a missing
     * intermediate directory is PATH_NOT_FOUND. */
    init_ustr(&name, missing_leaf);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&byif, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing leaf -> %08lx", (unsigned long)status);
    init_ustr(&name, missing_path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&byif, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "missing path -> %08lx", (unsigned long)status);

    /* Opening a name that exists as another type is a type mismatch. */
    init_ustr(&name, event_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&first, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "recreate for mismatch check -> %08lx", (unsigned long)status);
    status = NtOpenSemaphore(&byif, SEMAPHORE_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "open event as semaphore -> %08lx",
       (unsigned long)status);
    NtClose(first);
}
