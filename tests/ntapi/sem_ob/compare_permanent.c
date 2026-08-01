/*
 * sem_ob/compare_permanent.c — NtCompareObjects, NtMakePermanentObject and
 * NtOpenTimer (CUI-6).
 *
 * CompareObjectHandles (kernelbase) and the permanence pair. Oracle
 * behaviour pinned from the pinned tree (server/handle.c compare_objects /
 * set_object_permanence; dlls/ntdll/unix/server.c, unix/sync.c): compare
 * resolves both handles with ZERO required access and answers
 * STATUS_NOT_SAME_OBJECT for distinct bodies; make-permanent also needs no
 * access at all (the temporary direction keeps requiring DELETE, pinned in
 * sem_ob/make_temporary) and is idempotent — a permanent object survives
 * its last handle and reopens by name. NtOpenTimer is the plain
 * open-by-name against the Timer type (dlls/ntdll/unix/sync.c
 * NtOpenTimer).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCompareObjects(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMakePermanentObject(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateTimer(HANDLE *, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenTimer(HANDLE *, ACCESS_MASK, const OBJECT_ATTRIBUTES *);

#ifndef TIMER_ALL_ACCESS
#define TIMER_ALL_ACCESS 0x001F0003 /* wine/include/winnt.h */
#endif
/* mingw's ntstatus.h omits it; value as wine/include/ntstatus.h. */
#ifndef STATUS_NOT_SAME_OBJECT
#define STATUS_NOT_SAME_OBJECT ((NTSTATUS)0xC00001AC)
#endif
/* TIMER_TYPE value as wine/include/winternl.h defines it. */
#define TIMER_NOTIFICATION 0

static const void *perm_name = W("\\BaseNamedObjects\\prsk_cui6_perm_event");
static const void *timer_name = W("\\BaseNamedObjects\\prsk_cui6_open_timer");

START_TEST(compare_permanent)
{
    NTSTATUS status;
    HANDLE event = NULL, other = NULL, dup = NULL, reopened = NULL, timer = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* --- NtCompareObjects ------------------------------------------------ */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    status = NtCreateEvent(&other, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create other -> %08lx", (unsigned long)status);

    /* A zero-access duplicate still compares (the server resolves both
     * handles with access 0). */
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "dup zero-access -> %08lx", (unsigned long)status);
    status = NtCompareObjects(event, dup);
    ok(status == STATUS_SUCCESS, "same body -> %08lx", (unsigned long)status);
    status = NtCompareObjects(event, other);
    ok(status == STATUS_NOT_SAME_OBJECT, "distinct bodies -> %08lx", (unsigned long)status);
    status = NtCompareObjects(event, (HANDLE)(ULONG_PTR)0xdead0);
    ok(status == STATUS_INVALID_HANDLE, "bad second handle -> %08lx", (unsigned long)status);
    status = NtCompareObjects((HANDLE)(ULONG_PTR)0xdead0, event);
    ok(status == STATUS_INVALID_HANDLE, "bad first handle -> %08lx", (unsigned long)status);
    NtClose(dup);
    NtClose(other);
    NtClose(event);
    event = NULL;

    /* --- NtMakePermanentObject ------------------------------------------- */
    init_ustr(&name, perm_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create named -> %08lx", (unsigned long)status);

    /* No access needed: a zero-access duplicate may flip permanence on. */
    dup = NULL;
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "dup for permanence -> %08lx", (unsigned long)status);
    status = NtMakePermanentObject(dup);
    ok(status == STATUS_SUCCESS, "make permanent -> %08lx", (unsigned long)status);
    status = NtMakePermanentObject(dup);
    ok(status == STATUS_SUCCESS, "make permanent again -> %08lx", (unsigned long)status);
    NtClose(dup);
    status = NtClose(event);
    ok(status == STATUS_SUCCESS, "close last handle -> %08lx", (unsigned long)status);
    event = NULL;

    /* The object survived its last handle: reopen by name. */
    status = NtOpenEvent(&reopened, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "reopen permanent -> %08lx", (unsigned long)status);

    /* Back to temporary (DELETE-bearing handle), close, and it is gone. */
    status = NtMakeTemporaryObject(reopened);
    ok(status == STATUS_SUCCESS, "make temporary -> %08lx", (unsigned long)status);
    status = NtClose(reopened);
    ok(status == STATUS_SUCCESS, "close temporary -> %08lx", (unsigned long)status);
    reopened = NULL;
    status = NtOpenEvent(&reopened, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "reopen after temporary -> %08lx",
       (unsigned long)status);

    /* --- NtOpenTimer ------------------------------------------------------ */
    init_ustr(&name, timer_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateTimer(&timer, TIMER_ALL_ACCESS, &attr, TIMER_NOTIFICATION);
    ok(status == STATUS_SUCCESS, "create named timer -> %08lx", (unsigned long)status);
    reopened = NULL;
    status = NtOpenTimer(&reopened, TIMER_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "open timer -> %08lx", (unsigned long)status);
    status = NtCompareObjects(timer, reopened);
    ok(status == STATUS_SUCCESS, "open resolves to the same body -> %08lx", (unsigned long)status);
    NtClose(reopened);

    /* Wrong type behind the name. */
    reopened = NULL;
    status = NtOpenEvent(&reopened, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "open timer as event -> %08lx",
       (unsigned long)status);

    /* Missing name. */
    init_ustr(&name, W("\\BaseNamedObjects\\prsk_cui6_no_such_timer"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    reopened = NULL;
    status = NtOpenTimer(&reopened, TIMER_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open missing timer -> %08lx",
       (unsigned long)status);
    NtClose(timer);
}
