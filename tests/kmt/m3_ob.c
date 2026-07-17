/* tests/kmt/m3_ob.c — the M3 in-kernel suite (docs/02).
 *
 * "Done when: a named event opened from two places resolves to one object;
 * closing a handle drops the ref correctly." Everything here mirrors the
 * tests/ntapi/sem_ob/ oracle suite (greened on Wine first, Art. 5), plus
 * the two things only an in-kernel test can see: the OBJECT_HEADER refcount
 * bookkeeping itself, and KASAN catching pool misuse on demand.
 *
 * Runs on a kernel thread; the Nt* surface is called directly (KernelMode —
 * the syscall boundary arrives in M4).
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/kasan.h"
#include "kernel/lib/rtl.h"

/* --- small helpers (mirroring tests/ntapi/sem_ob/util.h) ------------------ */

static void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name, ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static NTSTATUS wait_now(HANDLE handle)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(handle, FALSE, &zero);
}

/* --- the milestone contract: two places, one object ----------------------- */

static void test_named_event_two_places(void)
{
    UNICODE_STRING name, upname;
    OBJECT_ATTRIBUTES attr;
    HANDLE first, second, third;
    NTSTATUS status;

    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_named_event"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&first, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent: %#x", (unsigned)status);

    status = NtOpenEvent(&second, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtOpenEvent: %#x", (unsigned)status);
    ok(second != first, "open returned the same handle value");

    /* One object behind both handles. */
    ok(wait_now(second) == STATUS_TIMEOUT, "fresh event signalled");
    NtSetEvent(first, 0);
    ok(wait_now(second) == STATUS_SUCCESS, "set via 1 invisible via 2");
    NtResetEvent(second, 0);
    ok(wait_now(first) == STATUS_TIMEOUT, "reset via 2 invisible via 1");

    /* Case-insensitive resolution binds the same object. */
    RtlInitUnicodeString(&upname, WSTR("\\BASENAMEDOBJECTS\\KMT_NAMED_EVENT"));
    init_attr(&attr, 0, &upname, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&third, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "case-insensitive open: %#x", (unsigned)status);
    NtSetEvent(third, 0);
    ok(wait_now(first) == STATUS_SUCCESS, "case-mangled open bound another object");
    NtResetEvent(third, 0);
    NtClose(third);

    /* Collision vs OBJ_OPENIF. */
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&third, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "recreate: %#x", (unsigned)status);
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    status = NtCreateEvent(&third, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_OBJECT_NAME_EXISTS, "create+OPENIF: %#x", (unsigned)status);
    NtSetEvent(third, 0);
    ok(wait_now(first) == STATUS_SUCCESS, "OPENIF bound another object");
    NtClose(third);

    /* Closing the last handle retires the temporary name. */
    NtClose(first);
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&third, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "object died with a handle open: %#x", (unsigned)status);
    NtClose(third);
    NtClose(second);
    status = NtOpenEvent(&third, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "name survived last close: %#x", (unsigned)status);

    /* NTSTATUS conventions. */
    RtlInitUnicodeString(&upname, WSTR("\\BaseNamedObjects\\kmt_no_such\\x"));
    init_attr(&attr, 0, &upname, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&third, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "missing path: %#x", (unsigned)status);
    RtlInitUnicodeString(&upname, WSTR("no_leading_backslash"));
    init_attr(&attr, 0, &upname, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&third, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "relative w/o root: %#x", (unsigned)status);

    /* Type mismatch on open. */
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&first, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "recreate: %#x", (unsigned)status);
    status = NtOpenSemaphore(&third, SEMAPHORE_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "event as semaphore: %#x", (unsigned)status);
    NtClose(first);
}

/* --- refcounts, observed from inside --------------------------------------- */

static void test_refcount_bookkeeping(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE first, second;
    NTSTATUS status;
    PVOID body;

    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_refcount"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&first, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent: %#x", (unsigned)status);

    status =
        ObReferenceObjectByHandle(first, EVENT_QUERY_STATE, &ObpEventType, KernelMode, &body, 0);
    ok(status == STATUS_SUCCESS, "ObReferenceObjectByHandle: %#x", (unsigned)status);
    POBJECT_HEADER header = ObpGetHeader(body);

    /* handle + name + our reference. */
    ok(header->handleCount == 1, "handleCount %d, expected 1", (int)header->handleCount);
    ok(header->pointerCount == 3, "pointerCount %d, expected 3 (handle+name+ref)",
       (int)header->pointerCount);

    status = NtOpenEvent(&second, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtOpenEvent: %#x", (unsigned)status);
    ok(header->handleCount == 2, "handleCount %d after open", (int)header->handleCount);
    ok(header->pointerCount == 4, "pointerCount %d after open", (int)header->pointerCount);

    NtClose(first);
    ok(header->handleCount == 1, "handleCount %d after close", (int)header->handleCount);
    ok(header->pointerCount == 3, "pointerCount %d after close", (int)header->pointerCount);

    /* Last close retires the name (name ref + dir link go) but our reference
     * keeps the object alive. */
    NtClose(second);
    ok(header->handleCount == 0, "handleCount %d after last close", (int)header->handleCount);
    ok(header->pointerCount == 1, "pointerCount %d after last close (our ref)",
       (int)header->pointerCount);
    ok(header->parentDirectory == 0, "name not retired on last close");

    /* The object is still usable through the body reference... */
    ok(KeReadStateEvent(body) == 0, "event state changed by close");
    /* ...and the final dereference frees it (KASAN would flag a UAF). */
    ObDereferenceObject(body);
}

/* --- namespace: directories, relative opens, symlinks ---------------------- */

static void test_namespace(void)
{
    UNICODE_STRING name, target;
    OBJECT_ATTRIBUTES attr;
    HANDLE dir, link, event, other;
    NTSTATUS status;

    /* \Device and \?? exist from boot. */
    RtlInitUnicodeString(&name, WSTR("\\Device"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(&other, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open \\Device: %#x", (unsigned)status);
    NtClose(other);
    RtlInitUnicodeString(&name, WSTR("\\??"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(&other, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open \\??: %#x", (unsigned)status);
    NtClose(other);

    /* A directory, an event inside it, a relative open through it. */
    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_dir"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateDirectoryObject(&dir, DIRECTORY_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtCreateDirectoryObject: %#x", (unsigned)status);

    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_dir\\evt"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event in dir: %#x", (unsigned)status);

    RtlInitUnicodeString(&name, WSTR("evt"));
    init_attr(&attr, dir, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "relative open: %#x", (unsigned)status);
    NtSetEvent(other, 0);
    ok(wait_now(event) == STATUS_SUCCESS, "relative open bound another object");
    NtResetEvent(other, 0);
    NtClose(other);

    /* A symlink into the directory: two paths, one object. */
    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_link"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    RtlInitUnicodeString(&target, WSTR("\\BaseNamedObjects\\kmt_dir"));
    status = NtCreateSymbolicLinkObject(&link, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_SUCCESS, "NtCreateSymbolicLinkObject: %#x", (unsigned)status);

    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_link\\evt"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "open through symlink: %#x", (unsigned)status);
    NtSetEvent(other, 0);
    ok(wait_now(event) == STATUS_SUCCESS, "symlink path bound another object");
    NtClose(other);

    /* Query the link back, including the too-small-buffer convention. */
    {
        WCHAR buffer[64];
        UNICODE_STRING out;
        ULONG needed = 0;
        out.Length = 0;
        out.MaximumLength = sizeof(buffer);
        out.Buffer = buffer;
        status = NtQuerySymbolicLinkObject(link, &out, &needed);
        ok(status == STATUS_SUCCESS, "NtQuerySymbolicLinkObject: %#x", (unsigned)status);
        ok(out.Length == target.Length, "target length %u != %u", out.Length, target.Length);
        ok(RtlEqualUnicodeString(&out, &target, FALSE), "target text differs");
        ok(needed == target.Length + sizeof(WCHAR), "needed %u", (unsigned)needed);

        out.MaximumLength = 2;
        needed = 0;
        status = NtQuerySymbolicLinkObject(link, &out, &needed);
        ok(status == STATUS_BUFFER_TOO_SMALL, "tiny buffer: %#x", (unsigned)status);
        ok(needed == target.Length + sizeof(WCHAR), "needed %u after fail", (unsigned)needed);
    }

    /* A directory is not an event; opening the link itself binds the link. */
    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_dir"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "dir as event: %#x", (unsigned)status);
    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_link"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenSymbolicLinkObject(&other, SYMBOLIC_LINK_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open the link itself: %#x", (unsigned)status);
    NtClose(other);

    NtClose(event);
    NtClose(link);
    NtClose(dir);
}

/* --- handle lifetime -------------------------------------------------------- */

static void test_handle_life(void)
{
    HANDLE event, dup;
    NTSTATUS status;

    status = NtClose(0);
    ok(status == STATUS_INVALID_HANDLE, "NtClose(0): %#x", (unsigned)status);
    status = NtClose((HANDLE)(ULONG_PTR)0xdead0);
    ok(status == STATUS_INVALID_HANDLE, "NtClose(garbage): %#x", (unsigned)status);

    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, 0, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "unnamed create: %#x", (unsigned)status);
    ok(NtClose(event) == STATUS_SUCCESS, "1st close failed");
    ok(NtClose(event) == STATUS_INVALID_HANDLE, "2nd close succeeded");
    ok(wait_now(event) == STATUS_INVALID_HANDLE, "wait on closed handle");
    ok(NtSetEvent(event, 0) == STATUS_INVALID_HANDLE, "set on closed handle");

    /* Duplication keeps the object alive across DUPLICATE_CLOSE_SOURCE. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, 0, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create: %#x", (unsigned)status);
    dup = 0;
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    ok(status == STATUS_SUCCESS, "NtDuplicateObject: %#x", (unsigned)status);
    if (dup != event)
    {
        ok(wait_now(event) == STATUS_INVALID_HANDLE, "source survived CLOSE_SOURCE");
    }
    ok(wait_now(dup) == STATUS_SUCCESS, "duplicate lost the signalled state");
    ok(NtClose(dup) == STATUS_SUCCESS, "close duplicate failed");

    /* Granted access is checked per use. */
    status = NtCreateEvent(&event, EVENT_QUERY_STATE, 0, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "query-only create: %#x", (unsigned)status);
    ok(NtSetEvent(event, 0) == STATUS_ACCESS_DENIED, "set without MODIFY_STATE");
    ok(wait_now(event) == STATUS_ACCESS_DENIED, "wait without SYNCHRONIZE");
    {
        EVENT_BASIC_INFORMATION info;
        status = NtQueryEvent(event, EventBasicInformation, &info, sizeof(info), 0);
        ok(status == STATUS_SUCCESS, "query with QUERY_STATE: %#x", (unsigned)status);
    }
    NtClose(event);
}

/* --- Nt-level dispatcher semantics ----------------------------------------- */

static void test_sync_objects(void)
{
    HANDLE event, mutant, sem;
    NTSTATUS status;
    LONG prev;
    ULONG uprev;

    /* Events: previous state, query, pulse. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, 0, SynchronizationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent: %#x", (unsigned)status);
    prev = -1;
    NtSetEvent(event, &prev);
    ok(prev == 0, "set previous %d", (int)prev);
    prev = -1;
    NtSetEvent(event, &prev);
    ok(prev == 1, "2nd set previous %d", (int)prev);
    {
        EVENT_BASIC_INFORMATION info;
        status = NtQueryEvent(event, EventBasicInformation, &info, sizeof(info), 0);
        ok(status == STATUS_SUCCESS, "NtQueryEvent: %#x", (unsigned)status);
        ok(info.EventType == SynchronizationEvent, "queried type %d", (int)info.EventType);
        ok(info.EventState == 1, "queried state %d", (int)info.EventState);
        ok(wait_now(event) == STATUS_SUCCESS, "query consumed the event");
        ok(wait_now(event) == STATUS_TIMEOUT, "wait did not consume");
    }
    NtSetEvent(event, 0);
    prev = -1;
    status = NtPulseEvent(event, &prev);
    ok(status == STATUS_SUCCESS, "NtPulseEvent: %#x", (unsigned)status);
    ok(prev == 1, "pulse previous %d", (int)prev);
    ok(wait_now(event) == STATUS_TIMEOUT, "still signalled after pulse");
    NtClose(event);

    /* Mutants: initial ownership, recursion, release discipline. */
    status = NtCreateMutant(&mutant, MUTANT_ALL_ACCESS, 0, TRUE);
    ok(status == STATUS_SUCCESS, "NtCreateMutant: %#x", (unsigned)status);
    ok(wait_now(mutant) == STATUS_SUCCESS, "recursive acquire");
    {
        MUTANT_BASIC_INFORMATION info;
        status = NtQueryMutant(mutant, MutantBasicInformation, &info, sizeof(info), 0);
        ok(status == STATUS_SUCCESS, "NtQueryMutant: %#x", (unsigned)status);
        ok(info.CurrentCount == -1, "count %d", (int)info.CurrentCount);
        ok(info.OwnedByCaller == TRUE, "not owned by caller");
        ok(info.AbandonedState == FALSE, "abandoned");
    }
    prev = -99;
    ok(NtReleaseMutant(mutant, &prev) == STATUS_SUCCESS, "1st release");
    ok(prev == -1, "release previous %d", (int)prev);
    prev = -99;
    ok(NtReleaseMutant(mutant, &prev) == STATUS_SUCCESS, "2nd release");
    ok(prev == 0, "release previous %d", (int)prev);
    ok(NtReleaseMutant(mutant, 0) == STATUS_MUTANT_NOT_OWNED, "over-release");
    NtClose(mutant);

    /* Semaphores: limits and counts. */
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, 0, 5, 3);
    ok(status == STATUS_INVALID_PARAMETER, "initial>max: %#x", (unsigned)status);
    status = NtCreateSemaphore(&sem, SEMAPHORE_ALL_ACCESS, 0, 1, 2);
    ok(status == STATUS_SUCCESS, "NtCreateSemaphore: %#x", (unsigned)status);
    uprev = 99;
    ok(NtReleaseSemaphore(sem, 1, &uprev) == STATUS_SUCCESS, "release");
    ok(uprev == 1, "previous count %u", (unsigned)uprev);
    ok(NtReleaseSemaphore(sem, 1, 0) == STATUS_SEMAPHORE_LIMIT_EXCEEDED, "over-release");
    {
        SEMAPHORE_BASIC_INFORMATION info;
        status = NtQuerySemaphore(sem, SemaphoreBasicInformation, &info, sizeof(info), 0);
        ok(status == STATUS_SUCCESS, "NtQuerySemaphore: %#x", (unsigned)status);
        ok(info.CurrentCount == 2, "count %u", (unsigned)info.CurrentCount);
        ok(info.MaximumCount == 2, "maximum %u", (unsigned)info.MaximumCount);
    }
    ok(wait_now(sem) == STATUS_SUCCESS, "sem wait 1");
    ok(wait_now(sem) == STATUS_SUCCESS, "sem wait 2");
    ok(wait_now(sem) == STATUS_TIMEOUT, "sem over-count");
    NtClose(sem);

    /* Wait-multiple conventions. */
    {
        HANDLE pair[2];
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        NtCreateEvent(&pair[0], EVENT_ALL_ACCESS, 0, SynchronizationEvent, FALSE);
        NtCreateEvent(&pair[1], EVENT_ALL_ACCESS, 0, SynchronizationEvent, TRUE);

        status = NtWaitForMultipleObjects(0, pair, WaitAny, FALSE, &zero);
        ok(status == STATUS_INVALID_PARAMETER_1, "count 0: %#x", (unsigned)status);
        status = NtWaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS + 1, pair, WaitAny, FALSE, &zero);
        ok(status == STATUS_INVALID_PARAMETER_1, "count 65: %#x", (unsigned)status);

        status = NtWaitForMultipleObjects(2, pair, WaitAny, FALSE, &zero);
        ok(status == STATUS_WAIT_1, "wait-any: %#x", (unsigned)status);
        NtSetEvent(pair[1], 0);
        status = NtWaitForMultipleObjects(2, pair, WaitAll, FALSE, &zero);
        ok(status == STATUS_TIMEOUT, "wait-all half-signalled: %#x", (unsigned)status);
        ok(wait_now(pair[1]) == STATUS_SUCCESS, "failed wait-all consumed");

        NtClose(pair[0]);
        NtClose(pair[1]);
    }
}

/* --- handle-based waits meet the dispatcher across threads ----------------- */

static HANDLE blocking_wait_handle;
static int blocking_wait_done;

static void blocking_waiter(void *context)
{
    NTSTATUS status = NtWaitForSingleObject(blocking_wait_handle, FALSE, 0);
    if (status == STATUS_SUCCESS)
    {
        blocking_wait_done = 1;
    }
}

static void test_blocking_handle_wait(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE mine, theirs;
    NTSTATUS status;

    RtlInitUnicodeString(&name, WSTR("\\BaseNamedObjects\\kmt_blocking"));
    init_attr(&attr, 0, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&mine, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "NtCreateEvent: %#x", (unsigned)status);
    status = NtOpenEvent(&theirs, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtOpenEvent: %#x", (unsigned)status);

    blocking_wait_handle = theirs;
    blocking_wait_done = 0;
    PKTHREAD waiter = KiCreateThread(8, blocking_waiter, 0);
    LARGE_INTEGER pause;
    pause.QuadPart = -10LL * 10000; /* 10 ms: let the waiter block */
    KeDelayExecutionThread(KernelMode, FALSE, &pause);
    ok(blocking_wait_done == 0, "waiter completed before the set");

    NtSetEvent(mine, 0);
    status = KeWaitForSingleObject(waiter, Executive, KernelMode, FALSE, 0);
    ok(status == STATUS_SUCCESS, "join: %#x", (unsigned)status);
    KiDeleteThread(waiter);
    ok(blocking_wait_done == 1, "set through one handle did not wake the other's waiter");

    NtClose(theirs);
    NtClose(mine);
}

/* --- KASAN catches what Ob would bleed ------------------------------------- */

static void test_kasan_catches(void)
{
    int reports = 0;
    volatile unsigned char *data = MiAllocatePool(24);
    ok(data != 0, "pool allocation failed");

    /* A valid access reports nothing. */
    MiKasanSetReportCounter(&reports);
    (void)data[0];
    (void)data[23];
    ok(reports == 0, "valid accesses reported (%d)", reports);

    /* Out of bounds: one byte past the requested size is red zone. */
    (void)data[24];
    ok(reports == 1, "out-of-bounds read not caught (%d reports)", reports);

    /* Use after free. */
    MiFreePool((void *)data);
    (void)data[0];
    ok(reports == 2, "use-after-free read not caught (%d reports)", reports);

    /* Header underflow from a fresh allocation. */
    volatile unsigned char *fresh = MiAllocatePool(24);
    (void)fresh[-1];
    ok(reports == 3, "header underflow not caught (%d reports)", reports);
    MiFreePool((void *)fresh);

    MiKasanSetReportCounter(0);
}

/* --- pool balance across the whole suite ------------------------------------ */

int kmt_run_m3(void)
{
    int failures_before = kmt_failures;

    /* Warm up the lazily-allocated handle table so it is not counted as a
     * "leak" by the balance check below (it persists by design). */
    {
        HANDLE warm;
        if (NtCreateEvent(&warm, EVENT_ALL_ACCESS, 0, NotificationEvent, FALSE) == STATUS_SUCCESS)
        {
            NtClose(warm);
        }
    }
    uint64_t pool_before = MiGetPoolBytesInUse();

    KMT_RUN(test_named_event_two_places);
    KMT_RUN(test_refcount_bookkeeping);
    KMT_RUN(test_namespace);
    KMT_RUN(test_handle_life);
    KMT_RUN(test_sync_objects);
    KMT_RUN(test_blocking_handle_wait);
    KMT_RUN(test_kasan_catches);

    /* Every object the suite created died with its last handle: the pool
     * must balance (the handle table itself may have grown; it persists). */
    ok(MiGetPoolBytesInUse() == pool_before,
       "pool leak: %lu bytes before, %lu after (Ob leaked an object?)", (unsigned long)pool_before,
       (unsigned long)MiGetPoolBytesInUse());
    DbgPrint("[KTEST] m3_pool_balance %s\n",
             MiGetPoolBytesInUse() == pool_before ? "PASS" : "FAIL");

    return kmt_failures - failures_before;
}
