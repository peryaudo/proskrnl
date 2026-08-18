/*
 * sem_ps/apc_reserve.c — reserve objects and NtQueueApcThreadEx (docs/21 W10).
 *
 * NtAllocateReserveObject mints a pre-allocation for ONE queued item: a
 * UserApcReserve holds the storage of one user APC, an IoCompletionReserve
 * that of one completion packet (server/object.c create_reserve, whose two
 * object_ops differ only in their type name). NtQueueApcThreadEx is the
 * legacy calling form over NtQueueApcThreadEx2 and folds its QUEUE_USER_APC_*
 * flags into the LOW TWO BITS of the reserve handle (dlls/ntdll/unix/thread.c:
 * `flags = (ULONG_PTR)reserve_handle & 3; reserve_handle &= ~3`), which is
 * behind the syscall boundary — so it is the kernel's unpacking to do, not
 * ntdll's.
 *
 * What the pinned oracle fixes here, and none of it follows from the names:
 *
 *   - the reserve is resolved BEFORE the target thread handle
 *     (server/thread.c DECL_HANDLER(queue_apc) — the APC_USER arm associates
 *     the reserve, then calls get_thread_from_handle), so a bad thread handle
 *     reports the RESERVE's error when the reserve is the one at fault;
 *   - a reserve already carrying a queued APC refuses the next one with
 *     STATUS_INVALID_PARAMETER_2 (reserve_obj_associate_apc's `bound_obj`
 *     test), and the binding is released when the APC is DESTROYED — by
 *     delivery, or by a queue that failed after the association;
 *   - a wrong-type reserve (an IoCompletionReserve, or any other object) is
 *     STATUS_OBJECT_TYPE_MISMATCH, from the same get_handle_obj that answers
 *     STATUS_INVALID_HANDLE for a value naming nothing.
 *
 * The tests/winetest consumer is dlls/ntdll/tests/thread.c
 * test_NtQueueApcThreadEx, which is where `ntdll:thread` stopped.
 */
#include "util.h"

typedef VOID(NTAPI *rsv_apcfunc)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(PHANDLE, const OBJECT_ATTRIBUTES *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx(HANDLE, HANDLE, rsv_apcfunc, ULONG_PTR, ULONG_PTR,
                                           ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx2(HANDLE, HANDLE, ULONG, rsv_apcfunc, ULONG_PTR,
                                            ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif
/* wine/include/processthreadsapi.h QUEUE_USER_APC_FLAGS (mingw may omit). */
#ifndef QUEUE_USER_APC_FLAGS_NONE
#define QUEUE_USER_APC_FLAGS_NONE 0
#endif
#ifndef QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
#define QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC 0x00000001
#endif
#ifndef QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
#define QUEUE_USER_APC_CALLBACK_DATA_CONTEXT 0x00010000
#endif

/* wine/include/winternl.h MEMORY_RESERVE_OBJECT_TYPE, spelled as constants so
 * the file compiles against either header set (abi/ntpsapi.h carries the same
 * generated enum; the values are positional in both). */
#define RSV_USER_APC      0
#define RSV_IO_COMPLETION 1

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

/* A thread handle value naming nothing: outside the pseudo-handle range and
 * far past any table this process has grown. */
#define BOGUS_HANDLE ((HANDLE)(ULONG_PTR)0xdead0)

static volatile LONG apc_calls;
static volatile ULONG_PTR apc_last_a1;

static VOID NTAPI count_apc(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3)
{
    (void)a2;
    (void)a3;
    apc_last_a1 = a1;
    InterlockedIncrement(&apc_calls);
}

/* One alertable point: delivers every APC queued to this thread. */
static NTSTATUS alertable_poll(void)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtDelayExecution(TRUE, &zero);
}

static void init_unicode(UNICODE_STRING *string, const void *wide)
{
    const unsigned short *text = (const unsigned short *)wide;
    unsigned length = 0;
    while (text[length])
        length++;
    string->Length = (USHORT)(length * 2);
    string->MaximumLength = (USHORT)(length * 2 + 2);
    string->Buffer = (PWSTR)(void *)text;
}

static int type_name_is(HANDLE handle, const void *wide)
{
    BYTE raw[512];
    ULONG used = 0;
    memset(raw, 0, sizeof(raw));
    if (NtQueryObject(handle, ObjectTypeInformation, raw, sizeof(raw), &used) != STATUS_SUCCESS)
        return 0;
    UNICODE_STRING *name = (UNICODE_STRING *)raw; /* TypeName is the first field */
    const unsigned short *want = (const unsigned short *)wide;
    unsigned length = 0;
    while (want[length])
        length++;
    if (name->Length != (USHORT)(length * 2))
        return 0;
    return memcmp(name->Buffer, want, length * 2) == 0;
}

START_TEST(apc_reserve)
{
    NTSTATUS status;
    HANDLE reserve = NULL, iocp = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* --- NtAllocateReserveObject's argument rules -------------------------- */

    /* The out-handle is written before anything else is looked at, so a NULL
     * slot faults rather than refusing (unix/server.c opens with
     * `*handle = 0;`). */
    status = NtAllocateReserveObject(NULL, NULL, RSV_USER_APC);
    ok(status == STATUS_ACCESS_VIOLATION, "alloc NULL out -> %08lx", (unsigned long)status);

    reserve = (HANDLE)(ULONG_PTR)0xdead;
    status = NtAllocateReserveObject(&reserve, NULL, RSV_USER_APC);
    ok(status == STATUS_SUCCESS, "alloc user-apc -> %08lx", (unsigned long)status);
    ok(reserve != NULL && reserve != (HANDLE)(ULONG_PTR)0xdead, "alloc gave a handle %p", reserve);
    ok(type_name_is(reserve, W("UserApcReserve")), "user-apc reserve type name");
    ok(NtClose(reserve) == STATUS_SUCCESS, "close user-apc reserve");

    reserve = (HANDLE)(ULONG_PTR)0xdead;
    status = NtAllocateReserveObject(&reserve, NULL, RSV_IO_COMPLETION + 1);
    ok(status == STATUS_INVALID_PARAMETER, "alloc bad type -> %08lx", (unsigned long)status);
    ok(reserve == NULL, "bad type cleared the slot: %p", reserve);

    /* A reserve object cannot be NAMED: create_reserve refuses a non-empty
     * name outright, before it looks at the type. */
    init_unicode(&name, W("\\BaseNamedObjects\\prsk_apc_reserve"));
    InitializeObjectAttributes(&attr, &name, 0, NULL, NULL);
    status = NtAllocateReserveObject(&reserve, &attr, RSV_USER_APC);
    ok(status == STATUS_OBJECT_NAME_INVALID, "alloc named -> %08lx", (unsigned long)status);

    /* ...but an OBJECT_ATTRIBUTES block carrying no name is fine. */
    attr.ObjectName = NULL;
    status = NtAllocateReserveObject(&reserve, &attr, RSV_USER_APC);
    ok(status == STATUS_SUCCESS, "alloc nameless attr -> %08lx", (unsigned long)status);
    ok(NtClose(reserve) == STATUS_SUCCESS, "close nameless-attr reserve");

    status = NtAllocateReserveObject(&iocp, NULL, RSV_IO_COMPLETION);
    ok(status == STATUS_SUCCESS, "alloc io-completion -> %08lx", (unsigned long)status);
    ok(type_name_is(iocp, W("IoCompletionReserve")), "io-completion reserve type name");

    /* --- NtQueueApcThreadEx: the flags ride in the handle's low two bits --- */

    /* QUEUE_USER_APC_CALLBACK_DATA_CONTEXT is 0x10000, i.e. NOT in the low two
     * bits — so this argument survives the mask whole and is read as a handle
     * naming nothing. (dlls/ntdll/tests/thread.c:328.) */
    apc_calls = 0;
    status = NtQueueApcThreadEx(NtCurrentThread(), (HANDLE)QUEUE_USER_APC_CALLBACK_DATA_CONTEXT,
                                count_apc, 1, 2, 3);
    ok(status == STATUS_INVALID_HANDLE, "Ex callback-data-context -> %08lx", (unsigned long)status);

    /* QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC is 1: the mask takes it as a FLAG
     * and leaves a NULL reserve handle behind. An implementation that read the
     * word as a handle would answer STATUS_INVALID_HANDLE here. */
    status = NtQueueApcThreadEx(NtCurrentThread(), (HANDLE)QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
                                count_apc, 0x1234, 0x5678, 0xdeadbeef);
    ok(status == STATUS_SUCCESS, "Ex special-flag -> %08lx", (unsigned long)status);
    ok(alertable_poll() == STATUS_USER_APC, "special-flag poll");
    ok(apc_calls == 1 && apc_last_a1 == 0x1234, "special-flag apc %ld/%lx", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* The current-THREAD pseudo-handle passed as a reserve: -2 masks down to
     * -4, which is the current PROCESS TOKEN pseudo-handle (server/handle.c
     * get_magic_handle), and a token is not a UserApcReserve. */
    status = NtQueueApcThreadEx(NtCurrentThread(), NtCurrentThread(), count_apc, 1, 2, 3);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "Ex thread-as-reserve -> %08lx",
       (unsigned long)status);

    /* An IoCompletionReserve is a reserve of the OTHER kind: same refusal. */
    status = NtQueueApcThreadEx(NtCurrentThread(), iocp, count_apc, 1, 2, 3);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "Ex io-completion reserve -> %08lx",
       (unsigned long)status);

    /* --- one reserve holds one APC at a time ------------------------------- */

    status = NtAllocateReserveObject(&reserve, NULL, RSV_USER_APC);
    ok(status == STATUS_SUCCESS, "alloc queueing reserve -> %08lx", (unsigned long)status);
    ok(((ULONG_PTR)reserve & 3) == 0, "reserve handle is tag-free: %p", reserve);

    apc_calls = 0;
    status = NtQueueApcThreadEx(NtCurrentThread(), reserve, count_apc, 10, 0, 0);
    ok(status == STATUS_SUCCESS, "reserve queue 1 -> %08lx", (unsigned long)status);
    status = NtQueueApcThreadEx(NtCurrentThread(), reserve, count_apc, 11, 0, 0);
    ok(status == STATUS_INVALID_PARAMETER_2, "reserve queue while bound -> %08lx",
       (unsigned long)status);
    ok(alertable_poll() == STATUS_USER_APC, "bound-reserve poll");
    ok(apc_calls == 1 && apc_last_a1 == 10, "one apc ran %ld/%lu", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* Delivery released the binding, so the same reserve serves again — and
     * the flag bits OR'd into the handle do not stop it naming the object. */
    apc_calls = 0;
    status = NtQueueApcThreadEx(
        NtCurrentThread(), (HANDLE)((ULONG_PTR)reserve | QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC),
        count_apc, 12, 0, 0);
    ok(status == STATUS_SUCCESS, "reserve queue after delivery -> %08lx", (unsigned long)status);
    status = NtQueueApcThreadEx(NtCurrentThread(), reserve, count_apc, 13, 0, 0);
    ok(status == STATUS_INVALID_PARAMETER_2, "tagged handle bound the same reserve -> %08lx",
       (unsigned long)status);
    ok(alertable_poll() == STATUS_USER_APC, "tagged-handle poll");
    ok(apc_calls == 1 && apc_last_a1 == 12, "tagged apc %ld/%lu", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* --- the reserve is resolved BEFORE the target thread ------------------ */

    apc_calls = 0;
    status = NtQueueApcThreadEx(NtCurrentThread(), reserve, count_apc, 20, 0, 0);
    ok(status == STATUS_SUCCESS, "ordering: bind the reserve -> %08lx", (unsigned long)status);
    status = NtQueueApcThreadEx(BOGUS_HANDLE, reserve, count_apc, 21, 0, 0);
    ok(status == STATUS_INVALID_PARAMETER_2, "bound reserve + bad thread -> %08lx",
       (unsigned long)status);
    ok(alertable_poll() == STATUS_USER_APC, "ordering poll");
    ok(apc_calls == 1 && apc_last_a1 == 20, "ordering apc %ld/%lu", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* A FREE reserve with the same bad thread handle reports the THREAD's
     * error — and the association the failed call made is released with the
     * APC it was made for, so the reserve is immediately usable again. */
    apc_calls = 0;
    status = NtQueueApcThreadEx(BOGUS_HANDLE, reserve, count_apc, 22, 0, 0);
    ok(status == STATUS_INVALID_HANDLE, "free reserve + bad thread -> %08lx",
       (unsigned long)status);
    status = NtQueueApcThreadEx(NtCurrentThread(), reserve, count_apc, 23, 0, 0);
    ok(status == STATUS_SUCCESS, "reserve reusable after a failed queue -> %08lx",
       (unsigned long)status);
    ok(alertable_poll() == STATUS_USER_APC, "reuse poll");
    ok(apc_calls == 1 && apc_last_a1 == 23, "reuse apc %ld/%lu", (long)apc_calls,
       (unsigned long)apc_last_a1);

    /* --- Ex2 takes a reserve too, with its flags spelled out --------------- */

    apc_calls = 0;
    status = NtQueueApcThreadEx2(NtCurrentThread(), reserve, QUEUE_USER_APC_FLAGS_NONE, count_apc,
                                 30, 0, 0);
    ok(status == STATUS_SUCCESS, "Ex2 with reserve -> %08lx", (unsigned long)status);
    status = NtQueueApcThreadEx2(NtCurrentThread(), reserve, QUEUE_USER_APC_FLAGS_NONE, count_apc,
                                 31, 0, 0);
    ok(status == STATUS_INVALID_PARAMETER_2, "Ex2 reserve while bound -> %08lx",
       (unsigned long)status);
    status = NtQueueApcThreadEx2(NtCurrentThread(), iocp, QUEUE_USER_APC_FLAGS_NONE, count_apc, 32,
                                 0, 0);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "Ex2 wrong reserve type -> %08lx",
       (unsigned long)status);

    /* Closing the last HANDLE while an APC is still bound to the reserve must
     * not take the object out from under the queued APC: the APC owns a
     * reference for as long as it can still be delivered. */
    ok(NtClose(reserve) == STATUS_SUCCESS, "close bound reserve");
    ok(alertable_poll() == STATUS_USER_APC, "closed-reserve poll");
    ok(apc_calls == 1 && apc_last_a1 == 30, "apc survived its reserve's close %ld/%lu",
       (long)apc_calls, (unsigned long)apc_last_a1);

    ok(NtClose(iocp) == STATUS_SUCCESS, "close io-completion reserve");
}
