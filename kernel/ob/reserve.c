/* kernel/ob/reserve.c — reserve objects (docs/21 W10).
 *
 * NtAllocateReserveObject mints a pre-allocation for exactly ONE queued item,
 * so that the service that consumes it cannot fail for want of memory at the
 * moment it is needed. NT has two kinds and this file has both: a
 * UserApcReserve holds the storage of one user APC (consumed by
 * NtQueueApcThreadEx/Ex2, kernel/ps/thread.c) and an IoCompletionReserve that
 * of one completion packet (NtSetIoCompletionEx, kernel/io/completion.c).
 *
 * The APC kind carries its KAPC INSIDE the object rather than keeping a flag
 * beside a pool allocation, because that is what the object is for: with the
 * block embedded, "this reserve is in use" and "this storage is spoken for"
 * are one fact, and a queue through a reserve reaches no allocator at all.
 * The completion kind pre-allocates nothing — the pinned server does not
 * either (server/object.c leaves `/ * BYTE *memory * /` commented out beside
 * `struct reserve`), and nothing at the boundary can see the difference:
 * add_completion resolves the handle, checks its type, and posts an ordinary
 * packet. Building storage no consumer reads would be furniture, not fidelity.
 *
 * Both types are unnameable (create_reserve refuses a non-empty name before it
 * looks at the type at all) and are pinned by tests/ntapi/sem_ps/apc_reserve.c
 * and the reserve half of tests/ntapi/sem_port/ports.c.
 */
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/init/panic.h"
#include "abi/ntpsapi.h"

/* One body for both types, as the server has one `struct reserve` for both. */
typedef struct OBP_RESERVE
{
    /* The KAPC currently queued out of `apc`, or 0 when the reserve is free.
     * It is the block's own address whenever it is set — a pointer rather
     * than a flag so an ASSERT can catch a release naming the wrong one. */
    struct KAPC *boundApc;
    KAPC apc; /* the pre-allocation itself (UserApcReserve only) */
} OBP_RESERVE, *POBP_RESERVE;

/* Nothing can delete a reserve that is still carrying an APC: the block holds
 * a reference for exactly as long as it can still be delivered. */
static void ObpDeleteReserve(PVOID body)
{
    POBP_RESERVE reserve = body;
    ASSERT(reserve->boundApc == 0);
}

/* The GENERIC_MAPPING and valid mask of both types, as wineserver composes
 * them (server/object.c apc_reserve_type / completion_reserve_type): the
 * standard rights plus the type's own two object-specific bits, and no
 * SYNCHRONIZE — a reserve is not waitable. */
#define OBP_RESERVE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x3)

OBJECT_TYPE ObpApcReserveType = {
    .name = "UserApcReserve",
    .validAccess = OBP_RESERVE_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = ObpDeleteReserve,
    .genericRead = STANDARD_RIGHTS_READ | 0x1,
    .genericWrite = STANDARD_RIGHTS_WRITE | 0x2,
    .genericExecute = STANDARD_RIGHTS_EXECUTE,
    .genericAll = OBP_RESERVE_ALL_ACCESS,
};

OBJECT_TYPE ObpIoCompletionReserveType = {
    .name = "IoCompletionReserve",
    .validAccess = OBP_RESERVE_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = ObpDeleteReserve,
    .genericRead = STANDARD_RIGHTS_READ | 0x1,
    .genericWrite = STANDARD_RIGHTS_WRITE | 0x2,
    .genericExecute = STANDARD_RIGHTS_EXECUTE,
    .genericAll = OBP_RESERVE_ALL_ACCESS,
};

NTSTATUS ObpAcquireApcReserve(HANDLE handle, struct KAPC **apcOut)
{
    *apcOut = 0;
    PVOID body;
    NTSTATUS status =
        ObReferenceObjectByHandle(handle, 0, &ObpApcReserveType, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    POBP_RESERVE reserve = body;
    if (reserve->boundApc != 0)
    {
        /* Already carrying one. The status names the ARGUMENT rather than the
         * state, which is the server's own answer and not a guess:
         * reserve_obj_associate_apc sets STATUS_INVALID_PARAMETER_2. */
        ObDereferenceObject(body);
        return STATUS_INVALID_PARAMETER_2;
    }
    reserve->boundApc = &reserve->apc;
    reserve->apc.reserveObject = body; /* the reference stays with the block */
    *apcOut = &reserve->apc;
    return STATUS_SUCCESS;
}

void ObpReleaseApcReserve(struct KAPC *apc)
{
    POBP_RESERVE reserve = apc->reserveObject;
    ASSERT(reserve != 0);
    ASSERT(reserve->boundApc == apc);
    reserve->boundApc = 0;
    apc->reserveObject = 0;
    ObDereferenceObject(reserve);
}

/* The oracle's order of checks, and each step is measurable: the out-handle is
 * written first (dlls/ntdll/unix/server.c opens with `*handle = 0;`, so a NULL
 * slot faults before anything is validated), then a non-empty NAME refuses —
 * ahead of the type, because server/object.c create_reserve tests `name->len`
 * before its type switch — and only then is the kind resolved. */
NTSTATUS NtAllocateReserveObject(PHANDLE handle, const OBJECT_ATTRIBUTES *attr,
                                 MEMORY_RESERVE_OBJECT_TYPE type)
{
    NTSTATUS clearStatus = ObpClearOutHandle(handle);
    if (!NT_SUCCESS(clearStatus))
    {
        return clearStatus;
    }
    NTSTATUS probeStatus = ObProbeObjectAttributes(attr);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    if (attr != 0 && attr->ObjectName != 0 && attr->ObjectName->Length != 0)
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    POBJECT_TYPE objectType;
    if (type == MemoryReserveObjectTypeUserApc)
    {
        objectType = &ObpApcReserveType;
    }
    else if (type == MemoryReserveObjectTypeIoCompletion)
    {
        objectType = &ObpIoCompletionReserveType;
    }
    else
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* The server hands the creator GENERIC_READ | GENERIC_WRITE without an
     * access check (alloc_handle_no_access_check, DECL_HANDLER of
     * allocate_reserve_object); the caller names no desired access at all. */
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(objectType, sizeof(OBP_RESERVE), attr,
                                                GENERIC_READ | GENERIC_WRITE, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        POBP_RESERVE reserve = body;
        reserve->boundApc = 0;
        reserve->apc.reserveObject = 0;
    }
    return status;
}
