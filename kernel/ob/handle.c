/* kernel/ob/handle.c — the handle table (M3).
 *
 * NT's 3-level tables and pushlocks are unnecessary (docs/05): one growable
 * array of {object, grantedAccess, attributes} entries suffices. There is
 * one table for the whole kernel until Ps brings processes (M4), at which
 * point it becomes the per-process table. Handle values are (index + 1) * 4
 * — NT's multiple-of-4 convention, never 0 — and the low two bits of an
 * incoming handle are ignored, as NT ignores its tag bits.
 */
#include "kernel/ob/ob.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

typedef struct
{
    PVOID body; /* 0 = free slot */
    ACCESS_MASK grantedAccess;
    ULONG attributes; /* OBJ_INHERIT etc., for M4's inheritance */
} OBP_HANDLE_ENTRY, *POBP_HANDLE_ENTRY;

#define OBP_INITIAL_HANDLE_CAPACITY 64

static POBP_HANDLE_ENTRY ObpHandleEntries;
static ULONG ObpHandleCapacity;
static ULONG ObpHandlesInUse;

ACCESS_MASK ObpMapDesiredAccess(POBJECT_TYPE type, ACCESS_MASK desiredAccess)
{
    if (desiredAccess &
        (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED))
    {
        /* Se is always-allow (docs/05): a generic wish grants the type's
         * full mask rather than carrying NT's per-type generic mapping. */
        return type->validAccess;
    }
    return desiredAccess & type->validAccess;
}

/* Handle value <-> table index; returns the entry or 0 when out of range or
 * free. The low two bits are NT's user-mode tag bits — ignored. */
static POBP_HANDLE_ENTRY ObpEntryFromHandle(HANDLE handle)
{
    ULONG_PTR value = (ULONG_PTR)handle & ~(ULONG_PTR)3;
    if (value == 0)
    {
        return 0;
    }
    ULONG_PTR index = value / 4 - 1;
    if (index >= ObpHandleCapacity)
    {
        return 0;
    }
    POBP_HANDLE_ENTRY entry = &ObpHandleEntries[index];
    return entry->body != 0 ? entry : 0;
}

static HANDLE ObpHandleFromIndex(ULONG index)
{
    return (HANDLE)(ULONG_PTR)((index + 1) * 4);
}

NTSTATUS ObpCreateHandle(PVOID body, ACCESS_MASK grantedAccess, ULONG attributes, PHANDLE handleOut)
{
    if (ObpHandleEntries == 0)
    {
        ObpHandleCapacity = OBP_INITIAL_HANDLE_CAPACITY;
        ObpHandleEntries = MiAllocatePool(ObpHandleCapacity * sizeof(OBP_HANDLE_ENTRY));
        if (ObpHandleEntries == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (ObpHandlesInUse == ObpHandleCapacity)
    {
        ULONG newCapacity = ObpHandleCapacity * 2;
        POBP_HANDLE_ENTRY grown = MiAllocatePool(newCapacity * sizeof(OBP_HANDLE_ENTRY));
        if (grown == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(grown, ObpHandleEntries, ObpHandleCapacity * sizeof(OBP_HANDLE_ENTRY));
        MiFreePool(ObpHandleEntries);
        ObpHandleEntries = grown;
        ObpHandleCapacity = newCapacity;
    }

    for (ULONG index = 0; index < ObpHandleCapacity; index++)
    {
        POBP_HANDLE_ENTRY entry = &ObpHandleEntries[index];
        if (entry->body == 0)
        {
            entry->body = body;
            entry->grantedAccess = grantedAccess;
            entry->attributes = attributes;
            ObpHandlesInUse++;
            ObfReferenceObject(body); /* the handle's pointer reference */
            ObpGetHeader(body)->handleCount++;
            *handleOut = ObpHandleFromIndex(index);
            return STATUS_SUCCESS;
        }
    }
    KiPanic("ObpCreateHandle: no free slot below capacity");
}

NTSTATUS ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK desiredAccess, POBJECT_TYPE type,
                                   KPROCESSOR_MODE accessMode, PVOID *body,
                                   POBJECT_HANDLE_INFORMATION handleInformation)
{
    POBP_HANDLE_ENTRY entry = ObpEntryFromHandle(handle);
    if (entry == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    if (type != 0 && ObpGetHeader(entry->body)->type != type)
    {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((entry->grantedAccess & desiredAccess) != desiredAccess)
    {
        return STATUS_ACCESS_DENIED;
    }
    ObfReferenceObject(entry->body);
    *body = entry->body;
    if (handleInformation != 0)
    {
        handleInformation->HandleAttributes = entry->attributes;
        handleInformation->GrantedAccess = entry->grantedAccess;
    }
    return STATUS_SUCCESS;
}

/* Close one table entry: retire a temporary object's name on the last
 * handle, then drop the handle's pointer reference. */
static void ObpCloseHandleEntry(POBP_HANDLE_ENTRY entry)
{
    PVOID body = entry->body;
    POBJECT_HEADER header = ObpGetHeader(body);

    entry->body = 0;
    ASSERT(ObpHandlesInUse > 0);
    ObpHandlesInUse--;

    ASSERT(header->handleCount > 0);
    header->handleCount--;
    if (header->handleCount == 0 && !header->permanent)
    {
        ObpUnlinkObjectName(header);
    }
    ObDereferenceObject(body);
}

NTSTATUS NtClose(HANDLE handle)
{
    POBP_HANDLE_ENTRY entry = ObpEntryFromHandle(handle);
    if (entry == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    ObpCloseHandleEntry(entry);
    return STATUS_SUCCESS;
}

NTSTATUS NtDuplicateObject(HANDLE sourceProcess, HANDLE sourceHandle, HANDLE targetProcess,
                           PHANDLE targetHandle, ACCESS_MASK desiredAccess, ULONG attributes,
                           ULONG options)
{
    /* Until Ps exists (M4) there is one process; only the pseudo-handle can
     * name it. */
    if (sourceProcess != NtCurrentProcess() || targetProcess != NtCurrentProcess())
    {
        return STATUS_INVALID_HANDLE;
    }
    POBP_HANDLE_ENTRY source = ObpEntryFromHandle(sourceHandle);
    if (source == 0)
    {
        return STATUS_INVALID_HANDLE;
    }

    POBJECT_TYPE type = ObpGetHeader(source->body)->type;
    ACCESS_MASK granted = (options & DUPLICATE_SAME_ACCESS)
                              ? source->grantedAccess
                              : ObpMapDesiredAccess(type, desiredAccess);
    ULONG newAttributes = (options & DUPLICATE_SAME_ATTRIBUTES) ? source->attributes : attributes;

    NTSTATUS status = STATUS_SUCCESS;
    if (targetHandle != 0)
    {
        status = ObpCreateHandle(source->body, granted, newAttributes, targetHandle);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    if (options & DUPLICATE_CLOSE_SOURCE)
    {
        /* The source entry may have moved if the table grew: re-resolve. */
        source = ObpEntryFromHandle(sourceHandle);
        ASSERT(source != 0);
        ObpCloseHandleEntry(source);
    }
    return status;
}
