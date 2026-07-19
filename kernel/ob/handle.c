/* kernel/ob/handle.c — the handle table (M3; per-process since M4).
 *
 * NT's 3-level tables and pushlocks are unnecessary (docs/05): one growable
 * array of {object, grantedAccess, attributes} entries suffices. Since M4
 * the table lives inside EPROCESS and handle values resolve against the
 * CURRENT thread's process (kernel threads resolve against the system
 * process, so kmt callers keep working). Handle values are (index + 1) * 4
 * — NT's multiple-of-4 convention, never 0 — and the low two bits of an
 * incoming handle are ignored, as NT ignores its tag bits.
 */
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

typedef struct
{
    PVOID body; /* 0 = free slot */
    ACCESS_MASK grantedAccess;
    ULONG attributes; /* OBJ_INHERIT etc., for later inheritance */
} OBP_HANDLE_ENTRY, *POBP_HANDLE_ENTRY;

#define OBP_INITIAL_HANDLE_CAPACITY 64

/* Handles belong to the calling thread's process (docs/05: the handle table
 * became per-process the moment Ps existed). */
static POBP_HANDLE_TABLE ObpCurrentTable(void)
{
    PEPROCESS process = KeGetCurrentThread()->process;
    ASSERT(process != 0);
    return &process->handleTable;
}

void ObpInitializeHandleTable(POBP_HANDLE_TABLE table)
{
    table->entries = 0;
    table->capacity = 0;
    table->inUse = 0;
}

void ObpDeleteHandleTable(POBP_HANDLE_TABLE table)
{
    ASSERT(table->inUse == 0);
    if (table->entries != 0)
    {
        MiFreePool(table->entries);
        table->entries = 0;
        table->capacity = 0;
    }
}

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
    POBP_HANDLE_TABLE table = ObpCurrentTable();
    ULONG_PTR value = (ULONG_PTR)handle & ~(ULONG_PTR)3;
    if (value == 0)
    {
        return 0;
    }
    ULONG_PTR index = value / 4 - 1;
    if (index >= table->capacity)
    {
        return 0;
    }
    POBP_HANDLE_ENTRY entry = (POBP_HANDLE_ENTRY)table->entries + index;
    return entry->body != 0 ? entry : 0;
}

static HANDLE ObpHandleFromIndex(ULONG index)
{
    return (HANDLE)(ULONG_PTR)((index + 1) * 4);
}

NTSTATUS ObpCreateHandle(PVOID body, ACCESS_MASK grantedAccess, ULONG attributes, PHANDLE handleOut)
{
    POBP_HANDLE_TABLE table = ObpCurrentTable();

    /* Every create/open/duplicate writes its result through here, so this is
     * THE choke point for the out-handle user probe. */
    NTSTATUS probeStatus = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }

    if (table->entries == 0)
    {
        table->capacity = OBP_INITIAL_HANDLE_CAPACITY;
        table->entries = MiAllocatePool(table->capacity * sizeof(OBP_HANDLE_ENTRY));
        if (table->entries == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (table->inUse == table->capacity)
    {
        ULONG newCapacity = table->capacity * 2;
        POBP_HANDLE_ENTRY grown = MiAllocatePool(newCapacity * sizeof(OBP_HANDLE_ENTRY));
        if (grown == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(grown, table->entries, table->capacity * sizeof(OBP_HANDLE_ENTRY));
        MiFreePool(table->entries);
        table->entries = grown;
        table->capacity = newCapacity;
    }

    POBP_HANDLE_ENTRY entries = table->entries;
    for (ULONG index = 0; index < table->capacity; index++)
    {
        POBP_HANDLE_ENTRY entry = &entries[index];
        if (entry->body == 0)
        {
            entry->body = body;
            entry->grantedAccess = grantedAccess;
            entry->attributes = attributes;
            table->inUse++;
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
static void ObpCloseHandleEntryIn(POBP_HANDLE_TABLE table, POBP_HANDLE_ENTRY entry)
{
    PVOID body = entry->body;
    POBJECT_HEADER header = ObpGetHeader(body);

    entry->body = 0;
    ASSERT(table->inUse > 0);
    table->inUse--;

    ASSERT(header->handleCount > 0);
    header->handleCount--;
    if (header->handleCount == 0)
    {
        /* NT's CloseProcedure moment: the last handle is gone but references
         * may keep the object alive (M6 Io cleanup runs here — share-mode
         * release and delete-on-close belong to handle lifetime, not object
         * lifetime). */
        if (header->type->closeProcedure != 0)
        {
            header->type->closeProcedure(body);
        }
        if (!header->permanent)
        {
            ObpUnlinkObjectName(header);
        }
    }
    ObDereferenceObject(body);
}

static void ObpCloseHandleEntry(POBP_HANDLE_ENTRY entry)
{
    ObpCloseHandleEntryIn(ObpCurrentTable(), entry);
}

void ObpCloseAllHandles(POBP_HANDLE_TABLE table)
{
    POBP_HANDLE_ENTRY entries = table->entries;
    for (ULONG index = 0; index < table->capacity && table->inUse > 0; index++)
    {
        if (entries[index].body != 0)
        {
            ObpCloseHandleEntryIn(table, &entries[index]);
        }
    }
    ASSERT(table->inUse == 0);
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
    /* Duplication maps generic wishes but grants SPECIFIC bits verbatim —
     * never filtered by the type's valid mask (Wine server/handle.c
     * duplicate_handle -> map_access keeps non-generic bits untouched;
     * sem_ob/handle_life pins the observable: a directory duplicate asking
     * event rights carries SYNCHRONIZE past a wait's access check). The
     * generic wish keeps the documented docs/03 over-grant deviation. */
    ACCESS_MASK granted;
    if (options & DUPLICATE_SAME_ACCESS)
    {
        granted = source->grantedAccess;
    }
    else
    {
        const ACCESS_MASK generics =
            GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED;
        granted = desiredAccess & ~generics;
        if (desiredAccess & generics)
        {
            granted |= type->validAccess;
        }
    }
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
