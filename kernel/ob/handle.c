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
        if (type->genericAll != 0)
        {
            /* The type carries a real NT GENERIC_MAPPING (see ob.h). */
            ACCESS_MASK granted = desiredAccess & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE |
                                                    GENERIC_ALL | MAXIMUM_ALLOWED);
            if (desiredAccess & GENERIC_READ)
            {
                granted |= type->genericRead;
            }
            if (desiredAccess & GENERIC_WRITE)
            {
                granted |= type->genericWrite;
            }
            if (desiredAccess & GENERIC_EXECUTE)
            {
                granted |= type->genericExecute;
            }
            if (desiredAccess & (GENERIC_ALL | MAXIMUM_ALLOWED))
            {
                granted |= type->genericAll;
            }
            return granted & type->validAccess;
        }
        /* Se is always-allow (docs/05): a generic wish grants the type's
         * full mask rather than carrying NT's per-type generic mapping. */
        return type->validAccess;
    }
    return desiredAccess & type->validAccess;
}

/* Handle value <-> table index against an EXPLICIT table; returns the entry
 * or 0 when out of range or free. The low two bits are NT's user-mode tag
 * bits — ignored. Every lookup lands here: the current process's table
 * (ObpEntryFromHandle), the parent's at inheritance, and either end of a
 * cross-process duplication. */
static POBP_HANDLE_ENTRY ObpEntryInTable(POBP_HANDLE_TABLE table, HANDLE handle)
{
    ULONG_PTR value = (ULONG_PTR)handle & ~(ULONG_PTR)3;
    if (value == 0 || table->entries == 0)
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

static POBP_HANDLE_ENTRY ObpEntryFromHandle(HANDLE handle)
{
    return ObpEntryInTable(ObpCurrentTable(), handle);
}

static HANDLE ObpHandleFromIndex(ULONG index)
{
    return (HANDLE)(ULONG_PTR)((index + 1) * 4);
}

NTSTATUS ObpCreateHandle(PVOID body, ACCESS_MASK grantedAccess, ULONG attributes, PHANDLE handleOut)
{
    /* Every create/open/duplicate writes its result through here, so this is
     * THE choke point for the out-handle user probe. */
    NTSTATUS probeStatus = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    return ObpCreateHandleInTable(ObpCurrentTable(), body, grantedAccess, attributes, handleOut);
}

/* Kernel-internal, table-explicit creation (M9: the console handles a
 * process is born with live in ITS table, seeded by the creator —
 * kernel pointers only, no probe). */
NTSTATUS ObpCreateHandleInTable(POBP_HANDLE_TABLE table, PVOID body, ACCESS_MASK grantedAccess,
                                ULONG attributes, PHANDLE handleOut)
{
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

/* --- consistency-sweep checks (kernel/init/verify.c; lock held) ------------ */

PVOID ObpHandleTableObjectAt(POBP_HANDLE_TABLE table, ULONG index)
{
    if (table->entries == 0 || index >= table->capacity)
    {
        return 0;
    }
    return ((POBP_HANDLE_ENTRY)table->entries)[index].body;
}

/* One table's internal invariants: inUse agrees with the occupied slots, and
 * every occupied slot points at a live object whose bookkeeping at least
 * accounts for this handle. The cross-table handleCount recount lives in the
 * sweep orchestrator (it needs every table at once). */
void ObpVerifyHandleTable(POBP_HANDLE_TABLE table)
{
    ASSERT(table->inUse <= table->capacity);
    ULONG occupied = 0;
    for (ULONG index = 0; index < table->capacity; index++)
    {
        PVOID body = ObpHandleTableObjectAt(table, index);
        if (body == 0)
        {
            continue;
        }
        occupied++;
        POBJECT_HEADER header = ObpGetHeader(body);
        ASSERT(header->type != 0 && header->type->name != 0);
        ASSERT(header->handleCount >= 1);
        ASSERT(header->pointerCount >=
               header->handleCount + (header->parentDirectory != 0 ? 1 : 0));
        if (header->type->waitable)
        {
            KiVerifyWaitList(body);
        }
    }
    ASSERT(occupied == table->inUse);
}

NTSTATUS ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK desiredAccess, POBJECT_TYPE type,
                                   KPROCESSOR_MODE accessMode, PVOID *body,
                                   POBJECT_HANDLE_INFORMATION handleInformation)
{
    /* CUI-2: the magic token pseudo-handles, resolved before the table
     * exactly as wineserver's get_magic_handle (server/handle.c) resolves
     * them — ~3 the process token, ~4 the thread token (none exists in
     * CUI-2), ~5 the thread-effective token (falls back to the process
     * token). Magic handles bypass the access check (get_handle_obj grabs
     * without checking; get_handle_access reports all rights) but keep the
     * type check. */
    ULONG_PTR value = (ULONG_PTR)handle;
    if (value >= (ULONG_PTR)-6 && value <= (ULONG_PTR)-4)
    {
        PVOID token = 0;
        if (value != (ULONG_PTR)-5) /* ~3 and ~5 resolve to the process token */
        {
            token = KeGetCurrentThread()->process->token;
        }
        if (token == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        if (type != 0 && ObpGetHeader(token)->type != type)
        {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        ObfReferenceObject(token);
        *body = token;
        if (handleInformation != 0)
        {
            handleInformation->HandleAttributes = 0;
            handleInformation->GrantedAccess = ~(ACCESS_MASK)0;
        }
        return STATUS_SUCCESS;
    }

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
    /* Closing any pseudo handle in [~5, ~0] is a successful no-op (the
     * oracle's unix layer short-circuits before the server ever sees it:
     * dlls/ntdll/unix/server.c NtClose's HandleToLong range check). */
    if ((ULONG_PTR)handle >= (ULONG_PTR)-6)
    {
        return STATUS_SUCCESS;
    }
    POBP_HANDLE_ENTRY entry = ObpEntryFromHandle(handle);
    if (entry == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    /* CUI-6: protect-from-close is enforced here, not stored-and-ignored
     * (wineserver close_handle: RESERVED_CLOSE_PROTECT refuses and the
     * handle stays live; sem_ob/handle_flags pins it). */
    if (entry->attributes & OBJ_PROTECT_CLOSE)
    {
        return STATUS_HANDLE_NOT_CLOSABLE;
    }
    ObpCloseHandleEntry(entry);
    return STATUS_SUCCESS;
}

/* CUI-6: the SetHandleInformation back end. One class; per-handle flag bits
 * stored in the entry's attributes word, the same bits OBJ_INHERIT/
 * OBJ_PROTECT_CLOSE occupy at create/duplicate time. The set always writes
 * BOTH flags (the oracle's mask is INHERIT|PROTECT_FROM_CLOSE, never
 * partial: dlls/ntdll/unix/file.c NtSetInformationObject); magic
 * pseudo-handles refuse with STATUS_ACCESS_DENIED (server/handle.c
 * set_handle_flags: "we can retrieve but not set info for magic handles"). */
NTSTATUS NtSetInformationObject(HANDLE handle, OBJECT_INFORMATION_CLASS infoClass, PVOID buffer,
                                ULONG length)
{
    switch (infoClass)
    {
    case ObjectHandleFlagInformation:
    {
        if (length < sizeof(OBJECT_HANDLE_FLAG_INFORMATION))
        {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        OBJECT_HANDLE_FLAG_INFORMATION info;
        NTSTATUS status = KiCopyFromUser(&info, buffer, sizeof(info));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if ((ULONG_PTR)handle >= (ULONG_PTR)-6)
        {
            return STATUS_ACCESS_DENIED;
        }
        POBP_HANDLE_ENTRY entry = ObpEntryFromHandle(handle);
        if (entry == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        entry->attributes &= ~(OBJ_INHERIT | OBJ_PROTECT_CLOSE);
        if (info.Inherit)
        {
            entry->attributes |= OBJ_INHERIT;
        }
        if (info.ProtectFromClose)
        {
            entry->attributes |= OBJ_PROTECT_CLOSE;
        }
        return STATUS_SUCCESS;
    }
    default:
        /* Unbuilt classes refuse loudly (Art. 12); the oracle's unix layer
         * answers the same status for every class it does not marshal. */
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* Resolve one end of a duplication to its process. The current-process
 * pseudo-handle is answered without a reference (the caller's own process
 * cannot go away underneath it); any other handle must GRANT
 * PROCESS_DUP_HANDLE, which is the right NT checks on both ends
 * (wineserver's duplicate_handle asks get_process_from_handle for
 * PROCESS_DUP_HANDLE on source and target alike, server/handle.c). */
static NTSTATUS ObpReferenceDupProcess(HANDLE processHandle, PEPROCESS *processOut,
                                       BOOLEAN *referenced)
{
    if (processHandle == NtCurrentProcess())
    {
        *processOut = KeGetCurrentThread()->process;
        *referenced = FALSE;
        return STATUS_SUCCESS;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_DUP_HANDLE, &PspProcessType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *processOut = body;
    *referenced = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS NtDuplicateObject(HANDLE sourceProcess, HANDLE sourceHandle, HANDLE targetProcess,
                           PHANDLE targetHandle, ACCESS_MASK desiredAccess, ULONG attributes,
                           ULONG options)
{
    /* Either end may name a FOREIGN process (GUI-3): wineserver-lite hands a
     * queue's sync event out to a client and pulls a client's window-station
     * directory handle in, which is how NT hands win32k handles across too.
     * The object is looked up in the SOURCE's table and created in the
     * TARGET's; DUPLICATE_CLOSE_SOURCE closes the entry in whichever process
     * owns it, not in the caller's. Pinned by sem_ob/dup_cross_process. */
    PEPROCESS sourceProc, targetProc;
    BOOLEAN sourceReferenced, targetReferenced;
    NTSTATUS status = ObpReferenceDupProcess(sourceProcess, &sourceProc, &sourceReferenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = ObpReferenceDupProcess(targetProcess, &targetProc, &targetReferenced);
    if (!NT_SUCCESS(status))
    {
        if (sourceReferenced)
        {
            ObDereferenceObject(sourceProc);
        }
        return status;
    }

    POBP_HANDLE_TABLE sourceTable = &sourceProc->handleTable;
    POBP_HANDLE_ENTRY source = ObpEntryInTable(sourceTable, sourceHandle);
    if (source == 0)
    {
        status = STATUS_INVALID_HANDLE;
        goto release;
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
        /* The generic half goes through ObpMapDesiredAccess -- THE mapping
         * authority (Art. 11) -- rather than being open-coded here. This
         * used to grant type->validAccess for any generic wish, ignoring the
         * type's real GENERIC_MAPPING, and the two had already drifted:
         * duplicating a keyed-event handle with GENERIC_READ granted wake
         * rights the original open correctly denied
         * (docs/review-2026-07 §9). The specific bits stay verbatim, which
         * is the pinned behaviour described above. */
        granted = desiredAccess & ~generics;
        if (desiredAccess & generics)
        {
            granted |= ObpMapDesiredAccess(type, desiredAccess & generics);
        }
    }
    ULONG newAttributes = (options & DUPLICATE_SAME_ATTRIBUTES) ? source->attributes : attributes;

    status = STATUS_SUCCESS;
    if (targetHandle != 0)
    {
        /* The out-pointer is the CALLER's, whichever processes the two ends
         * name — probe it here rather than through ObpCreateHandle, whose
         * table is implicitly the current one. */
        status = KiProbeForWrite(targetHandle, sizeof(*targetHandle), sizeof(*targetHandle));
        if (NT_SUCCESS(status))
        {
            /* Hold the body across the insert. The insert takes its own
             * reference on success, but it can allocate, and the source table
             * now belongs to a process whose OWN threads may close the handle
             * — so the transient reference is what keeps the body alive
             * between reading it here and the insert referencing it. */
            PVOID body = source->body;
            ObfReferenceObject(body);
            status = ObpCreateHandleInTable(&targetProc->handleTable, body, granted, newAttributes,
                                            targetHandle);
            ObDereferenceObject(body);
        }
        if (!NT_SUCCESS(status))
        {
            goto release;
        }
    }
    if (options & DUPLICATE_CLOSE_SOURCE)
    {
        /* The source entry may have moved if the table grew (it can be the
         * same table as the target's): re-resolve. A source that vanished
         * meanwhile is nothing left to close. */
        source = ObpEntryInTable(sourceTable, sourceHandle);
        if (source != 0)
        {
            ObpCloseHandleEntryIn(sourceTable, source);
        }
    }

release:
    if (targetReferenced)
    {
        ObDereferenceObject(targetProc);
    }
    if (sourceReferenced)
    {
        ObDereferenceObject(sourceProc);
    }
    return status;
}

/* --- M10: inheritance at process creation ---------------------------------- */

/* Copy one parent handle into the child AT THE SAME INDEX, if it exists, is
 * inherit-marked, and the slot is still free — wineserver's inherit_handle
 * (server/handle.c) exactly. */
static void ObpInheritOne(POBP_HANDLE_TABLE parent, POBP_HANDLE_TABLE child, HANDLE handle)
{
    POBP_HANDLE_ENTRY source = ObpEntryInTable(parent, handle);
    if (source == 0 || (source->attributes & OBJ_INHERIT) == 0)
    {
        return;
    }
    ULONG_PTR index = ((ULONG_PTR)handle & ~(ULONG_PTR)3) / 4 - 1;
    POBP_HANDLE_ENTRY destination = (POBP_HANDLE_ENTRY)child->entries + index;
    if (destination->body != 0)
    {
        return; /* listed twice / also a std handle */
    }
    *destination = *source;
    ObfReferenceObject(source->body);
    ObpGetHeader(source->body)->handleCount++;
    child->inUse++;
}

NTSTATUS ObpInheritHandles(POBP_HANDLE_TABLE parent, POBP_HANDLE_TABLE child,
                           const HANDLE *handleList, ULONG handleCount, const HANDLE stdHandles[3])
{
    ASSERT(child->inUse == 0); /* a fresh process's table */
    if (parent->entries == 0)
    {
        return STATUS_SUCCESS;
    }
    if (child->entries == 0 || child->capacity < parent->capacity)
    {
        PVOID grown = MiAllocatePool(parent->capacity * sizeof(OBP_HANDLE_ENTRY));
        if (grown == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (child->entries != 0)
        {
            MiFreePool(child->entries);
        }
        child->entries = grown;
        child->capacity = parent->capacity;
    }
    memset(child->entries, 0, child->capacity * sizeof(OBP_HANDLE_ENTRY));

    if (handleList == 0)
    {
        /* Inherit-all: every inherit-marked entry, same index. */
        POBP_HANDLE_ENTRY sources = parent->entries;
        POBP_HANDLE_ENTRY destinations = child->entries;
        for (ULONG index = 0; index < parent->capacity; index++)
        {
            if (sources[index].body == 0 || (sources[index].attributes & OBJ_INHERIT) == 0)
            {
                continue;
            }
            destinations[index] = sources[index];
            ObfReferenceObject(sources[index].body);
            ObpGetHeader(sources[index].body)->handleCount++;
            child->inUse++;
        }
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < handleCount; i++)
    {
        ObpInheritOne(parent, child, handleList[i]);
    }
    for (int i = 0; i < 3; i++)
    {
        ObpInheritOne(parent, child, stdHandles[i]);
    }
    return STATUS_SUCCESS;
}

NTSTATUS ObpDuplicateIntoTable(POBP_HANDLE_TABLE parent, HANDLE source, POBP_HANDLE_TABLE child,
                               BOOLEAN sameAttributes, PHANDLE handleOut)
{
    POBP_HANDLE_ENTRY entry = ObpEntryInTable(parent, source);
    if (entry == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    return ObpCreateHandleInTable(child, entry->body, entry->grantedAccess,
                                  sameAttributes ? entry->attributes : 0, handleOut);
}

/* --- NtQueryObject (M10 winetest) ------------------------------------------ */

/* The three classes the CUI tests read, shaped as the oracle reports them
 * (dlls/ntdll/unix/file.c NtQueryObject over wineserver's get_object_info/
 * get_object_name/get_object_type): Basic is GrantedAccess + the counts;
 * Name is the namespace path for header-named objects and the empty
 * OBJECT_NAME_INFORMATION for anonymous ones; Type is the type name with
 * the string buffer right after the struct. Consumer: kernel32:directory
 * (TEST_GRANTED_ACCESS). */
NTSTATUS NtQueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS infoClass, PVOID buffer,
                       ULONG length, PULONG returnLength)
{
    /* Validate the out-length once, up front. The class arms below each
     * wrote through it: the success paths with no probe at all, and the two
     * length-mismatch paths with a KiProbeForWrite whose RESULT WAS
     * DISCARDED -- the store went ahead regardless, which made a bad pointer
     * a 4-byte kernel write of a caller-influenced value rather than the
     * refusal the probe had just computed. */
    if (returnLength != 0)
    {
        NTSTATUS probeStatus = KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(probeStatus))
        {
            return probeStatus;
        }
    }
    /* CUI-6: a magic pseudo-handle answers the flag query with both flags
     * clear (wineserver set_handle_flags returns 0 for a zero mask on a
     * magic handle; sem_ob/handle_flags pins it) — resolved before the
     * table, which knows nothing of pseudo handles. */
    if (infoClass == ObjectHandleFlagInformation && (ULONG_PTR)handle >= (ULONG_PTR)-6)
    {
        if (length < sizeof(OBJECT_HANDLE_FLAG_INFORMATION))
        {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        NTSTATUS magicStatus = KiProbeForWrite(buffer, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 1);
        if (!NT_SUCCESS(magicStatus))
        {
            return magicStatus;
        }
        OBJECT_HANDLE_FLAG_INFORMATION magicInfo;
        memset(&magicInfo, 0, sizeof(magicInfo));
        memcpy(buffer, &magicInfo, sizeof(magicInfo));
        if (returnLength != 0)
        {
            ULONG used = sizeof(magicInfo);
            memcpy(returnLength, &used, sizeof(used));
        }
        return STATUS_SUCCESS;
    }

    POBP_HANDLE_ENTRY entry = ObpEntryFromHandle(handle);
    if (entry == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    POBJECT_HEADER header = ObpGetHeader(entry->body);
    NTSTATUS status;

    switch (infoClass)
    {
    case ObjectBasicInformation:
    {
        if (length < sizeof(OBJECT_BASIC_INFORMATION))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        status = KiProbeForWrite(buffer, sizeof(OBJECT_BASIC_INFORMATION), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        OBJECT_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.Attributes = entry->attributes;
        info.GrantedAccess = entry->grantedAccess;
        info.HandleCount = (ULONG)header->handleCount;
        info.PointerCount = (ULONG)header->pointerCount;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            ULONG used = sizeof(info);
            memcpy(returnLength, &used, sizeof(used));
        }
        return STATUS_SUCCESS;
    }
    case ObjectNameInformation:
    {
        /* The FULL path, walked to the root -- not the leaf component. The
         * oracle builds it the same way (its get_full_name walks
         * name->parent), and a caller that gets "prsk_evt" where NT gives
         * "\BaseNamedObjects\prsk_evt" cannot tell two objects of the same
         * leaf name apart (docs/review-2026-07 §9). */
        USHORT nameBytes = ObpFullNameLength(header);
        ULONG needed =
            sizeof(OBJECT_NAME_INFORMATION) + (nameBytes != 0 ? nameBytes + sizeof(WCHAR) : 0);
        if (length < sizeof(OBJECT_NAME_INFORMATION) || (nameBytes != 0 && length < needed))
        {
            if (returnLength != 0)
            {
                memcpy(returnLength, &needed, sizeof(needed));
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        OBJECT_NAME_INFORMATION *info = buffer;
        if (nameBytes == 0)
        {
            memset(info, 0, sizeof(*info));
        }
        else
        {
            WCHAR *nameOut = (WCHAR *)(info + 1);
            ObpWriteFullName(header, nameOut);
            nameOut[nameBytes / sizeof(WCHAR)] = 0;
            info->Name.Buffer = nameOut;
            info->Name.Length = nameBytes;
            info->Name.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        }
        if (returnLength != 0)
        {
            memcpy(returnLength, &needed, sizeof(needed));
        }
        return STATUS_SUCCESS;
    }
    case ObjectTypeInformation:
    {
        ULONG nameChars = (ULONG)KiStringLength(header->type->name);
        ULONG nameBytes = nameChars * sizeof(WCHAR);
        ULONG needed = sizeof(OBJECT_TYPE_INFORMATION) + nameBytes + sizeof(WCHAR);
        if (length < needed)
        {
            if (returnLength != 0)
            {
                memcpy(returnLength, &needed, sizeof(needed));
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        OBJECT_TYPE_INFORMATION *info = buffer;
        memset(info, 0, sizeof(*info));
        WCHAR *nameOut = (WCHAR *)(info + 1);
        for (ULONG i = 0; i < nameChars; i++)
        {
            nameOut[i] = (WCHAR)(unsigned char)header->type->name[i];
        }
        nameOut[nameChars] = 0;
        info->TypeName.Buffer = nameOut;
        info->TypeName.Length = (USHORT)nameBytes;
        info->TypeName.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        if (returnLength != 0)
        {
            ULONG used = (ULONG)sizeof(*info) + info->TypeName.MaximumLength;
            memcpy(returnLength, &used, sizeof(used));
        }
        return STATUS_SUCCESS;
    }
    case ObjectHandleFlagInformation:
    {
        /* CUI-6: GetHandleInformation — the entry's own flag bits back out
         * (dlls/ntdll/unix/file.c NtQueryObject: full struct or
         * STATUS_INVALID_BUFFER_SIZE; sem_ob/handle_flags pins it). */
        if (length < sizeof(OBJECT_HANDLE_FLAG_INFORMATION))
        {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        status = KiProbeForWrite(buffer, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        OBJECT_HANDLE_FLAG_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.Inherit = (entry->attributes & OBJ_INHERIT) != 0;
        info.ProtectFromClose = (entry->attributes & OBJ_PROTECT_CLOSE) != 0;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            ULONG used = sizeof(info);
            memcpy(returnLength, &used, sizeof(used));
        }
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}
