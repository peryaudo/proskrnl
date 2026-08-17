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
#include "drivers/afd.h" /* the Net-2 socket-handle report shim */
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

static ACCESS_MASK ObpMapDesiredAccessRaw(POBJECT_TYPE type, ACCESS_MASK desiredAccess);

/* The generic mapping, then the type's own implications. Split so every
 * return path below funnels through the second step (Art. 11) — an
 * implication applied at only some of them is the parallel-path drift G10
 * rejects. */
static ACCESS_MASK ObpApplyAccessImplications(POBJECT_TYPE type, ACCESS_MASK granted)
{
    return type->mapAccess != 0 ? type->mapAccess(granted) : granted;
}

ACCESS_MASK ObpMapDesiredAccess(POBJECT_TYPE type, ACCESS_MASK desiredAccess)
{
    return ObpApplyAccessImplications(type, ObpMapDesiredAccessRaw(type, desiredAccess));
}

static ACCESS_MASK ObpMapDesiredAccessRaw(POBJECT_TYPE type, ACCESS_MASK desiredAccess)
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

NTSTATUS ObpClearOutHandle(PHANDLE handleOut)
{
    /* The NULL slot is refused here rather than left to the probe, because
     * the probe is a no-op for a KernelMode caller (uaccess.h) and this store
     * would then be a ring-0 write to address 0. */
    if (handleOut == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *handleOut = 0;
    return STATUS_SUCCESS;
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

/* CUI-6: one occupied slot's facts for the SystemHandleInformation
 * snapshot (lock held); the handle value is index-derived exactly as
 * ObpCreateHandle mints it. */
BOOLEAN ObpHandleTableEntryAt(POBP_HANDLE_TABLE table, ULONG index, HANDLE *handleOut,
                              PVOID *bodyOut, ACCESS_MASK *accessOut, ULONG *attributesOut)
{
    if (table->entries == 0 || index >= table->capacity)
    {
        return FALSE;
    }
    POBP_HANDLE_ENTRY entry = &((POBP_HANDLE_ENTRY)table->entries)[index];
    if (entry->body == 0)
    {
        return FALSE;
    }
    *handleOut = ObpHandleFromIndex(index);
    *bodyOut = entry->body;
    *accessOut = entry->grantedAccess;
    *attributesOut = entry->attributes;
    return TRUE;
}

/* CUI-6: the type's snapshot id, minted lazily — THE one assignment site
 * (G11); types are C globals with no central registry to number them at. */
UCHAR ObpTypeIndex(POBJECT_TYPE type)
{
    static UCHAR ObpNextTypeIndex = 1;
    ASSERT(KiIsDispatcherLockHeld());
    if (type->typeIndex == 0)
    {
        type->typeIndex = ObpNextTypeIndex++;
    }
    return type->typeIndex;
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

/* The magic range, stated once (ob.h has the contract and the citation).
 * Kept immediately above the resolver that implements it so the two cannot
 * be edited apart. */
BOOLEAN ObpIsPseudoHandle(HANDLE handle)
{
    return (ULONG)(ULONG_PTR)handle >= 0xfffffffaU;
}

/* WHICH OBJECT each magic value names, referenced on the way out. Both the
 * by-handle resolver below and NtDuplicateObject's SOURCE lookup ask this one
 * function, because wineserver has exactly one such site too — get_magic_handle
 * inside get_handle_obj (third_party/wine server/handle.c) — and a second
 * transcription of the list is the parallel path G10 rejects.
 *
 * The comparisons are on the LOW 32 BITS for the same reason ObpIsPseudoHandle
 * is: a handle value's meaningful part is 32 bits wide, and mixing a 32-bit
 * predicate with 64-bit arms is how the two came to disagree about
 * 0x00000000fffffffa.
 *
 * ONE of the server's arms is deliberately absent: it also maps 0x7fffffff to
 * the current process, which is Wine's own spelling and not NT's. The range
 * this file recognises is the oracle's PE-side one (`is_pseudo_handle`,
 * dlls/ntdll/unix/sync.c — ob.h states why), and nothing in the stack sends
 * 0x7fffffff down, so carrying it would be transcribing a quirk rather than a
 * contract.
 *
 * Every arm names something of the CALLING thread's, and that is a rule and
 * not an accident of where the function is called from: the server resolves a
 * magic handle against `current` before it consults the process argument's
 * table at all, so naming a FOREIGN process as a duplication's source does not
 * make -1 mean that process (sem_ob/dup_cross_process pins it). */
static NTSTATUS ObpReferencePseudoHandle(HANDLE handle, PVOID *body)
{
    ASSERT(ObpIsPseudoHandle(handle));
    ULONG value = (ULONG)(ULONG_PTR)handle;
    PKTHREAD current = KeGetCurrentThread();
    PVOID named = 0;
    if (value >= (ULONG)-6 && value <= (ULONG)-4)
    {
        /* CUI-6: -4 = process token, -5 = thread (impersonation) token,
         * -6 = effective token (thread's if impersonating, else process's).
         * The thread token is 0 unless SetThreadToken attached one, which is
         * STATUS_INVALID_HANDLE for -5 and the fallback for -6. */
        if (value == (ULONG)-4)
        {
            named = current->process->token;
        }
        else if (value == (ULONG)-5)
        {
            named = PsCurrentThreadImpersonationToken();
        }
        else /* -6: effective */
        {
            named = PsCurrentThreadImpersonationToken();
            if (named == 0)
            {
                named = current->process->token;
            }
        }
    }
    else if (value == (ULONG)-1)
    {
        /* The CURRENT-process (-1) and CURRENT-thread (-2) pseudo-handles,
         * resolved here beside the token ones rather than at each call site.
         * NT treats them as real handles to the caller's own objects. The
         * boundary consequence of leaving them unresolved is unmistakable, and
         * kernel32:thread produced it: threadFunc3 is a four-line thread whose
         * whole body is SuspendThread(GetCurrentThread()), and with -2
         * unresolved NtSuspendThread answered STATUS_INVALID_HANDLE — so the
         * thread never parked and five assertions failed behind it.
         *
         * kernel/ps/ carries per-site `handle != NtCurrentThread()` dances
         * predating this; they are now redundant rather than wrong — they
         * short-circuit to the same object — and should be retired as their
         * classes are next touched rather than in a drive-by (G13). */
        named = current->process;
    }
    else if (value == (ULONG)-2)
    {
        named = current->threadObject;
    }
    /* -3: inside the range and naming nothing. Nothing ever hands one out, so
     * it is an invalid handle — said here rather than left to fall through to
     * a table lookup that would reach the same answer by accident.
     * kernel32:sync passes it to NtWaitForMultipleObjects among the six
     * (sync.c's pseudohandles[2] = ~(ULONG_PTR)2). */
    if (named == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    ObfReferenceObject(named);
    *body = named;
    return STATUS_SUCCESS;
}

NTSTATUS ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK desiredAccess, POBJECT_TYPE type,
                                   KPROCESSOR_MODE accessMode, PVOID *body,
                                   POBJECT_HANDLE_INFORMATION handleInformation)
{
    /* ONE range test, ObpIsPseudoHandle's, entered here so the predicate and
     * the resolver cannot drift (Art. 11 — ob.h states the contract). Magic
     * handles bypass the ACCESS check (get_handle_obj grabs without checking;
     * get_handle_access reports all rights — a caller always has full rights
     * to itself) and keep the TYPE check, so asking for a thread with -1 is
     * still an honest mismatch. */
    if (ObpIsPseudoHandle(handle))
    {
        PVOID self;
        NTSTATUS status = ObpReferencePseudoHandle(handle, &self);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (type != 0 && ObpGetHeader(self)->type != type)
        {
            ObDereferenceObject(self);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        *body = self;
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

/* How many handles THIS table holds on `body`, counting the one about to be
 * closed. wineserver counts the same way and in the same place
 * (third_party/wine server/handle.c get_obj_handle_count, read by
 * server/async.c async_close_obj_handle); NT hands the number to the close
 * method as ProcessHandleCount. A linear walk, once per close of a type that
 * has a hook — Art. 3's "stupidly correct": the alternative is a per-object
 * per-process count with its own invariant to keep. */
static ULONG ObpCountHandlesIn(POBP_HANDLE_TABLE table, PVOID body)
{
    ULONG count = 0;
    for (ULONG index = 0; index < table->capacity; index++)
    {
        if (ObpHandleTableObjectAt(table, index) == body)
        {
            count++;
        }
    }
    return count;
}

/* Close one table entry: run the type's close hook, retire a temporary
 * object's name on the last handle, then drop the handle's pointer reference.
 * `process` owns `table`, which is not always the caller's process
 * (DUPLICATE_CLOSE_SOURCE names the SOURCE's table). */
static void ObpCloseHandleEntryIn(PEPROCESS process, POBP_HANDLE_TABLE table,
                                  POBP_HANDLE_ENTRY entry)
{
    PVOID body = entry->body;
    POBJECT_HEADER header = ObpGetHeader(body);

    /* Both counts as NT's close method receives them: INCLUDING the handle
     * being closed, so they are taken before the entry goes. The process
     * count is only asked for a type that has a hook to tell. */
    ULONG systemHandleCount = (ULONG)header->handleCount;
    ULONG processHandleCount =
        header->type->closeProcedure != 0 ? ObpCountHandlesIn(table, body) : 0;

    entry->body = 0;
    ASSERT(table->inUse > 0);
    table->inUse--;

    ASSERT(header->handleCount > 0);
    header->handleCount--;
    /* NT's CloseProcedure moment. It fires on EVERY close now, because the
     * question "is this the last handle THIS PROCESS holds" has no other
     * answer, and the Io layer owes a cancel sweep at exactly that instant
     * (kernel/io/file.c). A hook that only wants the last-handle-in-the-system
     * moment says so from its own first line; the ordering of everything
     * around it is unchanged. */
    if (header->type->closeProcedure != 0)
    {
        header->type->closeProcedure(process, body, processHandleCount, systemHandleCount);
    }
    if (header->handleCount == 0 && !header->permanent)
    {
        ObpUnlinkObjectName(header);
    }
    ObDereferenceObject(body);
}

static void ObpCloseHandleEntry(POBP_HANDLE_ENTRY entry)
{
    ObpCloseHandleEntryIn(KeGetCurrentThread()->process, ObpCurrentTable(), entry);
}

void ObpCloseAllHandles(PEPROCESS process, POBP_HANDLE_TABLE table)
{
    POBP_HANDLE_ENTRY entries = table->entries;
    for (ULONG index = 0; index < table->capacity && table->inUse > 0; index++)
    {
        if (entries[index].body != 0)
        {
            ObpCloseHandleEntryIn(process, table, &entries[index]);
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

/* CUI-6: CompareObjectHandles' back end — body identity, both handles
 * resolved with ZERO required access (server/handle.c compare_objects;
 * sem_ob/compare_permanent pins it). The shared reference path also lets
 * the magic pseudo-handles compare. */
NTSTATUS NtCompareObjects(HANDLE first, HANDLE second)
{
    PVOID firstBody, secondBody;
    NTSTATUS status = ObReferenceObjectByHandle(first, 0, 0, KernelMode, &firstBody, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = ObReferenceObjectByHandle(second, 0, 0, KernelMode, &secondBody, 0);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(firstBody);
        return status;
    }
    status = firstBody == secondBody ? STATUS_SUCCESS : STATUS_NOT_SAME_OBJECT;
    ObDereferenceObject(secondBody);
    ObDereferenceObject(firstBody);
    return status;
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
    NTSTATUS status;
    if (targetHandle != 0)
    {
        /* The one entry point on the surface whose clear is GUARDED, because
         * its out-pointer is optional: a DUPLICATE_CLOSE_SOURCE-only call
         * legitimately passes NULL. Same guard the oracle writes
         * (third_party/wine dlls/ntdll/unix/server.c NtDuplicateObject:
         * `if (dest) *dest = 0;`). */
        status = ObpClearOutHandle(targetHandle);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    PEPROCESS sourceProc, targetProc;
    BOOLEAN sourceReferenced, targetReferenced;
    status = ObpReferenceDupProcess(sourceProcess, &sourceProc, &sourceReferenced);
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
    /* The SOURCE lookup is get_handle_obj's order (third_party/wine
     * server/handle.c): the magic pseudo-handles FIRST, then the source
     * process's table. Table-only is what refused
     * DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), ...) — the
     * documented way to turn a pseudo-handle into a real one, which
     * kernel32:virtual's test_ReadProcessMemory opens with. Pinned by
     * sem_ob/dup_pseudo. */
    PVOID sourceBody = 0;
    ACCESS_MASK sourceAccess;
    ULONG sourceAttributes;
    if (ObpIsPseudoHandle(sourceHandle))
    {
        status = ObpReferencePseudoHandle(sourceHandle, &sourceBody);
        if (!NT_SUCCESS(status))
        {
            goto release;
        }
        /* No entry means no RECORDED rights and no attributes, so the server
         * synthesises both: "pseudo-handle, give it full access", spelled
         * map_access( obj, GENERIC_ALL ) — which is this type's whole mask
         * through the one mapping authority — and attributes taken from that
         * mask's reserved bits, i.e. none. */
        sourceAccess = ObpMapDesiredAccess(ObpGetHeader(sourceBody)->type, GENERIC_ALL);
        sourceAttributes = 0;
    }
    else
    {
        POBP_HANDLE_ENTRY source = ObpEntryInTable(sourceTable, sourceHandle);
        if (source == 0)
        {
            status = STATUS_INVALID_HANDLE;
            goto release;
        }
        /* Hold the body for the rest of the call. The insert below takes its
         * own reference on success, but it can allocate, and the source table
         * belongs to a process whose OWN threads may close the handle — so
         * this reference is what keeps the body alive between reading it here
         * and the insert referencing it. */
        sourceBody = source->body;
        ObfReferenceObject(sourceBody);
        sourceAccess = source->grantedAccess;
        sourceAttributes = source->attributes;
    }

    POBJECT_TYPE type = ObpGetHeader(sourceBody)->type;
    /* Duplication maps generic wishes but grants SPECIFIC bits verbatim —
     * never filtered by the type's valid mask (Wine server/handle.c
     * duplicate_handle -> map_access keeps non-generic bits untouched;
     * sem_ob/handle_life pins the observable: a directory duplicate asking
     * event rights carries SYNCHRONIZE past a wait's access check). The
     * generic wish keeps the documented docs/03 over-grant deviation. */
    ACCESS_MASK granted;
    if (options & DUPLICATE_SAME_ACCESS)
    {
        granted = sourceAccess;
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
    ULONG newAttributes = (options & DUPLICATE_SAME_ATTRIBUTES) ? sourceAttributes : attributes;

    status = STATUS_SUCCESS;
    if (targetHandle != 0)
    {
        /* The out-pointer is the CALLER's, whichever processes the two ends
         * name — probe it here rather than through ObpCreateHandle, whose
         * table is implicitly the current one. */
        status = KiProbeForWrite(targetHandle, sizeof(*targetHandle), sizeof(*targetHandle));
        if (NT_SUCCESS(status))
        {
            status = ObpCreateHandleInTable(&targetProc->handleTable, sourceBody, granted,
                                            newAttributes, targetHandle);
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
         * meanwhile — or that was never in the table, i.e. a pseudo-handle —
         * is nothing left to close, which is both the server's answer (it
         * closes unconditionally and DISCARDS the error) and NT's documented
         * one ("calling the CloseHandle function with a pseudo handle has no
         * effect", learn.microsoft.com GetCurrentProcess). */
        POBP_HANDLE_ENTRY source = ObpEntryInTable(sourceTable, sourceHandle);
        if (source != 0)
        {
            ObpCloseHandleEntryIn(sourceProc, sourceTable, source);
        }
    }

release:
    if (sourceBody != 0)
    {
        ObDereferenceObject(sourceBody);
    }
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
    /* CUI-6: ObjectHandleFlagInformation checks its buffer size BEFORE the
     * handle (dlls/ntdll/unix/file.c NtQueryObject: the length gate precedes
     * the server call; a short buffer is STATUS_INVALID_BUFFER_SIZE even for
     * an invalid handle — a fuzzer-found ordering divergence). */
    if (infoClass == ObjectHandleFlagInformation && length < sizeof(OBJECT_HANDLE_FLAG_INFORMATION))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    /* A magic pseudo-handle answers the flag query with both flags clear
     * (wineserver set_handle_flags returns 0 for a zero mask on a magic
     * handle; sem_ob/handle_flags pins it) — resolved before the table,
     * which knows nothing of pseudo handles. */
    if (infoClass == ObjectHandleFlagInformation && (ULONG_PTR)handle >= (ULONG_PTR)-6)
    {
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
        /* Net-2 oracle parity (Art. 6; docs/03 "Net-2 notes"): the pinned
         * Wine reports a SOCKET handle's attributes without OBJ_INHERIT
         * (ws2_32:afd test_open_device carries the NT truth as todo_wine,
         * so the Wine answer is the spec here). The REPORT only — the
         * stored attribute, and inheritance with it, is untouched. */
        if (AfdIsSocketFile(entry->body))
        {
            info.Attributes &= ~(ULONG)OBJ_INHERIT;
        }
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
        /* A type that keeps its own namespace answers for itself, and its
         * refusal precedes the sizing below (ob.h OBJECT_TYPE.queryName). */
        ULONG nameBytes;
        if (header->type->queryName != 0)
        {
            status = header->type->queryName(entry->body, 0, &nameBytes);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            /* Zero falls through to the empty-UNICODE_STRING arm below, which
             * is the answer for an object with no name AT ALL — the oracle's
             * no_get_full_name reply (ob.h). "No name for THIS one" is a
             * refusal, and arrives above. */
        }
        else
        {
            nameBytes = ObpFullNameLength(header);
        }
        ULONG needed =
            sizeof(OBJECT_NAME_INFORMATION) + (nameBytes != 0 ? nameBytes + sizeof(WCHAR) : 0);
        if (length < sizeof(OBJECT_NAME_INFORMATION) || (nameBytes != 0 && length < needed))
        {
            if (returnLength != 0)
            {
                memcpy(returnLength, &needed, sizeof(needed));
            }
            /* Which length error is the TYPE's to say, and only for a buffer
             * that holds the fixed struct: below that the answer is forced
             * from above (ob.h OBJECT_TYPE.nameTooShortStatus). */
            if (length >= sizeof(OBJECT_NAME_INFORMATION) && header->type->nameTooShortStatus != 0)
            {
                return header->type->nameTooShortStatus;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        /* The buffer is big enough and the ANSWER still may not be: the shape
         * this class reports is a UNICODE_STRING, whose Length and
         * MaximumLength are USHORTs, so a name past 0xfffc bytes cannot be
         * described at all. It is reachable — a pipe's name is the caller's
         * ObjectName, bounded only by that same USHORT, so a 32760-character
         * name relative to \Device\NamedPipe composes past the ceiling.
         *
         * The refusal sits BELOW the size protocol on purpose, which is where
         * the oracle can still be followed: a too-small buffer gets
         * STATUS_BUFFER_OVERFLOW carrying the whole length, measured. Above it
         * the oracle has no valid answer — `p->Name.Length = res` truncates the
         * ULONG into the USHORT (dlls/ntdll/unix/file.c NtQueryObject), so a
         * 65556-byte name comes back as a 20-byte one, i.e. as a DIFFERENT
         * object's. Repeating that would be Art. 12's fabricated answer, and
         * answering the length error instead would spin every caller that grows
         * its buffer and retries (that file's own server_get_name_info is such
         * a loop). Pinned by tests/ntapi/sem_pipe/object_name.c §7. */
        if (nameBytes > 0xfffcu)
        {
            return STATUS_NAME_TOO_LONG;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* The header is staged and copied out as bytes. The probe above asks
         * for 4-byte alignment, so a caller's 4-mod-8 buffer is ACCEPTED —
         * and `info->Name.Buffer` is an 8-byte store at offset 8, i.e. at a
         * 4-mod-8 address, which is undefined in C and a UBSan #UD in this
         * build. (The name body behind it is WCHARs at a 4-aligned offset,
         * which the same probe already guarantees is 2-aligned.) */
        OBJECT_NAME_INFORMATION staged;
        memset(&staged, 0, sizeof(staged));
        if (nameBytes != 0)
        {
            WCHAR *nameOut = (WCHAR *)((char *)buffer + sizeof(OBJECT_NAME_INFORMATION));
            if (header->type->queryName != 0)
            {
                ULONG writtenBytes = nameBytes;
                status = header->type->queryName(entry->body, nameOut, &writtenBytes);
                if (!NT_SUCCESS(status))
                {
                    return status;
                }
                ASSERT(writtenBytes == nameBytes);
            }
            else
            {
                ObpWriteFullName(header, nameOut);
            }
            nameOut[nameBytes / sizeof(WCHAR)] = 0;
            staged.Name.Buffer = nameOut;
            staged.Name.Length = (USHORT)nameBytes; /* guarded above */
            staged.Name.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        }
        memcpy(buffer, &staged, sizeof(staged));
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
        /* Staged for the reason ObjectNameInformation's header is. */
        OBJECT_TYPE_INFORMATION staged;
        memset(&staged, 0, sizeof(staged));
        WCHAR *nameOut = (WCHAR *)((char *)buffer + sizeof(OBJECT_TYPE_INFORMATION));
        for (ULONG i = 0; i < nameChars; i++)
        {
            nameOut[i] = (WCHAR)(unsigned char)header->type->name[i];
        }
        nameOut[nameChars] = 0;
        staged.TypeName.Buffer = nameOut;
        staged.TypeName.Length = (USHORT)nameBytes;
        staged.TypeName.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        memcpy(buffer, &staged, sizeof(staged));
        if (returnLength != 0)
        {
            ULONG used = (ULONG)sizeof(staged) + staged.TypeName.MaximumLength;
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
