/* kernel/ob/namespace.c — \-rooted object namespace (M3).
 *
 * Directories are plain sibling lists (docs/05: a locked growable array /
 * list suffices; hashing is NT folklore we skip). Symbolic links substitute
 * their target for the consumed part of the path and restart the walk, with
 * a reparse limit against cycles. Lookup runs entirely in thread context —
 * no lock, per the Art. 3 note in ob.h.
 *
 * The NTSTATUS conventions implemented here are pinned by
 * tests/ntapi/sem_ob/: missing leaf = STATUS_OBJECT_NAME_NOT_FOUND, missing
 * intermediate = STATUS_OBJECT_PATH_NOT_FOUND, existing name =
 * STATUS_OBJECT_NAME_COLLISION unless OBJ_OPENIF makes it
 * STATUS_OBJECT_NAME_EXISTS, wrong final type = STATUS_OBJECT_TYPE_MISMATCH.
 */
#include "kernel/ob/ob.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* Directory body: the list of OBJECT_HEADER.directoryEntry links. */
typedef struct
{
    LIST_ENTRY entryListHead;
} OBP_DIRECTORY, *POBP_DIRECTORY;

/* Symbolic-link body: the substitution target, a pool copy. */
typedef struct
{
    UNICODE_STRING target;
} OBP_SYMBOLIC_LINK, *POBP_SYMBOLIC_LINK;

#define OBP_MAX_REPARSES   32
#define OBP_MAX_NAME_UNITS (0xFFFF / sizeof(WCHAR))

static PVOID ObpRootDirectory; /* body of "\" */

static void ObpDeleteDirectory(PVOID body)
{
    POBP_DIRECTORY directory = body;
    /* Every entry's name holds a reference on this directory, so a dying
     * directory is necessarily empty. (Flink == 0 is the still-zeroed body
     * of a create that failed before initializing it.) */
    ASSERT(directory->entryListHead.Flink == 0 || IsListEmpty(&directory->entryListHead));
}

static void ObpDeleteSymbolicLink(PVOID body)
{
    POBP_SYMBOLIC_LINK link = body;
    if (link->target.Buffer != 0)
    {
        MiFreePool(link->target.Buffer);
    }
}

OBJECT_TYPE ObpDirectoryType = {
    .name = "Directory",
    .validAccess = DIRECTORY_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = ObpDeleteDirectory,
};

OBJECT_TYPE ObpSymbolicLinkType = {
    .name = "SymbolicLink",
    .validAccess = SYMBOLIC_LINK_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = ObpDeleteSymbolicLink,
};

/* --- name linkage --------------------------------------------------------- */

/* Give `header` the name `name` inside `directoryBody`. The name and the
 * directory each hold a reference until ObpUnlinkObjectName. */
static NTSTATUS ObpLinkObjectName(PVOID directoryBody, POBJECT_HEADER header,
                                  const UNICODE_STRING *name)
{
    ASSERT(header->parentDirectory == 0 && header->name.Buffer == 0);
    PWSTR buffer = MiAllocatePool(name->Length);
    if (buffer == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(buffer, name->Buffer, name->Length);
    header->name.Buffer = buffer;
    header->name.Length = name->Length;
    header->name.MaximumLength = name->Length;

    header->parentDirectory = directoryBody;
    ObfReferenceObject(directoryBody);
    POBP_DIRECTORY directory = directoryBody;
    InsertTailList(&directory->entryListHead, &header->directoryEntry);
    ObfReferenceObject(ObpGetBody(header)); /* the name's reference */
    return STATUS_SUCCESS;
}

void ObpUnlinkObjectName(POBJECT_HEADER header)
{
    if (header->parentDirectory == 0)
    {
        return;
    }
    PVOID directoryBody = header->parentDirectory;
    RemoveEntryList(&header->directoryEntry);
    header->parentDirectory = 0;
    ObDereferenceObject(directoryBody);
    ObDereferenceObject(ObpGetBody(header)); /* may delete `header` */
}

/* Find `component` in a directory body; returns the child BODY or 0. */
static PVOID ObpFindEntry(PVOID directoryBody, const UNICODE_STRING *component,
                          BOOLEAN caseInsensitive)
{
    POBP_DIRECTORY directory = directoryBody;
    for (PLIST_ENTRY entry = directory->entryListHead.Flink; entry != &directory->entryListHead;
         entry = entry->Flink)
    {
        POBJECT_HEADER header = CONTAINING_RECORD(entry, OBJECT_HEADER, directoryEntry);
        if (RtlEqualUnicodeString(&header->name, component, caseInsensitive))
        {
            return ObpGetBody(header);
        }
    }
    return 0;
}

/* --- the path walk -------------------------------------------------------- */

/* Walk `attributes` down the namespace.
 *
 * Found:      *foundBody = referenced object, STATUS_SUCCESS.
 * Leaf free:  *foundBody = 0, *parentBody = referenced directory,
 *             *leafName = the remaining single component (pointing into the
 *             caller's or the reparse buffer — copy before returning to the
 *             caller), STATUS_SUCCESS.
 * Otherwise the failing NTSTATUS.
 *
 * A symbolic link met mid-path is always substituted; met as the FINAL
 * component it is substituted unless `followFinalLink` is FALSE (opening the
 * link itself, or OBJ_OPENLINK). *reparseBuffer, if the walk allocated one,
 * must be freed by the caller AFTER it is done with *leafName. */
static NTSTATUS ObpLookupName(const OBJECT_ATTRIBUTES *attributes, BOOLEAN followFinalLink,
                              PVOID *foundBody, PVOID *parentBody, UNICODE_STRING *leafName,
                              PWSTR *reparseBuffer)
{
    *foundBody = 0;
    *parentBody = 0;
    *reparseBuffer = 0;

    const UNICODE_STRING *name = attributes->ObjectName;
    BOOLEAN caseInsensitive = (attributes->Attributes & OBJ_CASE_INSENSITIVE) != 0;

    /* Resolve the walk's starting directory. */
    PVOID rootBody;
    BOOLEAN rootReferenced = FALSE;
    if (attributes->RootDirectory != 0)
    {
        NTSTATUS status = ObReferenceObjectByHandle(attributes->RootDirectory, DIRECTORY_TRAVERSE,
                                                    &ObpDirectoryType, KernelMode, &rootBody, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        rootReferenced = TRUE;
        if (name->Length >= sizeof(WCHAR) && name->Buffer[0] == '\\')
        {
            ObDereferenceObject(rootBody);
            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }
    }
    else
    {
        rootBody = ObpRootDirectory;
        if (name->Length < sizeof(WCHAR) || name->Buffer[0] != '\\')
        {
            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }
    }

    /* remaining = the path with any leading '\' stripped. */
    UNICODE_STRING remaining = *name;
    if (remaining.Length >= sizeof(WCHAR) && remaining.Buffer[0] == '\\')
    {
        remaining.Buffer++;
        remaining.Length -= sizeof(WCHAR);
    }
    if (remaining.Length == 0)
    {
        /* The name was "\" or empty: no leaf to create or open. */
        if (rootReferenced)
        {
            ObDereferenceObject(rootBody);
        }
        return STATUS_OBJECT_NAME_INVALID;
    }

    PVOID current = rootBody; /* holds a reference iff rootReferenced */
    if (!rootReferenced)
    {
        ObfReferenceObject(current);
    }
    int reparses = 0;

    for (;;)
    {
        /* Split the next component at '\'. */
        UNICODE_STRING component = remaining;
        ULONG units = remaining.Length / sizeof(WCHAR);
        ULONG i;
        for (i = 0; i < units; i++)
        {
            if (remaining.Buffer[i] == '\\')
            {
                break;
            }
        }
        component.Length = (USHORT)(i * sizeof(WCHAR));
        BOOLEAN isFinal = (i == units);
        if (!isFinal)
        {
            remaining.Buffer += i + 1;
            remaining.Length -= (USHORT)((i + 1) * sizeof(WCHAR));
        }
        else
        {
            remaining.Length = 0;
        }
        if (component.Length == 0 || (!isFinal && remaining.Length == 0))
        {
            /* Empty component: "\\a\\\\b", trailing '\', etc. */
            ObDereferenceObject(current);
            return STATUS_OBJECT_NAME_INVALID;
        }

        PVOID child = ObpFindEntry(current, &component, caseInsensitive);
        if (child == 0)
        {
            if (!isFinal)
            {
                ObDereferenceObject(current);
                return STATUS_OBJECT_PATH_NOT_FOUND;
            }
            /* Leaf free: hand the parent back for a create. */
            *parentBody = current;
            *leafName = component;
            return STATUS_SUCCESS;
        }

        if (ObpGetHeader(child)->type == &ObpSymbolicLinkType && (!isFinal || followFinalLink))
        {
            /* Substitute the target for the consumed prefix and restart. */
            POBP_SYMBOLIC_LINK link = child;
            if (++reparses > OBP_MAX_REPARSES)
            {
                ObDereferenceObject(current);
                return STATUS_OBJECT_NAME_INVALID;
            }
            ULONG targetUnits = link->target.Length / sizeof(WCHAR);
            ULONG restUnits = remaining.Length / sizeof(WCHAR);
            ULONG totalUnits = targetUnits + (restUnits != 0 ? 1 + restUnits : 0);
            if (totalUnits > OBP_MAX_NAME_UNITS)
            {
                ObDereferenceObject(current);
                return STATUS_OBJECT_NAME_INVALID;
            }
            PWSTR rebuilt = MiAllocatePool(totalUnits * sizeof(WCHAR));
            if (rebuilt == 0)
            {
                ObDereferenceObject(current);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            memcpy(rebuilt, link->target.Buffer, link->target.Length);
            if (restUnits != 0)
            {
                rebuilt[targetUnits] = '\\';
                memcpy(rebuilt + targetUnits + 1, remaining.Buffer, remaining.Length);
            }
            if (*reparseBuffer != 0)
            {
                MiFreePool(*reparseBuffer);
            }
            *reparseBuffer = rebuilt;

            remaining.Buffer = rebuilt;
            remaining.Length = (USHORT)(totalUnits * sizeof(WCHAR));
            ObDereferenceObject(current);
            /* Targets are absolute paths from the namespace root. */
            if (remaining.Length < sizeof(WCHAR) || remaining.Buffer[0] != '\\')
            {
                return STATUS_OBJECT_PATH_SYNTAX_BAD;
            }
            remaining.Buffer++;
            remaining.Length -= sizeof(WCHAR);
            if (remaining.Length == 0)
            {
                return STATUS_OBJECT_NAME_INVALID;
            }
            current = ObpRootDirectory;
            ObfReferenceObject(current);
            continue;
        }

        if (isFinal)
        {
            ObfReferenceObject(child);
            ObDereferenceObject(current);
            *foundBody = child;
            return STATUS_SUCCESS;
        }

        if (ObpGetHeader(child)->type != &ObpDirectoryType)
        {
            /* A non-container met mid-path. */
            ObDereferenceObject(current);
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
        ObfReferenceObject(child);
        ObDereferenceObject(current);
        current = child;
    }
}

/* --- the create / open engines (ob.h) ------------------------------------- */

NTSTATUS ObpCreateObjectWithHandle(POBJECT_TYPE type, ULONG bodySize,
                                   const OBJECT_ATTRIBUTES *attributes, ACCESS_MASK desiredAccess,
                                   PVOID *body, PHANDLE handleOut)
{
    ACCESS_MASK granted = ObpMapDesiredAccess(type, desiredAccess);

    if (attributes == 0 || attributes->ObjectName == 0)
    {
        /* Unnamed: allocate, hand out one handle, drop the creator's ref. */
        NTSTATUS status = ObpAllocateObject(type, bodySize, body);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONG attrFlags = attributes != 0 ? attributes->Attributes : 0;
        status = ObpCreateHandle(*body, granted, attrFlags, handleOut);
        ObDereferenceObject(*body);
        return status;
    }

    PVOID found, parent;
    UNICODE_STRING leaf;
    PWSTR reparseBuffer;
    NTSTATUS status = ObpLookupName(attributes, TRUE, &found, &parent, &leaf, &reparseBuffer);
    if (!NT_SUCCESS(status))
    {
        goto out;
    }

    if (found != 0)
    {
        /* The name exists. OBJ_OPENIF opens it (matching type required);
         * anything else is a collision. */
        if ((attributes->Attributes & OBJ_OPENIF) == 0)
        {
            ObDereferenceObject(found);
            status = STATUS_OBJECT_NAME_COLLISION;
            goto out;
        }
        if (ObpGetHeader(found)->type != type)
        {
            ObDereferenceObject(found);
            status = STATUS_OBJECT_TYPE_MISMATCH;
            goto out;
        }
        status = ObpCreateHandle(found, granted, attributes->Attributes, handleOut);
        if (NT_SUCCESS(status))
        {
            *body = found;
            status = STATUS_OBJECT_NAME_EXISTS;
        }
        ObDereferenceObject(found);
        goto out;
    }

    /* The leaf is free under `parent`: build the object there. */
    status = ObpAllocateObject(type, bodySize, body);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(parent);
        goto out;
    }
    POBJECT_HEADER header = ObpGetHeader(*body);
    if (attributes->Attributes & OBJ_PERMANENT)
    {
        header->permanent = TRUE;
    }
    status = ObpLinkObjectName(parent, header, &leaf);
    ObDereferenceObject(parent);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(*body);
        goto out;
    }
    status = ObpCreateHandle(*body, granted, attributes->Attributes, handleOut);
    if (!NT_SUCCESS(status))
    {
        ObpUnlinkObjectName(header); /* drops the name's reference */
    }
    ObDereferenceObject(*body); /* the creator's reference */

out:
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    return status;
}

NTSTATUS ObpOpenObjectByName(POBJECT_TYPE type, const OBJECT_ATTRIBUTES *attributes,
                             ACCESS_MASK desiredAccess, PHANDLE handleOut)
{
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_NAME_INVALID;
    }
    PVOID found, parent;
    UNICODE_STRING leaf;
    PWSTR reparseBuffer;
    /* Opening a symbolic link (or asking OBJ_OPENLINK) binds the link
     * itself; any other open follows a final link to its target. */
    BOOLEAN followFinalLink =
        type != &ObpSymbolicLinkType && (attributes->Attributes & OBJ_OPENLINK) == 0;
    NTSTATUS status =
        ObpLookupName(attributes, followFinalLink, &found, &parent, &leaf, &reparseBuffer);
    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (found == 0)
    {
        ObDereferenceObject(parent);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (type != 0 && ObpGetHeader(found)->type != type)
    {
        ObDereferenceObject(found);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    status = ObpCreateHandle(found, ObpMapDesiredAccess(ObpGetHeader(found)->type, desiredAccess),
                             attributes->Attributes, handleOut);
    ObDereferenceObject(found);
    return status;
}

/* --- initialization ------------------------------------------------------- */

/* Create one permanent directory under `parentBody` (0 = the root itself). */
static PVOID ObpCreatePermanentDirectory(PVOID parentBody, PCWSTR name)
{
    PVOID body;
    NTSTATUS status = ObpAllocateObject(&ObpDirectoryType, sizeof(OBP_DIRECTORY), &body);
    if (!NT_SUCCESS(status))
    {
        KiPanic("ObpInitializeObjectManager: out of pool");
    }
    POBP_DIRECTORY directory = body;
    InitializeListHead(&directory->entryListHead);
    ObpGetHeader(body)->permanent = TRUE;
    if (parentBody != 0)
    {
        UNICODE_STRING nameString;
        RtlInitUnicodeString(&nameString, name);
        if (!NT_SUCCESS(ObpLinkObjectName(parentBody, ObpGetHeader(body), &nameString)))
        {
            KiPanic("ObpInitializeObjectManager: out of pool");
        }
    }
    /* The creator's reference is kept: boot directories never die. */
    return body;
}

void ObpInitializeObjectManager(void)
{
    ObpRootDirectory = ObpCreatePermanentDirectory(0, 0);
    ObpCreatePermanentDirectory(ObpRootDirectory, WSTR("Device"));
    ObpCreatePermanentDirectory(ObpRootDirectory, WSTR("??"));
    ObpCreatePermanentDirectory(ObpRootDirectory, WSTR("BaseNamedObjects"));
}

/* --- the directory / symbolic-link Nt* surface ---------------------------- */

NTSTATUS NtCreateDirectoryObject(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&ObpDirectoryType, sizeof(OBP_DIRECTORY), attr,
                                                access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        POBP_DIRECTORY directory = body;
        InitializeListHead(&directory->entryListHead);
    }
    return status;
}

NTSTATUS NtOpenDirectoryObject(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpDirectoryType, attr, access, handle);
}

NTSTATUS NtCreateSymbolicLinkObject(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr,
                                    PUNICODE_STRING target)
{
    if (handle == 0 || target == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (target->Length == 0 || (target->Length & 1) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* Symbolic links are immutable after creation, so the target is copied
     * up front and OBJ_OPENIF reuse of an existing link keeps its own. */
    PWSTR copy = MiAllocatePool(target->Length);
    if (copy == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(copy, target->Buffer, target->Length);

    PVOID body;
    NTSTATUS status = ObpCreateObjectWithHandle(&ObpSymbolicLinkType, sizeof(OBP_SYMBOLIC_LINK),
                                                attr, access, &body, handle);
    if (status == STATUS_SUCCESS)
    {
        POBP_SYMBOLIC_LINK link = body;
        link->target.Buffer = copy;
        link->target.Length = target->Length;
        link->target.MaximumLength = target->Length;
    }
    else
    {
        MiFreePool(copy);
    }
    return status;
}

NTSTATUS NtOpenSymbolicLinkObject(PHANDLE handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    if (handle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    return ObpOpenObjectByName(&ObpSymbolicLinkType, attr, access, handle);
}

NTSTATUS NtQuerySymbolicLinkObject(HANDLE handle, PUNICODE_STRING target, PULONG returnedLength)
{
    if (target == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, SYMBOLIC_LINK_QUERY, &ObpSymbolicLinkType,
                                                KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    POBP_SYMBOLIC_LINK link = body;
    /* Wine's convention (dlls/ntdll/unix/sync.c): the buffer must also fit a
     * terminating NUL, and ReturnedLength reports target + NUL. */
    if (returnedLength != 0)
    {
        *returnedLength = link->target.Length + sizeof(WCHAR);
    }
    if (target->MaximumLength < link->target.Length + sizeof(WCHAR))
    {
        ObDereferenceObject(body);
        return STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(target->Buffer, link->target.Buffer, link->target.Length);
    target->Length = link->target.Length;
    target->Buffer[link->target.Length / sizeof(WCHAR)] = 0;
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}
