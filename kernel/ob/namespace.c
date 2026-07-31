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
#include "kernel/ke/ke.h"           /* KiVerifyWaitList (the consistency sweep) */
#include "kernel/syscall/uaccess.h" /* CUI-5: NtQueryDirectoryObject's mode */
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

/* Validate a caller-supplied OBJECT_ATTRIBUTES before the engine reads it.
 *
 * Every NtCreate and NtOpen funnels through the three entry points below, and
 * each of them dereferences attributes->ObjectName->Length and walks
 * ->Buffer. Those are ring-3 pointers: user and kernel VA share a PML4, so an
 * unmapped or kernel-side value faulted with CS.RPL == 0, which
 * KiDispatchTrap does not contain -- a machine halt where the caller should
 * have seen STATUS_ACCESS_VIOLATION. Probing here rather than in the twenty
 * services keeps it to one authority (Art. 11); NtOpenProcess was previously
 * the only caller in the tree that probed at all.
 *
 * Public because two subsystems resolve names WITHOUT going through the
 * engine below -- kernel/io/file.c reads attributes->ObjectName itself to
 * build a filesystem path, and kernel/cm/registry.c does the same for the
 * registry path -- so they must reach the same check rather than grow their
 * own.
 *
 * This is a probe, not a capture, matching the model kernel/syscall/uaccess.h
 * documents for the rest of the kernel: sound because nothing blocks between
 * the probe and the walk. The mid-syscall-unmap window that model already
 * calls out is unchanged by this commit, in either direction.
 *
 * A NULL `attributes` is left to the callers, which distinguish it
 * (STATUS_INVALID_PARAMETER) from a present block with no name. */
NTSTATUS ObProbeObjectAttributes(const OBJECT_ATTRIBUTES *attributes)
{
    if (attributes == 0)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = KiProbeForRead(attributes, sizeof(*attributes), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    const UNICODE_STRING *name = attributes->ObjectName;
    if (name == 0)
    {
        return STATUS_SUCCESS;
    }
    status = KiProbeForRead(name, sizeof(*name), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (name->Length == 0)
    {
        return STATUS_SUCCESS;
    }
    return KiProbeForRead(name->Buffer, name->Length, sizeof(WCHAR));
}

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
                              BOOLEAN forCreate, POBJECT_TYPE parseType, PVOID *foundBody,
                              PVOID *parentBody, UNICODE_STRING *leafName,
                              UNICODE_STRING *parseRemaining, PWSTR *reparseBuffer)
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
        /* The name was exactly "\": it denotes the starting directory itself
         * (the namespace root for an absolute name). Return it as the found
         * object — a create then sees it exists (collision), an open type-checks
         * it. Matches the pinned third_party/wine; docs/09 Art. 6. */
        if (!rootReferenced)
        {
            ObfReferenceObject(rootBody);
        }
        *foundBody = rootBody;
        return STATUS_SUCCESS;
    }

    PVOID current = rootBody; /* holds a reference iff rootReferenced */
    if (!rootReferenced)
    {
        ObfReferenceObject(current);
    }
    int reparses = 0;
    /* TRUE once the most recent reparse substituted a FINAL-component symbolic
     * link. A create cannot then materialize a new object at the link's target:
     * NT requires the target to already exist, so a free leaf reached this way
     * is STATUS_OBJECT_PATH_NOT_FOUND, not a creatable leaf. An INTERMEDIATE
     * link (path continues past it, e.g. \??\C:\file) leaves this FALSE, so
     * creating under it still works. Matches the pinned third_party/wine. */
    BOOLEAN reparsedFinal = FALSE;

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
        BOOLEAN trailingEmpty = FALSE; /* "name\" — a bare trailing '\' */
        if (!isFinal)
        {
            remaining.Buffer += i + 1;
            remaining.Length -= (USHORT)((i + 1) * sizeof(WCHAR));
            trailingEmpty = remaining.Length == 0;
        }
        else
        {
            remaining.Length = 0;
        }
        if (component.Length == 0)
        {
            /* Empty component: "\\a\\\\b" etc. */
            ObDereferenceObject(current);
            return STATUS_OBJECT_NAME_INVALID;
        }

        PVOID child = ObpFindEntry(current, &component, caseInsensitive);
        if (child != 0 && parseType != 0 && ObpGetHeader(child)->type == parseType)
        {
            /* A parse object (M6: an Io Device): the walk stops here and the
             * rest of the name — possibly empty, possibly a bare trailing
             * backslash — belongs to the object's own parser (the FS).
             * NT's ParseProcedure concept. */
            ObfReferenceObject(child);
            ObDereferenceObject(current);
            *foundBody = child;
            *parseRemaining = remaining;
            return STATUS_SUCCESS;
        }
        if (trailingEmpty && !(child != 0 && ObpGetHeader(child)->type == &ObpSymbolicLinkType))
        {
            /* Trailing '\' on a non-parse path: invalid — except through a
             * symbolic link ("\??\C:\" must reach the volume root exactly as
             * the pinned oracle resolves it; sem_pipe/device_type.c), which
             * the reparse below re-walks with the slash preserved. */
            ObDereferenceObject(current);
            return STATUS_OBJECT_NAME_INVALID;
        }
        if (child == 0)
        {
            if (!isFinal || reparsedFinal)
            {
                /* A missing intermediate, or a missing target reached by
                 * following a final-component symlink: no creatable leaf. */
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
            /* Substitute the target for the consumed prefix and restart. Record
             * whether this reparse consumed the FINAL component (isFinal): the
             * target then stands in for the whole name, so a missing leaf under
             * it is a path error rather than a creatable spot. */
            reparsedFinal = isFinal;
            POBP_SYMBOLIC_LINK link = child;
            if (++reparses > OBP_MAX_REPARSES)
            {
                /* A symbolic-link loop or an over-long reparse chain: NT gives
                 * up with STATUS_INVALID_PARAMETER. Matches the pinned
                 * third_party/wine; docs/09 Art. 6. */
                ObDereferenceObject(current);
                return STATUS_INVALID_PARAMETER;
            }
            ULONG targetUnits = link->target.Length / sizeof(WCHAR);
            ULONG restUnits = remaining.Length / sizeof(WCHAR);
            /* trailingEmpty: the link was named with a bare trailing '\'
             * ("\??\C:\") — keep it on the rebuilt path so the re-walk
             * presents the same shape to the parse object's own parser. */
            ULONG totalUnits =
                targetUnits + (restUnits != 0 ? 1 + restUnits : (trailingEmpty ? 1u : 0u));
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
            else if (trailingEmpty)
            {
                rebuilt[targetUnits] = '\\';
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
            /* A non-container met mid-path: the path cannot continue through it.
             * NT reports this differently for the two callers — a create sees a
             * wrong-typed component (TYPE_MISMATCH), an open sees the leaf as
             * unreachable (NAME_NOT_FOUND). Matches the pinned third_party/wine. */
            ObDereferenceObject(current);
            return forCreate ? STATUS_OBJECT_TYPE_MISMATCH : STATUS_OBJECT_NAME_NOT_FOUND;
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

    NTSTATUS probeStatus = ObProbeObjectAttributes(attributes);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    if (attributes == 0 || attributes->ObjectName == 0 || attributes->ObjectName->Length == 0)
    {
        /* Unnamed: no ObjectName, or a present-but-empty (zero-length) one,
         * which NT treats as unnamed on create (it is only OPEN that rejects an
         * empty name as a path). Allocate, hand out one handle, drop the
         * creator's ref. Matches the pinned third_party/wine; docs/09 Art. 6. */
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
    /* Creating a symbolic link does NOT follow a link already at the final name
     * (else you could never observe a name collision between two links) — an
     * existing entry there is a collision. Every other create follows a final
     * link, as an open would. Matches the pinned third_party/wine; docs/09
     * Art. 6. */
    BOOLEAN followFinalLink = (type != &ObpSymbolicLinkType);
    NTSTATUS status = ObpLookupName(attributes, followFinalLink, TRUE, 0, &found, &parent, &leaf, 0,
                                    &reparseBuffer);
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
    /* No attributes at all is a parameter error; a present attributes block with
     * no name is a (degenerate) path — an empty path fails as syntax, so NT
     * reports STATUS_OBJECT_PATH_SYNTAX_BAD, the same as an empty-string name
     * (which ObpLookupName rejects below). Matches the pinned third_party/wine;
     * docs/09 Art. 6. */
    NTSTATUS probeStatus = ObProbeObjectAttributes(attributes);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    if (attributes == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    PVOID found, parent;
    UNICODE_STRING leaf;
    PWSTR reparseBuffer;
    /* Opening a symbolic link (or asking OBJ_OPENLINK) binds the link
     * itself; any other open follows a final link to its target. */
    BOOLEAN followFinalLink =
        type != &ObpSymbolicLinkType && (attributes->Attributes & OBJ_OPENLINK) == 0;
    NTSTATUS status = ObpLookupName(attributes, followFinalLink, FALSE, 0, &found, &parent, &leaf,
                                    0, &reparseBuffer);
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
    /* An open must request at least one access right; NT rejects a zero
     * DesiredAccess on an existing object with ACCESS_DENIED (the object was
     * found, so this outranks a name error). Matches the pinned third_party/wine;
     * docs/09 Art. 6. */
    if (desiredAccess == 0)
    {
        ObDereferenceObject(found);
        return STATUS_ACCESS_DENIED;
    }
    status = ObpCreateHandle(found, ObpMapDesiredAccess(ObpGetHeader(found)->type, desiredAccess),
                             attributes->Attributes, handleOut);
    ObDereferenceObject(found);
    return status;
}

NTSTATUS ObpLookupParseObject(const OBJECT_ATTRIBUTES *attributes, POBJECT_TYPE parseType,
                              PVOID *parseObject, UNICODE_STRING *remainingName,
                              PWSTR *reparseBuffer)
{
    NTSTATUS probeStatus = ObProbeObjectAttributes(attributes);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    if (attributes == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    PVOID found, parent;
    UNICODE_STRING leaf;
    UNICODE_STRING remaining;
    remaining.Buffer = 0;
    remaining.Length = 0;
    remaining.MaximumLength = 0;
    NTSTATUS status = ObpLookupName(attributes, TRUE, FALSE, parseType, &found, &parent, &leaf,
                                    &remaining, reparseBuffer);
    if (!NT_SUCCESS(status))
    {
        if (*reparseBuffer != 0)
        {
            MiFreePool(*reparseBuffer);
            *reparseBuffer = 0;
        }
        return status;
    }
    if (found == 0)
    {
        ObDereferenceObject(parent);
        if (*reparseBuffer != 0)
        {
            MiFreePool(*reparseBuffer);
            *reparseBuffer = 0;
        }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (ObpGetHeader(found)->type != parseType)
    {
        /* The whole path resolved to some other object: NtCreateFile on an
         * event etc. */
        ObDereferenceObject(found);
        if (*reparseBuffer != 0)
        {
            MiFreePool(*reparseBuffer);
            *reparseBuffer = 0;
        }
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    *parseObject = found;
    /* remainingName may point into the caller's name or *reparseBuffer —
     * the caller copies what it needs before freeing the buffer. */
    *remainingName = remaining;
    return STATUS_SUCCESS;
}

/* --- the consistency sweep (kernel/init/verify.c; lock held) --------------- */

/* Every named object's name bookkeeping: the entry's parentDirectory points
 * back at the directory holding it, the name is a real pool string, and the
 * name's + every handle's reference are accounted for in pointerCount. The
 * namespace is shallow (boot directories + device/link leaves; Cm keys keep
 * their own tree behind \Registry), so bounded recursion is safe. */
static void ObpVerifyDirectory(PVOID directoryBody, int depth)
{
    ASSERT(depth < 16);
    POBP_DIRECTORY directory = directoryBody;
    if (directory->entryListHead.Flink == 0)
    {
        return; /* still-zeroed body: the private create window (ob.h contract) */
    }
    for (PLIST_ENTRY entry = directory->entryListHead.Flink; entry != &directory->entryListHead;
         entry = entry->Flink)
    {
        ASSERT(entry->Flink->Blink == entry && entry->Blink->Flink == entry);
        POBJECT_HEADER header = CONTAINING_RECORD(entry, OBJECT_HEADER, directoryEntry);
        ASSERT(header->parentDirectory == directoryBody);
        ASSERT(header->name.Buffer != 0 && header->name.Length != 0);
        ASSERT(header->type != 0 && header->type->name != 0);
        /* handles + the name itself; transient refs only push it higher */
        ASSERT(header->handleCount >= 0);
        ASSERT(header->pointerCount >= header->handleCount + 1);
        PVOID body = ObpGetBody(header);
        if (header->type->waitable)
        {
            KiVerifyWaitList(body);
        }
        if (header->type == &ObpDirectoryType)
        {
            ObpVerifyDirectory(body, depth + 1);
        }
    }
}

void ObpVerifyNamespace(void)
{
    if (ObpRootDirectory == 0)
    {
        return; /* before ObpInitializeObjectManager */
    }
    POBJECT_HEADER root = ObpGetHeader(ObpRootDirectory);
    ASSERT(root->type == &ObpDirectoryType);
    ASSERT(root->parentDirectory == 0);
    ASSERT(root->pointerCount >= 1);
    ObpVerifyDirectory(ObpRootDirectory, 0);
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
    /* NT's home for kernel-owned named objects, and the directory Wine's
     * win32u opens `__wine_session` in (dlls/win32u/winstation.c). Permanent
     * in the pinned Wine server too (server/directory.c, dir_kernel). */
    ObpCreatePermanentDirectory(ObpRootDirectory, WSTR("KernelObjects"));

    /* The per-session namespace. NT gives every session one, and window
     * stations live in \Sessions\<id>\Windows\WindowStations -- which is
     * where win32u names "WinSta0", relative to a handle on that directory
     * (dlls/win32u/winstation.c, get_winstations_dir_handle). The pinned
     * Wine server builds the same tree (server/directory.c, create_session).
     * One session: PsInitializePeb hands every process SessionId 1, so that
     * is the only id a lookup can ask for. */
    PVOID sessions = ObpCreatePermanentDirectory(ObpRootDirectory, WSTR("Sessions"));
    PVOID session = ObpCreatePermanentDirectory(sessions, WSTR("1"));
    PVOID windows = ObpCreatePermanentDirectory(session, WSTR("Windows"));
    ObpCreatePermanentDirectory(windows, WSTR("WindowStations"));
    /* The session's named-object home: kernelbase's
     * BaseGetNamedObjectDirectory opens \Sessions\<SessionId>\BaseNamedObjects
     * with no fallback (dlls/kernelbase/sync.c), so EVERY named
     * CreateEvent/Mutex/Semaphore dies ERROR_BAD_PATHNAME without it. The
     * pinned Wine server creates it per session too (server/directory.c,
     * create_session). Pinned by sem_ob/session_bno. */
    ObpCreatePermanentDirectory(session, WSTR("BaseNamedObjects"));
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

/* CUI-5: NtQueryDirectoryObject — kernelbase's volume enumeration
 * (QueryDosDeviceW list-all, GetLogicalDrives) loops single-entry calls
 * over \?? until a non-zero status. The protocol is the pinned Wine's
 * (dlls/ntdll/unix/sync.c + server/directory.c get_directory_entries),
 * pinned by sem_ob/query_directory.c: entries carry name + type name as
 * NUL-terminated UNICODE_STRINGs pointing into the caller's buffer (string
 * pool after the entry array), a zeroed terminator entry follows, and the
 * kernel owns the cursor. */
NTSTATUS NtQueryDirectoryObject(HANDLE handle, PDIRECTORY_BASIC_INFORMATION buffer, ULONG size,
                                BOOLEAN singleEntry, BOOLEAN restartScan, PULONG context,
                                PULONG returnedSize)
{
    if (buffer == 0 || context == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    /* Every one of these was written or read raw. *context is read before the
     * handle is even resolved, and the entry array plus its string pool are
     * filled in the caller's buffer -- with kernel and user VA sharing a
     * PML4, that was a kernel write with attacker-influenced content. */
    {
        NTSTATUS probeStatus = KiProbeForWrite(context, sizeof(*context), sizeof(ULONG));
        if (!NT_SUCCESS(probeStatus))
        {
            return probeStatus;
        }
        probeStatus = KiProbeForWrite(buffer, size, sizeof(uint64_t));
        if (!NT_SUCCESS(probeStatus))
        {
            return probeStatus;
        }
        if (returnedSize != 0)
        {
            probeStatus = KiProbeForWrite(returnedSize, sizeof(*returnedSize), sizeof(ULONG));
            if (!NT_SUCCESS(probeStatus))
            {
                return probeStatus;
            }
        }
    }
    ULONG index = restartScan ? 0 : *context;

    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, DIRECTORY_QUERY, &ObpDirectoryType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    POBP_DIRECTORY directory = body;

    /* First pass: how many entries from `index` fit (wine's sizing — each
     * entry costs its struct + both strings + both NULs; one struct is
     * reserved for the terminator). totalLength tracks the strings of every
     * entry CONSIDERED, feeding the BUFFER_TOO_SMALL hint. */
    ULONG maxCount = singleEntry ? 1 : 0xFFFFFFFFu;
    ULONG usedCount = 0;
    ULONG usedSize = sizeof(DIRECTORY_BASIC_INFORMATION);
    ULONG totalLength = 0;
    BOOLEAN more = FALSE;
    BOOLEAN any = FALSE;

    ULONG position = 0;
    for (PLIST_ENTRY entry = directory->entryListHead.Flink;
         entry != &directory->entryListHead && usedCount < maxCount; entry = entry->Flink)
    {
        if (position++ < index)
        {
            continue;
        }
        any = TRUE;
        POBJECT_HEADER header = CONTAINING_RECORD(entry, OBJECT_HEADER, directoryEntry);
        ULONG nameBytes = header->name.Length;
        ULONG typeBytes = (ULONG)KiStringLength(header->type->name) * sizeof(WCHAR);
        totalLength += nameBytes + typeBytes;
        ULONG entrySize =
            sizeof(DIRECTORY_BASIC_INFORMATION) + nameBytes + typeBytes + 2 * sizeof(WCHAR);
        if (usedSize + entrySize > size)
        {
            more = TRUE;
            break;
        }
        usedCount++;
        usedSize += entrySize;
    }
    /* Entries beyond the fitted window also mean MORE_ENTRIES on a
     * multi-entry sweep only when one failed to fit above — a window that
     * ends exactly at the directory's end is SUCCESS (wine's server stops
     * iterating without error). */

    if (!any && !more)
    {
        ObDereferenceObject(body);
        if (returnedSize != 0)
        {
            *returnedSize = sizeof(DIRECTORY_BASIC_INFORMATION);
        }
        return STATUS_NO_MORE_ENTRIES;
    }
    if (singleEntry && usedCount == 0)
    {
        ObDereferenceObject(body);
        if (returnedSize != 0)
        {
            *returnedSize =
                2 * sizeof(DIRECTORY_BASIC_INFORMATION) + 2 * sizeof(WCHAR) + totalLength;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Second pass: emit the fitted entries + the string pool. */
    ULONG strpoolHead = sizeof(DIRECTORY_BASIC_INFORMATION) * (usedCount + 1);
    ULONG emitted = 0;
    position = 0;
    for (PLIST_ENTRY entry = directory->entryListHead.Flink;
         entry != &directory->entryListHead && emitted < usedCount; entry = entry->Flink)
    {
        if (position++ < index)
        {
            continue;
        }
        POBJECT_HEADER header = CONTAINING_RECORD(entry, OBJECT_HEADER, directoryEntry);
        PWCHAR pool = (PWCHAR)((char *)buffer + strpoolHead);
        buffer[emitted].ObjectName.Buffer = pool;
        buffer[emitted].ObjectName.Length = header->name.Length;
        buffer[emitted].ObjectName.MaximumLength = header->name.Length + sizeof(WCHAR);
        memcpy(pool, header->name.Buffer, header->name.Length);
        pool[header->name.Length / sizeof(WCHAR)] = 0;
        strpoolHead += header->name.Length + sizeof(WCHAR);

        pool = (PWCHAR)((char *)buffer + strpoolHead);
        ULONG typeUnits = 0;
        for (const char *c = header->type->name; *c != '\0'; c++)
        {
            pool[typeUnits++] = (WCHAR)*c;
        }
        pool[typeUnits] = 0;
        buffer[emitted].ObjectTypeName.Buffer = pool;
        buffer[emitted].ObjectTypeName.Length = (USHORT)(typeUnits * sizeof(WCHAR));
        buffer[emitted].ObjectTypeName.MaximumLength =
            (USHORT)(typeUnits * sizeof(WCHAR) + sizeof(WCHAR));
        strpoolHead += typeUnits * sizeof(WCHAR) + sizeof(WCHAR);
        emitted++;
    }
    if (size >= sizeof(DIRECTORY_BASIC_INFORMATION))
    {
        memset(&buffer[usedCount], 0, sizeof(buffer[usedCount]));
    }

    ObDereferenceObject(body);
    *context = index + usedCount;
    if (returnedSize != 0)
    {
        *returnedSize = strpoolHead;
    }
    return more ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;
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
        /* An OBJ_OPENIF reuse of an existing link keeps its own target; the
         * fresh copy is unused. Unlike every other object type, NT reports that
         * reuse as plain STATUS_SUCCESS, not STATUS_OBJECT_NAME_EXISTS — match
         * the pinned third_party/wine (docs/09 Art. 6). */
        MiFreePool(copy);
        if (status == STATUS_OBJECT_NAME_EXISTS)
        {
            status = STATUS_SUCCESS;
        }
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
