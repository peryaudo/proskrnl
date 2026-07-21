/* kernel/cm/registry.c — the Cm registry: key objects, the tree, the Nt*
 * surface (M8, docs/02).
 *
 * The observable semantics mirror the pinned Wine oracle exactly (Art. 6:
 * Wine is the operative spec), pinned test-first by tests/ntapi/sem_reg/.
 * The load-bearing wrinkles, each cross-checked against the pinned tree:
 *
 *   - NtCreateKey is always open-if (ntdll forces OBJ_OPENIF — wine
 *     dlls/ntdll/unix/registry.c NtCreateKey), reporting the outcome via the
 *     disposition, and creates only the LAST path component (a missing
 *     intermediate is STATUS_OBJECT_NAME_NOT_FOUND — wine server/registry.c
 *     key_lookup_name).
 *   - Registry lookup is ALWAYS case-insensitive (ntdll forces
 *     OBJ_CASE_INSENSITIVE for create and open alike).
 *   - Subkeys and values are kept in case-insensitive sorted order (wine
 *     server/registry.c find_subkey/find_value: binary search, insert at the
 *     sort position) — enumeration order is observable.
 *   - Deleting a key with subkeys is STATUS_ACCESS_DENIED; deleting an
 *     already-deleted key is a success no-op; every OTHER operation through
 *     a stale handle is STATUS_KEY_DELETED (wine server/registry.c
 *     delete_key + get_hkey_obj).
 *   - The short-buffer protocol per info class: STATUS_BUFFER_TOO_SMALL
 *     below the fixed header, STATUS_BUFFER_OVERFLOW when only the variable
 *     part is cut, ResultLength always the full requirement, and the header
 *     is written truncated even then (wine dlls/ntdll/unix/registry.c
 *     enumerate_key / NtQueryValueKey / copy_key_value_info).
 *   - Name-length limits: a path component over 256 chars is
 *     STATUS_INVALID_PARAMETER (server MAX_NAME_LEN); a value name over
 *     16383 chars is STATUS_INVALID_PARAMETER on set and
 *     STATUS_OBJECT_NAME_NOT_FOUND on query/delete (ntdll
 *     MAX_VALUE_LENGTH).
 *
 * Everything internal is the dumbest correct shape (Art. 3): plain linked
 * lists, no KCB cache, no security beyond the granted-access mask, and a
 * full hive rewrite per mutation (hive.c).
 */
#include "kernel/cm/cm.h"

#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"

/* Limits as the pinned Wine tree fixes them (see the file comment). */
#define CMP_MAX_COMPONENT_BYTES  (256 * sizeof(WCHAR))   /* server MAX_NAME_LEN */
#define CMP_MAX_VALUE_NAME_BYTES (16383 * sizeof(WCHAR)) /* ntdll MAX_VALUE_LENGTH */

PCMP_KEY_NODE CmpRootNode;

/* --- the Key object type --------------------------------------------------- */

static void CmpDeleteKeyBody(PVOID bodyPointer)
{
    PCM_KEY_BODY body = bodyPointer;
    PCMP_KEY_NODE node = body->node;
    if (node == 0)
    {
        return; /* creation failed before binding */
    }
    ASSERT(node->bodyCount > 0);
    node->bodyCount--;
    if (node->deleted && node->bodyCount == 0)
    {
        /* Values were freed at delete time; the node itself waited for the
         * last stale handle. */
        ASSERT(node->subkeyCount == 0);
        if (node->name.Buffer != 0)
        {
            MiFreePool(node->name.Buffer);
        }
        MiFreePool(node);
    }
}

OBJECT_TYPE CmpKeyType = {
    .name = "Key",
    .validAccess = KEY_ALL_ACCESS,
    .waitable = FALSE,
    .deleteProcedure = CmpDeleteKeyBody,
};

/* --- tree primitives -------------------------------------------------------- */

static LARGE_INTEGER CmpNow(void)
{
    LARGE_INTEGER now;
    now.QuadPart = (LONGLONG)KeQueryInterruptTime();
    return now;
}

PCMP_KEY_NODE CmpAllocateNode(PCMP_KEY_NODE parent, const UNICODE_STRING *name)
{
    PCMP_KEY_NODE node = MiAllocatePool(sizeof(*node));
    if (node == 0)
    {
        return 0;
    }
    if (name->Length != 0)
    {
        node->name.Buffer = MiAllocatePool(name->Length);
        if (node->name.Buffer == 0)
        {
            MiFreePool(node);
            return 0;
        }
        memcpy(node->name.Buffer, name->Buffer, name->Length);
        node->name.Length = name->Length;
        node->name.MaximumLength = name->Length;
    }
    InitializeListHead(&node->subkeyListHead);
    InitializeListHead(&node->valueListHead);
    node->parent = parent;
    node->lastWriteTime = CmpNow();
    if (parent != 0)
    {
        /* Keep the sibling list in case-insensitive sorted order (wine
         * server/registry.c find_subkey: enumeration order is observable). */
        PLIST_ENTRY e = parent->subkeyListHead.Flink;
        for (; e != &parent->subkeyListHead; e = e->Flink)
        {
            PCMP_KEY_NODE sibling = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
            if (RtlCompareUnicodeString(&node->name, &sibling->name, TRUE) < 0)
            {
                break;
            }
        }
        /* insert before e (possibly the head = append) */
        node->siblingEntry.Flink = e;
        node->siblingEntry.Blink = e->Blink;
        e->Blink->Flink = &node->siblingEntry;
        e->Blink = &node->siblingEntry;
        parent->subkeyCount++;
    }
    return node;
}

static PCMP_KEY_NODE CmpFindSubkey(PCMP_KEY_NODE node, const UNICODE_STRING *name)
{
    for (PLIST_ENTRY e = node->subkeyListHead.Flink; e != &node->subkeyListHead; e = e->Flink)
    {
        PCMP_KEY_NODE child = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
        if (RtlEqualUnicodeString(&child->name, name, TRUE))
        {
            return child;
        }
    }
    return 0;
}

static PCMP_VALUE CmpFindValue(PCMP_KEY_NODE node, const UNICODE_STRING *name)
{
    for (PLIST_ENTRY e = node->valueListHead.Flink; e != &node->valueListHead; e = e->Flink)
    {
        PCMP_VALUE value = CONTAINING_RECORD(e, CMP_VALUE, listEntry);
        if (RtlEqualUnicodeString(&value->name, name, TRUE))
        {
            return value;
        }
    }
    return 0;
}

NTSTATUS CmpSetValue(PCMP_KEY_NODE node, const UNICODE_STRING *name, ULONG type, const void *data,
                     ULONG dataLength)
{
    PCMP_VALUE value = CmpFindValue(node, name);
    PVOID dataCopy = 0;
    if (dataLength != 0)
    {
        dataCopy = MiAllocatePool(dataLength);
        if (dataCopy == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(dataCopy, data, dataLength);
    }
    if (value == 0)
    {
        value = MiAllocatePool(sizeof(*value));
        if (value == 0)
        {
            if (dataCopy != 0)
            {
                MiFreePool(dataCopy);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (name->Length != 0)
        {
            value->name.Buffer = MiAllocatePool(name->Length);
            if (value->name.Buffer == 0)
            {
                MiFreePool(value);
                if (dataCopy != 0)
                {
                    MiFreePool(dataCopy);
                }
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            memcpy(value->name.Buffer, name->Buffer, name->Length);
            value->name.Length = name->Length;
            value->name.MaximumLength = name->Length;
        }
        /* Sorted insert (wine server/registry.c find_value: value
         * enumeration order is sorted, like subkeys). */
        PLIST_ENTRY e = node->valueListHead.Flink;
        for (; e != &node->valueListHead; e = e->Flink)
        {
            PCMP_VALUE existing = CONTAINING_RECORD(e, CMP_VALUE, listEntry);
            if (RtlCompareUnicodeString(&value->name, &existing->name, TRUE) < 0)
            {
                break;
            }
        }
        value->listEntry.Flink = e;
        value->listEntry.Blink = e->Blink;
        e->Blink->Flink = &value->listEntry;
        e->Blink = &value->listEntry;
        node->valueCount++;
    }
    else
    {
        /* Replace keeps the existing name (and its case). */
        if (value->data != 0)
        {
            MiFreePool(value->data);
        }
    }
    value->type = type;
    value->dataLength = dataLength;
    value->data = dataCopy;
    return STATUS_SUCCESS;
}

void CmpFreeValues(PCMP_KEY_NODE node)
{
    while (!IsListEmpty(&node->valueListHead))
    {
        PCMP_VALUE value = CONTAINING_RECORD(node->valueListHead.Flink, CMP_VALUE, listEntry);
        RemoveEntryList(&value->listEntry);
        if (value->name.Buffer != 0)
        {
            MiFreePool(value->name.Buffer);
        }
        if (value->data != 0)
        {
            MiFreePool(value->data);
        }
        MiFreePool(value);
    }
    node->valueCount = 0;
}

/* --- path resolution -------------------------------------------------------- */

/* Pop the leading path component off *path. Consecutive and trailing
 * backslashes are collapsed (wine server/registry.c key_lookup_name skips
 * backslash runs). FALSE = no component left. */
static BOOLEAN CmpNextComponent(UNICODE_STRING *path, UNICODE_STRING *component)
{
    ULONG chars = path->Length / sizeof(WCHAR);
    ULONG start = 0;
    while (start < chars && path->Buffer[start] == '\\')
    {
        start++;
    }
    if (start == chars)
    {
        path->Length = 0;
        return FALSE;
    }
    ULONG end = start;
    while (end < chars && path->Buffer[end] != '\\')
    {
        end++;
    }
    component->Buffer = path->Buffer + start;
    component->Length = (USHORT)((end - start) * sizeof(WCHAR));
    component->MaximumLength = component->Length;
    path->Buffer += end;
    path->Length = (USHORT)((chars - end) * sizeof(WCHAR));
    return TRUE;
}

/* Resolve `attributes` to a node in the tree. For forCreate, the walk stops
 * at the LAST component: *parentOut and *leafOut name it and *foundOut is the
 * existing child (0 = creatable); the leaf is copied into the caller's
 * leafScratch (CMP_MAX_COMPONENT_BYTES). For open (forCreate FALSE)
 * *foundOut is the named node itself. An empty path resolves to the base
 * key. */
static NTSTATUS CmpResolvePath(const OBJECT_ATTRIBUTES *attributes, BOOLEAN forCreate,
                               PCMP_KEY_NODE *parentOut, UNICODE_STRING *leafOut,
                               WCHAR *leafScratch, PCMP_KEY_NODE *foundOut)
{
    if (attributes == 0 || attributes->ObjectName == 0)
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    PCMP_KEY_NODE base;
    UNICODE_STRING path;
    PVOID referencedBody = 0; /* the Ob object keeping `base` alive */
    PWSTR reparseBuffer = 0;
    NTSTATUS status;

    if (attributes->RootDirectory != 0)
    {
        status = ObReferenceObjectByHandle(attributes->RootDirectory, 0, &CmpKeyType,
                                           ExGetPreviousMode(), &referencedBody, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        base = ((PCM_KEY_BODY)referencedBody)->node;
        if (base->deleted)
        {
            ObDereferenceObject(referencedBody);
            return STATUS_KEY_DELETED;
        }
        path = *attributes->ObjectName;
        if (path.Length >= sizeof(WCHAR) && path.Buffer[0] == '\\')
        {
            ObDereferenceObject(referencedBody);
            return STATUS_OBJECT_PATH_SYNTAX_BAD;
        }
    }
    else
    {
        UNICODE_STRING remaining;
        status = ObpLookupParseObject(attributes, &CmpKeyType, &referencedBody, &remaining,
                                      &reparseBuffer);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        base = ((PCM_KEY_BODY)referencedBody)->node;
        path = remaining;
        ASSERT(!base->deleted); /* namespace-reachable keys are never deleted */
    }

    /* Walk. Node pointers stay valid without references: nodes die only via
     * NtDeleteKey (which unlinks them) + the last body close, and nothing
     * here blocks (Art. 3 cooperative kernel). */
    PCMP_KEY_NODE node = base;
    UNICODE_STRING component;
    status = STATUS_SUCCESS;
    *foundOut = 0;
    if (parentOut != 0)
    {
        *parentOut = 0;
    }
    if (!forCreate)
    {
        while (CmpNextComponent(&path, &component))
        {
            if (component.Length > CMP_MAX_COMPONENT_BYTES)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            node = CmpFindSubkey(node, &component);
            if (node == 0)
            {
                status = STATUS_OBJECT_NAME_NOT_FOUND;
                break;
            }
        }
        if (NT_SUCCESS(status))
        {
            *foundOut = node;
        }
    }
    else
    {
        UNICODE_STRING leaf;
        leaf.Length = 0;
        leaf.Buffer = 0;
        leaf.MaximumLength = 0;
        PCMP_KEY_NODE parent = 0;
        while (CmpNextComponent(&path, &component))
        {
            if (component.Length > CMP_MAX_COMPONENT_BYTES)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (leaf.Length != 0)
            {
                /* the previous component was NOT last: it must exist */
                node = CmpFindSubkey(node, &leaf);
                if (node == 0)
                {
                    status = STATUS_OBJECT_NAME_NOT_FOUND;
                    break;
                }
            }
            leaf = component;
        }
        if (NT_SUCCESS(status))
        {
            if (leaf.Length == 0)
            {
                /* empty path: the base key itself */
                *foundOut = node;
            }
            else
            {
                parent = node;
                *foundOut = CmpFindSubkey(parent, &leaf);
            }
            if (parentOut != 0)
            {
                *parentOut = parent;
            }
            if (leafOut != 0)
            {
                /* leaf points into the caller's name (possibly user memory)
                 * or the reparse buffer freed below — copy it into the
                 * caller's scratch so it survives this frame. */
                if (leaf.Length != 0)
                {
                    memcpy(leafScratch, leaf.Buffer, leaf.Length);
                }
                leafOut->Buffer = leafScratch;
                leafOut->Length = leaf.Length;
                leafOut->MaximumLength = leaf.Length;
            }
        }
    }

    if (reparseBuffer != 0)
    {
        MiFreePool(reparseBuffer); /* the leaf was copied into leafScratch */
    }
    ObDereferenceObject(referencedBody);
    return status;
}

/* --- key body + handle ------------------------------------------------------ */

static NTSTATUS CmpCreateKeyHandle(PCMP_KEY_NODE node, ACCESS_MASK desiredAccess,
                                   ULONG objectAttributes, PHANDLE handleOut)
{
    PVOID body;
    NTSTATUS status = ObpAllocateObject(&CmpKeyType, sizeof(CM_KEY_BODY), &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCM_KEY_BODY keyBody = body;
    keyBody->node = node;
    node->bodyCount++;
    ACCESS_MASK granted = ObpMapDesiredAccess(&CmpKeyType, desiredAccess);
    status = ObpCreateHandle(body, granted, objectAttributes & ~OBJ_PERMANENT, handleOut);
    ObDereferenceObject(body); /* the handle holds its own reference */
    return status;
}

/* Resolve a key handle for one operation: type check, access check, and the
 * stale-handle rule (every op through a deleted key's handle is
 * STATUS_KEY_DELETED — wine server/registry.c get_hkey_obj). The caller
 * dereferences *bodyOut on success. */
static NTSTATUS CmpReferenceKey(HANDLE handle, ACCESS_MASK desiredAccess, BOOLEAN allowDeleted,
                                PCM_KEY_BODY *bodyOut)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, desiredAccess, &CmpKeyType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCM_KEY_BODY keyBody = body;
    if (keyBody->node->deleted && !allowDeleted)
    {
        ObDereferenceObject(body);
        return STATUS_KEY_DELETED;
    }
    *bodyOut = keyBody;
    return STATUS_SUCCESS;
}

/* --- info-class filling ----------------------------------------------------- */

/* Copy `sourceLength` variable bytes at `variableOffset`, as much as fits. */
static void CmpCopyVariable(UCHAR *buffer, ULONG length, ULONG variableOffset, const void *source,
                            ULONG sourceLength)
{
    if (length > variableOffset && sourceLength != 0)
    {
        ULONG copy = length - variableOffset;
        if (copy > sourceLength)
        {
            copy = sourceLength;
        }
        memcpy(buffer + variableOffset, source, copy);
    }
}

/* The shared verdict: header truncated-copied even when short (wine
 * copy_key_value_info memcpy min(length, fixed)); TOO_SMALL under the fixed
 * header, OVERFLOW when the variable part is cut. */
static NTSTATUS CmpFinishInfo(ULONG length, ULONG fixedSize, ULONG required, ULONG *resultLength)
{
    *resultLength = required;
    if (length < fixedSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (length < required)
    {
        return STATUS_BUFFER_OVERFLOW;
    }
    return STATUS_SUCCESS;
}

/* Fill key information about `node` (NtQueryKey and NtEnumerateKey share
 * this — wine dlls/ntdll/unix/registry.c enumerate_key). */
static NTSTATUS CmpFillKeyInfo(const CMP_KEY_NODE *node, KEY_INFORMATION_CLASS infoClass,
                               void *buffer, ULONG length, ULONG *resultLength)
{
    UCHAR *out = buffer;
    switch (infoClass)
    {
    case KeyBasicInformation:
    {
        KEY_BASIC_INFORMATION info;
        ULONG fixed = offsetof(KEY_BASIC_INFORMATION, Name);
        info.LastWriteTime = node->lastWriteTime;
        info.TitleIndex = 0;
        info.NameLength = node->name.Length;
        memcpy(out, &info, length < fixed ? length : fixed);
        CmpCopyVariable(out, length, fixed, node->name.Buffer, node->name.Length);
        return CmpFinishInfo(length, fixed, fixed + node->name.Length, resultLength);
    }
    case KeyNodeInformation:
    {
        KEY_NODE_INFORMATION info;
        ULONG fixed = offsetof(KEY_NODE_INFORMATION, Name);
        info.LastWriteTime = node->lastWriteTime;
        info.TitleIndex = 0;
        info.ClassLength = 0;
        info.ClassOffset = (ULONG)-1; /* no class (wine enumerate_key) */
        info.NameLength = node->name.Length;
        memcpy(out, &info, length < fixed ? length : fixed);
        CmpCopyVariable(out, length, fixed, node->name.Buffer, node->name.Length);
        return CmpFinishInfo(length, fixed, fixed + node->name.Length, resultLength);
    }
    case KeyFullInformation:
    {
        KEY_FULL_INFORMATION info;
        ULONG fixed = offsetof(KEY_FULL_INFORMATION, Class);
        info.LastWriteTime = node->lastWriteTime;
        info.TitleIndex = 0;
        info.ClassLength = 0;
        info.ClassOffset = (ULONG)-1; /* no class */
        info.SubKeys = node->subkeyCount;
        info.Values = node->valueCount;
        info.MaxNameLen = 0;
        info.MaxClassLen = 0;
        info.MaxValueNameLen = 0;
        info.MaxValueDataLen = 0;
        for (PLIST_ENTRY e = node->subkeyListHead.Flink; e != &node->subkeyListHead; e = e->Flink)
        {
            const CMP_KEY_NODE *child = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
            if (child->name.Length > info.MaxNameLen)
            {
                info.MaxNameLen = child->name.Length;
            }
        }
        for (PLIST_ENTRY e = node->valueListHead.Flink; e != &node->valueListHead; e = e->Flink)
        {
            const CMP_VALUE *value = CONTAINING_RECORD(e, CMP_VALUE, listEntry);
            if (value->name.Length > info.MaxValueNameLen)
            {
                info.MaxValueNameLen = value->name.Length;
            }
            if (value->dataLength > info.MaxValueDataLen)
            {
                info.MaxValueDataLen = value->dataLength;
            }
        }
        memcpy(out, &info, length < fixed ? length : fixed);
        return CmpFinishInfo(length, fixed, fixed, resultLength);
    }
    default:
        /* Unimplemented classes are STATUS_INVALID_PARAMETER (wine
         * enumerate_key's default arm). */
        return STATUS_INVALID_PARAMETER;
    }
}

/* Fill value information (NtEnumerateValueKey's shape: the value's own name
 * — wine copy_key_value_info + enum_value). */
static NTSTATUS CmpFillValueInfo(const CMP_VALUE *value, KEY_VALUE_INFORMATION_CLASS infoClass,
                                 void *buffer, ULONG length, ULONG *resultLength)
{
    UCHAR *out = buffer;
    switch (infoClass)
    {
    case KeyValueBasicInformation:
    {
        KEY_VALUE_BASIC_INFORMATION info;
        ULONG fixed = offsetof(KEY_VALUE_BASIC_INFORMATION, Name);
        info.TitleIndex = 0;
        info.Type = value->type;
        info.NameLength = value->name.Length;
        memcpy(out, &info, length < fixed ? length : fixed);
        CmpCopyVariable(out, length, fixed, value->name.Buffer, value->name.Length);
        return CmpFinishInfo(length, fixed, fixed + value->name.Length, resultLength);
    }
    case KeyValueFullInformation:
    {
        KEY_VALUE_FULL_INFORMATION info;
        ULONG fixed = offsetof(KEY_VALUE_FULL_INFORMATION, Name);
        info.TitleIndex = 0;
        info.Type = value->type;
        info.NameLength = value->name.Length;
        info.DataLength = value->dataLength;
        info.DataOffset = fixed + value->name.Length; /* unaligned, as wine */
        memcpy(out, &info, length < fixed ? length : fixed);
        CmpCopyVariable(out, length, fixed, value->name.Buffer, value->name.Length);
        CmpCopyVariable(out, length, fixed + value->name.Length, value->data, value->dataLength);
        return CmpFinishInfo(length, fixed, fixed + value->name.Length + value->dataLength,
                             resultLength);
    }
    case KeyValuePartialInformation:
    {
        KEY_VALUE_PARTIAL_INFORMATION info;
        ULONG fixed = offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data);
        info.TitleIndex = 0;
        info.Type = value->type;
        info.DataLength = value->dataLength;
        memcpy(out, &info, length < fixed ? length : fixed);
        CmpCopyVariable(out, length, fixed, value->data, value->dataLength);
        return CmpFinishInfo(length, fixed, fixed + value->dataLength, resultLength);
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* --- the Nt* surface -------------------------------------------------------- */

NTSTATUS NtCreateKey(PHANDLE keyHandle, ACCESS_MASK desiredAccess,
                     const OBJECT_ATTRIBUTES *attributes, ULONG titleIndex,
                     const UNICODE_STRING *class, ULONG options, PULONG disposition)
{
    (void)titleIndex; /* as wine: unused */
    (void)class;      /* key classes are not stored (docs/03 M8 notes) */

    if (keyHandle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(keyHandle, sizeof(*keyHandle), sizeof(*keyHandle));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *keyHandle = 0; /* as wine ntdll's NtCreateKey */
    if (disposition != 0)
    {
        status = KiProbeForWrite(disposition, sizeof(*disposition), sizeof(*disposition));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    if (attributes == 0 || attributes->Length != sizeof(OBJECT_ATTRIBUTES))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (attributes->ObjectName == 0 ||
        (attributes->ObjectName->Length == 0 && attributes->RootDirectory == 0))
    {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    if ((options & REG_OPTION_CREATE_LINK) != 0)
    {
        return STATUS_NOT_IMPLEMENTED; /* registry symlinks: unbuilt (docs/03) */
    }

    PCMP_KEY_NODE parent, found;
    UNICODE_STRING leaf;
    WCHAR leafScratch[CMP_MAX_COMPONENT_BYTES / sizeof(WCHAR)];
    status = CmpResolvePath(attributes, TRUE, &parent, &leaf, leafScratch, &found);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ULONG dispositionValue;
    if (found != 0)
    {
        /* Binding to an EXISTING key must request at least one access right
         * (wine server/handle.c alloc_handle: mapped access 0 ->
         * STATUS_ACCESS_DENIED); a newly created key is exempt (the
         * alloc_handle_no_access_check path). Same rule Ob's open engine
         * applies (kernel/ob/namespace.c); fuzzer-found, pinned by
         * sem_reg/create_open. */
        if (desiredAccess == 0)
        {
            return STATUS_ACCESS_DENIED;
        }
        dispositionValue = REG_OPENED_EXISTING_KEY;
    }
    else
    {
        /* Only the last component is created. Volatile parents refuse
         * stable children (wine server/registry.c create_key_object). */
        if (parent->isVolatile && (options & REG_OPTION_VOLATILE) == 0)
        {
            return STATUS_CHILD_MUST_BE_VOLATILE;
        }
        found = CmpAllocateNode(parent, &leaf);
        if (found == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        found->isVolatile = parent->isVolatile || (options & REG_OPTION_VOLATILE) != 0;
        parent->lastWriteTime = CmpNow();
        dispositionValue = REG_CREATED_NEW_KEY;
    }

    status = CmpCreateKeyHandle(found, desiredAccess, attributes->Attributes, keyHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (disposition != 0)
    {
        *disposition = dispositionValue;
    }
    if (dispositionValue == REG_CREATED_NEW_KEY && !found->isVolatile)
    {
        CmpSaveHive();
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtOpenKeyEx(PHANDLE keyHandle, ACCESS_MASK desiredAccess,
                     const OBJECT_ATTRIBUTES *attributes, ULONG options)
{
    /* REG_OPTION_OPEN_LINK is the only meaningful option and registry
     * symlinks are unbuilt (docs/03), so options only get wine's own
     * treatment: ignored. */
    (void)options;
    if (keyHandle == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(keyHandle, sizeof(*keyHandle), sizeof(*keyHandle));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *keyHandle = 0; /* as wine ntdll's NtOpenKeyEx */
    if (attributes == 0 || attributes->Length != sizeof(OBJECT_ATTRIBUTES))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (attributes->ObjectName != 0 && (attributes->ObjectName->Length & 1) != 0)
    {
        return STATUS_OBJECT_NAME_INVALID; /* odd byte count, as wine */
    }

    PCMP_KEY_NODE found;
    status = CmpResolvePath(attributes, FALSE, 0, 0, 0, &found);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* An open must request at least one access right (wine alloc_handle;
     * the same rule as Ob's open engine). */
    if (desiredAccess == 0)
    {
        return STATUS_ACCESS_DENIED;
    }
    return CmpCreateKeyHandle(found, desiredAccess, attributes->Attributes, keyHandle);
}

NTSTATUS NtOpenKey(PHANDLE keyHandle, ACCESS_MASK desiredAccess,
                   const OBJECT_ATTRIBUTES *attributes)
{
    /* as wine ntdll: NtOpenKey is NtOpenKeyEx without options */
    return NtOpenKeyEx(keyHandle, desiredAccess, attributes, 0);
}

NTSTATUS NtDeleteKey(HANDLE keyHandle)
{
    PCM_KEY_BODY body;
    /* allowDeleted: deleting an already-deleted key is a success no-op. */
    NTSTATUS status = CmpReferenceKey(keyHandle, DELETE, TRUE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCMP_KEY_NODE node = body->node;
    status = STATUS_SUCCESS;
    if (!node->deleted)
    {
        if (node->parent == 0 || node->parent == CmpRootNode)
        {
            /* the root and the Machine/User hive roots are permanent */
            status = STATUS_ACCESS_DENIED;
        }
        else if (node->subkeyCount != 0)
        {
            /* only leaf keys are deletable (wine server delete_key) */
            status = STATUS_ACCESS_DENIED;
        }
        else
        {
            BOOLEAN wasVolatile = node->isVolatile;
            RemoveEntryList(&node->siblingEntry);
            node->parent->subkeyCount--;
            node->parent->lastWriteTime = CmpNow();
            node->parent = 0;
            node->deleted = TRUE;
            CmpFreeValues(node);
            if (!wasVolatile)
            {
                CmpSaveHive();
            }
        }
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtDeleteValueKey(HANDLE keyHandle, const UNICODE_STRING *valueName)
{
    if (valueName == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (valueName->Length > CMP_MAX_VALUE_NAME_BYTES)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* as wine ntdll */
    }
    PCM_KEY_BODY body;
    NTSTATUS status = CmpReferenceKey(keyHandle, KEY_SET_VALUE, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCMP_KEY_NODE node = body->node;
    PCMP_VALUE value = CmpFindValue(node, valueName);
    if (value == 0)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    else
    {
        RemoveEntryList(&value->listEntry);
        node->valueCount--;
        if (value->name.Buffer != 0)
        {
            MiFreePool(value->name.Buffer);
        }
        if (value->data != 0)
        {
            MiFreePool(value->data);
        }
        MiFreePool(value);
        node->lastWriteTime = CmpNow();
        status = STATUS_SUCCESS;
        if (!node->isVolatile)
        {
            CmpSaveHive();
        }
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtSetValueKey(HANDLE keyHandle, const UNICODE_STRING *valueName, ULONG titleIndex,
                       ULONG type, const void *data, ULONG dataLength)
{
    (void)titleIndex;
    if (valueName == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (valueName->Length > CMP_MAX_VALUE_NAME_BYTES)
    {
        return STATUS_INVALID_PARAMETER; /* as wine ntdll */
    }
    if (dataLength != 0)
    {
        NTSTATUS probe = KiProbeForRead(data, dataLength, 1);
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
    }
    PCM_KEY_BODY body;
    NTSTATUS status = CmpReferenceKey(keyHandle, KEY_SET_VALUE, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCMP_KEY_NODE node = body->node;
    UNICODE_STRING name = *valueName;
    name.Length &= ~1u; /* as wine's server: whole WCHARs only */

    /* An identical set is a success no-op (wine server set_value): no
     * LastWriteTime touch, no hive rewrite. */
    PCMP_VALUE existing = CmpFindValue(node, &name);
    if (existing != 0 && existing->type == type && existing->dataLength == dataLength &&
        (dataLength == 0 || memcmp(existing->data, data, dataLength) == 0))
    {
        ObDereferenceObject(body);
        return STATUS_SUCCESS;
    }

    status = CmpSetValue(node, &name, type, data, dataLength);
    if (NT_SUCCESS(status))
    {
        node->lastWriteTime = CmpNow();
        if (!node->isVolatile)
        {
            CmpSaveHive();
        }
    }
    ObDereferenceObject(body);
    return status;
}

/* Shared probe for the query/enumerate services' out-parameters. */
static NTSTATUS CmpProbeInfoOut(void *buffer, ULONG length, ULONG *resultLength)
{
    if (resultLength == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(resultLength, sizeof(*resultLength), sizeof(*resultLength));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (length != 0)
    {
        status = KiProbeForWrite(buffer, length, 1);
    }
    return status;
}

NTSTATUS NtQueryValueKey(HANDLE keyHandle, const UNICODE_STRING *valueName,
                         KEY_VALUE_INFORMATION_CLASS infoClass, void *information, DWORD length,
                         DWORD *resultLength)
{
    if (valueName == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (valueName->Length > CMP_MAX_VALUE_NAME_BYTES)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* as wine ntdll */
    }
    NTSTATUS status = CmpProbeInfoOut(information, length, resultLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (infoClass != KeyValueBasicInformation && infoClass != KeyValueFullInformation &&
        infoClass != KeyValuePartialInformation)
    {
        return STATUS_INVALID_PARAMETER; /* incl. the Align64 flavours: unbuilt */
    }
    PCM_KEY_BODY body;
    status = CmpReferenceKey(keyHandle, KEY_QUERY_VALUE, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    UNICODE_STRING name = *valueName;
    name.Length &= ~1u;
    PCMP_VALUE value = CmpFindValue(body->node, &name);
    if (value == 0)
    {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    else
    {
        /* Query reports the CALLER's name spelling and length (wine ntdll
         * NtQueryValueKey builds the name part from its argument), which
         * differs from enumerate only in case — the stored value's name is
         * equal case-insensitively. Reuse the stored value but substitute
         * the caller's name for Basic/Full so NameLength matches. */
        CMP_VALUE queryView = *value;
        queryView.name = name;
        status = CmpFillValueInfo(&queryView, infoClass, information, length, resultLength);
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtEnumerateValueKey(HANDLE keyHandle, ULONG index, KEY_VALUE_INFORMATION_CLASS infoClass,
                             PVOID information, ULONG length, PULONG resultLength)
{
    NTSTATUS status = CmpProbeInfoOut(information, length, resultLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (infoClass != KeyValueBasicInformation && infoClass != KeyValueFullInformation &&
        infoClass != KeyValuePartialInformation)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PCM_KEY_BODY body;
    status = CmpReferenceKey(keyHandle, KEY_QUERY_VALUE, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCMP_KEY_NODE node = body->node;
    if (index >= node->valueCount)
    {
        status = STATUS_NO_MORE_ENTRIES;
    }
    else
    {
        PLIST_ENTRY e = node->valueListHead.Flink;
        for (ULONG i = 0; i < index; i++)
        {
            e = e->Flink;
        }
        status = CmpFillValueInfo(CONTAINING_RECORD(e, CMP_VALUE, listEntry), infoClass,
                                  information, length, resultLength);
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtEnumerateKey(HANDLE keyHandle, ULONG index, KEY_INFORMATION_CLASS infoClass,
                        void *information, DWORD length, DWORD *resultLength)
{
    NTSTATUS status = CmpProbeInfoOut(information, length, resultLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* index (ULONG)-1 is NtQueryKey's private encoding; refuse it here
     * (wine ntdll NtEnumerateKey). */
    if (index == (ULONG)-1)
    {
        return STATUS_NO_MORE_ENTRIES;
    }
    PCM_KEY_BODY body;
    status = CmpReferenceKey(keyHandle, KEY_ENUMERATE_SUB_KEYS, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCMP_KEY_NODE node = body->node;
    if (index >= node->subkeyCount)
    {
        status = STATUS_NO_MORE_ENTRIES;
    }
    else
    {
        PLIST_ENTRY e = node->subkeyListHead.Flink;
        for (ULONG i = 0; i < index; i++)
        {
            e = e->Flink;
        }
        status = CmpFillKeyInfo(CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry), infoClass,
                                information, length, resultLength);
    }
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtQueryKey(HANDLE keyHandle, KEY_INFORMATION_CLASS infoClass, void *information,
                    DWORD length, DWORD *resultLength)
{
    NTSTATUS status = CmpProbeInfoOut(information, length, resultLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PCM_KEY_BODY body;
    /* the key itself: no access bits required (wine enum_key with -1) */
    status = CmpReferenceKey(keyHandle, 0, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = CmpFillKeyInfo(body->node, infoClass, information, length, resultLength);
    ObDereferenceObject(body);
    return status;
}

NTSTATUS NtFlushKey(HANDLE keyHandle)
{
    PCM_KEY_BODY body;
    NTSTATUS status = CmpReferenceKey(keyHandle, 0, FALSE, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* Every mutation is already durable at syscall return (immediate
     * writeback, Art. 3) — nothing left to flush. */
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}

/* --- initialization --------------------------------------------------------- */

/* Create a skeleton path under the root if the loaded hive lacks it —
 * '\'-separated segments, existing nodes reused. Beyond the hive roots this
 * seeds the keys real NT guarantees exist (Session Manager: created by NT
 * itself, probed by kernel32:heap test_child_heap and read by the kernel's
 * own GlobalFlag stamp, kernel/ps/peb.c). */
static void CmpEnsureSkeletonKey(PCWSTR path)
{
    PCMP_KEY_NODE node = CmpRootNode;
    while (*path != 0)
    {
        const WCHAR *end = path;
        while (*end != 0 && *end != L'\\')
        {
            end++;
        }
        UNICODE_STRING segment;
        segment.Buffer = (PWSTR)path;
        segment.Length = (USHORT)((end - path) * sizeof(WCHAR));
        segment.MaximumLength = segment.Length;
        PCMP_KEY_NODE child = CmpFindSubkey(node, &segment);
        if (child == 0)
        {
            child = CmpAllocateNode(node, &segment);
            if (child == 0)
            {
                KiPanic("CmInitialize: out of pool");
            }
        }
        node = child;
        path = (*end != 0) ? end + 1 : end;
    }
}

void CmInitialize(void)
{
    CmpInitializeHiveLock();

    /* The root node and its permanent \Registry namespace object. */
    UNICODE_STRING rootNodeName;
    rootNodeName.Length = 0;
    rootNodeName.MaximumLength = 0;
    rootNodeName.Buffer = 0;
    CmpRootNode = CmpAllocateNode(0, &rootNodeName);
    if (CmpRootNode == 0)
    {
        KiPanic("CmInitialize: out of pool");
    }
    /* The root key's own (query-visible) name, NT-shaped. */
    RtlInitUnicodeString(&CmpRootNode->name, WSTR("REGISTRY"));

    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&objectName, WSTR("\\Registry"));
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = 0;
    attributes.ObjectName = &objectName;
    attributes.Attributes = OBJ_PERMANENT;
    attributes.SecurityDescriptor = 0;
    attributes.SecurityQualityOfService = 0;
    PVOID body;
    HANDLE handle;
    NTSTATUS status = ObpCreateObjectWithHandle(&CmpKeyType, sizeof(CM_KEY_BODY), &attributes,
                                                KEY_ALL_ACCESS, &body, &handle);
    if (status != STATUS_SUCCESS)
    {
        KiPanic("CmInitialize: cannot create \\Registry");
    }
    ((PCM_KEY_BODY)body)->node = CmpRootNode;
    CmpRootNode->bodyCount++;
    NtClose(handle);

    /* Load what survived the last boot, then guarantee the skeleton. */
    CmpLoadHive();
    CmpEnsureSkeletonKey(WSTR("Machine"));
    CmpEnsureSkeletonKey(WSTR("User"));
    CmpEnsureSkeletonKey(WSTR("Machine\\System\\CurrentControlSet\\Control\\Session Manager"));

    CmpSetHiveReady();
    DbgPrint("cm: registry up (\\Registry, hive %s)\n",
             CmpRootNode->subkeyCount > 2 ? "loaded" : "empty");
}
