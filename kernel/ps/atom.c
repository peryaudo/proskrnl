/* kernel/ps/atom.c — the global atom table (M10 winetest).
 *
 * On real NT the executive owns the global atom table behind
 * NtAddAtom/NtFindAtom/NtDeleteAtom/NtQueryInformationAtom. Under Wine the
 * same surface is split between ntdll's unix layer (integral-atom parsing —
 * dlls/ntdll/unix/sync.c is_integral_atom/integral_atom_name) and
 * wineserver's table (server/atom.c add_atom/find_atom/delete_atom/
 * get_atom_information). proskrnl's PE ntdll thunks straight into the
 * kernel, so BOTH halves are mirrored here, statuses and truncation rules
 * byte-for-byte; ntdll:atom test_Global pins them.
 *
 * Table shape follows server/atom.c: string atoms live at
 * MIN_STR_ATOM (0xc000) + index, names are case-insensitive, an add of an
 * existing name bumps its refcount. Sizing is fixed (Art. 3) with a loud
 * STATUS_NO_MEMORY when full.
 */
#include "kernel/ps/ps.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"

#include "abi/ntpsapi.h"

/* server/atom.c:44 MIN_STR_ATOM 0xc000 (integral atoms live below it — the
 * MAXINTATOM bound dlls/ntdll/unix/sync.c checks against), and
 * MAX_ATOM_LEN 255 chars (unix/sync.c:3220 and server/atom.c). */
#define PSP_ATOM_MIN_STR 0xc000
#define PSP_ATOM_MAX_LEN 255
#define PSP_ATOM_MAX     1024

typedef struct PSP_ATOM_ENTRY
{
    WCHAR *name; /* pooled, NUL-terminated; 0 = free slot */
    USHORT lengthBytes;
    ULONG referenceCount;
} PSP_ATOM_ENTRY;

static PSP_ATOM_ENTRY PspAtomTable[PSP_ATOM_MAX];

/* is_integral_atom (dlls/ntdll/unix/sync.c): a sub-64K "pointer" IS an
 * atom value; a real "#123" string parses to one. STATUS_MORE_ENTRIES
 * means "a real name — go to the table". `chars` counts WCHARs. */
static NTSTATUS PspIsIntegralAtom(const WCHAR *name, ULONG chars, RTL_ATOM *atomOut)
{
    RTL_ATOM atom;
    if (((uintptr_t)name >> 16) != 0)
    {
        if (chars == 0)
        {
            return STATUS_OBJECT_NAME_INVALID;
        }
        const WCHAR *ptr = name;
        if (*ptr++ == L'#')
        {
            atom = 0;
            while (ptr < name + chars && *ptr >= L'0' && *ptr <= L'9')
            {
                atom = (RTL_ATOM)(atom * 10 + (RTL_ATOM)(*ptr++ - L'0'));
            }
            if (ptr > name + 1 && ptr == name + chars)
            {
                goto done;
            }
        }
        if (chars > PSP_ATOM_MAX_LEN)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return STATUS_MORE_ENTRIES;
    }
    atom = (RTL_ATOM)(uintptr_t)name;
    if (atom >= PSP_ATOM_MIN_STR)
    {
        return STATUS_INVALID_PARAMETER;
    }
done:
    if (atom >= PSP_ATOM_MIN_STR)
    {
        atom = 0;
    }
    *atomOut = atom;
    return atom == 0 ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}

/* integral_atom_name (dlls/ntdll/unix/sync.c): "#%u", truncated to the
 * capacity, reporting the UNtruncated byte length. */
static ULONG PspIntegralAtomName(WCHAR *buffer, ULONG capacityBytes, RTL_ATOM atom)
{
    char ascii[16];
    int chars = 0;
    ascii[chars++] = '#';
    char digits[8];
    int d = 0;
    ULONG value = atom;
    do
    {
        digits[d++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (d > 0)
    {
        ascii[chars++] = digits[--d];
    }
    ULONG capacity = capacityBytes / sizeof(WCHAR);
    int copied = chars;
    if (capacity != 0)
    {
        if (capacity <= (ULONG)copied)
        {
            copied = (int)capacity - 1;
        }
        for (int i = 0; i < copied; i++)
        {
            buffer[i] = (WCHAR)(unsigned char)ascii[i];
        }
        buffer[copied] = 0;
    }
    return (ULONG)chars * sizeof(WCHAR);
}

/* Case-insensitive find (server/atom.c find_atom_entry / memicmp_strW).
 * Returns the index + 1, 0 = absent. */
static ULONG PspFindAtomEntry(const WCHAR *name, ULONG lengthBytes)
{
    for (ULONG i = 0; i < PSP_ATOM_MAX; i++)
    {
        if (PspAtomTable[i].name == 0 || PspAtomTable[i].lengthBytes != lengthBytes)
        {
            continue;
        }
        UNICODE_STRING a;
        a.Buffer = PspAtomTable[i].name;
        a.Length = (USHORT)lengthBytes;
        a.MaximumLength = a.Length;
        UNICODE_STRING b;
        b.Buffer = (PWSTR)name;
        b.Length = (USHORT)lengthBytes;
        b.MaximumLength = b.Length;
        if (RtlCompareUnicodeString(&a, &b, TRUE) == 0)
        {
            return i + 1;
        }
    }
    return 0;
}

/* Capture a user atom name into a bounded kernel buffer. */
static NTSTATUS PspCaptureAtomName(const WCHAR *userName, ULONG lengthBytes, WCHAR *kernelName)
{
    NTSTATUS status = KiProbeForRead(userName, lengthBytes, sizeof(WCHAR));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(kernelName, userName, lengthBytes);
    kernelName[lengthBytes / sizeof(WCHAR)] = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS PspAddOrFindAtom(const WCHAR *name, ULONG lengthBytes, BOOLEAN add,
                                 RTL_ATOM *atomOut)
{
    RTL_ATOM atom = 0;
    NTSTATUS status;
    if (((uintptr_t)name >> 16) == 0)
    {
        /* Integral "pointer": no memory behind it to capture. */
        status = PspIsIntegralAtom(name, 0, &atom);
    }
    else
    {
        WCHAR kernelName[PSP_ATOM_MAX_LEN + 1];
        ULONG chars = lengthBytes / sizeof(WCHAR);
        lengthBytes = chars * sizeof(WCHAR);
        if (chars > PSP_ATOM_MAX_LEN)
        {
            /* Bound the capture; the length check reports as the oracle. */
            return STATUS_INVALID_PARAMETER;
        }
        status = PspCaptureAtomName(name, lengthBytes, kernelName);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        status = PspIsIntegralAtom(kernelName, chars, &atom);
        if (status == STATUS_MORE_ENTRIES)
        {
            /* The table half (server/atom.c add_atom/find_atom). */
            if (lengthBytes == 0)
            {
                return STATUS_OBJECT_NAME_INVALID;
            }
            ULONG found = PspFindAtomEntry(kernelName, lengthBytes);
            if (found != 0)
            {
                if (add)
                {
                    PspAtomTable[found - 1].referenceCount++;
                }
                atom = (RTL_ATOM)(PSP_ATOM_MIN_STR + found - 1);
                status = STATUS_SUCCESS;
            }
            else if (!add)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            else
            {
                ULONG slot;
                for (slot = 0; slot < PSP_ATOM_MAX; slot++)
                {
                    if (PspAtomTable[slot].name == 0)
                    {
                        break;
                    }
                }
                if (slot == PSP_ATOM_MAX)
                {
                    return STATUS_NO_MEMORY;
                }
                WCHAR *copy = MiAllocatePool(lengthBytes + sizeof(WCHAR));
                if (copy == 0)
                {
                    return STATUS_NO_MEMORY;
                }
                memcpy(copy, kernelName, lengthBytes);
                copy[lengthBytes / sizeof(WCHAR)] = 0;
                PspAtomTable[slot].name = copy;
                PspAtomTable[slot].lengthBytes = (USHORT)lengthBytes;
                PspAtomTable[slot].referenceCount = 1;
                atom = (RTL_ATOM)(PSP_ATOM_MIN_STR + slot);
                status = STATUS_SUCCESS;
            }
        }
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    NTSTATUS writeStatus = KiProbeForWrite(atomOut, sizeof(RTL_ATOM), sizeof(RTL_ATOM));
    if (!NT_SUCCESS(writeStatus))
    {
        return writeStatus;
    }
    memcpy(atomOut, &atom, sizeof(atom));
    return status;
}

NTSTATUS NtAddAtom(const WCHAR *name, ULONG length, RTL_ATOM *atom)
{
    return PspAddOrFindAtom(name, length, TRUE, atom);
}

NTSTATUS NtFindAtom(const WCHAR *name, ULONG length, RTL_ATOM *atom)
{
    return PspAddOrFindAtom(name, length, FALSE, atom);
}

NTSTATUS NtDeleteAtom(RTL_ATOM atom)
{
    /* dlls/ntdll/unix/sync.c NtDeleteAtom: 0 is STATUS_INVALID_HANDLE, an
     * integral atom deletes as a no-op success; server/atom.c delete_atom
     * drops a reference and frees at zero. */
    if (atom == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    if (atom < PSP_ATOM_MIN_STR)
    {
        return STATUS_SUCCESS;
    }
    ULONG index = (ULONG)atom - PSP_ATOM_MIN_STR;
    if (index >= PSP_ATOM_MAX || PspAtomTable[index].name == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    if (--PspAtomTable[index].referenceCount == 0)
    {
        MiFreePool(PspAtomTable[index].name);
        PspAtomTable[index].name = 0;
        PspAtomTable[index].lengthBytes = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryInformationAtom(RTL_ATOM atom, ATOM_INFORMATION_CLASS infoClass, PVOID buffer,
                                ULONG length, PULONG returnLength)
{
    if (infoClass != AtomBasicInformation)
    {
        return STATUS_INVALID_INFO_CLASS;
    }
    /* The unix reference (dlls/ntdll/unix/sync.c NtQueryInformationAtom):
     * the struct must fit; the tail is name capacity. A truncated copy is
     * SUCCESS with the truncated NameLength; NO capacity at all reports the
     * full length as STATUS_BUFFER_TOO_SMALL. The NUL lands one WCHAR past
     * the copied name (the struct's own Name[1] provides the slack). */
    if (length < sizeof(ATOM_BASIC_INFORMATION))
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForWrite(buffer, length, sizeof(USHORT));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ATOM_BASIC_INFORMATION *info = buffer;
    ULONG capacityBytes = length - sizeof(ATOM_BASIC_INFORMATION);
    ULONG nameBytes = 0;

    if (atom < PSP_ATOM_MIN_STR)
    {
        if (atom == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        USHORT nameLength = (USHORT)PspIntegralAtomName(info->Name, capacityBytes, atom);
        USHORT one = 1;
        memcpy(&info->NameLength, &nameLength, sizeof(nameLength));
        memcpy(&info->ReferenceCount, &one, sizeof(one));
        memcpy(&info->Pinned, &one, sizeof(one));
        nameBytes = capacityBytes != 0 ? nameLength : 0;
        status = capacityBytes != 0 ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        ULONG index = (ULONG)atom - PSP_ATOM_MIN_STR;
        if (index >= PSP_ATOM_MAX || PspAtomTable[index].name == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        PSP_ATOM_ENTRY *entry = &PspAtomTable[index];
        ULONG copied = entry->lengthBytes < capacityBytes ? entry->lengthBytes : capacityBytes;
        USHORT nameLength;
        if (copied != 0)
        {
            memcpy(info->Name, entry->name, copied);
            info->Name[copied / sizeof(WCHAR)] = 0;
            nameLength = (USHORT)copied;
            status = STATUS_SUCCESS;
            nameBytes = copied;
        }
        else
        {
            nameLength = entry->lengthBytes;
            status = STATUS_BUFFER_TOO_SMALL;
            nameBytes = entry->lengthBytes;
        }
        USHORT referenceCount = (USHORT)entry->referenceCount;
        USHORT pinned = 0; /* server/atom.c get_atom_information: always 0 */
        memcpy(&info->NameLength, &nameLength, sizeof(nameLength));
        memcpy(&info->ReferenceCount, &referenceCount, sizeof(referenceCount));
        memcpy(&info->Pinned, &pinned, sizeof(pinned));
    }
    if (returnLength != 0)
    {
        NTSTATUS lengthStatus = KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(lengthStatus))
        {
            return lengthStatus;
        }
        ULONG total = (ULONG)sizeof(ATOM_BASIC_INFORMATION) + nameBytes;
        memcpy(returnLength, &total, sizeof(total));
    }
    return status;
}
