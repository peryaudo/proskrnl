/* kernel/cm/hive.c — hive persistence: the proskrnl hive v1 format (M8).
 *
 * Our own on-disk format — deliberately NOT Microsoft's regf (docs/03 "Cm
 * hive format": no MS hive binary compat; docs/05: "we never read a real
 * Windows hive", and regf's cell allocator + .LOG recovery journals are
 * exactly the complexity we shed). The bytes below are fixed by nothing but
 * this file, so this comment is their normative spec (gate G8: the trusted
 * source is proskrnl itself).
 *
 *   proskrnl hive v1 ("PHV1"), little-endian:
 *
 *   HEADER (16 bytes)
 *     u32 magic        'P''H''V''1' = 0x31564850
 *     u32 version      1
 *     u32 totalBytes   whole file, header included
 *     u32 reserved     0
 *   then one KEY record — the \Registry root (nameChars == 0) — where
 *   KEY  = u8 'K' | u8 flags | u16 nameChars | u64 lastWriteTime
 *          | u32 valueCount | UTF-16LE name
 *          | valueCount x VALUE | child KEYs... | u8 'E' u8 0
 *   flags: bit 0 = the key is a registry symbolic link
 *          (REG_OPTION_CREATE_LINK); other bits 0
 *   VALUE= u8 'V' | u8 pad(0) | u16 nameChars | u32 regType | u32 dataBytes
 *          | UTF-16LE name | data | u8 pad(0) if dataBytes is odd
 *
 * Every record's total size is even and the header is 16 bytes, so every
 * UTF-16 name in the stream sits at an even offset: the in-place
 * UNICODE_STRINGs the parser builds over the buffer are always 2-aligned
 * (the kernel is built with UBSan alignment traps; a misaligned WCHAR read
 * is a #UD panic). The parser's own arithmetic maintains this parity
 * regardless of file CONTENT, so a corrupted file cannot break it.
 *
 * Persistence model (Art. 3, "stupidly correct"): the whole tree is
 * serialized and the file rewritten on EVERY successful mutation, through
 * the ordinary NtCreateFile/NtWriteFile path onto write-through FAT32 — so
 * a mutating syscall's change is on disk when the syscall returns, and
 * NtFlushKey has nothing left to do. Crash cleanliness without recovery
 * logging: the body is written first with the header's magic still zero and
 * the real header is written last, so a torn rewrite leaves an invalid
 * magic and the next boot starts with an empty registry (deterministic
 * loss, never a garbage parse — the docs/03 M8 deviation).
 *
 * Volatile keys (REG_OPTION_VOLATILE) are simply skipped at serialize.
 */
#include "kernel/cm/cm.h"

#include "abi/ntioapi.h"
#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/le.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"

#define CMP_HIVE_MAGIC        0x31564850u /* "PHV1" */
#define CMP_HIVE_VERSION      1u
#define CMP_HIVE_HEADER_BYTES 16u
#define CMP_HIVE_MAX_BYTES    (64u << 20) /* sanity cap for load */

#define CMP_TAG_KEY   'K'
#define CMP_TAG_VALUE 'V'
#define CMP_TAG_END   'E'

/* The SYSTEM hive on the boot volume; NT's path shape, our bytes. */
#define CMP_HIVE_DIR  WSTR("\\??\\C:\\windows\\system32\\config")
#define CMP_HIVE_PATH WSTR("\\??\\C:\\windows\\system32\\config\\SYSTEM")

static KMUTEX CmpHiveMutex;   /* serializes concurrent savers */
static BOOLEAN CmpHiveReady;  /* set once CmInitialize finished */
static BOOLEAN CmpHiveWarned; /* one loud line per boot on save failure */

void CmpInitializeHiveLock(void)
{
    KeInitializeMutex(&CmpHiveMutex, 0);
}

void CmpSetHiveReady(void)
{
    CmpHiveReady = TRUE;
}

/* --- serialize -------------------------------------------------------------- */

/* The image's top record is stored with an EMPTY name whichever node it is:
 * the SYSTEM hive's root name ("REGISTRY") is fixed by CmInitialize, and a
 * subtree image's top name is fixed by wherever it is later attached
 * (NtLoadKey's destination) — the wineserver save_all_subkeys shape. */
static USHORT CmpPersistedNameBytes(const CMP_KEY_NODE *node, BOOLEAN asRoot)
{
    return asRoot ? 0 : node->name.Length;
}

/* Byte size of one KEY record (with descendants). Volatile CHILDREN are
 * skipped; the top node itself is always measured (an explicit NtSaveKey of
 * a loaded — volatile — key still saves its content). */
static ULONGLONG CmpMeasureKey(const CMP_KEY_NODE *node, BOOLEAN asRoot)
{
    ULONGLONG bytes =
        1 + 1 + 2 + 8 + 4 + CmpPersistedNameBytes(node, asRoot) + 2; /* K..name + E,0 */
    for (PLIST_ENTRY e = node->valueListHead.Flink; e != &node->valueListHead; e = e->Flink)
    {
        const CMP_VALUE *value = CONTAINING_RECORD(e, CMP_VALUE, listEntry);
        bytes += 1 + 1 + 2 + 4 + 4 + value->name.Length + value->dataLength +
                 (value->dataLength & 1); /* even parity (file comment) */
    }
    for (PLIST_ENTRY e = node->subkeyListHead.Flink; e != &node->subkeyListHead; e = e->Flink)
    {
        const CMP_KEY_NODE *child = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
        if (!child->isVolatile)
        {
            bytes += CmpMeasureKey(child, FALSE);
        }
    }
    return bytes;
}

static UCHAR *CmpEmitKey(const CMP_KEY_NODE *node, UCHAR *cursor, BOOLEAN asRoot)
{
    USHORT nameBytes = CmpPersistedNameBytes(node, asRoot);
    *cursor++ = CMP_TAG_KEY;
    *cursor++ = node->isLink ? 1 : 0;
    KiWriteLe16(cursor, nameBytes / sizeof(WCHAR));
    cursor += 2;
    KiWriteLe64(cursor, (ULONGLONG)node->lastWriteTime.QuadPart);
    cursor += 8;
    KiWriteLe32(cursor, node->valueCount);
    cursor += 4;
    memcpy(cursor, node->name.Buffer, nameBytes);
    cursor += nameBytes;
    for (PLIST_ENTRY e = node->valueListHead.Flink; e != &node->valueListHead; e = e->Flink)
    {
        const CMP_VALUE *value = CONTAINING_RECORD(e, CMP_VALUE, listEntry);
        *cursor++ = CMP_TAG_VALUE;
        *cursor++ = 0;
        KiWriteLe16(cursor, value->name.Length / sizeof(WCHAR));
        cursor += 2;
        KiWriteLe32(cursor, value->type);
        cursor += 4;
        KiWriteLe32(cursor, value->dataLength);
        cursor += 4;
        memcpy(cursor, value->name.Buffer, value->name.Length);
        cursor += value->name.Length;
        memcpy(cursor, value->data, value->dataLength);
        cursor += value->dataLength;
        if ((value->dataLength & 1) != 0)
        {
            *cursor++ = 0; /* keep the stream 2-aligned */
        }
    }
    for (PLIST_ENTRY e = node->subkeyListHead.Flink; e != &node->subkeyListHead; e = e->Flink)
    {
        const CMP_KEY_NODE *child = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
        if (!child->isVolatile)
        {
            cursor = CmpEmitKey(child, cursor, FALSE);
        }
    }
    *cursor++ = CMP_TAG_END;
    *cursor++ = 0; /* keep the stream 2-aligned */
    return cursor;
}

/* Build a complete PHV1 image of `top`'s subtree (top's name stored empty,
 * magic set — ready to hand to a caller's file). *bufferOut is pool, caller
 * frees. CUI-7: the NtSaveKey engine; CmpSaveHive uses the same emitters
 * with its own torn-write header dance. */
NTSTATUS CmpSerializeSubtree(const CMP_KEY_NODE *top, UCHAR **bufferOut, ULONG *totalOut)
{
    ULONGLONG total = CMP_HIVE_HEADER_BYTES + CmpMeasureKey(top, TRUE);
    if (total > CMP_HIVE_MAX_BYTES)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UCHAR *buffer = MiAllocatePool(total);
    if (buffer == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KiWriteLe32(buffer, CMP_HIVE_MAGIC);
    KiWriteLe32(buffer + 4, CMP_HIVE_VERSION);
    KiWriteLe32(buffer + 8, (ULONG)total);
    KiWriteLe32(buffer + 12, 0);
    UCHAR *end = CmpEmitKey(top, buffer + CMP_HIVE_HEADER_BYTES, TRUE);
    ASSERT(end == buffer + total);
    *bufferOut = buffer;
    *totalOut = (ULONG)total;
    return STATUS_SUCCESS;
}

/* --- parse ------------------------------------------------------------------ */

typedef struct
{
    const UCHAR *data;
    ULONGLONG length;
    ULONGLONG offset;
} CMP_HIVE_READER;

static BOOLEAN CmpReaderTake(CMP_HIVE_READER *reader, ULONGLONG bytes, const UCHAR **out)
{
    if (reader->length - reader->offset < bytes)
    {
        return FALSE;
    }
    *out = reader->data + reader->offset;
    reader->offset += bytes;
    return TRUE;
}

/* Parse one KEY record into `node` (already allocated and named): values,
 * children, the closing 'E'. Returns FALSE on any malformation. */
static BOOLEAN CmpParseKeyBody(CMP_HIVE_READER *reader, PCMP_KEY_NODE node, ULONG valueCount,
                               ULONG depth)
{
    const UCHAR *p;
    for (ULONG i = 0; i < valueCount; i++)
    {
        if (!CmpReaderTake(reader, 12, &p) || p[0] != CMP_TAG_VALUE)
        {
            return FALSE;
        }
        USHORT nameChars = KiReadLe16(p + 2);
        ULONG type = KiReadLe32(p + 4);
        ULONG dataBytes = KiReadLe32(p + 8);
        const UCHAR *nameBytes, *dataStart, *pad;
        if (!CmpReaderTake(reader, (ULONGLONG)nameChars * sizeof(WCHAR), &nameBytes) ||
            !CmpReaderTake(reader, dataBytes, &dataStart) ||
            ((dataBytes & 1) != 0 && !CmpReaderTake(reader, 1, &pad)))
        {
            return FALSE;
        }
        UNICODE_STRING name;
        name.Length = (USHORT)(nameChars * sizeof(WCHAR));
        name.MaximumLength = name.Length;
        name.Buffer = (PWSTR)(void *)nameBytes;
        if (!NT_SUCCESS(CmpSetValue(node, &name, type, dataStart, dataBytes)))
        {
            return FALSE;
        }
    }
    for (;;)
    {
        if (!CmpReaderTake(reader, 2, &p))
        {
            return FALSE;
        }
        if (p[0] == CMP_TAG_END)
        {
            return p[1] == 0; /* 'E' is a 2-byte record (parity) */
        }
        if (p[0] != CMP_TAG_KEY || (p[1] & ~1u) != 0 || depth >= CMP_HIVE_MAX_DEPTH)
        {
            return FALSE;
        }
        UCHAR keyFlags = p[1];
        const UCHAR *header;
        if (!CmpReaderTake(reader, 14, &header)) /* nameChars..valueCount */
        {
            return FALSE;
        }
        USHORT nameChars = KiReadLe16(header);
        ULONGLONG lastWrite = KiReadLe64(header + 2);
        ULONG childValues = KiReadLe32(header + 10);
        const UCHAR *nameBytes;
        if (nameChars == 0 ||
            !CmpReaderTake(reader, (ULONGLONG)nameChars * sizeof(WCHAR), &nameBytes))
        {
            return FALSE;
        }
        UNICODE_STRING name;
        name.Length = (USHORT)(nameChars * sizeof(WCHAR));
        name.MaximumLength = name.Length;
        name.Buffer = (PWSTR)(void *)nameBytes;
        PCMP_KEY_NODE child = CmpAllocateNode(node, &name);
        if (child == 0)
        {
            return FALSE;
        }
        child->lastWriteTime.QuadPart = (LONGLONG)lastWrite;
        child->isLink = (keyFlags & 1) != 0;
        if (!CmpParseKeyBody(reader, child, childValues, depth + 1))
        {
            return FALSE;
        }
    }
}

/* Free every child subtree + all values of `node` (parse-failure unwind;
 * only run while no key bodies exist, i.e. during CmInitialize). */
static void CmpFreeSubtree(PCMP_KEY_NODE node)
{
    while (!IsListEmpty(&node->subkeyListHead))
    {
        PCMP_KEY_NODE child =
            CONTAINING_RECORD(node->subkeyListHead.Flink, CMP_KEY_NODE, siblingEntry);
        CmpFreeSubtree(child);
        RemoveEntryList(&child->siblingEntry);
        node->subkeyCount--;
        ASSERT(child->bodyCount == 0);
        MiFreePool(child->name.Buffer);
        MiFreePool(child);
    }
    CmpFreeValues(node);
}

/* Parse a whole PHV1 image into `top` (fresh or wiped; content merges via
 * CmpSetValue/CmpAllocateNode). Any malformation unwinds everything parsed
 * so far and answers STATUS_NOT_REGISTRY_FILE — the caller keeps `top`
 * itself (the oracle's failed load also leaves its created destination
 * behind; pinned by sem_reg/save_load). */
NTSTATUS CmpParseSubtreeInto(PCMP_KEY_NODE top, const UCHAR *buffer, ULONGLONG length)
{
    if (length < CMP_HIVE_HEADER_BYTES + 16 || length > CMP_HIVE_MAX_BYTES ||
        KiReadLe32(buffer) != CMP_HIVE_MAGIC || KiReadLe32(buffer + 4) != CMP_HIVE_VERSION ||
        KiReadLe32(buffer + 8) != length)
    {
        return STATUS_NOT_REGISTRY_FILE;
    }
    CMP_HIVE_READER reader = {buffer, length, CMP_HIVE_HEADER_BYTES};
    const UCHAR *p;
    ULONG depth = CmpKeyDepth(top);
    if (!CmpReaderTake(&reader, 16, &p) || p[0] != CMP_TAG_KEY || KiReadLe16(p + 2) != 0 ||
        depth == 0 || depth > CMP_HIVE_MAX_DEPTH)
    {
        return STATUS_NOT_REGISTRY_FILE;
    }
    LARGE_INTEGER lastWrite;
    lastWrite.QuadPart = (LONGLONG)KiReadLe64(p + 4);
    if (!CmpParseKeyBody(&reader, top, KiReadLe32(p + 12), depth - 1) ||
        reader.offset != reader.length)
    {
        CmpFreeSubtree(top);
        return STATUS_NOT_REGISTRY_FILE;
    }
    top->lastWriteTime = lastWrite;
    return STATUS_SUCCESS;
}

/* --- the file --------------------------------------------------------------- */

/* Open the hive (or its directory) with a kernel-internal transient handle;
 * the IopOpenFileSection pattern (kernel/io/file.c). */
static NTSTATUS CmpOpenHiveFile(PCWSTR path, ACCESS_MASK access, ULONG disposition, ULONG options,
                                PHANDLE handleOut)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK iosb;
    return NtCreateFile(handleOut, access, &attributes, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ, disposition, options, 0, 0);
}

/* Read the whole hive file. *bufferOut is pool (caller frees); FALSE = no
 * usable file (missing, empty, oversized, short read). */
static BOOLEAN CmpReadHiveFile(UCHAR **bufferOut, ULONGLONG *lengthOut)
{
    HANDLE handle;
    NTSTATUS status =
        CmpOpenHiveFile(CMP_HIVE_PATH, FILE_GENERIC_READ, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    BOOLEAN ok = FALSE;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    if (NT_SUCCESS(status) && standard.EndOfFile.QuadPart >= (LONGLONG)CMP_HIVE_HEADER_BYTES &&
        standard.EndOfFile.QuadPart <= (LONGLONG)CMP_HIVE_MAX_BYTES)
    {
        ULONGLONG length = (ULONGLONG)standard.EndOfFile.QuadPart;
        UCHAR *buffer = MiAllocatePool(length);
        if (buffer != 0)
        {
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, (ULONG)length, &offset, 0);
            if (NT_SUCCESS(status) && iosb.Information == length)
            {
                *bufferOut = buffer;
                *lengthOut = length;
                ok = TRUE;
            }
            else
            {
                MiFreePool(buffer);
            }
        }
    }
    NtClose(handle);
    return ok;
}

void CmpLoadHive(void)
{
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;

    UCHAR *buffer = 0;
    ULONGLONG length = 0;
    BOOLEAN haveFile = CmpReadHiveFile(&buffer, &length);
    thread->previousMode = saved;
    if (!haveFile)
    {
        DbgPrint("cm: no hive on the boot volume - starting an empty registry\n");
        return;
    }

    BOOLEAN ok = FALSE;
    if (KiReadLe32(buffer) == CMP_HIVE_MAGIC && KiReadLe32(buffer + 4) == CMP_HIVE_VERSION &&
        KiReadLe32(buffer + 8) == length)
    {
        CMP_HIVE_READER reader = {buffer, length, CMP_HIVE_HEADER_BYTES};
        const UCHAR *p;
        /* The root record: tag, flags, nameChars == 0, time, valueCount. */
        if (CmpReaderTake(&reader, 16, &p) && p[0] == CMP_TAG_KEY && KiReadLe16(p + 2) == 0)
        {
            CmpRootNode->lastWriteTime.QuadPart = (LONGLONG)KiReadLe64(p + 4);
            ok = CmpParseKeyBody(&reader, CmpRootNode, KiReadLe32(p + 12), 0) &&
                 reader.offset == reader.length;
        }
    }
    if (!ok)
    {
        DbgPrint("cm: hive file invalid - starting an empty registry\n");
        CmpFreeSubtree(CmpRootNode);
    }
    MiFreePool(buffer);
}

void CmpSaveHive(void)
{
    if (!CmpHiveReady)
    {
        return; /* skeleton building during CmInitialize */
    }

    /* One saver at a time; each mutating syscall persists its own snapshot
     * before returning (immediate writeback, Art. 3). */
    KeWaitForSingleObject(&CmpHiveMutex, Executive, KernelMode, FALSE, 0);

    ULONGLONG total = CMP_HIVE_HEADER_BYTES + CmpMeasureKey(CmpRootNode, TRUE);
    UCHAR *buffer = MiAllocatePool(total);
    if (buffer == 0)
    {
        KeReleaseMutex(&CmpHiveMutex, FALSE);
        DbgPrint("cm: hive save skipped - out of pool\n");
        return;
    }
    KiWriteLe32(buffer, 0); /* magic goes in only after the body is on disk */
    KiWriteLe32(buffer + 4, CMP_HIVE_VERSION);
    KiWriteLe32(buffer + 8, (ULONG)total);
    KiWriteLe32(buffer + 12, 0);
    UCHAR *end = CmpEmitKey(CmpRootNode, buffer + CMP_HIVE_HEADER_BYTES, TRUE);
    ASSERT(end == buffer + total);

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;

    /* Ensure ...\config exists (first boot), then rewrite the file: truncate,
     * whole image with the magic field still zero, then the real magic —
     * the torn-write story in the file comment. */
    HANDLE handle;
    NTSTATUS status = CmpOpenHiveFile(CMP_HIVE_DIR, FILE_GENERIC_READ, FILE_OPEN_IF,
                                      FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
        status = CmpOpenHiveFile(CMP_HIVE_PATH, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                 FILE_OVERWRITE_IF,
                                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    }
    if (NT_SUCCESS(status))
    {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        status = NtWriteFile(handle, 0, 0, 0, &iosb, buffer, (ULONG)total, &offset, 0);
        if (NT_SUCCESS(status))
        {
            KiWriteLe32(buffer, CMP_HIVE_MAGIC);
            status = NtWriteFile(handle, 0, 0, 0, &iosb, buffer, 4, &offset, 0);
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    MiFreePool(buffer);
    KeReleaseMutex(&CmpHiveMutex, FALSE);

    if (!NT_SUCCESS(status) && !CmpHiveWarned)
    {
        CmpHiveWarned = TRUE;
        DbgPrint("cm: hive save FAILED %08lx - registry changes will not survive reboot\n",
                 (unsigned long)status);
    }
}
