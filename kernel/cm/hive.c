/* kernel/cm/hive.c — hive persistence: the proskrnl hive v2 format (M8, CUI-7).
 *
 * Our own on-disk format — deliberately NOT Microsoft's regf (docs/03 "Cm
 * hive format": no MS hive binary compat; docs/05: "we never read a real
 * Windows hive", and regf's cell allocator + .LOG recovery journals are
 * exactly the complexity we shed). The bytes below are fixed by nothing but
 * this file, so this comment is their normative spec (gate G8: the trusted
 * source is proskrnl itself).
 *
 * PHV1 stored the tree AS A TREE: a nested preorder dump in which a key's
 * parent was "whichever record we are lexically inside" and its subtree was
 * delimited by an end marker. That shape has exactly one way to change a key
 * three levels down — rewrite the whole file — which is what made every
 * mutating syscall O(hive). PHV2 stores the same tree as a FLAT LOG of
 * records, each naming its key by FULL PATH, so a change is a record appended
 * at the end and structure is a field rather than a position.
 *
 *   proskrnl hive v2 ("PHV2"), little-endian:
 *
 *   HEADER (16 bytes)
 *     u32 magic        'P''H''V''2' = 0x32564850
 *     u32 version      2
 *     u32 reserved     0
 *     u32 reserved     0
 *   (no totalBytes: an append-only file cannot maintain one, and the record
 *   framing below is what bounds the reader instead)
 *
 *   RECORD (repeated to EOF; every record is a multiple of 8 bytes)
 *     u32 byteLength     whole record including this field
 *     u32 crc32          CRC-32/ISO-HDLC over every byte AFTER this field
 *     u8  op             1 CREATE_KEY  2 DELETE_KEY   3 SET_VALUES
 *                        4 DELETE_VALUE 5 RENAME_KEY
 *     u8  keyFlags       bit 0 = registry symbolic link
 *                        (REG_OPTION_CREATE_LINK); other bits 0
 *     u16 pathChars
 *     u16 sharedChars    RESERVED, always 0. Held for a later common-prefix
 *                        elision against the previous record's path; a
 *                        reader must refuse a nonzero value rather than
 *                        guess at it.
 *     u16 valueCount     0 except SET_VALUES
 *     u64 lastWriteTime  the key's stamp AFTER this action
 *     UTF-16LE path      pathChars, then padding to a multiple of 8
 *     <tail per op>      then padding to a multiple of 8
 *
 *     CREATE_KEY    no tail
 *     DELETE_KEY    no tail
 *     SET_VALUES    valueCount x VALUE
 *     DELETE_VALUE  u16 nameChars | u16 pad | UTF-16LE name | pad to 8
 *     RENAME_KEY    u16 nameChars | u16 pad | UTF-16LE name | pad to 8
 *
 *   VALUE = u16 nameChars | u16 pad | u32 regType | u32 dataBytes
 *           | UTF-16LE name | data | padding to a multiple of 8
 *
 * The path is RELATIVE to the image's top key and carries no leading
 * backslash: "Machine\Software\Foo" in the boot hive, and the empty path for
 * the top key itself. That is what lets an NtSaveKey subtree image attach
 * anywhere an NtLoadKey names (PHV1 needed a store-the-top-name-empty special
 * case for the same job).
 *
 * REPLAY is the fold of the log in order, and three of its rules are load
 * bearing:
 *
 *   - SET_VALUES MERGES. Each named value replaces any prior binding for that
 *     name; values the record does not mention are untouched. Absence is
 *     therefore not expressible by a SET_VALUES, which is exactly why
 *     DELETE_VALUE is its own op — a log whose only value op were "set" would
 *     replay a deletion away. valueCount == 0 is legal and means "touch": it
 *     carries a new lastWriteTime and nothing else, which is what
 *     NtSetInformationKey(KeyWriteTimeInformation) mutates.
 *   - A RECORD'S PARENT MUST ALREADY EXIST. Ancestors are always logged
 *     before descendants (nothing can create a child before its parent), so
 *     a missing parent means a corrupt or reordered file, and replay refuses
 *     it rather than conjuring the intermediate keys. This mirrors
 *     NtCreateKey, which also creates only the last component.
 *   - NO RECORD EVER DELETES A NON-EMPTY KEY. NtDeleteKey refuses a key with
 *     subkeys, so DELETE_KEY is always a leaf. The two syscalls that DO drop
 *     a whole subtree — NtUnloadKey on a non-volatile target, and
 *     NtRestoreKey — rewrite the log from a fresh snapshot instead of
 *     appending, so replay never has to cascade a delete and a corrupt path
 *     cannot become more destructive than the record it sits in.
 *
 * ALIGNMENT is 8, and it is not cosmetic. Names are read in place as
 * UNICODE_STRINGs pointing into the file buffer, and the kernel is built with
 * UBSan alignment traps, so a misaligned WCHAR read is a #UD panic. The fixed
 * record header is 24 bytes, the path is padded to 8, and every VALUE is
 * padded to 8 — so a path starts 8-aligned and a value's name starts at
 * value+12, always even. The parser maintains that arithmetic itself,
 * regardless of file CONTENT, so a corrupted file cannot break it.
 *
 * RECOVERY without a journal: the reader validates each record's length,
 * bounds and CRC, and STOPS at the first one that fails, keeping everything
 * before it. A torn append therefore costs the last record and nothing else
 * — where PHV1's torn rewrite cost the whole registry, because its magic was
 * written last and an unfinished body left no valid file at all.
 *
 * Volatile keys (REG_OPTION_VOLATILE) are never logged.
 */
#include "kernel/cm/cm.h"

#include "abi/ntioapi.h"
#include "kernel/init/panic.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/crc32.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/le.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"

#define CMP_HIVE_MAGIC        0x32564850u /* "PHV2" */
#define CMP_HIVE_VERSION      2u
#define CMP_HIVE_HEADER_BYTES 16u
/* CMP_HIVE_MAX_BYTES lives in cm.h — the ring-3 load paths bound their file
 * with the same number. */

/* Fixed part of a record, up to and not including the path. */
#define CMP_RECORD_HEADER_BYTES 24u
#define CMP_RECORD_ALIGN        8u

/* Fixed part of one VALUE, up to and not including its name. */
#define CMP_VALUE_HEADER_BYTES 12u

/* Values per SET_VALUES record. Bounded by the u16 valueCount field; kept
 * well under it so a record stays a sane size. Splitting is invisible
 * because SET_VALUES merges. */
#define CMP_VALUES_PER_RECORD 1024u

#define CMP_OP_CREATE_KEY   1u
#define CMP_OP_DELETE_KEY   2u
#define CMP_OP_SET_VALUES   3u
#define CMP_OP_DELETE_VALUE 4u
#define CMP_OP_RENAME_KEY   5u

/* The SYSTEM hive on the boot volume; NT's path shape, our bytes. */
#define CMP_HIVE_DIR  WSTR("\\??\\C:\\windows\\system32\\config")
#define CMP_HIVE_PATH WSTR("\\??\\C:\\windows\\system32\\config\\SYSTEM")
/* Compaction writes here and renames over CMP_HIVE_PATH. */
#define CMP_HIVE_TEMP_PATH WSTR("\\??\\C:\\windows\\system32\\config\\SYSTEM.new")

static KMUTEX CmpHiveMutex;   /* serializes concurrent savers */
static BOOLEAN CmpHiveReady;  /* set once CmInitialize finished */
static BOOLEAN CmpHiveWarned; /* one loud line per boot on save failure */

void CmpInitializeHiveLock(void)
{
    KeInitializeMutex(&CmpHiveMutex, 0);
    /* Prove the checksum before anything depends on it: a wrong CRC would
     * otherwise surface as an unreadable hive on some later boot, which
     * reads as data loss rather than as arithmetic. */
    KiCrc32SelfTest();
}

void CmpSetHiveReady(void)
{
    CmpHiveReady = TRUE;
}

static ULONGLONG CmpRoundUp8(ULONGLONG bytes)
{
    return (bytes + (CMP_RECORD_ALIGN - 1)) & ~(ULONGLONG)(CMP_RECORD_ALIGN - 1);
}

/* --- the writer ------------------------------------------------------------
 *
 * One walk serves both the measuring pass and the emitting pass: with
 * `buffer` null nothing is written and only `offset` advances. PHV1 had a
 * separate CmpMeasureKey and CmpEmitKey that had to agree byte for byte;
 * this cannot disagree with itself. */

typedef struct
{
    UCHAR *buffer; /* 0 = measure only */
    ULONGLONG offset;
} CMP_WRITER;

static void CmpWriteBytes(CMP_WRITER *writer, const void *data, ULONGLONG bytes)
{
    if (writer->buffer != 0 && bytes != 0)
    {
        memcpy(writer->buffer + writer->offset, data, bytes);
    }
    writer->offset += bytes;
}

static void CmpWritePad(CMP_WRITER *writer)
{
    ULONGLONG padded = CmpRoundUp8(writer->offset);
    if (writer->buffer != 0)
    {
        memset(writer->buffer + writer->offset, 0, padded - writer->offset);
    }
    writer->offset = padded;
}

static void CmpWrite16(CMP_WRITER *writer, USHORT value)
{
    if (writer->buffer != 0)
    {
        KiWriteLe16(writer->buffer + writer->offset, value);
    }
    writer->offset += 2;
}

static void CmpWrite32(CMP_WRITER *writer, ULONG value)
{
    if (writer->buffer != 0)
    {
        KiWriteLe32(writer->buffer + writer->offset, value);
    }
    writer->offset += 4;
}

static void CmpWrite64(CMP_WRITER *writer, ULONGLONG value)
{
    if (writer->buffer != 0)
    {
        KiWriteLe64(writer->buffer + writer->offset, value);
    }
    writer->offset += 8;
}

/* Open a record: writes the fixed header and the path, leaving the cursor at
 * the tail. `byteLength` and `crc32` are backpatched by CmpEndRecord, which
 * is why the record's start offset is returned. */
static ULONGLONG CmpBeginRecord(CMP_WRITER *writer, UCHAR op, UCHAR keyFlags,
                                const CMP_KEY_NODE *node, const CMP_KEY_NODE *top,
                                const UNICODE_STRING *capturedPath, LARGE_INTEGER stamp,
                                ULONG valueCount)
{
    ULONGLONG start = writer->offset;
    /* Either derive the path from the live node (the snapshot walk) or use one
     * the caller captured BEFORE it mutated the tree. NtDeleteKey unlinks the
     * node and NtRenameKey replaces its name before the log is written, so
     * deriving the path at that point would spell the wrong key -- a truncated
     * one and the NEW one respectively. */
    ULONG pathBytes = capturedPath != 0 ? capturedPath->Length : CmpBuildPath(node, top, 0, 0);

    ASSERT((start & (CMP_RECORD_ALIGN - 1)) == 0);
    CmpWrite32(writer, 0); /* byteLength, backpatched */
    CmpWrite32(writer, 0); /* crc32, backpatched */
    if (writer->buffer != 0)
    {
        writer->buffer[writer->offset] = op;
        writer->buffer[writer->offset + 1] = keyFlags;
    }
    writer->offset += 2;
    CmpWrite16(writer, (USHORT)(pathBytes / sizeof(WCHAR)));
    CmpWrite16(writer, 0); /* sharedChars: reserved */
    CmpWrite16(writer, (USHORT)valueCount);
    CmpWrite64(writer, (ULONGLONG)stamp.QuadPart);
    ASSERT(writer->offset - start == CMP_RECORD_HEADER_BYTES);

    if (writer->buffer != 0 && pathBytes != 0)
    {
        /* The path is written straight into the record; capacity is exactly
         * what the measuring call above reported. The record is 8-aligned and
         * the header is 24 bytes, so this destination is WCHAR-aligned. */
        UCHAR *pathAt = writer->buffer + writer->offset;
        WCHAR *pathOut = (WCHAR *)(void *)pathAt; /* NOLINT(bugprone-casting-through-void) */
        if (capturedPath != 0)
        {
            memcpy(pathOut, capturedPath->Buffer, pathBytes);
        }
        else
        {
            (void)CmpBuildPath(node, top, pathOut, pathBytes / sizeof(WCHAR));
        }
    }
    writer->offset += pathBytes;
    CmpWritePad(writer);
    return start;
}

/* Close a record: pad to 8, then backpatch its length and checksum. */
static void CmpEndRecord(CMP_WRITER *writer, ULONGLONG start)
{
    CmpWritePad(writer);
    ULONGLONG length = writer->offset - start;
    ASSERT(length >= CMP_RECORD_HEADER_BYTES && (length & (CMP_RECORD_ALIGN - 1)) == 0);
    if (writer->buffer != 0)
    {
        KiWriteLe32(writer->buffer + start, (ULONG)length);
        ULONG crc = KiCrc32(writer->buffer + start + 8, (size_t)(length - 8));
        KiWriteLe32(writer->buffer + start + 4, crc);
    }
}

static void CmpWriteValue(CMP_WRITER *writer, const CMP_VALUE *value)
{
    CmpWrite16(writer, (USHORT)(value->name.Length / sizeof(WCHAR)));
    CmpWrite16(writer, 0); /* pad */
    CmpWrite32(writer, value->type);
    CmpWrite32(writer, value->dataLength);
    CmpWriteBytes(writer, value->name.Buffer, value->name.Length);
    CmpWriteBytes(writer, value->data, value->dataLength);
    CmpWritePad(writer);
}

/* Emit the snapshot records for one key: its CREATE_KEY, and a SET_VALUES if
 * it has any values. */
static void CmpWriteKeySnapshot(CMP_WRITER *writer, const CMP_KEY_NODE *node,
                                const CMP_KEY_NODE *top)
{
    ULONGLONG start = CmpBeginRecord(writer, CMP_OP_CREATE_KEY, node->isLink ? 1 : 0, node, top, 0,
                                     node->lastWriteTime, 0);
    CmpEndRecord(writer, start);

    /* Values go out in chunks. valueCount is a u16 in the record, and a key
     * may hold more values than that — but SET_VALUES MERGES, so several
     * records rebuild exactly the set one record would have. Chunking is
     * therefore free here, and it bounds a record's size as a side effect. */
    PLIST_ENTRY entry = node->valueListHead.Flink;
    while (entry != &node->valueListHead)
    {
        ULONG chunk = 0;
        for (PLIST_ENTRY e = entry; e != &node->valueListHead && chunk < CMP_VALUES_PER_RECORD;
             e = e->Flink)
        {
            chunk++;
        }
        start =
            CmpBeginRecord(writer, CMP_OP_SET_VALUES, 0, node, top, 0, node->lastWriteTime, chunk);
        for (ULONG i = 0; i < chunk; i++)
        {
            CmpWriteValue(writer, CONTAINING_RECORD(entry, CMP_VALUE, listEntry));
            entry = entry->Flink;
        }
        CmpEndRecord(writer, start);
    }
}

/* Preorder over the non-volatile tree. The top node itself is always
 * emitted (an explicit NtSaveKey of a loaded — volatile — key still saves its
 * content); volatile CHILDREN are skipped, and with them their subtrees. */
static void CmpWriteSubtree(CMP_WRITER *writer, const CMP_KEY_NODE *node, const CMP_KEY_NODE *top)
{
    CmpWriteKeySnapshot(writer, node, top);
    for (PLIST_ENTRY e = node->subkeyListHead.Flink; e != &node->subkeyListHead; e = e->Flink)
    {
        const CMP_KEY_NODE *child = CONTAINING_RECORD(e, CMP_KEY_NODE, siblingEntry);
        if (!child->isVolatile)
        {
            CmpWriteSubtree(writer, child, top);
        }
    }
}

/* Build a complete PHV2 image of `top`'s subtree, paths relative to `top`.
 * *bufferOut is pool, caller frees. THE snapshot emitter: NtSaveKey, the
 * boot-time save, and the subtree rewrite the unload/restore paths need all
 * come through here (Art. 11). */
NTSTATUS CmpSerializeSubtree(const CMP_KEY_NODE *top, UCHAR **bufferOut, ULONG *totalOut)
{
    CMP_WRITER measure = {0, CMP_HIVE_HEADER_BYTES};
    CmpWriteSubtree(&measure, top, top);
    ULONGLONG total = measure.offset;
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
    KiWriteLe32(buffer + 8, 0);
    KiWriteLe32(buffer + 12, 0);

    CMP_WRITER emit = {buffer, CMP_HIVE_HEADER_BYTES};
    CmpWriteSubtree(&emit, top, top);
    ASSERT(emit.offset == total);
    *bufferOut = buffer;
    *totalOut = (ULONG)total;
    return STATUS_SUCCESS;
}

/* --- the reader ------------------------------------------------------------ */

typedef struct
{
    const UCHAR *data;
    ULONGLONG length;
    ULONGLONG offset;
} CMP_HIVE_READER;

/* One record, already bounds-checked, with its variable parts located. */
typedef struct
{
    UCHAR op;
    UCHAR keyFlags;
    ULONG valueCount;
    ULONGLONG lastWriteTime;
    UNICODE_STRING path;
    const UCHAR *tail;
    ULONGLONG tailBytes;
} CMP_RECORD;

/* Take the next record. FALSE = the log ends here: a short tail, a bad
 * length, a failed CRC or a reserved field this reader does not understand.
 * Every one of those is "stop and keep the prefix", never a diagnosis — a
 * torn append and a corrupt byte are indistinguishable and are treated the
 * same on purpose. */
static BOOLEAN CmpReadRecord(CMP_HIVE_READER *reader, CMP_RECORD *out)
{
    if (reader->length - reader->offset < CMP_RECORD_HEADER_BYTES)
    {
        return FALSE;
    }
    const UCHAR *p = reader->data + reader->offset;
    ULONG length = KiReadLe32(p);
    if (length < CMP_RECORD_HEADER_BYTES || (length & (CMP_RECORD_ALIGN - 1)) != 0 ||
        length > reader->length - reader->offset)
    {
        return FALSE;
    }
    if (KiCrc32(p + 8, length - 8) != KiReadLe32(p + 4))
    {
        return FALSE;
    }
    USHORT pathChars = KiReadLe16(p + 10);
    if (KiReadLe16(p + 12) != 0) /* sharedChars is reserved */
    {
        return FALSE;
    }
    ULONGLONG pathBytes = (ULONGLONG)pathChars * sizeof(WCHAR);
    ULONGLONG tailStart = CmpRoundUp8(CMP_RECORD_HEADER_BYTES + pathBytes);
    if (tailStart > length)
    {
        return FALSE;
    }
    out->op = p[8];
    out->keyFlags = p[9];
    out->valueCount = KiReadLe16(p + 14);
    out->lastWriteTime = KiReadLe64(p + 16);
    out->path.Length = (USHORT)pathBytes;
    out->path.MaximumLength = out->path.Length;
    /* In place over the buffer: the record header is 24 bytes and the record
     * itself is 8-aligned, so this pointer is 8-aligned and the WCHAR reads
     * below are legal (see the ALIGNMENT paragraph at the top). */
    const UCHAR *pathPtr = p + CMP_RECORD_HEADER_BYTES;
    out->path.Buffer = (PWSTR)(void *)pathPtr; /* NOLINT(bugprone-casting-through-void) */
    out->tail = p + tailStart;
    out->tailBytes = length - tailStart;
    reader->offset += length;
    return TRUE;
}

/* Apply one SET_VALUES tail to `node`. FALSE = malformed. */
static BOOLEAN CmpApplyValues(PCMP_KEY_NODE node, const CMP_RECORD *record)
{
    const UCHAR *cursor = record->tail;
    ULONGLONG remaining = record->tailBytes;

    for (ULONG i = 0; i < record->valueCount; i++)
    {
        if (remaining < CMP_VALUE_HEADER_BYTES)
        {
            return FALSE;
        }
        USHORT nameChars = KiReadLe16(cursor);
        ULONG type = KiReadLe32(cursor + 4);
        ULONG dataBytes = KiReadLe32(cursor + 8);
        ULONGLONG nameBytes = (ULONGLONG)nameChars * sizeof(WCHAR);
        ULONGLONG used = CmpRoundUp8(CMP_VALUE_HEADER_BYTES + nameBytes + dataBytes);
        if (nameBytes + dataBytes < nameBytes || used > remaining)
        {
            return FALSE;
        }
        UNICODE_STRING name;
        name.Length = (USHORT)nameBytes;
        name.MaximumLength = name.Length;
        /* In place: the value starts 8-aligned, so name is at +12, even. */
        const UCHAR *namePtr = cursor + CMP_VALUE_HEADER_BYTES;
        name.Buffer = (PWSTR)(void *)namePtr; /* NOLINT(bugprone-casting-through-void) */
        if (!NT_SUCCESS(CmpSetValue(node, &name, type, cursor + CMP_VALUE_HEADER_BYTES + nameBytes,
                                    dataBytes)))
        {
            return FALSE;
        }
        cursor += used;
        remaining -= used;
    }
    return TRUE;
}

/* Resolve a record's path under `top`, creating only the LAST component. A
 * missing intermediate is a refusal, not something to conjure: ancestors are
 * always logged first, so their absence means the file is corrupt. */
static PCMP_KEY_NODE CmpResolveRecordKey(PCMP_KEY_NODE top, const UNICODE_STRING *path,
                                         BOOLEAN create)
{
    if (path->Length == 0)
    {
        return top; /* the empty path is the image's own top key */
    }
    ULONG chars = path->Length / sizeof(WCHAR);
    ULONG split = chars;
    while (split > 0 && path->Buffer[split - 1] != L'\\')
    {
        split--;
    }
    PCMP_KEY_NODE parent = top;
    if (split > 0)
    {
        UNICODE_STRING parentPath;
        parentPath.Buffer = path->Buffer;
        parentPath.Length = (USHORT)((split - 1) * sizeof(WCHAR)); /* drop the separator */
        parentPath.MaximumLength = parentPath.Length;
        parent = CmpWalkPathCounted(top, &parentPath, FALSE);
        if (parent == 0)
        {
            return 0;
        }
    }
    UNICODE_STRING leaf;
    leaf.Buffer = path->Buffer + split;
    leaf.Length = (USHORT)((chars - split) * sizeof(WCHAR));
    leaf.MaximumLength = leaf.Length;
    if (leaf.Length == 0)
    {
        return 0;
    }
    /* One component, through the one resolver: find-or-create with the same
     * NLS fold NtOpenKey uses. */
    return CmpWalkPathCounted(parent, &leaf, create);
}

/* The single-name tail DELETE_VALUE and RENAME_KEY share:
 * u16 nameChars | u16 pad | UTF-16LE name. FALSE = malformed. */
static BOOLEAN CmpReadTailName(const CMP_RECORD *record, UNICODE_STRING *out)
{
    if (record->tailBytes < 4)
    {
        return FALSE;
    }
    USHORT nameChars = KiReadLe16(record->tail);
    ULONGLONG nameBytes = (ULONGLONG)nameChars * sizeof(WCHAR);
    if (4 + nameBytes > record->tailBytes)
    {
        return FALSE;
    }
    out->Length = (USHORT)nameBytes;
    out->MaximumLength = out->Length;
    /* In place: the tail starts 8-aligned, so the name at +4 is even. */
    const UCHAR *namePtr = record->tail + 4;
    out->Buffer = (PWSTR)(void *)namePtr; /* NOLINT(bugprone-casting-through-void) */
    return TRUE;
}

/* Apply one record to the tree under `top`. FALSE stops the replay. */
static BOOLEAN CmpApplyRecord(PCMP_KEY_NODE top, const CMP_RECORD *record)
{
    switch (record->op)
    {
    case CMP_OP_CREATE_KEY:
    {
        PCMP_KEY_NODE node = CmpResolveRecordKey(top, &record->path, TRUE);
        if (node == 0)
        {
            return FALSE;
        }
        node->lastWriteTime.QuadPart = (LONGLONG)record->lastWriteTime;
        node->isLink = (record->keyFlags & 1) != 0;
        return (record->keyFlags & ~1u) == 0;
    }
    case CMP_OP_SET_VALUES:
    {
        PCMP_KEY_NODE node = CmpResolveRecordKey(top, &record->path, FALSE);
        if (node == 0)
        {
            return FALSE;
        }
        node->lastWriteTime.QuadPart = (LONGLONG)record->lastWriteTime;
        return CmpApplyValues(node, record);
    }
    case CMP_OP_DELETE_KEY:
    {
        PCMP_KEY_NODE node = CmpResolveRecordKey(top, &record->path, FALSE);
        /* Never a cascade: the emitters only ever log a LEAF delete (see the
         * format comment), so a record naming a key that still has subkeys is
         * corruption and must not be obeyed. */
        if (node == 0 || node == top || node->parent == 0 || node->subkeyCount != 0)
        {
            return FALSE;
        }
        PCMP_KEY_NODE parent = node->parent;
        /* Replay only ever runs over a subtree nobody has opened -- the boot
         * tree before the hive goes live, or an NtLoadKey destination created
         * moments ago. State the invariant rather than argue it. */
        ASSERT(node->bodyCount == 0);
        RemoveEntryList(&node->siblingEntry);
        parent->subkeyCount--;
        parent->lastWriteTime.QuadPart = (LONGLONG)record->lastWriteTime;
        CmpFreeValues(node);
        MiFreePool(node->name.Buffer);
        MiFreePool(node);
        return TRUE;
    }
    case CMP_OP_DELETE_VALUE:
    {
        PCMP_KEY_NODE node = CmpResolveRecordKey(top, &record->path, FALSE);
        UNICODE_STRING name;
        if (node == 0 || !CmpReadTailName(record, &name))
        {
            return FALSE;
        }
        node->lastWriteTime.QuadPart = (LONGLONG)record->lastWriteTime;
        /* A value the log deletes twice (a replay of a compacted prefix plus
         * its tail) is not an error: absence is the requested state. */
        (void)CmpRemoveValue(node, &name);
        return TRUE;
    }
    case CMP_OP_RENAME_KEY:
    {
        PCMP_KEY_NODE node = CmpResolveRecordKey(top, &record->path, FALSE);
        UNICODE_STRING newName;
        if (node == 0 || node == top || node->parent == 0 || !CmpReadTailName(record, &newName) ||
            newName.Length == 0)
        {
            return FALSE;
        }
        if (!CmpRenameNode(node, &newName))
        {
            return FALSE;
        }
        node->lastWriteTime.QuadPart = (LONGLONG)record->lastWriteTime;
        return TRUE;
    }
    default:
        /* An op this reader does not implement ends the log rather than
         * being skipped: a record whose meaning is unknown may be the one
         * that removes something, so continuing past it would replay a
         * WRONG tree rather than a short one. */
        return FALSE;
    }
}

/* Free every child subtree + all values of `node`, leaving the node itself.
 * Only ever run where no key BODIES exist below it — CmInitialize's failed
 * load, and a refused NtLoadKey whose destination was created empty moments
 * earlier. */
static void CmpFreeSubtreeContents(PCMP_KEY_NODE node)
{
    while (!IsListEmpty(&node->subkeyListHead))
    {
        PCMP_KEY_NODE child =
            CONTAINING_RECORD(node->subkeyListHead.Flink, CMP_KEY_NODE, siblingEntry);
        CmpFreeSubtreeContents(child);
        RemoveEntryList(&child->siblingEntry);
        node->subkeyCount--;
        ASSERT(child->bodyCount == 0);
        MiFreePool(child->name.Buffer);
        MiFreePool(child);
    }
    CmpFreeValues(node);
}

/* Replay a PHV2 image into `top`. The two callers want DIFFERENT things from
 * a malformed record and this is the only thing that separates them:
 *
 *   keepPrefix == FALSE (NtLoadKey): a ring-3 caller handed us a file and
 *     deserves a verdict on it, so anything malformed unwinds what was
 *     applied and answers STATUS_NOT_REGISTRY_FILE — what PHV1 did, and what
 *     the oracle does.
 *   keepPrefix == TRUE (the boot hive): the file is OUR append log, so a
 *     torn tail is an expected end rather than a corruption. Replay stops
 *     there and everything before it stands.
 *
 * One parser, one flag — not two parsers (Art. 11). */
static NTSTATUS CmpReplayImage(PCMP_KEY_NODE top, const UCHAR *buffer, ULONGLONG length,
                               BOOLEAN keepPrefix)
{
    if (length < CMP_HIVE_HEADER_BYTES || length > CMP_HIVE_MAX_BYTES ||
        KiReadLe32(buffer) != CMP_HIVE_MAGIC || KiReadLe32(buffer + 4) != CMP_HIVE_VERSION)
    {
        return STATUS_NOT_REGISTRY_FILE;
    }
    ULONG depth = CmpKeyDepth(top);
    if (depth == 0 || depth > CMP_HIVE_MAX_DEPTH)
    {
        return STATUS_NOT_REGISTRY_FILE;
    }
    CMP_HIVE_READER reader = {buffer, length, CMP_HIVE_HEADER_BYTES};
    CMP_RECORD record;
    ULONGLONG applied = 0;
    while (CmpReadRecord(&reader, &record))
    {
        if (!CmpApplyRecord(top, &record))
        {
            break;
        }
        applied++;
    }
    BOOLEAN complete = (reader.offset == reader.length) && applied != 0;
    if (!complete && !keepPrefix)
    {
        CmpFreeSubtreeContents(top);
        return STATUS_NOT_REGISTRY_FILE;
    }
    if (!complete)
    {
        DbgPrint("cm: hive log ends at %lu of %lu bytes - keeping the prefix\n",
                 (unsigned long)reader.offset, (unsigned long)reader.length);
    }
    return STATUS_SUCCESS;
}

/* The NtLoadKey/NtRestoreKey form: a verdict on a caller's file. */
NTSTATUS CmpParseSubtreeInto(PCMP_KEY_NODE top, const UCHAR *buffer, ULONGLONG length)
{
    return CmpReplayImage(top, buffer, length, FALSE);
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

    /* The same replay NtLoadKey uses (Art. 11); the root is its own top, so
     * the image's paths are the tree's paths. keepPrefix: this file is our
     * own log, so a torn tail ends it rather than voiding it. */
    if (!NT_SUCCESS(CmpReplayImage(CmpRootNode, buffer, length, TRUE)))
    {
        DbgPrint("cm: hive file invalid - starting an empty registry\n");
        CmpFreeSubtreeContents(CmpRootNode);
    }
    MiFreePool(buffer);
}

/* --- the append path --------------------------------------------------------
 *
 * A mutation writes ONE record at the end of the file instead of rewriting
 * the whole tree, which is the entire point of the format. The file is
 * opened and closed per append rather than held open for the boot: holding
 * it would collide with compaction's rename, which FAT32 refuses against a
 * file with an open handle (fs/fat32/file.c FatVfsRenameLocked).
 *
 * The log only ever GROWS between boots -- there is no runtime compaction --
 * so the cap below is a real ceiling rather than a sanity check, and it is
 * loud on the way to it (G12: never a silent drop). Once-per-boot compaction
 * is what keeps it out of reach in practice. */

#define CMP_HIVE_SOFT_WARN_BYTES (16u << 20)

static ULONGLONG CmpHiveLogBytes; /* the live file's size, tracked as we append */
static BOOLEAN CmpHiveLogWarned;  /* one soft-threshold line per boot */

static NTSTATUS CmpAppendToHiveFile(const UCHAR *buffer, ULONG bytes)
{
    HANDLE handle;
    NTSTATUS status =
        CmpOpenHiveFile(CMP_HIVE_PATH, FILE_GENERIC_WRITE, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    offset.QuadPart = -1; /* FILE_WRITE_TO_END_OF_FILE (kernel/io/rw.c) -- the file's
                           * length is the disk's business, never tracked in memory */
    status = NtWriteFile(handle, 0, 0, 0, &iosb, buffer, bytes, &offset, 0);
    NtClose(handle);
    return status;
}

/* Build one record and append it. `node` supplies the path unless
 * `capturedPath` is set (see CmpBeginRecord). `value` != 0 emits a
 * one-value SET_VALUES; `tailName` != 0 supplies the DELETE_VALUE /
 * RENAME_KEY tail; both null with op SET_VALUES is the "touch" form. */
static void CmpLogRecord(UCHAR op, UCHAR keyFlags, const CMP_KEY_NODE *node,
                         const UNICODE_STRING *capturedPath, LARGE_INTEGER stamp,
                         const CMP_VALUE *value, const UNICODE_STRING *tailName)
{
    if (!CmpHiveReady)
    {
        return; /* skeleton building during CmInitialize */
    }

    KeWaitForSingleObject(&CmpHiveMutex, Executive, KernelMode, FALSE, 0);

    ULONG valueCount = value != 0 ? 1 : 0;
    CMP_WRITER measure = {0, 0};
    ULONGLONG start =
        CmpBeginRecord(&measure, op, keyFlags, node, CmpRootNode, capturedPath, stamp, valueCount);
    if (value != 0)
    {
        CmpWriteValue(&measure, value);
    }
    else if (tailName != 0)
    {
        CmpWrite16(&measure, (USHORT)(tailName->Length / sizeof(WCHAR)));
        CmpWrite16(&measure, 0);
        CmpWriteBytes(&measure, tailName->Buffer, tailName->Length);
        CmpWritePad(&measure);
    }
    CmpEndRecord(&measure, start);
    ULONGLONG total = measure.offset;

    NTSTATUS status = STATUS_SUCCESS;
    if (CmpHiveLogBytes + total > CMP_HIVE_MAX_BYTES)
    {
        /* Nothing can shrink the log until the next boot compacts it, so this
         * is a real end rather than a retryable one -- and it names itself
         * every time rather than dropping a mutation quietly. */
        DbgPrint("cm: hive log is at its %lu MiB cap - this change will NOT survive reboot\n",
                 (unsigned long)(CMP_HIVE_MAX_BYTES >> 20));
        KeReleaseMutex(&CmpHiveMutex, FALSE);
        return;
    }

    UCHAR *buffer = MiAllocatePool(total);
    if (buffer == 0)
    {
        KeReleaseMutex(&CmpHiveMutex, FALSE);
        DbgPrint("cm: hive append skipped - out of pool\n");
        return;
    }
    CMP_WRITER emit = {buffer, 0};
    start = CmpBeginRecord(&emit, op, keyFlags, node, CmpRootNode, capturedPath, stamp, valueCount);
    if (value != 0)
    {
        CmpWriteValue(&emit, value);
    }
    else if (tailName != 0)
    {
        CmpWrite16(&emit, (USHORT)(tailName->Length / sizeof(WCHAR)));
        CmpWrite16(&emit, 0);
        CmpWriteBytes(&emit, tailName->Buffer, tailName->Length);
        CmpWritePad(&emit);
    }
    CmpEndRecord(&emit, start);
    ASSERT(emit.offset == total);

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;
    status = CmpAppendToHiveFile(buffer, (ULONG)total);
    thread->previousMode = saved;
    MiFreePool(buffer);

    if (NT_SUCCESS(status))
    {
        CmpHiveLogBytes += total;
        if (CmpHiveLogBytes > CMP_HIVE_SOFT_WARN_BYTES && !CmpHiveLogWarned)
        {
            CmpHiveLogWarned = TRUE;
            DbgPrint("cm: hive log past %lu MiB this boot (cap %lu MiB); it is compacted at "
                     "boot, so this means one boot is writing a great deal\n",
                     (unsigned long)(CMP_HIVE_SOFT_WARN_BYTES >> 20),
                     (unsigned long)(CMP_HIVE_MAX_BYTES >> 20));
        }
    }
    KeReleaseMutex(&CmpHiveMutex, FALSE);

    if (!NT_SUCCESS(status) && !CmpHiveWarned)
    {
        CmpHiveWarned = TRUE;
        DbgPrint("cm: hive append FAILED %08lx - registry changes will not survive reboot\n",
                 (unsigned long)status);
    }
}

/* The per-mutation entry points. Each is named for the syscall that calls it
 * so the call sites read as what they persist. */

void CmpLogCreateKey(const CMP_KEY_NODE *node)
{
    CmpLogRecord(CMP_OP_CREATE_KEY, node->isLink ? 1 : 0, node, 0, node->lastWriteTime, 0, 0);
}

void CmpLogSetValue(const CMP_KEY_NODE *node, const CMP_VALUE *value)
{
    CmpLogRecord(CMP_OP_SET_VALUES, 0, node, 0, node->lastWriteTime, value, 0);
}

void CmpLogTouchKey(const CMP_KEY_NODE *node)
{
    CmpLogRecord(CMP_OP_SET_VALUES, 0, node, 0, node->lastWriteTime, 0, 0);
}

void CmpLogDeleteValue(const CMP_KEY_NODE *node, const UNICODE_STRING *valueName)
{
    CmpLogRecord(CMP_OP_DELETE_VALUE, 0, node, 0, node->lastWriteTime, 0, valueName);
}

/* Delete and rename both need the path the key had BEFORE the tree moved, so
 * they take one the caller captured with CmpCaptureLogPath. */
void CmpLogDeleteKey(const UNICODE_STRING *capturedPath, LARGE_INTEGER stamp)
{
    CmpLogRecord(CMP_OP_DELETE_KEY, 0, 0, capturedPath, stamp, 0, 0);
}

void CmpLogRenameKey(const UNICODE_STRING *capturedPath, const UNICODE_STRING *newName,
                     LARGE_INTEGER stamp)
{
    CmpLogRecord(CMP_OP_RENAME_KEY, 0, 0, capturedPath, stamp, 0, newName);
}

/* Capture a node's log path into pool while the node is still where it is.
 * FALSE = out of pool, and the caller must then skip its log record rather
 * than log a wrong path. CmpReleaseLogPath frees it. */
BOOLEAN CmpCaptureLogPath(const CMP_KEY_NODE *node, UNICODE_STRING *out)
{
    ULONG bytes = CmpBuildPath(node, CmpRootNode, 0, 0);
    out->Buffer = 0;
    out->Length = 0;
    out->MaximumLength = 0;
    if (bytes == 0 || bytes > 0xFFFFu)
    {
        return FALSE;
    }
    PWSTR buffer = MiAllocatePool(bytes);
    if (buffer == 0)
    {
        return FALSE;
    }
    (void)CmpBuildPath(node, CmpRootNode, buffer, bytes / sizeof(WCHAR));
    out->Buffer = buffer;
    out->Length = (USHORT)bytes;
    out->MaximumLength = (USHORT)bytes;
    return TRUE;
}

void CmpReleaseLogPath(UNICODE_STRING *path)
{
    if (path->Buffer != 0)
    {
        MiFreePool(path->Buffer);
        path->Buffer = 0;
    }
    path->Length = 0;
    path->MaximumLength = 0;
}

static void CmpRewriteHiveLocked(void);

/* Rename the just-written temp file over the live hive, replacing it. This is
 * the commit point of a compaction. FAT32's rename refuses a destination with
 * an open handle (fs/fat32/file.c FatVfsRenameLocked), which is exactly why
 * the hive file is never held open across a boot. */
static NTSTATUS CmpRenameOverHive(HANDLE tempHandle)
{
    /* A union rather than a cast buffer: it gives the struct its natural
     * alignment without one, and the trailing room is the name. */
    union
    {
        FILE_RENAME_INFORMATION info;
        UCHAR raw[sizeof(FILE_RENAME_INFORMATION) + 64 * sizeof(WCHAR)];
    } storage;
    PFILE_RENAME_INFORMATION renameInfo = &storage.info;
    UNICODE_STRING target;
    RtlInitUnicodeString(&target, CMP_HIVE_PATH);
    ASSERT(target.Length <= 64 * sizeof(WCHAR));

    memset(&storage, 0, sizeof(storage));
    renameInfo->ReplaceIfExists = TRUE;
    /* RootDirectory == 0 means the name is a FULL NT path, not a leaf --
     * kernel/io/query.c IopSetRenameInformation answers
     * STATUS_OBJECT_PATH_SYNTAX_BAD for anything else. */
    renameInfo->RootDirectory = 0;
    renameInfo->FileNameLength = target.Length;
    memcpy(renameInfo->FileName, target.Buffer, target.Length);

    IO_STATUS_BLOCK iosb;
    return NtSetInformationFile(tempHandle, &iosb, renameInfo,
                                (ULONG)(sizeof(FILE_RENAME_INFORMATION) + target.Length),
                                FileRenameInformation);
}

/* Rewrite the whole log from a fresh snapshot: write a temp file, then rename
 * it over the live one.
 *
 * THE only whole-file writer, and it has three callers (Art. 11): the
 * once-per-boot compaction, NtUnloadKey on a non-volatile target and
 * NtRestoreKey -- the two syscalls that drop a whole subtree, which the log's
 * leaf-only DELETE_KEY cannot express.
 *
 * Crash story, which is strictly better than PHV1's: the temp file is written
 * and closed BEFORE the rename, so a crash during it leaves the live hive
 * completely untouched. The only exposed window is inside the rename itself,
 * between FAT deleting the old directory entry and writing the new one
 * (fs/fat32/dir.c FatRenameEntry) -- two directory-slot writes, during which
 * the data is intact under the temp name. PHV1's equivalent window was a
 * 237 KiB body write on EVERY mutation. */
void CmpRewriteHive(void)
{
    if (!CmpHiveReady)
    {
        return; /* skeleton building during CmInitialize */
    }
    CmpRewriteHiveLocked();
}

/* The body, callable from CmInitialize before CmpHiveReady is set (that is
 * what boot-time compaction is). */
static void CmpRewriteHiveLocked(void)
{
    KeWaitForSingleObject(&CmpHiveMutex, Executive, KernelMode, FALSE, 0);

    UCHAR *buffer = 0;
    ULONG total = 0;
    NTSTATUS status = CmpSerializeSubtree(CmpRootNode, &buffer, &total);
    if (!NT_SUCCESS(status))
    {
        KeReleaseMutex(&CmpHiveMutex, FALSE);
        DbgPrint("cm: hive rewrite skipped - out of pool\n");
        return;
    }

    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;

    HANDLE handle;
    status = CmpOpenHiveFile(CMP_HIVE_DIR, FILE_GENERIC_READ, FILE_OPEN_IF,
                             FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
        status = CmpOpenHiveFile(CMP_HIVE_TEMP_PATH, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                                 FILE_OVERWRITE_IF,
                                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, &handle);
    }
    if (NT_SUCCESS(status))
    {
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        status = NtWriteFile(handle, 0, 0, 0, &iosb, buffer, total, &offset, 0);
        if (NT_SUCCESS(status))
        {
            status = CmpRenameOverHive(handle);
        }
        NtClose(handle);
    }
    thread->previousMode = saved;
    MiFreePool(buffer);
    if (NT_SUCCESS(status))
    {
        CmpHiveLogBytes = total;
    }
    KeReleaseMutex(&CmpHiveMutex, FALSE);

    if (!NT_SUCCESS(status) && !CmpHiveWarned)
    {
        CmpHiveWarned = TRUE;
        DbgPrint("cm: hive rewrite FAILED %08lx - registry changes will not survive reboot\n",
                 (unsigned long)status);
    }
}

/* Compaction: run UNCONDITIONALLY ONCE PER BOOT, from CmInitialize after the
 * replay and after every seed, immediately before CmpSetHiveReady.
 *
 * Unconditional on purpose. A size threshold would need a policy nobody can
 * tune from first principles, and -- worse -- it would leave the rewrite path
 * running on almost no boot, which is how a rarely-taken path rots. Every
 * boot of every test leg exercises this one. It also means the seeded
 * furniture (the 139-zone time-zone table, the license values) lands in the
 * snapshot rather than being appended, and that one boot's log is all the
 * file ever accumulates. */
void CmpCompactHive(void)
{
    CmpRewriteHiveLocked();
}
