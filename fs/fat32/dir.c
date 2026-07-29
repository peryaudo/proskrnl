/* fs/fat32/dir.c — directory entries: 8.3 + long names, lookup, create,
 * delete, enumerate (see fat.h; spec sections cited inline are the
 * "Microsoft FAT Specification", Aug 30 2005).
 */
#include "fs/fat32/fat.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/le.h"
#include "kernel/lib/string.h"
#include "kernel/lib/rtl.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

#define FAT_DIR_ENTRY_SIZE      32
#define FAT_LFN_CHARS_PER_ENTRY 13   /* 5 + 6 + 2 (spec §7 name fields) */
#define FAT_LFN_LAST            0x40 /* LAST_LONG_ENTRY ordinal mask (spec §7) */
#define FAT_MAX_LFN_ENTRIES     20   /* ceil(255 / 13); 255-char limit spec §7 */

/* --- slot I/O -------------------------------------------------------------- */

static ULONG FatSlotsPerCluster(PFAT_VOLUME volume)
{
    ULONG slots = volume->sectorsPerCluster * volume->bytesPerSector / FAT_DIR_ENTRY_SIZE;
    ASSERT(slots != 0); /* BPB validated at mount */
    return slots;
}

static ULONG FatDirFirstCluster(PFAT_FCB dir)
{
    return dir->isRoot ? dir->volume->rootCluster : dir->firstCluster;
}

/* Locate slot -> (volume sector, byte offset); 0 when past the chain. */
static uint64_t FatSlotToSector(PFAT_FCB dir, ULONG slot, ULONG *byteOffset)
{
    PFAT_VOLUME volume = dir->volume;
    ULONG perCluster = FatSlotsPerCluster(volume);
    ULONG cluster = FatWalkChain(volume, FatDirFirstCluster(dir), slot / perCluster);
    if (cluster == 0)
    {
        return 0;
    }
    ULONG within = slot % perCluster;
    ULONG perSector = volume->bytesPerSector / FAT_DIR_ENTRY_SIZE;
    *byteOffset = (within % perSector) * FAT_DIR_ENTRY_SIZE;
    return FatClusterToSector(volume, cluster) + within / perSector;
}

NTSTATUS FatReadDirSlot(PFAT_FCB dir, ULONG slot, unsigned char entry[32])
{
    unsigned char sector[FAT_SECTOR_SIZE];
    ULONG offset;
    uint64_t lba = FatSlotToSector(dir, slot, &offset);
    if (lba == 0)
    {
        return STATUS_NO_MORE_FILES; /* past the directory's cluster chain */
    }
    NTSTATUS status = FatReadSector(dir->volume, lba, sector);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(entry, sector + offset, FAT_DIR_ENTRY_SIZE);
    return STATUS_SUCCESS;
}

NTSTATUS FatWriteDirSlot(PFAT_FCB dir, ULONG slot, const unsigned char entry[32])
{
    unsigned char sector[FAT_SECTOR_SIZE];
    ULONG offset;
    uint64_t lba = FatSlotToSector(dir, slot, &offset);
    if (lba == 0)
    {
        return STATUS_DISK_FULL;
    }
    NTSTATUS status = FatReadSector(dir->volume, lba, sector);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(sector + offset, entry, FAT_DIR_ENTRY_SIZE);
    return FatWriteSector(dir->volume, lba, sector);
}

/* --- names ----------------------------------------------------------------- */

static BOOLEAN FatNamesEqualInsensitive(const UNICODE_STRING *a, const WCHAR *b, USHORT bLength)
{
    if (a->Length != bLength)
    {
        return FALSE;
    }
    for (ULONG i = 0; i < a->Length / sizeof(WCHAR); i++)
    {
        if (RtlUpcaseUnicodeChar(a->Buffer[i]) != RtlUpcaseUnicodeChar(b[i]))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Render an 11-byte stored 8.3 name as "NAME.EXT" (spec §6.1: space-padded
 * halves, the dot never stored, 0x05 stands for a leading 0xE5). */
static USHORT FatRenderShortName(const unsigned char sfn[11], WCHAR out[13])
{
    USHORT n = 0;
    for (int i = 0; i < 8 && sfn[i] != ' '; i++)
    {
        unsigned char c = (i == 0 && sfn[0] == 0x05) ? 0xE5 : sfn[i];
        out[n++] = c;
    }
    if (sfn[8] != ' ')
    {
        out[n++] = '.';
        for (int i = 8; i < 11 && sfn[i] != ' '; i++)
        {
            out[n++] = sfn[i];
        }
    }
    return (USHORT)(n * sizeof(WCHAR));
}

/* The 8.3 checksum every LFN entry carries (spec §7.2, verbatim rotate). */
static UCHAR FatShortNameChecksum(const unsigned char sfn[11])
{
    UCHAR sum = 0;
    for (int i = 0; i < 11; i++)
    {
        sum = (UCHAR)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + sfn[i]);
    }
    return sum;
}

/* Extract this LFN entry's 13 UTF-16 units (spec §7: 5 at offset 1, 6 at
 * offset 14, 2 at offset 28). */
static void FatLfnEntryChars(const unsigned char entry[32], WCHAR out[13])
{
    for (size_t i = 0; i < 5; i++)
    {
        out[i] = KiReadLe16(entry + 1 + i * 2);
    }
    for (size_t i = 0; i < 6; i++)
    {
        out[5 + i] = KiReadLe16(entry + 14 + i * 2);
    }
    for (size_t i = 0; i < 2; i++)
    {
        out[11 + i] = KiReadLe16(entry + 28 + i * 2);
    }
}

/* --- the directory walk ---------------------------------------------------- */

/* One assembled logical entry. */
typedef struct
{
    unsigned char sfn[32];
    ULONG sfnSlot;
    ULONG lfnStartSlot;
    WCHAR name[256];
    USHORT nameLength; /* bytes; falls back to the rendered 8.3 name */
} FAT_WALK_ENTRY;

/* Read the next logical entry at/after *slot; advances *slot past it.
 * Returns STATUS_NO_MORE_FILES at the 0x00 terminator or the chain end. */
static NTSTATUS FatWalkNext(PFAT_FCB dir, ULONG *slot, FAT_WALK_ENTRY *out)
{
    WCHAR lfn[FAT_MAX_LFN_ENTRIES * FAT_LFN_CHARS_PER_ENTRY];
    int lfnTop = -1; /* highest ordinal seen; -1 = no LFN run pending */
    UCHAR lfnChecksum = 0;
    ULONG runStart = 0;

    for (;;)
    {
        unsigned char entry[32];
        NTSTATUS status = FatReadDirSlot(dir, *slot, entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            return STATUS_NO_MORE_FILES;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (entry[0] == 0x00)
        {
            return STATUS_NO_MORE_FILES; /* terminator: all following free (spec §6.1) */
        }
        if (entry[0] == 0xE5)
        {
            (*slot)++;
            lfnTop = -1;
            continue;
        }
        if ((entry[11] & FAT_ATTR_LONG_NAME_MASK) == FAT_ATTR_LONG_NAME)
        {
            /* A long-name entry (spec §7): ordinal at 0, LAST flag on the
             * first-on-disk (highest) member. */
            int ordinal = entry[0] & 0x3F;
            if (ordinal == 0 || ordinal > FAT_MAX_LFN_ENTRIES)
            {
                (*slot)++;
                lfnTop = -1;
                continue;
            }
            if (entry[0] & FAT_LFN_LAST)
            {
                lfnTop = ordinal;
                lfnChecksum = entry[13];
                runStart = *slot;
                memset(lfn, 0, sizeof(lfn));
            }
            else if (lfnTop < 0 || entry[13] != lfnChecksum)
            {
                lfnTop = -1; /* orphan (spec §7.1) */
            }
            if (lfnTop > 0)
            {
                FatLfnEntryChars(entry, lfn + (size_t)(ordinal - 1) * FAT_LFN_CHARS_PER_ENTRY);
            }
            (*slot)++;
            continue;
        }
        if (entry[11] & FAT_ATTR_VOLUME_ID)
        {
            (*slot)++;
            lfnTop = -1;
            continue; /* the volume label (spec §6.2) */
        }

        /* A short entry: emit, with the LFN run if it checksums. */
        memcpy(out->sfn, entry, 32);
        out->sfnSlot = *slot;
        out->lfnStartSlot = *slot;
        out->nameLength = 0;
        if (lfnTop > 0 && FatShortNameChecksum(entry) == lfnChecksum)
        {
            USHORT units = 0;
            USHORT max = (USHORT)(lfnTop * FAT_LFN_CHARS_PER_ENTRY);
            while (units < max && lfn[units] != 0x0000 && lfn[units] != 0xFFFF)
            {
                units++;
            }
            if (units > 0 && units <= 255)
            {
                memcpy(out->name, lfn, units * sizeof(WCHAR));
                out->nameLength = (USHORT)(units * sizeof(WCHAR));
                out->lfnStartSlot = runStart;
            }
        }
        if (out->nameLength == 0)
        {
            out->nameLength = FatRenderShortName(entry, out->name);
        }
        (*slot)++;
        return STATUS_SUCCESS;
    }
}

/* --- lookup ---------------------------------------------------------------- */

NTSTATUS FatLookup(PFAT_FCB dir, const UNICODE_STRING *component, PFAT_FCB *fcbOut)
{
    ASSERT(dir->isDirectory);
    ULONG slot = 0;
    FAT_WALK_ENTRY entry;
    for (;;)
    {
        NTSTATUS status = FatWalkNext(dir, &slot, &entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* Skip "." and ".." — they resolve via the namespace, not here. */
        if (entry.sfn[0] == '.')
        {
            continue;
        }
        WCHAR shortName[13];
        USHORT shortLength = FatRenderShortName(entry.sfn, shortName);
        UNICODE_STRING longName;
        longName.Buffer = entry.name;
        longName.Length = entry.nameLength;
        longName.MaximumLength = entry.nameLength;
        if (FatNamesEqualInsensitive(component, entry.name, entry.nameLength) ||
            FatNamesEqualInsensitive(component, shortName, shortLength))
        {
            return FatGetFcb(dir, entry.sfnSlot, entry.lfnStartSlot, entry.sfn, &longName, fcbOut);
        }
    }
}

/* --- creation -------------------------------------------------------------- */

/* Grow the directory by one zeroed cluster (spec §6.5: new directory
 * clusters are zero-filled, which also plants the 0x00 terminator). */
static NTSTATUS FatExtendDirectory(PFAT_FCB dir)
{
    PFAT_VOLUME volume = dir->volume;
    ULONG first = FatDirFirstCluster(dir);
    ULONG last = FatWalkChain(volume, first, FatChainLength(volume, first) - 1);
    ULONG fresh;
    NTSTATUS status = FatAllocateCluster(volume, last, &fresh);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    unsigned char zero[FAT_SECTOR_SIZE];
    memset(zero, 0, sizeof(zero));
    for (ULONG i = 0; i < volume->sectorsPerCluster; i++)
    {
        status = FatWriteSector(volume, FatClusterToSector(volume, fresh) + i, zero);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

/* Can `name` be stored as a bare 8.3 entry with no LFN? Only if it is
 * ASCII, upper-case-only where letters occur, one optional dot, and fits
 * 8+3 with legal characters (spec §6.1) — i.e. rendering the stored form
 * reproduces the name byte-for-byte, so no case is lost. */
static BOOLEAN FatBuildExact83(const UNICODE_STRING *name, unsigned char sfn[11])
{
    memset(sfn, ' ', 11);
    ULONG units = name->Length / sizeof(WCHAR);
    int dot = -1;
    for (ULONG i = 0; i < units; i++)
    {
        if (name->Buffer[i] == '.')
        {
            if (dot >= 0)
            {
                return FALSE;
            }
            dot = (int)i;
        }
    }
    ULONG baseLength = dot >= 0 ? (ULONG)dot : units;
    ULONG extLength = dot >= 0 ? units - dot - 1 : 0;
    if (baseLength == 0 || baseLength > 8 || extLength > 3 || (dot >= 0 && extLength == 0))
    {
        return FALSE;
    }
    for (ULONG i = 0; i < units; i++)
    {
        WCHAR c = name->Buffer[i];
        if (c == '.')
        {
            continue;
        }
        if (c > 0x7E || c < 0x20)
        {
            return FALSE;
        }
        if (c >= 'a' && c <= 'z')
        {
            return FALSE; /* stored upper-case; keep the case via an LFN */
        }
        /* Illegal 8.3 bytes (spec §6.1). */
        static const char illegal[] = "\"*+,./:;<=>?[\\]|";
        for (const char *x = illegal; *x != '\0'; x++)
        {
            if (c == (WCHAR)*x)
            {
                return FALSE;
            }
        }
        if (c == ' ')
        {
            return FALSE; /* embedded spaces need an LFN */
        }
        ULONG position = i < baseLength ? i : 8 + (i - baseLength - 1);
        sfn[position] = (unsigned char)c;
    }
    return TRUE;
}

/* Is this 11-byte short name already taken in `dir`? */
static NTSTATUS FatShortNameExists(PFAT_FCB dir, const unsigned char sfn[11], BOOLEAN *exists)
{
    ULONG slot = 0;
    FAT_WALK_ENTRY entry;
    *exists = FALSE;
    for (;;)
    {
        NTSTATUS status = FatWalkNext(dir, &slot, &entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            return STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (memcmp(entry.sfn, sfn, 11) == 0)
        {
            *exists = TRUE;
            return STATUS_SUCCESS;
        }
    }
}

/* Generate a unique numeric-tail short name ("BASENA~1EXT") for a long
 * name (the classic Windows scheme; any unique legal 8.3 name is valid
 * per spec §7.4 — the exact mangling is not contractual). */
static NTSTATUS FatGenerateShortName(PFAT_FCB dir, const UNICODE_STRING *name,
                                     unsigned char sfn[11])
{
    unsigned char base[8];
    unsigned char ext[3];
    ULONG baseLength = 0, extLength = 0;
    ULONG units = name->Length / sizeof(WCHAR);

    int lastDot = -1;
    for (ULONG i = 0; i < units; i++)
    {
        if (name->Buffer[i] == '.')
        {
            lastDot = (int)i;
        }
    }
    for (ULONG i = 0; i < units && baseLength < 8; i++)
    {
        if (lastDot >= 0 && i >= (ULONG)lastDot)
        {
            break;
        }
        WCHAR c = RtlUpcaseUnicodeChar(name->Buffer[i]);
        if (c <= 0x20 || c > 0x7E || c == '.')
        {
            continue;
        }
        static const char illegal[] = "\"*+,/:;<=>?[\\]|";
        BOOLEAN bad = FALSE;
        for (const char *x = illegal; *x != '\0'; x++)
        {
            if (c == (WCHAR)*x)
            {
                bad = TRUE;
            }
        }
        base[baseLength++] = bad ? '_' : (unsigned char)c;
    }
    if (baseLength == 0)
    {
        base[baseLength++] = '_';
    }
    if (lastDot >= 0)
    {
        for (ULONG i = (ULONG)lastDot + 1; i < units && extLength < 3; i++)
        {
            WCHAR c = RtlUpcaseUnicodeChar(name->Buffer[i]);
            if (c > 0x20 && c <= 0x7E && c != '.')
            {
                ext[extLength++] = (unsigned char)c;
            }
        }
    }

    for (ULONG tail = 1; tail < 1000000; tail++)
    {
        /* "BASE~N": the numeric tail replaces the end of the base. */
        char digits[8];
        int digitCount = 0;
        for (ULONG value = tail; value != 0; value /= 10)
        {
            digits[digitCount++] = (char)('0' + value % 10);
        }
        ULONG keep = baseLength;
        if (keep > 8 - 1 - (ULONG)digitCount)
        {
            keep = 8 - 1 - (ULONG)digitCount;
        }
        memset(sfn, ' ', 11);
        memcpy(sfn, base, keep);
        sfn[keep] = '~';
        for (int i = 0; i < digitCount; i++)
        {
            sfn[keep + 1 + (ULONG)i] = (unsigned char)digits[digitCount - 1 - i];
        }
        memcpy(sfn + 8, ext, extLength);

        BOOLEAN exists;
        NTSTATUS status = FatShortNameExists(dir, sfn, &exists);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (!exists)
        {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_DISK_FULL;
}

/* Find `count` contiguous free slots; extends the directory as needed. */
static NTSTATUS FatFindFreeSlots(PFAT_FCB dir, ULONG count, ULONG *firstOut)
{
    /* Up to 3 extensions: a worst-case 21-slot run (20 LFN + SFN, 255-char
     * name) can span multiple 512-byte clusters. */
    for (int attempt = 0; attempt < 4; attempt++)
    {
        ULONG runStart = 0, runLength = 0, slot = 0;
        for (;;)
        {
            unsigned char entry[32];
            NTSTATUS status = FatReadDirSlot(dir, slot, entry);
            if (status == STATUS_NO_MORE_FILES)
            {
                break; /* chain exhausted */
            }
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            if (entry[0] == 0x00 || entry[0] == 0xE5)
            {
                if (runLength == 0)
                {
                    runStart = slot;
                }
                runLength++;
                if (runLength == count)
                {
                    *firstOut = runStart;
                    return STATUS_SUCCESS;
                }
            }
            else
            {
                runLength = 0;
            }
            slot++;
        }
        NTSTATUS status = FatExtendDirectory(dir);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    return STATUS_DISK_FULL;
}

NTSTATUS FatWriteEntrySlots(PFAT_FCB dir, const UNICODE_STRING *component,
                            unsigned char shortEntry[32], ULONG *sfnSlotOut, ULONG *lfnStartOut)
{
    ASSERT(dir->isDirectory);
    ULONG units = component->Length / sizeof(WCHAR);
    if (units == 0 || units > 255)
    {
        return STATUS_OBJECT_NAME_INVALID;
    }

    unsigned char sfn[11];
    BOOLEAN needLfn = !FatBuildExact83(component, sfn);
    if (needLfn)
    {
        NTSTATUS status = FatGenerateShortName(dir, component, sfn);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    memcpy(shortEntry, sfn, 11);

    ULONG lfnEntries =
        needLfn ? (units + FAT_LFN_CHARS_PER_ENTRY - 1) / FAT_LFN_CHARS_PER_ENTRY : 0;
    ULONG firstSlot;
    NTSTATUS status = FatFindFreeSlots(dir, lfnEntries + 1, &firstSlot);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* LFN run: last (highest-ordinal) entry first on disk (spec §7),
     * NUL-terminated then 0xFFFF-padded (spec §7.3). */
    if (needLfn)
    {
        UCHAR checksum = FatShortNameChecksum(sfn);
        for (ULONG ordinal = lfnEntries; ordinal >= 1; ordinal--)
        {
            unsigned char lfnEntry[32];
            memset(lfnEntry, 0, sizeof(lfnEntry));
            lfnEntry[0] = (unsigned char)(ordinal | (ordinal == lfnEntries ? FAT_LFN_LAST : 0));
            lfnEntry[11] = FAT_ATTR_LONG_NAME;
            lfnEntry[12] = 0; /* LDIR_Type */
            lfnEntry[13] = checksum;
            KiWriteLe16(lfnEntry + 26, 0); /* LDIR_FstClusLO */
            for (ULONG i = 0; i < FAT_LFN_CHARS_PER_ENTRY; i++)
            {
                ULONG nameIndex = (ordinal - 1) * FAT_LFN_CHARS_PER_ENTRY + i;
                uint16_t unit;
                if (nameIndex < units)
                {
                    unit = component->Buffer[nameIndex];
                }
                else if (nameIndex == units)
                {
                    unit = 0x0000;
                }
                else
                {
                    unit = 0xFFFF;
                }
                ULONG offset = i < 5 ? 1 + i * 2 : (i < 11 ? 14 + (i - 5) * 2 : 28 + (i - 11) * 2);
                KiWriteLe16(lfnEntry + offset, unit);
            }
            status = FatWriteDirSlot(dir, firstSlot + (lfnEntries - ordinal), lfnEntry);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }
    }
    status = FatWriteDirSlot(dir, firstSlot + lfnEntries, shortEntry);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *sfnSlotOut = firstSlot + lfnEntries;
    *lfnStartOut = firstSlot;
    return STATUS_SUCCESS;
}

NTSTATUS FatCreateEntry(PFAT_FCB dir, const UNICODE_STRING *component, BOOLEAN directory,
                        UCHAR attributes, PFAT_FCB *fcbOut)
{
    ASSERT(dir->isDirectory);

    /* A directory gets one zeroed cluster with "." / ".." (spec §6.5). */
    ULONG firstCluster = 0;
    NTSTATUS status;
    if (directory)
    {
        status = FatAllocateCluster(dir->volume, 0, &firstCluster);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        unsigned char zero[FAT_SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));
        for (ULONG i = 0; i < dir->volume->sectorsPerCluster; i++)
        {
            status = FatWriteSector(dir->volume, FatClusterToSector(dir->volume, firstCluster) + i,
                                    zero);
            if (!NT_SUCCESS(status))
            {
                FatFreeChain(dir->volume, firstCluster);
                return status;
            }
        }
    }

    LARGE_INTEGER now = FatCurrentNtTime();
    USHORT date, time;
    FatNtTimeToFatTime(now, &date, &time);

    /* The short entry (spec §6 field layout); the name bytes are filled by
     * the slot writer. */
    unsigned char shortEntry[32];
    memset(shortEntry, 0, sizeof(shortEntry));
    shortEntry[11] = (unsigned char)(attributes | (directory ? FAT_ATTR_DIRECTORY : 0));
    shortEntry[13] = 0;                 /* DIR_CrtTimeTenth */
    KiWriteLe16(shortEntry + 14, time); /* DIR_CrtTime */
    KiWriteLe16(shortEntry + 16, date); /* DIR_CrtDate */
    KiWriteLe16(shortEntry + 18, date); /* DIR_LstAccDate */
    KiWriteLe16(shortEntry + 20, (uint16_t)(firstCluster >> 16));
    KiWriteLe16(shortEntry + 22, time); /* DIR_WrtTime */
    KiWriteLe16(shortEntry + 24, date); /* DIR_WrtDate */
    KiWriteLe16(shortEntry + 26, (uint16_t)firstCluster);
    KiWriteLe32(shortEntry + 28, 0); /* DIR_FileSize */

    ULONG sfnSlot, lfnStart;
    status = FatWriteEntrySlots(dir, component, shortEntry, &sfnSlot, &lfnStart);
    if (!NT_SUCCESS(status))
    {
        if (firstCluster != 0)
        {
            FatFreeChain(dir->volume, firstCluster);
        }
        return status;
    }
    if (directory)
    {
        /* "." and ".." (spec §6.5: first cluster of ".." is 0 when the
         * parent is the root). */
        unsigned char dot[32];
        memcpy(dot, shortEntry, 32);
        memset(dot, ' ', 11);
        dot[0] = '.';
        KiWriteLe32(dot + 28, 0);
        /* Write via raw sectors: slot 0 = ".", slot 1 = "..". */
        unsigned char sector[FAT_SECTOR_SIZE];
        NTSTATUS s2 =
            FatReadSector(dir->volume, FatClusterToSector(dir->volume, firstCluster), sector);
        if (NT_SUCCESS(s2))
        {
            memcpy(sector, dot, 32);
            unsigned char dotdot[32];
            memcpy(dotdot, dot, 32);
            dotdot[1] = '.';
            ULONG parentCluster = dir->isRoot ? 0 : FatDirFirstCluster(dir);
            KiWriteLe16(dotdot + 20, (uint16_t)(parentCluster >> 16));
            KiWriteLe16(dotdot + 26, (uint16_t)parentCluster);
            memcpy(sector + 32, dotdot, 32);
            s2 = FatWriteSector(dir->volume, FatClusterToSector(dir->volume, firstCluster), sector);
        }
        if (!NT_SUCCESS(s2))
        {
            return s2;
        }
    }

    UNICODE_STRING longName = *component;
    return FatGetFcb(dir, sfnSlot, lfnStart, shortEntry, &longName, fcbOut);
}

/* --- deletion, metadata ----------------------------------------------------- */

NTSTATUS FatFreeEntrySlots(PFAT_FCB dir, ULONG lfnStart, ULONG sfnSlot)
{
    for (ULONG slot = lfnStart; slot <= sfnSlot; slot++)
    {
        unsigned char entry[32];
        NTSTATUS status = FatReadDirSlot(dir, slot, entry);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        entry[0] = 0xE5; /* free marker (spec §6.1) */
        status = FatWriteDirSlot(dir, slot, entry);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS FatDeleteEntry(PFAT_FCB fcb)
{
    ASSERT(!fcb->isRoot);
    NTSTATUS status = FatFreeEntrySlots(fcb->parent, fcb->lfnStartIndex, fcb->dirEntryIndex);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (fcb->firstCluster != 0)
    {
        FatFreeChain(fcb->volume, fcb->firstCluster);
        fcb->firstCluster = 0;
    }
    fcb->fileSize = 0;
    return STATUS_SUCCESS;
}

NTSTATUS FatRenameEntry(PFAT_FCB fcb, PFAT_FCB newParent, const UNICODE_STRING *newName)
{
    ASSERT(!fcb->isRoot);
    ASSERT(newParent->isDirectory);

    /* The moved short entry: current metadata, exactly the fields
     * FatFlushFcbMetadata persists; the slot writer fills the name bytes. */
    unsigned char shortEntry[32];
    memset(shortEntry, 0, sizeof(shortEntry));
    shortEntry[11] = fcb->attributes;
    shortEntry[13] = fcb->createTimeTenth;
    KiWriteLe16(shortEntry + 14, fcb->createTime);
    KiWriteLe16(shortEntry + 16, fcb->createDate);
    KiWriteLe16(shortEntry + 18, fcb->accessDate);
    KiWriteLe16(shortEntry + 20, (uint16_t)(fcb->firstCluster >> 16));
    KiWriteLe16(shortEntry + 22, fcb->writeTime);
    KiWriteLe16(shortEntry + 24, fcb->writeDate);
    KiWriteLe16(shortEntry + 26, (uint16_t)fcb->firstCluster);
    KiWriteLe32(shortEntry + 28, (uint32_t)fcb->fileSize);

    PWSTR nameCopy = MiAllocatePool(newName->Length);
    if (nameCopy == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(nameCopy, newName->Buffer, newName->Length);

    /* New slots before the old run is freed: a failure part-way leaves the
     * file reachable under at least one of its names (write-through, no
     * journal — the crash window is a docs/03 "CUI-5 notes" deviation). */
    ULONG sfnSlot, lfnStart;
    NTSTATUS status = FatWriteEntrySlots(newParent, newName, shortEntry, &sfnSlot, &lfnStart);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(nameCopy);
        return status;
    }
    status = FatFreeEntrySlots(fcb->parent, fcb->lfnStartIndex, fcb->dirEntryIndex);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(nameCopy);
        return status;
    }
    if (fcb->isDirectory && newParent != fcb->parent)
    {
        status = FatRewriteDotDot(fcb, newParent);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(nameCopy);
            return status;
        }
    }

    /* Rewrite the live FCB's identity in place: the (directory cluster,
     * SFN slot) key — which is also the NT FileId (fat.h FatFileId) — moves
     * with the entry, keeping FatGetFcb's dedup coherent. The parent pin
     * swaps before the old pin drops (the old parent may only die after it
     * has no children). */
    if (newParent != fcb->parent)
    {
        PFAT_FCB oldParent = fcb->parent;
        FatReferenceFcb(newParent);
        fcb->parent = newParent;
        FatDereferenceFcb(oldParent);
    }
    fcb->parentDirCluster = FatDirCluster(newParent);
    fcb->dirEntryIndex = sfnSlot;
    fcb->lfnStartIndex = lfnStart;
    MiFreePool(fcb->longName.Buffer);
    fcb->longName.Buffer = nameCopy;
    fcb->longName.Length = newName->Length;
    fcb->longName.MaximumLength = newName->Length;
    return STATUS_SUCCESS;
}

NTSTATUS FatRewriteDotDot(PFAT_FCB dir, PFAT_FCB newParent)
{
    /* A moved directory's ".." entry names its new parent (spec §6.5: the
     * stored cluster is 0 when the parent is the root). ".." is always slot
     * 1 of the directory's first sector (spec §6.5: "." then ".."). */
    ASSERT(dir->isDirectory && !dir->isRoot);
    PFAT_VOLUME volume = dir->volume;
    uint64_t firstSector = FatClusterToSector(volume, dir->firstCluster);
    unsigned char sector[FAT_SECTOR_SIZE];
    NTSTATUS status = FatReadSector(volume, firstSector, sector);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    unsigned char *dotdot = sector + 32;
    if (dotdot[0] != '.' || dotdot[1] != '.')
    {
        return STATUS_DISK_CORRUPT_ERROR;
    }
    ULONG parentCluster = newParent->isRoot ? 0 : FatDirFirstCluster(newParent);
    KiWriteLe16(dotdot + 20, (uint16_t)(parentCluster >> 16));
    KiWriteLe16(dotdot + 26, (uint16_t)parentCluster);
    return FatWriteSector(volume, firstSector, sector);
}

NTSTATUS FatIsDirectoryEmpty(PFAT_FCB dir, BOOLEAN *empty)
{
    ULONG slot = 0;
    FAT_WALK_ENTRY entry;
    *empty = TRUE;
    for (;;)
    {
        NTSTATUS status = FatWalkNext(dir, &slot, &entry);
        if (status == STATUS_NO_MORE_FILES)
        {
            return STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (entry.sfn[0] == '.')
        {
            continue; /* "." / ".." */
        }
        *empty = FALSE;
        return STATUS_SUCCESS;
    }
}

NTSTATUS FatReadDirectoryEntry(PFAT_FCB dir, ULONG *slot, IO_DIR_ENTRY *out)
{
    FAT_WALK_ENTRY entry;
    NTSTATUS status = FatWalkNext(dir, slot, &entry);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(out->name, entry.name, entry.nameLength);
    out->nameLength = entry.nameLength;
    out->info.creationTime =
        FatTimeToNtTime(KiReadLe16(entry.sfn + 16), KiReadLe16(entry.sfn + 14), entry.sfn[13]);
    out->info.lastAccessTime = FatTimeToNtTime(KiReadLe16(entry.sfn + 18), 0, 0);
    out->info.lastWriteTime =
        FatTimeToNtTime(KiReadLe16(entry.sfn + 24), KiReadLe16(entry.sfn + 22), 0);
    out->info.isDirectory = (entry.sfn[11] & FAT_ATTR_DIRECTORY) != 0;
    /* The listed entry's own identity key. Caveat for a future FileId*
     * directory class: "." and ".." resolve here to their slot in THIS
     * directory, not to the directory they name. */
    out->info.fileId = FatFileId(FatDirCluster(dir), entry.sfnSlot);
    out->info.endOfFile = KiReadLe16(entry.sfn + 28) | ((uint64_t)KiReadLe16(entry.sfn + 30) << 16);
    PFAT_VOLUME volume = dir->volume;
    uint64_t clusterBytes = (uint64_t)volume->sectorsPerCluster * volume->bytesPerSector;
    out->info.allocationSize =
        (out->info.endOfFile + clusterBytes - 1) / clusterBytes * clusterBytes;
    ULONG attributes = 0;
    if (entry.sfn[11] & FAT_ATTR_READ_ONLY)
    {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    if (entry.sfn[11] & FAT_ATTR_HIDDEN)
    {
        attributes |= FILE_ATTRIBUTE_HIDDEN;
    }
    if (entry.sfn[11] & FAT_ATTR_SYSTEM)
    {
        attributes |= FILE_ATTRIBUTE_SYSTEM;
    }
    if (entry.sfn[11] & FAT_ATTR_DIRECTORY)
    {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    if (entry.sfn[11] & FAT_ATTR_ARCHIVE)
    {
        attributes |= FILE_ATTRIBUTE_ARCHIVE;
    }
    out->info.fileAttributes = attributes != 0 ? attributes : FILE_ATTRIBUTE_NORMAL;
    return STATUS_SUCCESS;
}

NTSTATUS FatFlushFcbMetadata(PFAT_FCB fcb)
{
    if (fcb->isRoot)
    {
        return STATUS_SUCCESS; /* the root has no entry (spec §6.6) */
    }
    unsigned char entry[32];
    NTSTATUS status = FatReadDirSlot(fcb->parent, fcb->dirEntryIndex, entry);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    entry[11] = fcb->attributes;
    entry[13] = fcb->createTimeTenth;
    KiWriteLe16(entry + 14, fcb->createTime);
    KiWriteLe16(entry + 16, fcb->createDate);
    KiWriteLe16(entry + 18, fcb->accessDate);
    KiWriteLe16(entry + 20, (uint16_t)(fcb->firstCluster >> 16));
    KiWriteLe16(entry + 22, fcb->writeTime);
    KiWriteLe16(entry + 24, fcb->writeDate);
    KiWriteLe16(entry + 26, (uint16_t)fcb->firstCluster);
    KiWriteLe32(entry + 28, (uint32_t)fcb->fileSize);
    return FatWriteDirSlot(fcb->parent, fcb->dirEntryIndex, entry);
}
