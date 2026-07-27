/* arch/x86_64/smbios.c — locate and bound the firmware's SMBIOS structure
 * table.
 *
 * An OS reads its own firmware tables; there is nothing host-derived here and
 * nothing to fabricate. Limine reports the entry point's PHYSICAL address
 * (PROTOCOL.md "SMBIOS Feature": physical for base revisions 3 and 4, and
 * kernel/init/main.c asks for base revision 3), which the HHDM reaches
 * because arch/x86_64/mmu.c maps every memmap region, reserved included.
 *
 * All field offsets below are DMTF DSP0134 (SMBIOS Reference Specification)
 * section 5.2 "Entry point"; re-verify against that document. Nothing here is
 * an NT contract — kernel/ps/query.c shapes the RSMB answer.
 */
#include "arch/x86_64/smbios.h"

#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"

/* DSP0134 5.2.1 (32-bit "_SM_") and 5.2.2 (64-bit "_SM3_") entry points. */
#define KI_SMBIOS32_LENGTH 0x1F
#define KI_SMBIOS64_LENGTH 0x18

/* DSP0134 6.1.2: type 127 is the end-of-table structure. */
#define KI_SMBIOS_TYPE_END_OF_TABLE 127

/* DSP0134 6.1.2: every structure's formatted area starts with the 4-byte
 * header (type, length, 2-byte handle), so a shorter length is malformed. */
#define KI_SMBIOS_HEADER_LENGTH 4

static KI_SMBIOS_TABLE KiSmbiosTable;
static BOOLEAN KiSmbiosPresent;

static BOOLEAN KiSmbiosAnchorMatches(const uint8_t *entry, const char *anchor, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++)
    {
        if (entry[i] != (uint8_t)anchor[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* DSP0134 5.2.1/5.2.2: the entry point's bytes sum to zero modulo 256. */
static BOOLEAN KiSmbiosChecksumOk(const uint8_t *entry, uint32_t length)
{
    uint8_t sum = 0;
    for (uint32_t i = 0; i < length; i++)
    {
        sum = (uint8_t)(sum + entry[i]);
    }
    return sum == 0;
}

static uint16_t KiSmbiosRead16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t KiSmbiosRead32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t KiSmbiosRead64(const uint8_t *p)
{
    return (uint64_t)KiSmbiosRead32(p) | ((uint64_t)KiSmbiosRead32(p + 4) << 32);
}

/* Walk the structure table to the end-of-table marker and return the byte
 * count up to and including it, or 0 if the table runs off `maxLength` or a
 * structure is malformed. The 64-bit entry point reports only a MAXIMUM size
 * (DSP0134 5.2.2), so the real length can only be found by walking; the
 * 32-bit one states the length outright and does not come through here.
 *
 * Each structure is a formatted area of hdr.length bytes followed by the
 * unformatted string-set, which ends at a double NUL (DSP0134 6.1.3) — that
 * holds for a structure with no strings too, which is written as two NULs. */
static uint32_t KiSmbiosMeasureTable(const uint8_t *table, uint32_t maxLength)
{
    uint32_t offset = 0;
    for (;;)
    {
        /* The length test comes first: maxLength - 4 would wrap below it. */
        if (maxLength < KI_SMBIOS_HEADER_LENGTH || offset > maxLength - KI_SMBIOS_HEADER_LENGTH)
        {
            return 0;
        }
        uint8_t type = table[offset];
        uint8_t formattedLength = table[offset + 1];
        if (formattedLength < KI_SMBIOS_HEADER_LENGTH)
        {
            return 0;
        }
        uint32_t cursor = offset + formattedLength;
        /* Scan for the double NUL that ends the string-set. Needs two bytes
         * in range, so stop one short of the end. */
        while (cursor + 1 < maxLength && !(table[cursor] == 0 && table[cursor + 1] == 0))
        {
            cursor++;
        }
        if (cursor + 1 >= maxLength)
        {
            return 0; /* unterminated: refuse the whole table rather than guess */
        }
        cursor += 2;
        if (type == KI_SMBIOS_TYPE_END_OF_TABLE)
        {
            return cursor;
        }
        offset = cursor;
    }
}

static BOOLEAN KiSmbiosParse64(const uint8_t *entry)
{
    if (!KiSmbiosAnchorMatches(entry, "_SM3_", 5))
    {
        return FALSE;
    }
    uint8_t length = entry[0x06];
    if (length < KI_SMBIOS64_LENGTH || !KiSmbiosChecksumOk(entry, length))
    {
        return FALSE;
    }
    uint32_t maxSize = KiSmbiosRead32(entry + 0x0C);
    uint64_t tablePhysical = KiSmbiosRead64(entry + 0x10);
    if (tablePhysical == 0 || maxSize == 0)
    {
        return FALSE;
    }
    const uint8_t *table = MiPhysicalToVirtual(tablePhysical);
    uint32_t measured = KiSmbiosMeasureTable(table, maxSize);
    if (measured == 0)
    {
        return FALSE;
    }
    KiSmbiosTable.tableData = table;
    KiSmbiosTable.tableLength = measured;
    KiSmbiosTable.majorVersion = entry[0x07];
    KiSmbiosTable.minorVersion = entry[0x08];
    KiSmbiosTable.docRevision = entry[0x09];
    return TRUE;
}

static BOOLEAN KiSmbiosParse32(const uint8_t *entry)
{
    if (!KiSmbiosAnchorMatches(entry, "_SM_", 4))
    {
        return FALSE;
    }
    uint8_t length = entry[0x05];
    if (length < KI_SMBIOS32_LENGTH || !KiSmbiosChecksumOk(entry, length))
    {
        return FALSE;
    }
    /* The intermediate "_DMI_" anchor guards the table pointer (5.2.1). */
    if (!KiSmbiosAnchorMatches(entry + 0x10, "_DMI_", 5))
    {
        return FALSE;
    }
    uint32_t tableLength = KiSmbiosRead16(entry + 0x16);
    uint32_t tablePhysical = KiSmbiosRead32(entry + 0x18);
    if (tablePhysical == 0 || tableLength == 0)
    {
        return FALSE;
    }
    KiSmbiosTable.tableData = MiPhysicalToVirtual(tablePhysical);
    KiSmbiosTable.tableLength = tableLength;
    KiSmbiosTable.majorVersion = entry[0x06];
    KiSmbiosTable.minorVersion = entry[0x07];
    KiSmbiosTable.docRevision = 0; /* 2.x has no DocRev field */
    return TRUE;
}

void KiSmbiosInitialize(uint64_t entryPoint32Physical, uint64_t entryPoint64Physical)
{
    /* Prefer the 64-bit entry point: when firmware publishes both, only it
     * can describe a table above 4 GiB (DSP0134 5.2.2). */
    if (entryPoint64Physical != 0 && KiSmbiosParse64(MiPhysicalToVirtual(entryPoint64Physical)))
    {
        KiSmbiosPresent = TRUE;
    }
    else if (entryPoint32Physical != 0 &&
             KiSmbiosParse32(MiPhysicalToVirtual(entryPoint32Physical)))
    {
        KiSmbiosPresent = TRUE;
    }

    if (KiSmbiosPresent)
    {
        DbgPrint("[KTEST] smbios %u.%u, %lu bytes\n", KiSmbiosTable.majorVersion,
                 KiSmbiosTable.minorVersion, (unsigned long)KiSmbiosTable.tableLength);
    }
    else
    {
        /* Not a failure: firmware need not publish SMBIOS. Callers refuse
         * rather than invent a table (Art. 12). */
        DbgPrint("[KTEST] smbios absent\n");
    }
}

const KI_SMBIOS_TABLE *KiSmbiosGetTable(void)
{
    return KiSmbiosPresent ? &KiSmbiosTable : 0;
}
