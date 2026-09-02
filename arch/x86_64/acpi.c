/* arch/x86_64/acpi.c — locate, validate and bound the firmware's ACPI tables.
 *
 * An OS reads its own firmware tables; there is nothing host-derived here and
 * nothing to fabricate. Limine reports the RSDP's PHYSICAL address
 * (PROTOCOL.md "RSDP Feature": physical for base revision 3 only, and
 * kernel/init/main.c asks for base revision 3), which the HHDM reaches
 * because arch/x86_64/mmu.c maps every memmap region, reserved and ACPI
 * (reclaimable / NVS) included. Every table this walks is reached the same
 * way, so nothing here maps anything.
 *
 * What is read, and what is deliberately not: the RSDP and its root table,
 * the FADT's fixed-hardware facts (the PM1 control blocks, the SMI command
 * port, the SCI vector, the flags), ONE object out of the DSDT (the \_S5
 * sleep package, by a bounded byte scan of the AML — there is no AML
 * interpreter, and a firmware that defines \_S5 as a Method rather than a
 * Name of constants is reported "no S5" rather than half-evaluated), and the
 * MADT's local-APIC address and interrupt-controller census. SSDTs, the PM
 * timer, GPEs, the reset register, hardware-reduced platforms: unbuilt, each
 * a named exit (docs/02 "ACPI"). Any validation failure leaves the fact
 * absent and says so on serial (Art. 12) — a caller refuses rather than
 * inventing a table.
 *
 * All offsets and values are the ACPI Specification 6.5 (UEFI Forum), cited
 * per constant; re-verify against that document. The pinned QEMU tree, whose
 * hw/i386/acpi-build.c + hw/acpi/aml-build.c generate the tables the tests
 * boot against, is named as the runtime cross-check where it pins a value
 * (tests/kmt/acpi.c pins those). Nothing here is an NT contract. */
#include "arch/x86_64/acpi.h"

#include "kernel/mm/phys.h"
#include "kernel/lib/dbgprint.h"

/* DESCRIPTION_HEADER (ACPI 6.5 §5.2.6 Table 5.4): Signature @0 (4), Length
 * @4 (4), Revision @8 (1), Checksum @9 (1, the entire table sums to zero);
 * 36 bytes in all. Every system description table starts with it. */
#define KI_ACPI_HEADER_LENGTH       36
#define KI_ACPI_HEADER_OFF_LENGTH   4
#define KI_ACPI_HEADER_OFF_REVISION 8

/* A table's Length is firmware data and is taken on trust nowhere: cap it at
 * something no real table approaches before walking it (the lesson of
 * arch/x86_64/smbios.c KiSmbiosMeasureTable — a firmware-supplied bound once
 * sent a walk over four gigabytes of the HHDM). DSDTs run to a few hundred
 * KiB on the largest boards; 1 MiB is generous. */
#define KI_ACPI_MAX_TABLE_LENGTH 0x100000u

/* RSDP (ACPI 6.5 §5.2.5.3 Table 5.3): Signature "RSD PTR " @0 (8), Checksum
 * @8 over bytes 0..19, Revision @15 (0 = ACPI 1.0, 2 = ACPI 2.0+),
 * RsdtAddress @16 (4); ACPI 2.0+ adds Length @20 (4, = 36), XsdtAddress @24
 * (8) and an Extended Checksum @32 over the whole Length. Cross-check:
 * pinned QEMU hw/acpi/aml-build.c build_rsdp emits exactly this layout,
 * with revision 0 on the x86 machines (hw/i386/acpi-build.c
 * acpi_build: `.revision = 0, .xsdt_tbl_offset = NULL`). */
#define KI_ACPI_RSDP_SIGNATURE        "RSD PTR "
#define KI_ACPI_RSDP_V1_LENGTH        20
#define KI_ACPI_RSDP_V2_LENGTH        36
#define KI_ACPI_RSDP_OFF_REVISION     15
#define KI_ACPI_RSDP_OFF_RSDT_ADDRESS 16
#define KI_ACPI_RSDP_OFF_LENGTH       20
#define KI_ACPI_RSDP_OFF_XSDT_ADDRESS 24
#define KI_ACPI_RSDP_REVISION_2       2

/* RSDT / XSDT (ACPI 6.5 §5.2.7 Table 5.7 / §5.2.8 Table 5.8): the header,
 * then an array of 32-bit / 64-bit physical table addresses from offset 36
 * to Length. The XSDT's entries are only 4-byte aligned (36 is not a
 * multiple of 8), which is why every multi-byte read below is byte-wise. */
#define KI_ACPI_ROOT_OFF_ENTRIES 36

/* Generic Address Structure (ACPI 6.5 §5.2.3.2 Table 5.1): Address Space
 * ID @0 (1), Register Bit Width @1 (1), Register Bit Offset @2 (1), Access
 * Size @3 (1), Address @4 (8); 12 bytes. Cross-check: pinned QEMU
 * hw/acpi/aml-build.c build_append_gas. */
#define KI_ACPI_GAS_LENGTH        12
#define KI_ACPI_GAS_OFF_SPACE_ID  0
#define KI_ACPI_GAS_OFF_BIT_WIDTH 1
#define KI_ACPI_GAS_OFF_ADDRESS   4

/* FADT (ACPI 6.5 §5.2.9 Table 5.9, signature "FACP"): DSDT @40 (4), SCI_INT
 * @46 (2), SMI_CMD @48 (4), ACPI_ENABLE @52 (1), ACPI_DISABLE @53 (1),
 * PM1a_CNT_BLK @64 (4), PM1b_CNT_BLK @68 (4), PM1_CNT_LEN @89 (1), Flags
 * @112 (4) — through which the ACPI 1.0 FADT is 116 bytes — then X_DSDT
 * @140 (8), X_PM1a_CNT_BLK @172 (GAS), X_PM1b_CNT_BLK @184 (GAS). Cross-check:
 * pinned QEMU hw/acpi/aml-build.c build_fadt emits the fields in this order
 * (its per-field SCI_INT ... X_PM1b_CNT_BLK comments), 244 bytes at revision
 * 3 (the x86 machines' .rev, hw/i386/acpi-build.c acpi_get_pm_info). */
#define KI_ACPI_FADT_SIGNATURE          "FACP"
#define KI_ACPI_FADT_OFF_DSDT           40
#define KI_ACPI_FADT_OFF_SCI_INT        46
#define KI_ACPI_FADT_OFF_SMI_CMD        48
#define KI_ACPI_FADT_OFF_ACPI_ENABLE    52
#define KI_ACPI_FADT_OFF_ACPI_DISABLE   53
#define KI_ACPI_FADT_OFF_PM1A_CNT_BLK   64
#define KI_ACPI_FADT_OFF_PM1B_CNT_BLK   68
#define KI_ACPI_FADT_OFF_PM1_CNT_LEN    89
#define KI_ACPI_FADT_OFF_FLAGS          112
#define KI_ACPI_FADT_V1_LENGTH          116
#define KI_ACPI_FADT_OFF_X_DSDT         140
#define KI_ACPI_FADT_OFF_X_PM1A_CNT_BLK 172
#define KI_ACPI_FADT_OFF_X_PM1B_CNT_BLK 184

/* DSDT (ACPI 6.5 §5.2.11.1): a DESCRIPTION_HEADER followed by AML. */
#define KI_ACPI_DSDT_SIGNATURE "DSDT"

/* MADT (ACPI 6.5 §5.2.12 Table 5.19, signature "APIC"): Local Interrupt
 * Controller Address @36 (4), Flags @40 (4), then interrupt-controller
 * structures from @44, each starting Type @0 (1), Length @1 (1) (Table 5.21
 * lists the types). Processor Local APIC (type 0, §5.2.12.2 Table 5.22, 8
 * bytes): Flags @4 (4). I/O APIC (type 1, §5.2.12.3 Table 5.24, 12 bytes).
 * Local APIC Address Override (type 5, §5.2.12.8 Table 5.29, 12 bytes):
 * Local APIC Address @4 (8). Processor Local x2APIC (type 9, §5.2.12.12
 * Table 5.34, 16 bytes): Flags @8 (4). Local APIC Flags (Table 5.23): bit 0
 * Enabled. Cross-check: pinned QEMU hw/i386/acpi-common.c acpi_build_madt /
 * pc_madt_cpu_entry / build_ioapic emit exactly these shapes. */
#define KI_ACPI_MADT_SIGNATURE                  "APIC"
#define KI_ACPI_MADT_OFF_LAPIC_ADDRESS          36
#define KI_ACPI_MADT_OFF_ENTRIES                44
#define KI_ACPI_MADT_ENTRY_HEADER_LENGTH        2
#define KI_ACPI_MADT_TYPE_LOCAL_APIC            0
#define KI_ACPI_MADT_TYPE_IO_APIC               1
#define KI_ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE   5
#define KI_ACPI_MADT_TYPE_LOCAL_X2APIC          9
#define KI_ACPI_MADT_LOCAL_APIC_LENGTH          8
#define KI_ACPI_MADT_LOCAL_APIC_OFF_FLAGS       4
#define KI_ACPI_MADT_IO_APIC_LENGTH             12
#define KI_ACPI_MADT_LAPIC_OVERRIDE_LENGTH      12
#define KI_ACPI_MADT_LAPIC_OVERRIDE_OFF_ADDRESS 4
#define KI_ACPI_MADT_LOCAL_X2APIC_LENGTH        16
#define KI_ACPI_MADT_LOCAL_X2APIC_OFF_FLAGS     8
#define KI_ACPI_MADT_LAPIC_FLAG_ENABLED         0x1u

/* The AML bytes the \_S5 scan recognizes (ACPI 6.5 §20.2, byte values from
 * §20.3 "AML Byte Stream Byte Values"): DefName := NameOp NameString
 * DataRefObject (§20.2.5.1, NameOp 0x08); NameString may begin with RootChar
 * '\' 0x5C (§20.2.2), and a NameSeg is four chars '_'-padded ("_S5_");
 * DefPackage := PackageOp PkgLength NumElements PackageElementList
 * (§20.2.5.4, PackageOp 0x12); PkgLength (§20.2.4): lead byte bits 7:6 count
 * the following bytes (0..3), bits 5:0 are the whole length when none
 * follow, else bits 3:0 are its low nibble and the following bytes supply
 * bits 4 upward; integer constants (§20.2.3): ZeroOp 0x00, OneOp 0x01, OnesOp
 * 0xFF, BytePrefix 0x0A + 1, WordPrefix 0x0B + 2, DWordPrefix 0x0C + 4,
 * QWordPrefix 0x0E + 8. Cross-check: pinned QEMU hw/acpi/aml-build.c
 * aml_name_decl / aml_package / build_prepend_package_length / aml_int emit
 * these bytes; its \_S5 is `08 5F 53 35 5F 12 06 04 00 00 00 00`
 * (hw/i386/acpi-build.c build_dsdt, the `_S5` package of four aml_int(0)). */
#define KI_AML_ZERO_OP         0x00
#define KI_AML_ONE_OP          0x01
#define KI_AML_NAME_OP         0x08
#define KI_AML_BYTE_PREFIX     0x0A
#define KI_AML_WORD_PREFIX     0x0B
#define KI_AML_DWORD_PREFIX    0x0C
#define KI_AML_QWORD_PREFIX    0x0E
#define KI_AML_PACKAGE_OP      0x12
#define KI_AML_ROOT_CHAR       0x5C
#define KI_AML_ONES_OP         0xFF
#define KI_AML_NAME_SEG_LENGTH 4

/* The \_Sx package (ACPI 6.5 §7.4.2 Table 7.11): byte 0 is the PM1a_CNT
 * SLP_TYP value, byte 1 the PM1b_CNT one — written as one integer with those
 * bytes, or (as every firmware does, QEMU included) as separate integer
 * elements. SLP_TYP is a 3-bit field (§4.8.3.2.1 Table 4.13, bits 12:10). */
#define KI_ACPI_SLP_TYP_MASK 0x7u

static KI_ACPI_INFO KiAcpiInfo;
static BOOLEAN KiAcpiPresent;

static uint16_t KiAcpiRead16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t KiAcpiRead32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t KiAcpiRead64(const uint8_t *p)
{
    return (uint64_t)KiAcpiRead32(p) | ((uint64_t)KiAcpiRead32(p + 4) << 32);
}

/* ACPI 6.5 §5.2.5.3 / §5.2.6: the bytes sum to zero modulo 256. */
static BOOLEAN KiAcpiChecksumOk(const uint8_t *data, uint32_t length)
{
    uint8_t sum = 0;
    for (uint32_t i = 0; i < length; i++)
    {
        sum = (uint8_t)(sum + data[i]);
    }
    return sum == 0;
}

static BOOLEAN KiAcpiBytesMatch(const uint8_t *data, const char *expected, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++)
    {
        if (data[i] != (uint8_t)expected[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Validate a DESCRIPTION_HEADER'd table: a sane Length and a zero checksum.
 * Returns the Length, or 0 to refuse. The signature is the caller's to
 * check — a table with the wrong one is still a valid table. */
static uint32_t KiAcpiValidateTable(const uint8_t *table)
{
    uint32_t length = KiAcpiRead32(table + KI_ACPI_HEADER_OFF_LENGTH);
    if (length < KI_ACPI_HEADER_LENGTH || length > KI_ACPI_MAX_TABLE_LENGTH)
    {
        return 0;
    }
    if (!KiAcpiChecksumOk(table, length))
    {
        return 0;
    }
    return length;
}

/* The physical address in the root table's entry array at `index`. */
static uint64_t KiAcpiRootEntry(uint32_t index)
{
    const uint8_t *entry = KiAcpiInfo.rootTable + KI_ACPI_ROOT_OFF_ENTRIES;
    if (KiAcpiInfo.xsdtUsed)
    {
        return KiAcpiRead64(entry + (uint64_t)index * 8);
    }
    return KiAcpiRead32(entry + (uint64_t)index * 4);
}

const uint8_t *KiAcpiFindTable(const char *signature, uint32_t nth, uint32_t *lengthOut)
{
    if (KiAcpiInfo.rootTable == 0)
    {
        return 0;
    }
    uint32_t seen = 0;
    for (uint32_t i = 0; i < KiAcpiInfo.tableCount; i++)
    {
        uint64_t physical = KiAcpiRootEntry(i);
        if (physical == 0)
        {
            continue;
        }
        const uint8_t *table = MiPhysicalToVirtual(physical);
        if (!KiAcpiBytesMatch(table, signature, 4))
        {
            continue;
        }
        uint32_t length = KiAcpiValidateTable(table);
        if (length == 0)
        {
            /* Right signature, bad table: skip it rather than serve it.
             * Said once per boot per table would be noise; the parser's
             * own "refused" lines cover the tables anything depends on. */
            continue;
        }
        if (seen++ == nth)
        {
            if (lengthOut != 0)
            {
                *lengthOut = length;
            }
            return table;
        }
    }
    return 0;
}

/* RSDP + root table. FALSE leaves KiAcpiInfo.rootTable 0. */
static BOOLEAN KiAcpiParseRoot(uint64_t rsdpPhysical)
{
    const uint8_t *rsdp = MiPhysicalToVirtual(rsdpPhysical);
    if (!KiAcpiBytesMatch(rsdp, KI_ACPI_RSDP_SIGNATURE, 8) ||
        !KiAcpiChecksumOk(rsdp, KI_ACPI_RSDP_V1_LENGTH))
    {
        DbgPrint("[KTEST] acpi rsdp refused (signature/checksum)\n");
        return FALSE;
    }
    KiAcpiInfo.rsdp = rsdp;
    KiAcpiInfo.rsdpRevision = rsdp[KI_ACPI_RSDP_OFF_REVISION];

    uint64_t rootPhysical = 0;
    BOOLEAN xsdt = FALSE;
    if (KiAcpiInfo.rsdpRevision >= KI_ACPI_RSDP_REVISION_2)
    {
        uint32_t length = KiAcpiRead32(rsdp + KI_ACPI_RSDP_OFF_LENGTH);
        if (length >= KI_ACPI_RSDP_V2_LENGTH && length <= KI_ACPI_MAX_TABLE_LENGTH &&
            KiAcpiChecksumOk(rsdp, length))
        {
            rootPhysical = KiAcpiRead64(rsdp + KI_ACPI_RSDP_OFF_XSDT_ADDRESS);
            xsdt = rootPhysical != 0;
        }
        else
        {
            /* A 2.0 RSDP whose extension fails its own checksum still
             * carries a valid 1.0 half (checked above): use the RSDT. */
            DbgPrint("[KTEST] acpi rsdp extension refused (length/checksum); using rsdt\n");
        }
    }
    if (!xsdt)
    {
        rootPhysical = KiAcpiRead32(rsdp + KI_ACPI_RSDP_OFF_RSDT_ADDRESS);
    }
    if (rootPhysical == 0)
    {
        DbgPrint("[KTEST] acpi root table absent (rsdp names none)\n");
        return FALSE;
    }

    const uint8_t *root = MiPhysicalToVirtual(rootPhysical);
    uint32_t rootLength = KiAcpiValidateTable(root);
    if (rootLength == 0 || !KiAcpiBytesMatch(root, xsdt ? "XSDT" : "RSDT", 4))
    {
        if (xsdt)
        {
            /* Fall back to the RSDT the same RSDP names (§5.2.5.3: both are
             * present in a 2.0 RSDP). */
            DbgPrint("[KTEST] acpi xsdt refused; trying rsdt\n");
            rootPhysical = KiAcpiRead32(rsdp + KI_ACPI_RSDP_OFF_RSDT_ADDRESS);
            xsdt = FALSE;
            if (rootPhysical != 0)
            {
                root = MiPhysicalToVirtual(rootPhysical);
                rootLength = KiAcpiValidateTable(root);
            }
            else
            {
                rootLength = 0;
            }
        }
        if (rootLength == 0 || !KiAcpiBytesMatch(root, xsdt ? "XSDT" : "RSDT", 4))
        {
            DbgPrint("[KTEST] acpi root table refused (signature/length/checksum)\n");
            return FALSE;
        }
    }
    KiAcpiInfo.xsdtUsed = xsdt;
    KiAcpiInfo.rootTable = root;
    KiAcpiInfo.tableCount = (rootLength - KI_ACPI_ROOT_OFF_ENTRIES) / (xsdt ? 8u : 4u);
    return TRUE;
}

static void KiAcpiReadGas(const uint8_t *gas, KI_ACPI_GAS *out)
{
    out->addressSpaceId = gas[KI_ACPI_GAS_OFF_SPACE_ID];
    out->bitWidth = gas[KI_ACPI_GAS_OFF_BIT_WIDTH];
    out->address = KiAcpiRead64(gas + KI_ACPI_GAS_OFF_ADDRESS);
}

/* One PM1 control block: the X_ Generic Address when the FADT carries one
 * that names a real System I/O register, else the ACPI 1.0 32-bit port with
 * PM1_CNT_LEN as its width (§5.2.9: the X_ field "if nonzero" supersedes the
 * 32-bit one). */
static void KiAcpiReadPm1Control(const uint8_t *fadt, uint32_t length, uint32_t offset32,
                                 uint32_t offsetGas, KI_ACPI_GAS *out)
{
    out->addressSpaceId = KI_ACPI_GAS_SYSTEM_IO;
    out->bitWidth = (uint8_t)(fadt[KI_ACPI_FADT_OFF_PM1_CNT_LEN] * 8u);
    out->address = KiAcpiRead32(fadt + offset32);
    if (length >= offsetGas + KI_ACPI_GAS_LENGTH)
    {
        KI_ACPI_GAS extended;
        KiAcpiReadGas(fadt + offsetGas, &extended);
        if (extended.address != 0 && extended.addressSpaceId == KI_ACPI_GAS_SYSTEM_IO)
        {
            *out = extended;
        }
    }
}

static void KiAcpiParseFadt(void)
{
    uint32_t length;
    const uint8_t *fadt = KiAcpiFindTable(KI_ACPI_FADT_SIGNATURE, 0, &length);
    if (fadt == 0)
    {
        DbgPrint("[KTEST] acpi fadt absent\n");
        return;
    }
    if (length < KI_ACPI_FADT_V1_LENGTH)
    {
        DbgPrint("[KTEST] acpi fadt refused (length %lu < %u)\n", (unsigned long)length,
                 KI_ACPI_FADT_V1_LENGTH);
        return;
    }
    KiAcpiInfo.fadt = fadt;
    KiAcpiInfo.fadtLength = length;
    KiAcpiInfo.fadtRevision = fadt[KI_ACPI_HEADER_OFF_REVISION];
    KiAcpiInfo.fadtFlags = KiAcpiRead32(fadt + KI_ACPI_FADT_OFF_FLAGS);
    KiAcpiInfo.sciInterrupt = KiAcpiRead16(fadt + KI_ACPI_FADT_OFF_SCI_INT);
    KiAcpiInfo.smiCommandPort = KiAcpiRead32(fadt + KI_ACPI_FADT_OFF_SMI_CMD);
    KiAcpiInfo.acpiEnableValue = fadt[KI_ACPI_FADT_OFF_ACPI_ENABLE];
    KiAcpiInfo.acpiDisableValue = fadt[KI_ACPI_FADT_OFF_ACPI_DISABLE];
    KiAcpiInfo.pm1ControlLength = fadt[KI_ACPI_FADT_OFF_PM1_CNT_LEN];
    KiAcpiReadPm1Control(fadt, length, KI_ACPI_FADT_OFF_PM1A_CNT_BLK,
                         KI_ACPI_FADT_OFF_X_PM1A_CNT_BLK, &KiAcpiInfo.pm1aControl);
    KiAcpiReadPm1Control(fadt, length, KI_ACPI_FADT_OFF_PM1B_CNT_BLK,
                         KI_ACPI_FADT_OFF_X_PM1B_CNT_BLK, &KiAcpiInfo.pm1bControl);
}

/* One AML integer constant at `p` (§20.2.3 ComputationalData / ConstObj).
 * Returns the bytes consumed, 0 when `p` does not start one or it would run
 * past `remaining`. */
static uint32_t KiAcpiReadAmlInteger(const uint8_t *p, uint32_t remaining, uint64_t *value)
{
    if (remaining < 1)
    {
        return 0;
    }
    uint32_t width;
    switch (p[0])
    {
    case KI_AML_ZERO_OP:
        *value = 0;
        return 1;
    case KI_AML_ONE_OP:
        *value = 1;
        return 1;
    case KI_AML_ONES_OP:
        *value = ~(uint64_t)0;
        return 1;
    case KI_AML_BYTE_PREFIX:
        width = 1;
        break;
    case KI_AML_WORD_PREFIX:
        width = 2;
        break;
    case KI_AML_DWORD_PREFIX:
        width = 4;
        break;
    case KI_AML_QWORD_PREFIX:
        width = 8;
        break;
    default:
        return 0;
    }
    if (remaining < 1 + width)
    {
        return 0;
    }
    uint64_t v = 0;
    for (uint32_t i = 0; i < width; i++)
    {
        v |= (uint64_t)p[1 + i] << (8 * i);
    }
    *value = v;
    return 1 + width;
}

/* Try to read `Name(_S5_, Package() { a, b, ... })` starting at the NameOp
 * at `p`. Returns TRUE and fills the sleep types on a match; FALSE leaves
 * the caller scanning. */
static BOOLEAN KiAcpiMatchS5At(const uint8_t *p, uint32_t remaining, uint8_t *typeA, uint8_t *typeB)
{
    uint32_t i = 1; /* past NameOp */
    if (i < remaining && p[i] == KI_AML_ROOT_CHAR)
    {
        i++;
    }
    if (i + KI_AML_NAME_SEG_LENGTH > remaining || !KiAcpiBytesMatch(p + i, "_S5_", 4))
    {
        return FALSE;
    }
    i += KI_AML_NAME_SEG_LENGTH;
    if (i >= remaining || p[i] != KI_AML_PACKAGE_OP)
    {
        return FALSE;
    }
    i++;
    /* PkgLength (§20.2.4): its value counts the bytes from the lead byte
     * through the end of the package, which bounds the element reads. */
    if (i >= remaining)
    {
        return FALSE;
    }
    uint32_t lead = p[i];
    uint32_t followBytes = lead >> 6;
    uint32_t packageLength;
    if (followBytes == 0)
    {
        packageLength = lead & 0x3F;
    }
    else
    {
        if (i + 1 + followBytes > remaining)
        {
            return FALSE;
        }
        packageLength = lead & 0x0F;
        for (uint32_t k = 0; k < followBytes; k++)
        {
            packageLength |= (uint32_t)p[i + 1 + k] << (4 + 8 * k);
        }
    }
    uint32_t packageEnd = i + packageLength;
    if (packageLength < 1 + followBytes || packageEnd > remaining)
    {
        return FALSE;
    }
    i += 1 + followBytes;
    if (i >= packageEnd)
    {
        return FALSE;
    }
    uint32_t numElements = p[i++];
    if (numElements < 1)
    {
        return FALSE;
    }
    uint64_t first;
    uint32_t consumed = KiAcpiReadAmlInteger(p + i, packageEnd - i, &first);
    if (consumed == 0)
    {
        return FALSE; /* a Method, a Buffer, a name: not evaluable here */
    }
    i += consumed;
    uint64_t second;
    if (numElements >= 2)
    {
        consumed = KiAcpiReadAmlInteger(p + i, packageEnd - i, &second);
        if (consumed == 0)
        {
            return FALSE;
        }
    }
    else
    {
        /* The single-integer form of Table 7.11: byte 1 is SLP_TYPb. */
        second = first >> 8;
    }
    *typeA = (uint8_t)(first & KI_ACPI_SLP_TYP_MASK);
    *typeB = (uint8_t)(second & KI_ACPI_SLP_TYP_MASK);
    return TRUE;
}

/* Bounded scan of the DSDT's AML for the \_S5 Name. Not an interpreter: it
 * looks for the byte pattern and then insists on the grammar from the
 * NameOp on, so an "_S5_" inside a string or a buffer fails the PackageOp
 * check and the scan moves on. */
static void KiAcpiScanS5(const uint8_t *dsdt, uint32_t length)
{
    for (uint32_t i = KI_ACPI_HEADER_LENGTH; i < length; i++)
    {
        if (dsdt[i] != KI_AML_NAME_OP)
        {
            continue;
        }
        uint8_t typeA, typeB;
        if (KiAcpiMatchS5At(dsdt + i, length - i, &typeA, &typeB))
        {
            KiAcpiInfo.s5Present = TRUE;
            KiAcpiInfo.s5SleepTypeA = typeA;
            KiAcpiInfo.s5SleepTypeB = typeB;
            return;
        }
    }
}

static void KiAcpiParseDsdt(void)
{
    if (KiAcpiInfo.fadt == 0)
    {
        return;
    }
    uint64_t physical = 0;
    if (KiAcpiInfo.fadtLength >= KI_ACPI_FADT_OFF_X_DSDT + 8)
    {
        physical = KiAcpiRead64(KiAcpiInfo.fadt + KI_ACPI_FADT_OFF_X_DSDT);
    }
    if (physical == 0)
    {
        physical = KiAcpiRead32(KiAcpiInfo.fadt + KI_ACPI_FADT_OFF_DSDT);
    }
    if (physical == 0)
    {
        DbgPrint("[KTEST] acpi dsdt absent (fadt names none)\n");
        return;
    }
    const uint8_t *dsdt = MiPhysicalToVirtual(physical);
    uint32_t length = KiAcpiValidateTable(dsdt);
    if (length == 0 || !KiAcpiBytesMatch(dsdt, KI_ACPI_DSDT_SIGNATURE, 4))
    {
        DbgPrint("[KTEST] acpi dsdt refused (signature/length/checksum)\n");
        return;
    }
    KiAcpiInfo.dsdt = dsdt;
    KiAcpiInfo.dsdtLength = length;
    KiAcpiScanS5(dsdt, length);
    if (!KiAcpiInfo.s5Present)
    {
        DbgPrint("[KTEST] acpi dsdt has no \\_S5 package of constants\n");
    }
}

static void KiAcpiParseMadt(void)
{
    uint32_t length;
    const uint8_t *madt = KiAcpiFindTable(KI_ACPI_MADT_SIGNATURE, 0, &length);
    if (madt == 0)
    {
        DbgPrint("[KTEST] acpi madt absent\n");
        return;
    }
    if (length < KI_ACPI_MADT_OFF_ENTRIES)
    {
        DbgPrint("[KTEST] acpi madt refused (length %lu)\n", (unsigned long)length);
        return;
    }
    KiAcpiInfo.madt = madt;
    KiAcpiInfo.localApicAddress = KiAcpiRead32(madt + KI_ACPI_MADT_OFF_LAPIC_ADDRESS);
    uint32_t offset = KI_ACPI_MADT_OFF_ENTRIES;
    while (offset + KI_ACPI_MADT_ENTRY_HEADER_LENGTH <= length)
    {
        uint8_t type = madt[offset];
        uint8_t entryLength = madt[offset + 1];
        if (entryLength < KI_ACPI_MADT_ENTRY_HEADER_LENGTH || offset + entryLength > length)
        {
            DbgPrint("[KTEST] acpi madt refused (entry at %lu runs off the table)\n",
                     (unsigned long)offset);
            break;
        }
        const uint8_t *entry = madt + offset;
        switch (type)
        {
        case KI_ACPI_MADT_TYPE_LOCAL_APIC:
            if (entryLength >= KI_ACPI_MADT_LOCAL_APIC_LENGTH &&
                (KiAcpiRead32(entry + KI_ACPI_MADT_LOCAL_APIC_OFF_FLAGS) &
                 KI_ACPI_MADT_LAPIC_FLAG_ENABLED))
            {
                KiAcpiInfo.enabledLocalApicCount++;
            }
            break;
        case KI_ACPI_MADT_TYPE_LOCAL_X2APIC:
            if (entryLength >= KI_ACPI_MADT_LOCAL_X2APIC_LENGTH &&
                (KiAcpiRead32(entry + KI_ACPI_MADT_LOCAL_X2APIC_OFF_FLAGS) &
                 KI_ACPI_MADT_LAPIC_FLAG_ENABLED))
            {
                KiAcpiInfo.enabledLocalApicCount++;
            }
            break;
        case KI_ACPI_MADT_TYPE_IO_APIC:
            if (entryLength >= KI_ACPI_MADT_IO_APIC_LENGTH)
            {
                KiAcpiInfo.ioApicCount++;
            }
            break;
        case KI_ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE:
            if (entryLength >= KI_ACPI_MADT_LAPIC_OVERRIDE_LENGTH)
            {
                KiAcpiInfo.localApicAddress =
                    KiAcpiRead64(entry + KI_ACPI_MADT_LAPIC_OVERRIDE_OFF_ADDRESS);
            }
            break;
        default:
            break; /* §5.2.12: OSPM skips structures it does not know */
        }
        offset += entryLength;
    }
}

void KiAcpiInitialize(uint64_t rsdpPhysical)
{
    if (rsdpPhysical == 0)
    {
        /* Not a failure: firmware need not publish ACPI (and Limine gives
         * no response at all when it finds no RSDP). Callers refuse rather
         * than invent a table (Art. 12). */
        DbgPrint("[KTEST] acpi absent\n");
        return;
    }
    if (!KiAcpiParseRoot(rsdpPhysical))
    {
        return;
    }
    KiAcpiPresent = TRUE;
    KiAcpiParseFadt();
    KiAcpiParseDsdt();
    KiAcpiParseMadt();
    DbgPrint("[KTEST] acpi rsdp rev %u, %s %lu tables, fadt rev %u pm1a=%#lx pm1b=%#lx "
             "smi_cmd=%#x sci=%u, s5=%u/%u, madt lapic=%#lx enabled=%lu ioapic=%lu\n",
             KiAcpiInfo.rsdpRevision, KiAcpiInfo.xsdtUsed ? "xsdt" : "rsdt",
             (unsigned long)KiAcpiInfo.tableCount, KiAcpiInfo.fadtRevision,
             (unsigned long)KiAcpiInfo.pm1aControl.address,
             (unsigned long)KiAcpiInfo.pm1bControl.address, KiAcpiInfo.smiCommandPort,
             KiAcpiInfo.sciInterrupt, KiAcpiInfo.s5Present ? KiAcpiInfo.s5SleepTypeA : 0xFFu,
             KiAcpiInfo.s5Present ? KiAcpiInfo.s5SleepTypeB : 0xFFu,
             (unsigned long)KiAcpiInfo.localApicAddress,
             (unsigned long)KiAcpiInfo.enabledLocalApicCount,
             (unsigned long)KiAcpiInfo.ioApicCount);
}

const KI_ACPI_INFO *KiAcpiGetInfo(void)
{
    return KiAcpiPresent ? &KiAcpiInfo : 0;
}
