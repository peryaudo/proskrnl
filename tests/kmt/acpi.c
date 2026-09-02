/* tests/kmt/acpi.c — the firmware-table verdicts: what arch/x86_64/acpi.c
 * located is self-consistent, agrees with the hardware it describes, and
 * carries the \_S5 power-off arch/x86_64/power.c will use.
 *
 * Two layers. The first is what any boot of THIS kernel holds itself to,
 * QEMU or not: checksums re-run, the FADT's PM1 control block a real I/O
 * port, the DSDT's \_S5 present, the MADT's local APIC address the one
 * IA32_APIC_BASE names (two descriptions of one register window, held to
 * agreement — a misread field offset in the parser fails this on any box),
 * and exactly one enabled local APIC — the uniprocessor mandate (docs/09
 * Art. 3) stated as a fact about the machine, which a multi-core box would
 * fail until docs/18's SMP work lifts it.
 * The second runs only under QEMU (fw_cfg answered) and pins the parser
 * against the pinned q35 device model's OWN values, each read back from the
 * device model rather than typed in: the PM I/O base out of the LPC bridge's
 * PCI config, the APM command port, the S5 sleep type its DSDT declares.
 * That is the G8 cross-check discipline applied to a whole table walk.
 *
 * Nothing here has a side effect: PM1a_CNT is read, never written, and the
 * ACPI-mode enable dance is power.c's alone. */
#include "tests/kmt/kmt.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/fwcfg.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/lapic.h"
#include "drivers/pci.h"

#include <stdint.h>

/* The pinned q35 device model (third_party/qemu), cited per value:
 *   - the LPC bridge is D31:F0, vendor 0x8086 device 0x2918
 *     (include/hw/southbridge/ich9.h ICH9_LPC_DEV / ICH9_LPC_FUNC;
 *     include/hw/pci/pci_ids.h PCI_DEVICE_ID_INTEL_ICH9_8; hw/isa/lpc_ich9.c
 *     ich9_lpc_class_init);
 *   - its PMBASE config register is 0x40, base address in bits 15:7, and the
 *     PM I/O range is decoded only while ACPI_CTRL (0x44) bit 7 ACPI_EN is
 *     set (ich9.h ICH9_LPC_PMBASE / ICH9_LPC_PMBASE_BASE_ADDRESS_MASK /
 *     ICH9_LPC_ACPI_CTRL / ICH9_LPC_ACPI_CTRL_ACPI_EN; hw/isa/lpc_ich9.c
 *     ich9_lpc_pmbase_sci_update) — the FADT's PM1a_CNT_BLK is that base +
 *     0x04 (ich9.h ICH9_PMIO_PM1_CNT; hw/i386/acpi-build.c acpi_get_pm_info
 *     `.pm1a_cnt = { ..., .address = io + 0x04 }`);
 *   - ACPI_CTRL bits 2:0 select the SCI: 0 = IRQ 9 (ich9.h
 *     ICH9_LPC_ACPI_CTRL_SCI_IRQ_SEL_MASK / ICH9_LPC_ACPI_CTRL_9;
 *     lpc_ich9.c ich9_lpc_sci_irq);
 *   - the SMI command port is the APM control port 0xB2 and the
 *     ACPI_ENABLE/ACPI_DISABLE values 2/3 (include/hw/isa/apm.h
 *     APM_CNT_IOPORT; ich9.h ICH9_APM_ACPI_ENABLE / ICH9_APM_ACPI_DISABLE;
 *     lpc_ich9.c ich9_lpc_initfn) — but the FADT publishes them as 0 when
 *     the machine has no SMM (acpi-build.c acpi_get_pm_info `smm_enabled ?
 *     ... : 0`; hw/i386/x86.c x86_machine_is_smm_enabled: TCG always,
 *     KVM only with kvm_has_smm), in which case the PM1 control register
 *     reads SCI_EN already set from reset (hw/acpi/ich9.c ich9_pm_init
 *     passes !smm_enabled as acpi_only; hw/acpi/core.c acpi_pm1_cnt_reset);
 *   - the DSDT's \_S5 is Package(){0, 0, 0, 0} (acpi-build.c build_dsdt);
 *   - the FADT is revision 3, 244 bytes (acpi-build.c acpi_get_pm_info
 *     `.rev = 3`; hw/acpi/aml-build.c build_fadt ends after X_GPE1_BLK for
 *     rev <= 4), with the PM1a control block a 16-bit System I/O GAS
 *     (`.bit_width = 2 * 8`);
 *   - the MADT names the LAPIC at 0xFEE00000 (hw/i386/acpi-common.c
 *     acpi_build_madt; target/i386/cpu.h APIC_DEFAULT_ADDRESS) and one
 *     I/O APIC (acpi-common.c: a second only with x86ms->ioapic2, which the
 *     q35 machine does not set);
 *   - the RSDP is ACPI 1.0 (revision 0, RSDT only) on the x86 machines
 *     (acpi-build.c acpi_build `.revision = 0, .xsdt_tbl_offset = NULL`).
 *     That is the SeaBIOS boot Limine's BIOS stages make; an OVMF boot would
 *     republish a revision-2 RSDP with an XSDT, and this one pin would then
 *     be the thing to update. */
#define QEMU_LPC_DEVICE          31
#define QEMU_LPC_FUNCTION        0
#define QEMU_PCI_VENDOR_INTEL    0x8086
#define QEMU_PCI_DEVICE_ICH9_LPC 0x2918
#define QEMU_LPC_PMBASE          0x40
#define QEMU_LPC_PMBASE_MASK     0xFF80u
#define QEMU_LPC_ACPI_CTRL       0x44
#define QEMU_LPC_ACPI_CTRL_EN    0x80
#define QEMU_LPC_ACPI_CTRL_SCI   0x07
#define QEMU_PMIO_PM1_CNT        0x04
#define QEMU_SCI_IRQ             9
#define QEMU_APM_CNT_IOPORT      0xB2
#define QEMU_APM_ACPI_ENABLE     0x2
#define QEMU_APM_ACPI_DISABLE    0x3
#define QEMU_FADT_REVISION       3
#define QEMU_FADT_LENGTH         244
#define QEMU_LAPIC_ADDRESS       0xFEE00000u
#define QEMU_S5_SLEEP_TYPE       0

/* PM1_CNT SCI_EN is bit 0 (ACPI 6.5 §4.8.3.2.1 Table 4.13; pinned QEMU
 * include/hw/acpi/acpi.h ACPI_BITMASK_SCI_ENABLE). */
#define ACPI_PM1_CNT_SCI_EN 0x0001

/* ACPI 6.5 §5.2.6 / §5.2.5.3: bytes sum to zero. */
static int checksum_ok(const uint8_t *data, uint32_t length)
{
    uint8_t sum = 0;
    for (uint32_t i = 0; i < length; i++)
        sum = (uint8_t)(sum + data[i]);
    return sum == 0;
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void test_acpi_present(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    ok(info != 0, "acpi tables located (the boot log says why not)");
    if (!info)
        return;

    /* Re-run the RSDP's own checksums (ACPI 6.5 §5.2.5.3 Table 5.3: the
     * first 20 bytes; a 2.0+ RSDP additionally the whole Length). */
    ok(checksum_ok(info->rsdp, 20), "rsdp 1.0 checksum");
    ok(info->rsdpRevision == 0 || info->rsdpRevision >= 2, "rsdp revision %u is 0 or >= 2",
       info->rsdpRevision);
    if (info->rsdpRevision >= 2)
        ok(checksum_ok(info->rsdp, read32(info->rsdp + 20)), "rsdp 2.0 extended checksum");
    ok(info->xsdtUsed == (info->rsdpRevision >= 2) || !info->xsdtUsed,
       "xsdt used only from a 2.0+ rsdp");
    ok(info->rootTable != 0 && info->tableCount > 0, "root table with %lu entries",
       (unsigned long)info->tableCount);
    ok(checksum_ok(info->rootTable, read32(info->rootTable + 4)), "root table checksum");

    /* The accessor finds the same FADT the parser took. */
    uint32_t length = 0;
    const uint8_t *fadt = KiAcpiFindTable("FACP", 0, &length);
    ok(fadt == info->fadt, "KiAcpiFindTable(FACP) is the parsed fadt");
    ok(fadt == 0 || length == info->fadtLength, "KiAcpiFindTable length %lu == %lu",
       (unsigned long)length, (unsigned long)info->fadtLength);
    ok(KiAcpiFindTable("FACP", 1, 0) == 0, "exactly one fadt");
    ok(KiAcpiFindTable("XXXX", 0, 0) == 0, "an unknown signature finds nothing");
}

static void test_acpi_fadt(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    if (!info)
        return;
    ok(info->fadt != 0, "fadt present");
    if (!info->fadt)
        return;
    ok(info->fadtLength >= 116, "fadt length %lu covers the ACPI 1.0 fields",
       (unsigned long)info->fadtLength);
    ok(checksum_ok(info->fadt, info->fadtLength), "fadt checksum");
    ok(!(info->fadtFlags & KI_ACPI_FADT_FLAG_HW_REDUCED_ACPI),
       "not a hardware-reduced platform (it would have no PM1 block)");
    ok(info->pm1aControl.addressSpaceId == KI_ACPI_GAS_SYSTEM_IO,
       "pm1a control block is in System I/O space (id %u)", info->pm1aControl.addressSpaceId);
    ok(info->pm1aControl.address != 0 && info->pm1aControl.address <= 0xFFFF,
       "pm1a control block at a real port (%#lx)", (unsigned long)info->pm1aControl.address);
    ok(info->pm1ControlLength >= 2, "PM1_CNT_LEN %u decodes the 16-bit register",
       info->pm1ControlLength);
    ok(info->pm1aControl.bitWidth >= 16, "pm1a control width %u bits", info->pm1aControl.bitWidth);
    ok(info->pm1bControl.address == 0 || info->pm1bControl.addressSpaceId == KI_ACPI_GAS_SYSTEM_IO,
       "pm1b control block, when present, is in System I/O space");
    ok(info->sciInterrupt != 0, "SCI_INT %u is wired", info->sciInterrupt);
}

static void test_acpi_dsdt(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    if (!info)
        return;
    ok(info->dsdt != 0, "dsdt present");
    if (!info->dsdt)
        return;
    ok(checksum_ok(info->dsdt, info->dsdtLength), "dsdt checksum");
    ok(info->s5Present, "\\_S5 package found in the dsdt");
    ok(info->s5SleepTypeA <= 7 && info->s5SleepTypeB <= 7, "sleep types %u/%u fit SLP_TYP",
       info->s5SleepTypeA, info->s5SleepTypeB);
}

static void test_acpi_madt(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    if (!info)
        return;
    ok(info->madt != 0, "madt present");
    if (!info->madt)
        return;
    /* Two descriptions of one register window: the firmware's and the
     * MSR's. arch/x86_64/lapic.c mapped the latter; the kernel is
     * uniprocessor (docs/09 Art. 3), so tools/qemu.sh passes no -smp and
     * the census must say exactly one enabled local APIC. */
    ok(info->localApicAddress == KiLocalApicPhysicalAddress(),
       "madt lapic %#lx == IA32_APIC_BASE %#lx", (unsigned long)info->localApicAddress,
       (unsigned long)KiLocalApicPhysicalAddress());
    ok(info->enabledLocalApicCount == 1, "one enabled local apic (%lu)",
       (unsigned long)info->enabledLocalApicCount);
    ok(info->ioApicCount >= 1, "at least one I/O apic (%lu)", (unsigned long)info->ioApicCount);
}

static void test_acpi_pinned_qemu(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    if (!info || !info->fadt)
        return;
    if (!KiFwCfgPresent())
        return; /* not QEMU: the machine-agnostic layer above is the whole verdict */

    KI_PCI_FUNCTION lpc = {QEMU_LPC_DEVICE, QEMU_LPC_FUNCTION, 0, 0};
    uint16_t vendor = KiPciReadConfig16(&lpc, PCI_CONFIG_VENDOR_ID);
    uint16_t device = KiPciReadConfig16(&lpc, PCI_CONFIG_DEVICE_ID);
    ok(vendor == QEMU_PCI_VENDOR_INTEL && device == QEMU_PCI_DEVICE_ICH9_LPC,
       "D31:F0 is the ICH9 LPC bridge (%04x:%04x)", vendor, device);
    if (vendor != QEMU_PCI_VENDOR_INTEL || device != QEMU_PCI_DEVICE_ICH9_LPC)
        return;

    /* The PM base the device model decodes, read back from the bridge
     * rather than typed: the FADT must name that base + 4. */
    uint32_t pmbase = KiPciReadConfig32(&lpc, QEMU_LPC_PMBASE) & QEMU_LPC_PMBASE_MASK;
    uint8_t acpiCtrl = KiPciReadConfig8(&lpc, QEMU_LPC_ACPI_CTRL);
    ok(acpiCtrl & QEMU_LPC_ACPI_CTRL_EN, "LPC ACPI_CTRL.ACPI_EN set (%#x)", acpiCtrl);
    ok(pmbase != 0, "LPC PMBASE %#lx", (unsigned long)pmbase);
    ok(info->pm1aControl.address == pmbase + QEMU_PMIO_PM1_CNT,
       "fadt pm1a_cnt %#lx == PMBASE %#lx + 4", (unsigned long)info->pm1aControl.address,
       (unsigned long)pmbase);
    ok(info->pm1aControl.bitWidth == 16, "X_PM1a_CNT_BLK taken (width %u)",
       info->pm1aControl.bitWidth);
    ok(info->pm1bControl.address == 0, "no pm1b block (%#lx)",
       (unsigned long)info->pm1bControl.address);
    ok((acpiCtrl & QEMU_LPC_ACPI_CTRL_SCI) == 0 && info->sciInterrupt == QEMU_SCI_IRQ,
       "SCI on IRQ 9 (ctrl sel %u, fadt %u)", acpiCtrl & QEMU_LPC_ACPI_CTRL_SCI,
       info->sciInterrupt);

    /* Either SMM shape (see the header): the SMI command port published with
     * the APM values, or no port at all with ACPI mode fixed on. */
    uint16_t pm1aCnt = KiInWord((uint16_t)info->pm1aControl.address);
    if (info->smiCommandPort != 0)
        ok(info->smiCommandPort == QEMU_APM_CNT_IOPORT &&
               info->acpiEnableValue == QEMU_APM_ACPI_ENABLE &&
               info->acpiDisableValue == QEMU_APM_ACPI_DISABLE,
           "smi_cmd %#x enable %u disable %u are the APM port and values", info->smiCommandPort,
           info->acpiEnableValue, info->acpiDisableValue);
    else
        ok(pm1aCnt & ACPI_PM1_CNT_SCI_EN, "no smi_cmd: SCI_EN already set (pm1a_cnt %#x)", pm1aCnt);

    ok(info->s5Present && info->s5SleepTypeA == QEMU_S5_SLEEP_TYPE &&
           info->s5SleepTypeB == QEMU_S5_SLEEP_TYPE,
       "\\_S5 is Package(){0, 0, ...} (%u/%u)", info->s5SleepTypeA, info->s5SleepTypeB);
    ok(info->fadtRevision == QEMU_FADT_REVISION && info->fadtLength == QEMU_FADT_LENGTH,
       "fadt rev %u length %lu", info->fadtRevision, (unsigned long)info->fadtLength);
    ok(info->localApicAddress == QEMU_LAPIC_ADDRESS, "madt lapic at %#lx",
       (unsigned long)info->localApicAddress);
    ok(info->ioApicCount == 1, "one I/O apic (%lu)", (unsigned long)info->ioApicCount);
    ok(info->rsdpRevision == 0 && !info->xsdtUsed, "ACPI 1.0 rsdp, rsdt (SeaBIOS boot; rev %u)",
       info->rsdpRevision);
}

int kmt_run_acpi(void)
{
    int before = kmt_failures;
    KMT_RUN(test_acpi_present);
    KMT_RUN(test_acpi_fadt);
    KMT_RUN(test_acpi_dsdt);
    KMT_RUN(test_acpi_madt);
    KMT_RUN(test_acpi_pinned_qemu);
    return kmt_failures - before;
}
