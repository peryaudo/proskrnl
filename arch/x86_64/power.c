/* arch/x86_64/power.c — power the machine off through ACPI S5.
 *
 * The sequence is the ACPI Specification 6.5's, §16.1.7 "Transitioning from
 * the Working to the Soft Off State", cut down to what a kernel with no AML
 * interpreter and no device power model can honestly do: no _PTS control
 * method (there is nothing to run it with — and nothing to prepare, every
 * mutation being durable already), then SLP_TYPa from \_S5 with SLP_EN into
 * PM1a_CNT, then the same for PM1b_CNT when the FADT names one. Before
 * that, §16.3.1 "Placing the System in ACPI Mode": when the FADT publishes
 * an SMI command port and PM1a_CNT reads SCI_EN clear, the platform is in
 * legacy mode and the sleep bits are the firmware's, not ours, until
 * ACPI_ENABLE has been written to SMI_CMD and SCI_EN comes back set.
 *
 * What it does not do is invent a way out. A platform whose tables carry no
 * usable S5 gets the QEMU debug-exit port as the fallback, said on serial —
 * the same "clean-exit convention" every kernel exit rode before this file
 * existed (arch/x86_64/io.h KiQemuExit), which on real hardware is a write
 * to an unclaimed port followed by the halt loop, i.e. NT's own "it is now
 * safe to turn off your computer". Nothing here parks (G14: KiPowerOff is
 * reachable from NtShutdownSystem, and calls only port I/O and DbgPrint).
 *
 * Register bits are ACPI 6.5 §4.8.3.2.1 Table 4.13 (PM1 Control Registers):
 * SCI_EN bit 0, SLP_TYPx bits 12:10, SLP_EN bit 13 (write-only, reads 0).
 * Cross-check: pinned QEMU include/hw/acpi/acpi.h ACPI_BITMASK_SCI_ENABLE /
 * ACPI_BITMASK_SLEEP_TYPE / ACPI_BITMASK_SLEEP_ENABLE, and hw/acpi/core.c
 * acpi_pm1_cnt_write: SLP_EN with (val >> 10) & 7 == 0 is the S5 the x86
 * machines' DSDT declares, and it requests SHUTDOWN_CAUSE_GUEST_SHUTDOWN —
 * QEMU's main loop then exits with status 0 (system/runstate.c
 * qemu_system_shutdown_request / main_loop_should_exit; contrast the debug
 * port's (code << 1) | 1). */
#include "arch/x86_64/power.h"

#include "arch/x86_64/acpi.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/lapic.h"
#include "kernel/lib/dbgprint.h"

#define ACPI_PM1_CNT_SCI_EN        0x0001u
#define ACPI_PM1_CNT_SLP_TYP_SHIFT 10
#define ACPI_PM1_CNT_SLP_TYP_MASK  0x1C00u
#define ACPI_PM1_CNT_SLP_EN        0x2000u

/* The x86 I/O address space is 2^16 byte-addressable ports (Intel SDM Vol.
 * 1, "Input/Output" chapter, "I/O Port Addressing"; the FADT's PM1x_CNT_BLK
 * and SMI_CMD are "system port addresses", ACPI 6.5 §5.2.9), so an address
 * above this in a System I/O GAS is a table defect, not a port. */
#define KI_IO_PORT_MAX 0xFFFFu

/* How long to wait for SCI_EN after ACPI_ENABLE (§16.3.1 names no bound;
 * the firmware's SMI handler answers in microseconds on any real platform,
 * and QEMU's answers synchronously — hw/isa/lpc_ich9.c ich9_apm_ctrl_changed
 * sets it inside the outb). Ours, generous: the alternative is to hang here. */
#define KI_ACPI_ENABLE_TIMEOUT_MS 3000u

/* When the clock is not calibrated yet (a poweroff before KiInitializeClock —
 * no caller does that today) count polls instead of milliseconds. */
#define KI_ACPI_ENABLE_POLLS_UNCALIBRATED 1000000u

__attribute__((noreturn)) static void KiHaltForever(void)
{
    for (;;)
    {
        __asm__ volatile("hlt");
    }
}

/* Why the located tables cannot power this machine off, or 0 when they can. */
static const char *KiPowerOffUnusableReason(const KI_ACPI_INFO *info)
{
    if (info == 0)
    {
        return "no acpi tables";
    }
    if (info->fadt == 0)
    {
        return "no fadt";
    }
    if (info->fadtFlags & KI_ACPI_FADT_FLAG_HW_REDUCED_ACPI)
    {
        return "hardware-reduced platform (SLEEP_CONTROL_REG unbuilt)";
    }
    if (info->pm1aControl.address == 0 || info->pm1aControl.address > KI_IO_PORT_MAX ||
        info->pm1aControl.addressSpaceId != KI_ACPI_GAS_SYSTEM_IO)
    {
        return "pm1a control block not a System I/O port";
    }
    if (info->pm1bControl.address != 0 &&
        (info->pm1bControl.address > KI_IO_PORT_MAX ||
         info->pm1bControl.addressSpaceId != KI_ACPI_GAS_SYSTEM_IO))
    {
        return "pm1b control block not a System I/O port";
    }
    if (!info->s5Present)
    {
        return "no \\_S5 package of constants in the dsdt";
    }
    return 0;
}

/* §16.3.1: leave legacy mode if the platform is in it. Returns the PM1a_CNT
 * value read last, so the caller can say what SCI_EN ended up as. */
static uint16_t KiAcpiEnableMode(const KI_ACPI_INFO *info, uint16_t pm1aPort)
{
    uint16_t control = KiInWord(pm1aPort);
    if ((control & ACPI_PM1_CNT_SCI_EN) != 0 || info->smiCommandPort == 0 ||
        info->smiCommandPort > KI_IO_PORT_MAX || info->acpiEnableValue == 0)
    {
        /* Already in ACPI mode, or a platform with no SMI command port at
         * all (§5.2.9 SMI_CMD = 0: "no SMI ownership to disable"), where
         * SCI_EN is fixed set — the shape QEMU takes without SMM. */
        return control;
    }
    KiOutByte((uint16_t)info->smiCommandPort, info->acpiEnableValue);
    if (KiTscPerMillisecond != 0)
    {
        uint64_t deadline =
            KiReadTimestampCounter() + KI_ACPI_ENABLE_TIMEOUT_MS * KiTscPerMillisecond;
        do
        {
            control = KiInWord(pm1aPort);
        } while ((control & ACPI_PM1_CNT_SCI_EN) == 0 && KiReadTimestampCounter() < deadline);
    }
    else
    {
        for (uint32_t polls = 0; polls < KI_ACPI_ENABLE_POLLS_UNCALIBRATED; polls++)
        {
            control = KiInWord(pm1aPort);
            if (control & ACPI_PM1_CNT_SCI_EN)
            {
                break;
            }
        }
    }
    if ((control & ACPI_PM1_CNT_SCI_EN) == 0)
    {
        /* Said, then carried on: the SLP_EN write is the only thing left to
         * try, and on a platform that never answers ACPI_ENABLE it is also
         * the only thing that could work. */
        DbgPrint("[KTEST] acpi enable: SCI_EN still clear after ACPI_ENABLE (pm1a_cnt=%#x)\n",
                 control);
    }
    return control;
}

/* SLP_TYP + SLP_EN into one PM1 control register, the other bits preserved
 * (§4.8.3.2.1: the register also carries SCI_EN and BM_RLD, which a
 * read-modify-write keeps; GBL_RLS is write-only and reads 0). */
static void KiWriteSleepEnable(uint16_t port, uint8_t sleepType)
{
    uint16_t value = KiInWord(port);
    value &= (uint16_t) ~(ACPI_PM1_CNT_SLP_TYP_MASK | ACPI_PM1_CNT_SLP_EN);
    value |= (uint16_t)((uint16_t)sleepType << ACPI_PM1_CNT_SLP_TYP_SHIFT);
    value |= ACPI_PM1_CNT_SLP_EN;
    KiOutWord(port, value);
}

void KiPowerOff(void)
{
    const KI_ACPI_INFO *info = KiAcpiGetInfo();
    const char *why = KiPowerOffUnusableReason(info);
    if (why != 0)
    {
        DbgPrint("[KTEST] poweroff: no usable ACPI S5 (%s); isa-debug-exit\n", why);
        KiQemuExit(0);
        /* The debug-exit teardown is asynchronous; do not run past it. */
        KiHaltForever();
    }

    uint16_t pm1aPort = (uint16_t)info->pm1aControl.address;
    uint16_t control = KiAcpiEnableMode(info, pm1aPort);
    DbgPrint("[KTEST] acpi poweroff S5 (pm1a_cnt=%#x slp_typ=%u/%u sci_en=%u)\n", pm1aPort,
             info->s5SleepTypeA, info->s5SleepTypeB, (control & ACPI_PM1_CNT_SCI_EN) ? 1 : 0);

    /* From here the machine is ending: no interrupt has anything left to do,
     * and the halt below must not be woken into code that assumes a
     * running system. §7.4.2 Table 7.11: PM1a_CNT before PM1b_CNT. */
    __asm__ volatile("cli");
    KiWriteSleepEnable(pm1aPort, info->s5SleepTypeA);
    if (info->pm1bControl.address != 0)
    {
        KiWriteSleepEnable((uint16_t)info->pm1bControl.address, info->s5SleepTypeB);
    }
    KiHaltForever();
}
