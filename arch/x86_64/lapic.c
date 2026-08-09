/* arch/x86_64/lapic.c — Local APIC + the periodic clock interrupt, xAPIC mode.
 *
 * We drive the LAPIC through its xAPIC MMIO window rather than x2APIC MSRs.
 * x2APIC's advantages are 32-bit APIC IDs (>255 CPUs), no MMIO mapping, and a
 * single-write ICR; the first and third are worth nothing to a uniprocessor
 * kernel (Art. 3) and the second costs one page-table entry. What xAPIC buys
 * in exchange is that it is *unconditionally present*: every x86-64 CPU and
 * every QEMU has it, so there is no CPUID bit to test, no firmware "Local APIC
 * Mode = Compatibility" setting to lose to, and no second code path. x2APIC
 * comes back if and when the CPU count justifies it (docs/18 §13).
 *
 * M2 turns the M1 free-running timer into a real 1 ms clock: the LAPIC timer
 * frequency is CPU-dependent, so it is calibrated once against the PIT
 * (channel 2, gated one-shot — the classic dance), then programmed periodic.
 * The tick itself is handled in kernel/ke/timer.c (KiUpdateClock).
 *
 * Constants cross-check: Intel SDM Vol. 3A, "Advanced Programmable Interrupt
 * Controller (APIC)" (xAPIC register offsets, LVT/SVR/divide bit layouts,
 * IA32_APIC_BASE and its EN/EXTD bits, the 4 KiB register window and its
 * 32-bit-aligned access rule); Intel 8254 datasheet + IBM PC/AT port 0x61 for
 * the PIT side. The pinned QEMU we run on (third_party/qemu) decodes the same
 * values in hw/intc/apic.c (register index = offset >> 4: EOI 0x0B, SVR 0x0F,
 * LVT timer 0x32, initial/current count 0x38/0x39, divide 0x3E),
 * target/i386/cpu.h (MSR_IA32_APICBASE 0x1B, ENABLE bit 11, EXTD bit 10;
 * its MSR_IA32_APICBASE_BASE is the 32-bit-guest field, bits 31:12 — the
 * 51:12 mask below is the SDM's full-width one), include/hw/timer/i8254.h
 * (PIT_FREQ 1193182), and hw/audio/pcspk.c (port 0x61: bit 0 = channel-2
 * gate, bit 5 = channel-2 OUT).
 */
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/mmu.h"
#include "kernel/init/panic.h"

#include <stdint.h>

#define IA32_APIC_BASE    0x1B
#define APIC_BASE_EN      (1ULL << 11) /* xAPIC global enable */
#define APIC_BASE_EXTD    (1ULL << 10) /* x2APIC enable       */
#define APIC_BASE_ADDRESS 0x000FFFFFFFFFF000ULL

/* xAPIC register offsets within the 4 KiB window. */
#define LAPIC_EOI      0x0B0
#define LAPIC_SVR      0x0F0
#define LAPIC_LVT_TMR  0x320
#define LAPIC_TMR_INIT 0x380
#define LAPIC_TMR_CUR  0x390
#define LAPIC_TMR_DIV  0x3E0

#define LAPIC_SVR_ENABLE   (1U << 8) /* APIC software enable */
#define LAPIC_TMR_PERIODIC (1U << 17)
#define LAPIC_TMR_MASKED   (1U << 16)

/* Kernel VA the register window is mapped at. Deliberately inside PML4 slot
 * 511 — the kernel image's slot, which MiInitializeVirtualMemory always
 * populates — because KiInitializeClock runs after MiFreezeKernelPml4
 * (kernel/init/main.c order) and claiming a *fresh* PML4 slot there would
 * panic. Lower-level tables under an existing slot are shared by every
 * process PML4 automatically, so growing them later is safe. The kernel image
 * itself sits in the top 2 GiB of the same slot (arch/x86_64/linker.ld),
 * 510 GiB above this. */
#define LAPIC_WINDOW_BASE 0xFFFFFF8000000000ULL

static volatile uint8_t *KiApicWindow;

/* The window is strongly uncacheable, so plain volatile 32-bit accesses are
 * the whole contract: no reordering into or out of a cacheable line, and the
 * SDM's "32-bit aligned accesses only" rule is satisfied by construction. */
static uint32_t KiApicRead(uint32_t offset)
{
    ASSERT(KiApicWindow != 0);
    return *(volatile uint32_t *)(KiApicWindow + offset);
}

static void KiApicWrite(uint32_t offset, uint32_t value)
{
    ASSERT(KiApicWindow != 0);
    *(volatile uint32_t *)(KiApicWindow + offset) = value;
}

/* PIT: channel 2 gated by port 0x61 bit 0; OUT2 readable at 0x61 bit 5. */
#define PIT_CHANNEL2 0x42
#define PIT_COMMAND  0x43
#define PIT_GATE     0x61
/* 1.193182 MHz PIT clock (QEMU include/hw/timer/i8254.h PIT_FREQ) in 10 ms:
 * 1193182 / 100 = 11931.82, rounded. */
#define PIT_10MS_COUNT 11932

extern uint64_t KiTrapThunkTable[]; /* trap.S */

void KiEndOfInterrupt(void)
{
    KiApicWrite(LAPIC_EOI, 0);
}

/* Put the LAPIC in xAPIC mode and map its register window. Firmware or a
 * bootloader may hand off with x2APIC already enabled, and in that mode every
 * access to the MMIO window faults — so force the mode rather than assuming
 * it. The SDM forbids clearing EXTD directly: the transition back to xAPIC
 * must pass through the disabled state (EN = 0, EXTD = 0). */
static void KiEnableXApic(void)
{
    uint64_t apicBase = KiReadMsr(IA32_APIC_BASE);
    if (apicBase & APIC_BASE_EXTD)
    {
        KiWriteMsr(IA32_APIC_BASE, apicBase & ~(APIC_BASE_EN | APIC_BASE_EXTD));
        apicBase &= ~APIC_BASE_EXTD;
    }
    KiWriteMsr(IA32_APIC_BASE, apicBase | APIC_BASE_EN);

    /* The window is relocatable (bits 51:12 of the MSR), so read it rather
     * than hardwiring the 0xFEE00000 power-on default. */
    MiMapDevicePage(LAPIC_WINDOW_BASE, apicBase & APIC_BASE_ADDRESS);
    KiApicWindow = (volatile uint8_t *)LAPIC_WINDOW_BASE;
}

uint64_t KiTscPerMillisecond;

/* Count LAPIC timer ticks (divide-by-16) across one 10 ms PIT gate, and count
 * TSC cycles across the same gate into *tscPerMs — one measurement, two
 * consumers, so the interpolation kernel/ke/timer.c does between ticks is
 * calibrated against the very gate that set the tick's length. */
static uint32_t KiCalibrateApicTimer(uint64_t *tscPerMs)
{
    /* Gate high, speaker off; channel 2, lobyte/hibyte, mode 0 (one-shot,
     * OUT rises at terminal count). */
    KiOutByte(PIT_GATE, (uint8_t)((KiInByte(PIT_GATE) & 0xFC) | 0x01));
    KiOutByte(PIT_COMMAND, 0xB0);

    /* Arm the LAPIC timer BEFORE the PIT starts counting, and start them as
     * close together as the two buses allow. In mode 0 with lobyte/hibyte
     * access the PIT loads and begins on the HIGH-byte write, so the low
     * byte goes out first, the LAPIC's initial-count store next, and the
     * high byte last -- one I/O write apart.
     *
     * The whole LAPIC setup used to sit after both count bytes, so the
     * LAPIC missed the head of the gate: the tick count came out low, the
     * derived ticks-per-ms came out low, and every timeout in the system
     * expired early. Small (<0.1%) but one-directional, which is what makes
     * it worth fixing rather than tolerating (docs/review-2026-07 §8). */
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT & 0xFF);
    KiApicWrite(LAPIC_TMR_DIV, 0x3); /* divide by 16 */
    KiApicWrite(LAPIC_LVT_TMR, LAPIC_TMR_MASKED | TIMER_VECTOR);
    KiApicWrite(LAPIC_TMR_INIT, 0xFFFFFFFFU);
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT >> 8);
    uint64_t tscStart = KiReadTimestampCounter();

    while ((KiInByte(PIT_GATE) & 0x20) == 0)
    {
    }

    uint64_t tscEnd = KiReadTimestampCounter();
    uint32_t remaining = KiApicRead(LAPIC_TMR_CUR);
    KiApicWrite(LAPIC_TMR_INIT, 0); /* stop */
    *tscPerMs = (tscEnd - tscStart) / 10;
    return (0xFFFFFFFFU - remaining) / 10; /* ticks per 1 ms */
}

void KiInitializeClock(void)
{
    /* Mask both halves of the legacy 8259 PIC so no stray IRQ arrives on a
     * vector that overlaps a CPU exception. */
    KiOutByte(0x21, 0xFF);
    KiOutByte(0xA1, 0xFF);

    KiEnableXApic();

    /* Enable the LAPIC; route spurious interrupts to vector 0xFF -- and give
     * that vector a gate. Without one, the architecturally-defined "ignore
     * this" event raised a #GP and panicked blaming an unrelated RIP
     * (docs/review-2026-07 §8). The handler returns WITHOUT an EOI, as the
     * SDM requires for a spurious interrupt (Vol. 3A §11.9 "Spurious
     * Interrupt"). */
    KiSetInterruptGate(KI_SPURIOUS_VECTOR, (uint64_t)(uintptr_t)KiSpuriousInterruptThunk);
    KiApicWrite(LAPIC_SVR, LAPIC_SVR_ENABLE | KI_SPURIOUS_VECTOR);

    KiSetInterruptGate(TIMER_VECTOR, KiTrapThunkTable[TIMER_VECTOR]);

    uint64_t tscPerMs = 0;
    uint32_t ticksPerMs = KiCalibrateApicTimer(&tscPerMs);
    if (ticksPerMs == 0)
    {
        KiPanic("KiInitializeClock: LAPIC timer calibration failed");
    }
    if (tscPerMs == 0)
    {
        /* A stopped TSC would make every interpolated reading saturate at
         * one tick short of the next tick — still monotone, but a silently
         * useless clock. There is no such processor (the TSC has been
         * architectural since the Pentium, Intel SDM Vol. 3B §18.17) and no
         * such QEMU, so this refuses rather than degrading quietly (G12). */
        KiPanic("KiInitializeClock: TSC calibration failed");
    }
    KiTscPerMillisecond = tscPerMs;

    KiApicWrite(LAPIC_TMR_DIV, 0x3);
    KiApicWrite(LAPIC_LVT_TMR, TIMER_VECTOR | LAPIC_TMR_PERIODIC);
    KiApicWrite(LAPIC_TMR_INIT, ticksPerMs); /* 1 ms period */

    __asm__ volatile("sti");
}
