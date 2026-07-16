/* arch/x86_64/lapic.c — Local APIC + the periodic clock interrupt, x2APIC mode.
 *
 * We use x2APIC (LAPIC registers via MSRs) rather than the xAPIC MMIO window:
 * MSR access needs no memory mapping. The legacy 8259 PIC is masked;
 * interrupts come from the LAPIC.
 *
 * M2 turns the M1 free-running timer into a real 1 ms clock: the LAPIC timer
 * frequency is CPU-dependent, so it is calibrated once against the PIT
 * (channel 2, gated one-shot — the classic dance), then programmed periodic.
 * The tick itself is handled in kernel/ke/timer.c (KiUpdateClock).
 */
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io.h"
#include "kernel/init/panic.h"

#include <stdint.h>

#define IA32_APIC_BASE 0x1B
#define APIC_BASE_EN   (1ULL << 11) /* xAPIC global enable */
#define APIC_BASE_EXTD (1ULL << 10) /* x2APIC enable       */

/* x2APIC register MSRs = 0x800 + (xAPIC offset >> 4). */
#define X2APIC_SVR      0x80F
#define X2APIC_EOI      0x80B
#define X2APIC_LVT_TMR  0x832
#define X2APIC_TMR_INIT 0x838
#define X2APIC_TMR_CUR  0x839
#define X2APIC_TMR_DIV  0x83E

#define LAPIC_TMR_PERIODIC (1U << 17)
#define LAPIC_TMR_MASKED   (1U << 16)

/* PIT: channel 2 gated by port 0x61 bit 0; OUT2 readable at 0x61 bit 5. */
#define PIT_CHANNEL2 0x42
#define PIT_COMMAND  0x43
#define PIT_GATE     0x61
/* 1.193182 MHz PIT clock ticks in 10 ms. */
#define PIT_10MS_COUNT 11932

extern uint64_t KiTrapThunkTable[]; /* trap.S */

void KiEndOfInterrupt(void)
{
    KiWriteMsr(X2APIC_EOI, 0);
}

/* Count LAPIC timer ticks (divide-by-16) across one 10 ms PIT gate. */
static uint32_t KiCalibrateApicTimer(void)
{
    /* Gate high, speaker off; channel 2, lobyte/hibyte, mode 0 (one-shot,
     * OUT rises at terminal count). */
    KiOutByte(PIT_GATE, (uint8_t)((KiInByte(PIT_GATE) & 0xFC) | 0x01));
    KiOutByte(PIT_COMMAND, 0xB0);
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT & 0xFF);
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT >> 8);

    KiWriteMsr(X2APIC_TMR_DIV, 0x3); /* divide by 16 */
    KiWriteMsr(X2APIC_LVT_TMR, LAPIC_TMR_MASKED | TIMER_VECTOR);
    KiWriteMsr(X2APIC_TMR_INIT, 0xFFFFFFFFU);

    while ((KiInByte(PIT_GATE) & 0x20) == 0)
    {
    }

    uint32_t remaining = (uint32_t)KiReadMsr(X2APIC_TMR_CUR);
    KiWriteMsr(X2APIC_TMR_INIT, 0);        /* stop */
    return (0xFFFFFFFFU - remaining) / 10; /* ticks per 1 ms */
}

void KiInitializeClock(void)
{
    /* Mask both halves of the legacy 8259 PIC so no stray IRQ arrives on a
     * vector that overlaps a CPU exception. */
    KiOutByte(0x21, 0xFF);
    KiOutByte(0xA1, 0xFF);

    /* Enable xAPIC, then x2APIC (staged, as the SDM recommends). */
    uint64_t apicBase = KiReadMsr(IA32_APIC_BASE);
    apicBase |= APIC_BASE_EN;
    KiWriteMsr(IA32_APIC_BASE, apicBase);
    apicBase |= APIC_BASE_EXTD;
    KiWriteMsr(IA32_APIC_BASE, apicBase);

    /* Enable the LAPIC; route spurious interrupts to vector 0xFF. */
    KiWriteMsr(X2APIC_SVR, 0x100 | 0xFF);

    KiSetInterruptGate(TIMER_VECTOR, KiTrapThunkTable[TIMER_VECTOR]);

    uint32_t ticksPerMs = KiCalibrateApicTimer();
    if (ticksPerMs == 0)
    {
        KiPanic("KiInitializeClock: LAPIC timer calibration failed");
    }

    KiWriteMsr(X2APIC_TMR_DIV, 0x3);
    KiWriteMsr(X2APIC_LVT_TMR, TIMER_VECTOR | LAPIC_TMR_PERIODIC);
    KiWriteMsr(X2APIC_TMR_INIT, ticksPerMs); /* 1 ms period */

    __asm__ volatile("sti");
}
