/* arch/x86_64/lapic.c — Local APIC + periodic timer (M1), x2APIC mode.
 *
 * We use x2APIC (LAPIC registers via MSRs) rather than the xAPIC MMIO window:
 * the MMIO page at 0xFEE00000 is not in Limine's HHDM and we have no Mm to map
 * it until M5. MSR access sidesteps that entirely. The legacy 8259 PIC is
 * masked; interrupts come from the LAPIC.
 */
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io.h"

#include <stdint.h>

#define IA32_APIC_BASE 0x1B
#define APIC_BASE_EN   (1ULL << 11) /* xAPIC global enable */
#define APIC_BASE_EXTD (1ULL << 10) /* x2APIC enable       */

/* x2APIC register MSRs = 0x800 + (xAPIC offset >> 4). */
#define X2APIC_SVR      0x80F
#define X2APIC_EOI      0x80B
#define X2APIC_LVT_TMR  0x832
#define X2APIC_TMR_INIT 0x838
#define X2APIC_TMR_DIV  0x83E

#define LAPIC_TMR_PERIODIC (1u << 17)

extern uint64_t KiTrapThunkTable[]; /* trap.S */

volatile uint64_t KeTickCount;

void KiEndOfInterrupt(void)
{
    KiWriteMsr(X2APIC_EOI, 0);
}

void KiUpdateTickCount(void)
{
    KeTickCount++;
}

void KiInitializeTimer(void)
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

    KiWriteMsr(X2APIC_TMR_DIV, 0x3); /* divide by 16 */
    KiWriteMsr(X2APIC_LVT_TMR, TIMER_VECTOR | LAPIC_TMR_PERIODIC);
    KiWriteMsr(X2APIC_TMR_INIT, 1000000);

    __asm__ volatile("sti");
}
