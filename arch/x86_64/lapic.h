/* arch/x86_64/lapic.h — Local APIC + the periodic clock interrupt (M1/M2). */
#ifndef PROSKRNL_ARCH_X86_64_LAPIC_H
#define PROSKRNL_ARCH_X86_64_LAPIC_H

#define TIMER_VECTOR 32

/* Put the LAPIC in xAPIC mode and map its register window, mask the legacy
 * 8259 PIC, calibrate the LAPIC timer against the PIT, start it periodic at
 * 1 ms, and enable interrupts. The tick lands in kernel/ke/timer.c
 * (KiUpdateClock) via kernel/ke/irq.c. */
void KiInitializeClock(void);

/* Signal end-of-interrupt to the LAPIC. */
void KiEndOfInterrupt(void);

#endif /* PROSKRNL_ARCH_X86_64_LAPIC_H */
