/* arch/x86_64/lapic.h — Local APIC + its periodic timer (M1). */
#ifndef PROSKRNL_ARCH_X86_64_LAPIC_H
#define PROSKRNL_ARCH_X86_64_LAPIC_H

#include <stdint.h>

#define TIMER_VECTOR 32

/* Monotonic tick counter, bumped by the timer interrupt (NT's KeTickCount). */
extern volatile uint64_t KeTickCount;

/* Enable the LAPIC (x2APIC / MSR access — no MMIO mapping needed), mask the
 * legacy 8259 PIC, install the timer gate, and start the periodic timer. */
void HalpInitializeTimer(void);

/* Signal end-of-interrupt to the LAPIC (called from the timer handler). */
void HalpEndOfInterrupt(void);

/* Advance KeTickCount (called from the timer interrupt). */
void KiUpdateTickCount(void);

#endif /* PROSKRNL_ARCH_X86_64_LAPIC_H */
