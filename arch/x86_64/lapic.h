/* arch/x86_64/lapic.h — Local APIC + its periodic timer (M1). */
#ifndef PROSKRNL_ARCH_X86_64_LAPIC_H
#define PROSKRNL_ARCH_X86_64_LAPIC_H

#include <stdint.h>

#define TIMER_VECTOR 32

/* Enable the LAPIC (x2APIC / MSR access — no MMIO mapping needed), mask the
 * legacy 8259 PIC, install the timer gate, and start the periodic timer. */
void timer_init(void);

/* Signal end-of-interrupt to the LAPIC (called from the timer handler). */
void lapic_eoi(void);

/* Monotonic tick counter and its bump (from the timer interrupt). */
uint64_t timer_ticks(void);
void     timer_tick(void);

#endif /* PROSKRNL_ARCH_X86_64_LAPIC_H */
