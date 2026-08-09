/* arch/x86_64/lapic.h — Local APIC + the periodic clock interrupt (M1/M2). */
#ifndef PROSKRNL_ARCH_X86_64_LAPIC_H
#define PROSKRNL_ARCH_X86_64_LAPIC_H

#include <stdint.h>

#define TIMER_VECTOR 32

/* Put the LAPIC in xAPIC mode and map its register window, mask the legacy
 * 8259 PIC, calibrate the LAPIC timer against the PIT, start it periodic at
 * 1 ms, and enable interrupts. The tick lands in kernel/ke/timer.c
 * (KiUpdateClock) via kernel/ke/irq.c. */
void KiInitializeClock(void);

/* Signal end-of-interrupt to the LAPIC. */
void KiEndOfInterrupt(void);

/* TSC cycles per millisecond, measured across the SAME PIT gate the LAPIC
 * timer is calibrated on, and 0 until KiInitializeClock has run. It is the
 * conversion kernel/ke/timer.c interpolates the 1 ms tick with, so that the
 * system clock has sub-tick resolution (docs/03 "Sub-tick system time"); the
 * clock stays the tick's, this only subdivides it. */
extern uint64_t KiTscPerMillisecond;

/* Read the TSC in program order. RDTSC is not a serializing instruction and
 * the processor may execute it ahead of preceding instructions, so two reads
 * can retire out of order and appear to go BACKWARDS — Intel SDM Vol. 2B,
 * RDTSC, "Serializing Instruction" note, which prescribes LFENCE before the
 * read when the order matters. It matters here: the interpolated clock is
 * pinned monotone (tests/ntapi/sem_ps/precise_time.c). */
static inline uint64_t KiReadTimestampCounter(void)
{
    /* LFENCE as inline asm, not __builtin_ia32_lfence: the kernel is built
     * -mno-sse2 and the builtin is gated on that feature, while the
     * instruction itself is unconditionally available on x86-64. */
    __asm__ volatile("lfence" ::: "memory");
    return __builtin_ia32_rdtsc();
}

#endif /* PROSKRNL_ARCH_X86_64_LAPIC_H */
