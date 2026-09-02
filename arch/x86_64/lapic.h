/* arch/x86_64/lapic.h — Local APIC + the periodic clock interrupt (M1/M2). */
#ifndef PROSKRNL_ARCH_X86_64_LAPIC_H
#define PROSKRNL_ARCH_X86_64_LAPIC_H

#include <stdint.h>

#define TIMER_VECTOR 32

/* virtio-blk completion vector (docs/19 §11a): the next free vector above
 * the timer — Intel SDM Vol. 3A §6.2 reserves vectors 0-31 for exceptions.
 * Edge-delivered by MSI-X straight to the LAPIC; no IOAPIC, no sharing. */
#define BLK_VECTOR 33

/* MSI message address/data (Intel SDM Vol. 3A §11.11.1 / §11.11.2):
 * address 0xFEE00000 targets the LAPIC, destination ID 0 in bits 19:12
 * (the BSP — the only CPU, docs/18), RH=DM=0 physical destination; data is
 * the vector number with fixed delivery mode (bits 10:8 = 0) and edge
 * trigger (bit 15 = 0). Cross-check: pinned QEMU hw/pci/msix.c delivers
 * the entry's address/data verbatim via msi_send_message. */
#define KI_MSI_MESSAGE_ADDRESS      0xFEE00000u
#define KI_MSI_MESSAGE_DATA(vector) ((uint32_t)(vector))

/* Put the LAPIC in xAPIC mode and map its register window, mask the legacy
 * 8259 PIC, calibrate the LAPIC timer against the PIT, start it periodic at
 * 1 ms, and enable interrupts. The tick lands in kernel/ke/timer.c
 * (KiUpdateClock) via kernel/ke/irq.c. */
void KiInitializeClock(void);

/* Signal end-of-interrupt to the LAPIC. */
void KiEndOfInterrupt(void);

/* The physical base of the LAPIC register window as IA32_APIC_BASE names it
 * right now (the same read KiInitializeClock mapped the window from). The
 * firmware describes the same window in the MADT (arch/x86_64/acpi.c), and
 * tests/kmt/acpi.c holds the two to agreement. */
uint64_t KiLocalApicPhysicalAddress(void);

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
