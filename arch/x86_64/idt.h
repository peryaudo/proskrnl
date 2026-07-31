/* arch/x86_64/idt.h — interrupt descriptor table (M1). */
#ifndef PROSKRNL_ARCH_X86_64_IDT_H
#define PROSKRNL_ARCH_X86_64_IDT_H

#include <stdint.h>

/* Install the CPU exception vectors (0..31) and load the IDT. */
void KiInitializeIdt(void);

/* Set one 64-bit interrupt gate, DPL 0: only the CPU may deliver it, and an
 * `int N` from ring 3 raises #GP instead. Used by KiInitializeIdt and by the
 * timer. */
void KiSetInterruptGate(int vector, uint64_t handler);

/* Same, DPL 3: ring 3 may raise this vector with an `int` instruction. Only
 * the software-interrupt exceptions get it -- see KiInitializeIdt. */
void KiSetUserInterruptGate(int vector, uint64_t handler);

/* Same, with a nonzero IST slot: deliver on TSS.IST[ist] regardless of the
 * interrupted stack (gdt.c owns the stacks; #DF uses KI_IST_DOUBLE_FAULT). */
void KiSetInterruptGateIst(int vector, uint64_t handler, uint8_t ist);

/* The LAPIC spurious-interrupt vector, and the handler arch/x86_64/trap.S
 * supplies for it (arch/x86_64/lapic.c programs the SVR with both). */
#define KI_SPURIOUS_VECTOR 0xFF
void KiSpuriousInterruptThunk(void);

#endif /* PROSKRNL_ARCH_X86_64_IDT_H */
