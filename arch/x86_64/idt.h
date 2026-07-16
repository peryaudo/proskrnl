/* arch/x86_64/idt.h — interrupt descriptor table (M1). */
#ifndef PROSKRNL_ARCH_X86_64_IDT_H
#define PROSKRNL_ARCH_X86_64_IDT_H

#include <stdint.h>

/* Install the CPU exception vectors (0..31) and load the IDT. */
void idt_init(void);

/* Set one 64-bit interrupt gate. Used by idt_init and later by the timer. */
void idt_set_gate(int vector, uint64_t handler);

#endif /* PROSKRNL_ARCH_X86_64_IDT_H */
