/* arch/x86_64/idt.c — interrupt descriptor table (M1).
 *
 * Gate selector is the current %cs (whatever Limine handed us) so we need no
 * GDT of our own yet — a real GDT + TSS arrives with user mode at M4. */
#include "arch/x86_64/idt.h"

struct idt_entry {
    uint16_t off_lo;
    uint16_t sel;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t off_mid;
    uint32_t off_hi;
    uint32_t zero;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[256];
static uint16_t kernel_cs;

extern uint64_t isr_stub_table[]; /* trap.S */

void idt_set_gate(int vector, uint64_t handler)
{
    idt[vector].off_lo    = (uint16_t)(handler & 0xFFFF);
    idt[vector].sel       = kernel_cs;
    idt[vector].ist       = 0;
    idt[vector].type_attr = 0x8E; /* present, DPL 0, 64-bit interrupt gate */
    idt[vector].off_mid   = (uint16_t)((handler >> 16) & 0xFFFF);
    idt[vector].off_hi    = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    idt[vector].zero      = 0;
}

void idt_init(void)
{
    __asm__ volatile("mov %%cs, %0" : "=r"(kernel_cs));

    for (int i = 0; i < 32; i++) {
        idt_set_gate(i, isr_stub_table[i]);
    }

    struct idt_ptr ptr = { (uint16_t)(sizeof(idt) - 1), (uint64_t)(uintptr_t)idt };
    __asm__ volatile("lidt %0" : : "m"(ptr));
}
