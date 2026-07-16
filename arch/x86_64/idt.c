/* arch/x86_64/idt.c — interrupt descriptor table (M1).
 *
 * Gate selector is the current %cs (whatever Limine handed us) so we need no
 * GDT of our own yet — a real GDT + TSS arrives with user mode at M4. */
#include "arch/x86_64/idt.h"

typedef struct _KIDTENTRY
{
    uint16_t offsetLow;
    uint16_t selector;
    uint8_t ist;
    uint8_t typeAttributes;
    uint16_t offsetMiddle;
    uint32_t offsetHigh;
    uint32_t reserved;
} __attribute__((packed)) KIDTENTRY, *PKIDTENTRY;

typedef struct _KDESCRIPTOR
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) KDESCRIPTOR;

static KIDTENTRY KiIdt[256];
static uint16_t KiKernelCs;

extern uint64_t KiTrapThunkTable[]; /* trap.S */

void KiSetInterruptGate(int vector, uint64_t handler)
{
    KiIdt[vector].offsetLow = (uint16_t)(handler & 0xFFFF);
    KiIdt[vector].selector = KiKernelCs;
    KiIdt[vector].ist = 0;
    KiIdt[vector].typeAttributes = 0x8E; /* present, DPL 0, 64-bit interrupt gate */
    KiIdt[vector].offsetMiddle = (uint16_t)((handler >> 16) & 0xFFFF);
    KiIdt[vector].offsetHigh = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    KiIdt[vector].reserved = 0;
}

void KiInitializeIdt(void)
{
    __asm__ volatile("mov %%cs, %0" : "=r"(KiKernelCs));

    for (int vector = 0; vector < 32; vector++)
    {
        KiSetInterruptGate(vector, KiTrapThunkTable[vector]);
    }

    KDESCRIPTOR descriptor = {(uint16_t)(sizeof(KiIdt) - 1), (uint64_t)(uintptr_t)KiIdt};
    __asm__ volatile("lidt %0" : : "m"(descriptor));
}
