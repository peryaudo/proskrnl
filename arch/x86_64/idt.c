/* arch/x86_64/idt.c — interrupt descriptor table (M1).
 *
 * Gate selector is the current %cs (whatever Limine handed us) so we need no
 * GDT of our own yet — a real GDT + TSS arrives with user mode at M4. */
#include "arch/x86_64/idt.h"

typedef struct _KIDTENTRY
{
    uint16_t OffsetLow;
    uint16_t Selector;
    uint8_t Ist;
    uint8_t TypeAttributes;
    uint16_t OffsetMiddle;
    uint32_t OffsetHigh;
    uint32_t Reserved;
} __attribute__((packed)) KIDTENTRY, *PKIDTENTRY;

typedef struct _KDESCRIPTOR
{
    uint16_t Limit;
    uint64_t Base;
} __attribute__((packed)) KDESCRIPTOR;

static KIDTENTRY KiIdt[256];
static uint16_t KiKernelCs;

extern uint64_t KiTrapThunkTable[]; /* trap.S */

void KiSetInterruptGate(int Vector, uint64_t Handler)
{
    KiIdt[Vector].OffsetLow = (uint16_t)(Handler & 0xFFFF);
    KiIdt[Vector].Selector = KiKernelCs;
    KiIdt[Vector].Ist = 0;
    KiIdt[Vector].TypeAttributes = 0x8E; /* present, DPL 0, 64-bit interrupt gate */
    KiIdt[Vector].OffsetMiddle = (uint16_t)((Handler >> 16) & 0xFFFF);
    KiIdt[Vector].OffsetHigh = (uint32_t)((Handler >> 32) & 0xFFFFFFFF);
    KiIdt[Vector].Reserved = 0;
}

void KiInitializeIdt(void)
{
    __asm__ volatile("mov %%cs, %0" : "=r"(KiKernelCs));

    for (int Vector = 0; Vector < 32; Vector++)
    {
        KiSetInterruptGate(Vector, KiTrapThunkTable[Vector]);
    }

    KDESCRIPTOR Descriptor = {(uint16_t)(sizeof(KiIdt) - 1), (uint64_t)(uintptr_t)KiIdt};
    __asm__ volatile("lidt %0" : : "m"(Descriptor));
}
