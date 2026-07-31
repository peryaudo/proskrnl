/* arch/x86_64/idt.c — interrupt descriptor table (M1).
 *
 * Gate selector is the current %cs (whatever Limine handed us) so we need no
 * GDT of our own yet — a real GDT + TSS arrives with user mode at M4.
 *
 * Constants cross-check: Intel SDM Vol. 3A, "Interrupt and Exception
 * Handling" — the 16-byte 64-bit IDT gate descriptor layout and its
 * type/attribute byte (0x8E = present, DPL 0, 64-bit interrupt gate). */
#include "arch/x86_64/idt.h"
#include "arch/x86_64/gdt.h"
#include "kernel/init/panic.h"

typedef struct
{
    uint16_t offsetLow;
    uint16_t selector;
    uint8_t ist;
    uint8_t typeAttributes;
    uint16_t offsetMiddle;
    uint32_t offsetHigh;
    uint32_t reserved;
} __attribute__((packed)) KIDTENTRY, *PKIDTENTRY;

typedef struct
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) KDESCRIPTOR;

static KIDTENTRY KiIdt[256];
static uint16_t KiKernelCs;

extern uint64_t KiTrapThunkTable[]; /* trap.S */

/* The gate's IST byte: bits 2:0 select TSS.IST[n] (nonzero n = switch to
 * that stack on delivery, 0 = legacy stack switching) — Intel SDM Vol. 3A
 * §6.14.4 "Stack Switching in IA-32e Mode" / Figure 6-8 (64-Bit IDT Gate
 * Descriptors). */
static void KiSetGate(int vector, uint64_t handler, uint8_t ist, uint8_t typeAttributes)
{
    ASSERT(vector >= 0 && vector < 256);
    ASSERT(handler != 0);
    ASSERT(ist <= 7);
    KiIdt[vector].offsetLow = (uint16_t)(handler & 0xFFFF);
    KiIdt[vector].selector = KiKernelCs;
    KiIdt[vector].ist = ist;
    KiIdt[vector].typeAttributes = typeAttributes;
    KiIdt[vector].offsetMiddle = (uint16_t)((handler >> 16) & 0xFFFF);
    KiIdt[vector].offsetHigh = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    KiIdt[vector].reserved = 0;
}

void KiSetInterruptGateIst(int vector, uint64_t handler, uint8_t ist)
{
    KiSetGate(vector, handler, ist, 0x8E); /* present, DPL 0, 64-bit interrupt gate */
}

void KiSetInterruptGate(int vector, uint64_t handler)
{
    KiSetInterruptGateIst(vector, handler, 0);
}

void KiSetUserInterruptGate(int vector, uint64_t handler)
{
    /* 0xEE = present, DPL 3, 64-bit interrupt gate -- the same descriptor as
     * 0x8E with the DPL field (bits 6:5 of the type/attribute byte) set to 3
     * (Intel SDM Vol. 3A Figure 6-8, "64-Bit IDT Gate Descriptors"). The
     * gate's DPL is what the CPU checks for a SOFTWARE interrupt, i.e. an
     * `int N` executed by the program; hardware and fault delivery ignore
     * it. */
    KiSetGate(vector, handler, 0, 0xEE);
}

void KiInitializeIdt(void)
{
    __asm__ volatile("mov %%cs, %0" : "=r"(KiKernelCs));

    for (int vector = 0; vector < 32; vector++)
    {
        KiSetInterruptGate(vector, KiTrapThunkTable[vector]);
    }
    /* #BP (3) and #OF (4) are the two exceptions ring 3 raises DELIBERATELY,
     * with `int3` and `into`, so their gates are DPL 3 -- as they are on
     * Windows. At DPL 0 an `int3` from ring 3 raises #GP instead of #BP, so
     * every DbgBreakPoint / __debugbreak / CRT assert in the Wine stack died
     * as STATUS_ACCESS_VIOLATION and KiUserFaultStatus's
     * `case 3: return STATUS_BREAKPOINT;` was unreachable
     * (docs/review-2026-07 §8). The other half of that fix is in
     * KiDispatchTrap, which must not swallow a ring-3 #BP as the M1 demo. */
    KiSetUserInterruptGate(3, KiTrapThunkTable[3]);
    KiSetUserInterruptGate(4, KiTrapThunkTable[4]);
    /* #DF rides its own IST stack: after a kernel-stack overflow the faulted
     * stack is unusable, and without the switch delivery escalates to a
     * silent triple-fault reset — no dump at all. #DF always pushes error
     * code 0 (SDM Vol. 3A §6.15), so trap.S's vector-8 stub already fits. */
    KiSetInterruptGateIst(8, KiTrapThunkTable[8], KI_IST_DOUBLE_FAULT);

    KDESCRIPTOR descriptor = {(uint16_t)(sizeof(KiIdt) - 1), (uint64_t)(uintptr_t)KiIdt};
    __asm__ volatile("lidt %0" : : "m"(descriptor));
}
