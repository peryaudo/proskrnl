/* arch/x86_64/trap.h — CPU trap frame (M1). Field order matches the push
 * sequence in trap.S: GP registers (r15..rax), then vector + error code, then
 * the CPU-pushed interrupt frame. */
#ifndef PROSKRNL_ARCH_X86_64_TRAP_H
#define PROSKRNL_ARCH_X86_64_TRAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector;
    uint64_t errorCode;
    /* pushed by the CPU on interrupt/exception */
    uint64_t rip, segCs, eflags, rsp, segSs;
} KTRAP_FRAME, *PKTRAP_FRAME;

/* Both places trap.S asks "were we in ring 3?" name segCs by a raw %rsp
 * displacement, once before the GP pushes (24) and once after them (144). A
 * field inserted above segCs turns either test into a read of rip, and the
 * mistake is silent — which is precisely how the #VC/#SX error-code shift
 * (trap.S, KI_TRAP_ERR 29/30) survived. Weld both numbers here. */
_Static_assert(offsetof(KTRAP_FRAME, segCs) - offsetof(KTRAP_FRAME, vector) == 24,
               "trap.S KiTrapCommon: 24(%rsp) is segCs before the GP pushes");
_Static_assert(offsetof(KTRAP_FRAME, segCs) == 144,
               "trap.S KiTrapCommon: 144(%rsp) is segCs after the GP pushes");

void KiDispatchTrap(PKTRAP_FRAME trapFrame);

#endif /* PROSKRNL_ARCH_X86_64_TRAP_H */
