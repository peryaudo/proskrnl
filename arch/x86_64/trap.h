/* arch/x86_64/trap.h — CPU trap frame (M1). Field order matches the push
 * sequence in trap.S: GP registers (R15..Rax), then vector + error code, then
 * the CPU-pushed interrupt frame. */
#ifndef PROSKRNL_ARCH_X86_64_TRAP_H
#define PROSKRNL_ARCH_X86_64_TRAP_H

#include <stdint.h>

typedef struct _KTRAP_FRAME
{
    uint64_t R15, R14, R13, R12, R11, R10, R9, R8;
    uint64_t Rbp, Rdi, Rsi, Rdx, Rcx, Rbx, Rax;
    uint64_t Vector;
    uint64_t ErrorCode;
    /* pushed by the CPU on interrupt/exception */
    uint64_t Rip, SegCs, EFlags, Rsp, SegSs;
} KTRAP_FRAME, *PKTRAP_FRAME;

void KiDispatchTrap(PKTRAP_FRAME TrapFrame);

#endif /* PROSKRNL_ARCH_X86_64_TRAP_H */
