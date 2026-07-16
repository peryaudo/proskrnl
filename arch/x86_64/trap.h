/* arch/x86_64/trap.h — CPU trap frame (M1). Field order matches the push
 * sequence in trap.S: GP registers (r15..rax), then vector + error code, then
 * the CPU-pushed interrupt frame. */
#ifndef PROSKRNL_ARCH_X86_64_TRAP_H
#define PROSKRNL_ARCH_X86_64_TRAP_H

#include <stdint.h>

struct trap_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector;
    uint64_t error_code;
    /* pushed by the CPU on interrupt/exception */
    uint64_t rip, cs, rflags, rsp, ss;
};

void trap_handler(struct trap_frame *tf);

#endif /* PROSKRNL_ARCH_X86_64_TRAP_H */
