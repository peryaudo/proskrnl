/* arch/x86_64/ctxswitch.S — kernel thread context switch (M2).
 *
 *     void KiSwapContext(PKTHREAD oldThread [rdi], PKTHREAD newThread [rsi])
 *
 * Called and returns with the dispatcher lock held (interrupts disabled), so
 * only the SysV callee-saved registers + RSP form a context; everything else
 * is dead across the call by the C ABI. The saved RSP lives at a fixed offset
 * inside KTHREAD, pinned by a _Static_assert in kernel/ke/thread.c. A new
 * thread's stack is pre-built by KiCreateThread so that the pops + ret below
 * land in KiThreadStartup.
 */
#define KTHREAD_KERNEL_STACK 24

    .section .text
    .global KiSwapContext
KiSwapContext:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, KTHREAD_KERNEL_STACK(%rdi)
    mov KTHREAD_KERNEL_STACK(%rsi), %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
