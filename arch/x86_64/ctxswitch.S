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
#define KTHREAD_FX_AREA      32

    .section .text
    .global KiSwapContext
KiSwapContext:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    /* M7: the x87/SSE state is part of a thread's context too — NT preserves
     * the MS-ABI nonvolatile XMM6-15 across syscalls/waits, and kernel code
     * (-mno-sse) never saves them per-call. FXSAVE/FXRSTOR image in KTHREAD
     * (Intel SDM Vol. 1 "FXSAVE Area"; offset pinned in kernel/ke/thread.c). */
    fxsave64 KTHREAD_FX_AREA(%rdi)
    mov %rsp, KTHREAD_KERNEL_STACK(%rdi)
    mov KTHREAD_KERNEL_STACK(%rsi), %rsp
    fxrstor64 KTHREAD_FX_AREA(%rsi)
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
