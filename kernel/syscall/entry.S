/* kernel/syscall/entry.S — the syscall/sysret boundary crossing (M4; the
 * NT x64 convention + full-frame return at M7).
 *
 * As of M7 the kernel speaks the SAME syscall convention Wine's PE ntdll
 * thunks emit (third_party/wine include/wine/asm.h __ASM_SYSCALL_FUNC):
 * number in eax, arguments 1-4 in r10/rdx/r8/r9 (rcx is destroyed by the
 * syscall instruction, so the caller moves it to r10), arguments 5+ on the
 * user stack at [rsp+0x28+8n] (the Windows caller frame: a return address
 * plus four home/shadow slots), NTSTATUS back in eax.
 *
 * syscall does not switch stacks, so the stub below must: it saves the user
 * RSP into the KPCR scratch slot (safe: SFMASK cleared IF, and the KPCR is
 * per-CPU on a uniprocessor), loads the current thread's kernel stack, and
 * then SYNTHESIZES a full KTRAP_FRAME (arch/x86_64/trap.h) — the same shape
 * the CPU builds for an interrupt — so a single return path can restore
 * every register with iretq. That is what makes the M7 user-mode return
 * protocol expressible: NtContinue / the exception dispatcher just rewrite
 * this frame and let the iretq deliver the new context (KiUserException
 * Dispatcher / KiUserApcDispatcher), which a bare sysret (rcx/r11/rsp only)
 * cannot do. A blocked syscall (NtWaitFor*) still resumes here through the
 * ordinary context switch, then returns through the same iretq.
 */
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/kipcr.inc"


/* The synthetic trap-frame vector marking a syscall entry (>= 32, so it is
 * never confused with a CPU exception vector; not delivered anywhere). */
#define KI_SYSCALL_VECTOR 0x100

    .section .text
    .global KiSystemCall64
KiSystemCall64:
    swapgs
    movq %rsp, %gs:KIPCR_USER_RSP
    movq %gs:KIPCR_KERNEL_RSP, %rsp

    /* Synthesize the CPU interrupt frame (ss, rsp, rflags, cs, rip). syscall
     * left the user RIP in rcx and the user RFLAGS in r11. */
    pushq $(KI_GDT_USER_DS | 3)  /* ss */
    pushq %gs:KIPCR_USER_RSP     /* user rsp */
    pushq %r11                   /* rflags */
    pushq $(KI_GDT_USER_CS | 3)  /* cs */
    pushq %rcx                   /* rip */

    /* vector + error code, matching trap.S's order (vector at the lower
     * address). No hardware error code for a syscall. */
    pushq $0                     /* errorCode */
    pushq $KI_SYSCALL_VECTOR     /* vector */

    /* GP registers, in KTRAP_FRAME order (rax highest .. r15 lowest). */
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, %rdi              /* PKTRAP_FRAME */
    sti
    call KiSystemServiceTrap
    cli

    /* A service that terminated / rescheduled the thread never returns here;
     * one that blocked resumes here after the context switch. Fall into the
     * common ring-transition return. */
    .global KiReturnToUser
KiReturnToUser:
    /* Before the pops: the macro needs a scratch register, and every GPR is
     * still on the stack here — doing it after would hand user mode a
     * clobbered RAX (i.e. the syscall's return value). */
    KI_LOAD_USER_SEGMENTS
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp              /* drop vector + error code */
    swapgs                      /* returning to ring 3: restore user GS */
    iretq

/* void KiEnterUserMode(uint64_t rip [rdi], uint64_t rsp [rsi],
 *                      uint64_t arg1 [rdx], uint64_t arg2 [rcx])
 *
 * First descent into ring 3 (kernel/ps). Builds an iretq frame for the user
 * selectors (gdt.h) with IF set, and seeds rcx/rdx with the thread's start
 * arguments (rcx=arg1, rdx=arg2 — for a native client the entry argument;
 * for the M7 Wine path, &CONTEXT). KERNEL_GS_BASE already holds the thread's
 * TEB (context-switch hook), so the swapgs hands GS to user correctly. The
 * kernel stack contents above are abandoned — the next kernel entry restarts
 * from the stack top. */
    .global KiEnterUserMode
KiEnterUserMode:
    cli
    movq %rdx, %rax            /* arg1 (rdx clobbered below) */
    pushq $(KI_GDT_USER_DS | 3) /* SS */
    pushq %rsi                  /* RSP */
    pushq $0x202                /* RFLAGS: IF (bit 9) | always-1 bit 1 (SDM Vol. 1, EFLAGS) */
    pushq $(KI_GDT_USER_CS | 3) /* CS */
    pushq %rdi                  /* RIP */
    movq %rcx, %rdx            /* user rdx = arg2 */
    movq %rax, %rcx            /* user rcx = arg1 */
    KI_LOAD_USER_SEGMENTS      /* clobbers eax; the zeroing below follows */
    xorl %eax, %eax
    xorl %ebx, %ebx
    xorl %esi, %esi
    xorl %edi, %edi
    xorl %ebp, %ebp
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    xorl %r10d, %r10d
    xorl %r11d, %r11d
    xorl %r12d, %r12d
    xorl %r13d, %r13d
    xorl %r14d, %r14d
    xorl %r15d, %r15d
    swapgs
    iretq
