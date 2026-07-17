/* kernel/syscall/entry.S — the syscall/sysret boundary crossing (M4).
 *
 * User-side convention (tests/ntapi/syscall/syscall_stubs.S): number in eax,
 * arguments 1-6 in rdi/rsi/rdx/r10/r8/r9 (rcx is destroyed by the syscall
 * instruction), argument 7 on the caller's stack at [rsp+8]. NTSTATUS back
 * in eax.
 *
 * syscall does not switch stacks, so the stub below must: it saves the user
 * RSP into the KPCR scratch slot (safe: SFMASK cleared IF, and the KPCR is
 * per-CPU on a uniprocessor), loads the current thread's kernel stack, and
 * builds a small frame holding the sysret state (user RSP / RIP / RFLAGS)
 * plus the six register arguments, which KiSystemService receives as an
 * array. Interrupts are enabled only after the switch — a blocked syscall
 * (NtWaitFor*) later resumes here through the ordinary context switch path.
 */
#include "arch/x86_64/gdt.h"

#define KIPCR_KERNEL_RSP 0
#define KIPCR_USER_RSP   8

    .section .text
    .global KiSystemCall64
KiSystemCall64:
    swapgs
    movq %rsp, %gs:KIPCR_USER_RSP
    movq %gs:KIPCR_KERNEL_RSP, %rsp

    pushq %gs:KIPCR_USER_RSP    /* the sysret frame: user RSP ...           */
    pushq %rcx                  /* ... user RIP                              */
    pushq %r11                  /* ... user RFLAGS                           */
    subq $8, %rsp               /* pad: 10 slots total keeps the call 16-aligned */
    pushq %r9                   /* args[5] */
    pushq %r8                   /* args[4] */
    pushq %r10                  /* args[3] */
    pushq %rdx                  /* args[2] */
    pushq %rsi                  /* args[1] */
    pushq %rdi                  /* args[0] */

    movq %rax, %rdi             /* number */
    movq %rsp, %rsi             /* args array */
    movq %gs:KIPCR_USER_RSP, %rdx /* user RSP (stack-passed argument 7) */
    sti
    call KiSystemService
    cli

    addq $56, %rsp              /* drop args + pad */
    popq %r11                   /* user RFLAGS */
    popq %rcx                   /* user RIP */
    popq %rsp                   /* user RSP */
    swapgs
    sysretq

/* void KiEnterUserMode(uint64_t rip [rdi], uint64_t rsp [rsi])
 *
 * First descent into ring 3 (kernel/ps). Builds an iretq frame for the user
 * selectors (gdt.h) with IF set; KERNEL_GS_BASE already holds the thread's
 * TEB (context-switch hook), so the swapgs hands GS to user correctly. The
 * kernel stack contents above are abandoned — the next kernel entry restarts
 * from the stack top. */
    .global KiEnterUserMode
KiEnterUserMode:
    cli
    pushq $(KI_GDT_USER_DS | 3) /* SS */
    pushq %rsi                  /* RSP */
    pushq $0x202                /* RFLAGS: IF | reserved-1 */
    pushq $(KI_GDT_USER_CS | 3) /* CS */
    pushq %rdi                  /* RIP */
    swapgs
    iretq
