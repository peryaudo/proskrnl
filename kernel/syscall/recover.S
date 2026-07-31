/* kernel/syscall/recover.S — the ring-0 fault recovery frame (docs/05).
 *
 * A save/restore pair with setjmp shape, used by ONE caller: the system
 * service dispatcher (kernel/syscall/table.c), which arms a frame around
 * every ring-3-originated service call. When a service faults in ring 0 on a
 * user address — a missing or stale probe — KiDispatchTrap unwinds to that
 * frame with STATUS_ACCESS_VIOLATION instead of halting the machine. This is
 * how NT's dispatcher behaves too: KiSystemServiceHandler returns the
 * exception code as the service's status.
 *
 * Only the SysV callee-saved set (rbx, rbp, r12-r15) plus rsp/rip is saved;
 * the C caller re-derives everything else after the unwind (see table.c).
 * Constants cross-check: System V AMD64 ABI §3.2.1 "Registers and the Stack
 * Frame" (Table 3.4, register-saving rules).
 */

.section .text

/* ULONG KiSetFaultRecovery(KI_FAULT_RECOVERY *frame)
 * Returns 0 on the direct call, the unwind's status value on recovery. */
.globl KiSetFaultRecovery
.type KiSetFaultRecovery, @function
KiSetFaultRecovery:
    movq    (%rsp), %rax        /* our return address == the resume point */
    movq    %rax, 0(%rdi)
    leaq    8(%rsp), %rax       /* rsp as the caller will see it after ret */
    movq    %rax, 8(%rdi)
    movq    %rbx, 16(%rdi)
    movq    %rbp, 24(%rdi)
    movq    %r12, 32(%rdi)
    movq    %r13, 40(%rdi)
    movq    %r14, 48(%rdi)
    movq    %r15, 56(%rdi)
    xorl    %eax, %eax
    ret
.size KiSetFaultRecovery, . - KiSetFaultRecovery

/* void KiJumpFaultRecovery(KI_FAULT_RECOVERY *frame, ULONG value) — noreturn.
 * `value` must be nonzero so the resumed KiSetFaultRecovery reads as an
 * unwind rather than a direct call. */
.globl KiJumpFaultRecovery
.type KiJumpFaultRecovery, @function
KiJumpFaultRecovery:
    movl    %esi, %eax
    movq    16(%rdi), %rbx
    movq    24(%rdi), %rbp
    movq    32(%rdi), %r12
    movq    40(%rdi), %r13
    movq    48(%rdi), %r14
    movq    56(%rdi), %r15
    movq    0(%rdi), %rcx       /* resume rip, read before rsp moves */
    movq    8(%rdi), %rsp
    jmp     *%rcx
.size KiJumpFaultRecovery, . - KiJumpFaultRecovery

.section .note.GNU-stack, "", @progbits
