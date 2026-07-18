/* arch/x86_64/trap.S — CPU exception entry stubs (vectors 0..31) + LAPIC timer.
 *
 * Each stub normalises the stack to a KTRAP_FRAME (trap.h): push a dummy error
 * code where the CPU does not, push the vector number, save the GP registers,
 * then call KiDispatchTrap with a pointer to the frame. Vectors that push a
 * hardware error code (8,10-14,17,21) use KI_TRAP_ERR; the rest KI_TRAP_NOERR.
 *
 * The error-code vector set is Intel SDM Vol. 3A, "Interrupt and Exception
 * Handling", exception summary table: #DF(8), #TS(10), #NP(11), #SS(12),
 * #GP(13), #PF(14), #AC(17), #CP(21) push an error code; all others do not.
 */
    .section .text

    .macro KI_TRAP_NOERR num
    .global KiTrap\num
KiTrap\num:
    pushq $0
    pushq $\num
    jmp KiTrapCommon
    .endm

    .macro KI_TRAP_ERR num
    .global KiTrap\num
KiTrap\num:
    pushq $\num
    jmp KiTrapCommon
    .endm

    KI_TRAP_NOERR 0
    KI_TRAP_NOERR 1
    KI_TRAP_NOERR 2
    KI_TRAP_NOERR 3
    KI_TRAP_NOERR 4
    KI_TRAP_NOERR 5
    KI_TRAP_NOERR 6
    KI_TRAP_NOERR 7
    KI_TRAP_ERR   8
    KI_TRAP_NOERR 9
    KI_TRAP_ERR   10
    KI_TRAP_ERR   11
    KI_TRAP_ERR   12
    KI_TRAP_ERR   13
    KI_TRAP_ERR   14
    KI_TRAP_NOERR 15
    KI_TRAP_NOERR 16
    KI_TRAP_ERR   17
    KI_TRAP_NOERR 18
    KI_TRAP_NOERR 19
    KI_TRAP_NOERR 20
    KI_TRAP_ERR   21
    KI_TRAP_NOERR 22
    KI_TRAP_NOERR 23
    KI_TRAP_NOERR 24
    KI_TRAP_NOERR 25
    KI_TRAP_NOERR 26
    KI_TRAP_NOERR 27
    KI_TRAP_NOERR 28
    KI_TRAP_NOERR 29
    KI_TRAP_NOERR 30
    KI_TRAP_NOERR 31
    KI_TRAP_NOERR 32          /* LAPIC timer IRQ (M1) */

KiTrapCommon:
    /* From ring 3 (M4): GS still holds the user TEB base; swap to the KPCR.
     * The CPU-pushed CS sits above the vector + error code slots. */
    testq $3, 24(%rsp)
    jz 1f
    swapgs
1:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    mov %rsp, %rdi          /* PKTRAP_FRAME */
    call KiDispatchTrap
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    add $16, %rsp          /* discard vector + error code */
    /* Returning to ring 3: give GS back to the user TEB base. */
    testq $3, 8(%rsp)
    jz 2f
    swapgs
2:
    iretq

    /* Table of stub addresses, indexed by vector, for idt.c. */
    .section .rodata
    .align 8
    .global KiTrapThunkTable
KiTrapThunkTable:
    .quad KiTrap0,  KiTrap1,  KiTrap2,  KiTrap3,  KiTrap4,  KiTrap5,  KiTrap6,  KiTrap7
    .quad KiTrap8,  KiTrap9,  KiTrap10, KiTrap11, KiTrap12, KiTrap13, KiTrap14, KiTrap15
    .quad KiTrap16, KiTrap17, KiTrap18, KiTrap19, KiTrap20, KiTrap21, KiTrap22, KiTrap23
    .quad KiTrap24, KiTrap25, KiTrap26, KiTrap27, KiTrap28, KiTrap29, KiTrap30, KiTrap31
    .quad KiTrap32
