/* user/init-tests/crt0.S — the flat-binary entry stub for M4 user clients.
 *
 * The kernel enters at _start with a fresh stack (RSP = top of the user
 * stack region) and no arguments. We call main(), then exit the process with
 * its return value through NtTerminateProcess(NtCurrentProcess(), status) —
 * there is no ntdll to return into yet (that is M7). Placed in its own
 * section so user.ld can force it to image offset 0.
 */
    .section .text._start, "ax"
    .global _start
_start:
    xorq %rbp, %rbp        /* terminate stack traces */
    call main
    movl %eax, %esi        /* exit status (LONG, arg 2) */
    movq $-1, %rdi         /* NtCurrentProcess() pseudo-handle (arg 1) */
    call NtTerminateProcess
1:  hlt                    /* NtTerminateProcess never returns */
    jmp 1b

    .section .note.GNU-stack, "", @progbits
