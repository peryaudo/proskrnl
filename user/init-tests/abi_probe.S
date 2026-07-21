/* user/init-tests/abi_probe.S — the ABI probe's PE entry stub.
 *
 * Captures the machine state the entry-convention checks assert BEFORE any
 * compiler-generated code can disturb it:
 *
 *   - the entry RSP: NT enters a thread like a called function, so rsp must
 *     be ≡ 8 (mod 16) — "the stack will always be maintained 16-byte
 *     aligned, except within the prolog (for example, after the return
 *     address is pushed)" (MS Learn, "x64 stack usage"); Wine builds the
 *     initial frame as context.Rsp = StackBase - 0x28 (third_party/wine
 *     dlls/ntdll/unix/signal_x86_64.c init_syscall_frame).
 *
 *   - the x87 control word and MXCSR the thread's first FXRSTOR seeded:
 *     the MS x64 calling convention pins their standard values "at the
 *     start of program execution" (MS Learn, "x64 calling convention",
 *     FPCSR/MXCSR sections), and Wine seeds new-thread CONTEXTs with
 *     exactly FCW=0x27f / MxCsr=0x1f80 (dlls/ntdll/unix/signal_x86_64.c
 *     init_syscall_frame). The C body compares against those values.
 *
 * Then it bridges to the SysV C body (PECFLAGS -mabi=sysv, like the other
 * init-tests PE clients) and exits with its verdict.
 */
    .section .text
    .global pe_start
pe_start:
    movq %rsp, abi_entry_rsp(%rip)
    stmxcsr abi_entry_mxcsr(%rip)
    fnstcw abi_entry_fcw(%rip)
    subq $8, %rsp            /* entry rsp ≡ 8 (mod 16): re-align the call site */
    call abi_probe_main      /* SysV; the verdict comes back in %eax */
    movl %eax, %esi          /* exit status (LONG) */
    movq $-1, %rdi           /* NtCurrentProcess() == (HANDLE)~0 */
    call NtTerminateProcess
    ud2

    .section .data
    .global abi_entry_rsp
    .global abi_entry_mxcsr
    .global abi_entry_fcw
abi_entry_rsp:
    .quad 0
abi_entry_mxcsr:
    .long 0
abi_entry_fcw:
    .word 0

#ifdef __ELF__
    .section .note.GNU-stack, "", @progbits
#endif
