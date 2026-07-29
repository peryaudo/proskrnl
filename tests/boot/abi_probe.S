/* tests/boot/abi_probe.S — the ABI probe's PE entry stub.
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
    pushfq                   /* rflags: the C body asserts DF clear */
    popq %rax
    movq %rax, abi_entry_rflags(%rip)
    subq $8, %rsp            /* entry rsp ≡ 8 (mod 16): re-align the call site */
    call abi_probe_main      /* SysV; the verdict comes back in %eax */
    movl %eax, %esi          /* exit status (LONG) */
    movq $-1, %rdi           /* NtCurrentProcess() == (HANDLE)~0 */
    call NtTerminateProcess
    ud2

/* The second-thread entry (the NtCreateThreadEx target): the kernel's thread
 * protocol enters with rcx = this routine, rdx = the argument
 * (kernel/ps/thread.c, the RtlUserThreadStart shape — third_party/wine
 * dlls/ntdll/signal_x86_64.c RtlUserThreadStart). Entry conventions hold for
 * EVERY thread, not just the first: capture the same state pe_start does,
 * then bridge to the SysV C body and exit the thread. */
    .global abi_thread_entry
abi_thread_entry:
    movq %rsp, abi_thread_rsp(%rip)
    stmxcsr abi_thread_mxcsr(%rip)
    fnstcw abi_thread_fcw(%rip)
    movq %rdx, %rdi          /* SysV arg1 = the thread argument */
    subq $8, %rsp            /* entry rsp ≡ 8 (mod 16): re-align the call site */
    call abi_thread_main
    xorl %esi, %esi          /* exit status 0 (LONG) */
    movq $-2, %rdi           /* NtCurrentThread() == (HANDLE)~1 */
    call NtTerminateThread
    ud2

    .section .data
    .global abi_entry_rsp
    .global abi_entry_rflags
    .global abi_entry_mxcsr
    .global abi_entry_fcw
    .global abi_thread_rsp
    .global abi_thread_mxcsr
    .global abi_thread_fcw
abi_entry_rsp:
    .quad 0
abi_entry_rflags:
    .quad 0
abi_thread_rsp:
    .quad 0
abi_entry_mxcsr:
    .long 0
abi_thread_mxcsr:
    .long 0
abi_entry_fcw:
    .word 0
abi_thread_fcw:
    .word 0

#ifdef __ELF__
    .section .note.GNU-stack, "", @progbits
#endif
