/* user/hello/hello_seh.S — the guarded region for the M7 SEH acceptance.
 *
 * mingw-gcc has no __try/__except, so the exact frame such a construct
 * compiles to is written by hand: a function with .seh_ unwind directives and
 * a `.seh_handler <handler>, @except` record in the image's .pdata/.xdata.
 * The deliberate store through NULL faults; the kernel delivers the AV to
 * ntdll's KiUserExceptionDispatcher; RtlDispatchException unwinds .pdata to
 * hello_seh_handler (hello.c), which resumes at hello_seh_resume — the same
 * path a real __except(EXCEPTION_EXECUTE_HANDLER)/continue takes. The frame
 * shape (push rbp / setframe) mirrors Wine's own hand-written .seh_ users
 * (third_party/wine dlls/ntdll/signal_x86_64.c process_breakpoint).
 */
    .text
    .globl hello_trigger_seh
    .globl hello_seh_resume
    .def hello_trigger_seh; .scl 2; .type 32; .endef
    .seh_proc hello_trigger_seh
hello_trigger_seh:
    pushq %rbp
    .seh_pushreg %rbp
    movq %rsp, %rbp
    .seh_setframe %rbp, 0
    .seh_endprologue
    .seh_handler hello_seh_handler, @except
    xorl %eax, %eax          /* return 0 if the fault falls through */
    movl $1, (%rax)          /* write to NULL -> STATUS_ACCESS_VIOLATION */
    jmp 1f                   /* not reached: the handler skips to resume */
hello_seh_resume:
    movl $1, %eax            /* resumed by the handler: caught */
1:
    popq %rbp
    ret
    .seh_endproc
