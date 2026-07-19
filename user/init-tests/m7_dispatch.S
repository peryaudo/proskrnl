/* user/init-tests/m7_dispatch.S — the M7 native client's ring-3 dispatchers.
 *
 * The kernel enters these exactly as it enters Wine's PE ntdll dispatchers
 * (kernel/ps/usermode.c): the register/stack contract is the NT one, but the
 * client's C code is built -mabi=sysv (like the M5 pe_smoke client), so these
 * thin stubs bridge the two conventions. They are PE exports so the loader
 * resolves them from the image's export table (the same mechanism that finds
 * the dispatchers in ntdll) — see kernel/ps/process.c PspResolveUserDispatchers.
 */
    .section .text

/* KiUserExceptionDispatcher: entered with rcx = PEXCEPTION_RECORD, rdx =
 * PCONTEXT (kernel/ps/usermode.c KiEnterUserExceptionDispatcher). Call the
 * SysV C handler m7_handle_exception(rec, ctx); it does not return (it calls
 * NtContinue). */
    .global KiUserExceptionDispatcher
KiUserExceptionDispatcher:
    movq %rcx, %rdi          /* EXCEPTION_RECORD* */
    movq %rdx, %rsi          /* CONTEXT* */
    call m7_handle_exception
    ud2                      /* the handler NtContinue's away; never returns */

/* KiUserApcDispatcher: entered with rcx = normalRoutine, rdx/r8/r9 = the three
 * APC arguments, and the saved CONTEXT at [rsp] (kernel/ps/usermode.c
 * KiDeliverUserApc). Run the routine (SysV) then NtContinue back to the saved
 * context. */
    .global KiUserApcDispatcher
KiUserApcDispatcher:
    movq %rsp, %rbx          /* &CONTEXT (callee-saved across the call) */
    movq %rcx, %rax          /* normalRoutine */
    movq %rdx, %rdi          /* arg1 */
    movq %r8, %rsi           /* arg2 */
    movq %r9, %rdx           /* arg3 */
    call *%rax
    movq %rbx, %rdi          /* CONTEXT* */
    xorl %esi, %esi          /* testAlert = FALSE */
    call NtContinue
    ud2

/* void m7_trigger_av(void): store through a null pointer to raise a #PF. The
 * kernel delivers it to KiUserExceptionDispatcher; the handler rewrites the
 * saved CONTEXT's Rip to m7_av_resume, so NtContinue lands on the ret and the
 * call returns normally to the C caller. Both symbols are global so the C
 * handler can name the resume address. */
    .global m7_trigger_av
    .global m7_av_resume
m7_trigger_av:
    xorq %rax, %rax
    movl $1, (%rax)          /* write to 0 -> access violation */
m7_av_resume:
    ret

/* void m7_thread_entry(void): a new thread's ring-3 entry. The kernel's thread
 * loader protocol (kernel/ps/thread.c) enters here with rcx = this routine and
 * rdx = the NtCreateThreadEx argument; bridge to SysV, run the C body, then
 * exit the thread. */
    .global m7_thread_entry
m7_thread_entry:
    movq %rdx, %rdi          /* SysV arg1 = the thread argument */
    call m7_thread_main      /* void m7_thread_main(void *arg) */
    xorl %esi, %esi          /* exit status 0 (LONG) */
    movq $-2, %rdi           /* NtCurrentThread() == (HANDLE)~1 */
    call NtTerminateThread
    ud2

#ifdef __ELF__
    .section .note.GNU-stack, "", @progbits
#endif
