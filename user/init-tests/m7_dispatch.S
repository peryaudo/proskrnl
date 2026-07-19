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

/* KiUserApcDispatcher: entered on Wine's apc_stack_layout (kernel/ps/
 * usermode.c KiDeliverUserApc, offsets pinned by the C_ASSERTs in
 * third_party/wine dlls/ntdll/unix/signal_x86_64.c): rsp = the frame base
 * with the saved CONTEXT at [rsp], the routine + arguments in its
 * P1Home..P4Home slots (offsets 0x00..0x18), and the KCONTINUE_ARGUMENT to
 * hand back to NtContinueEx at 0x4f0 — the same contract Wine's PE ntdll
 * dispatcher consumes. Run the routine (SysV) then NtContinueEx back. */
    .global KiUserApcDispatcher
KiUserApcDispatcher:
    movq %rsp, %rbx          /* frame base (callee-saved across the call) */
    movq 0x00(%rsp), %rdi    /* context->P1Home = arg1 */
    movq 0x08(%rsp), %rsi    /* context->P2Home = arg2 */
    movq 0x10(%rsp), %rdx    /* context->P3Home = arg3 */
    movq 0x18(%rsp), %rax    /* context->P4Home = normalRoutine */
    call *%rax
    movq %rbx, %rdi          /* CONTEXT* */
    leaq 0x4f0(%rbx), %rsi   /* KCONTINUE_ARGUMENT* */
    call NtContinueEx
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
