/* kernel/ps/usermode.c — the ring-3 return protocol (M7; docs/05 Ps
 * "usermode.c", the difficult file).
 *
 * The observable, depended-upon contract (docs/02 M7 "Done when": the SEH
 * test) is how the kernel hands control to ntdll's user-mode dispatchers and
 * how they hand it back:
 *
 *   - a user-mode exception (a contained fault, or NtRaiseException) is
 *     delivered by re-pointing the outgoing trap frame at the process's
 *     KiUserExceptionDispatcher, with an EXCEPTION_RECORD + CONTEXT laid out
 *     on the user stack exactly where the dispatcher reads them;
 *   - a queued user APC is delivered the same way through KiUserApcDispatcher
 *     at an alertable point;
 *   - NtContinue resumes an arbitrary CONTEXT (what the dispatchers call to
 *     return), which a bare sysret cannot express — hence the full-frame
 *     syscall entry (kernel/syscall/entry.S).
 *
 * The stack layout matches Wine's dlls/ntdll/signal_x86_64.c (KiUser*
 * Dispatcher) so the same code path serves both the native M7 test client and
 * the unmodified PE ntdll: CONTEXT at rsp+0x000, EXCEPTION_RECORD at rsp+0x4f0
 * for the exception dispatcher; the APC dispatcher takes (arg1,arg2,arg3) in
 * the home slots and &CONTEXT in r9.
 */
#include "kernel/ps/ps.h"
#include "kernel/mm/virtual.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/gdt.h"

#include "abi/ntcontext.h"
#include "abi/ntpsapi.h"

/* Wine's exc_stack_layout (third_party/wine dlls/ntdll/unix/signal_x86_64.c):
 * the exception dispatcher finds the CONTEXT at the base and the
 * EXCEPTION_RECORD 0x4f0 above it — pinned there by
 *   C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x4f0 );
 * (and sizeof == 0x5c0, machine_frame at 0x590 for the full Wine layout).
 * KI_EXC_FRAME_SIZE over-allocates that. The native M7 client's dispatcher
 * reads only CONTEXT + rec; wiring the machine_frame at 0x590 is part of the
 * Wine-ntdll bring-up. */
#define KI_EXC_RECORD_OFFSET 0x4f0
#define KI_EXC_FRAME_SIZE    0x600

/* --- CONTEXT <-> KTRAP_FRAME --------------------------------------------- */

static void KiTrapFrameToContext(const KTRAP_FRAME *frame, CONTEXT *context)
{
    memset(context, 0, sizeof(*context));
    context->ContextFlags = CONTEXT_FULL;
    context->Rax = frame->rax;
    context->Rcx = frame->rcx;
    context->Rdx = frame->rdx;
    context->Rbx = frame->rbx;
    context->Rsp = frame->rsp;
    context->Rbp = frame->rbp;
    context->Rsi = frame->rsi;
    context->Rdi = frame->rdi;
    context->R8 = frame->r8;
    context->R9 = frame->r9;
    context->R10 = frame->r10;
    context->R11 = frame->r11;
    context->R12 = frame->r12;
    context->R13 = frame->r13;
    context->R14 = frame->r14;
    context->R15 = frame->r15;
    context->Rip = frame->rip;
    context->SegCs = (WORD)frame->segCs;
    context->SegSs = (WORD)frame->segSs;
    context->EFlags = (DWORD)frame->eflags;
    context->MxCsr = 0x1f80;
    context->FltSave.ControlWord = 0x27f;
    context->FltSave.MxCsr = 0x1f80;
}

/* Apply a user-supplied CONTEXT to the outgoing trap frame. Segment selectors
 * and RFLAGS are forced back to safe ring-3 values (a process must not be able
 * to return to ring 0 or set IOPL/IF-off via NtContinue). */
static void KiContextToTrapFrame(const CONTEXT *context, KTRAP_FRAME *frame)
{
    frame->rax = context->Rax;
    frame->rcx = context->Rcx;
    frame->rdx = context->Rdx;
    frame->rbx = context->Rbx;
    frame->rsp = context->Rsp;
    frame->rbp = context->Rbp;
    frame->rsi = context->Rsi;
    frame->rdi = context->Rdi;
    frame->r8 = context->R8;
    frame->r9 = context->R9;
    frame->r10 = context->R10;
    frame->r11 = context->R11;
    frame->r12 = context->R12;
    frame->r13 = context->R13;
    frame->r14 = context->R14;
    frame->r15 = context->R15;
    frame->rip = context->Rip;
    frame->segCs = KI_USER_CS_SELECTOR;
    frame->segSs = KI_USER_DS_SELECTOR;
    /* Sanitize the RFLAGS a ring-3 CONTEXT may set (our security policy, not an
     * external contract — analogous to the SFMASK choice in arch/x86_64/gdt.c):
     * keep only the user-settable status/control bits CF(0) PF(2) AF(4) ZF(6)
     * SF(7) DF(10) OF(11) (mask 0xcd5; SDM Vol. 1 "EFLAGS Register"), then force
     * IF on and the always-1 bit 1 (0x202), so NtContinue can never return to
     * ring 0, raise IOPL, or run with interrupts masked. */
    frame->eflags = (context->EFlags & 0x00000cd5ULL) | 0x202ULL;
}

/* --- exception delivery --------------------------------------------------- */

/* Push `record` + `context` onto the user stack of `trapFrame` and re-point it
 * at the process's KiUserExceptionDispatcher. Returns FALSE (leaving the frame
 * untouched) if the process resolved no dispatcher. */
static BOOLEAN KiEnterUserExceptionDispatcher(PKTRAP_FRAME trapFrame,
                                              const EXCEPTION_RECORD *record,
                                              const CONTEXT *context)
{
    PEPROCESS process = KeGetCurrentThread()->process;
    if (process->userExceptionDispatcher == 0)
    {
        return FALSE;
    }

    /* Carve the frame off the interrupted user RSP (below the red zone),
     * 16-aligned as the dispatcher's own calls require. */
    uint64_t sp = context->Rsp;
    sp -= 0x20; /* skip the red zone / a little slack */
    sp &= ~(uint64_t)0xf;
    sp -= KI_EXC_FRAME_SIZE;
    uint64_t frameBase = sp;

    /* Probe the whole frame for write before touching user memory. */
    if (!NT_SUCCESS(KiProbeForWrite((void *)frameBase, KI_EXC_FRAME_SIZE, sizeof(uint64_t))))
    {
        return FALSE;
    }
    memcpy((void *)frameBase, context, sizeof(CONTEXT));
    memcpy((void *)(frameBase + KI_EXC_RECORD_OFFSET), record, sizeof(EXCEPTION_RECORD));

    trapFrame->rip = process->userExceptionDispatcher;
    trapFrame->rsp = frameBase;
    trapFrame->rcx = frameBase + KI_EXC_RECORD_OFFSET; /* PEXCEPTION_RECORD */
    trapFrame->rdx = frameBase;                        /* PCONTEXT */
    trapFrame->segCs = KI_USER_CS_SELECTOR;
    trapFrame->segSs = KI_USER_DS_SELECTOR;
    trapFrame->eflags = 0x202;
    return TRUE;
}

BOOLEAN PspDispatchUserException(PKTRAP_FRAME trapFrame, ULONG exceptionCode, uint64_t faultAddress)
{
    EXCEPTION_RECORD record;
    memset(&record, 0, sizeof(record));
    record.ExceptionCode = exceptionCode;
    record.ExceptionAddress = (PVOID)(uintptr_t)trapFrame->rip;
    if (exceptionCode == (ULONG)STATUS_ACCESS_VIOLATION ||
        exceptionCode == (ULONG)STATUS_IN_PAGE_ERROR)
    {
        record.NumberParameters = 2;
        record.ExceptionInformation[0] = 0; /* read (we do not decode the PF error code yet) */
        record.ExceptionInformation[1] = faultAddress;
    }

    CONTEXT context;
    KiTrapFrameToContext(trapFrame, &context);
    return KiEnterUserExceptionDispatcher(trapFrame, &record, &context);
}

/* --- APC delivery --------------------------------------------------------- */

void KiDeliverUserApc(PKTHREAD thread, PKTRAP_FRAME trapFrame)
{
    uint64_t flags = KiAcquireDispatcherLock();
    if (IsListEmpty(&thread->userApcListHead))
    {
        thread->apcDeliverPending = FALSE;
        KiReleaseDispatcherLock(flags);
        return;
    }
    PKAPC apc = CONTAINING_RECORD(thread->userApcListHead.Flink, KAPC, apcListEntry);
    RemoveEntryList(&apc->apcListEntry);
    if (IsListEmpty(&thread->userApcListHead))
    {
        thread->userApcPending = FALSE;
        thread->apcDeliverPending = FALSE;
    }
    KiReleaseDispatcherLock(flags);

    PEPROCESS process = thread->process;
    uint64_t normalRoutine = apc->normalRoutine;
    uint64_t arg1 = apc->normalContext;
    uint64_t arg2 = apc->systemArgument1;
    uint64_t arg3 = apc->systemArgument2;
    MiFreePool(apc);

    if (process->userApcDispatcher == 0 || normalRoutine == 0)
    {
        return; /* no dispatcher / no routine: drop it (nothing to run) */
    }

    /* Save the interrupted context and enter KiUserApcDispatcher with the APC
     * arguments in the home registers and &CONTEXT in the slot at rsp
     * (context sits at the new rsp; the dispatcher NtContinue's back to it). */
    CONTEXT context;
    KiTrapFrameToContext(trapFrame, &context);

    uint64_t sp = trapFrame->rsp;
    sp -= 0x20;
    sp &= ~(uint64_t)0xf;
    sp -= sizeof(CONTEXT);
    uint64_t contextAddr = sp;
    if (!NT_SUCCESS(KiProbeForWrite((void *)contextAddr, sizeof(CONTEXT), sizeof(uint64_t))))
    {
        return;
    }
    memcpy((void *)contextAddr, &context, sizeof(CONTEXT));

    trapFrame->rip = process->userApcDispatcher;
    trapFrame->rsp = contextAddr; /* CONTEXT is at [rsp] */
    trapFrame->rcx = normalRoutine;
    trapFrame->rdx = arg1;
    trapFrame->r8 = arg2;
    trapFrame->r9 = arg3;
    trapFrame->segCs = KI_USER_CS_SELECTOR;
    trapFrame->segSs = KI_USER_DS_SELECTOR;
    trapFrame->eflags = 0x202;
}

/* --- the Nt* surface ------------------------------------------------------ */

static NTSTATUS KiContinue(const CONTEXT *userContext, BOOLEAN testAlert)
{
    PKTHREAD thread = KeGetCurrentThread();
    PKTRAP_FRAME trapFrame = thread->trapFrame;
    if (trapFrame == 0)
    {
        return STATUS_INVALID_PARAMETER; /* not a ring-3-originated call */
    }

    CONTEXT context;
    NTSTATUS status = KiProbeForRead(userContext, sizeof(CONTEXT), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(&context, userContext, sizeof(CONTEXT));
    KiContextToTrapFrame(&context, trapFrame);
    thread->userContextReplaced = TRUE; /* the dispatcher must not overwrite rax */

    if (testAlert)
    {
        uint64_t flags = KiAcquireDispatcherLock();
        if (!IsListEmpty(&thread->userApcListHead))
        {
            thread->apcDeliverPending = TRUE;
        }
        KiReleaseDispatcherLock(flags);
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtContinue(PCONTEXT context, BOOLEAN testAlert)
{
    return KiContinue(context, testAlert);
}

NTSTATUS NtContinueEx(CONTEXT *context, KCONTINUE_ARGUMENT *continueArgument)
{
    /* Wine's KiUserApcDispatcher passes a KCONTINUE_ARGUMENT; older callers a
     * BOOLEAN. Treat a small integer as the alert flag (as Wine's ntdll does),
     * else read the KCONTINUE_ARGUMENT.ContinueFlags. */
    BOOLEAN testAlert = FALSE;
    if ((uint64_t)(uintptr_t)continueArgument > 0xffff)
    {
        KCONTINUE_ARGUMENT arg;
        if (NT_SUCCESS(KiProbeForRead(continueArgument, sizeof(arg), sizeof(uint64_t))))
        {
            memcpy(&arg, continueArgument, sizeof(arg));
            testAlert = (arg.ContinueFlags & KCONTINUE_FLAG_TEST_ALERT) != 0;
        }
    }
    else
    {
        testAlert = continueArgument != 0;
    }
    return KiContinue(context, testAlert);
}

NTSTATUS NtRaiseException(PEXCEPTION_RECORD userRecord, PCONTEXT userContext, BOOL firstChance)
{
    PKTHREAD thread = KeGetCurrentThread();
    PKTRAP_FRAME trapFrame = thread->trapFrame;
    if (trapFrame == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    EXCEPTION_RECORD record;
    CONTEXT context;
    NTSTATUS status = KiProbeForRead(userRecord, sizeof(record), sizeof(uint32_t));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForRead(userContext, sizeof(context), sizeof(uint64_t));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(&record, userRecord, sizeof(record));
    memcpy(&context, userContext, sizeof(context));

    if (firstChance)
    {
        /* Re-dispatch to the user handler (RtlRaiseException's normal path).
         * The context describes where the raise happened / where to resume. */
        if (KiEnterUserExceptionDispatcher(trapFrame, &record, &context))
        {
            thread->userContextReplaced = TRUE;
            return STATUS_SUCCESS;
        }
    }

    /* No handler resolved / non-first-chance: an unhandled user exception is a
     * contained process death (as the M4 fault path already does). */
    PspExitCurrentThread(record.ExceptionCode);
}

NTSTATUS NtGetContextThread(HANDLE threadHandle, PCONTEXT context)
{
    PKTHREAD thread = KeGetCurrentThread();
    /* M7: self only (a running foreign thread cannot be stopped under Art. 3's
     * no-preemption model without the suspend machinery). */
    if (threadHandle != NtCurrentThread() && threadHandle != 0)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    if (thread->trapFrame == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForWrite(context, sizeof(CONTEXT), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    CONTEXT captured;
    KiTrapFrameToContext(thread->trapFrame, &captured);
    memcpy(context, &captured, sizeof(CONTEXT));
    return STATUS_SUCCESS;
}

NTSTATUS NtSetContextThread(HANDLE threadHandle, const CONTEXT *context)
{
    if (threadHandle != NtCurrentThread() && threadHandle != 0)
    {
        return STATUS_NOT_IMPLEMENTED;
    }
    return KiContinue(context, FALSE);
}
