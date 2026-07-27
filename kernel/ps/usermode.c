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
#include "kernel/mm/fault.h"
#include "kernel/mm/phys.h"
#include "arch/x86_64/mmu.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "arch/x86_64/gdt.h"

#include "abi/ntcontext.h"
#include "abi/ntpsapi.h"

/* Wine's exc_stack_layout (third_party/wine dlls/ntdll/unix/signal_x86_64.c):
 * the exception dispatcher finds the CONTEXT at the base, the
 * EXCEPTION_RECORD 0x4f0 above it, and the machine frame (the interrupted
 * RIP/RSP its .seh_pushframe unwind info reads) at 0x590 — pinned there by
 *   C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x4f0 );
 *   C_ASSERT( offsetof(struct exc_stack_layout, machine_frame) == 0x590 );
 *   C_ASSERT( sizeof(struct exc_stack_layout) == 0x5c0 );
 * KI_EXC_FRAME_SIZE over-allocates that. */
#define KI_EXC_RECORD_OFFSET 0x4f0
#define KI_EXC_MACHINE_FRAME 0x590
#define KI_EXC_FRAME_SIZE    0x600

/* Wine's apc_stack_layout (same file): CONTEXT at the base with the APC
 * routine + arguments in its P1Home..P4Home slots, the KCONTINUE_ARGUMENT
 * KiUserApcDispatcher hands back to NtContinueEx at 0x4f0, and the machine
 * frame at 0x530:
 *   C_ASSERT( offsetof(struct apc_stack_layout, continue_arg) == 0x4f0 );
 *   C_ASSERT( offsetof(struct apc_stack_layout, machine_frame) == 0x530 );
 *   C_ASSERT( sizeof(struct apc_stack_layout) == 0x560 ); */
#define KI_APC_CONTINUE_ARG  0x4f0
#define KI_APC_MACHINE_FRAME 0x530
#define KI_APC_FRAME_SIZE    0x560

/* Wine's struct machine_frame (same file): the five iretq-shaped slots the
 * dispatchers' .seh_pushframe unwind info reads (rip/cs/eflags/rsp/ss). */
typedef struct
{
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
} KI_MACHINE_FRAME;

/* Make [base, base+size) present-and-writable in the CURRENT address space
 * before the kernel writes a dispatch frame there. A fresh or deep user stack
 * may still be guard-paged: a ring-3 touch would grow it through
 * MiHandleUserFault, but the kernel's own memcpy must not fault — so run the
 * same growth logic per page up front (what NT does when it pushes a
 * dispatcher frame onto a guarded stack). FALSE = truly unwritable. */
static BOOLEAN KiMaterializeUserRange(uint64_t base, uint64_t size)
{
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    uint64_t page = base & ~(uint64_t)(PAGE_SIZE - 1);
    for (; page < base + size; page += PAGE_SIZE)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            int writable = 0;
            int present = 0;
            uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, &writable, &present);
            if (frame != 0 && present != 0 && writable != 0)
            {
                break;
            }
            if (attempt == 1 || !NT_SUCCESS(MiHandleUserFault(page)))
            {
                return FALSE;
            }
        }
    }
    return TRUE;
}

/* --- x87/SSE state <-> CONTEXT.FltSave ------------------------------------ */

/* The user thread's x87/SSE registers are LIVE in the CPU whenever its kernel
 * side runs (kernel code is -mno-sse and KiSwapContext restores the owner's
 * state — kernel/ke/thread.c), so capturing into / restoring from a CONTEXT is
 * a plain FXSAVE/FXRSTOR of the current CPU state. */

/* MXCSR bits FXRSTOR accepts: the CPU's MXCSR_MASK, read once from a clean
 * FXSAVE image (bytes 28-31; 0 means the default 0xffbf). Restoring a
 * user-supplied MXCSR unmasked would #GP in ring 0 (Intel SDM Vol. 1
 * "FXRSTOR"), so KiRestoreFxState filters through this. */
static uint32_t KiMxcsrMask;

static void KiCaptureFxState(CONTEXT *context)
{
    __attribute__((aligned(16))) XMM_SAVE_AREA32 area;
    memset(&area, 0, sizeof(area));
    __asm__ volatile("fxsave64 %0" : "=m"(area));
    if (KiMxcsrMask == 0)
    {
        KiMxcsrMask = area.MxCsr_Mask != 0 ? area.MxCsr_Mask : 0xffbf;
    }
    memcpy(&context->FltSave, &area, sizeof(area));
    context->MxCsr = area.MxCsr;
}

static void KiRestoreFxState(const CONTEXT *context)
{
    __attribute__((aligned(16))) XMM_SAVE_AREA32 area;
    memcpy(&area, &context->FltSave, sizeof(area));
    area.MxCsr = context->MxCsr & KiMxcsrMask;
    area.MxCsr_Mask = KiMxcsrMask;
    __asm__ volatile("fxrstor64 %0" : : "m"(area));
}

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
    KiCaptureFxState(context);
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
    if (context->ContextFlags & (CONTEXT_FLOATING_POINT & ~CONTEXT_AMD64))
    {
        KiRestoreFxState(context);
    }
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

/* --- the first descent into ring 3 ---------------------------------------- */

/* Enter ring 3 for a fresh thread. Two protocols:
 *
 *   - NT (a real ntdll is mapped, process->rtlUserThreadStart resolved): build
 *     the initial CONTEXT on the user stack — Rip = RtlUserThreadStart, Rcx =
 *     the start routine, Rdx = its argument — and enter LdrInitializeThunk
 *     with rcx = &CONTEXT. ntdll runs loader_init off it and NtContinue's
 *     into RtlUserThreadStart. Shape cross-checked against the pinned Wine's
 *     dlls/ntdll/unix/signal_x86_64.c init_syscall_frame (context.Rsp =
 *     StackBase - 0x28; ctx 16-aligned below it; entry rsp = ctx - 8) and
 *     dlls/ntdll/signal_x86_64.c LdrInitializeThunk.
 *
 *   - bare-register (no ntdll: the M4 flat binaries and the native PE
 *     clients): enter at the resolved rip with rcx/rdx = the two arguments.
 */
/* CUI-4: the choke point every return-to-ring-3 edge runs (syscall return,
 * interrupt return, first descent). A pending foreign terminate reaps the
 * thread through the ordinary exit path — on its OWN stack, in its OWN context
 * (Art. 3: never torn down from another thread). A closed suspend gate parks
 * it here until resumed. The loop re-checks because a terminate can arrive
 * while suspended. Lock NOT held: KeWaitForSingleObject takes it itself. */
void KiProcessPendingUserSignals(PKTHREAD thread)
{
    for (;;)
    {
        if (thread->terminating)
        {
            PspExitCurrentThread(thread->terminateStatus); /* never returns */
        }
        if (KeReadStateEvent(&thread->suspendGate) != 0)
        {
            return;
        }
        KeWaitForSingleObject(&thread->suspendGate, Suspended, KernelMode, FALSE, 0);
    }
}

__attribute__((noreturn)) void PspEnterUserThread(PKTHREAD tcb)
{
    KiProcessPendingUserSignals(tcb); /* honour a create-suspend / terminate before ring 3 */
    PEPROCESS process = tcb->process;
    if (process->rtlUserThreadStart != 0 && process->ldrInitializeThunk != 0)
    {
        CONTEXT context;
        memset(&context, 0, sizeof(context));
        context.ContextFlags = CONTEXT_FULL;
        context.Rcx = tcb->userStartArg1; /* the thread's start routine */
        context.Rdx = tcb->userStartArg2; /* its argument */
        context.Rsp = tcb->userStartRsp;
        context.Rip = process->rtlUserThreadStart;
        context.SegCs = KI_USER_CS_SELECTOR;
        context.SegSs = KI_USER_DS_SELECTOR;
        context.EFlags = 0x202;
        context.MxCsr = 0x1f80;
        context.FltSave.ControlWord = 0x27f;
        context.FltSave.MxCsr = 0x1f80;

        uint64_t contextAddr = (context.Rsp & ~(uint64_t)0xf) - sizeof(CONTEXT);
        if (NT_SUCCESS(KiProbeForWrite((void *)contextAddr, sizeof(CONTEXT), sizeof(uint64_t))) &&
            KiMaterializeUserRange(contextAddr, sizeof(CONTEXT)))
        {
            memcpy((void *)contextAddr, &context, sizeof(CONTEXT));
            KiEnterUserMode(process->ldrInitializeThunk, contextAddr - 8, contextAddr, 0);
        }
        /* An unwritable fresh stack is a setup bug, not a user fault. */
        KiPanic("PspEnterUserThread: initial user stack unwritable");
    }
    KiEnterUserMode(tcb->userStartRip, tcb->userStartRsp, tcb->userStartArg1, tcb->userStartArg2);
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

    /* Probe the whole frame for write before touching user memory — and
     * materialize it (a deep stack may still be guard pages; the kernel's
     * own stores must not fault). */
    if (!NT_SUCCESS(KiProbeForWrite((void *)frameBase, KI_EXC_FRAME_SIZE, sizeof(uint64_t))) ||
        !KiMaterializeUserRange(frameBase, KI_EXC_FRAME_SIZE))
    {
        return FALSE;
    }
    memcpy((void *)frameBase, context, sizeof(CONTEXT));
    memcpy((void *)(frameBase + KI_EXC_RECORD_OFFSET), record, sizeof(EXCEPTION_RECORD));

    /* The machine frame the dispatcher's .seh_pushframe unwind info reads:
     * the interrupted RIP/RSP (Wine exc_stack_layout.machine_frame). */
    KI_MACHINE_FRAME machineFrame;
    machineFrame.rip = context->Rip;
    machineFrame.cs = context->SegCs;
    machineFrame.eflags = context->EFlags;
    machineFrame.rsp = context->Rsp;
    machineFrame.ss = context->SegSs;
    memcpy((void *)(frameBase + KI_EXC_MACHINE_FRAME), &machineFrame, sizeof(machineFrame));

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
    /* Art. 9: name every exception the kernel hands to user mode — when an
     * unhandled one later kills the process, this line is the only record
     * of where it struck (no ASLR: the rip symbolizes offline). Intentional
     * faults (guard pages, IsBad*Ptr probes) make this chatty in bursts;
     * measured against the winetest sweeps the volume stays readable. */
    DbgPrint("[KTEST] user exception code=%#lx rip=%p addr=%p pid=%lu\n",
             (unsigned long)exceptionCode, (void *)trapFrame->rip, (void *)faultAddress,
             (unsigned long)KeGetCurrentThread()->process->uniqueProcessId);
    /* Scan the top of the faulting thread's stack for module-range values —
     * the return addresses that name the caller chain (the wedge dump's
     * trick, at fault time; MiCopyFromUserRange stops at unmapped pages). */
    {
        uint64_t stack[96];
        uint64_t copied = MiCopyFromUserRange(&KeGetCurrentThread()->process->addressSpace, stack,
                                              trapFrame->rsp, sizeof(stack));
        int shown = 0;
        for (uint64_t i = 0; i < copied / sizeof(uint64_t) && shown < 8; i++)
        {
            if (stack[i] >= 0x140000000ull && stack[i] < 0x200000000ull)
            {
                DbgPrint("[KTEST] user exception frame=%p\n", (void *)stack[i]);
                shown++;
            }
        }
    }

    EXCEPTION_RECORD record;
    memset(&record, 0, sizeof(record));
    record.ExceptionCode = exceptionCode;
    record.ExceptionAddress = (PVOID)(uintptr_t)trapFrame->rip;
    if (exceptionCode == (ULONG)STATUS_ACCESS_VIOLATION ||
        exceptionCode == (ULONG)STATUS_IN_PAGE_ERROR ||
        exceptionCode == (ULONG)STATUS_GUARD_PAGE_VIOLATION)
    {
        /* Page-fault-family records carry [access, address] — a guard
         * violation included (sem_mm/guard_pages pins the address). */
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

    /* Save the interrupted context and enter KiUserApcDispatcher on Wine's
     * apc_stack_layout: the CONTEXT at the frame base carries the routine +
     * arguments in P1Home..P4Home, the KCONTINUE_ARGUMENT the dispatcher
     * passes back to NtContinueEx sits at 0x4f0, and the machine frame its
     * unwind info reads at 0x530 (offsets pinned at the top of this file). */
    CONTEXT context;
    KiTrapFrameToContext(trapFrame, &context);
    context.P1Home = arg1;
    context.P2Home = arg2;
    context.P3Home = arg3;
    context.P4Home = normalRoutine;

    uint64_t sp = trapFrame->rsp;
    sp -= 0x20; /* skip the red zone */
    sp &= ~(uint64_t)0xf;
    sp -= KI_APC_FRAME_SIZE;
    uint64_t frameBase = sp;
    if (!NT_SUCCESS(KiProbeForWrite((void *)frameBase, KI_APC_FRAME_SIZE, sizeof(uint64_t))) ||
        !KiMaterializeUserRange(frameBase, KI_APC_FRAME_SIZE))
    {
        return;
    }
    memcpy((void *)frameBase, &context, sizeof(CONTEXT));

    KCONTINUE_ARGUMENT continueArg;
    memset(&continueArg, 0, sizeof(continueArg));
    continueArg.ContinueType = KCONTINUE_RESUME;
    continueArg.ContinueFlags = KCONTINUE_FLAG_TEST_ALERT | KCONTINUE_FLAG_DELIVER_APC;
    memcpy((void *)(frameBase + KI_APC_CONTINUE_ARG), &continueArg, sizeof(continueArg));

    KI_MACHINE_FRAME machineFrame;
    machineFrame.rip = context.Rip;
    machineFrame.cs = context.SegCs;
    machineFrame.eflags = context.EFlags;
    machineFrame.rsp = context.Rsp;
    machineFrame.ss = context.SegSs;
    memcpy((void *)(frameBase + KI_APC_MACHINE_FRAME), &machineFrame, sizeof(machineFrame));

    trapFrame->rip = process->userApcDispatcher;
    trapFrame->rsp = frameBase; /* the apc_stack_layout base */
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
