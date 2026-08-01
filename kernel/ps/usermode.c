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
    /* The bound comes first and is not optional. Every caller derives `base`
     * from a ring-3-controlled RSP. Without this test a user process that
     * points RSP at the kernel image gets its CONTEXT memcpy'd there: the
     * loop below would find the page present and writable, because a user
     * PML4 shares the kernel's upper half.
     *
     * This function is the WHOLE gate for the three frame writers, and it is
     * meant to be. A KiProbeForWrite used to sit alongside each call and did
     * nothing at all — these paths run with previousMode == KernelMode (the
     * syscall path restores it before delivering an APC, and a trap never
     * sets it), so the probe short-circuited to success. Making the probes
     * mode-aware instead would be worse than useless here: they run BEFORE
     * materialization and demand present-and-writable, which is exactly what
     * a guard page on a growing stack is not, so a live probe would refuse
     * the frames it is supposed to admit. One authority, and it is this one
     * (Art. 11). */
    if (!KiIsUserRange(base, size))
    {
        return FALSE;
    }

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
            if (attempt == 1 || !NT_SUCCESS(MiHandleUserFault(page, TRUE)))
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
 * "FXRSTOR"), so KiRestoreFxState filters through this. BOTH paths
 * initialize it: a restore runs before any capture on every boot (ntdll's
 * startup NtContinue), and filtering through a still-zero mask would strip
 * the exception-mask bits from the restored MXCSR — every later inexact
 * SSE op in that thread then dies with #XM (tests/ntapi
 * sem_ps/initial_fpu.c pins the startup state). */
static uint32_t KiMxcsrMask;

static void KiEnsureMxcsrMask(void)
{
    if (KiMxcsrMask == 0)
    {
        __attribute__((aligned(16))) XMM_SAVE_AREA32 area;
        memset(&area, 0, sizeof(area));
        __asm__ volatile("fxsave64 %0" : "=m"(area));
        KiMxcsrMask = area.MxCsr_Mask != 0 ? area.MxCsr_Mask : 0xffbf;
    }
}

/* foreignFx != 0 (CUI-6): read the SUSPENDED target's saved FXSAVE image
 * (KTHREAD.fxArea) instead of the live CPU — the foreign thread's SSE state
 * is off-CPU, saved by KiSwapContext. NULL means the self path (live). */
static void KiCaptureFxState(CONTEXT *context, const unsigned char *foreignFx)
{
    __attribute__((aligned(16))) XMM_SAVE_AREA32 area;
    memset(&area, 0, sizeof(area));
    if (foreignFx != 0)
    {
        memcpy(&area, foreignFx, sizeof(area));
    }
    else
    {
        __asm__ volatile("fxsave64 %0" : "=m"(area));
    }
    KiEnsureMxcsrMask();
    memcpy(&context->FltSave, &area, sizeof(area));
    context->MxCsr = area.MxCsr;
}

/* foreignFx != 0 (CUI-6): write the SUSPENDED target's saved FXSAVE image so
 * it is restored when the target next runs; NULL restores the live CPU. */
static void KiRestoreFxState(const CONTEXT *context, unsigned char *foreignFx)
{
    __attribute__((aligned(16))) XMM_SAVE_AREA32 area;
    KiEnsureMxcsrMask();
    memcpy(&area, &context->FltSave, sizeof(area));
    area.MxCsr = context->MxCsr & KiMxcsrMask;
    area.MxCsr_Mask = KiMxcsrMask;
    if (foreignFx != 0)
    {
        memcpy(foreignFx, &area, sizeof(area));
    }
    else
    {
        __asm__ volatile("fxrstor64 %0" : : "m"(area));
    }
}

/* --- CONTEXT <-> KTRAP_FRAME --------------------------------------------- */

/* Capture the trap frame into `context`, honouring the ContextFlags the
 * CALLER put there. NT's documented idiom is to ask for a subset --
 * `ContextFlags = CONTEXT_INTEGER; NtGetContextThread(...)` -- and only the
 * requested groups are filled; the returned ContextFlags say which. This
 * used to ignore the caller's request entirely and stamp CONTEXT_FULL over
 * it, which paired with the set side made the documented get-modify-set
 * sequence overwrite Rip and Rsp with zero (docs/review-2026-07 §9).
 *
 * The four groups follow the AMD64 CONTEXT layout (abi/ntcontext.h):
 * CONTROL is SegSs/Rsp/SegCs/Rip/EFlags, INTEGER the 16 GPRs minus Rsp,
 * SEGMENTS the four data selectors, FLOATING_POINT the FltSave area + MxCsr.
 * SEGMENTS was never filled at all -- KiTrapFrameToContext zeroed the
 * selectors and CONTEXT_FULL claimed otherwise. */
static void KiTrapFrameToContext(const KTRAP_FRAME *frame, CONTEXT *context,
                                 const unsigned char *foreignFx)
{
    ULONG wanted = context->ContextFlags;
    if ((wanted & CONTEXT_AMD64) != CONTEXT_AMD64)
    {
        wanted = CONTEXT_FULL; /* an unset/foreign architecture tag: give it all */
    }
    /* Fields OUTSIDE the requested groups are left exactly as the caller
     * left them -- not zeroed. Verified against the pinned oracle: a
     * CONTEXT_INTEGER get returns the caller's own Rip untouched, and a
     * CONTEXT_CONTROL get its own Rax. */
    context->ContextFlags = wanted;
    if (wanted & CONTEXT_SEGMENTS)
    {
        context->SegDs = KI_USER_DS_SELECTOR;
        context->SegEs = KI_USER_DS_SELECTOR;
        context->SegFs = KI_USER_DS_SELECTOR;
        context->SegGs = KI_USER_DS_SELECTOR;
    }
    if (wanted & CONTEXT_CONTROL)
    {
        context->SegSs = (WORD)frame->segSs;
        context->Rsp = frame->rsp;
        context->SegCs = (WORD)frame->segCs;
        context->Rip = frame->rip;
        context->EFlags = (DWORD)frame->eflags;
    }
    if (wanted & CONTEXT_FLOATING_POINT)
    {
        KiCaptureFxState(context, foreignFx);
    }
    if ((wanted & CONTEXT_INTEGER) == 0)
    {
        return;
    }
    context->Rax = frame->rax;
    context->Rcx = frame->rcx;
    context->Rdx = frame->rdx;
    context->Rbx = frame->rbx;
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
}

/* Apply a user-supplied CONTEXT to the outgoing trap frame. Segment selectors
 * and RFLAGS are forced back to safe ring-3 values (a process must not be able
 * to return to ring 0 or set IOPL/IF-off via NtContinue). */
static void KiContextToTrapFrame(const CONTEXT *context, KTRAP_FRAME *frame,
                                 unsigned char *foreignFx)
{
    /* Apply only the groups the caller declared. Applying everything
     * unconditionally is what made the documented get-modify-set idiom --
     * ask for CONTEXT_INTEGER, change one register, set it back -- write Rip
     * and Rsp as zero (docs/review-2026-07 §9). */
    ULONG wanted = context->ContextFlags;
    if ((wanted & CONTEXT_AMD64) != CONTEXT_AMD64)
    {
        wanted = CONTEXT_FULL;
    }
    if (wanted & CONTEXT_INTEGER)
    {
        frame->rax = context->Rax;
        frame->rcx = context->Rcx;
        frame->rdx = context->Rdx;
        frame->rbx = context->Rbx;
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
    }
    if (wanted & CONTEXT_FLOATING_POINT)
    {
        KiRestoreFxState(context, foreignFx);
    }
    if (wanted & CONTEXT_CONTROL)
    {
        frame->rsp = context->Rsp;
        frame->rip = context->Rip;
        /* Sanitize the RFLAGS a ring-3 CONTEXT may set (our security policy,
         * not an external contract — analogous to the SFMASK choice in
         * arch/x86_64/gdt.c): keep the user-settable status/control bits
         * CF(0) PF(2) AF(4) ZF(6) SF(7) TF(8) DF(10) OF(11), then force IF
         * on and the always-1 bit 1 (0x202), so NtContinue can never return
         * to ring 0, raise IOPL, or run with interrupts masked. TF is in the
         * kept set: dropping it made user single-stepping impossible, which
         * is a debugger's whole mechanism (SDM Vol. 1 "EFLAGS Register";
         * mask 0xdd5). */
        frame->eflags = (context->EFlags & 0x00000dd5ULL) | 0x202ULL;
    }
    /* The selectors are ALWAYS forced, whatever the caller declared: a ring-3
     * CONTEXT must never choose its own CS/SS. */
    frame->segCs = KI_USER_CS_SELECTOR;
    frame->segSs = KI_USER_DS_SELECTOR;
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
        if (KiMaterializeUserRange(contextAddr, sizeof(CONTEXT)))
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

    /* Bound and materialize the whole frame before touching user memory (a
     * deep stack may still be guard pages; the kernel's own stores must not
     * fault). KiMaterializeUserRange is the ONLY gate here by design — see
     * its comment. */
    if (!KiMaterializeUserRange(frameBase, KI_EXC_FRAME_SIZE))
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
            if (stack[i] >= PSP_MODULE_FLOOR && stack[i] < PSP_MODULE_CEIL)
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
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_FULL; /* the dispatchers want everything */
    KiTrapFrameToContext(trapFrame, &context, 0);
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
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_FULL; /* the dispatchers want everything */
    KiTrapFrameToContext(trapFrame, &context, 0);
    context.P1Home = arg1;
    context.P2Home = arg2;
    context.P3Home = arg3;
    context.P4Home = normalRoutine;

    uint64_t sp = trapFrame->rsp;
    sp -= 0x20; /* skip the red zone */
    sp &= ~(uint64_t)0xf;
    sp -= KI_APC_FRAME_SIZE;
    uint64_t frameBase = sp;
    if (!KiMaterializeUserRange(frameBase, KI_APC_FRAME_SIZE))
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
    KiContextToTrapFrame(&context, trapFrame, 0);
    thread->userContextReplaced = TRUE; /* the dispatcher must not overwrite rax */

    /* A Rip outside user space -- non-canonical, or simply a kernel address
     * -- must not reach the iretq that ends this syscall: IRET checks the
     * new CS:RIP itself, so a bad one raises #GP with the KERNEL CS still
     * loaded, and that panics the machine (docs/review-2026-07 §8).
     * Choosing iretq over sysret correctly avoided the classic
     * non-canonical-RCX hole; IRET has its own.
     *
     * The oracle's answer is not a refusal but an ACCESS VIOLATION delivered
     * to the process -- verified against the pinned Wine, which reports
     * c0000005 to a vectored handler for exactly this input -- so deliver
     * that, through the same path a real fault takes. The frame is already
     * rewritten above, so the exception reports the Rip the caller asked to
     * resume at, as it would have if that address were merely unmapped. */
    if (!KiIsUserRange(trapFrame->rip, 1))
    {
        if (thread->process->userExceptionDispatcher != 0 &&
            PspDispatchUserException(trapFrame, (ULONG)STATUS_ACCESS_VIOLATION, trapFrame->rip))
        {
            return STATUS_SUCCESS; /* iretq into the exception dispatcher */
        }
        DbgPrint("[USERFAULT] NtContinue to %#018lx (outside user space); terminating process\n",
                 (unsigned long)trapFrame->rip);
        PspExitCurrentProcess(STATUS_ACCESS_VIOLATION);
    }

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

/* CUI-6: resolve a foreign thread handle to its saved ring-3 frame and
 * FXSAVE image for NtGet/SetContextThread. The target must have descended to
 * ring 3 and be off-CPU with a live published frame — a suspended-and-parked
 * thread (the sanctioned SuspendThread+GetThreadContext pattern), whose
 * trapFrame stays published across the park (kernel/init/panic.c,
 * kernel/syscall/table.c) and whose SSE state KiSwapContext has spilled to
 * fxArea. A never-descended or currently-running target has no frame and
 * refuses loudly (Art. 12; the profiler pattern always suspends first).
 * Self resolves to the live trap frame and live SSE (foreignFx = 0). */
static NTSTATUS KiResolveContextTarget(HANDLE threadHandle, ACCESS_MASK access,
                                       PKTRAP_FRAME *frameOut, unsigned char **foreignFxOut,
                                       PETHREAD *referenceOut)
{
    *referenceOut = 0;
    if (threadHandle == NtCurrentThread() || threadHandle == 0)
    {
        PKTHREAD self = KeGetCurrentThread();
        if (self->trapFrame == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        *frameOut = self->trapFrame;
        *foreignFxOut = 0;
        return STATUS_SUCCESS;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(threadHandle, access, &PspThreadType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PETHREAD target = body;
    PKTHREAD tcb = target->tcb;
    if (tcb == KeGetCurrentThread())
    {
        /* A handle that happens to name the caller: the live path. */
        if (tcb->trapFrame == 0)
        {
            ObDereferenceObject(target);
            return STATUS_INVALID_PARAMETER;
        }
        *frameOut = tcb->trapFrame;
        *foreignFxOut = 0;
        *referenceOut = target;
        return STATUS_SUCCESS;
    }
    /* A foreign target is only readable when it is off-CPU with a published
     * ring-3 frame — the suspended-and-parked case. */
    uint64_t flags = KiAcquireDispatcherLock();
    PKTRAP_FRAME frame = tcb->trapFrame;
    KiReleaseDispatcherLock(flags);
    if (frame == 0)
    {
        ObDereferenceObject(target);
        return STATUS_NOT_IMPLEMENTED;
    }
    *frameOut = frame;
    *foreignFxOut = tcb->fxArea;
    *referenceOut = target;
    return STATUS_SUCCESS;
}

NTSTATUS NtGetContextThread(HANDLE threadHandle, PCONTEXT context)
{
    PKTRAP_FRAME frame;
    unsigned char *foreignFx;
    PETHREAD reference;
    NTSTATUS status =
        KiResolveContextTarget(threadHandle, THREAD_GET_CONTEXT, &frame, &foreignFx, &reference);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = KiProbeForWrite(context, sizeof(CONTEXT), sizeof(uint64_t));
    if (NT_SUCCESS(status))
    {
        /* The caller's ContextFlags is an INPUT: it names the groups it
         * wants (the documented get-modify-set idiom); everything outside
         * those groups must come back unchanged, so capture the whole CONTEXT
         * first (see KiTrapFrameToContext). */
        CONTEXT captured;
        status = KiCopyFromUser(&captured, context, sizeof(CONTEXT));
        if (NT_SUCCESS(status))
        {
            KiTrapFrameToContext(frame, &captured, foreignFx);
            memcpy(context, &captured, sizeof(CONTEXT));
        }
    }
    if (reference != 0)
    {
        ObDereferenceObject(reference);
    }
    return status;
}

NTSTATUS NtSetContextThread(HANDLE threadHandle, const CONTEXT *context)
{
    if (threadHandle == NtCurrentThread() || threadHandle == 0)
    {
        return KiContinue(context, FALSE);
    }
    PKTRAP_FRAME frame;
    unsigned char *foreignFx;
    PETHREAD reference;
    NTSTATUS status =
        KiResolveContextTarget(threadHandle, THREAD_SET_CONTEXT, &frame, &foreignFx, &reference);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (reference != 0 && reference->tcb == KeGetCurrentThread())
    {
        /* A handle naming the caller: the live continue path (KiContinue
         * rewrites the current frame and returns through it). */
        ObDereferenceObject(reference);
        return KiContinue(context, FALSE);
    }
    CONTEXT captured;
    status = KiCopyFromUser(&captured, context, sizeof(CONTEXT));
    if (NT_SUCCESS(status))
    {
        /* Apply onto the target's saved frame + FXSAVE image in place; it
         * takes effect when the target next returns to ring 3 (its iretq
         * reads this frame, KiSwapContext its fxArea). */
        KiContextToTrapFrame(&captured, frame, foreignFx);
    }
    if (reference != 0)
    {
        ObDereferenceObject(reference);
    }
    return status;
}
