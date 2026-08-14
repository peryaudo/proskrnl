/* kernel/init/panic.c — the thick fatal-error / trap handler (Constitution Art. 9).
 *
 * Under LLM-driven development the panic dump is the debugger: register state,
 * a frame-pointer stack trace, and the last syscall number, all on serial with
 * a machine-greppable [PANIC] prefix (docs/08). The CPU exception path and
 * UBSan traps (#UD) both land here.
 */
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/fault.h"
#include "kernel/mm/phys.h"
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "arch/x86_64/mmu.h"
#include "abi/ntstatus.h"
#include "arch/x86_64/trap.h"
#include "arch/x86_64/io.h"

#include <stdint.h>

uint64_t KiLastSystemCall = ~(uint64_t)0;

static const char *KiExceptionName(uint64_t vector)
{
    switch (vector)
    {
    case 0:
        return "#DE divide error";
    case 1:
        return "#DB debug";
    case 3:
        return "#BP breakpoint";
    case 6:
        return "#UD invalid opcode";
    case 8:
        return "#DF double fault";
    case 12:
        return "#SS stack fault";
    case 13:
        return "#GP general protection";
    case 14:
        return "#PF page fault";
    default:
        return "exception";
    }
}

static void KiDumpTrapFrame(const char *tag, PKTRAP_FRAME trapFrame)
{
    DbgPrint("%s vector=%lu (%s) err=%#lx\n", tag, trapFrame->vector,
             KiExceptionName(trapFrame->vector), trapFrame->errorCode);
    DbgPrint("  RIP=%#018lx CS=%#lx RFLAGS=%#lx\n", trapFrame->rip, trapFrame->segCs,
             trapFrame->eflags);
    DbgPrint("  RSP=%#018lx SS=%#lx last_syscall=%#lx\n", trapFrame->rsp, trapFrame->segSs,
             KiLastSystemCall);
    DbgPrint("  RAX=%#018lx RBX=%#018lx RCX=%#018lx RDX=%#018lx\n", trapFrame->rax, trapFrame->rbx,
             trapFrame->rcx, trapFrame->rdx);
    DbgPrint("  RSI=%#018lx RDI=%#018lx RBP=%#018lx\n", trapFrame->rsi, trapFrame->rdi,
             trapFrame->rbp);
    DbgPrint("  r8 =%#018lx r9 =%#018lx r10=%#018lx r11=%#018lx\n", trapFrame->r8, trapFrame->r9,
             trapFrame->r10, trapFrame->r11);
    DbgPrint("  r12=%#018lx r13=%#018lx r14=%#018lx r15=%#018lx\n", trapFrame->r12, trapFrame->r13,
             trapFrame->r14, trapFrame->r15);
    if (trapFrame->vector == 14)
    {
        uint64_t cr2;
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
        DbgPrint("  CR2=%#018lx\n", cr2);
    }
}

/* Walk the saved-RBP chain. Kernel stacks live in Limine's higher-half direct
 * map (top bit set), so bound the walk to canonical higher-half to avoid
 * chasing a wild pointer into a recursive fault. */
static void KiDumpStackTrace(uint64_t rbp)
{
    DbgPrint("  stack trace (rbp chain):\n");
    for (int index = 0; index < 16; index++)
    {
        if (rbp < 0xffff800000000000ULL || (rbp & 0x7) != 0)
        {
            break;
        }
        uint64_t *frame = (uint64_t *)(uintptr_t)rbp;
        uint64_t savedRbp = frame[0];
        uint64_t returnAddress = frame[1];
        if (returnAddress == 0)
        {
            break;
        }
        DbgPrint("    [%d] %#018lx\n", index, returnAddress);
        if (savedRbp <= rbp)
        {
            break; /* frame pointers must grow upward */
        }
        rbp = savedRbp;
    }
}

__attribute__((noreturn)) static void KiHalt(void)
{
    KiQemuExit(1);
    for (;;)
    {
        __asm__ volatile("hlt");
    }
}

/* A fault while dumping must not loop into an endless dump cascade: every
 * fatal path latches here first, and a second fatal entry halts after one
 * line. The first dump is the one that matters (Art. 9). Non-static: KASAN
 * suppresses its reports while this is set (see panic.h). */
int KiPanicInProgress;

static void KiPanicLatch(void)
{
    if (KiPanicInProgress)
    {
        DbgPrint("[PANIC] recursive fault during panic; halting\n");
        KiHalt();
    }
    KiPanicInProgress = 1;
}

/* The dump runs when kernel state may already be smashed (a stack overflow
 * ploughs through adjacent pool objects — including the current KTHREAD).
 * Before chasing a pointer read out of such memory, require it to at least
 * be canonical higher-half; a garbage value would re-fault and the latch
 * would truncate the dump. Best-effort, not proof of validity. */
static int KiLooksLikeKernelPointer(const void *pointer)
{
    /* Lowest canonical higher-half address for 48-bit virtual addressing
     * (Intel SDM Vol. 1 §3.3.7.1 "Canonical Addressing") — same bound the
     * kernel RBP walk above uses. */
    return (uint64_t)(uintptr_t)pointer >= 0xffff800000000000ULL;
}

/* Who and when: the identity block every fatal dump (and the #BP demo dump)
 * carries so a log line never needs out-of-band context — uptime, current
 * thread/process, kernel stack bounds (put next to the dumped RSP, a stack
 * overflow becomes visually obvious), and the last syscall by NAME. */
static void KiDumpSystemState(void)
{
    /* Recovered ticks alongside uptime: a platform that failed to deliver its
     * clock interrupts on schedule produced an uptime that is honest only
     * because the clock caught up (kernel/ke/timer.c KiTicksElapsed), and a
     * dump that showed uptime alone would hide how much of it was recovered
     * rather than ticked. */
    DbgPrint("  uptime=%lums (recovered=%lu)\n", (uint64_t)KeTickCount, (uint64_t)KiCatchUpTicks);
    PKTHREAD thread = KiCurrentThread; /* 0 before the scheduler exists */
    if (thread != 0 && KiLooksLikeKernelPointer(thread))
    {
        DbgPrint("  thread=%p state=%d prio=%d prevmode=%d\n", (void *)thread, thread->state,
                 (int)thread->priority, (int)thread->previousMode);
        if (KiLooksLikeKernelPointer(thread->process))
        {
            const char *imageName = thread->process->imageName;
            DbgPrint("  process=%p image='%s'\n", (void *)thread->process,
                     imageName != 0 && KiLooksLikeKernelPointer(imageName) ? imageName : "?");
        }
        DbgPrint("  kstack base=%p top=%#lx\n", thread->stackBase, thread->stackTop);
    }
    if (KiLastSystemCall != ~(uint64_t)0)
    {
        DbgPrint("  last_syscall=%#lx (%s)\n", KiLastSystemCall,
                 KiSystemCallName(KiLastSystemCall));
    }
    /* The unwind ledger (issue #32 A3): a boot that already swallowed ring-0
     * faults on user addresses is a boot whose earlier [UACCESS] lines are
     * part of this dump's story, so the dump says how many to go look for. */
    if (KiUserFaultRecoveryCount != 0)
    {
        DbgPrint("  uaccess_unwinds=%lu (unexpected=%lu)\n", KiUserFaultRecoveryCount,
                 KiUserFaultRecoveryUnexpected);
    }
    KiDumpTraceRing();
}

/* Walk the faulting process's USER RBP chain (user modules build with
 * forced frame pointers; crt0.S zeroes RBP as the terminator). Each frame's
 * two qwords are probed through the page tables first — the uaccess.c
 * pattern, sound under Art. 3 (no paging/eviction, uniprocessor, and we run
 * on the faulting thread's CR3 with no SMAP) — so a wild chain prints fewer
 * frames instead of re-faulting. */
static void KiDumpUserStackTrace(uint64_t rbp)
{
    PKTHREAD thread = KiCurrentThread;
    if (thread == 0 || !KiLooksLikeKernelPointer(thread->process))
    {
        return;
    }
    uint64_t pml4 = thread->process->addressSpace.pml4Physical;
    DbgPrint("  user stack trace (rbp chain):\n");
    for (int index = 0; index < 16; index++)
    {
        if (rbp == 0 || (rbp & 0x7) != 0 || rbp + 16 > KI_USER_SPACE_LIMIT)
        {
            break;
        }
        int probeOk = 1;
        for (uint64_t page = rbp & ~(uint64_t)(PAGE_SIZE - 1);
             page <= ((rbp + 15) & ~(uint64_t)(PAGE_SIZE - 1)); page += PAGE_SIZE)
        {
            int writable = 0;
            int present = 0;
            if (MiTranslateUserPage(pml4, page, &writable, &present) == 0 || !present)
            {
                probeOk = 0;
                break;
            }
        }
        if (!probeOk)
        {
            break;
        }
        uint64_t savedRbp = ((const uint64_t *)(uintptr_t)rbp)[0];
        uint64_t returnAddress = ((const uint64_t *)(uintptr_t)rbp)[1];
        if (returnAddress == 0)
        {
            break;
        }
        DbgPrint("    u[%d] %#018lx\n", index, returnAddress);
        if (savedRbp <= rbp)
        {
            break; /* frame pointers must grow upward */
        }
        rbp = savedRbp;
    }
}

/* Map a contained user-mode exception vector to the NTSTATUS the process
 * dies with (what a debugger/parent would observe). */
static NTSTATUS KiUserFaultStatus(uint64_t vector)
{
    switch (vector)
    {
    case 0:
        return STATUS_INTEGER_DIVIDE_BY_ZERO;
    case 6:
        return STATUS_ILLEGAL_INSTRUCTION;
    case 3:
        return STATUS_BREAKPOINT;
    case 12: /* #SS */
    case 14: /* #PF */
        return STATUS_ACCESS_VIOLATION;
    default:
        return STATUS_ACCESS_VIOLATION;
    }
}

/* Called from trap.S for every CPU exception (vectors 0..31) and every IRQ. */
void KiDispatchTrap(PKTRAP_FRAME trapFrame)
{
    /* Hardware interrupts route to Ke's dispatcher (kernel/ke/irq.c). */
    if (trapFrame->vector >= 32)
    {
        /* CUI-6: the interrupted CS discriminates the CPU-time charge — a
         * user-CS tick is user time, a kernel-CS one kernel time (NT's
         * clock-interrupt accounting; previousMode flags "inside a syscall",
         * not "was running ring-3 code", so it cannot serve here). */
        KiDispatchInterrupt(trapFrame->vector, (trapFrame->segCs & 3) == 3);
        /* CUI-4: the interrupt-return edge — the one that catches a syscall-
         * free ring-3 busy loop at the next timer tick (the EOI is already
         * sent). A foreign terminate reaps here; a closed suspend gate parks
         * here. Only when returning to ring 3. */
        if ((trapFrame->segCs & 3) == 3)
        {
            /* CUI-6: publish the interrupted ring-3 frame for the whole time
             * this user thread is off-CPU (parked on a closed suspend gate
             * OR round-robined out just below), the way the syscall edge
             * publishes its own (table.c). A syscall-free spinner is
             * otherwise invisible to foreign NtGetContextThread — its
             * trapFrame would be stale. Restored only when it is genuinely
             * about to re-enter ring 3, so nothing downstream reads an
             * interrupt frame as a syscall frame. */
            PKTHREAD current = KeGetCurrentThread();
            PKTRAP_FRAME previousFrame = current->trapFrame;
            current->trapFrame = trapFrame;
            KiProcessPendingUserSignals(current);
            /* The one preemption point: round-robin a ring-3 thread at the
             * timer tick so a syscall-free busy loop cannot starve others
             * (CUI-4 — without it a killer/parent never regains the CPU). */
            KiPreemptAtUserReturn();
            current->trapFrame = previousFrame;
        }
        return;
    }

    /* #BP taken in RING 0 is a trap: RIP already points past int3, so dump
     * and resume. This is how M1 demonstrates "an exception dumps registers
     * over serial" while keeping the run green. Every other vector is fatal.
     *
     * The ring test is load-bearing and belongs BEFORE the vector test: now
     * that vector 3's gate is DPL 3 (arch/x86_64/idt.c), a ring-3 `int3`
     * actually reaches here, and swallowing it as the M1 demo would hand
     * ring 3 an unbounded serial-spam primitive AND resume the faulting
     * thread instead of delivering STATUS_BREAKPOINT to its exception
     * dispatcher. */
    if (trapFrame->vector == 3 && (trapFrame->segCs & 3) == 0)
    {
        KiDumpTrapFrame("[KTEST] trap", trapFrame);
        KiDumpStackTrace(trapFrame->rbp);
        KiDumpSystemState();
        return;
    }

    /* M4: a fault taken IN ring 3 is contained as process termination, never
     * a kernel fault (docs/02 "a user crash is contained"). M5 slots one
     * resolvable case in front: a guard-page touch (stack growth), which
     * resumes the process silently. The dump still prints for everything
     * fatal — the panic handler is the debugger (Art. 9) — but with a
     * [USERFAULT] prefix and then the offending process exits. */
    if ((trapFrame->segCs & 3) == 3)
    {
        NTSTATUS faultStatus = KiUserFaultStatus(trapFrame->vector);
        uint64_t cr2 = 0;
        if (trapFrame->vector == 14)
        {
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            /* #PF error code bit 1 = the access was a write (Intel SDM
             * Vol. 3A §4.7, "Page-Fault Exceptions"). */
            faultStatus = MiHandleUserFault(cr2, (trapFrame->errorCode & 2) != 0);
            if (faultStatus == STATUS_SUCCESS)
            {
                /* Resolved fault returning to ring 3: same suspend/terminate
                 * edge as the interrupt path (a stack-growing loop must stay
                 * catchable). */
                KiProcessPendingUserSignals(KeGetCurrentThread());
                return; /* guard consumed / stack grown: resume ring 3 */
            }
        }

        /* M7: a first-chance user exception is delivered to the process's
         * KiUserExceptionDispatcher (docs/02 "the SEH test") — the fault
         * becomes a structured exception the user handler can catch, rather
         * than immediate process death. Only when the process resolved a
         * dispatcher; otherwise fall through to the contained-death path.
         * Trace BEFORE dispatch rewrites the frame, so the ring shows the
         * faulting RIP, not the dispatcher's. */
        KiTraceEvent(KiTraceUserFault, trapFrame->vector, trapFrame->rip, cr2);
        if (KeGetCurrentThread()->process->userExceptionDispatcher != 0 &&
            PspDispatchUserException(trapFrame, (ULONG)faultStatus, cr2))
        {
            return; /* iretq into the user exception dispatcher */
        }
        KiDumpTrapFrame("[USERFAULT]", trapFrame);
        KiDumpUserStackTrace(trapFrame->rbp);
        /* Entry + stack bounds make every user address in the dump an
         * offset a reader can compute (flat binaries: entry == image base;
         * tools/symbolize.py resolves against the module's .elf). */
        PEPROCESS process = KeGetCurrentThread()->process;
        DbgPrint("[USERFAULT] entry=%#018lx stack=[%#018lx,%#018lx)\n", process->entryRip,
                 process->stackAllocationBase, process->stackBase);
        DbgPrint("[USERFAULT] pid image '%s'; terminating process\n", process->imageName);
        PspExitCurrentProcess(faultStatus);
    }

    /* A ring-0 fault on a USER address inside a system service: unwind to the
     * dispatcher's recovery frame and let the service return
     * STATUS_ACCESS_VIOLATION, exactly as NT's KiSystemServiceHandler does.
     * Without this every missing or stale user-pointer probe is an
     * unprivileged machine halt rather than a failed syscall. Returns only
     * when there is nothing to unwind to (a genuine kernel-address bug), and
     * then the panic below is the right answer. */
    if (trapFrame->vector == 14 || trapFrame->vector == 12)
    {
        uint64_t faultAddress = 0;
        __asm__ volatile("mov %%cr2, %0" : "=r"(faultAddress));
        KiRecoverFromKernelFault(faultAddress, trapFrame->vector, trapFrame->rip);
    }

    KiPanicLatch();
    KiDumpTrapFrame("[PANIC]", trapFrame);
    KiDumpStackTrace(trapFrame->rbp);
    KiDumpSystemState();
    if (trapFrame->vector == 8)
    {
        /* We got here on the IST stack (idt.c); the dumped RSP is where the
         * faulted stack stood. */
        DbgPrint("[PANIC] #DF: compare RSP with the kstack bounds above — "
                 "likely kernel stack overflow\n");
    }
    DbgPrint("[PANIC] unhandled exception; halting\n");
    KiHalt();
}

__attribute__((noreturn)) void KiPanic(const char *message)
{
    KiPanicLatch();
    DbgPrint("[PANIC] %s\n", message);
    KiDumpStackTrace((uint64_t)(uintptr_t)__builtin_frame_address(0));
    KiDumpSystemState();
    KiHalt();
}

__attribute__((noreturn)) void KiAssertFail(const char *expression, const char *file, int line)
{
    KiPanicLatch();
    DbgPrint("[ASSERT] %s:%d: %s\n", file, line, expression);
    KiDumpStackTrace((uint64_t)(uintptr_t)__builtin_frame_address(0));
    KiDumpSystemState();
    DbgPrint("[PANIC] assertion failed; halting\n");
    KiHalt();
}
