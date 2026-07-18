/* kernel/init/panic.c — the thick fatal-error / trap handler (Constitution Art. 9).
 *
 * Under LLM-driven development the panic dump is the debugger: register state,
 * a frame-pointer stack trace, and the last syscall number, all on serial with
 * a machine-greppable [PANIC] prefix (docs/08). The CPU exception path and
 * UBSan traps (#UD) both land here.
 */
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/fault.h"
#include "kernel/syscall/syscall.h"
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
 * line. The first dump is the one that matters (Art. 9). */
static int KiPanicInProgress;

static void KiPanicLatch(void)
{
    if (KiPanicInProgress)
    {
        DbgPrint("[PANIC] recursive fault during panic; halting\n");
        KiHalt();
    }
    KiPanicInProgress = 1;
}

/* Who and when: the identity block every fatal dump (and the #BP demo dump)
 * carries so a log line never needs out-of-band context — uptime, current
 * thread/process, kernel stack bounds (put next to the dumped RSP, a stack
 * overflow becomes visually obvious), and the last syscall by NAME. */
static void KiDumpSystemState(void)
{
    DbgPrint("  uptime=%lums\n", (uint64_t)KeTickCount);
    PKTHREAD thread = KiCurrentThread; /* 0 before the scheduler exists */
    if (thread != 0)
    {
        DbgPrint("  thread=%p state=%d prio=%d prevmode=%d\n", (void *)thread, thread->state,
                 (int)thread->priority, (int)thread->previousMode);
        if (thread->process != 0)
        {
            DbgPrint("  process=%p image='%s'\n", (void *)thread->process,
                     thread->process->imageName != 0 ? thread->process->imageName : "?");
        }
        DbgPrint("  kstack base=%p top=%#lx\n", thread->stackBase, thread->stackTop);
    }
    if (KiLastSystemCall != ~(uint64_t)0)
    {
        DbgPrint("  last_syscall=%#lx (%s)\n", KiLastSystemCall,
                 KiSystemCallName(KiLastSystemCall));
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
        KiDispatchInterrupt(trapFrame->vector);
        return;
    }

    /* #BP is a trap: RIP already points past int3, so dump and resume. This is
     * how M1 demonstrates "an exception dumps registers over serial" while
     * keeping the run green. Every other vector is fatal. */
    if (trapFrame->vector == 3)
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
        if (trapFrame->vector == 14)
        {
            uint64_t cr2;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            faultStatus = MiHandleUserFault(cr2);
            if (faultStatus == STATUS_SUCCESS)
            {
                return; /* guard consumed / stack grown: resume ring 3 */
            }
        }
        KiDumpTrapFrame("[USERFAULT]", trapFrame);
        DbgPrint("[USERFAULT] pid image '%s'; terminating process\n",
                 KeGetCurrentThread()->process->imageName);
        PspExitCurrentProcess(faultStatus);
    }

    KiPanicLatch();
    KiDumpTrapFrame("[PANIC]", trapFrame);
    KiDumpStackTrace(trapFrame->rbp);
    KiDumpSystemState();
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
