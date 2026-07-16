/* kernel/init/panic.c — the thick fatal-error / trap handler (Constitution Art. 9).
 *
 * Under LLM-driven development the panic dump is the debugger: register state,
 * a frame-pointer stack trace, and the last syscall number, all on serial with
 * a machine-greppable [PANIC] prefix (docs/08). The CPU exception path and
 * UBSan traps (#UD) both land here.
 */
#include "kernel/init/panic.h"
#include "kernel/lib/kprintf.h"
#include "arch/x86_64/trap.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/lapic.h"

#include <stdint.h>

uint64_t KiLastSystemCall = ~(uint64_t)0;

static const char *KiExceptionName(uint64_t Vector)
{
    switch (Vector)
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

static void KiDumpTrapFrame(const char *Tag, PKTRAP_FRAME TrapFrame)
{
    DbgPrint("%s vector=%lu (%s) err=%#lx\n", Tag, TrapFrame->Vector,
             KiExceptionName(TrapFrame->Vector), TrapFrame->ErrorCode);
    DbgPrint("  RIP=%#018lx CS=%#lx RFLAGS=%#lx\n", TrapFrame->Rip, TrapFrame->SegCs,
             TrapFrame->EFlags);
    DbgPrint("  RSP=%#018lx SS=%#lx last_syscall=%#lx\n", TrapFrame->Rsp, TrapFrame->SegSs,
             KiLastSystemCall);
    DbgPrint("  RAX=%#018lx RBX=%#018lx RCX=%#018lx RDX=%#018lx\n", TrapFrame->Rax, TrapFrame->Rbx,
             TrapFrame->Rcx, TrapFrame->Rdx);
    DbgPrint("  RSI=%#018lx RDI=%#018lx RBP=%#018lx\n", TrapFrame->Rsi, TrapFrame->Rdi,
             TrapFrame->Rbp);
    DbgPrint("  R8 =%#018lx R9 =%#018lx R10=%#018lx R11=%#018lx\n", TrapFrame->R8, TrapFrame->R9,
             TrapFrame->R10, TrapFrame->R11);
    DbgPrint("  R12=%#018lx R13=%#018lx R14=%#018lx R15=%#018lx\n", TrapFrame->R12, TrapFrame->R13,
             TrapFrame->R14, TrapFrame->R15);
    if (TrapFrame->Vector == 14)
    {
        uint64_t Cr2;
        __asm__ volatile("mov %%cr2, %0" : "=r"(Cr2));
        DbgPrint("  CR2=%#018lx\n", Cr2);
    }
}

/* Walk the saved-RBP chain. Kernel stacks live in Limine's higher-half direct
 * map (top bit set), so bound the walk to canonical higher-half to avoid
 * chasing a wild pointer into a recursive fault. */
static void KiDumpStackTrace(uint64_t Rbp)
{
    DbgPrint("  stack trace (rbp chain):\n");
    for (int Index = 0; Index < 16; Index++)
    {
        if (Rbp < 0xffff800000000000ULL || (Rbp & 0x7) != 0)
        {
            break;
        }
        uint64_t *Frame = (uint64_t *)(uintptr_t)Rbp;
        uint64_t SavedRbp = Frame[0];
        uint64_t ReturnAddress = Frame[1];
        if (ReturnAddress == 0)
        {
            break;
        }
        DbgPrint("    [%d] %#018lx\n", Index, ReturnAddress);
        if (SavedRbp <= Rbp)
        {
            break; /* frame pointers must grow upward */
        }
        Rbp = SavedRbp;
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

/* Called from trap.S for every CPU exception (vectors 0..31) and the timer. */
void KiDispatchTrap(PKTRAP_FRAME TrapFrame)
{
    /* IRQs (>= 32) dispatch here too for now; a dedicated irq.c arrives with
     * the M2 scheduler. The LAPIC timer just bumps the tick counter. */
    if (TrapFrame->Vector == TIMER_VECTOR)
    {
        KiUpdateTickCount();
        KiEndOfInterrupt();
        return;
    }

    /* #BP is a trap: RIP already points past int3, so dump and resume. This is
     * how M1 demonstrates "an exception dumps registers over serial" while
     * keeping the run green. Every other vector is fatal. */
    if (TrapFrame->Vector == 3)
    {
        KiDumpTrapFrame("[KTEST] trap", TrapFrame);
        return;
    }

    KiDumpTrapFrame("[PANIC]", TrapFrame);
    KiDumpStackTrace(TrapFrame->Rbp);
    DbgPrint("[PANIC] unhandled exception; halting\n");
    KiHalt();
}

__attribute__((noreturn)) void KiPanic(const char *Message)
{
    DbgPrint("[PANIC] %s\n", Message);
    KiHalt();
}
