/* kernel/init/panic.c — the thick panic handler (Constitution Art. 9).
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

#include <stdint.h>

uint64_t g_last_syscall = ~(uint64_t)0;

static const char *exc_name(uint64_t v)
{
    switch (v) {
    case 0:  return "#DE divide error";
    case 1:  return "#DB debug";
    case 3:  return "#BP breakpoint";
    case 6:  return "#UD invalid opcode";
    case 8:  return "#DF double fault";
    case 12: return "#SS stack fault";
    case 13: return "#GP general protection";
    case 14: return "#PF page fault";
    default: return "exception";
    }
}

static void dump_regs(const char *tag, struct trap_frame *tf)
{
    kprintf("%s vector=%lu (%s) err=%#lx\n",
            tag, tf->vector, exc_name(tf->vector), tf->error_code);
    kprintf("  RIP=%#018lx CS=%#lx RFLAGS=%#lx\n", tf->rip, tf->cs, tf->rflags);
    kprintf("  RSP=%#018lx SS=%#lx last_syscall=%#lx\n",
            tf->rsp, tf->ss, g_last_syscall);
    kprintf("  RAX=%#018lx RBX=%#018lx RCX=%#018lx RDX=%#018lx\n",
            tf->rax, tf->rbx, tf->rcx, tf->rdx);
    kprintf("  RSI=%#018lx RDI=%#018lx RBP=%#018lx\n",
            tf->rsi, tf->rdi, tf->rbp);
    kprintf("  R8 =%#018lx R9 =%#018lx R10=%#018lx R11=%#018lx\n",
            tf->r8, tf->r9, tf->r10, tf->r11);
    kprintf("  R12=%#018lx R13=%#018lx R14=%#018lx R15=%#018lx\n",
            tf->r12, tf->r13, tf->r14, tf->r15);
    if (tf->vector == 14) {
        uint64_t cr2;
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
        kprintf("  CR2=%#018lx\n", cr2);
    }
}

/* Walk the saved-RBP chain. Kernel stacks live in Limine's higher-half direct
 * map (top bit set), so bound the walk to canonical higher-half to avoid
 * chasing a wild pointer into a recursive fault. */
static void stack_trace(uint64_t rbp)
{
    kprintf("  stack trace (rbp chain):\n");
    for (int i = 0; i < 16; i++) {
        if (rbp < 0xffff800000000000ULL || (rbp & 0x7) != 0) {
            break;
        }
        uint64_t *frame = (uint64_t *)(uintptr_t)rbp;
        uint64_t saved_rbp = frame[0];
        uint64_t ret_addr  = frame[1];
        if (ret_addr == 0) {
            break;
        }
        kprintf("    [%d] %#018lx\n", i, ret_addr);
        if (saved_rbp <= rbp) {
            break; /* frame pointers must grow upward */
        }
        rbp = saved_rbp;
    }
}

__attribute__((noreturn)) static void die(void)
{
    qemu_exit(1);
    for (;;) {
        __asm__ volatile("hlt");
    }
}

/* Called from trap.S for every CPU exception (vectors 0..31). */
void trap_handler(struct trap_frame *tf)
{
    /* #BP is a trap: RIP already points past int3, so dump and resume. This is
     * how M1 demonstrates "an exception dumps registers over serial" while
     * keeping the run green. Every other vector is fatal. */
    if (tf->vector == 3) {
        dump_regs("[KTEST] trap", tf);
        return;
    }

    dump_regs("[PANIC]", tf);
    stack_trace(tf->rbp);
    kprintf("[PANIC] unhandled exception; halting\n");
    die();
}

__attribute__((noreturn)) void panic(const char *msg)
{
    kprintf("[PANIC] %s\n", msg);
    die();
}
