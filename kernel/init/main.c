/* kernel/init/main.c — kernel entry (M1).
 *
 * Limine enters here in 64-bit long mode with a stack set up. M1 brings up the
 * boot essentials and proves the "Done when" criteria over serial (docs/02):
 * boots, an exception dumps registers, and (S4+) the timer ticks. Real
 * per-department init arrives in later milestones.
 */
#include <stdint.h>

#include "limine.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/idt.h"
#include "kernel/lib/kprintf.h"

__attribute__((used, section(".limine_requests_start_marker")))
static volatile uint64_t limine_requests_start[4] = LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[3] = LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end[2] = LIMINE_REQUESTS_END_MARKER;

__attribute__((noreturn)) static void halt(void)
{
    for (;;) {
        __asm__ volatile("hlt");
    }
}

void kmain(void)
{
    serial_init();

    if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision)) {
        kprintf("[PANIC] Limine base revision 3 unsupported\n");
        qemu_exit(1);
        halt();
    }
    kprintf("[KTEST] boot PASS\n");

    idt_init();
    kprintf("[KTEST] idt PASS\n");

    /* Demonstrate the exception path: a breakpoint traps into the panic
     * handler, which dumps registers over serial, then resumes (docs/02). */
    __asm__ volatile("int3");
    kprintf("[KTEST] trap-recovered PASS\n");

    qemu_exit(0);
    halt();
}
