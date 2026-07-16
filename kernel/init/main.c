/* kernel/init/main.c — kernel entry (M1 S0).
 *
 * Limine enters here in 64-bit long mode with a stack already set up. For S0
 * this only proves the toolchain + boot + QEMU loop: init serial, confirm the
 * Limine base revision, emit the [KTEST] verdict, and exit the VM (docs/08).
 * Real per-department init lands in later M1 slices.
 */
#include <stdint.h>

#include "limine.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"

/* Limine request block. The markers bound the region Limine scans; the base
 * revision tag negotiates protocol v3. Placed in dedicated sections so the
 * linker keeps them (arch/x86_64/linker.ld). */
__attribute__((used, section(".limine_requests_start_marker")))
static volatile uint64_t limine_requests_start[4] = LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[3] = LIMINE_BASE_REVISION(3);

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end[2] = LIMINE_REQUESTS_END_MARKER;

static void halt(void)
{
    for (;;) {
        __asm__ volatile("hlt");
    }
}

void kmain(void)
{
    serial_init();

    if (!LIMINE_BASE_REVISION_SUPPORTED(limine_base_revision)) {
        serial_puts("[PANIC] Limine base revision 3 unsupported\n");
        qemu_exit(1);
        halt();
    }

    serial_puts("[KTEST] boot PASS\n");

    qemu_exit(0);
    halt();
}
