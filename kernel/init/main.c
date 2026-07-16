/* kernel/init/main.c — kernel entry (M1).
 *
 * Limine enters here in 64-bit long mode with a stack set up. M1 brings up the
 * boot essentials and proves the "Done when" criteria over serial (docs/02):
 * boots, an exception dumps registers, and the timer ticks. Real per-department
 * init arrives in later milestones.
 */
#include <stdint.h>

#include "limine.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/lapic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/mm/phys.h"
#include "kernel/init/panic.h"

__attribute__((
    used, section(".limine_requests_start_marker"))) static volatile uint64_t LiRequestsStart[4] =
    LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests"))) static volatile uint64_t LiBaseRevision[3] =
    LIMINE_BASE_REVISION(3);

/* Higher-half direct-map offset (phys->virt) and the physical memory map, for
 * the page-frame allocator. */
__attribute__((
    used, section(".limine_requests"))) static volatile struct limine_hhdm_request LiHhdmRequest = {
    .id = LIMINE_HHDM_REQUEST_ID,
    .revision = 0,
};

__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_memmap_request LiMemmapRequest = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
    .revision = 0,
};

__attribute__((used,
               section(".limine_requests_end_marker"))) static volatile uint64_t LiRequestsEnd[2] =
    LIMINE_REQUESTS_END_MARKER;

__attribute__((noreturn)) static void KiIdleLoop(void)
{
    for (;;)
    {
        __asm__ volatile("hlt");
    }
}

void KiSystemStartup(void)
{
    KiInitializeSerial();

    if (!LIMINE_BASE_REVISION_SUPPORTED(LiBaseRevision))
    {
        KiPanic("Limine base revision 3 unsupported");
    }
    DbgPrint("[KTEST] boot PASS\n");

    KiInitializeIdt();
    DbgPrint("[KTEST] idt PASS\n");

    /* Demonstrate the exception path: a breakpoint traps into the bugcheck
     * handler, which dumps registers over serial, then resumes (docs/02). */
    __asm__ volatile("int3");
    DbgPrint("[KTEST] trap-recovered PASS\n");

    KiInitializeTimer();
    while (KeTickCount < 10)
    {
        __asm__ volatile("hlt");
    }
    __asm__ volatile("cli");
    DbgPrint("[KTEST] timer PASS (%lu ticks)\n", KeTickCount);

    if (LiHhdmRequest.response == 0 || LiMemmapRequest.response == 0)
    {
        KiPanic("missing HHDM/memmap response from Limine");
    }
    MiInitializePhysicalMemory(LiHhdmRequest.response->offset, LiMemmapRequest.response);
    DbgPrint("[KTEST] phys: %lu frames usable (%lu MiB)\n", MiGetTotalPageCount(),
             MiGetTotalPageCount() * PAGE_SIZE / (1024ULL * 1024));
    if (!MiTestPhysicalAllocator())
    {
        KiPanic("phys allocator self-test failed");
    }
    DbgPrint("[KTEST] phys PASS\n");

    DbgPrint("[KTEST] M1 PASS\n");
    KiQemuExit(0);
    KiIdleLoop();
}
