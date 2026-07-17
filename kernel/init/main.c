/* kernel/init/main.c — kernel entry (M1+M2).
 *
 * Limine enters here in 64-bit long mode with a stack set up. Init order:
 * serial + IDT (M1), physical frames, the kernel's own page tables, the pool,
 * the scheduler and clock (M2). The boot context then spawns the in-kernel
 * test thread (tests/kmt) and becomes the idle thread. The [KTEST] verdicts
 * on serial are the milestone's proof (docs/02, docs/08).
 */
#include <stdint.h>

#include "limine.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/mmu.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/init/panic.h"
#include "tests/kmt/kmt.h"

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

/* Where Limine actually loaded the kernel, for building our own page tables. */
__attribute__((
    used, section(".limine_requests"))) static volatile struct limine_executable_address_request
    LiExecutableAddressRequest = {
        .id = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID,
        .revision = 0,
};

/* M4: flat-binary user clients, handed to the kernel as Limine modules
 * (docs/02: "test client is a flat binary"). tools/mkimage.sh bakes them
 * into the image and appends the module lines to limine.conf. */
__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_module_request LiModuleRequest = {
    .id = LIMINE_MODULE_REQUEST_ID,
    .revision = 0,
};

__attribute__((used,
               section(".limine_requests_end_marker"))) static volatile uint64_t LiRequestsEnd[2] =
    LIMINE_REQUESTS_END_MARKER;

static int KiStringEquals(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b)
    {
        a++;
        b++;
    }
    return *a == *b;
}

/* Run every boot module as a user process (M4). A module's cmdline string
 * declares its expected outcome: "expect=0" must exit STATUS_SUCCESS,
 * "expect=av" must be contained as a user-mode access violation (the crash
 * test — its containment IS the milestone's "a user crash is process
 * termination, not a kernel fault"). Returns failure count. */
static int KiRunBootModules(void)
{
    if (LiModuleRequest.response == 0)
    {
        return 0;
    }
    int failures = 0;
    for (uint64_t i = 0; i < LiModuleRequest.response->module_count; i++)
    {
        struct limine_file *module = LiModuleRequest.response->modules[i];
        const char *path = module->path != 0 ? module->path : "?";
        const char *expect = module->string != 0 ? module->string : "expect=0";

        NTSTATUS exitStatus = 0;
        NTSTATUS runStatus = PsRunBootModule(path, module->address, module->size, &exitStatus);

        BOOLEAN pass;
        if (KiStringEquals(expect, "expect=av"))
        {
            pass = NT_SUCCESS(runStatus) && exitStatus == STATUS_ACCESS_VIOLATION;
        }
        else
        {
            pass = NT_SUCCESS(runStatus) && exitStatus == 0;
        }
        DbgPrint("[KTEST] module %s %s (exit=%#lx)\n", path, pass ? "PASS" : "FAIL",
                 (unsigned long)exitStatus);
        if (!pass)
        {
            failures++;
        }
    }
    return failures;
}

/* The in-kernel suites, run on a real kernel thread (waits need a
 * schedulable context). Ends the QEMU run with the milestone verdict
 * (docs/08): M3 PASS requires the M2 suite to stay green too. */
static void KiTestMainThread(void *context)
{
    int m2Failures = kmt_run_m2();
    DbgPrint(m2Failures == 0 ? "[KTEST] M2 PASS\n" : "[KTEST] M2 FAIL failures=%d\n", m2Failures);
    int m3Failures = kmt_run_m3();
    DbgPrint(m3Failures == 0 ? "[KTEST] M3 PASS\n" : "[KTEST] M3 FAIL failures=%d\n", m3Failures);

    /* M4: the mm/VAD engine in kernel mode, then the real ring-3 clients as
     * boot modules (user memory + a waited-on event via syscalls, and a
     * contained crash — docs/02's "Done when"). */
    int m4Failures = kmt_run_m4();
    m4Failures += KiRunBootModules();
    DbgPrint(m4Failures == 0 ? "[KTEST] M4 PASS\n" : "[KTEST] M4 FAIL failures=%d\n", m4Failures);

    int total = m2Failures + m3Failures + m4Failures;
    KiQemuExit(total == 0 ? 0 : 1);
    /* The debug-exit teardown is asynchronous; do not run past it. */
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

    /* Our own GDT + TSS + syscall MSRs, off the bootloader's, BEFORE the IDT
     * so its gates capture our kernel CS (M4). */
    KiInitializeGdt();
    DbgPrint("[KTEST] gdt PASS\n");

    KiInitializeIdt();
    DbgPrint("[KTEST] idt PASS\n");

    /* Demonstrate the exception path: a breakpoint traps into the bugcheck
     * handler, which dumps registers over serial, then resumes (docs/02). */
    __asm__ volatile("int3");
    DbgPrint("[KTEST] trap-recovered PASS\n");

    if (LiHhdmRequest.response == 0 || LiMemmapRequest.response == 0 ||
        LiExecutableAddressRequest.response == 0)
    {
        KiPanic("missing HHDM/memmap/address response from Limine");
    }
    MiInitializePhysicalMemory(LiHhdmRequest.response->offset, LiMemmapRequest.response);
    DbgPrint("[KTEST] phys: %lu frames usable (%lu MiB)\n", MiGetTotalPageCount(),
             MiGetTotalPageCount() * PAGE_SIZE / (1024ULL * 1024));
    if (!MiTestPhysicalAllocator())
    {
        KiPanic("phys allocator self-test failed");
    }
    DbgPrint("[KTEST] phys PASS\n");

    /* M2: our own page tables (off the bootloader's), then the pool on top. */
    MiInitializeVirtualMemory(LiExecutableAddressRequest.response->physical_base,
                              LiExecutableAddressRequest.response->virtual_base,
                              LiMemmapRequest.response);
    if (!MiTestVirtualMemory())
    {
        KiPanic("virtual memory self-test failed");
    }
    DbgPrint("[KTEST] mmu PASS\n");

    MiInitializePool();
    if (!MiTestPool())
    {
        KiPanic("pool self-test failed");
    }
    DbgPrint("[KTEST] pool PASS\n");

    /* M3: the object manager and its namespace roots, on top of the pool. */
    ObpInitializeObjectManager();
    DbgPrint("[KTEST] ob PASS\n");

    /* M4: the system process (owns the kernel address space + the kernel
     * handle table) and the kernel-PML4 freeze process page tables copy
     * from. Every thread carries a process, so this precedes the scheduler. */
    PsInitializeProcessSubsystem();
    DbgPrint("[KTEST] ps PASS\n");

    /* Dispatcher structures must exist before the first clock interrupt. */
    KiInitializeTimerList();
    KiInitializeScheduler();
    KiInitializeClock(); /* calibrates against the PIT; enables interrupts */

    while (KeTickCount < 10)
    {
        __asm__ volatile("hlt");
    }
    DbgPrint("[KTEST] timer PASS (%lu ms ticks)\n", KeTickCount);
    DbgPrint("[KTEST] M1 PASS\n");

    /* M2: the dispatcher suite runs on its own thread; the boot context
     * becomes the idle thread. */
    KiCreateThread(8, KiTestMainThread, 0);
    KiIdleLoop();
}
