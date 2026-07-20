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
#include "kernel/lib/rtl.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/io/io.h"
#include "kernel/cm/cm.h"
#include "kernel/init/panic.h"
#include "kernel/init/initrd.h"
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

static int KiStringStartsWith(const char *s, const char *prefix)
{
    while (*prefix != '\0' && *s == *prefix)
    {
        s++;
        prefix++;
    }
    return *prefix == '\0';
}

/* Register every boot module as a RAM-disk file (M5: the seed read-only FS
 * that image and data sections map from). Call before the module runner —
 * and before the scheduler needs nothing, so early is fine. */
static void KiRegisterBootModules(void)
{
    if (LiModuleRequest.response == 0)
    {
        return;
    }
    for (uint64_t i = 0; i < LiModuleRequest.response->module_count; i++)
    {
        struct limine_file *module = LiModuleRequest.response->modules[i];
        const char *path = module->path != 0 ? module->path : "?";
        if (KiRegisterRamdiskFile(path, module->address, module->size) == 0)
        {
            KiPanic("KiRegisterBootModules: ramdisk table full / out of pool");
        }
    }
}

/* Run every PROGRAM boot module as a user process (M4/M5). A module whose
 * cmdline starts with "expect=" is a program declaring its expected outcome:
 * "expect=0" must exit STATUS_SUCCESS, "expect=av" must be contained as a
 * user-mode access violation (the crash test — its containment IS M4's "a
 * user crash is process termination, not a kernel fault"). Any other
 * cmdline (e.g. "initrd") marks a data file: registered, never run.
 * Returns failure count. */
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
        if (!KiStringStartsWith(expect, "expect="))
        {
            continue; /* a RAM-disk data file or an M7 module, not an M5 program */
        }

        PKI_RAMDISK_FILE file = KiFindRamdiskFile(KiRamdiskBasename(path));
        ASSERT(file != 0); /* KiRegisterBootModules registered every module */

        NTSTATUS exitStatus = 0;
        NTSTATUS runStatus = PsRunBootModule(file, &exitStatus);

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

/* Run the M7 boot modules (cmdline "m7"): a real PE process that drives the
 * M7 boundary from ring 3 — threads, PEB/TEB/KUSER_SHARED_DATA, the user
 * exception/APC dispatchers, NtContinue (docs/02 "Done when": hello.exe starts
 * and exits; the SEH test passes). Each must exit STATUS_SUCCESS. */
static int KiRunM7Modules(void)
{
    if (LiModuleRequest.response == 0)
    {
        return 0;
    }
    int failures = 0;
    int ran = 0;
    for (uint64_t i = 0; i < LiModuleRequest.response->module_count; i++)
    {
        struct limine_file *module = LiModuleRequest.response->modules[i];
        const char *tag = module->string != 0 ? module->string : "";
        if (!KiStringEquals(tag, "m7"))
        {
            continue;
        }
        const char *path = module->path != 0 ? module->path : "?";
        PKI_RAMDISK_FILE file = KiFindRamdiskFile(KiRamdiskBasename(path));
        ASSERT(file != 0);

        NTSTATUS exitStatus = 0;
        NTSTATUS runStatus = PsRunBootModule(file, &exitStatus);
        BOOLEAN pass = NT_SUCCESS(runStatus) && exitStatus == 0;
        DbgPrint("[KTEST] module %s %s (exit=%#lx)\n", path, pass ? "PASS" : "FAIL",
                 (unsigned long)exitStatus);
        ran++;
        if (!pass)
        {
            failures++;
        }
    }
    if (ran == 0)
    {
        DbgPrint("[KTEST] M7 no module ran\n");
        return 1;
    }
    return failures;
}

/* Run the M7 Wine acceptance (docs/02 "Done when"): hello.exe from the boot
 * volume, loaded beside the unmodified Wine PE ntdll.dll and started through
 * LdrInitializeThunk — ntdll's loader runs the process, and hello's SEH test
 * exercises KiUserExceptionDispatcher end to end. Exit 0 = PASS. */
static int KiRunWineHello(void)
{
    /* The ntapi/fuzz images carry no Wine userland (tests/run/run.sh builds
     * them without the windows/ tree); skip cleanly there. The `make run`
     * image ships ntdll.dll + hello.exe (Makefile WINFILES), so a load
     * failure on it IS a FAIL, not a skip. */
    struct MI_SECTION *probe;
    NTSTATUS probeStatus =
        IoOpenImageSection(WSTR("\\??\\C:\\windows\\system32\\ntdll.dll"), &probe);
    if (probeStatus == STATUS_OBJECT_NAME_NOT_FOUND || probeStatus == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        DbgPrint("[KTEST] module hello.exe SKIP (no ntdll.dll on the boot volume)\n");
        return 0;
    }
    if (!NT_SUCCESS(probeStatus))
    {
        DbgPrint("[KTEST] module hello.exe FAIL (ntdll probe=%#lx)\n", (unsigned long)probeStatus);
        return 1;
    }
    ObDereferenceObject(probe);

    NTSTATUS exitStatus = 0;
    NTSTATUS status = PsRunWineImage(WSTR("\\??\\C:\\hello.exe"), "C:\\hello.exe", &exitStatus);
    BOOLEAN pass = NT_SUCCESS(status) && exitStatus == 0;
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] module hello.exe FAIL (create=%#lx)\n", (unsigned long)status);
    }
    else
    {
        DbgPrint("[KTEST] module hello.exe %s (exit=%#lx)\n", pass ? "PASS" : "FAIL",
                 (unsigned long)exitStatus);
    }
    return pass ? 0 : 1;
}

/* Run the M8 initial process chain (docs/02): kernel → smss-equiv → test
 * process. smss.exe exits with hello.exe's code, so one verdict covers the
 * whole pipeline — including NtCreateUserProcess and the ring-3 registry. */
static int KiRunInitialChain(void)
{
    struct MI_SECTION *probe;
    NTSTATUS probeStatus =
        IoOpenImageSection(WSTR("\\??\\C:\\windows\\system32\\smss.exe"), &probe);
    if (probeStatus == STATUS_OBJECT_NAME_NOT_FOUND || probeStatus == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        DbgPrint("[KTEST] module smss.exe SKIP (no smss.exe on the boot volume)\n");
        return 0;
    }
    if (!NT_SUCCESS(probeStatus))
    {
        DbgPrint("[KTEST] module smss.exe FAIL (probe=%#lx)\n", (unsigned long)probeStatus);
        return 1;
    }
    ObDereferenceObject(probe);

    NTSTATUS exitStatus = 0;
    NTSTATUS status = PsRunWineImage(WSTR("\\??\\C:\\windows\\system32\\smss.exe"),
                                     "C:\\windows\\system32\\smss.exe", &exitStatus);
    BOOLEAN pass = NT_SUCCESS(status) && exitStatus == 0;
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] module smss.exe FAIL (create=%#lx)\n", (unsigned long)status);
    }
    else
    {
        DbgPrint("[KTEST] module smss.exe %s (exit=%#lx)\n", pass ? "PASS" : "FAIL",
                 (unsigned long)exitStatus);
    }
    return pass ? 0 : 1;
}

/* The in-kernel suites, run on a real kernel thread (waits need a
 * schedulable context). Ends the QEMU run with the milestone verdict
 * (docs/08): M3 PASS requires the M2 suite to stay green too. */
static void KiTestMainThread(void *context)
{
    /* M6 phase 2: mount the boot volume and publish it in the namespace —
     * needs a thread (handle tables live on the process). Everything after
     * this point, including the ring-3 boot modules, can open \??\C:. */
    IoMountBootVolume();

    /* M8: bring up the registry — \Registry + the SYSTEM hive from the boot
     * volume (an absent/invalid hive starts empty: first boot). Needs the
     * volume above and a thread with a handle table for the hive file I/O. */
    CmInitialize();

    int libFailures = kmt_run_lib();
    DbgPrint(libFailures == 0 ? "[KTEST] LIB PASS\n" : "[KTEST] LIB FAIL failures=%d\n",
             libFailures);

    int m2Failures = kmt_run_m2();
    DbgPrint(m2Failures == 0 ? "[KTEST] M2 PASS\n" : "[KTEST] M2 FAIL failures=%d\n", m2Failures);
    int m3Failures = kmt_run_m3();
    DbgPrint(m3Failures == 0 ? "[KTEST] M3 PASS\n" : "[KTEST] M3 FAIL failures=%d\n", m3Failures);

    /* M4: the mm/VAD engine in kernel mode. */
    int m4Failures = kmt_run_m4();
    DbgPrint(m4Failures == 0 ? "[KTEST] M4 PASS\n" : "[KTEST] M4 FAIL failures=%d\n", m4Failures);

    /* M5: sections + image mapping in kernel mode (kmt), then the ring-3
     * clients as boot modules — including the PE client the section-based
     * loader maps and runs, and M4's flat binaries (docs/02's "Done when":
     * NtCreateSection + NtMapViewOfSection maps a PE image). */
    int m5Failures = kmt_run_m5();
    m5Failures += KiRunBootModules();
    DbgPrint(m5Failures == 0 ? "[KTEST] M5 PASS\n" : "[KTEST] M5 FAIL failures=%d\n", m5Failures);

    /* M6: the I/O manager + FAT32 over virtio-blk (docs/02). The final
     * milestone line is the verdict tools/qemu.sh greps for, so it
     * aggregates every suite this run — a lib failure must flip it too. */
    int m6Failures = kmt_run_m6();
    m6Failures += libFailures;
    DbgPrint(m6Failures == 0 ? "[KTEST] M6 PASS\n" : "[KTEST] M6 FAIL failures=%d\n", m6Failures);

    /* M7: NtCreateUserProcess-shaped process lifecycle + the user-mode return
     * protocol, driven by a real PE client (the mountain — docs/02). This is
     * the milestone's acceptance artifact. */
    int m7Failures = KiRunM7Modules();
    /* The Wine bring-up half of M7: the unmodified PE ntdll runs hello.exe. */
    m7Failures += KiRunWineHello();
    DbgPrint(m7Failures == 0 ? "[KTEST] M7 PASS\n" : "[KTEST] M7 FAIL failures=%d\n", m7Failures);

    /* M8: the initial process chain (docs/02 "Done when: boot completes as
     * kernel → smss-equiv → test process"): smss.exe verifies \Registry from
     * ring 3, spawns hello.exe through NtCreateUserProcess, and exits with
     * the child's code. */
    int m8Failures = KiRunInitialChain();
    DbgPrint(m8Failures == 0 ? "[KTEST] M8 PASS\n" : "[KTEST] M8 FAIL failures=%d\n", m8Failures);

    /* End-of-suite #BP: the resume-path dump (panic.c) prints the full
     * system state INCLUDING a populated trace ring — every green run shows
     * what a real panic dump would look like after the whole boot suite
     * (Art. 9: eyeball the debugger's output without breaking the verdict). */
    __asm__ volatile("int3");

    int total =
        m2Failures + m3Failures + m4Failures + m5Failures + m6Failures + m7Failures + m8Failures;
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

    /* M6 phase 1: probe virtio-blk and map its MMIO window. Must precede
     * Ps: the window may claim a fresh kernel PML4 slot, and
     * MiFreezeKernelPml4 happens inside PsInitializeProcessSubsystem. */
    IoInitializeTransport();
    DbgPrint("[KTEST] io PASS\n");

    /* M4: the system process (owns the kernel address space + the kernel
     * handle table) and the kernel-PML4 freeze process page tables copy
     * from. Every thread carries a process, so this precedes the scheduler. */
    PsInitializeProcessSubsystem();
    DbgPrint("[KTEST] ps PASS\n");

    /* M5: every boot module becomes a RAM-disk file (the seed read-only FS
     * sections map images and data from — docs/02). */
    KiRegisterBootModules();
    DbgPrint("[KTEST] initrd PASS\n");

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
