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
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/mmu.h"
#include "arch/x86_64/smbios.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/se/se.h"
#include "kernel/io/io.h"
#include "kernel/cm/cm.h"
#include "kernel/syscall/syscall.h"
#include "fs/npfs/npfs.h"
#include "drivers/afd.h"
#include "drivers/condrv.h"
#include "drivers/fb.h"
#include "drivers/hid.h"
#include "drivers/net/netd.h"
#include "drivers/snd.h"
#include "drivers/virtio/blk.h"
#include "kernel/init/bootvid.h"
#include "kernel/init/panic.h"
#include "kernel/init/initrd.h"
#include "kernel/init/verify.h"
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

/* The firmware's SMBIOS entry point, for the SystemFirmwareTableInformation
 * RSMB provider (arch/x86_64/smbios.c). Absent on firmware that publishes no
 * SMBIOS at all, which the class then refuses. */
__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_smbios_request LiSmbiosRequest = {
    .id = LIMINE_SMBIOS_REQUEST_ID,
    .revision = 0,
};

__attribute__((used,
               section(".limine_requests_end_marker"))) static volatile uint64_t LiRequestsEnd[2] =
    LIMINE_REQUESTS_END_MARKER;

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
        KiVerifyKernelState(); /* the exited process must have left no debris */
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
        KiVerifyKernelState();
    }
    if (ran == 0)
    {
        DbgPrint("[KTEST] M7 no module ran\n");
        return 1;
    }
    return failures;
}

/* Run the standing ABI-conformance probe (cmdline "abi"): a native PE that
 * asserts ring-3 CONVENTIONS rather than features — entry-rsp alignment, the
 * FXSAVE seed values, mapped-header rebasing, TEB/query id agreement, the
 * process cookie, KUSER_SHARED_DATA ticking, the absolute-timeout contract
 * (tests/boot/abi_probe.c). The checks guard documented contracts no
 * current consumer may exercise yet, so a convention regression names itself
 * here instead of surfacing as a distant Wine crash. Exit 0 = conformant;
 * a missing probe module is itself a failure (the probe must never silently
 * fall off the image). */
static int KiRunAbiProbe(void)
{
    if (LiModuleRequest.response == 0)
    {
        return 1;
    }
    int failures = 0;
    int ran = 0;
    for (uint64_t i = 0; i < LiModuleRequest.response->module_count; i++)
    {
        struct limine_file *module = LiModuleRequest.response->modules[i];
        const char *tag = module->string != 0 ? module->string : "";
        if (!KiStringEquals(tag, "abi"))
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
        DbgPrint("[KTEST] ABI no probe ran\n");
        return 1;
    }
    return failures;
}

/* Probe/skip on the boot volume's content: does `path` exist? The one
 * authority for every flag-file and presence probe below (G10). */
static BOOLEAN KiBootFileExists(PCWSTR path)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attributes, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    NtClose(handle);
    return TRUE;
}

/* The interactive boot (make run, make rungui): a human owns the console —
 * the test suites are skipped and the console goes straight to cmd.exe or the
 * shell (via the session manager).
 *
 * Decided by the QEMU command line rather than by the image: `-fw_cfg
 * name=opt/org.proskrnl/interactive,string=1` (tools/qemu.sh
 * GUEST_INTERACTIVE=1), surfacing as \Registry\Machine\Hardware\qemu
 * "Interactive" (kernel/cm/registry.c). Booting somewhere with no fw_cfg
 * device at all — real hardware, another hypervisor — has no command line to
 * have said either way, and nobody there is scraping a serial log for
 * [KTEST] lines, so the default is the interactive boot. smss makes the same
 * call for its half of the session (user/smss/smss.c
 * SmssIsInteractiveBoot). */
static BOOLEAN KiIsInteractiveBoot(void)
{
    return CmQueryQemuBootFlag(WSTR("Interactive"), 1) != 0;
}

/* Art. 12 dialed to fatal: arm the dispatcher's panic on any
 * STATUS_NOT_IMPLEMENTED answer (kernel/syscall/table.c) — no refusal is
 * exempt.
 *
 * Same channel as KiIsInteractiveBoot, opposite default. Armed on every boot
 * that found a fw_cfg device — that default is the seeding table's, not this
 * script's or that one's (kernel/cm/registry.c CmpQemuBootFlags), so "under
 * QEMU" is what arms it rather than "launched through tools/qemu.sh". The
 * distinction matters because the two were the same thing only by discipline:
 * every leg does boot through that script today, but a hand-rolled qemu line
 * (docs/08's recipe) would have lost the net silently, and losing it is
 * invisible — the run still passes.
 *
 * Off where no fw_cfg device answered at all, which is the one case that is
 * not a development VM. Arming is a development stance ("convict the first
 * unbuilt service I needed"), and defaulting a machine we know nothing about
 * into a kernel panic on a missing service is the wrong way round; the
 * interactive flag defaults the other way there for the mirror reason — that
 * unknown machine has a human at it. PANIC_NOTIMPL=0 says otherwise out
 * loud. */
static void KiConfigurePanicOnNotImplemented(void)
{
    KiPanicOnNotImplemented = CmQueryQemuBootFlag(WSTR("PanicOnNotImplemented"), 0) != 0;
    if (KiPanicOnNotImplemented)
    {
        DbgPrint("[KTEST] panic on STATUS_NOT_IMPLEMENTED armed "
                 "(Hardware\\qemu PanicOnNotImplemented)\n");
    }
}

/* CUI-8 stress (docs/19 §8.1): C:\cui8_stress.flag zeroes the await
 * drain-spin, so every device await parks — the maximally different legal
 * interleaving, with which every verdict must still agree (the cui8 leg
 * compares). Never baked into a default image (tools/mkimage.sh
 * CUI8_STRESS=1) — the last knob still decided by the IMAGE rather than by
 * the run, now that the interactive and panic flags ride the QEMU command
 * line (docs/10 HACK-006). KiBootFileExists is its one remaining caller. */
static void KiConfigureCui8Stress(void)
{
    if (KiBootFileExists(WSTR("\\??\\C:\\cui8_stress.flag")))
    {
        VioBlkSetAwaitSpinBound(0);
        DbgPrint("[KTEST] cui8 stress knob armed (C:\\cui8_stress.flag)\n");
    }
}

/* Launch the session manager (user/smss): the ONE user image the kernel
 * starts. Everything user-mode past this point — wineserver-lite, conhost,
 * firstboot, the interactive console, the acceptance flows, the ntapi and
 * winetest sweeps, the GUI legs — is smss.exe's job, spawned through the
 * real NtCreateUserProcess boundary; smss prints the same [KTEST] verdict
 * lines this thread used to (NtDisplayString shares the serial transport,
 * kernel/ps/display.c), so the harness greps are unchanged. Its exit code
 * is its failure count. The kernel's ABI-probe count rides the command line
 * so smss can fold it into the M9 verdict (the `make test` PASS_RE) exactly
 * as the kernel runner did; on images with no smss.exe the count lands in
 * the return value instead. On GUI images smss parks forever with its
 * clients — the wait never returns, and the leg owns QEMU's lifetime. */
static int KiRunSessionManager(int abiFailures)
{
    struct MI_SECTION *probe;
    NTSTATUS probeStatus =
        IoOpenImageSection(WSTR("\\??\\C:\\windows\\system32\\smss.exe"), &probe);
    if (probeStatus == STATUS_OBJECT_NAME_NOT_FOUND || probeStatus == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        DbgPrint("[KTEST] smss.exe SKIP (not on the boot volume)\n");
        return abiFailures;
    }
    if (!NT_SUCCESS(probeStatus))
    {
        DbgPrint("[KTEST] smss.exe FAIL (probe=%#lx)\n", (unsigned long)probeStatus);
        return abiFailures + 1;
    }
    ObDereferenceObject(probe);

    char commandLine[24] = "smss.exe abi=";
    int n = 13;
    int value = abiFailures < 999 ? abiFailures : 999;
    char digits[4];
    int d = 0;
    do
    {
        digits[d++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (d != 0)
    {
        commandLine[n++] = digits[--d];
    }
    commandLine[n] = '\0';

    NTSTATUS exitStatus = 0;
    NTSTATUS status =
        PsRunUserImageEx(WSTR("\\??\\C:\\windows\\system32\\smss.exe"),
                         "C:\\windows\\system32\\smss.exe", commandLine, 0, &exitStatus);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] smss.exe FAIL (create=%#lx)\n", (unsigned long)status);
        return abiFailures + 1;
    }
    if (!NT_SUCCESS(exitStatus))
    {
        /* A crash status, not a failure count — the session died. */
        DbgPrint("[KTEST] smss.exe FAIL (exit=%#lx)\n", (unsigned long)exitStatus);
        return abiFailures + 1;
    }
    return (int)exitStatus; /* the session's failure count (ABI folded in) */
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

    /* \Device\Null + \??\NUL — the bit bucket ntdll's DOS-path resolution
     * turns the reserved name "nul" into. Same no-disk dependency as npfs
     * below. Consumer: ucrtbase:file's fopen("nul"). */
    IoInitializeNullDevice();

    /* M9: the named-pipe FS (\Device\NamedPipe + \??\pipe). No disk
     * dependency — only the namespace and this thread's handle table. */
    NpfsInitialize();

    /* M9: the console devices — \Device\Serial0 (the HACK-004 serial
     * transport) and, with conhost, the ConDrv console object. */
    CondrvInitialize();

    /* GUI-1: \Device\Fb0 over the framebuffer Limine set (HACK-001). No
     * framebuffer means no device — nothing else in the boot cares. */
    FbInitialize();

    /* GUI-1: \Device\Input0 over virtio-input (HACK-002). No input device
     * means no device published -- an open then fails honestly. */
    HidInitialize();

    /* AUD-1: \Device\Snd* over virtio-snd (HACK-007). Same rule: no sound
     * device, no nodes, and an open fails honestly. */
    SndInitialize();

    /* M8: bring up the registry — \Registry + the SYSTEM hive from the boot
     * volume (an absent/invalid hive starts empty: first boot). Needs the
     * volume above and a thread with a handle table for the hive file I/O. */
    CmInitialize();
    PspInitializeLanguage();

    /* Arm the panic-on-STATUS_NOT_IMPLEMENTED boot before anything runs
     * ring-3 code — smss below is a Wine process (needs only the boot
     * volume, mounted above). */
    KiConfigurePanicOnNotImplemented();
    KiConfigureCui8Stress();

    /* Net-1: lwIP + the netd mainloop over the NIC IoInitializeTransport
     * probed pre-freeze. Deliberately here — after the boot volume and the
     * registry (the DHCP lease is written through the ordinary NtSetValueKey
     * path) and before anything that might want the wire (docs/24 §4b).
     * Since Net-2 the stack and its thread come up on every image (the
     * loopback interface is \Device\Afd's device-free substrate); only
     * the ethernet netif and DHCP need the NIC. */
    NetInitialize();

    /* Net-2: \Device\Afd — the socket boundary ws2_32 issues, over the
     * stack brought up above (loopback works with no NIC at all). */
    AfdInitialize();

    /* The interactive boot (make run) skips the kernel test suites: the
     * serial console belongs to a human — the session manager runs
     * firstboot and hands the console to cmd.exe, and the VM powers off
     * when it exits (`exit` at the prompt). */
    if (KiIsInteractiveBoot())
    {
        KiRunSessionManager(0);
        KiQemuExit(0);
        /* The debug-exit teardown is asynchronous; do not run past it. */
        for (;;)
        {
            __asm__ volatile("hlt");
        }
    }

    /* Boot is quiescent: the first consistency sweep (kernel/init/verify.c)
     * baselines the executive before any suite mutates it; the per-suite
     * sweeps below then catch the suite that introduced an inconsistency,
     * not the consumer that later trips over it. */
    KiVerifyKernelState();

    int libFailures = kmt_run_lib();
    DbgPrint(libFailures == 0 ? "[KTEST] LIB PASS\n" : "[KTEST] LIB FAIL failures=%d\n",
             libFailures);
    KiVerifyKernelState();

    int m2Failures = kmt_run_m2();
    DbgPrint(m2Failures == 0 ? "[KTEST] M2 PASS\n" : "[KTEST] M2 FAIL failures=%d\n", m2Failures);
    KiVerifyKernelState();
    int m3Failures = kmt_run_m3();
    DbgPrint(m3Failures == 0 ? "[KTEST] M3 PASS\n" : "[KTEST] M3 FAIL failures=%d\n", m3Failures);
    KiVerifyKernelState();

    /* M4: the mm/VAD engine in kernel mode. */
    int m4Failures = kmt_run_m4();
    DbgPrint(m4Failures == 0 ? "[KTEST] M4 PASS\n" : "[KTEST] M4 FAIL failures=%d\n", m4Failures);
    KiVerifyKernelState();

    /* M5: sections + image mapping in kernel mode (kmt), then the ring-3
     * clients as boot modules — including the PE client the section-based
     * loader maps and runs, and M4's flat binaries (docs/02's "Done when":
     * NtCreateSection + NtMapViewOfSection maps a PE image). */
    int m5Failures = kmt_run_m5();
    m5Failures += KiRunBootModules();
    DbgPrint(m5Failures == 0 ? "[KTEST] M5 PASS\n" : "[KTEST] M5 FAIL failures=%d\n", m5Failures);
    KiVerifyKernelState();

    /* M6: the I/O manager + FAT32 over virtio-blk (docs/02). The final
     * milestone line is the verdict tools/qemu.sh greps for, so it
     * aggregates every suite this run — a lib failure must flip it too. */
    int m6Failures = kmt_run_m6();
    m6Failures += libFailures;
    DbgPrint(m6Failures == 0 ? "[KTEST] M6 PASS\n" : "[KTEST] M6 FAIL failures=%d\n", m6Failures);
    KiVerifyKernelState();

    /* The CUI-8 machine verdicts (docs/19 §8.3/§8.4): progress while a
     * transfer is parked, the depth floor, in-flight cancellation. After
     * M6 (the volume and the Nt* file surface it drives are up). */
    int cui8Failures = kmt_run_cui8();
    DbgPrint(cui8Failures == 0 ? "[KTEST] CUI8 PASS\n" : "[KTEST] CUI8 FAIL failures=%d\n",
             cui8Failures);
    KiVerifyKernelState();

    /* The CUI-9 shared-master verdicts (docs/17 §8): the sharing metric and
     * the master lifecycle, in kernel mode over scratch address spaces. */
    int cui9Failures = kmt_run_cui9();
    DbgPrint(cui9Failures == 0 ? "[KTEST] CUI9 PASS\n" : "[KTEST] CUI9 FAIL failures=%d\n",
             cui9Failures);
    KiVerifyKernelState();

    /* The console driver's terminate-unwind states (tests/kmt/condrv_unwind.c):
     * it drives conhost's side of \Device\ConDrv\Server itself, so it must run
     * BEFORE smss starts the real conhost — there is one server slot. */
    int condrvFailures = kmt_run_condrv();
    DbgPrint(condrvFailures == 0 ? "[KTEST] CONDRV PASS\n" : "[KTEST] CONDRV FAIL failures=%d\n",
             condrvFailures);
    KiVerifyKernelState();

    /* The issue #96 preventive-mechanism guards: the no-block depth and the
     * obligation ledger are balanced across the gated FS verbs. After CUI8,
     * so a region or a hold leaked by ANY earlier suite is attributed here
     * rather than to whichever later park it would otherwise kill. */
    int preventiveFailures = kmt_run_preventive();
    DbgPrint(preventiveFailures == 0 ? "[KTEST] PREVENTIVE PASS\n"
                                     : "[KTEST] PREVENTIVE FAIL failures=%d\n",
             preventiveFailures);
    KiVerifyKernelState();

    /* The issue #96 D interleaving search: two-thread compositions replayed
     * under enumerated schedules, judged by linearizability. After
     * PREVENTIVE, because it leans on everything above it (the volume gate,
     * the drain, the ledgers) already being sound. */
    int schedFailures = kmt_run_sched_explore();
    DbgPrint(schedFailures == 0 ? "[KTEST] SCHED PASS\n" : "[KTEST] SCHED FAIL failures=%d\n",
             schedFailures);
    KiVerifyKernelState();

    /* The standing ABI-conformance probe: ring-3 conventions asserted every
     * boot (tests/boot/abi_probe.c). Before the M7 clients, so a broken
     * convention names itself here rather than surfacing as an M7 crash. */
    int abiFailures = KiRunAbiProbe();
    DbgPrint(abiFailures == 0 ? "[KTEST] ABI PASS\n" : "[KTEST] ABI FAIL failures=%d\n",
             abiFailures);

    /* The FAT interop battery (tests/kmt/fat_interop.c): only on images
     * baked with C:\fatcorpus\manifest.txt (run.sh fatinterop). Prints its
     * own [KTEST] FATINTEROP verdict when it runs; absence is silent. */
    int fatInteropFailures = kmt_run_fat_interop();

    /* The FS churn stress (tests/kmt/fat_churn.c): only on images baked
     * with C:\churn.cfg (run.sh fatstress); prints its own churn-seed /
     * churn-verify verdict. Absence is silent. */
    fatInteropFailures += kmt_run_fat_churn();

    /* The \Device\Snd* contract smoke (tests/kmt/snd.c): only on boots
     * whose QEMU carries a virtio-snd device (run.sh audio). Prints its
     * own [KTEST] SND verdict when it runs; absence is silent. */
    fatInteropFailures += kmt_run_snd();

    /* The Net-1 device verdicts (tests/kmt/net_smoke.c): only when a NIC
     * exists (the run.sh net leg boots with -netdev user + virtio-net-pci);
     * prints its own [KTEST] verdicts. Absence is silent. */
    fatInteropFailures += kmt_run_net();

    /* M7: NtCreateUserProcess-shaped process lifecycle + the user-mode return
     * protocol, driven by a real PE client (the mountain — docs/02). This is
     * the milestone's acceptance artifact. The Wine bring-up half — the
     * unmodified PE ntdll running hello.exe — now lives in the session
     * manager's M8 chain (user/smss/session.c), which runs the same binary
     * through NtCreateUserProcess. */
    int m7Failures = KiRunM7Modules();
    DbgPrint(m7Failures == 0 ? "[KTEST] M7 PASS\n" : "[KTEST] M7 FAIL failures=%d\n", m7Failures);
    KiVerifyKernelState();

    /* The session: everything user-mode from here — the servers, firstboot,
     * the M8/M9 acceptance flows and their [KTEST] verdicts, the ntapi and
     * wtest sweeps, the console flows, the GUI legs (which never return on
     * GUI images) — happens inside smss.exe. Per-process kernel sweeps
     * continue from the idle loop: every process teardown requests one
     * (kernel/init/verify.c), so each exited test still gets audited. */
    int sessionFailures = KiRunSessionManager(abiFailures);

    /* The whole run swept clean: every sweep either passed or panicked, so
     * reaching this line IS the verdict (plus the idle-loop sweeps that ran
     * whenever the machine went quiet). */
    KiVerifyKernelState();
    DbgPrint("[KTEST] sweep PASS (%lu sweeps)\n", (unsigned long)KiSweepCount);

    /* End-of-suite #BP: the resume-path dump (panic.c) prints the full
     * system state INCLUDING a populated trace ring — every green run shows
     * what a real panic dump would look like after the whole boot suite
     * (Art. 9: eyeball the debugger's output without breaking the verdict). */
    __asm__ volatile("int3");

    /* EVERY suite this run reached, including the four that used to be left
     * out — cui8/condrv/preventive/sched all report after M6, and a boot's
     * verdict is one PASS_RE grep (tools/qemu.sh), so omitting them here left
     * their counts with no reader at all. The log stays the authority for the
     * verdict (tests/run/kmtcheck.sh reads these same lines, which is what
     * `make test` gates on); this status is the second, in-kernel statement of
     * the same total. abiFailures reaches it through KiRunSessionManager. */
    int total = m2Failures + m3Failures + m4Failures + m5Failures + m6Failures + cui8Failures +
                condrvFailures + preventiveFailures + schedFailures + fatInteropFailures +
                m7Failures + sessionFailures;
    /* What the clock had to recover to stay honest over this boot (docs/22
     * §4a). Not a verdict — no test in the guest can convict a clock that ran
     * slow, every clock here having shared the error — but the measurement
     * that says whether this platform delivers its interrupts on schedule, and
     * the number to watch when a timing-sensitive test starts flaking. */
    DbgPrint("clock: %lu ms uptime, %lu ms recovered from undelivered ticks\n",
             (uint64_t)KeTickCount, (uint64_t)KiCatchUpTicks);
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

    /* The screen joins the serial log here, before anything that can fail:
     * the console needs no allocator and no page tables of ours, so there is
     * no reason for it to come up later than this (kernel/init/bootvid.h).
     * It gives the framebuffer back at FbInitialize. */
    KiInitializeBootVideo();
    if (!KiTestBootVideo())
    {
        KiPanic("boot console self-test failed: the console is up but the scanout is blank");
    }

    DbgPrint("\n"
             "  _n_\n"
             "  o-o =3\n"
             "    ____\n"
             "   / ^  \\\n"
             "   ~__* /     proskrnl - WinNT compatible toy kernel\n"
             "     /  /     Copyright (C) 2026 Tetsui Ohkubo\n"
             "    |=) \\_/\n"
             "    \\____/\n"
             "     /  \\\n"
             "    ^    ^\n\n");

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

    /* The firmware tables, once paging can reach reserved memory: Limine
     * reports the entry point physically (base revision 3). */
    if (LiSmbiosRequest.response != 0)
    {
        KiSmbiosInitialize((uint64_t)(uintptr_t)LiSmbiosRequest.response->entry_32,
                           (uint64_t)(uintptr_t)LiSmbiosRequest.response->entry_64);
    }
    else
    {
        KiSmbiosInitialize(0, 0); /* no response: the table stays absent */
    }

    /* M3: the object manager and its namespace roots, on top of the pool. */
    ObpInitializeObjectManager();
    DbgPrint("[KTEST] ob PASS\n");

    /* M6 phase 1: probe virtio-blk and map its MMIO window. Must precede
     * Ps: the window may claim a fresh kernel PML4 slot, and
     * MiFreezeKernelPml4 happens inside PsInitializeProcessSubsystem. */
    IoInitializeTransport();
    DbgPrint("[KTEST] io PASS\n");

    /* CUI-2: mint the boot token (the fixed admin identity every process
     * token duplicates). Needs only Ob + pool; must precede Ps — the system
     * process's own token is a duplicate of it. */
    SeInitializeSecuritySubsystem();
    DbgPrint("[KTEST] se PASS\n");

    /* M4: the system process (owns the kernel address space + the kernel
     * handle table) and the kernel-PML4 freeze process page tables copy
     * from. Every thread carries a process, so this precedes the scheduler. */
    PsInitializeProcessSubsystem();
    DbgPrint("[KTEST] ps PASS\n");

    /* M5: every boot module becomes a RAM-disk file (the seed read-only FS
     * sections map images and data from — docs/02). */
    KiRegisterBootModules();
    DbgPrint("[KTEST] initrd PASS\n");

    /* CUI-1: seed the wall clock from the CMOS RTC, before the first clock
     * interrupt mirrors SystemTime into KUSER_SHARED_DATA and before the
     * boot volume mounts (FAT timestamps read KeQuerySystemTime). A garbage
     * CMOS keeps the fixed-date fallback (docs/03) rather than failing boot. */
    uint64_t rtcTime = KiReadRtcTime();
    if (rtcTime != 0)
    {
        KiSystemTimeBase = rtcTime;
        DbgPrint("[KTEST] rtc PASS\n");
    }
    else
    {
        DbgPrint("[KTEST] rtc SKIP (implausible CMOS time; fixed-date base)\n");
    }

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
