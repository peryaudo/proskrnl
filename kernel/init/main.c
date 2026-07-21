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
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/ps/ps.h"
#include "kernel/io/io.h"
#include "kernel/cm/cm.h"
#include "fs/npfs/npfs.h"
#include "drivers/condrv.h"
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
 * (user/init-tests/abi_probe.c). The checks guard documented contracts no
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

/* Run the M7 Wine acceptance (docs/02 "Done when"): hello.exe from the boot
 * volume, loaded beside the unmodified Wine PE ntdll.dll and started through
 * LdrInitializeThunk — ntdll's loader runs the process, and hello's SEH test
 * exercises KiUserExceptionDispatcher end to end. Exit 0 = PASS. */
static int KiRunWineHello(void)
{
    /* The ntapi/fuzz images carry the windows/ tree but not hello.exe
     * (tests/run/run.sh bakes only the test .exes); skip cleanly there.
     * The `make test` image ships it (Makefile WINFILES), so a load failure
     * on it IS a FAIL, not a skip. */
    struct MI_SECTION *probe;
    NTSTATUS probeStatus = IoOpenImageSection(WSTR("\\??\\C:\\hello.exe"), &probe);
    if (probeStatus == STATUS_OBJECT_NAME_NOT_FOUND || probeStatus == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        DbgPrint("[KTEST] module hello.exe SKIP (not on the boot volume)\n");
        return 0;
    }
    if (!NT_SUCCESS(probeStatus))
    {
        DbgPrint("[KTEST] module hello.exe FAIL (probe=%#lx)\n", (unsigned long)probeStatus);
        return 1;
    }
    ObDereferenceObject(probe);

    NTSTATUS exitStatus = 0;
    NTSTATUS status =
        PsRunWineImage(WSTR("\\??\\C:\\hello.exe"), "C:\\hello.exe", TRUE, &exitStatus);
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
                                     "C:\\windows\\system32\\smss.exe", TRUE, &exitStatus);
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

/* Start the M9 console server (docs/02): the ported Wine conhost, pumping
 * the kernel ConDrv transport with the COM1 serial tty behind it
 * (HACK-004). Fire-and-forget — conhost outlives every console client; the
 * kept reference pins the process object (KTHREAD does not reference its
 * process). Absent conhost.exe (the ntapi/fuzz images) is not an error:
 * console requests then fail fast and nothing here blocks. */
static PEPROCESS KiConhostProcess;

static void KiStartConhost(void)
{
    struct MI_SECTION *probe;
    NTSTATUS status = IoOpenImageSection(WSTR("\\??\\C:\\windows\\system32\\conhost.exe"), &probe);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ObDereferenceObject(probe);

    /* The main-thread ETHREAD reference is held forever: conhost is a
     * permanent process (its thread never exits, so the reference may never
     * be dropped — PsCreateWineProcess contract). */
    static PETHREAD KiConhostThread;
    status = PsCreateWineProcess(WSTR("\\??\\C:\\windows\\system32\\conhost.exe"),
                                 "C:\\windows\\system32\\conhost.exe", FALSE, &KiConhostProcess,
                                 &KiConhostThread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] conhost FAIL (create=%#lx)\n", (unsigned long)status);
        return;
    }
    if (CondrvWaitForServer(10000))
    {
        DbgPrint("[KTEST] conhost up\n");
    }
    else
    {
        DbgPrint("[KTEST] conhost FAIL (no server attach)\n");
    }
}

/* Run the M9 acceptance client (docs/02 "Done when"): m9_smoke.exe drives
 * the threaded blocking-pipe protocol (the proskrnl twin of the oracle-only
 * sem_pipe/pipe_blocking.c) and writes through the real console stack —
 * kernelbase -> ConDrv -> conhost -> serial. */
static int KiRunM9(void)
{
    struct MI_SECTION *probe;
    NTSTATUS probeStatus = IoOpenImageSection(WSTR("\\??\\C:\\m9_smoke.exe"), &probe);
    if (probeStatus == STATUS_OBJECT_NAME_NOT_FOUND || probeStatus == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        DbgPrint("[KTEST] module m9_smoke.exe SKIP (not on the boot volume)\n");
        return 0;
    }
    if (!NT_SUCCESS(probeStatus))
    {
        DbgPrint("[KTEST] module m9_smoke.exe FAIL (probe=%#lx)\n", (unsigned long)probeStatus);
        return 1;
    }
    ObDereferenceObject(probe);

    if (KiConhostProcess == 0)
    {
        DbgPrint("[KTEST] module m9_smoke.exe FAIL (no conhost)\n");
        return 1;
    }

    NTSTATUS exitStatus = 0;
    NTSTATUS status =
        PsRunWineImage(WSTR("\\??\\C:\\m9_smoke.exe"), "C:\\m9_smoke.exe", TRUE, &exitStatus);
    BOOLEAN pass = NT_SUCCESS(status) && exitStatus == 0;
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] module m9_smoke.exe FAIL (create=%#lx)\n", (unsigned long)status);
    }
    else
    {
        DbgPrint("[KTEST] module m9_smoke.exe %s (exit=%#lx)\n", pass ? "PASS" : "FAIL",
                 (unsigned long)exitStatus);
    }
    return pass ? 0 : 1;
}

/* Run the M9 interactive-echo client when (and only when) the image carries
 * it — the console-mode image (Makefile console-img; tests/run/run.sh
 * console). It blocks on console input until the runner types a line into
 * the serial socket, so the plain image must never include it; absence is
 * silent (the KiRunWineHello probe/skip pattern). */
static int KiRunM9Echo(void)
{
    struct MI_SECTION *probe;
    NTSTATUS probeStatus = IoOpenImageSection(WSTR("\\??\\C:\\m9_echo.exe"), &probe);
    if (!NT_SUCCESS(probeStatus))
    {
        return 0; /* not a console-mode image */
    }
    ObDereferenceObject(probe);

    NTSTATUS exitStatus = 0;
    NTSTATUS status =
        PsRunWineImage(WSTR("\\??\\C:\\m9_echo.exe"), "C:\\m9_echo.exe", TRUE, &exitStatus);
    BOOLEAN pass = NT_SUCCESS(status) && exitStatus == 0;
    DbgPrint("[KTEST] module m9_echo.exe %s (exit=%#lx)\n", pass ? "PASS" : "FAIL",
             (unsigned long)exitStatus);
    return pass ? 0 : 1;
}

/* The M10 acceptance (docs/02 "cmd.exe prompts; pipes/redirection work; an
 * off-the-shelf MSVC-built CUI app runs unmodified"): an INTERACTIVE
 * cmd.exe on the serial console, driven by tests/run/console_expect.py —
 * prompt, echo, redirection to a file, `type file | upcase` through a real
 * anonymous-pipe child, hello_crt.exe's output and %errorlevel%, and a
 * clean `exit`. Present only on the console-mode image (probe/skip like
 * m9_echo). */
static int KiRunCmdConsole(void)
{
    struct MI_SECTION *probe;
    NTSTATUS probeStatus = IoOpenImageSection(WSTR("\\??\\C:\\hello_crt.exe"), &probe);
    if (!NT_SUCCESS(probeStatus))
    {
        return 0; /* not a console-mode image */
    }
    ObDereferenceObject(probe);

    DbgPrint("[KTEST] cmd interactive start\n");
    NTSTATUS exitStatus = 0;
    NTSTATUS status = PsRunWineImage(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"),
                                     "C:\\windows\\system32\\cmd.exe", TRUE, &exitStatus);
    BOOLEAN pass = NT_SUCCESS(status) && exitStatus == 0;
    DbgPrint("[KTEST] module cmd.exe %s (exit=%#lx)\n", pass ? "PASS" : "FAIL",
             (unsigned long)exitStatus);
    return pass ? 0 : 1;
}

/* The interactive boot (make run): the image carries C:\interactive.flag
 * (Makefile IMG_RUN), meaning a human owns the serial console — the test
 * suites are skipped and the console goes straight to cmd.exe. The image,
 * not a kernel-side switch, decides (the KiRunNtapiTests pattern). */
static BOOLEAN KiIsInteractiveBoot(void)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, WSTR("\\??\\C:\\interactive.flag"));
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

/* CUI-1 firstboot: run `smss.exe firstboot` (which spawns wineboot --init,
 * user/smss/firstboot.c) so wine.inf's machine-state registry payload is
 * applied before anything else uses the hive. Probe/skip on the image
 * content (the KiIsInteractiveBoot pattern): images without wineboot.exe —
 * the hermetic ntapi/fuzz images — boot exactly as before. wineboot's own
 * .update-timestamp freshness check makes non-first boots near-instant, so
 * this runs on every boot of a full image. */
static int KiRunFirstBoot(void)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, WSTR("\\??\\C:\\windows\\system32\\wineboot.exe"));
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
        return 0; /* no wineboot baked: silently absent, like KiRunNtapiTests */
    }
    NtClose(handle);

    NTSTATUS exitStatus = STATUS_UNSUCCESSFUL;
    status = PsRunWineImageEx(WSTR("\\??\\C:\\windows\\system32\\smss.exe"),
                              "C:\\windows\\system32\\smss.exe", "smss.exe firstboot", FALSE, 0,
                              &exitStatus);
    if (!NT_SUCCESS(status) || exitStatus != 0)
    {
        DbgPrint("[KTEST] firstboot FAIL (status=%#lx exit=%#lx)\n", (unsigned long)status,
                 (unsigned long)exitStatus);
        return 1;
    }
    DbgPrint("[KTEST] firstboot PASS\n");
    return 0;
}

/* Hand the console to a human-driven cmd.exe and power the VM off when it
 * exits (`exit` at the prompt). A start failure still powers off — an
 * interactive boot has no runner watching a timeout. */
__attribute__((noreturn)) static void KiRunInteractiveCmd(void)
{
    DbgPrint("\nproskrnl: interactive console - starting cmd.exe (type 'exit' to power off)\n\n");
    NTSTATUS exitStatus = 0;
    NTSTATUS status = PsRunWineImage(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"),
                                     "C:\\windows\\system32\\cmd.exe", TRUE, &exitStatus);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("proskrnl: cmd.exe failed to start (%#lx)\n", (unsigned long)status);
    }
    KiQemuExit(0);
    /* The debug-exit teardown is asynchronous; do not run past it. */
    for (;;)
    {
        __asm__ volatile("hlt");
    }
}

/* --- the ntapi single-binary test runner (docs/14) ------------------------- */

/* Every tests/ntapi test is ONE PE .exe that runs unmodified on the Wine
 * oracle and here (no more flat-binary build mode). tests/run/run.sh
 * proskrnl bakes them all under C:\ntapi; this runner sweeps the directory
 * — the image, not a kernel-side list, decides what runs — and each test
 * prints its own [KTEST] <name> PASS/FAIL line, which the runner script
 * greps off the serial log. Absence of C:\ntapi (the `make test` image) is
 * silent. Tests run WITHOUT a console on purpose: no std handles is the
 * harness's "running on proskrnl" discriminator (tests/ntapi/ntapi.c). */
#define KI_NTAPI_MAX_TESTS  64
#define KI_NTAPI_NAME_CHARS 64

typedef struct KI_NTAPI_LIST
{
    WCHAR names[KI_NTAPI_MAX_TESTS][KI_NTAPI_NAME_CHARS];
    int count;
    BOOLEAN overflow;
} KI_NTAPI_LIST;

static BOOLEAN KiNtapiCollect(const IO_DIR_ENTRY *entry, PVOID context)
{
    KI_NTAPI_LIST *list = context;
    ULONG chars = entry->nameLength / sizeof(WCHAR);
    if (entry->info.isDirectory || chars < 5 || chars >= KI_NTAPI_NAME_CHARS)
    {
        return TRUE;
    }
    const WCHAR *name = entry->name;
    if (name[chars - 4] != L'.' || (name[chars - 3] | 0x20) != L'e' ||
        (name[chars - 2] | 0x20) != L'x' || (name[chars - 1] | 0x20) != L'e')
    {
        return TRUE;
    }
    if (list->count >= KI_NTAPI_MAX_TESTS)
    {
        list->overflow = TRUE; /* a silent cap would read as "all covered" */
        return TRUE;
    }
    for (ULONG i = 0; i < chars; i++)
    {
        list->names[list->count][i] = name[i];
    }
    list->names[list->count][chars] = 0;
    list->count++;
    return TRUE;
}

/* Case-insensitive ASCII order, so the run order (and the serial log) is
 * stable regardless of FAT directory layout. */
static void KiNtapiSort(KI_NTAPI_LIST *list)
{
    for (int i = 1; i < list->count; i++)
    {
        WCHAR key[KI_NTAPI_NAME_CHARS];
        for (int k = 0; k < KI_NTAPI_NAME_CHARS; k++)
        {
            key[k] = list->names[i][k];
        }
        int j = i - 1;
        while (j >= 0)
        {
            const WCHAR *a = list->names[j];
            const WCHAR *b = key;
            int cmp = 0;
            while (*a != 0 || *b != 0)
            {
                WCHAR ca = (*a >= L'A' && *a <= L'Z') ? (WCHAR)(*a + 32) : *a;
                WCHAR cb = (*b >= L'A' && *b <= L'Z') ? (WCHAR)(*b + 32) : *b;
                if (ca != cb)
                {
                    cmp = ca < cb ? -1 : 1;
                    break;
                }
                a++;
                b++;
            }
            if (cmp <= 0)
            {
                break;
            }
            for (int k = 0; k < KI_NTAPI_NAME_CHARS; k++)
            {
                list->names[j + 1][k] = list->names[j][k];
            }
            j--;
        }
        for (int k = 0; k < KI_NTAPI_NAME_CHARS; k++)
        {
            list->names[j + 1][k] = key[k];
        }
    }
}

static int KiRunNtapiTests(void)
{
    static KI_NTAPI_LIST list; /* 8 KiB: bss, not this thread's stack */
    list.count = 0;
    list.overflow = FALSE;
    NTSTATUS status = IoEnumerateDirectory(WSTR("\\??\\C:\\ntapi"), KiNtapiCollect, &list);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        return 0; /* not an ntapi image */
    }
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KTEST] ntapi FAIL (enumerate=%#lx)\n", (unsigned long)status);
        return 1;
    }
    KiNtapiSort(&list);

    int failures = 0;
    for (int i = 0; i < list.count; i++)
    {
        /* Sequential runs: one static path set, rebuilt per test (the
         * process holds the imageName pointer only while it runs, and
         * PsRunWineImage waits for exit). */
        static WCHAR widePath[32 + KI_NTAPI_NAME_CHARS];
        static char dosPath[32 + KI_NTAPI_NAME_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\ntapi\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            widePath[n] = prefix[n];
            n++;
        }
        int m = 0;
        while (list.names[i][m] != 0)
        {
            widePath[n + m] = list.names[i][m];
            m++;
        }
        widePath[n + m] = 0;
        for (int k = 0; widePath[4 + k] != 0; k++) /* past "\??\" */
        {
            dosPath[k] = (char)widePath[4 + k];
            dosPath[k + 1] = 0;
        }
        const char *ascii = dosPath + 9; /* past "C:\ntapi\" */

        NTSTATUS exitStatus = 0;
        status = PsRunWineImage(widePath, dosPath, FALSE, &exitStatus);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[KTEST] module ntapi/%s FAIL (create=%#lx)\n", ascii, (unsigned long)status);
            failures++;
        }
        else if (exitStatus != 0)
        {
            DbgPrint("[KTEST] module ntapi/%s FAIL (exit=%#lx)\n", ascii,
                     (unsigned long)exitStatus);
            failures++;
        }
        else
        {
            DbgPrint("[KTEST] module ntapi/%s PASS\n", ascii);
        }
        KiVerifyKernelState(); /* between tests: each must leave a clean executive */
    }
    if (list.overflow)
    {
        DbgPrint("[KTEST] ntapi FAIL (more than %d tests; raise KI_NTAPI_MAX_TESTS)\n",
                 KI_NTAPI_MAX_TESTS);
        failures++;
    }
    DbgPrint("[KTEST] ntapi done tests=%d failures=%d\n", list.count, failures);
    return failures;
}

/* --- the winetest sweep (M10 stretch: docs/02 "Ideal regression") ---------- */

/* tests/run/run.sh winetest bakes standalone Wine-test binaries (the pinned
 * tree's own test objects, docs/14) under C:\wtests plus a manifest of
 * <exe>:<subtest> pairs curated to be green on the oracle. Each pair runs
 * WITH a console (winetest prints through msvcrt stdout -> condrv -> conhost
 * -> serial) and its exit code — winetest's failure count — is the verdict.
 * Absence of the manifest (every other image) is silent. A pair that times
 * out cannot be reaped (no foreign terminate — docs/03), so the sweep aborts
 * rather than running more clients against a wedged console. */
#define KI_WTEST_MAX_PAIRS     128
#define KI_WTEST_EXE_CHARS     40
#define KI_WTEST_SUBTEST_CHARS 32
#define KI_WTEST_MANIFEST_MAX  (64 * 1024)
#define KI_WTEST_TIMEOUT_MS                                                                        \
    (300 * 1000) /* TCG is ~10x native; the string tests are millions of ok()s */

typedef struct KI_WTEST_LIST
{
    struct
    {
        char exe[KI_WTEST_EXE_CHARS];
        char subtest[KI_WTEST_SUBTEST_CHARS];
    } pairs[KI_WTEST_MAX_PAIRS];
    int count;
    BOOLEAN overflow;
} KI_WTEST_LIST;

/* Whole-file read with a kernel-internal transient handle (the
 * CmpReadHiveFile pattern, kernel/cm/hive.c). *bufferOut is pool. */
static BOOLEAN KiWtestReadManifest(UCHAR **bufferOut, ULONG *lengthOut)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, WSTR("\\??\\C:\\wtests\\manifest.txt"));
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
    BOOLEAN ok = FALSE;
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    if (NT_SUCCESS(status) && standard.EndOfFile.QuadPart > 0 &&
        standard.EndOfFile.QuadPart <= KI_WTEST_MANIFEST_MAX)
    {
        ULONG length = (ULONG)standard.EndOfFile.QuadPart;
        UCHAR *buffer = MiAllocatePool(length);
        if (buffer != 0)
        {
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, length, &offset, 0);
            if (NT_SUCCESS(status) && iosb.Information == length)
            {
                *bufferOut = buffer;
                *lengthOut = length;
                ok = TRUE;
            }
            else
            {
                MiFreePool(buffer);
            }
        }
    }
    NtClose(handle);
    return ok;
}

/* Parse `<exe>:<subtest>` lines; '#' comments and blank lines skipped,
 * CRLF tolerated. Malformed/oversized lines are loud (a silently dropped
 * pair would read as "covered"). Returns FALSE on a parse failure. */
static BOOLEAN KiWtestParseManifest(const UCHAR *buffer, ULONG length, KI_WTEST_LIST *list)
{
    ULONG pos = 0;
    while (pos < length)
    {
        ULONG end = pos;
        while (end < length && buffer[end] != '\n')
        {
            end++;
        }
        ULONG lineEnd = end;
        while (lineEnd > pos && (buffer[lineEnd - 1] == '\r' || buffer[lineEnd - 1] == ' '))
        {
            lineEnd--;
        }
        if (lineEnd > pos && buffer[pos] != '#')
        {
            ULONG colon = pos;
            while (colon < lineEnd && buffer[colon] != ':')
            {
                colon++;
            }
            ULONG exeChars = colon - pos;
            ULONG subChars = (colon < lineEnd) ? lineEnd - colon - 1 : 0;
            if (colon >= lineEnd || exeChars == 0 || exeChars >= KI_WTEST_EXE_CHARS ||
                subChars == 0 || subChars >= KI_WTEST_SUBTEST_CHARS)
            {
                DbgPrint("[KTEST] wtest FAIL (manifest line at byte %u malformed)\n",
                         (unsigned)pos);
                return FALSE;
            }
            if (list->count >= KI_WTEST_MAX_PAIRS)
            {
                list->overflow = TRUE;
                pos = end + 1;
                continue;
            }
            for (ULONG i = 0; i < exeChars; i++)
            {
                list->pairs[list->count].exe[i] = (char)buffer[pos + i];
            }
            list->pairs[list->count].exe[exeChars] = 0;
            for (ULONG i = 0; i < subChars; i++)
            {
                list->pairs[list->count].subtest[i] = (char)buffer[colon + 1 + i];
            }
            list->pairs[list->count].subtest[subChars] = 0;
            list->count++;
        }
        pos = end + 1;
    }
    return TRUE;
}

static int KiRunWineTests(void)
{
    static KI_WTEST_LIST list; /* pairs table: bss, not this thread's stack */
    list.count = 0;
    list.overflow = FALSE;

    UCHAR *manifest = 0;
    ULONG manifestLength = 0;
    if (!KiWtestReadManifest(&manifest, &manifestLength))
    {
        return 0; /* not a wtest image */
    }
    BOOLEAN parsed = KiWtestParseManifest(manifest, manifestLength, &list);
    MiFreePool(manifest);
    if (!parsed)
    {
        return 1;
    }

    int failures = 0;
    for (int i = 0; i < list.count; i++)
    {
        /* Sequential runs, one static path set (the KiRunNtapiTests shape;
         * the process copies the command line and holds imageName only
         * while PsRunWineImageEx waits). */
        static WCHAR widePath[16 + KI_WTEST_EXE_CHARS];
        static char dosPath[12 + KI_WTEST_EXE_CHARS];
        static char cmdLine[12 + KI_WTEST_EXE_CHARS + 1 + KI_WTEST_SUBTEST_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\wtests\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            widePath[n] = prefix[n];
            n++;
        }
        for (int m = 0;; m++)
        {
            widePath[n + m] = (WCHAR)(unsigned char)list.pairs[i].exe[m];
            if (list.pairs[i].exe[m] == 0)
            {
                break;
            }
        }
        int d = 0;
        for (int k = 4; widePath[k] != 0; k++) /* past "\??\" */
        {
            dosPath[d++] = (char)widePath[k];
        }
        dosPath[d] = 0;
        int c = 0;
        while (dosPath[c] != 0)
        {
            cmdLine[c] = dosPath[c];
            c++;
        }
        cmdLine[c++] = ' ';
        for (int m = 0;; m++)
        {
            cmdLine[c + m] = list.pairs[i].subtest[m];
            if (list.pairs[i].subtest[m] == 0)
            {
                break;
            }
        }

        NTSTATUS exitStatus = 0;
        NTSTATUS status =
            PsRunWineImageEx(widePath, dosPath, cmdLine, TRUE, KI_WTEST_TIMEOUT_MS, &exitStatus);
        if (status == STATUS_TIMEOUT)
        {
            /* The wedged process owns the console; further pairs would be
             * noise. Abort loudly — the runner sees the missing PASSes. */
            DbgPrint("[KTEST] wtest %s:%s FAIL (timeout)\n", list.pairs[i].exe,
                     list.pairs[i].subtest);
            failures += list.count - i;
            break;
        }
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[KTEST] wtest %s:%s FAIL (create=%#lx)\n", list.pairs[i].exe,
                     list.pairs[i].subtest, (unsigned long)status);
            failures++;
        }
        else if (exitStatus != 0)
        {
            DbgPrint("[KTEST] wtest %s:%s FAIL (exit=%#lx)\n", list.pairs[i].exe,
                     list.pairs[i].subtest, (unsigned long)exitStatus);
            failures++;
        }
        else
        {
            DbgPrint("[KTEST] wtest %s:%s PASS\n", list.pairs[i].exe, list.pairs[i].subtest);
        }
        KiVerifyKernelState(); /* between pairs: each must leave a clean executive */
    }
    if (list.overflow)
    {
        DbgPrint("[KTEST] wtest FAIL (more than %d pairs; raise KI_WTEST_MAX_PAIRS)\n",
                 KI_WTEST_MAX_PAIRS);
        failures++;
    }
    DbgPrint("[KTEST] wtest done tests=%d failures=%d\n", list.count, failures);
    return failures;
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

    /* M9: the named-pipe FS (\Device\NamedPipe + \??\pipe). No disk
     * dependency — only the namespace and this thread's handle table. */
    NpfsInitialize();

    /* M9: the console devices — \Device\Serial0 (the HACK-004 serial
     * transport) and, with conhost, the ConDrv console object. */
    CondrvInitialize();

    /* M8: bring up the registry — \Registry + the SYSTEM hive from the boot
     * volume (an absent/invalid hive starts empty: first boot). Needs the
     * volume above and a thread with a handle table for the hive file I/O. */
    CmInitialize();

    /* M9: the console server, before anything that may use a console. */
    KiStartConhost();

    /* CUI-1: firstboot — wineboot --init populates the machine state before
     * the console/test flows, so cmd.exe and the test sweeps below see the
     * wine.inf registry payload. Probe/skip: absent wineboot.exe is a no-op. */
    int firstbootFailures = KiRunFirstBoot();

    /* The interactive boot (make run) skips the test suites entirely: the
     * serial console belongs to a human and cmd.exe. Never returns. */
    if (KiIsInteractiveBoot())
    {
        KiRunInteractiveCmd();
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

    /* The standing ABI-conformance probe: ring-3 conventions asserted every
     * boot (user/init-tests/abi_probe.c). Before the M7 clients, so a broken
     * convention names itself here rather than surfacing as an M7 crash. */
    int abiFailures = KiRunAbiProbe();
    DbgPrint(abiFailures == 0 ? "[KTEST] ABI PASS\n" : "[KTEST] ABI FAIL failures=%d\n",
             abiFailures);

    /* M7: NtCreateUserProcess-shaped process lifecycle + the user-mode return
     * protocol, driven by a real PE client (the mountain — docs/02). This is
     * the milestone's acceptance artifact. */
    int m7Failures = KiRunM7Modules();
    /* The Wine bring-up half of M7: the unmodified PE ntdll runs hello.exe. */
    m7Failures += KiRunWineHello();
    DbgPrint(m7Failures == 0 ? "[KTEST] M7 PASS\n" : "[KTEST] M7 FAIL failures=%d\n", m7Failures);
    KiVerifyKernelState();

    /* M8: the initial process chain (docs/02 "Done when: boot completes as
     * kernel → smss-equiv → test process"): smss.exe verifies \Registry from
     * ring 3, spawns hello.exe through NtCreateUserProcess, and exits with
     * the child's code. */
    int m8Failures = KiRunInitialChain();
    DbgPrint(m8Failures == 0 ? "[KTEST] M8 PASS\n" : "[KTEST] M8 FAIL failures=%d\n", m8Failures);
    KiVerifyKernelState();

    /* M9: npfs + condrv + conhost (docs/02): the threaded pipe client/server
     * protocol and a console write through the whole stack. The npfs
     * differential surface itself is the sem_pipe suite (run.sh). */
    int m9Failures = KiRunM9();
    /* The M9 line is the verdict tools/qemu.sh greps for (PASS_RE), so it
     * must aggregate the ABI probe too — the same fold the M6 line does for
     * lib above; an unconsumed-convention regression must flip `make test`. */
    m9Failures += abiFailures;
    DbgPrint(m9Failures == 0 ? "[KTEST] M9 PASS\n" : "[KTEST] M9 FAIL failures=%d\n", m9Failures);
    KiVerifyKernelState();

    /* The ntapi image only (tests/run/run.sh proskrnl): run every single
     * binary test baked under C:\ntapi. Absence is silent. */
    int ntapiFailures = KiRunNtapiTests();

    /* The wtest image only (tests/run/run.sh winetest): the curated pairs
     * from Wine's own CUI test suite baked under C:\wtests. Absence is
     * silent. */
    int wtestFailures = KiRunWineTests();

    /* Console-mode image only: block on the interactive echo (the M9
     * acceptance's other half — input typed on the serial wire). AFTER the
     * M9 verdict so the runner knows the boot suite is already green. */
    int echoFailures = KiRunM9Echo();

    /* Console-mode image only (M10): the interactive cmd.exe session. */
    int cmdFailures = KiRunCmdConsole();

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

    int total = firstbootFailures + m2Failures + m3Failures + m4Failures + m5Failures + m6Failures +
                m7Failures + m8Failures + m9Failures + ntapiFailures + wtestFailures +
                echoFailures + cmdFailures;
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
