/* tests/boot/m7_smoke.c — the M7 "Done when" client (docs/02).
 *
 * A real PE image that exercises the M7 boundary from ring 3 the way an
 * unmodified ntdll would: it reads the byte-exact PEB / TEB / KUSER_SHARED_DATA
 * the kernel built, creates and joins a second thread (NtCreateThreadEx),
 * flips page protection (NtProtectVirtualMemory), takes a delivered user APC,
 * and — the SEH test — raises an access violation, catches it in its own
 * KiUserExceptionDispatcher, and resumes via NtContinue. The dispatchers and
 * the thread/APC trampolines live in m7_dispatch.S and are PE exports the
 * kernel resolves from this image's export table, exactly as it will resolve
 * ntdll's (kernel/ps/process.c). Returns 0 on success; a distinct nonzero code
 * per failed step, reported by the boot-module runner.
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntmmapi.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntcontext.h"
#include "abi/ntpebteb.h"
#include "abi/ntkeapi.h"

/* From m7_dispatch.S. */
void m7_trigger_av(void);
extern char m7_av_resume[];
void m7_thread_entry(void);

static volatile int g_caught;
static volatile int g_apc_ran;
static volatile unsigned long g_apc_arg;
static volatile int g_child_ran;

static void say(const char *ascii)
{
    WCHAR wide[80];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 79)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

static volatile TEB *get_teb(void)
{
    void *self;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(self)); /* NT_TIB.Self */
    return (volatile TEB *)self;
}

/* The exception dispatcher's C body (called from KiUserExceptionDispatcher in
 * m7_dispatch.S). An access violation is "handled" by pointing the resume RIP
 * at m7_av_resume and continuing — the minimal shape of RtlDispatchException. */
void m7_handle_exception(EXCEPTION_RECORD *record, CONTEXT *context)
{
    g_caught = (int)record->ExceptionCode;
    if (record->ExceptionCode == (ULONG)STATUS_ACCESS_VIOLATION)
    {
        context->Rip = (DWORD64)(ULONG_PTR)m7_av_resume;
    }
    NtContinue(context, FALSE);
}

/* A user APC routine (delivered through KiUserApcDispatcher). */
void m7_apc(ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3)
{
    (void)arg2;
    (void)arg3;
    g_apc_ran = 1;
    g_apc_arg = arg1;
}

/* The second thread's C body. */
void m7_thread_main(void *arg)
{
    g_child_ran = (int)(ULONG_PTR)arg;
}

static int run_checks(void)
{
    /* --- PEB / TEB the kernel built ------------------------------------- */
    volatile TEB *teb = get_teb();
    if (teb == 0 || teb->Tib.Self != (struct _NT_TIB *)teb)
        return 1;
    PEB *peb = teb->Peb;
    if (peb == 0)
        return 2;
    if (teb->ClientId.UniqueProcess == 0 || teb->ClientId.UniqueThread == 0)
        return 3;

    /* PEB->ImageBaseAddress must match our mapped image's AllocationBase. */
    MEMORY_BASIC_INFORMATION mbi;
    if (NtQueryVirtualMemory(NtCurrentProcess(), (void *)(ULONG_PTR)run_checks,
                             MemoryBasicInformation, &mbi, sizeof(mbi), 0) != STATUS_SUCCESS)
        return 4;
    if ((void *)peb->ImageBaseAddress != mbi.AllocationBase)
        return 5;

    /* --- KUSER_SHARED_DATA at its NT-fixed user address ----------------- */
    const KUSER_SHARED_DATA *kusd = (const KUSER_SHARED_DATA *)(ULONG_PTR)0x7ffe0000;
    if (kusd->NtMajorVersion != 10 || kusd->NtMinorVersion != 0)
        return 6;
    if (kusd->SystemCall != 0) /* the raw-syscall path (Wine thunk contract) */
        return 7;

    /* --- NtQueryInformationProcess(ProcessBasicInformation) ------------- */
    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi),
                                  0) != STATUS_SUCCESS)
        return 8;
    if (pbi.PebBaseAddress != peb || pbi.UniqueProcessId == 0)
        return 9;

    /* --- NtProtectVirtualMemory ----------------------------------------- */
    void *region = 0;
    SIZE_T regionSize = 0x1000;
    if (NtAllocateVirtualMemory(NtCurrentProcess(), &region, 0, &regionSize,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != STATUS_SUCCESS)
        return 10;
    *(volatile int *)region = 0x1234;
    void *protectBase = region;
    SIZE_T protectSize = 0x1000;
    ULONG oldProtect = 0;
    if (NtProtectVirtualMemory(NtCurrentProcess(), &protectBase, &protectSize, PAGE_READONLY,
                               &oldProtect) != STATUS_SUCCESS)
        return 11;
    if (oldProtect != PAGE_READWRITE)
        return 12;
    if (*(volatile int *)region != 0x1234) /* still readable */
        return 13;

    /* --- the SEH test: fault -> KiUserExceptionDispatcher -> NtContinue -- */
    g_caught = 0;
    m7_trigger_av();
    if (g_caught != (int)STATUS_ACCESS_VIOLATION)
        return 14;

    /* --- user APC delivery ---------------------------------------------- */
    g_apc_ran = 0;
    g_apc_arg = 0;
    if (NtQueueApcThread(NtCurrentThread(), (PNTAPCFUNC)m7_apc, 0xABCD, 0, 0) != STATUS_SUCCESS)
        return 15;
    NtTestAlert(); /* delivers the queued APC on the way back to ring 3 */
    if (!g_apc_ran || g_apc_arg != 0xABCD)
        return 16;

    /* --- NtCreateThreadEx + join ---------------------------------------- */
    g_child_ran = 0;
    HANDLE thread = 0;
    NTSTATUS status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, 0, NtCurrentProcess(),
                                       (PRTL_THREAD_START_ROUTINE)m7_thread_entry,
                                       (void *)(ULONG_PTR)0x55, 0, 0, 0, 0, 0);
    if (status != STATUS_SUCCESS || thread == 0)
        return 17;
    if (NtWaitForSingleObject(thread, FALSE, 0) != STATUS_SUCCESS)
        return 18;
    if (g_child_ran != 0x55)
        return 19;
    NtClose(thread);

    say("[KTEST] user m7_smoke PASS\n");
    return 0;
}

/* The PE entry point (AddressOfEntryPoint): no CRT, no arguments. */
__attribute__((used)) void pe_start(void)
{
    NtTerminateProcess(NtCurrentProcess(), run_checks());
    for (;;)
    {
    }
}
