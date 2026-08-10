/*
 * sem_ps/wow64_process.c — the WOW64 process shape (WOW64 milestone).
 *
 * Wine's new WoW64 keeps the whole 32->64 transition in user mode; what the
 * KERNEL owes a 32-bit .exe is the furniture this test reads off a suspended
 * child before one guest instruction has run:
 *
 *   - ProcessWow64Information answers the PEB32, which sits one page above
 *     the 64-bit PEB (third_party/wine dlls/ntdll/unix/env.c init_peb:
 *     `wow_peb = (PEB32 *)((char *)peb + page_size)`);
 *   - the TEB32 sits at TEB64 + 0x2000 inside the same block
 *     (dlls/ntdll/unix/unix_private.h teb_offset; virtual.c init_teb), with
 *     TEB64.WowTebOffset = +0x2000, TEB32.WowTebOffset = -0x2000,
 *     TEB64.Tib.ExceptionList pointing at the TEB32, and TEB32.GdiBatchCount
 *     carrying the TEB64 address (ntdll_misc.h NtCurrentTeb64);
 *   - the initial thread carries TWO stacks: the 64-bit one ABOVE 4GB (its
 *     limit_4g argument is the LOW limit — the low space is the guest's),
 *     with the WOW64_CPURESERVED area carved off its top and published in
 *     BOTH TEB64.Tib.StackBase and TEB64.TlsSlots[1] (WOW64_TLS_CPURESERVED
 *     — dlls/ntdll/unix/thread.c init_thread_stack), and the guest one,
 *     under the wow limit, recorded in TEB32.Tib;
 *   - the PEB32 carries its own 32-bit RTL_USER_PROCESS_PARAMETERS copy
 *     (env.c build_wow64_parameters), mirroring the 64-bit block's strings.
 *
 * The 64-bit control arm at the end pins the inverse: a 64-bit child has
 * WowTebOffset 0 and answers 0 for ProcessWow64Information (the existing
 * process_query pin covers the self-process case).
 *
 * Every struct offset below is the offset comment in wine/include/winternl.h
 * (the same comments gen_abi turns into abi/ntwow64.h's _Static_asserts);
 * oracle-first (G5): every assert here is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* wine/include/winternl.h TEB (x64 offset comments). */
#define TEB64_EXCEPTION_LIST 0x000 /* Tib.ExceptionList */
#define TEB64_STACK_BASE     0x008 /* Tib.StackBase */
#define TEB64_STACK_LIMIT    0x010 /* Tib.StackLimit */
#define TEB64_SELF           0x030 /* Tib.Self */
#define TEB64_CLIENT_ID      0x040
#define TEB64_TLS_SLOTS      0x1480
#define TEB64_WOW_TEB_OFFSET 0x180c
#define TEB64_READ_SIZE      0x1810

/* wine/include/winternl.h TEB32 (offset comments). */
#define TEB32_EXCEPTION_LIST   0x000 /* Tib.ExceptionList */
#define TEB32_STACK_BASE       0x004 /* Tib.StackBase */
#define TEB32_STACK_LIMIT      0x008 /* Tib.StackLimit */
#define TEB32_FIBER_DATA       0x010 /* Tib.FiberData */
#define TEB32_SELF             0x018 /* Tib.Self */
#define TEB32_CLIENT_ID        0x020
#define TEB32_PEB              0x030
#define TEB32_ACTCTX_STACK_PTR 0x1a8
#define TEB32_STATIC_USTR      0xbf8
#define TEB32_STATIC_BUFFER    0xc00
#define TEB32_DEALLOC_STACK    0xe0c
#define TEB32_GDI_BATCH_COUNT  0xf70 /* NtCurrentTeb64: holds the TEB64 VA */
#define TEB32_WOW_TEB_OFFSET   0xfdc
#define TEB32_READ_SIZE        0x1000

/* dlls/ntdll/unix/unix_private.h teb_offset / env.c init_peb page offset. */
#define WOW_TEB_OFFSET 0x2000
#define WOW_PEB_OFFSET 0x1000

/* wine/include/winternl.h PEB32 (offset comments). */
#define PEB32_IMAGE_BASE      0x008
#define PEB32_PROCESS_PARAMS  0x010
#define PEB32_NUM_PROCESSORS  0x064
#define PEB32_NT_GLOBAL_FLAG  0x068
#define PEB32_OS_MAJOR        0x0a4
#define PEB32_OS_BUILD        0x0ac
#define PEB32_IMAGE_SUBSYSTEM 0x0b4
#define PEB32_SESSION_ID      0x1d4
#define PEB32_READ_SIZE       0x480 /* sizeof(PEB32) */

/* wine/include/winternl.h RTL_USER_PROCESS_PARAMETERS32. */
#define PARAMS32_SIZE_FIELD  0x004
#define PARAMS32_IMAGE_PATH  0x038 /* UNICODE_STRING32 {Len,MaxLen,Buffer} */
#define PARAMS32_CMDLINE     0x040
#define PARAMS32_ENVIRONMENT 0x048
#define PARAMS32_ENV_SIZE    0x290
#define PARAMS32_READ_SIZE   0x2a4

/* wine/include/winternl.h PEB / RTL_USER_PROCESS_PARAMETERS (x64 offsets),
 * for the 64-bit halves the 32-bit mirrors are compared against. */
#define PEB64_IMAGE_BASE      0x010
#define PEB64_PROCESS_PARAMS  0x020
#define PEB64_NUM_PROCESSORS  0x0b8
#define PEB64_NT_GLOBAL_FLAG  0x0bc
#define PEB64_OS_MAJOR        0x118
#define PEB64_OS_BUILD        0x120
#define PEB64_IMAGE_SUBSYSTEM 0x128
#define PEB64_SESSION_ID      0x2c0
#define PEB64_READ_SIZE       0x2c8
#define PARAMS64_IMAGE_PATH   0x060
#define PARAMS64_CMDLINE      0x070
#define PARAMS64_ENV_SIZE     0x3f0
#define PARAMS64_READ_SIZE    0x3f8

#define FOUR_GB ((ULONG64)1 << 32)

static ULONG64 rd64(const BYTE *block, ULONG offset)
{
    ULONG64 value;
    memcpy(&value, block + offset, sizeof(value));
    return value;
}

static ULONG rd32(const BYTE *block, ULONG offset)
{
    ULONG value;
    memcpy(&value, block + offset, sizeof(value));
    return value;
}

static USHORT rd16(const BYTE *block, ULONG offset)
{
    USHORT value;
    memcpy(&value, block + offset, sizeof(value));
    return value;
}

/* THREAD_BASIC_INFORMATION, as the pinned tree spells it; mingw's omits
 * it from winternl.h (the thread_info_sweep mirror). */
typedef struct
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    struct
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} NTAPI_THREAD_BASIC_INFORMATION;

static BYTE teb64_block[TEB64_READ_SIZE];
static BYTE teb32_block[TEB32_READ_SIZE];
static BYTE peb32_block[PEB32_READ_SIZE];
static BYTE peb64_block[PEB64_READ_SIZE];
static BYTE params32_block[PARAMS32_READ_SIZE];
static BYTE params64_block[PARAMS64_READ_SIZE];

START_TEST(wow64_process)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    NTSTATUS status;
    SIZE_T res;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    /* --- the wow64 child, held suspended: everything below is the
     * CREATOR's work, not the guest's ---------------------------------- */
    BOOL created = CreateProcessA("C:\\windows\\syswow64\\cmd.exe", NULL, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessA(syswow64\\cmd.exe) -> %lu", (unsigned long)GetLastError());
    if (!created)
    {
        skip("no wow64 child to measure");
        return;
    }

    /* --- ProcessWow64Information: the PEB32, one page above the PEB64 -- */
    PROCESS_BASIC_INFORMATION basic;
    memset(&basic, 0, sizeof(basic));
    status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &basic, sizeof(basic),
                                       NULL);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ULONG_PTR peb64 = (ULONG_PTR)basic.PebBaseAddress;
    ok(peb64 != 0, "no PEB address");

    ULONG_PTR peb32 = 0;
    ULONG returnLength = 0;
    status = NtQueryInformationProcess(pi.hProcess, ProcessWow64Information, &peb32, sizeof(peb32),
                                       &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessWow64Information -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(peb32), "wow64 return length %lu", (unsigned long)returnLength);
    ok(peb32 == peb64 + WOW_PEB_OFFSET, "PEB32 %p not PEB64 %p + 0x%x", (void *)peb32,
       (void *)peb64, WOW_PEB_OFFSET);
    ok(peb32 + PEB32_READ_SIZE < FOUR_GB, "PEB32 %p above 4GB", (void *)peb32);

    /* --- the TEB pair ---------------------------------------------------- */
    NTAPI_THREAD_BASIC_INFORMATION thread_info;
    memset(&thread_info, 0, sizeof(thread_info));
    status = NtQueryInformationThread(pi.hThread, ThreadBasicInformation, &thread_info,
                                      sizeof(thread_info), NULL);
    ok(status == STATUS_SUCCESS, "ThreadBasicInformation -> %08lx", (unsigned long)status);
    ULONG_PTR teb64 = (ULONG_PTR)thread_info.TebBaseAddress;
    ok(teb64 != 0, "no TEB address");

    ok(ReadProcessMemory(pi.hProcess, (void *)teb64, teb64_block, sizeof(teb64_block), &res) &&
           res == sizeof(teb64_block),
       "TEB64 read %Iu", (ULONG_PTR)res);
    ok(rd32(teb64_block, TEB64_WOW_TEB_OFFSET) == WOW_TEB_OFFSET, "TEB64.WowTebOffset %lx",
       (unsigned long)rd32(teb64_block, TEB64_WOW_TEB_OFFSET));
    ok(rd64(teb64_block, TEB64_SELF) == teb64, "TEB64.Tib.Self %llx",
       (unsigned long long)rd64(teb64_block, TEB64_SELF));
    ok(rd64(teb64_block, TEB64_EXCEPTION_LIST) == teb64 + WOW_TEB_OFFSET,
       "TEB64.Tib.ExceptionList %llx not the TEB32",
       (unsigned long long)rd64(teb64_block, TEB64_EXCEPTION_LIST));
    ok(rd64(teb64_block, TEB64_CLIENT_ID) == pi.dwProcessId, "TEB64 ClientId process %llx",
       (unsigned long long)rd64(teb64_block, TEB64_CLIENT_ID));
    ok(rd64(teb64_block, TEB64_CLIENT_ID + 8) == pi.dwThreadId, "TEB64 ClientId thread %llx",
       (unsigned long long)rd64(teb64_block, TEB64_CLIENT_ID + 8));

    /* The 64-bit stack, below 4GB, its top carved into the WOW64 cpu area
     * published in both Tib.StackBase and TlsSlots[WOW64_TLS_CPURESERVED=1]
     * (dlls/ntdll/unix/thread.c init_thread_stack). */
    ULONG64 stack_base = rd64(teb64_block, TEB64_STACK_BASE);
    ULONG64 stack_limit = rd64(teb64_block, TEB64_STACK_LIMIT);
    ULONG64 cpu_area = rd64(teb64_block, TEB64_TLS_SLOTS + 1 * 8);
    /* ABOVE 4GB, deliberately: init_thread_stack passes limit_4g as the
     * LOW limit for the 64-bit stack (dlls/ntdll/unix/thread.c:1193 —
     * virtual_alloc_thread_stack(&stack, limit_4g, 0, ...)), so the scarce
     * low address space is left for the guest, which gets its own stack
     * under user_space_wow_limit below. MEASURED, not assumed: the obvious
     * reading of "wow64 lives low" puts this stack under 4GB and is wrong. */
    ok(stack_base >= FOUR_GB, "64-bit stack base %llx not above 4GB",
       (unsigned long long)stack_base);
    ok(stack_limit != 0 && stack_limit < stack_base, "64-bit stack limit %llx",
       (unsigned long long)stack_limit);
    ok(cpu_area == stack_base, "TlsSlots[1] %llx != Tib.StackBase %llx",
       (unsigned long long)cpu_area, (unsigned long long)stack_base);
    ok((cpu_area & 15) == 0, "cpu area %llx not 16-aligned", (unsigned long long)cpu_area);

    /* --- the TEB32 mirror ------------------------------------------------ */
    ULONG_PTR teb32 = teb64 + WOW_TEB_OFFSET;
    ok(ReadProcessMemory(pi.hProcess, (void *)teb32, teb32_block, sizeof(teb32_block), &res) &&
           res == sizeof(teb32_block),
       "TEB32 read %Iu", (ULONG_PTR)res);
    ok(rd32(teb32_block, TEB32_SELF) == (ULONG)teb32, "TEB32.Tib.Self %lx",
       (unsigned long)rd32(teb32_block, TEB32_SELF));
    ok(rd32(teb32_block, TEB32_EXCEPTION_LIST) == ~0u, "TEB32.Tib.ExceptionList %lx",
       (unsigned long)rd32(teb32_block, TEB32_EXCEPTION_LIST));
    ok(rd32(teb32_block, TEB32_FIBER_DATA) == 0x1e00, "TEB32.Tib.FiberData %lx",
       (unsigned long)rd32(teb32_block, TEB32_FIBER_DATA));
    ok(rd32(teb32_block, TEB32_PEB) == (ULONG)peb32, "TEB32.Peb %lx",
       (unsigned long)rd32(teb32_block, TEB32_PEB));
    ok(rd32(teb32_block, TEB32_CLIENT_ID) == pi.dwProcessId, "TEB32 ClientId process %lx",
       (unsigned long)rd32(teb32_block, TEB32_CLIENT_ID));
    ok(rd32(teb32_block, TEB32_CLIENT_ID + 4) == pi.dwThreadId, "TEB32 ClientId thread %lx",
       (unsigned long)rd32(teb32_block, TEB32_CLIENT_ID + 4));
    ok(rd32(teb32_block, TEB32_WOW_TEB_OFFSET) == (ULONG)-WOW_TEB_OFFSET, "TEB32.WowTebOffset %lx",
       (unsigned long)rd32(teb32_block, TEB32_WOW_TEB_OFFSET));
    ok(rd32(teb32_block, TEB32_GDI_BATCH_COUNT) == (ULONG)teb64,
       "TEB32.GdiBatchCount %lx (NtCurrentTeb64 wants the TEB64)",
       (unsigned long)rd32(teb32_block, TEB32_GDI_BATCH_COUNT));

    /* The guest stack: recorded in TEB32.Tib, distinct from the 64-bit one. */
    ULONG guest_base = rd32(teb32_block, TEB32_STACK_BASE);
    ULONG guest_limit = rd32(teb32_block, TEB32_STACK_LIMIT);
    ULONG guest_dealloc = rd32(teb32_block, TEB32_DEALLOC_STACK);
    ok(guest_base != 0, "guest stack base 0");
    ok(guest_limit != 0 && guest_limit < guest_base, "guest stack limit %lx / %lx",
       (unsigned long)guest_limit, (unsigned long)guest_base);
    ok(guest_dealloc != 0 && guest_dealloc <= guest_limit, "guest dealloc %lx / limit %lx",
       (unsigned long)guest_dealloc, (unsigned long)guest_limit);
    ok(guest_base != (ULONG)stack_base, "guest and 64-bit stacks are the same allocation");

    /* The static-string furniture (env.c init_teb writes the 32-bit halves
     * the way PspBuildTeb writes the 64-bit ones). */
    ok(rd32(teb32_block, TEB32_ACTCTX_STACK_PTR) != 0, "TEB32 ActivationContextStackPointer 0");
    ok(rd32(teb32_block, TEB32_STATIC_USTR + 4) == (ULONG)(teb32 + TEB32_STATIC_BUFFER),
       "TEB32 StaticUnicodeString.Buffer %lx",
       (unsigned long)rd32(teb32_block, TEB32_STATIC_USTR + 4));

    /* --- the PEB32 mirror ------------------------------------------------ */
    ok(ReadProcessMemory(pi.hProcess, (void *)peb64, peb64_block, sizeof(peb64_block), &res) &&
           res == sizeof(peb64_block),
       "PEB64 read %Iu", (ULONG_PTR)res);
    ok(ReadProcessMemory(pi.hProcess, (void *)peb32, peb32_block, sizeof(peb32_block), &res) &&
           res == sizeof(peb32_block),
       "PEB32 read %Iu", (ULONG_PTR)res);

    ULONG64 image_base64 = rd64(peb64_block, PEB64_IMAGE_BASE);
    ok(rd32(peb32_block, PEB32_IMAGE_BASE) == (ULONG)image_base64,
       "PEB32.ImageBaseAddress %lx / PEB64 %llx",
       (unsigned long)rd32(peb32_block, PEB32_IMAGE_BASE), (unsigned long long)image_base64);
    ok(image_base64 < FOUR_GB, "32-bit image mapped at %llx", (unsigned long long)image_base64);
    ok(rd32(peb32_block, PEB32_NUM_PROCESSORS) == rd32(peb64_block, PEB64_NUM_PROCESSORS),
       "PEB32.NumberOfProcessors %lu", (unsigned long)rd32(peb32_block, PEB32_NUM_PROCESSORS));
    ok(rd32(peb32_block, PEB32_NT_GLOBAL_FLAG) == rd32(peb64_block, PEB64_NT_GLOBAL_FLAG),
       "PEB32.NtGlobalFlag %lx", (unsigned long)rd32(peb32_block, PEB32_NT_GLOBAL_FLAG));
    ok(rd32(peb32_block, PEB32_OS_MAJOR) == rd32(peb64_block, PEB64_OS_MAJOR),
       "PEB32.OSMajorVersion %lu", (unsigned long)rd32(peb32_block, PEB32_OS_MAJOR));
    ok(rd32(peb32_block, PEB32_OS_BUILD) == rd32(peb64_block, PEB64_OS_BUILD),
       "PEB32.OSBuildNumber %lu", (unsigned long)rd32(peb32_block, PEB32_OS_BUILD));
    ok(rd32(peb32_block, PEB32_IMAGE_SUBSYSTEM) == rd32(peb64_block, PEB64_IMAGE_SUBSYSTEM),
       "PEB32.ImageSubSystem %lu", (unsigned long)rd32(peb32_block, PEB32_IMAGE_SUBSYSTEM));
    ok(rd32(peb32_block, PEB32_SESSION_ID) == rd32(peb64_block, PEB64_SESSION_ID),
       "PEB32.SessionId %lu", (unsigned long)rd32(peb32_block, PEB32_SESSION_ID));

    /* --- the 32-bit process parameters: a separate low copy whose strings
     * mirror the 64-bit block's (env.c build_wow64_parameters) ------------ */
    ULONG params32 = rd32(peb32_block, PEB32_PROCESS_PARAMS);
    ULONG64 params64 = rd64(peb64_block, PEB64_PROCESS_PARAMS);
    ok(params32 != 0, "no 32-bit process parameters");
    ok(params32 != (ULONG)params64, "params32 aliases the 64-bit block");
    ok(ReadProcessMemory(pi.hProcess, (void *)(ULONG_PTR)params32, params32_block,
                         sizeof(params32_block), &res) &&
           res == sizeof(params32_block),
       "params32 read %Iu", (ULONG_PTR)res);
    ok(ReadProcessMemory(pi.hProcess, (void *)params64, params64_block, sizeof(params64_block),
                         &res) &&
           res == sizeof(params64_block),
       "params64 read %Iu", (ULONG_PTR)res);

    ULONG params32_size = rd32(params32_block, PARAMS32_SIZE_FIELD);
    ok(params32_size >= PARAMS32_READ_SIZE, "params32 Size %lx", (unsigned long)params32_size);
    struct
    {
        ULONG off32;
        ULONG off64;
        const char *name;
    } strings[] = {
        {PARAMS32_IMAGE_PATH, PARAMS64_IMAGE_PATH, "ImagePathName"},
        {PARAMS32_CMDLINE, PARAMS64_CMDLINE, "CommandLine"},
    };
    for (unsigned i = 0; i < 2; i++)
    {
        USHORT len32 = rd16(params32_block, strings[i].off32);
        USHORT len64 = rd16(params64_block, strings[i].off64);
        ULONG buffer32 = rd32(params32_block, strings[i].off32 + 4);
        ok(len32 == len64, "%s length %u / %u", strings[i].name, len32, len64);
        ok(buffer32 >= params32 && buffer32 < params32 + params32_size,
           "%s buffer %lx outside params32 [%lx,+%lx)", strings[i].name, (unsigned long)buffer32,
           (unsigned long)params32, (unsigned long)params32_size);
    }
    ok(rd32(params32_block, PARAMS32_ENV_SIZE) == (ULONG)rd64(params64_block, PARAMS64_ENV_SIZE),
       "EnvironmentSize %lx / %llx", (unsigned long)rd32(params32_block, PARAMS32_ENV_SIZE),
       (unsigned long long)rd64(params64_block, PARAMS64_ENV_SIZE));
    ok(rd32(params32_block, PARAMS32_ENVIRONMENT) != 0, "no 32-bit environment");

    /* --- the image facts: a PE32 section, entry under 4GB ---------------- */
    ps_section_image_info image_info;
    memset(&image_info, 0, sizeof(image_info));
    status = NtQueryInformationProcess(pi.hProcess, PS_ProcessImageInformation, &image_info,
                                       sizeof(image_info), NULL);
    ok(status == STATUS_SUCCESS, "ProcessImageInformation -> %08lx", (unsigned long)status);
    ok(image_info.machine == 0x014c, "machine %04x", image_info.machine); /* I386 */
    ok((ULONG_PTR)image_info.transfer_address < FOUR_GB, "entry %p", image_info.transfer_address);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* --- the 64-bit control arm: no mirror, no offset -------------------- */
    created = CreateProcessA("C:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE,
                             CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessA(system32\\cmd.exe) -> %lu", (unsigned long)GetLastError());
    if (created)
    {
        ULONG_PTR wow_peb = ~(ULONG_PTR)0;
        status = NtQueryInformationProcess(pi.hProcess, ProcessWow64Information, &wow_peb,
                                           sizeof(wow_peb), NULL);
        ok(status == STATUS_SUCCESS, "ProcessWow64Information(64) -> %08lx", (unsigned long)status);
        ok(wow_peb == 0, "64-bit child reports a PEB32 %p", (void *)wow_peb);

        memset(&thread_info, 0, sizeof(thread_info));
        status = NtQueryInformationThread(pi.hThread, ThreadBasicInformation, &thread_info,
                                          sizeof(thread_info), NULL);
        ok(status == STATUS_SUCCESS, "ThreadBasicInformation(64) -> %08lx", (unsigned long)status);
        ok(ReadProcessMemory(pi.hProcess, thread_info.TebBaseAddress, teb64_block,
                             sizeof(teb64_block), &res) &&
               res == sizeof(teb64_block),
           "TEB64(64) read %Iu", (ULONG_PTR)res);
        ok(rd32(teb64_block, TEB64_WOW_TEB_OFFSET) == 0, "64-bit child WowTebOffset %lx",
           (unsigned long)rd32(teb64_block, TEB64_WOW_TEB_OFFSET));
        ok(rd64(teb64_block, TEB64_EXCEPTION_LIST) == 0, "64-bit child ExceptionList %llx",
           (unsigned long long)rd64(teb64_block, TEB64_EXCEPTION_LIST));

        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}
