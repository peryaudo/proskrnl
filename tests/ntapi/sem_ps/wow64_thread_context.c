/*
 * sem_ps/wow64_thread_context.c — ThreadWow64Context (WOW64 milestone).
 *
 * The guest CONTEXT of a WOW64 thread does not live in a trap frame: it
 * lives in the WOW64_CPURESERVED area carved off the top of that thread's
 * 64-bit stack, and NtQuery/SetInformationThread(ThreadWow64Context) is the
 * only door to it. Everything on the 32-bit side goes through this class —
 * wow64cpu's BTCpuProcessInit reads the guest CS/SS out of it before the
 * first guest instruction runs (third_party/wine dlls/wow64cpu/cpu.c), and
 * wow64.dll's thread_init writes the guest entry through it.
 *
 * Two halves are pinned here, both measured on a SUSPENDED child so the
 * answer is the creator's work and nothing has raced it:
 *
 *   1. the initial guest context a 32-bit .exe is born with — Eax = the
 *      image entry, Ebx = the PEB32, a guest Esp inside TEB32.Tib's stack,
 *      an Eip inside the guest ntdll, the compat-mode segment trio, and
 *      EFlags with IF set (dlls/ntdll/unix/signal_x86_64.c, the wow_context
 *      arm of init_thread_context);
 *   2. the merge rule on SET: ContextFlags selects GROUPS, so setting only
 *      CONTEXT_I386_CONTROL must leave the integer registers alone. Getting
 *      that wrong is silent — the guest simply starts with zeroed registers.
 *
 * The last arm pins the inverse that ntdll depends on structurally: on a
 * NON-WOW64 target the class must FAIL. RtlWow64GetThreadSelectorEntry keys
 * its whole hardcoded-selector fallback on exactly that failure
 * (dlls/ntdll/process.c), so a helpfully-succeeding stub would change
 * observable behavior in a caller that never mentions this class.
 *
 * Oracle-first (G5): every assert below is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* wine/include/winternl.h ThreadWow64Context = 29. A wrong value would
 * answer STATUS_INVALID_INFO_CLASS on the oracle, so the oracle run
 * validates it. */
#define PS_ThreadWow64Context ((THREADINFOCLASS)29)

/* wine/include/winnt.h I386_CONTEXT (the x86 CONTEXT, spelled out here
 * because a 64-bit build's CONTEXT is the AMD64 one). Offsets are the
 * header's own comments; sizeof is 0x2cc. */
#define I386_MAXIMUM_SUPPORTED_EXTENSION 512

typedef struct
{
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
} I386_FLOATING_SAVE_AREA;

typedef struct
{
    DWORD ContextFlags;                                       /* 000 */
    DWORD Dr0;                                                /* 004 */
    DWORD Dr1;                                                /* 008 */
    DWORD Dr2;                                                /* 00c */
    DWORD Dr3;                                                /* 010 */
    DWORD Dr6;                                                /* 014 */
    DWORD Dr7;                                                /* 018 */
    I386_FLOATING_SAVE_AREA FloatSave;                        /* 01c */
    DWORD SegGs;                                              /* 08c */
    DWORD SegFs;                                              /* 090 */
    DWORD SegEs;                                              /* 094 */
    DWORD SegDs;                                              /* 098 */
    DWORD Edi;                                                /* 09c */
    DWORD Esi;                                                /* 0a0 */
    DWORD Ebx;                                                /* 0a4 */
    DWORD Edx;                                                /* 0a8 */
    DWORD Ecx;                                                /* 0ac */
    DWORD Eax;                                                /* 0b0 */
    DWORD Ebp;                                                /* 0b4 */
    DWORD Eip;                                                /* 0b8 */
    DWORD SegCs;                                              /* 0bc */
    DWORD EFlags;                                             /* 0c0 */
    DWORD Esp;                                                /* 0c4 */
    DWORD SegSs;                                              /* 0c8 */
    BYTE ExtendedRegisters[I386_MAXIMUM_SUPPORTED_EXTENSION]; /* 0cc */
} I386_CONTEXT_PIN;

#define CONTEXT_i386_PIN      0x00010000
#define CONTEXT_I386_CONTROL  (CONTEXT_i386_PIN | 0x0001)
#define CONTEXT_I386_INTEGER  (CONTEXT_i386_PIN | 0x0002)
#define CONTEXT_I386_SEGMENTS (CONTEXT_i386_PIN | 0x0004)
#define CONTEXT_I386_FULL     (CONTEXT_I386_CONTROL | CONTEXT_I386_INTEGER | CONTEXT_I386_SEGMENTS)

/* TEB32 offsets (wine/include/winternl.h TEB32 offset comments) — the guest
 * stack bounds the initial Esp must fall inside. */
#define TEB32_STACK_BASE  0x004
#define TEB32_STACK_LIMIT 0x008
#define WOW_TEB_OFFSET    0x2000
#define WOW_PEB_OFFSET    0x1000

/* TEB64.TlsSlots (winternl.h TEB offset comment) and the slot the CPU area
 * is published in (winternl.h WOW64_TLS_CPURESERVED). */
#define TEB64_TLS_SLOTS            0x1480
#define WOW64_TLS_CPURESERVED_SLOT 1

/* THREAD_BASIC_INFORMATION, as the pinned tree spells it; mingw's omits it
 * from winternl.h (the wow64_process.c / thread_info_sweep mirror). */
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

static ULONG rd32(const BYTE *block, ULONG offset)
{
    ULONG value;
    memcpy(&value, block + offset, sizeof(value));
    return value;
}

static BYTE teb32_block[0x1000];

START_TEST(wow64_thread_context)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    NTSTATUS status;
    SIZE_T res;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    _Static_assert(sizeof(I386_CONTEXT_PIN) == 0x2cc, "I386_CONTEXT size");

    /* --- the failing half first: a 64-bit thread has no CPU area ------- */
    I386_CONTEXT_PIN self_context;
    memset(&self_context, 0, sizeof(self_context));
    self_context.ContextFlags = CONTEXT_I386_FULL;
    status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadWow64Context, &self_context,
                                      sizeof(self_context), NULL);
    ok(status != STATUS_SUCCESS, "ThreadWow64Context on a 64-bit thread -> %08lx (must fail)",
       (unsigned long)status);

    BOOL created = CreateProcessA("C:\\windows\\syswow64\\cmd.exe", NULL, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessA(syswow64\\cmd.exe) -> %lu", (unsigned long)GetLastError());
    if (!created)
    {
        skip("no wow64 child to measure");
        return;
    }

    /* --- the initial guest context ------------------------------------- */
    PROCESS_BASIC_INFORMATION basic;
    memset(&basic, 0, sizeof(basic));
    status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &basic, sizeof(basic),
                                       NULL);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ULONG_PTR peb32 = (ULONG_PTR)basic.PebBaseAddress + WOW_PEB_OFFSET;

    NTAPI_THREAD_BASIC_INFORMATION thread_info;
    memset(&thread_info, 0, sizeof(thread_info));
    status = NtQueryInformationThread(pi.hThread, ThreadBasicInformation, &thread_info,
                                      sizeof(thread_info), NULL);
    ok(status == STATUS_SUCCESS, "ThreadBasicInformation -> %08lx", (unsigned long)status);
    ULONG_PTR teb32 = (ULONG_PTR)thread_info.TebBaseAddress + WOW_TEB_OFFSET;
    ok(ReadProcessMemory(pi.hProcess, (void *)teb32, teb32_block, sizeof(teb32_block), &res) &&
           res == sizeof(teb32_block),
       "TEB32 read %Iu", (ULONG_PTR)res);
    ULONG guest_base = rd32(teb32_block, TEB32_STACK_BASE);
    ULONG guest_limit = rd32(teb32_block, TEB32_STACK_LIMIT);

    I386_CONTEXT_PIN context;
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_I386_FULL;
    ULONG return_length = 0;
    status = NtQueryInformationThread(pi.hThread, PS_ThreadWow64Context, &context, sizeof(context),
                                      &return_length);
    ok(status == STATUS_SUCCESS, "ThreadWow64Context get -> %08lx", (unsigned long)status);
    /* MEASURED: the oracle leaves the return length UNTOUCHED for this
     * class (get_thread_wow64_context, dlls/ntdll/unix/signal_x86_64.c,
     * never writes it), so no caller can be depending on it and the kernel
     * must not invent one. */
    ok(return_length == 0, "return length %lu (the oracle writes none)",
       (unsigned long)return_length);

    ok(context.Ebx == (ULONG)peb32, "Ebx %lx is not the PEB32 %lx", (unsigned long)context.Ebx,
       (unsigned long)peb32);
    ok(context.Eax != 0, "Eax (the image entry) is 0");
    ok(context.Eip != 0, "Eip is 0");
    ok(context.Esp > guest_limit && context.Esp <= guest_base,
       "Esp %lx outside the guest stack [%lx,%lx)", (unsigned long)context.Esp,
       (unsigned long)guest_limit, (unsigned long)guest_base);
    /* The compat-mode selectors. These are the values the guest actually
     * runs with, and wow64cpu reads them here to build its far-jump thunk. */
    ok(context.SegCs == 0x23, "SegCs %lx", (unsigned long)context.SegCs);
    ok(context.SegSs == 0x2b, "SegSs %lx", (unsigned long)context.SegSs);
    ok(context.SegDs == 0x2b, "SegDs %lx", (unsigned long)context.SegDs);
    ok(context.SegEs == 0x2b, "SegEs %lx", (unsigned long)context.SegEs);
    /* SegFs is the one selector this pin does NOT bind to a value: it names
     * a per-thread descriptor the HOST kernel owns, so the oracle reports
     * Linux's TLS selector (0x63) where NT reports KGDT64_R3_CMTEB (0x53).
     * What is common to both — and all a guest can rely on — is that it is
     * a ring-3 selector distinct from the flat data one. proskrnl's own
     * value is pinned against its GDT in tests/boot/abi_probe.c. */
    ok((context.SegFs & 3) == 3 && context.SegFs != context.SegDs,
       "SegFs %lx is not a ring-3 selector distinct from SegDs %lx",
       (unsigned long)context.SegFs, (unsigned long)context.SegDs);
    ok((context.EFlags & 0x200) != 0, "EFlags %lx has IF clear", (unsigned long)context.EFlags);

    /* --- the SET merge rule: groups, not the whole struct --------------- */
    I386_CONTEXT_PIN set;
    memset(&set, 0, sizeof(set));
    set.ContextFlags = CONTEXT_I386_CONTROL;
    set.Eip = context.Eip;
    set.Esp = context.Esp;
    set.Ebp = 0;
    set.SegCs = context.SegCs;
    set.SegSs = context.SegSs;
    set.EFlags = context.EFlags;
    /* Eax/Ebx are ZERO in `set` and CONTEXT_I386_INTEGER is not requested,
     * so they must survive the call untouched. */
    status = NtSetInformationThread(pi.hThread, PS_ThreadWow64Context, &set, sizeof(set));
    ok(status == STATUS_SUCCESS, "ThreadWow64Context set(CONTROL) -> %08lx", (unsigned long)status);

    /* WOW64_CPURESERVED_FLAG_RESET_STATE is wow64cpu's only signal that the
     * guest state it is about to resume was rewritten under it: every
     * syscall thunk ends in `btrl $0,-4(%r13); jc ...` — read-and-clear, full
     * iretq restore when it was set, a short Eip/SegCs/Esp-only ljmp when it
     * was not (third_party/wine dlls/wow64cpu/cpu.c, syscall_32to64 and
     * unix_call_32to64). wow64cpu is the CONSUMER that clears it.
     *
     * The setter is the CONTEXT_I386_CONTROL arm of set_thread_wow64_context
     * — and it is SELF-ONLY, which is what this arm measures. Every pointer
     * in that arm comes from `get_thread_data()`, the CALLING thread: the CPU
     * area it writes and the `cpu->Flags |= ...` it raises are the caller's
     * own. A non-self target never reaches it, because the `if (!self)` gate
     * above hands the context to the server and returns
     * (dlls/ntdll/unix/signal_x86_64.c).
     *
     * So the pin for a CROSS-THREAD set is that the target's flag is left
     * exactly as it was, and it is asserted in BOTH directions, because one
     * direction alone cannot tell "untouched" from "written to that value":
     * a kernel that CLEARS it fails the first arm, one that RAISES it fails
     * the second. (A 64-bit test cannot reach the self path at all — it has
     * no CPU area of its own; tests/cui/hello32.c and the wow64gui leg are
     * what exercise it, by running a real guest through exception and APC
     * returns.) */
    ULONG64 cpu_area = 0;
    ok(ReadProcessMemory(pi.hProcess,
                         (void *)((ULONG_PTR)thread_info.TebBaseAddress + TEB64_TLS_SLOTS +
                                  WOW64_TLS_CPURESERVED_SLOT * sizeof(ULONG64)),
                         &cpu_area, sizeof(cpu_area), &res) &&
           res == sizeof(cpu_area),
       "CPU area slot read %Iu", (ULONG_PTR)res);
    ok(cpu_area != 0, "no CPU area in TEB64.TlsSlots[1]");
    if (cpu_area != 0)
    {
        USHORT reserved[2] = {0, 0};
        ok(ReadProcessMemory(pi.hProcess, (void *)(ULONG_PTR)cpu_area, reserved, sizeof(reserved),
                             &res) &&
               res == sizeof(reserved),
           "WOW64_CPURESERVED read %Iu", (ULONG_PTR)res);
        ok(reserved[1] == 0x014c, "WOW64_CPURESERVED.Machine %x (not IMAGE_FILE_MACHINE_I386)",
           reserved[1]);
        ok((reserved[0] & 1) == 0,
           "WOW64_CPURESERVED.Flags %x gained RESET_STATE from a cross-thread CONTROL set",
           reserved[0]);

        /* The other direction: raise it from here, repeat the set, and it
         * must survive. */
        USHORT raised[2] = {(USHORT)(reserved[0] | 1), reserved[1]};
        ok(WriteProcessMemory(pi.hProcess, (void *)(ULONG_PTR)cpu_area, raised, sizeof(raised),
                              &res) &&
               res == sizeof(raised),
           "WOW64_CPURESERVED write %Iu", (ULONG_PTR)res);
        status = NtSetInformationThread(pi.hThread, PS_ThreadWow64Context, &set, sizeof(set));
        ok(status == STATUS_SUCCESS, "ThreadWow64Context set(CONTROL) again -> %08lx",
           (unsigned long)status);
        ok(ReadProcessMemory(pi.hProcess, (void *)(ULONG_PTR)cpu_area, reserved, sizeof(reserved),
                             &res) &&
               res == sizeof(reserved),
           "WOW64_CPURESERVED re-read %Iu", (ULONG_PTR)res);
        ok((reserved[0] & 1) != 0,
           "WOW64_CPURESERVED.Flags %x lost RESET_STATE to a cross-thread CONTROL set",
           reserved[0]);
    }

    I386_CONTEXT_PIN after;
    memset(&after, 0, sizeof(after));
    after.ContextFlags = CONTEXT_I386_FULL;
    status =
        NtQueryInformationThread(pi.hThread, PS_ThreadWow64Context, &after, sizeof(after), NULL);
    ok(status == STATUS_SUCCESS, "ThreadWow64Context re-get -> %08lx", (unsigned long)status);
    ok(after.Eax == context.Eax, "Eax %lx clobbered by a CONTROL-only set (was %lx)",
       (unsigned long)after.Eax, (unsigned long)context.Eax);
    ok(after.Ebx == context.Ebx, "Ebx %lx clobbered by a CONTROL-only set (was %lx)",
       (unsigned long)after.Ebx, (unsigned long)context.Ebx);
    ok(after.SegFs == context.SegFs, "SegFs %lx clobbered by a CONTROL-only set",
       (unsigned long)after.SegFs);

    /* And an INTEGER-only set moves exactly the integer group. */
    memset(&set, 0, sizeof(set));
    set.ContextFlags = CONTEXT_I386_INTEGER;
    set.Eax = 0x1234abcd;
    set.Ebx = context.Ebx;
    status = NtSetInformationThread(pi.hThread, PS_ThreadWow64Context, &set, sizeof(set));
    ok(status == STATUS_SUCCESS, "ThreadWow64Context set(INTEGER) -> %08lx", (unsigned long)status);
    memset(&after, 0, sizeof(after));
    after.ContextFlags = CONTEXT_I386_FULL;
    status =
        NtQueryInformationThread(pi.hThread, PS_ThreadWow64Context, &after, sizeof(after), NULL);
    ok(status == STATUS_SUCCESS, "ThreadWow64Context re-get 2 -> %08lx", (unsigned long)status);
    ok(after.Eax == 0x1234abcd, "Eax %lx not the value just set", (unsigned long)after.Eax);
    ok(after.Eip == context.Eip, "Eip %lx clobbered by an INTEGER-only set",
       (unsigned long)after.Eip);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
