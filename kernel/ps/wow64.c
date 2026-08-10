/* kernel/ps/wow64.c — the 32-bit furniture a WOW64 process is born with
 * (docs/02 "WOW64"; ADR 0006).
 *
 * Wine's new WoW64 keeps the whole 32->64 transition in user mode: the guest
 * far-jumps through wow64cpu's thunk into 64-bit code, and every syscall it
 * makes arrives here as an ordinary 64-bit one. The kernel therefore never
 * sees a 32-bit syscall and never emulates an instruction. What it DOES owe
 * a 32-bit .exe is the mirrored state the 64-bit ntdll, wow64.dll and the
 * guest ntdll all read before any of them has run:
 *
 *   PEB32   one page above the PEB, with WOW64INFO immediately behind it
 *           and its own 32-bit RTL_USER_PROCESS_PARAMETERS copy;
 *   TEB32   0x2000 into the (already 4-page) TEB block, cross-linked with
 *           the TEB64 through WowTebOffset and GdiBatchCount;
 *   the CPU area, carved off the top of the 64-bit stack, holding the guest
 *           I386_CONTEXT the first far-jump into the guest restores;
 *   LdrSystemDllInitBlock, the handshake by which the 64-bit ntdll tells
 *           wow64.dll where the guest ntdll's entry points are.
 *
 * Every layout here comes from abi/ntwow64.h (generated, Art. 4) and every
 * VALUE from the pinned tree's own initializers, named per block. This file
 * is the WOW64 milestone's cohesive home (Art. 7 / G7): deleting it and the
 * handful of `if (process->wow64)` call sites restores the CUI core.
 */
#include "kernel/ps/ps.h"

#include "abi/ntimage.h"
#include "abi/ntpebteb.h"
#include "abi/ntwow64.h"
#include "arch/x86_64/gdt.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/mm/pecoff.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/syscall/uaccess.h"
#include "arch/x86_64/mmu.h"

/* The guest ntdll. WOW64's directory convention: a 32-bit image's system DLL
 * comes from syswow64 while system32 keeps the 64-bit one (third_party/wine
 * dlls/ntdll/unix/loader.c get_machine_wow64_dir). */
#define PSP_NTDLL32_PATH WSTR("\\??\\C:\\windows\\syswow64\\ntdll.dll")

/* dlls/ntdll/unix/unix_private.h: `static const LONG teb_offset = 0x2000;`
 * — the TEB32 sits that far into the TEB block, and the two TEBs point at
 * each other with +/- this value. */
#define PSP_WOW_TEB_OFFSET 0x2000

/* The guest address-space ceilings, from virtual_set_large_address_space
 * (dlls/ntdll/unix/virtual.c): 2GB, or 4GB when the main image declares
 * IMAGE_FILE_LARGE_ADDRESS_AWARE. Wine reports the ceiling as limit-1. */
#define PSP_WOW_LIMIT_2GB 0x80000000ULL
#define PSP_WOW_LIMIT_4GB 0x100000000ULL

/* The 64-bit stack of a WOW64 thread: a fixed 0x40000, allocated ABOVE 4GB.
 * The low bound is deliberate and is the opposite of the obvious reading —
 * dlls/ntdll/unix/thread.c init_thread_stack passes limit_4g as the LOW
 * limit, keeping the scarce sub-4GB space for the guest, which gets its own
 * stack under the wow limit. */
#define PSP_WOW_HOST_STACK_SIZE 0x40000

uint64_t PspWow64SpaceLimit(USHORT imageCharacteristics)
{
    return (imageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ? PSP_WOW_LIMIT_4GB
                                                                   : PSP_WOW_LIMIT_2GB;
}

/* ---- the 32-bit process parameters --------------------------------------
 * A separate low allocation whose strings mirror the 64-bit block's, laid
 * out [struct][string buffers][env] exactly as the 64-bit builder lays its
 * own out — the shape build_wow64_parameters produces (dlls/ntdll/unix/
 * env.c) and the shape ntdll frees wholesale. */
#define PSP_ROUND16(x) (((uint64_t)(x) + 15) & ~15ULL)

static void PspWow64SetString32(UNICODE_STRING32 *field, const UNICODE_STRING *source,
                                uint64_t bufferVa)
{
    field->Length = source->Length;
    field->MaximumLength = source->MaximumLength;
    field->Buffer = (ULONG)bufferVa;
}

static NTSTATUS PspWow64BuildParameters32(PEPROCESS process, const PSP_CAPTURED_PARAMS *captured,
                                          uint64_t *paramsOut)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;

    /* Same capacity rule as the 64-bit block: CurrentDirectory always gets
     * MAX_PATH so the guest's RtlSetCurrentDirectory_U can write into it. */
    USHORT maximums[PSP_PARAM_COUNT];
    uint64_t structSize = sizeof(RTL_USER_PROCESS_PARAMETERS32);
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        USHORT maximum = captured->strings[i].Buffer != 0 ? captured->strings[i].MaximumLength : 0;
        if (i == PSP_PARAM_CURRENT_DIRECTORY && maximum < 260 * sizeof(WCHAR))
        {
            maximum = 260 * sizeof(WCHAR);
        }
        /* The same never-a-NULL-Buffer rule the 64-bit block follows, and
         * the same two exemptions (ps/peb.c says why DllPath's null is
         * load-bearing). build_wow64_parameters duplicates whatever the
         * 64-bit block has, so the two must agree field for field —
         * ntdll:wow64 checks each 32-bit Buffer lands inside the 32-bit
         * block AND that its Length matches the 64-bit one. */
        if (maximum < sizeof(WCHAR) && i != PSP_PARAM_DLL_PATH && i != PSP_PARAM_RUNTIME_INFO)
        {
            maximum = sizeof(WCHAR);
        }
        maximums[i] = maximum;
        structSize += PSP_ROUND16(maximum);
    }
    uint64_t environmentBytes =
        captured->environment != 0 ? captured->environmentSize : 2 * sizeof(WCHAR);
    uint64_t regionSize = structSize + PSP_ROUND16(environmentBytes);

    /* Under the guest ceiling: the block is addressed by 32-bit pointers. */
    PVOID base = 0;
    SIZE_T size = regionSize;
    NTSTATUS status =
        MiAllocateVirtualMemoryEx(space, &base, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0,
                                  process->wowSpaceLimit - 1, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t paramsVa = (uint64_t)(uintptr_t)base;

    char *scratch = MiAllocatePool(regionSize);
    if (scratch == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(scratch, 0, regionSize);
    RTL_USER_PROCESS_PARAMETERS32 *params = (RTL_USER_PROCESS_PARAMETERS32 *)scratch;
    params->AllocationSize = (ULONG)regionSize;
    params->Size = (ULONG)structSize;
    params->Flags = captured->header.Flags;
    params->DebugFlags = captured->header.DebugFlags;
    params->ConsoleFlags = captured->header.ConsoleFlags;
    params->dwX = captured->header.dwX;
    params->dwY = captured->header.dwY;
    params->dwXSize = captured->header.dwXSize;
    params->dwYSize = captured->header.dwYSize;
    params->dwXCountChars = captured->header.dwXCountChars;
    params->dwYCountChars = captured->header.dwYCountChars;
    params->dwFillAttribute = captured->header.dwFillAttribute;
    params->dwFlags = captured->header.dwFlags;
    params->wShowWindow = captured->header.wShowWindow;
    /* Handles are ints on both sides — a 32-bit process's handle values are
     * the same small numbers (Wine's own wow64 thunks pass them through). */
    params->ConsoleHandle = (ULONG)(ULONG_PTR)captured->header.ConsoleHandle;
    params->hStdInput = (ULONG)(ULONG_PTR)captured->header.hStdInput;
    params->hStdOutput = (ULONG)(ULONG_PTR)captured->header.hStdOutput;
    params->hStdError = (ULONG)(ULONG_PTR)captured->header.hStdError;

    UNICODE_STRING32 *fields[PSP_PARAM_COUNT];
    fields[PSP_PARAM_CURRENT_DIRECTORY] = &params->CurrentDirectory.DosPath;
    fields[PSP_PARAM_DLL_PATH] = &params->DllPath;
    fields[PSP_PARAM_IMAGE_PATH] = &params->ImagePathName;
    fields[PSP_PARAM_COMMAND_LINE] = &params->CommandLine;
    fields[PSP_PARAM_WINDOW_TITLE] = &params->WindowTitle;
    fields[PSP_PARAM_DESKTOP] = &params->Desktop;
    fields[PSP_PARAM_SHELL_INFO] = &params->ShellInfo;
    fields[PSP_PARAM_RUNTIME_INFO] = &params->RuntimeInfo;

    uint64_t heapOffset = sizeof(RTL_USER_PROCESS_PARAMETERS32);
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        if (maximums[i] == 0)
        {
            continue;
        }
        if (captured->strings[i].Buffer != 0 && captured->strings[i].Length != 0)
        {
            memcpy(scratch + heapOffset, captured->strings[i].Buffer, captured->strings[i].Length);
        }
        PspWow64SetString32(fields[i], &captured->strings[i], paramsVa + heapOffset);
        fields[i]->MaximumLength = maximums[i];
        heapOffset += PSP_ROUND16(maximums[i]);
    }
    if (captured->environment != 0)
    {
        memcpy(scratch + heapOffset, captured->environment, captured->environmentSize);
    }
    params->Environment = (ULONG)(paramsVa + heapOffset);
    params->EnvironmentSize = (ULONG)environmentBytes;

    MiCopyToUserRange(space, paramsVa, scratch, regionSize);
    MiFreePool(scratch);
    *paramsOut = paramsVa;
    return STATUS_SUCCESS;
}

/* ---- PEB32 + WOW64INFO ---------------------------------------------------
 * init_peb (dlls/ntdll/unix/env.c): the PEB32 is the page above the PEB, and
 * RtlWow64GetSharedInfoProcess reads the WOW64INFO at `peb32 + 1` — so the
 * two are adjacent by contract, not by convenience. Both live inside the
 * PEB's existing 4-page block. */
NTSTATUS PspWow64BuildPeb32(PEPROCESS process, uint64_t imageBase,
                            const PSP_CAPTURED_PARAMS *captured, ULONG globalFlag)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    uint64_t peb32Va = process->pebBase + PAGE_SIZE;
    _Static_assert(sizeof(PEB32) + sizeof(WOW64INFO) <= 3 * PAGE_SIZE,
                   "PEB32 + WOW64INFO must fit the PEB block's tail");

    uint64_t params32Va = 0;
    NTSTATUS status = PspWow64BuildParameters32(process, captured, &params32Va);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEB32 *peb32 = MiAllocatePool(sizeof(PEB32));
    if (peb32 == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(peb32, 0, sizeof(PEB32));
    peb32->ImageBaseAddress = (ULONG)imageBase;
    peb32->ProcessParameters = (ULONG)params32Va;
    peb32->NtGlobalFlag = globalFlag;
    peb32->NumberOfProcessors = KE_NUMBER_PROCESSORS;
    peb32->OSMajorVersion = 10;
    peb32->OSMinorVersion = 0;
    peb32->OSBuildNumber = 19045;
    peb32->OSPlatformId = 2; /* VER_PLATFORM_WIN32_NT */
    peb32->SessionId = 1;
    peb32->ImageSubSystem = process->imageInformation.SubSystemType;
    peb32->ImageSubSystemMajorVersion = process->imageInformation.MajorSubsystemVersion;
    peb32->ImageSubSystemMinorVersion = process->imageInformation.MinorSubsystemVersion;
    /* Ldr / ProcessHeap / the TLS bitmaps stay null for the same reason the
     * 64-bit PEB's do: the guest ntdll's own loader_init builds them. */
    MiCopyToUserRange(space, peb32Va, peb32, sizeof(PEB32));
    MiFreePool(peb32);

    /* WOW64INFO. wow64.dll's process_init fills the page size and the two
     * machine words itself and wow64cpu ORs in WOW64_CPUFLAGS_MSFT64, so
     * the kernel's job is only to leave a zeroed, WRITABLE struct where the
     * contract says it is — which the zero-filled PEB block already does.
     * Written explicitly all the same: a reader that finds it by scanning
     * (ntdll:wow64's test_wow64_shared_info walks the PEB looking for a
     * byte-for-byte match) must not match on a run of incidental zeros. */
    WOW64INFO info;
    memset(&info, 0, sizeof(info));
    MiCopyToUserRange(space, peb32Va + sizeof(PEB32), &info, sizeof(info));

    process->peb32Base = peb32Va;
    return STATUS_SUCCESS;
}

/* ---- TEB32 ---------------------------------------------------------------
 * init_teb (dlls/ntdll/unix/virtual.c, the _WIN64 arm) — the 32-bit mirror
 * of what PspBuildTeb writes, plus the two cross-links that make the pair
 * navigable from either side: TEB64.WowTebOffset/-Tib.ExceptionList point
 * DOWN at the TEB32, and TEB32.GdiBatchCount carries the TEB64 address,
 * which is how 32-bit ntdll's NtCurrentTeb64() finds its other half
 * (dlls/ntdll/ntdll_misc.h). */
NTSTATUS PspWow64BuildTeb32(PEPROCESS process, uint64_t tebVa, uint64_t uniqueProcessId,
                            uint64_t uniqueThreadId, uint64_t guestStackBase,
                            uint64_t guestStackLimit, uint64_t guestStackAllocation)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    uint64_t teb32Va = tebVa + PSP_WOW_TEB_OFFSET;
    _Static_assert(sizeof(TEB32) <= 2 * PAGE_SIZE, "TEB32 must fit the TEB block's tail");

    TEB32 *teb32 = MiAllocatePool(sizeof(TEB32));
    if (teb32 == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(teb32, 0, sizeof(TEB32));
    teb32->Tib.Self = (ULONG)teb32Va;
    teb32->Tib.ExceptionList = ~0u; /* the empty 32-bit SEH chain */
    teb32->Tib.FiberData = 0x1e00;
    teb32->Tib.StackBase = (ULONG)guestStackBase;
    teb32->Tib.StackLimit = (ULONG)guestStackLimit;
    teb32->DeallocationStack = (ULONG)guestStackAllocation;
    teb32->Peb = (ULONG)process->peb32Base;
    teb32->ClientId.UniqueProcess = (ULONG)uniqueProcessId;
    teb32->ClientId.UniqueThread = (ULONG)uniqueThreadId;
    teb32->RealClientId = teb32->ClientId;
    teb32->ActivationContextStackPointer =
        (ULONG)(teb32Va + offsetof(TEB32, ActivationContextStack));
    uint64_t frameListVa = teb32Va + offsetof(TEB32, ActivationContextStack) +
                           offsetof(ACTIVATION_CONTEXT_STACK32, FrameListCache);
    teb32->ActivationContextStack.FrameListCache.Flink =
        teb32->ActivationContextStack.FrameListCache.Blink = (ULONG)frameListVa;
    teb32->StaticUnicodeString.Buffer = (ULONG)(teb32Va + offsetof(TEB32, StaticUnicodeBuffer));
    teb32->StaticUnicodeString.MaximumLength = sizeof(teb32->StaticUnicodeBuffer);
    teb32->GdiBatchCount = (ULONG)tebVa;
    teb32->WowTebOffset = -PSP_WOW_TEB_OFFSET;
    MiCopyToUserRange(space, teb32Va, teb32, sizeof(TEB32));
    MiFreePool(teb32);

    /* The 64-bit half's two WOW64 fields. Tib.ExceptionList is not an SEH
     * chain on x64 — for a WOW64 thread it is where init_teb parks the
     * TEB32 pointer, and 32-bit ntdll reads it back. */
    uint64_t exceptionList = teb32Va;
    MiCopyToUserRange(space, tebVa + offsetof(TEB, Tib.ExceptionList), &exceptionList,
                      sizeof(exceptionList));
    LONG wowTebOffset = PSP_WOW_TEB_OFFSET;
    MiCopyToUserRange(space, tebVa + offsetof(TEB, WowTebOffset), &wowTebOffset,
                      sizeof(wowTebOffset));
    return STATUS_SUCCESS;
}

/* The base a WOW64 thread's compat-mode FS descriptor must carry — its
 * TEB32 — and 0 for every thread of a 64-bit process, which is what marks
 * the descriptor absent. The scheduler's whole WOW64 cost is this one call
 * (G7: delete wow64.c and the call site collapses to "always 0"). */
uint64_t PspWow64Fs32Base(PKTHREAD thread)
{
    if (thread->teb == 0 || thread->process == 0 || !thread->process->wow64)
    {
        return 0;
    }
    return (uint64_t)(uintptr_t)thread->teb + PSP_WOW_TEB_OFFSET;
}

/* ---- the CPU area and the guest's initial context ------------------------
 * init_thread_stack (dlls/ntdll/unix/thread.c): the WOW64_CPURESERVED is
 * carved off the TOP of the 64-bit stack, 16-aligned, with the guest CONTEXT
 * immediately behind it, and its address is published in BOTH
 * TEB64.Tib.StackBase and TEB64.TlsSlots[WOW64_TLS_CPURESERVED] — wow64.dll
 * reads the TLS slot, ntdll's RtlWow64GetCpuAreaInfo reads either. */
NTSTATUS PspWow64BuildCpuArea(PEPROCESS process, uint64_t tebVa, uint64_t hostStackTop,
                              uint64_t guestEntry, uint64_t guestStackBase, uint64_t *cpuAreaOut)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;

    uint64_t cpuSize = sizeof(WOW64_CPURESERVED) + ((sizeof(I386_CONTEXT) + 7) & ~7ULL) +
                       sizeof(uint64_t); /* + the CONTEXT_EX slot Wine reserves */
    uint64_t cpuArea = (hostStackTop - cpuSize) & ~15ULL;

    WOW64_CPURESERVED reserved;
    memset(&reserved, 0, sizeof(reserved));
    reserved.Machine = IMAGE_FILE_MACHINE_I386;
    MiCopyToUserRange(space, cpuArea, &reserved, sizeof(reserved));

    /* The guest's first context. Values from the pinned tree's own thread
     * seeding (dlls/ntdll/unix/signal_x86_64.c, the wow_context arm):
     * Eax = the image entry, Ebx = the PEB32, Esp just under the guest
     * stack's top, Eip = the GUEST ntdll's RtlUserThreadStart, and the
     * segment trio the compat-mode descriptors gdt.c installs. wow64.dll's
     * thread_init rewrites Eip/Esp to enter the guest LdrInitializeThunk;
     * what must be right HERE is everything it reads to do so. */
    I386_CONTEXT context;
    memset(&context, 0, sizeof(context));
    context.ContextFlags = CONTEXT_I386_FULL;
    context.Eax = (ULONG)guestEntry;
    context.Ebx = (ULONG)process->peb32Base;
    context.Esp = (ULONG)((guestStackBase - 16) & ~15ULL);
    context.Eip = (ULONG)process->wow64RtlUserThreadStart;
    context.SegCs = KI_USER_CS32_SELECTOR;
    context.SegSs = KI_USER_DS_SELECTOR;
    context.SegDs = KI_USER_DS_SELECTOR;
    context.SegEs = KI_USER_DS_SELECTOR;
    context.SegGs = KI_USER_DS_SELECTOR;
    context.SegFs = KI_USER_FS32_SELECTOR;
    context.EFlags = 0x202; /* IF, and bit 1 (reserved, always set) */
    context.FloatSave.ControlWord = 0x27f;
    MiCopyToUserRange(space, cpuArea + sizeof(WOW64_CPURESERVED), &context, sizeof(context));

    /* Published twice, deliberately (see the block comment). */
    MiCopyToUserRange(space, tebVa + offsetof(TEB, Tib.StackBase), &cpuArea, sizeof(cpuArea));
    uint64_t slot = tebVa + offsetof(TEB, TlsSlots) + WOW64_TLS_CPURESERVED * sizeof(uint64_t);
    MiCopyToUserRange(space, slot, &cpuArea, sizeof(cpuArea));

    *cpuAreaOut = cpuArea;
    return STATUS_SUCCESS;
}

/* ---- LdrSystemDllInitBlock ----------------------------------------------
 * load_ntdll_wow64_functions (dlls/ntdll/unix/loader.c): the 64-bit ntdll
 * exports an empty LdrSystemDllInitBlock which the loader fills with the
 * GUEST ntdll's entry points and then copies into the guest ntdll's own
 * copy of the same variable. wow64.dll reads the 64-bit one to find where
 * to re-enter the guest; the guest's ntdll reads its own. Both must be
 * written before the first thread runs, which is why it happens here and
 * not in a user-mode loader. */
NTSTATUS PspWow64FillInitBlock(PEPROCESS process, uint64_t hostBlockVa, uint64_t guestBlockVa,
                               const PSP_WOW64_NTDLL32_RVAS *rvas)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    uint64_t base = process->ntdll32Base;

    SYSTEM_DLL_INIT_BLOCK block;
    memset(&block, 0, sizeof(block));
    block.version = sizeof(block);
    block.ntdll_handle = base;
    block.pLdrInitializeThunk = base + rvas->ldrInitializeThunk;
    block.pKiUserExceptionDispatcher = base + rvas->kiUserExceptionDispatcher;
    block.pKiUserApcDispatcher = base + rvas->kiUserApcDispatcher;
    block.pKiUserCallbackDispatcher = base + rvas->kiUserCallbackDispatcher;
    block.pRtlUserThreadStart = base + rvas->rtlUserThreadStart;
    block.pRtlpQueryProcessDebugInformationRemote =
        rvas->rtlpQueryProcessDebugInformationRemote != 0
            ? base + rvas->rtlpQueryProcessDebugInformationRemote
            : 0;
    block.pLdrSystemDllInitBlock = guestBlockVa;
    block.pRtlpFreezeTimeBias = rvas->rtlpFreezeTimeBias != 0 ? base + rvas->rtlpFreezeTimeBias : 0;

    if (hostBlockVa != 0)
    {
        MiCopyToUserRange(space, hostBlockVa, &block, sizeof(block));
    }
    if (guestBlockVa != 0)
    {
        MiCopyToUserRange(space, guestBlockVa, &block, sizeof(block));
    }
    process->wow64RtlUserThreadStart = block.pRtlUserThreadStart;
    return STATUS_SUCCESS;
}

/* ---- the guest stack -----------------------------------------------------
 * The second of a WOW64 thread's two stacks: reserved from the image's own
 * header sizes and placed under the guest ceiling, where 32-bit code can
 * address it. The 64-bit stack it pairs with is the ordinary one every
 * thread gets — except placed ABOVE 4GB (see PSP_WOW_HOST_STACK_SIZE). */
NTSTATUS PspWow64AllocateGuestStack(PEPROCESS process, uint64_t reserve, uint64_t commit,
                                    uint64_t *baseOut, uint64_t *limitOut, uint64_t *allocationOut)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    uint64_t limit = process->wowSpaceLimit - 1;

    /* The same clamping ladder the 64-bit stack goes through (process.c
     * PspAllocateUserStack): both sizes come from a file the caller
     * supplies, so an absurd SizeOfStackReserve must not round to 0 and
     * underflow the commit. Bounded by the guest ceiling, not
     * KI_USER_SPACE_LIMIT. */
    if (reserve > limit - MI_ALLOCATION_GRANULARITY)
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    reserve = (reserve + MI_ALLOCATION_GRANULARITY - 1) & ~(MI_ALLOCATION_GRANULARITY - 1);
    if (reserve < 3ULL * PAGE_SIZE)
    {
        reserve = MI_ALLOCATION_GRANULARITY;
    }
    commit = (commit + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);
    if (commit < PAGE_SIZE)
    {
        commit = PAGE_SIZE;
    }
    if (commit > reserve - 2ULL * PAGE_SIZE)
    {
        commit = reserve - 2ULL * PAGE_SIZE;
    }

    PVOID base = 0;
    SIZE_T size = reserve;
    NTSTATUS status =
        MiAllocateVirtualMemoryEx(space, &base, &size, MEM_RESERVE, PAGE_READWRITE, 0, limit, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t bottom = (uint64_t)(uintptr_t)base;
    uint64_t top = bottom + reserve;

    PVOID commitBase = (PVOID)(uintptr_t)(top - commit);
    size = commit;
    status = MiAllocateVirtualMemory(space, &commitBase, &size, MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(status))
    {
        PVOID guardBase = (PVOID)(uintptr_t)(top - commit - PAGE_SIZE);
        size = PAGE_SIZE;
        status = MiAllocateVirtualMemory(space, &guardBase, &size, MEM_COMMIT,
                                         PAGE_READWRITE | PAGE_GUARD);
    }
    if (!NT_SUCCESS(status))
    {
        return status; /* PspDeleteProcess unwinds the reservation */
    }

    *baseOut = top;
    *limitOut = top - commit;
    *allocationOut = bottom;
    return STATUS_SUCCESS;
}

/* The LOWEST address a WOW64 thread's 64-bit stack may take. The guest owns
 * the low address space and it is scarce (2GB or 4GB total for image, heap
 * and guest stacks), so the host stack is pushed above 4GB — the same split
 * init_thread_stack makes by handing virtual_alloc_thread_stack limit_4g as
 * its LOW limit (dlls/ntdll/unix/thread.c). Pinned by
 * sem_ps/wow64_process.c, which measures the stack base above 4GB. */
uint64_t PspWow64HostStackFloor(void)
{
    return PSP_WOW_LIMIT_4GB;
}

/* A WOW64 thread's CPU area, read back from where it was published —
 * TEB64.TlsSlots[WOW64_TLS_CPURESERVED]. Reading the TEB rather than
 * caching a kernel copy keeps ONE authority for the value (Art. 11): user
 * mode is allowed to move it (wow64.dll's thread_init does exactly that on
 * every thread), and a stale kernel copy would then describe a context
 * nobody uses. A thread with no CPU area is not a WOW64 thread — the
 * caller turns that into the failure its own contract names. */
NTSTATUS PspWow64ThreadCpuArea(PETHREAD thread, uint64_t *cpuAreaOut)
{
    if (thread->process == 0 || !thread->process->wow64 || thread->tebBase == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    uint64_t slot =
        thread->tebBase + offsetof(TEB, TlsSlots) + WOW64_TLS_CPURESERVED * sizeof(uint64_t);
    uint64_t cpuArea = 0;
    if (MiCopyFromUserRange(&thread->process->addressSpace, &cpuArea, slot, sizeof(cpuArea)) !=
        sizeof(cpuArea))
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (cpuArea == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *cpuAreaOut = cpuArea;
    return STATUS_SUCCESS;
}

const WCHAR *PspWow64Ntdll32Path(void)
{
    static const WCHAR path[] = PSP_NTDLL32_PATH;
    return path;
}

uint64_t PspWow64HostStackSize(void)
{
    return PSP_WOW_HOST_STACK_SIZE;
}
