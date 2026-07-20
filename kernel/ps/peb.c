/* kernel/ps/peb.c — the user-visible process structures (M7).
 *
 * docs/00 puts PEB / TEB / RTL_USER_PROCESS_PARAMETERS / KUSER_SHARED_DATA on
 * the boundary "byte-for-byte, because Wine's DLLs read their fields
 * directly." The layouts are the generated abi/ (Art. 4); this file only
 * decides the *values* and where the blocks live in the user address space.
 * docs/05 (Ps): only the OUTSIDE of these structs is strict — the values that
 * ntdll's loader_init and RTL actually read (ImageBaseAddress,
 * ProcessParameters, the NT_TIB, the version fields). Everything ntdll builds
 * for itself (Peb->Ldr, ProcessHeap, the TLS bitmaps) is deliberately left
 * zero here (see the M7 startup map in docs/03).
 *
 * The blocks are built in kernel pool then copied into the (not-current)
 * target address space through the Mm engine, so every user page stays
 * VAD-tracked exactly like an NtAllocateVirtualMemory result.
 */
#include "kernel/ps/ps.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/virtual.h"
#include "kernel/lib/string.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntpebteb.h"
#include "abi/ntkeapi.h"

/* KUSER_SHARED_DATA lives at this fixed user VA on x64 NT; Wine's PE ntdll
 * syscall thunks test its SystemCall byte at 0x7ffe0308 and RTL reads its
 * time/version fields. Cross-check: third_party/wine dlls/ntdll/unix/virtual.c
 * `user_shared_data = (void *)0x7ffe0000`, and include/ddk/wdm.h. */
#define PSP_SHARED_USER_DATA_VA 0x7ffe0000ULL

/* The single shared page, kernel-owned, mapped read-only into every process. */
static uint64_t PspSharedUserDataFrame;

void PspInitializeSharedUserData(void)
{
    PspSharedUserDataFrame = MiAllocatePage();
    if (PspSharedUserDataFrame == 0)
    {
        KiPanic("PspInitializeSharedUserData: out of frames");
    }
    KUSER_SHARED_DATA *kusd = MiPhysicalToVirtual(PspSharedUserDataFrame);
    memset(kusd, 0, PAGE_SIZE);

    /* SystemCall == 0 keeps Wine's PE thunks on the raw `syscall` path
     * (include/wine/asm.h: they detour to 0x7ffe1000 only when bit 0 is set —
     * that is a host-Wine-on-Linux need, not ours). */
    kusd->SystemCall = 0;

    /* M10: the time fields tick. Readers ignore TickCountMultiplier
     * (dlls/kernelbase/sync.c GetTickCount64) but it is set once, as Wine's
     * own page constructor does (dlls/ntdll/unix/virtual.c: 1 << 24, i.e.
     * TickCount is already in milliseconds). Registering the page with Ke
     * turns on the per-tick mirror (kernel/ke/timer.c); the explicit seed
     * makes the fields nonzero before the first tick. */
    kusd->TickCountMultiplier = 1 << 24;
    KiUserSharedData = kusd;
    KiSeedUserSharedDataTime();

    /* Version + machine fields ntdll/RTL read (docs/03 M7 startup map).
     * proskrnl reports as Windows 10.0 (the modern world Wine targets). */
    kusd->NtMajorVersion = 10;
    kusd->NtMinorVersion = 0;
    kusd->NtBuildNumber = 19045;
    kusd->NtProductType = NtProductWinNt;
    kusd->ProductTypeIsValid = TRUE;
    kusd->NativeProcessorArchitecture = 9; /* PROCESSOR_ARCHITECTURE_AMD64 */
    kusd->NXSupportPolicy = 2;             /* NX_SUPPORT_POLICY_OPTIN */

    /* NtSystemRoot = "C:\\windows" (UTF-16). ntdll composes DLL search paths
     * from it when ProcessParameters carries no DllPath. */
    static const char *systemRoot = "C:\\windows";
    for (int i = 0; systemRoot[i] != '\0'; i++)
    {
        kusd->NtSystemRoot[i] = (WCHAR)(unsigned char)systemRoot[i];
    }
}

NTSTATUS PspMapSharedUserData(PEPROCESS process)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    /* A mapped VAD that does NOT own its frame: teardown unmaps the page but
     * never frees the single shared frame (mm/virtual.c ownsFrames == FALSE). */
    PMI_VAD vad = MiCreateMappedVad(space, PSP_SHARED_USER_DATA_VA, PAGE_SIZE, PAGE_READONLY,
                                    MEM_MAPPED, 0, FALSE);
    if (vad == 0)
    {
        return STATUS_NO_MEMORY;
    }
    MiCommitFrameInVad(space, vad, PSP_SHARED_USER_DATA_VA, PspSharedUserDataFrame, PAGE_READONLY);
    return STATUS_SUCCESS;
}

/* Copy an ASCII string into a kernel UTF-16 buffer; returns the byte length
 * (excluding the terminator). */
static USHORT PspAsciiToWide(WCHAR *out, const char *ascii, USHORT maxChars)
{
    USHORT n = 0;
    while (ascii[n] != '\0' && n < maxChars - 1)
    {
        out[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    out[n] = 0;
    return (USHORT)(n * sizeof(WCHAR));
}

/* --- captured process parameters (M10) ------------------------------------- */

/* One pooled UNICODE_STRING copy; `source` is a header field whose Buffer is
 * a (parent) user VA — probed and copied under the parent's context. */
static NTSTATUS PspCaptureString(const UNICODE_STRING *source, UNICODE_STRING *out)
{
    out->Buffer = 0;
    out->Length = 0;
    out->MaximumLength = 0;
    if (source->Buffer == 0 || source->Length == 0)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = KiProbeForRead(source->Buffer, source->Length, sizeof(WCHAR));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    WCHAR *copy = MiAllocatePool(source->Length + sizeof(WCHAR));
    if (copy == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(copy, source->Buffer, source->Length);
    copy[source->Length / sizeof(WCHAR)] = 0;
    out->Buffer = copy;
    out->Length = source->Length;
    out->MaximumLength = (USHORT)(source->Length + sizeof(WCHAR));
    return STATUS_SUCCESS;
}

void PspFreeCapturedParams(PSP_CAPTURED_PARAMS *captured)
{
    if (captured == 0)
    {
        return;
    }
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        if (captured->strings[i].Buffer != 0)
        {
            MiFreePool(captured->strings[i].Buffer);
        }
    }
    if (captured->environment != 0)
    {
        MiFreePool(captured->environment);
    }
    MiFreePool(captured);
}

/* An environment block is bounded: NT caps the block at 32767 WCHARs per
 * variable but the whole block only by memory; 1 MiB is far beyond any real
 * CreateProcess environment and bounds the kernel copy. */
#define PSP_MAX_ENVIRONMENT_BYTES 0x100000

NTSTATUS PspCaptureProcessParameters(const RTL_USER_PROCESS_PARAMETERS *userParams,
                                     PSP_CAPTURED_PARAMS **capturedOut)
{
    NTSTATUS status = KiProbeForRead(userParams, sizeof(*userParams), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PSP_CAPTURED_PARAMS *captured = MiAllocatePool(sizeof(*captured));
    if (captured == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(captured, 0, sizeof(*captured));
    memcpy(&captured->header, userParams, sizeof(captured->header));

    /* The eight strings, from the snapshotted header's (parent-VA) fields. */
    const UNICODE_STRING *sources[PSP_PARAM_COUNT];
    sources[PSP_PARAM_CURRENT_DIRECTORY] = &captured->header.CurrentDirectory.DosPath;
    sources[PSP_PARAM_DLL_PATH] = &captured->header.DllPath;
    sources[PSP_PARAM_IMAGE_PATH] = &captured->header.ImagePathName;
    sources[PSP_PARAM_COMMAND_LINE] = &captured->header.CommandLine;
    sources[PSP_PARAM_WINDOW_TITLE] = &captured->header.WindowTitle;
    sources[PSP_PARAM_DESKTOP] = &captured->header.Desktop;
    sources[PSP_PARAM_SHELL_INFO] = &captured->header.ShellInfo;
    sources[PSP_PARAM_RUNTIME_INFO] = &captured->header.RuntimeInfo;
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        status = PspCaptureString(sources[i], &captured->strings[i]);
        if (!NT_SUCCESS(status))
        {
            PspFreeCapturedParams(captured);
            return status;
        }
    }

    /* The environment block, sized by the header's EnvironmentSize (Wine's
     * RtlCreateProcessParametersEx sets it; dlls/ntdll/env.c). */
    SIZE_T environmentSize = captured->header.EnvironmentSize;
    if (captured->header.Environment != 0 && environmentSize >= 2 * sizeof(WCHAR) &&
        environmentSize <= PSP_MAX_ENVIRONMENT_BYTES)
    {
        status = KiProbeForRead(captured->header.Environment, environmentSize, sizeof(WCHAR));
        if (!NT_SUCCESS(status))
        {
            PspFreeCapturedParams(captured);
            return status;
        }
        WCHAR *environment = MiAllocatePool(environmentSize);
        if (environment == 0)
        {
            PspFreeCapturedParams(captured);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(environment, captured->header.Environment, environmentSize);
        /* Force termination whatever the caller handed over. */
        environment[environmentSize / sizeof(WCHAR) - 1] = 0;
        captured->environment = environment;
        captured->environmentSize = environmentSize;
    }
    *capturedOut = captured;
    return STATUS_SUCCESS;
}

/* Pooled kernel-default string (ASCII in). */
static NTSTATUS PspDefaultString(const char *ascii, UNICODE_STRING *out)
{
    SIZE_T chars = 0;
    while (ascii[chars] != '\0')
    {
        chars++;
    }
    WCHAR *copy = MiAllocatePool((chars + 1) * sizeof(WCHAR));
    if (copy == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PspAsciiToWide(copy, ascii, (USHORT)(chars + 1));
    out->Buffer = copy;
    out->Length = (USHORT)(chars * sizeof(WCHAR));
    out->MaximumLength = (USHORT)((chars + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

NTSTATUS PspBuildDefaultParams(const char *imagePath, const char *commandLine,
                               PSP_CAPTURED_PARAMS **capturedOut)
{
    PSP_CAPTURED_PARAMS *captured = MiAllocatePool(sizeof(*captured));
    if (captured == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(captured, 0, sizeof(*captured));
    NTSTATUS status = PspDefaultString(imagePath, &captured->strings[PSP_PARAM_IMAGE_PATH]);
    if (NT_SUCCESS(status))
    {
        status = PspDefaultString(commandLine, &captured->strings[PSP_PARAM_COMMAND_LINE]);
    }
    if (NT_SUCCESS(status))
    {
        status = PspDefaultString("C:\\windows\\system32", &captured->strings[PSP_PARAM_DLL_PATH]);
    }
    if (NT_SUCCESS(status))
    {
        /* Current directory keeps its trailing slash (ntdll's
         * RtlSetCurrentDirectory_U expects the stored shape). */
        status = PspDefaultString("C:\\windows\\system32\\",
                                  &captured->strings[PSP_PARAM_CURRENT_DIRECTORY]);
    }
    if (NT_SUCCESS(status))
    {
        status = PspDefaultString(imagePath, &captured->strings[PSP_PARAM_WINDOW_TITLE]);
    }
    if (!NT_SUCCESS(status))
    {
        PspFreeCapturedParams(captured);
        return status;
    }
    *capturedOut = captured;
    return STATUS_SUCCESS;
}

/* The process-parameters block is laid out as [struct][string buffers][env]
 * in one user allocation — the shape Wine's own alloc_process_params emits
 * (dlls/ntdll/env.c) and ntdll frees wholesale with NtFreeVirtualMemory
 * (docs/03). Offsets are fixed in a scratch copy and the Buffer pointers set
 * to the matching user VAs before the block is copied out. */
#define PSP_ROUND16(x) (((uint64_t)(x) + 15) & ~15ULL)

NTSTATUS PspBuildPeb(PEPROCESS process, uint64_t imageBase, const PSP_CAPTURED_PARAMS *captured)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;

    /* --- RTL_USER_PROCESS_PARAMETERS -------------------------------------- */
    /* CurrentDirectory gets MAX_PATH capacity whatever its length: ntdll's
     * RtlSetCurrentDirectory_U writes the new path into this very buffer
     * (Wine dlls/ntdll/env.c: curdir.MaximumLength = MAX_PATH * 2). */
    USHORT maximums[PSP_PARAM_COUNT];
    uint64_t structSize = sizeof(RTL_USER_PROCESS_PARAMETERS);
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        USHORT maximum = captured->strings[i].Buffer != 0 ? captured->strings[i].MaximumLength : 0;
        if (i == PSP_PARAM_CURRENT_DIRECTORY && maximum < 260 * sizeof(WCHAR))
        {
            maximum = 260 * sizeof(WCHAR);
        }
        maximums[i] = maximum;
        structSize += PSP_ROUND16(maximum);
    }
    uint64_t environmentBytes =
        captured->environment != 0 ? captured->environmentSize : 2 * sizeof(WCHAR);
    uint64_t regionSize = structSize + PSP_ROUND16(environmentBytes);

    PVOID paramsBase = 0;
    SIZE_T paramsSize = regionSize;
    NTSTATUS status = MiAllocateVirtualMemory(space, &paramsBase, &paramsSize,
                                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t paramsVa = (uint64_t)(uintptr_t)paramsBase;

    char *scratch = MiAllocatePool(regionSize);
    if (scratch == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(scratch, 0, regionSize);
    RTL_USER_PROCESS_PARAMETERS *params = (RTL_USER_PROCESS_PARAMETERS *)scratch;
    /* Scalars travel verbatim from the captured header — ConsoleHandle,
     * ConsoleFlags, hStd*, dwX..wShowWindow, dwFlags (STARTF_*),
     * ProcessGroupId; the creation-time console/std fixups have already
     * been applied to it. */
    memcpy(params, &captured->header, sizeof(*params));
    params->AllocationSize = (ULONG)structSize;
    params->Size = (ULONG)structSize;
    params->Flags = captured->header.Flags | PROCESS_PARAMS_FLAG_NORMALIZED;
    params->EnvironmentSize = PSP_ROUND16(environmentBytes);

    UNICODE_STRING *fields[PSP_PARAM_COUNT];
    fields[PSP_PARAM_CURRENT_DIRECTORY] = &params->CurrentDirectory.DosPath;
    fields[PSP_PARAM_DLL_PATH] = &params->DllPath;
    fields[PSP_PARAM_IMAGE_PATH] = &params->ImagePathName;
    fields[PSP_PARAM_COMMAND_LINE] = &params->CommandLine;
    fields[PSP_PARAM_WINDOW_TITLE] = &params->WindowTitle;
    fields[PSP_PARAM_DESKTOP] = &params->Desktop;
    fields[PSP_PARAM_SHELL_INFO] = &params->ShellInfo;
    fields[PSP_PARAM_RUNTIME_INFO] = &params->RuntimeInfo;

    uint64_t heapOffset = sizeof(RTL_USER_PROCESS_PARAMETERS);
    for (int i = 0; i < PSP_PARAM_COUNT; i++)
    {
        if (maximums[i] == 0)
        {
            fields[i]->Length = 0;
            fields[i]->MaximumLength = 0;
            fields[i]->Buffer = 0;
            continue;
        }
        if (captured->strings[i].Buffer != 0)
        {
            memcpy(scratch + heapOffset, captured->strings[i].Buffer, captured->strings[i].Length);
        }
        fields[i]->Length = captured->strings[i].Length;
        fields[i]->MaximumLength = maximums[i];
        fields[i]->Buffer = (PWSTR)(uintptr_t)(paramsVa + heapOffset);
        heapOffset += PSP_ROUND16(maximums[i]);
    }
    ASSERT(heapOffset == structSize);

    /* Environment right after the struct+strings, exactly Wine's layout; an
     * absent environment becomes the valid empty (double-NUL) block. */
    if (captured->environment != 0)
    {
        memcpy(scratch + heapOffset, captured->environment, captured->environmentSize);
    }
    params->Environment = (PWSTR)(uintptr_t)(paramsVa + heapOffset);

    MiCopyToUserRange(space, paramsVa, scratch, regionSize);
    MiFreePool(scratch);

    /* --- PEB -------------------------------------------------------------- */
    /* A 4-page block, PEB at its base, rest committed zero — the shape Wine's
     * own allocator gives it (third_party/wine dlls/ntdll/unix/virtual.c
     * virtual_alloc_first_teb: the PEB occupies a TEB-sized 4*page block).
     * PE-side ntdll addresses relative to the PEB (its debug-channel table
     * sits pages behind it), so the block must be there to read. */
    PVOID pebBase = 0;
    SIZE_T pebSize = 4 * PAGE_SIZE;
    status = MiAllocateVirtualMemory(space, &pebBase, &pebSize, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t pebVa = (uint64_t)(uintptr_t)pebBase;

    PEB *peb = MiAllocatePool(sizeof(PEB));
    if (peb == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(peb, 0, sizeof(PEB));
    peb->ImageBaseAddress = (HMODULE)(uintptr_t)imageBase;
    peb->ProcessParameters = (RTL_USER_PROCESS_PARAMETERS *)(uintptr_t)paramsVa;
    peb->NumberOfProcessors = 1; /* uniprocessor (Art. 3) */
    peb->OSMajorVersion = 10;
    peb->OSMinorVersion = 0;
    peb->OSBuildNumber = 19045;
    peb->OSPlatformId = 2; /* VER_PLATFORM_WIN32_NT */
    peb->SessionId = 1;
    /* Ldr, ProcessHeap, FastPebLock, the TLS bitmaps: ntdll's loader_init
     * builds these itself (docs/03) — leave them null. */

    MiCopyToUserRange(space, pebVa, peb, sizeof(PEB));
    MiFreePool(peb);

    process->pebBase = pebVa;
    process->imageBase = imageBase;
    return STATUS_SUCCESS;
}

NTSTATUS PspBuildTeb(PEPROCESS process, uint64_t stackTop, uint64_t stackLimit,
                     uint64_t uniqueProcessId, uint64_t uniqueThreadId, uint64_t *tebOut)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;
    /* A 4-page block per TEB — Wine's PE ntdll keeps per-thread state BEHIND
     * the TEB proper (the debug_info buffer at teb+0x2000+sizeof(TEB32);
     * dlls/ntdll/thread.c get_info), and its unix allocator sizes every TEB
     * block at 4 * page_size (dlls/ntdll/unix/virtual.c virtual_alloc_teb).
     * The tail pages stay committed zero. */
    PVOID tebBase = 0;
    SIZE_T tebSize = 4 * PAGE_SIZE;
    _Static_assert(sizeof(TEB) <= 2 * PAGE_SIZE, "TEB must fit its block");
    NTSTATUS status = MiAllocateVirtualMemory(space, &tebBase, &tebSize, MEM_RESERVE | MEM_COMMIT,
                                              PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t tebVa = (uint64_t)(uintptr_t)tebBase;

    TEB *teb = MiAllocatePool(sizeof(TEB));
    if (teb == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(teb, 0, sizeof(TEB));
    teb->Tib.StackBase = (PVOID)(uintptr_t)stackTop;
    teb->Tib.StackLimit = (PVOID)(uintptr_t)stackLimit;
    teb->Tib.Self = (struct _NT_TIB *)(uintptr_t)tebVa;
    teb->Peb = (PEB *)(uintptr_t)process->pebBase;
    teb->ClientId.UniqueProcess = (HANDLE)(uintptr_t)uniqueProcessId;
    teb->ClientId.UniqueThread = (HANDLE)(uintptr_t)uniqueThreadId;
    /* The self-referential furniture ntdll's RTL reads without checking,
     * exactly as Wine's own TEB constructor seeds it (third_party/wine
     * dlls/ntdll/unix/virtual.c init_teb): an empty activation-context
     * stack (actctx.c walks ActivationContextStackPointer->ActiveFrame
     * unconditionally), the static-string buffer, and the x64 no-exception
     * list marker. All pointers are USER VAs into this same block. */
    teb->Tib.ExceptionList = (void *)~(uintptr_t)0;
    teb->ActivationContextStackPointer =
        (ACTIVATION_CONTEXT_STACK *)(uintptr_t)(tebVa + offsetof(TEB, ActivationContextStack));
    uint64_t frameListVa = tebVa + offsetof(TEB, ActivationContextStack) +
                           offsetof(ACTIVATION_CONTEXT_STACK, FrameListCache);
    teb->ActivationContextStack.FrameListCache.Flink =
        teb->ActivationContextStack.FrameListCache.Blink = (LIST_ENTRY *)(uintptr_t)frameListVa;
    teb->StaticUnicodeString.Buffer =
        (WCHAR *)(uintptr_t)(tebVa + offsetof(TEB, StaticUnicodeBuffer));
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);

    MiCopyToUserRange(space, tebVa, teb, sizeof(TEB));
    MiFreePool(teb);

    *tebOut = tebVa;
    return STATUS_SUCCESS;
}
