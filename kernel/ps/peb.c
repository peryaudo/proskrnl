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

/* The process-parameters block is laid out as [struct][string buffers][env] in
 * one user allocation; ntdll frees it wholesale with NtFreeVirtualMemory
 * (docs/03), so it must be a standalone region. Offsets within a scratch copy
 * are fixed here and the UNICODE_STRING.Buffer pointers set to the matching
 * user VAs before the block is copied out. */
#define PSP_PARAMS_REGION_SIZE 0x1000

NTSTATUS PspBuildPeb(PEPROCESS process, uint64_t imageBase, const char *imagePath,
                     const char *commandLine)
{
    PMI_ADDRESS_SPACE space = &process->addressSpace;

    /* --- RTL_USER_PROCESS_PARAMETERS -------------------------------------- */
    PVOID paramsBase = 0;
    SIZE_T paramsSize = PSP_PARAMS_REGION_SIZE;
    NTSTATUS status = MiAllocateVirtualMemory(space, &paramsBase, &paramsSize,
                                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t paramsVa = (uint64_t)(uintptr_t)paramsBase;

    char *scratch = MiAllocatePool(PSP_PARAMS_REGION_SIZE);
    if (scratch == 0)
    {
        return STATUS_NO_MEMORY;
    }
    memset(scratch, 0, PSP_PARAMS_REGION_SIZE);
    RTL_USER_PROCESS_PARAMETERS *params = (RTL_USER_PROCESS_PARAMETERS *)scratch;
    params->AllocationSize = PSP_PARAMS_REGION_SIZE;
    params->Size = PSP_PARAMS_REGION_SIZE;
    params->Flags = PROCESS_PARAMS_FLAG_NORMALIZED; /* pointers are absolute */

    /* String heap grows from just past the struct; each UNICODE_STRING.Buffer
     * is a USER VA into the same block. */
    uint64_t heapOffset = (sizeof(RTL_USER_PROCESS_PARAMETERS) + 15) & ~15ULL;

#define PSP_EMIT_STRING(field, ascii)                                                              \
    do                                                                                             \
    {                                                                                              \
        WCHAR *dst = (WCHAR *)(scratch + heapOffset);                                              \
        USHORT bytes = PspAsciiToWide(dst, (ascii), 260);                                          \
        params->field.Length = bytes;                                                              \
        params->field.MaximumLength = (USHORT)(bytes + sizeof(WCHAR));                             \
        params->field.Buffer = (PWSTR)(uintptr_t)(paramsVa + heapOffset);                          \
        heapOffset += (params->field.MaximumLength + 15) & ~15ULL;                                 \
    } while (0)

    PSP_EMIT_STRING(ImagePathName, imagePath);
    PSP_EMIT_STRING(CommandLine, commandLine);
    PSP_EMIT_STRING(DllPath, "C:\\windows\\system32");
    params->CurrentDirectory.DosPath.Length = 0;
    PSP_EMIT_STRING(WindowTitle, imagePath);
#undef PSP_EMIT_STRING

    /* M9: the console plumbing. A REAL handle value (not the CONSOLE_HANDLE_*
     * alloc sentinels) makes kernelbase's init_console bind to the existing
     * console — create_console_connection(params->ConsoleHandle) — and the
     * seeded std handles are used as-is (third_party/wine
     * dlls/kernelbase/console.c init_console). Zero = no console. */
    params->ConsoleHandle = process->consoleHandle;
    params->hStdInput = process->stdInput;
    params->hStdOutput = process->stdOutput;
    params->hStdError = process->stdError;

    /* Current directory "C:\\windows\\system32\\" with a trailing slash. */
    {
        WCHAR *dst = (WCHAR *)(scratch + heapOffset);
        USHORT bytes = PspAsciiToWide(dst, "C:\\windows\\system32\\", 260);
        params->CurrentDirectory.DosPath.Length = bytes;
        params->CurrentDirectory.DosPath.MaximumLength = (USHORT)(bytes + sizeof(WCHAR));
        params->CurrentDirectory.DosPath.Buffer = (PWSTR)(uintptr_t)(paramsVa + heapOffset);
        heapOffset += (params->CurrentDirectory.DosPath.MaximumLength + 15) & ~15ULL;
    }

    /* Environment: an empty double-NUL block (a valid, terminated env). */
    WCHAR *env = (WCHAR *)(scratch + heapOffset);
    env[0] = 0;
    env[1] = 0;
    params->Environment = (PWSTR)(uintptr_t)(paramsVa + heapOffset);
    params->EnvironmentSize = 2 * sizeof(WCHAR);
    heapOffset += 16;
    ASSERT(heapOffset <= PSP_PARAMS_REGION_SIZE);

    MiCopyToUserRange(space, paramsVa, scratch, PSP_PARAMS_REGION_SIZE);
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
