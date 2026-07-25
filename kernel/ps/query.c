/* kernel/ps/query.c — the M7 process/system query + miscellaneous Nt* surface.
 *
 * These are the services ntdll's loader_init and RTL read at startup (docs/03
 * M7 map): the process's PEB address and image info, a few system-information
 * classes, the timer/perf counter, the graceful-failure registry + NLS slice
 * (Cm proper is M8, NLS data is furniture), and the scheduling primitives
 * (NtDelayExecution / NtYieldExecution). io/query.c is the model for the
 * struct-filling (docs/05: the easiest kernel work). Classes with no
 * observable effect on a single-CPU proskrnl are accepted; unimplemented ones
 * name themselves via STATUS_NOT_IMPLEMENTED.
 */
#include "kernel/ps/ps.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/section.h"
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/io.h"

#include "abi/ntpsapi.h"
#include "abi/ntimage.h"
#include "abi/ntpebteb.h"
#include "abi/ntioapi.h"
#include "abi/ntregapi.h"

/* --- process information -------------------------------------------------- */

NTSTATUS NtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS infoClass, PVOID buffer,
                                   ULONG length, PULONG returnLength)
{
    PKTHREAD thread = KeGetCurrentThread();
    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = thread->process;
    }
    else
    {
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_INFORMATION,
                                                    &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    NTSTATUS status;
    switch (infoClass)
    {
    case ProcessBasicInformation:
    {
        /* NT wants the length EXACT: a short buffer is rejected, and an
         * over-long one is still filled but reported as INFO_LENGTH_MISMATCH
         * (Wine dlls/ntdll/unix/process.c: the `if (size > sizeof(...)) ret =
         * STATUS_INFO_LENGTH_MISMATCH` after the memcpy). returnLength is the
         * needed size in every case. Pinned by sem_ps/process_query. */
        if (length < sizeof(PROCESS_BASIC_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(PROCESS_BASIC_INFORMATION);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(PROCESS_BASIC_INFORMATION), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        PROCESS_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        /* STATUS_PENDING while alive, the real code once the process object
         * is signalled (what GetExitCodeProcess is built on — Wine
         * dlls/kernelbase/process.c reads this field). The M8 smss chain
         * propagates its child's code through here. */
        info.ExitStatus = process->header.signalState != 0 ? process->exitStatus : STATUS_PENDING;
        info.PebBaseAddress = (PEB *)(uintptr_t)process->pebBase;
        info.UniqueProcessId = process->uniqueProcessId;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        status = (length > sizeof(PROCESS_BASIC_INFORMATION)) ? STATUS_INFO_LENGTH_MISMATCH
                                                              : STATUS_SUCCESS;
        break;
    }
    case ProcessDebugPort:
    {
        if (length < sizeof(HANDLE))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(HANDLE), sizeof(HANDLE));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        HANDLE none = 0; /* not debugged */
        memcpy(buffer, &none, sizeof(none));
        if (returnLength != 0)
        {
            *returnLength = sizeof(none);
        }
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessVmCounters:
    {
        /* Both documented sizes are served, any other size is filled-but-
         * flagged (Wine dlls/ntdll/unix/process.c ProcessVmCounters: fill,
         * `if (size != sizeof(VM_COUNTERS) && size != sizeof(VM_COUNTERS_EX))
         * ret = STATUS_INFO_LENGTH_MISMATCH`). Values: with no paging and no
         * COW (Art. 3) every committed page is resident, so committed IS the
         * working set and the pagefile usage; reserved is VirtualSize.
         * Consumer: kernelbase GlobalMemoryStatusEx, pinned by kernel32:heap
         * test_GlobalMemoryStatus. */
        if (length < sizeof(VM_COUNTERS))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(VM_COUNTERS_EX);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        ULONG copyLength =
            length >= sizeof(VM_COUNTERS_EX) ? sizeof(VM_COUNTERS_EX) : sizeof(VM_COUNTERS);
        status = KiProbeForWrite(buffer, copyLength, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        uint64_t reserved = 0;
        uint64_t committed = 0;
        MiQueryVmCounters(&process->addressSpace, &reserved, &committed);
        VM_COUNTERS_EX info;
        memset(&info, 0, sizeof(info));
        info.PeakVirtualSize = reserved;
        info.VirtualSize = reserved;
        info.PeakWorkingSetSize = committed;
        info.WorkingSetSize = committed;
        info.PagefileUsage = committed;
        info.PeakPagefileUsage = committed;
        info.PrivateUsage = committed;
        memcpy(buffer, &info, copyLength);
        if (returnLength != 0)
        {
            *returnLength =
                length != sizeof(VM_COUNTERS) ? sizeof(VM_COUNTERS_EX) : sizeof(VM_COUNTERS);
        }
        status = (length == sizeof(VM_COUNTERS) || length == sizeof(VM_COUNTERS_EX))
                     ? STATUS_SUCCESS
                     : STATUS_INFO_LENGTH_MISMATCH;
        break;
    }
    case ProcessWow64Information:
    {
        /* The WOW64 PEB address: always 0 — x64-only, no WOW64 process can
         * exist (docs/adr/0006), so 0 is the true answer, not a stub. EXACT
         * ULONG_PTR size, and the mismatch returns before returnLength is
         * touched (Wine dlls/ntdll/unix/process.c). Consumer: kernelbase's
         * IsWow64Process. Pinned by sem_ps/process_query. */
        if (length != sizeof(ULONG_PTR))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG_PTR), sizeof(ULONG_PTR));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        ULONG_PTR wowPeb = 0;
        memcpy(buffer, &wowPeb, sizeof(wowPeb));
        if (returnLength != 0)
        {
            *returnLength = sizeof(wowPeb);
        }
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessImageInformation:
    {
        /* The main image's SECTION_IMAGE_INFORMATION, retained at creation
         * (EPROCESS.imageInformation — the PS_ATTRIBUTE_IMAGE_INFO fill's
         * twin). EXACT size, returnLength = sizeof either way (Wine
         * dlls/ntdll/unix/process.c ProcessImageInformation). ntdll's
         * build_main_module reads it at every process start and terminates
         * on IMAGE_FILE_DLL — an unserved query hands it stack garbage.
         * Pinned by sem_ps/process_query. */
        if (length != sizeof(SECTION_IMAGE_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(SECTION_IMAGE_INFORMATION);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(SECTION_IMAGE_INFORMATION), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        memcpy(buffer, &process->imageInformation, sizeof(SECTION_IMAGE_INFORMATION));
        if (returnLength != 0)
        {
            *returnLength = sizeof(SECTION_IMAGE_INFORMATION);
        }
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessCookie:
    {
        /* Own process only, size exactly ULONG (Wine
         * dlls/ntdll/unix/process.c ProcessCookie). ntdll's
         * get_process_cookie ignores this call's status, so failing it
         * hands RtlEncodePointer an uninitialized obfuscator and every
         * encoded pointer (vectored handlers first) goes wild — pinned by
         * sem_ps/process_query. */
        if (processHandle != NtCurrentProcess())
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (length != sizeof(ULONG))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(ULONG);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        memcpy(buffer, &process->cookie, sizeof(ULONG));
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG);
        }
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }

    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}

/* --- ProcessWineMakeProcessSystem (CUI-3) ---------------------------------- */

/* The one global shutdown event (wineserver's shutdown_event,
 * server/process.c make_process_system): manual-reset, created on first
 * use, signalled when the last COUNTED user process exits. Every
 * make-process-system caller gets a fresh SYNCHRONIZE handle to it. */
static PKEVENT PspShutdownEventBody;
static LONG PspLiveUserProcessCount;

void PspNoteUserProcessBirth(void)
{
    PspLiveUserProcessCount++;
}

/* A counted process stops counting exactly once: at its exit, or earlier
 * when ProcessWineMakeProcessSystem marks it system. */
static void PspNoteUserProcessGone(void)
{
    ASSERT(PspLiveUserProcessCount > 0);
    if (--PspLiveUserProcessCount == 0 && PspShutdownEventBody != 0)
    {
        KeSetEvent(PspShutdownEventBody, 0, FALSE);
    }
}

void PspShutdownNoteProcessExit(PEPROCESS process)
{
    if (process == PsInitialSystemProcess || process->isSystemProcess || process->shutdownAccounted)
    {
        return; /* system processes never counted (or already un-counted) */
    }
    process->shutdownAccounted = TRUE;
    PspNoteUserProcessGone();
}

static NTSTATUS PspMakeProcessSystem(HANDLE processHandle, PVOID buffer, ULONG length)
{
    /* Size gate first (wine/dlls/ntdll/unix/process.c; pinned
     * sem_ps/make_system.c). The out-value is one HANDLE. */
    if (length != sizeof(HANDLE *))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS status = KiProbeForWrite(buffer, sizeof(HANDLE), sizeof(HANDLE));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (PspShutdownEventBody == 0)
    {
        PVOID body;
        status = ObpAllocateObject(&ObpEventType, sizeof(KEVENT), &body);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        KeInitializeEvent(body, NotificationEvent, FALSE);
        PspShutdownEventBody = body; /* keeps the creator reference forever */
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = KeGetCurrentThread()->process;
    }
    else
    {
        PVOID body;
        status = ObReferenceObjectByHandle(processHandle, PROCESS_SET_INFORMATION, &PspProcessType,
                                           ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    /* Idempotent mark (wineserver: an already-system process still gets a
     * handle); the un-count happens exactly once. */
    if (!process->isSystemProcess && process != PsInitialSystemProcess)
    {
        if (!process->shutdownAccounted)
        {
            process->shutdownAccounted = TRUE;
            PspNoteUserProcessGone();
        }
        process->isSystemProcess = TRUE;
    }
    if (referenced)
    {
        ObDereferenceObject(process);
    }

    /* The kernel-internal creation path: ObpCreateHandle probes its
     * out-pointer as USER memory (the create/open choke point), but this
     * handle value lands on the kernel stack first and only its VALUE is
     * copied out through the probed caller buffer. */
    HANDLE handle;
    status = ObpCreateHandleInTable(&KeGetCurrentThread()->process->handleTable,
                                    PspShutdownEventBody, SYNCHRONIZE, 0, &handle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *(HANDLE *)buffer = handle; /* probed above */
    return STATUS_SUCCESS;
}

NTSTATUS NtSetInformationProcess(HANDLE processHandle, PROCESSINFOCLASS infoClass, PVOID buffer,
                                 ULONG length)
{
    if (infoClass == ProcessWineMakeProcessSystem)
    {
        /* services.exe's RPC_Init and every service's
         * service_run_main_thread store the returned event and wait on it —
         * the old blanket success handed them a NULL handle (the Art. 12
         * planted-bug shape this rewrite retires). */
        return PspMakeProcessSystem(processHandle, buffer, length);
    }
    /* The classes ntdll sets at startup (default hard-error mode, fault
     * policy, etc.) have no observable effect here; accept them — but by
     * NAME on serial, so a class whose effect matters cannot hide (Art. 12
     * hygiene; the pattern that caught this very class). */
    DbgPrint("ps: NtSetInformationProcess class %u accepted as a no-op\n", (unsigned)infoClass);
    return STATUS_SUCCESS;
}

/* --- system information --------------------------------------------------- */

NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS infoClass, PVOID buffer, ULONG length,
                                  PULONG returnLength)
{
    switch (infoClass)
    {
    case SystemBasicInformation:
    {
        /* SystemBasicInformation wants an EXACT length — both under- and
         * over-sized buffers are STATUS_INFO_LENGTH_MISMATCH (Wine
         * dlls/ntdll/unix/system.c: `if (size == len) ...; else ret =
         * STATUS_INFO_LENGTH_MISMATCH`). Pinned by sem_ps/process_query. */
        if (length != sizeof(SYSTEM_BASIC_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(SYSTEM_BASIC_INFORMATION);
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status =
            KiProbeForWrite(buffer, sizeof(SYSTEM_BASIC_INFORMATION), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SYSTEM_BASIC_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.PageSize = PAGE_SIZE;
        info.MmNumberOfPhysicalPages = (ULONG)MiGetTotalPageCount();
        info.NumberOfProcessors = 1; /* uniprocessor (Art. 3) */
        info.ActiveProcessorsAffinityMask = 1;
        info.LowestUserAddress = (void *)0x10000;
        info.HighestUserAddress = (void *)(KI_USER_SPACE_LIMIT - 1);
        info.AllocationGranularity = 0x10000;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }
    case SystemCpuInformation:
    {
        /* An OVERSIZED buffer is fine here (`size >= len` — Wine
         * dlls/ntdll/unix/system.c, unlike SystemBasicInformation's
         * exact-length rule); return length = sizeof. Consumer: wineboot's
         * create_hardware_registry_keys switches on ProcessorArchitecture
         * (CUI-1). Level/revision use Wine's get_cpuinfo encoding of CPUID
         * leaf 1 eax: level = family, revision = extended-model/model/
         * stepping nibbles. FeatureBits stay 0 until a boundary test pins
         * them. Pinned by sem_ps/cpu_info. */
        if (length < sizeof(SYSTEM_CPU_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(SYSTEM_CPU_INFORMATION);
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(SYSTEM_CPU_INFORMATION), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SYSTEM_CPU_INFORMATION info;
        memset(&info, 0, sizeof(info));
        uint32_t regs[4];
        KiCpuid(1, 0, regs);
        info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        info.ProcessorLevel = (USHORT)(((regs[0] >> 8) & 0xf) + ((regs[0] >> 20) & 0xff));
        info.ProcessorRevision = (USHORT)((((regs[0] >> 16) & 0xf) << 12) |
                                          (((regs[0] >> 4) & 0xf) << 8) | (regs[0] & 0xf));
        info.MaximumProcessors = 1; /* uniprocessor (Art. 3) */
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }
    case SystemTimeOfDayInformation:
    {
        /* A PARTIAL buffer is served here — `if (size <= sizeof(sti)) copy
         * size bytes` (Wine dlls/ntdll/unix/system.c); an oversized one is
         * the mismatch. TimeZoneBias must equal the shared page's (the
         * ntdll:time pin): proskrnl is UTC-only (docs/03 no-RTC rule), both
         * are zero. BootTime is the fixed base date — the instant uptime
         * started counting. */
        SYSTEM_TIMEOFDAY_INFORMATION info;
        if (length > sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, length, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        info.SystemTime = now;
        info.BootTime.QuadPart = now.QuadPart - (LONGLONG)KeQueryInterruptTime();
        info.TimeZoneBias.QuadPart = 0; /* UTC, as the shared page */
        memcpy(buffer, &info, length);
        if (returnLength != 0)
        {
            *returnLength = length;
        }
        return STATUS_SUCCESS;
    }
    case SystemCurrentTimeZoneInformation:
    case SystemDynamicTimeZoneInformation:
    {
        /* The fixed UTC zone in the pinned Wine's own shape: MUI indirect
         * names from the tree's tzres (dlls/tzres/tzres.rc: 22000 standard /
         * 22001 daylight for the UTC zone), key name "UTC", no DST rules,
         * zero bias. Class 44 answers the RTL_TIME_ZONE_INFORMATION prefix,
         * class 102 the full dynamic struct — `size >= len` accepted, as
         * Wine's handlers do (dlls/ntdll/unix/system.c). Consumer:
         * ntdll:time RtlQueryTimeZoneInformation tests. */
        static const char *standardName = "@tzres.dll,-22000";
        static const char *daylightName = "@tzres.dll,-22001";
        static const char *keyName = "UTC";
        RTL_DYNAMIC_TIME_ZONE_INFORMATION zone;
        memset(&zone, 0, sizeof(zone));
        for (int i = 0; standardName[i] != '\0'; i++)
        {
            zone.StandardName[i] = (WCHAR)(unsigned char)standardName[i];
        }
        for (int i = 0; daylightName[i] != '\0'; i++)
        {
            zone.DaylightName[i] = (WCHAR)(unsigned char)daylightName[i];
        }
        for (int i = 0; keyName[i] != '\0'; i++)
        {
            zone.TimeZoneKeyName[i] = (WCHAR)(unsigned char)keyName[i];
        }
        ULONG needed = infoClass == SystemDynamicTimeZoneInformation
                           ? sizeof(RTL_DYNAMIC_TIME_ZONE_INFORMATION)
                           : sizeof(RTL_TIME_ZONE_INFORMATION);
        if (length < needed)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, needed, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, &zone, needed);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }
    case SystemPerformanceInformation:
    {
        /* An OVERSIZED buffer is fine here (unlike SystemBasicInformation):
         * `if (size >= len) memcpy else STATUS_INFO_LENGTH_MISMATCH`, return
         * length = sizeof (Wine dlls/ntdll/unix/system.c) — the heap test
         * passes sizeof+16 "for some Win 7 versions". Consumer: kernelbase
         * GlobalMemoryStatusEx (dlls/kernelbase/memory.c) multiplies these
         * page counts into MEMORYSTATUSEX, pinned by kernel32:heap
         * test_GlobalMemoryStatus. With no pagefile and no eviction (Art. 3)
         * the commit limit IS physical memory and committed = total - free. */
        if (length < sizeof(SYSTEM_PERFORMANCE_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(SYSTEM_PERFORMANCE_INFORMATION);
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status =
            KiProbeForWrite(buffer, sizeof(SYSTEM_PERFORMANCE_INFORMATION), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SYSTEM_PERFORMANCE_INFORMATION info;
        memset(&info, 0, sizeof(info));
        uint64_t total = MiGetTotalPageCount();
        uint64_t free = MiGetFreePageCount();
        info.AvailablePages = (ULONG)free;
        info.TotalCommittedPages = (ULONG)(total - free);
        info.TotalCommitLimit = (ULONG)total;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }
    case SystemInterruptInformation:
    {
        /* The RtlGenRandom entropy source (CUI-3): cryptbase's
         * SystemFunction036 fills its pool from this class, and rpcrt4's
         * UuidCreate feeds the SCM's RPC context handles from it WITHOUT
         * checking for failure — refusing the class hands out repeating
         * stack garbage as "UUIDs" and the client's GUID-keyed context
         * cache collides (pinned sem_ps/entropy.c). Contract from
         * wine/dlls/ntdll/unix/system.c: ncpus records, size >= len
         * required, content is random (the oracle reads /dev/urandom;
         * here a TSC-seeded splitmix64 — uniqueness is the contract,
         * docs/03: not a cryptographic source). */
        ULONG len = sizeof(SYSTEM_INTERRUPT_INFORMATION); /* uniprocessor (Art. 3) */
        if (returnLength != 0 &&
            NT_SUCCESS(KiProbeForWrite(returnLength, sizeof(ULONG), sizeof(ULONG))))
        {
            *returnLength = len;
        }
        if (length < len)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, len, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* splitmix64 (Steele/Lea/Flood via Vigna, prng.di.unimi.it/splitmix64.c
         * — the mixing constants are the algorithm's own), stirred with the
         * TSC so state can never repeat across calls. */
        static uint64_t PspEntropyState;
        if (PspEntropyState == 0)
        {
            PspEntropyState = __builtin_ia32_rdtsc() | 1;
        }
        unsigned char out[sizeof(SYSTEM_INTERRUPT_INFORMATION)];
        for (ULONG offset = 0; offset < len; offset += sizeof(uint64_t))
        {
            PspEntropyState += 0x9E3779B97F4A7C15ULL + (__builtin_ia32_rdtsc() << 1);
            uint64_t z = PspEntropyState;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            z ^= z >> 31;
            ULONG chunk = len - offset < sizeof(z) ? len - offset : sizeof(z);
            memcpy(out + offset, &z, chunk);
        }
        memcpy(buffer, out, len);
        return STATUS_SUCCESS;
    }
    default:
        /* version_init tolerates a failure here (docs/03). */
        return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS infoClass, PVOID query,
                                    ULONG queryLength, PVOID buffer, ULONG length,
                                    PULONG returnLength)
{
    switch (infoClass)
    {
    case SystemSupportedProcessorArchitectures:
    {
        /* The query blob is the target process HANDLE (Wine
         * dlls/ntdll/unix/system.c): absent/short is STATUS_INVALID_PARAMETER
         * before returnLength is touched; a NULL handle is allowed (no
         * per-process machine then). proskrnl is 64-bit-only x86-64, so the
         * answer is one native entry plus the all-zero terminator whatever
         * the process — but an invalid real handle is still an error, as on
         * the oracle. Consumer: wineboot (a failure zeroes machines[0] and
         * its rundll32 DefaultInstall pass never runs — CUI-1). Pinned by
         * sem_ps/supported_machines. */
        if (query == 0 || queryLength < sizeof(HANDLE))
        {
            return STATUS_INVALID_PARAMETER;
        }
        HANDLE processHandle;
        NTSTATUS status = KiCopyFromUser(&processHandle, query, sizeof(processHandle));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (processHandle != 0 && processHandle != NtCurrentProcess())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_LIMITED_INFORMATION,
                                               &PspProcessType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            ObDereferenceObject(body);
        }
        SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION machines[2];
        ULONG needed = sizeof(machines);
        if (length < needed)
        {
            /* returnLength still reports the needed size (the oracle's
             * epilogue writes it unconditionally). */
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_BUFFER_TOO_SMALL;
        }
        status = KiProbeForWrite(buffer, needed, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(machines, 0, sizeof(machines));
        machines[0].Machine = IMAGE_FILE_MACHINE_AMD64;
        machines[0].KernelMode = 1;
        machines[0].UserMode = 1;
        machines[0].Native = 1;
        /* Wine sets Process when the target's machine matches; every real
         * process here is native AMD64, only the NULL handle has none. */
        machines[0].Process = processHandle != 0;
        memcpy(buffer, machines, needed);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS NtQueryDefaultLocale(BOOLEAN userProfile, LCID *lcid)
{
    (void)userProfile;
    NTSTATUS status = KiProbeForWrite(lcid, sizeof(ULONG), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG enUs = 0x0409; /* LOCALE_USER_DEFAULT en-US */
    memcpy(lcid, &enUs, sizeof(enUs));
    return STATUS_SUCCESS;
}

NTSTATUS NtQuerySystemTime(PLARGE_INTEGER time)
{
    NTSTATUS status = KiProbeForWrite(time, sizeof(LARGE_INTEGER), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* The same clock the shared page's SystemTime mirrors (kernel/ke/timer.c:
     * fixed base date + uptime, docs/03 no-RTC rule); Wine's implementation is
     * dlls/ntdll/unix/sync.c NtQuerySystemTime (wall clock there). */
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    memcpy(time, &now, sizeof(now));
    return STATUS_SUCCESS;
}

/* Wine's fixed resolution triple (dlls/ntdll/unix/sync.c
 * NtQueryTimerResolution: max = current = 10000, min = 156250 — 100 ns
 * units, i.e. 1 ms current against a 15.625 ms floor). A NULL argument is
 * STATUS_ACCESS_VIOLATION through the probes — the oracle faults on the
 * unix-side write and reports the same; ntdll:time pins all of it. */
NTSTATUS NtQueryTimerResolution(PULONG minimumResolution, PULONG maximumResolution,
                                PULONG currentResolution)
{
    NTSTATUS status = KiProbeForWrite(minimumResolution, sizeof(ULONG), sizeof(ULONG));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(maximumResolution, sizeof(ULONG), sizeof(ULONG));
    }
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(currentResolution, sizeof(ULONG), sizeof(ULONG));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG minimum = 156250;
    ULONG maximum = 10000;
    ULONG current = 10000;
    memcpy(minimumResolution, &minimum, sizeof(minimum));
    memcpy(maximumResolution, &maximum, sizeof(maximum));
    memcpy(currentResolution, &current, sizeof(current));
    return STATUS_SUCCESS;
}

/* The Wine shape (dlls/ntdll/unix/sync.c NtSetTimerResolution): the current
 * resolution is always reported as 10000, nothing actually changes, and a
 * per-process latch answers STATUS_TIMER_RESOLUTION_NOT_SET for a rescind
 * with no prior request. Wine's latch is its process-local static; here it
 * lives on the EPROCESS. */
NTSTATUS NtSetTimerResolution(ULONG requestedResolution, BOOLEAN set, PULONG currentResolution)
{
    (void)requestedResolution;
    NTSTATUS status = KiProbeForWrite(currentResolution, sizeof(ULONG), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG current = 10000;
    memcpy(currentResolution, &current, sizeof(current));

    PEPROCESS process = KeGetCurrentThread()->process;
    if (!process->timerResolutionRequested && !set)
    {
        return STATUS_TIMER_RESOLUTION_NOT_SET;
    }
    process->timerResolutionRequested = set;
    return STATUS_SUCCESS;
}

/* No auxiliary counter exists — probe the two required pointers (a NULL is
 * STATUS_ACCESS_VIOLATION, as the oracle's unix-side write would fault) and
 * refuse without writing anything (Wine answers STATUS_NOT_SUPPORTED and
 * leaves the buffers untouched; ntdll:time pins both). */
NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(ULONG direction, ULONGLONG *value,
                                                               ULONGLONG *converted,
                                                               ULONGLONG *error)
{
    (void)direction;
    (void)error;
    NTSTATUS status = KiProbeForWrite(value, sizeof(ULONGLONG), sizeof(ULONGLONG));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(converted, sizeof(ULONGLONG), sizeof(ULONGLONG));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER counter, PLARGE_INTEGER frequency)
{
    NTSTATUS status = KiProbeForWrite(counter, sizeof(LARGE_INTEGER), sizeof(uint64_t));
    if (NT_SUCCESS(status) && frequency != 0)
    {
        status = KiProbeForWrite(frequency, sizeof(LARGE_INTEGER), sizeof(uint64_t));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER now;
    now.QuadPart = (LONGLONG)KeQueryInterruptTime(); /* 100 ns units */
    memcpy(counter, &now, sizeof(now));
    if (frequency != 0)
    {
        LARGE_INTEGER freq;
        freq.QuadPart = 10000000; /* ticks per second for a 100 ns counter */
        memcpy(frequency, &freq, sizeof(freq));
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtPowerInformation(POWER_INFORMATION_LEVEL level, PVOID input, ULONG inputLength,
                            PVOID output, ULONG outputLength)
{
    (void)input;
    (void)inputLength;
    switch (level)
    {
    case ProcessorInformation:
    {
        /* wineboot's ~MHz registry source (create_hardware_registry_keys;
         * it tolerates failure by memsetting zeros). Contract from Wine
         * dlls/ntdll/unix/system.c ProcessorInformation: NULL/0 output is
         * INVALID_PARAMETER, under one record per CPU is BUFFER_TOO_SMALL,
         * else one PROCESSOR_POWER_INFORMATION per CPU — one, uniprocessor
         * (Art. 3). MHz: CPUID leaf 0x16 (Intel SDM vol. 2A "CPUID",
         * Processor Frequency Information: EAX = base MHz, 0 when
         * unsupported — TCG qemu64 tops out below it), else 1000 — the
         * oracle's own no-cpufreq fallback (`cannedMHz`), a pinned shape,
         * not a guess. Pinned by sem_ps/process_query. */
        if (output == 0 || outputLength == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (outputLength / sizeof(PROCESSOR_POWER_INFORMATION) < 1)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        NTSTATUS status =
            KiProbeForWrite(output, sizeof(PROCESSOR_POWER_INFORMATION), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        uint32_t regs[4];
        KiCpuid(0, 0, regs);
        ULONG mhz = 0;
        if (regs[0] >= 0x16)
        {
            KiCpuid(0x16, 0, regs);
            mhz = regs[0];
        }
        if (mhz == 0)
        {
            mhz = 1000;
        }
        PROCESSOR_POWER_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.MaxMhz = mhz;
        info.CurrentMhz = mhz;
        info.MhzLimit = mhz;
        memcpy(output, &info, sizeof(info));
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED; /* other levels: unbuilt, loud (Art. 12) */
    }
}

/* --- scheduling ----------------------------------------------------------- */

NTSTATUS NtDelayExecution(BOOLEAN alertable, const LARGE_INTEGER *interval)
{
    LARGE_INTEGER captured;
    NTSTATUS status = KiProbeForRead(interval, sizeof(LARGE_INTEGER), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(&captured, interval, sizeof(captured));
    return KeDelayExecutionThread(UserMode, alertable, &captured);
}

NTSTATUS NtYieldExecution(void)
{
    KiYield();
    return STATUS_SUCCESS;
}

NTSTATUS NtFlushInstructionCache(HANDLE process, LPCVOID base, SIZE_T length)
{
    /* Uniprocessor, coherent I-cache after our own writes — a no-op, as on
     * x86 generally (the instruction stream is snooped). */
    (void)process;
    (void)base;
    (void)length;
    return STATUS_SUCCESS;
}

/* --- NLS (the data files ntdll's locale_init maps at startup) ------------- */

/* Map one \??\C:\windows\system32 NLS data file read-only into the CURRENT
 * process (both services below run on the caller's thread). Mirrors Wine's
 * unix-side implementations, which open the file and map a PAGE_READONLY
 * SEC_COMMIT section over it (third_party/wine dlls/ntdll/unix/env.c
 * NtGetNlsSectionPtr / NtInitializeNlsFiles). */
static NTSTATUS PspMapNlsFile(const WCHAR *fileName, uint64_t *baseOut, uint64_t *sizeOut)
{
    WCHAR path[64];
    static const WCHAR prefix[] = WSTR("\\??\\C:\\windows\\system32\\");
    size_t n = 0;
    while (prefix[n] != 0)
    {
        path[n] = prefix[n];
        n++;
    }
    for (size_t i = 0; fileName[i] != 0; i++)
    {
        ASSERT(n + 1 < sizeof(path) / sizeof(path[0]));
        path[n++] = fileName[i];
    }
    path[n] = 0;

    PMI_SECTION section;
    NTSTATUS status = IoOpenDataSection(path, &section);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEPROCESS process = KeGetCurrentThread()->process;
    uint64_t base = 0;
    uint64_t viewSize = 0;
    status =
        MiMapViewOfSection(section, &process->addressSpace, &base, 0, &viewSize, PAGE_READONLY);
    ObDereferenceObject(section); /* the view holds its own pin */
    if (NT_SUCCESS(status))
    {
        *baseOut = base;
        *sizeOut = viewSize;
    }
    return status;
}

NTSTATUS NtInitializeNlsFiles(void **baseAddress, LCID *lcid, LARGE_INTEGER *size)
{
    NTSTATUS status = KiProbeForWrite(baseAddress, sizeof(*baseAddress), sizeof(void *));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(lcid, sizeof(*lcid), sizeof(LCID));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t base = 0;
    uint64_t viewSize = 0;
    status = PspMapNlsFile(WSTR("locale.nls"), &base, &viewSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *baseAddress = (void *)(uintptr_t)base;
    /* The system locale: en-US, the fallback Wine's unix side reports when no
     * host locale configures one (dlls/ntdll/unix/env.c init_locale:
     * MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT)). The size argument is left
     * untouched — Wine's implementation never writes it (sem_ps/nls_files
     * pins this; locale_init passes a throwaway named `unused`). */
    *lcid = 0x0409;
    (void)size;
    return STATUS_SUCCESS;
}

NTSTATUS NtGetNlsSectionPtr(ULONG type, ULONG codePage, PVOID contextData, PVOID *sectionPointer,
                            PSIZE_T sectionSize)
{
    (void)contextData;
    NTSTATUS status = KiProbeForWrite(sectionPointer, sizeof(*sectionPointer), sizeof(void *));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sectionSize, sizeof(*sectionSize), sizeof(SIZE_T));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* File names per type follow Wine's unix get_nls_file_path (dlls/ntdll/
     * unix/env.c): l_intl.nls for the case table, c_%03u.nls per codepage,
     * sortdefault.nls for the sortkey table kernelbase parses at attach,
     * norm*.nls per normalization form. */
    WCHAR name[32];
    switch (type)
    {
    case NLS_SECTION_SORTKEYS:
        if (codePage != 0)
        {
            return STATUS_INVALID_PARAMETER_1;
        }
        {
            static const WCHAR sortName[] = WSTR("sortdefault.nls");
            memcpy(name, sortName, sizeof(sortName));
        }
        break;
    case NLS_SECTION_CASEMAP:
        if (codePage != 0)
        {
            return STATUS_UNSUCCESSFUL;
        }
        {
            static const WCHAR intl[] = WSTR("l_intl.nls");
            memcpy(name, intl, sizeof(intl));
        }
        break;
    case NLS_SECTION_CODEPAGE:
    {
        static const WCHAR digits[] = WSTR("0123456789");
        WCHAR *p = name;
        *p++ = 'c';
        *p++ = '_';
        WCHAR buffer[10];
        int i = 0;
        ULONG value = codePage;
        do
        {
            buffer[i++] = digits[value % 10];
            value /= 10;
        } while (value != 0);
        while (i < 3)
        {
            buffer[i++] = '0'; /* c_%03u */
        }
        while (i > 0)
        {
            *p++ = buffer[--i];
        }
        static const WCHAR suffix[] = WSTR(".nls");
        memcpy(p, suffix, sizeof(suffix));
        break;
    }
    case NLS_SECTION_NORMALIZE:
        /* Normalization form -> file, per Wine's get_nls_file_path (the
         * NORM_FORM values are generated into abi/ntpsapi.h; 13 is the IDNA
         * table id Wine hard-codes the same way). An unknown form has no
         * file: STATUS_OBJECT_NAME_NOT_FOUND, matching the oracle. */
        switch (codePage)
        {
        case NormalizationC:
        {
            static const WCHAR n[] = WSTR("normnfc.nls");
            memcpy(name, n, sizeof(n));
            break;
        }
        case NormalizationD:
        {
            static const WCHAR n[] = WSTR("normnfd.nls");
            memcpy(name, n, sizeof(n));
            break;
        }
        case NormalizationKC:
        {
            static const WCHAR n[] = WSTR("normnfkc.nls");
            memcpy(name, n, sizeof(n));
            break;
        }
        case NormalizationKD:
        {
            static const WCHAR n[] = WSTR("normnfkd.nls");
            memcpy(name, n, sizeof(n));
            break;
        }
        case 13:
        {
            static const WCHAR n[] = WSTR("normidna.nls");
            memcpy(name, n, sizeof(n));
            break;
        }
        default:
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    default:
        /* Wine's get_nls_section_name: an unrecognized type is parameter
         * validation, not a lookup miss. */
        return STATUS_INVALID_PARAMETER_1;
    }

    uint64_t base = 0;
    uint64_t viewSize = 0;
    status = PspMapNlsFile(name, &base, &viewSize);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *sectionPointer = (void *)(uintptr_t)base;
    *sectionSize = viewSize;
    return STATUS_SUCCESS;
}

/* NtQueryVolumeInformationFile moved to kernel/io/query.c (M10: the answer
 * is per-device now — DeviceType feeds GetFileType). */

/* --- KiUserCallbackDispatcher return (unreachable for a CUI process) ------ */

NTSTATUS NtCallbackReturn(PVOID result, ULONG resultLength, NTSTATUS status)
{
    (void)result;
    (void)resultLength;
    (void)status;
    /* Kernel callbacks (win32k) are not on the CUI path (docs/03 M7 map);
     * PEB->KernelCallbackTable is null, so this is never reached. */
    return STATUS_UNSUCCESSFUL;
}
