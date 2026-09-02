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
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/mm/virtual.h"
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "kernel/se/se.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/power.h"
#include "arch/x86_64/cpu.h"

#include "abi/ntkeapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntimage.h"
#include "abi/ntpebteb.h"
#include "abi/ntioapi.h"
#include "abi/ntregapi.h"

/* End of the kernel image, past .bss (arch/x86_64/linker.ld). A linker symbol
 * is a module global, so it is declared at file scope: the same declaration
 * inside a function would read as a local and take a local's casing. */
extern char KiImageEnd[];

/* The machine's feature array, which lives on the shared page and is filled
 * once by PspInitializeSharedUserData. Every capability answer this file
 * gives is that array restated — never a second read of CPUID (Art. 11):
 * two derivations of one fact drift even while they currently agree. */
static const BOOLEAN *PspProcessorFeatures(void)
{
    ASSERT(KiUserSharedData != 0);
    return ((const KUSER_SHARED_DATA *)KiUserSharedData)->ProcessorFeatures;
}

/* --- process information -------------------------------------------------- */

/* A process's accumulated kernel/user time: the exited threads' totals plus
 * every live thread's counters. ONE derivation (Art. 11) — ProcessTimes and
 * SystemProcessInformation's per-entry times both report this, and two
 * summation loops would drift the moment either grew a term. The dispatcher
 * lock must be HELD: it is what makes a thread mid-exit counted exactly once,
 * and the two callers hold it over different spans. */
static void PspSumProcessTimes(PEPROCESS process, uint64_t *kernel100nsOut, uint64_t *user100nsOut)
{
    ASSERT(KiIsDispatcherLockHeld());
    uint64_t kernel100ns = process->exitedKernelTime100ns;
    uint64_t user100ns = process->exitedUserTime100ns;
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        PKTHREAD tcb = CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb;
        kernel100ns += tcb->kernelTime100ns;
        user100ns += tcb->userTime100ns;
    }
    *kernel100nsOut = kernel100ns;
    *user100nsOut = user100ns;
}

/* A process's VM_COUNTERS_EX, likewise once (Art. 11): ProcessVmCounters and
 * SystemProcessInformation's per-entry copy are the same seven fields over
 * the same two quantities. With no paging and no COW (Art. 3) every
 * committed page is resident, so committed IS the working set and the
 * pagefile usage, and reserved is VirtualSize. */
static void PspFillVmCounters(PEPROCESS process, VM_COUNTERS_EX *info)
{
    uint64_t reserved = 0;
    uint64_t committed = 0;
    MiQueryVmCounters(&process->addressSpace, &reserved, &committed);
    memset(info, 0, sizeof(*info));
    info->PeakVirtualSize = reserved;
    info->VirtualSize = reserved;
    info->PeakWorkingSetSize = committed;
    info->WorkingSetSize = committed;
    info->PagefileUsage = committed;
    info->PeakPagefileUsage = committed;
    info->PrivateUsage = committed;
}

NTSTATUS NtQueryInformationProcess(HANDLE processHandle, PROCESSINFOCLASS infoClass, PVOID buffer,
                                   ULONG length, PULONG returnLength)
{
    NTSTATUS probeStatus = PspProbeReturnLength(returnLength);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    PKTHREAD thread = KeGetCurrentThread();
    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = thread->process;
    }
    else
    {
        /* NT splits process queries across TWO rights: the "limited" classes
         * (identity and other harmless facts) are readable through
         * PROCESS_QUERY_LIMITED_INFORMATION, and everything
         * PROCESS_QUERY_INFORMATION covers is readable too — the full right is
         * a superset in NT's rules, but a distinct BIT, so a handle carrying
         * only one of them must still satisfy the check. Ob's mask test wants
         * every requested bit, so try the limited right and fall back.
         * ProcessIdToSessionId is the consumer that forces this: it opens
         * other processes with PROCESS_QUERY_LIMITED_INFORMATION alone
         * (dlls/kernelbase/process.c), and refusing it made tasklist drop
         * every row but its own. */
        PVOID body;
        KPROCESSOR_MODE mode = ExGetPreviousMode();
        NTSTATUS status = ObReferenceObjectByHandle(
            processHandle, PROCESS_QUERY_LIMITED_INFORMATION, &PspProcessType, mode, &body, 0);
        if (status == STATUS_ACCESS_DENIED)
        {
            status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_INFORMATION,
                                               &PspProcessType, mode, &body, 0);
        }
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
        /* The creator's pid — the same EPROCESS field SystemProcessInformation
         * reports as ParentProcessId (one authority; 0 for an unparented
         * process, which is also the oracle's answer for a session root).
         * Left zero, every consumer that finds a process's parent by pid dies
         * silently — wineserver-lite's connect-time desktop inheritance
         * matched nothing and every GUI-6 child self-created its desktop.
         * Pinned by sem_ps/system_processes (suspended-child check). */
        info.InheritedFromUniqueProcessId = process->parentProcessId;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        status = (length > sizeof(PROCESS_BASIC_INFORMATION)) ? STATUS_INFO_LENGTH_MISMATCH
                                                              : STATUS_SUCCESS;
        break;
    }
    case ProcessIoCounters:
    {
        /* The process's own I/O tally (EPROCESS.ioCounters, charged by
         * PsChargeIoCounters). Length protocol from the oracle
         * (dlls/ntdll/unix/process.c ProcessIoCounters): a buffer SHORTER
         * than IO_COUNTERS is refused with STATUS_INFO_LENGTH_MISMATCH, an
         * exact one succeeds, and a LONGER one is filled but still answers
         * STATUS_INFO_LENGTH_MISMATCH; returnLength is sizeof(IO_COUNTERS)
         * in every case. What the counters CONTAIN is beyond that oracle —
         * the pinned Wine memsets them to zero behind a "FIXME: real data"
         * — so the values follow the contract Microsoft documents for
         * IO_COUNTERS / GetProcessIoCounters instead: the read, write and
         * other operations the process has performed, and their bytes.
         * Pinned by sem_file/io_counters.c (its beyond_oracle block carries
         * the citation). taskmgr.exe is the consumer: perfdata.c calls
         * GetProcessIoCounters for every process it lists, and an unbuilt
         * class there took the whole applet down. */
        if (length < sizeof(IO_COUNTERS))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(IO_COUNTERS);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        /* Alignment 1, not 8: the WOW64 thunk forwards the caller's own
         * pointer untranslated for this class — the switch arm is a bare
         * `return NtQueryInformationProcess( handle, class, ptr, len, retlen )`
         * under a `FIXME: check buffer alignment` (third_party/wine
         * dlls/wow64/process.c) — and an i386 caller's stack struct is
         * 4-aligned. The fill below stages in a local and copies out as
         * bytes, so refusing here would be the divergence
         * sem_ps/misaligned_out.c already pinned for the time queries.
         */
        status = KiProbeForWrite(buffer, sizeof(IO_COUNTERS), 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        IO_COUNTERS counters = process->ioCounters;
        memcpy(buffer, &counters, sizeof(counters));
        if (returnLength != 0)
        {
            *returnLength = sizeof(counters);
        }
        status = (length > sizeof(IO_COUNTERS)) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
        break;
    }
    case ProcessTimes:
    {
        /* CUI-6 (sem_ps/times): exact-length protocol as
         * ProcessBasicInformation above; the answer is the EPROCESS wall
         * stamps plus exited totals plus every live thread's tick counters,
         * summed under the dispatcher lock so a thread mid-exit is counted
         * exactly once. */
        if (length < sizeof(KERNEL_USER_TIMES))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(KERNEL_USER_TIMES);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        /* Alignment 1, for the reason ProcessIoCounters' probe gives. */
        status = KiProbeForWrite(buffer, sizeof(KERNEL_USER_TIMES), 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        KERNEL_USER_TIMES times;
        memset(&times, 0, sizeof(times));
        uint64_t kernel100ns = 0;
        uint64_t user100ns = 0;
        uint64_t flags = KiAcquireDispatcherLock();
        times.CreateTime = process->createTime;
        times.ExitTime = process->exitTime;
        PspSumProcessTimes(process, &kernel100ns, &user100ns);
        KiReleaseDispatcherLock(flags);
        times.KernelTime.QuadPart = (LONGLONG)kernel100ns;
        times.UserTime.QuadPart = (LONGLONG)user100ns;
        memcpy(buffer, &times, sizeof(times));
        if (returnLength != 0)
        {
            *returnLength = sizeof(times);
        }
        status =
            (length > sizeof(KERNEL_USER_TIMES)) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
        break;
    }
    case ProcessPriorityClass:
    {
        /* CUI-6 (sem_ps/proc_classes): the 2-byte struct, size EXACT
         * (dlls/ntdll/unix/process.c); Foreground is always FALSE (the
         * oracle's own "not yet supported"). */
        if (length != sizeof(PROCESS_PRIORITY_CLASS))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(PROCESS_PRIORITY_CLASS), 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        PROCESS_PRIORITY_CLASS info;
        memset(&info, 0, sizeof(info));
        info.Foreground = FALSE;
        info.PriorityClass = process->priorityClass;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessHandleCount:
    {
        /* CUI-6 (sem_ps/proc_classes): the oracle's odd protocol verbatim —
         * size >= 4 writes the ULONG, size > 4 ALSO refuses, size < 4
         * refuses with length 4. The value is the real in-use handle count
         * (beyond_oracle: the oracle fabricates 0 under its own FIXME). */
        if (length < sizeof(ULONG))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(ULONG);
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG), 1);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        ULONG count = process->handleTable.inUse;
        memcpy(buffer, &count, sizeof(count));
        if (returnLength != 0)
        {
            *returnLength = sizeof(count);
        }
        status = (length > sizeof(ULONG)) ? STATUS_INFO_LENGTH_MISMATCH : STATUS_SUCCESS;
        break;
    }
    case ProcessImageFileName:
    case ProcessImageFileNameWin32:
    {
        /* CUI-6 (sem_ps/proc_classes): UNICODE_STRING + embedded
         * NUL-terminated buffer, NT (\??\) form; min-size refusal reports
         * header + name (dlls/ntdll/unix/process.c). Boot/flat processes
         * with no NT path answer an empty string. AUD-2: the Win32 class
         * shares the fill and drops exactly the NT prefix, the pinned
         * server's shape (server/process.c get_process_image_name skips a
         * leading \??\ for req->win32; consumed by mmdevapi's
         * audio-session machinery). */
        ULONG skipBytes = 0;
        if (infoClass == ProcessImageFileNameWin32)
        {
            static const WCHAR ntPrefix[] = {'\\', '?', '?', '\\'};
            if (process->imageNtPath.Length >= sizeof(ntPrefix) &&
                memcmp(process->imageNtPath.Buffer, ntPrefix, sizeof(ntPrefix)) == 0)
            {
                skipBytes = sizeof(ntPrefix);
            }
        }
        ULONG minSize = sizeof(UNICODE_STRING) + sizeof(WCHAR);
        ULONG nameBytes = process->imageNtPath.Length - skipBytes;
        if (length < minSize + nameBytes)
        {
            if (returnLength != 0)
            {
                *returnLength = minSize + nameBytes;
            }
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, minSize + nameBytes, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        UNICODE_STRING header;
        WCHAR *userBuffer = (WCHAR *)((UNICODE_STRING *)buffer + 1);
        header.Length = (USHORT)nameBytes;
        header.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        header.Buffer = userBuffer;
        memcpy(buffer, &header, sizeof(header));
        if (nameBytes != 0)
        {
            memcpy(userBuffer, (const char *)process->imageNtPath.Buffer + skipBytes, nameBytes);
        }
        WCHAR nul = 0;
        memcpy(userBuffer + nameBytes / sizeof(WCHAR), &nul, sizeof(nul));
        if (returnLength != 0)
        {
            *returnLength = minSize + nameBytes;
        }
        status = STATUS_SUCCESS;
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
        VM_COUNTERS_EX info;
        PspFillVmCounters(process, &info);
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
        /* The target's PEB32, or 0 for a 64-bit process — which is what
         * makes IsWow64Process answer (kernelbase), and what wow64.dll's
         * process_init reads to find the WOW64INFO behind it. EXACT
         * ULONG_PTR size, and the mismatch returns before returnLength is
         * touched (Wine dlls/ntdll/unix/process.c). Pinned by
         * sem_ps/process_query (the 64-bit arm) and sem_ps/wow64_process
         * (the PEB64 + 0x1000 arm). */
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
        ULONG_PTR wowPeb = (ULONG_PTR)process->peb32Base;
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
    case ProcessDefaultHardErrorMode:
    {
        /* The per-process error mode kernelbase's GetErrorMode reads (and
         * SetErrorMode stores through the set pair below). EXACT UINT size,
         * returnLength = sizeof either way (Wine dlls/ntdll/unix/process.c
         * ProcessDefaultHardErrorMode). Pinned by sem_ps/process_query;
         * ucrtbase's misc tests convicted the refusal under the armed
         * boot. */
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG);
        }
        if (length != sizeof(ULONG))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        memcpy(buffer, &process->hardErrorMode, sizeof(ULONG));
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessSessionInformation:
    {
        /* The session id ProcessIdToSessionId reads per row
         * (dlls/kernelbase/process.c) — tasklist hits it for every process
         * it lists (CUI-4). One interactive session (PEB.SessionId == 1,
         * kernel/ps/peb.c). EXACT ULONG size; returnLength = sizeof either
         * way (Wine dlls/ntdll/unix/process.c ProcessSessionInformation).
         * Pinned by sem_ps/system_processes. */
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG);
        }
        if (length != sizeof(ULONG))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        ULONG sessionId = 1; /* the one interactive session (peb.c) */
        memcpy(buffer, &sessionId, sizeof(sessionId));
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
    case ProcessAffinityMask:
    {
        /* One CPU, so one bit — the same fact ThreadAffinityMask reports,
         * from the same KE_NUMBER_PROCESSORS authority (Art. 11), and true
         * rather than approximate because Art. 3 mandates uniprocessor.
         * Exact length or STATUS_INFO_LENGTH_MISMATCH, as the oracle
         * (dlls/ntdll/unix/process.c). */
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
        ULONG_PTR affinity = ((ULONG_PTR)1 << KE_NUMBER_PROCESSORS) - 1;
        memcpy(buffer, &affinity, sizeof(affinity));
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG_PTR);
        }
        status = STATUS_SUCCESS;
        break;
    }
    case ProcessPriorityBoost:
    {
        /* The process twin of ThreadPriorityBoost: stored and returned,
         * because proskrnl boosts nothing but the pair must agree with
         * itself. Note the asymmetry the oracle carries and an
         * implementation written from the docs would flatten — the QUERY
         * rejects a wrong size with STATUS_INFO_LENGTH_MISMATCH and a NULL
         * buffer with STATUS_ACCESS_VIOLATION, while the SET rejects a
         * wrong size with STATUS_INVALID_PARAMETER
         * (dlls/ntdll/unix/process.c). Pinned by
         * tests/ntapi/sem_ps/process_priority_boost.c. */
        if (length != sizeof(ULONG))
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buffer == 0)
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }
        status = KiProbeForWrite(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        ULONG disableBoost = (process != 0 && process->priorityBoostDisabled) ? 1 : 0;
        memcpy(buffer, &disableBoost, sizeof(disableBoost));
        if (returnLength != 0)
        {
            *returnLength = sizeof(ULONG);
        }
        status = STATUS_SUCCESS;
        break;
    }
    default:
        /* The refusal split (Art. 12, docs/21 W1): out of the enum is
         * INVALID and implemented; inside it and unbuilt stays fatal. The
         * bound is the header's own MaxProcessInfoClass, never typed.
         * The fork's own extensions (ProcessWineMakeProcessSystem 1000,
         * ProcessWineGrantAdminToken 1002) sit ABOVE that sentinel and are
         * real classes, so they stay unbuilt-and-loud rather than invalid. */
        if (infoClass != ProcessWineMakeProcessSystem && infoClass != ProcessWineGrantAdminToken &&
            ((LONG)infoClass < 0 || (ULONG)infoClass >= (ULONG)MaxProcessInfoClass))
        {
            status = STATUS_INVALID_INFO_CLASS;
            break;
        }
        DbgPrint("NtQueryInformationProcess: unbuilt info class %d\n", (int)infoClass);
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
    KI_PROBE_TOKEN handleToken;
    NTSTATUS status = KiProbeForWriteToken(buffer, sizeof(HANDLE), sizeof(HANDLE), &handleToken);
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

    /* The kernel-internal creation path: ObpCreateHandle probes its
     * out-pointer as USER memory (the create/open choke point), but this
     * handle value lands on the kernel stack first and only its VALUE is
     * copied out through the probed caller buffer. */
    HANDLE handle;
    status = ObpCreateHandleInTable(&KeGetCurrentThread()->process->handleTable,
                                    PspShutdownEventBody, SYNCHRONIZE, 0, &handle);
    if (!NT_SUCCESS(status))
    {
        if (referenced)
        {
            ObDereferenceObject(process);
        }
        return status;
    }
    /* Through the token: "no park since the probe" was a claim a reader had
     * to re-derive over the whole body above, and docs/20 §10.2 convicted
     * exactly that claim here once (issue #96 C). */
    KiWriteUser(&handleToken, buffer, &handle, sizeof(handle));
    /* The dereference LAST (docs/20 R7): dropping a last reference runs a
     * whole process teardown, whose handle-table sweep closes files and
     * parks on the volume gate (docs/20 §10.1) — parked, a sibling can
     * unmap `buffer`, and a store after the deref would fault and unwind
     * with the system-mark, the shutdown accounting, and the minted handle
     * already permanent. After the store, there is nothing left to lose;
     * the mint above used the CURRENT process's table and never needed the
     * target reference. */
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

/* ProcessPriorityBoost's disable flag reaches a thread by being COPIED into
 * every thread the process currently has, not by being consulted at query
 * time — the oracle's server states it that way in one function
 * (third_party/wine server/process.c, set_process_disable_boost: assign
 * process->disable_boost, then set_thread_disable_boost on each thread of
 * thread_list; a new thread takes the process value at creation,
 * server/thread.c create_thread). The distinction is observable and
 * kernel32:thread checks it: after a process-wide disable, a
 * SetThreadPriorityBoost(thread, 0) must make the THREAD read 0 while the
 * PROCESS still reads 1 (thread.c:806-812). A query-time OR could not
 * produce that. */
static void PspSetProcessPriorityBoost(PEPROCESS process, BOOLEAN disable)
{
    process->priorityBoostDisabled = disable;
    for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
         entry = entry->Flink)
    {
        CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->priorityBoostDisabled = disable;
    }
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
    if (infoClass == ProcessManageWritesToExecutableMemory)
    {
        /* A CAPABILITY PROBE, and the no-op arm at the bottom of this
         * function was answering it "yes". dlls/ntdll/tests/virtual.c
         * test_exec_memory_writes sets this class and reads the status: a
         * success means "this is an ARM64EC host", so it then asserts the
         * processor architecture is ARM64 (:3339) and skips its whole body.
         * An accepted-and-dropped input turned into a wrong answer — the
         * same shape as the dropped MEM_EXTENDED_PARAMETER_EC_CODE attribute
         * (docs/21 W6).
         *
         * The pinned oracle's arm is `#ifdef __aarch64__ ... #else return
         * STATUS_NOT_SUPPORTED; #endif` (third_party/wine
         * dlls/ntdll/unix/process.c, case
         * ProcessManageWritesToExecutableMemory), so on x86_64 the refusal
         * precedes every argument check the ARM64EC path makes — length,
         * Version, the mutually-exclusive flag, and the handle — and nothing
         * captures the caller's buffer. Pinned by
         * tests/ntapi/sem_ps/manage_exec_writes.c, which measures that
         * ordering rather than only the happy case. */
        return STATUS_NOT_SUPPORTED;
    }
    if (infoClass == ProcessThreadStackAllocation)
    {
        /* THE ONE KERNEL CALL RtlCreateUserStack MAKES, and the accept-as-a-
         * no-op arm at the bottom of this function was answering it with
         * STATUS_SUCCESS over the caller's UNINITIALISED buffer
         * (third_party/wine dlls/ntdll/thread.c: `PROCESS_STACK_ALLOCATION_
         * INFORMATION alloc;` is a plain local, and only the success arm
         * writes StackBase). The caller then commits a guard page and a stack
         * at whatever was in that stack slot and reports it as the new
         * stack's DeallocationStack — so CreateFiberEx (dlls/kernelbase/
         * thread.c) ran its fibers on it. A no-op success is a fabricated
         * answer whenever the caller reads something the call was supposed to
         * WRITE, which is the sharper form of docs/21 W5's rule about a
         * caller reading the status.
         *
         * The oracle's whole arm is one MEM_RESERVE allocation
         * (dlls/ntdll/unix/process.c, case ProcessThreadStackAllocation), and
         * three things about it are not guessable from the class name — all
         * three pinned by tests/ntapi/sem_ps/thread_stack_alloc.c:
         *
         *   - THE LENGTH SELECTS THE STRUCT. sizeof(..._EX) means the _EX
         *     form and the reservation is described by its embedded
         *     AllocInfo; there is no version field and no flag.
         *   - ZeroBits IS NtAllocateVirtualMemory's, so the class inherits
         *     that syscall's bands and its STATUS_INVALID_PARAMETER_3 —
         *     stated once, in MiZeroBitsPlacementLimit (Art. 11).
         *   - THE HANDLE IS NEVER READ. The oracle allocates in
         *     GetCurrentProcess() unconditionally and never mentions its own
         *     `handle`, so the reservation is always the CALLER's and a
         *     handle that resolves to nothing is not an error. */
        ULONG allocOffset;
        if (length == sizeof(PROCESS_STACK_ALLOCATION_INFORMATION_EX))
        {
            allocOffset = (ULONG)offsetof(PROCESS_STACK_ALLOCATION_INFORMATION_EX, AllocInfo);
        }
        else if (length == sizeof(PROCESS_STACK_ALLOCATION_INFORMATION))
        {
            allocOffset = 0;
        }
        else
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        PROCESS_STACK_ALLOCATION_INFORMATION *userAlloc =
            (PROCESS_STACK_ALLOCATION_INFORMATION *)((char *)buffer + allocOffset);
        /* One probe for both directions: the request is read out of the same
         * struct the answer goes back into. Nothing between them can park —
         * and the reason is narrower than "a reserve takes no frames", so it
         * is worth naming for whoever re-checks it: `blocking_frontier.py
         * --path` finds exactly one park reachable from
         * MiAllocateVirtualMemoryEx, a section dereference inside the
         * VAD-teardown unwind, and that unwind belongs to the MEM_COMMIT
         * failure arm. Every function on the pure-reserve path reports
         * "cannot park". */
        KI_PROBE_TOKEN token;
        NTSTATUS status =
            KiProbeForWriteToken(userAlloc, sizeof(*userAlloc), sizeof(SIZE_T), &token);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PROCESS_STACK_ALLOCATION_INFORMATION alloc;
        KiReadUser(&token, &alloc, userAlloc, sizeof(alloc));

        uint64_t limitHigh = 0;
        status = MiZeroBitsPlacementLimit((uint64_t)alloc.ZeroBits, &limitHigh);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PVOID base = 0;
        SIZE_T size = alloc.ReserveSize;
        status = MiAllocateVirtualMemoryEx(&KeGetCurrentThread()->process->addressSpace, &base,
                                           &size, MEM_RESERVE, PAGE_READWRITE, 0, limitHigh, 0, 0);
        if (!NT_SUCCESS(status))
        {
            /* StackBase is written on the SUCCESS arm only. A refusal that
             * scribbled a plausible pointer would be the same defect this
             * case exists to remove, one status further along. */
            return status;
        }
        KiWriteUser(&token, &userAlloc->StackBase, &base, sizeof(base));
        return STATUS_SUCCESS;
    }
    if (infoClass == ProcessPriorityBoost)
    {
        /* Stored, so the query can see it. A wrong size is
         * STATUS_INVALID_PARAMETER on this side — not the
         * INFO_LENGTH_MISMATCH the query gives (dlls/ntdll/unix/process.c
         * states both, and they differ). */
        if (length != sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS probe = KiProbeForRead(buffer, sizeof(ULONG), sizeof(ULONG));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        ULONG disableBoost;
        memcpy(&disableBoost, buffer, sizeof(disableBoost));
        /* The pseudo-handle means the caller, as every other class in this
         * file resolves it — one idiom, one place. */
        if (processHandle == NtCurrentProcess())
        {
            PspSetProcessPriorityBoost(KeGetCurrentThread()->process, disableBoost != 0);
            return STATUS_SUCCESS;
        }
        PVOID body;
        NTSTATUS status = ObReferenceObjectByHandle(processHandle, PROCESS_SET_INFORMATION,
                                                    &PspProcessType, ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PspSetProcessPriorityBoost((PEPROCESS)body, disableBoost != 0);
        ObDereferenceObject(body);
        return STATUS_SUCCESS;
    }
    if (infoClass == ProcessDefaultHardErrorMode)
    {
        /* kernelbase SetErrorMode's store; the query pair reads it back.
         * EXACT UINT, STATUS_INVALID_PARAMETER otherwise (Wine
         * dlls/ntdll/unix/process.c). Pinned by sem_ps/process_query. */
        if (length != sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER;
        }
        ULONG mode;
        NTSTATUS status = KiCopyFromUser(&mode, buffer, sizeof(mode));
        if (!NT_SUCCESS(status))
        {
            return status;
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
            status = ObReferenceObjectByHandle(processHandle, PROCESS_SET_INFORMATION,
                                               &PspProcessType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            process = body;
            referenced = TRUE;
        }
        process->hardErrorMode = mode;
        if (referenced)
        {
            ObDereferenceObject(process);
        }
        return STATUS_SUCCESS;
    }
    /* CUI-6 (sem_ps/proc_classes): the stored priority class — an explicit
     * case BEFORE the accept-as-no-op default arm, so this class can never
     * again "succeed" silently without effect (Art. 12). Size exact, the
     * oracle's own refusal status (dlls/ntdll/unix/process.c). Store and
     * report only: one CPU, one priority band that matters (docs/03). */
    if (infoClass == ProcessPriorityClass)
    {
        if (length != sizeof(PROCESS_PRIORITY_CLASS))
        {
            return STATUS_INVALID_PARAMETER;
        }
        PROCESS_PRIORITY_CLASS info;
        NTSTATUS status = KiCopyFromUser(&info, buffer, sizeof(info));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        PEPROCESS target = KeGetCurrentThread()->process;
        BOOLEAN referenced = FALSE;
        if (processHandle != NtCurrentProcess())
        {
            PVOID body;
            status = ObReferenceObjectByHandle(processHandle, PROCESS_SET_INFORMATION,
                                               &PspProcessType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            target = body;
            referenced = TRUE;
        }
        target->priorityClass = info.PriorityClass;
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return STATUS_SUCCESS;
    }
    /* The classes ntdll sets at startup (fault policy etc.) have no
     * observable effect here; accept them — but by NAME on serial, so a
     * class whose effect matters cannot hide (Art. 12 hygiene; the pattern
     * that caught ProcessWineMakeProcessSystem and the hard-error mode
     * above). */
    DbgPrint("ps: NtSetInformationProcess class %u accepted as a no-op\n", (unsigned)infoClass);
    return STATUS_SUCCESS;
}

/* --- system information --------------------------------------------------- */

/* CUI-4: SystemProcessInformation — the chained snapshot kernel32's
 * CreateToolhelp32Snapshot walks (dlls/kernel32/toolhelp.c). The producer
 * contract is dlls/ntdll/unix/system.c get_system_process_info: per process a
 * SYSTEM_PROCESS_INFORMATION header, its SYSTEM_THREAD_INFORMATION[] array,
 * then the base-name string, all 8-aligned and NextEntryOffset-linked (0 ends
 * the chain). Pinned by sem_ps/system_processes.
 *
 * We build into a kernel scratch (the dispatcher lock is held only across the
 * two list walks, never during the user copy), computing ProcessName.Buffer
 * as the FINAL user VA so the caller's chain is self-consistent. */

/* The base name (past the last path separator) of an ASCII image path, as a
 * character count; the DOS/NT path uses '\\', flat clients may have none. */
static ULONG PspImageBaseNameChars(const char *imageName)
{
    ULONG length = 0;
    ULONG base = 0;
    for (ULONG i = 0; imageName != 0 && imageName[i] != 0; i++)
    {
        length = i + 1;
        if (imageName[i] == '\\' || imageName[i] == '/')
        {
            base = i + 1;
        }
    }
    return length - base;
}

static const char *PspImageBaseName(const char *imageName)
{
    const char *base = imageName;
    for (const char *p = imageName; p != 0 && *p != 0; p++)
    {
        if (*p == '\\' || *p == '/')
        {
            base = p + 1;
        }
    }
    return base;
}

/* One process's entry length: header + its threads + its base name + NUL,
 * rounded up to 8 (Wine's proc_len). */
static ULONG PspProcessEntryLength(PEPROCESS process, ULONG threadInfoSize)
{
    ULONG threadCount = (ULONG)process->activeThreadCount;
    ULONG nameChars = PspImageBaseNameChars(process->imageName);
    ULONG length = (ULONG)sizeof(SYSTEM_PROCESS_INFORMATION) + threadCount * threadInfoSize +
                   (nameChars + 1) * (ULONG)sizeof(WCHAR);
    return (length + 7) & ~7u;
}

/* Fill one process entry into `entry` (a kernel scratch pointer); the name
 * Buffer points at `userEntry` (the entry's final user VA) so the copied-out
 * chain resolves. Lock held. */
static void PspFillProcessEntry(PEPROCESS process, SYSTEM_PROCESS_INFORMATION *entry,
                                uint64_t userEntry, ULONG entryLength, BOOLEAN isLast,
                                ULONG threadInfoSize)
{
    ULONG threadCount = (ULONG)process->activeThreadCount;
    ULONG nameChars = PspImageBaseNameChars(process->imageName);
    const char *baseName = PspImageBaseName(process->imageName);

    memset(entry, 0, entryLength);
    entry->NextEntryOffset = isLast ? 0 : entryLength;
    entry->dwThreadCount = threadCount;
    entry->UniqueProcessId = (HANDLE)(uintptr_t)process->uniqueProcessId;
    entry->ParentProcessId = (HANDLE)(uintptr_t)process->parentProcessId;
    entry->HandleCount = process->handleTable.inUse;
    entry->SessionId = 1; /* the one interactive session (peb.c) */
    /* The same tally ProcessIoCounters reports, not a second one (Art. 11):
     * taskmgr reads the per-process class, kernel32's toolhelp readers walk
     * this snapshot, and two derivations of one fact drift. */
    entry->ioCounters = process->ioCounters;
    entry->dwBasePriority = process->mainThread != 0 ? process->mainThread->priority : 8;
    /* The times and the memory figures, from the SAME two authorities the
     * per-process classes answer from — ProcessTimes' exited-totals-plus-live
     * -threads sum, and MiQueryVmCounters (Art. 11 again: this snapshot
     * RESTATES those classes, it does not compute a second opinion). Left
     * zero until now, which taskmgr's Processes tab showed as "0 K" and
     * "0:00:00" in every row: the columns are read from this snapshot, not
     * from the per-process classes.
     *
     * The thread sum runs under the dispatcher lock this whole fill already
     * holds, so a thread mid-exit is counted exactly once — the reason
     * ProcessTimes takes the lock too. */
    entry->CreationTime = process->createTime;
    uint64_t kernel100ns = 0;
    uint64_t user100ns = 0;
    PspSumProcessTimes(process, &kernel100ns, &user100ns);
    entry->KernelTime.QuadPart = (LONGLONG)kernel100ns;
    entry->UserTime.QuadPart = (LONGLONG)user100ns;
    PspFillVmCounters(process, &entry->vmCounters);

    ULONG threadIndex = 0;
    for (PLIST_ENTRY p = process->threadListHead.Flink;
         p != &process->threadListHead && threadIndex < threadCount; p = p->Flink)
    {
        PETHREAD ethread = CONTAINING_RECORD(p, ETHREAD, threadListEntry);
        /* The per-thread record is EITHER shape, so it is addressed by
         * stride rather than by array index — the extended class (57) is
         * the same walk with a wider record, not a second enumeration
         * (Art. 11). */
        BYTE *slot = (BYTE *)&entry->ti[0] + (SIZE_T)threadIndex * threadInfoSize;
        SYSTEM_THREAD_INFORMATION *ti = (SYSTEM_THREAD_INFORMATION *)slot;
        threadIndex++;
        ti->ClientId.UniqueProcess = (HANDLE)(uintptr_t)process->uniqueProcessId;
        ti->ClientId.UniqueThread = (HANDLE)(uintptr_t)ethread->uniqueThreadId;
        LONG priority = ethread->tcb != 0 ? ethread->tcb->priority : 8;
        ti->dwCurrentPriority = (DWORD)priority;
        ti->dwBasePriority = (DWORD)priority;
        if (threadInfoSize == (ULONG)sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION))
        {
            SYSTEM_EXTENDED_THREAD_INFORMATION *ex = (SYSTEM_EXTENDED_THREAD_INFORMATION *)slot;
            ex->StackBase = (void *)(uintptr_t)ethread->stackBase;
            ex->StackLimit = (void *)(uintptr_t)ethread->stackAllocationBase;
            ex->Win32StartAddress = (void *)(uintptr_t)ethread->win32StartAddress;
            ex->TebBase = (void *)(uintptr_t)ethread->tebBase;
        }
    }

    /* The name sits just past the thread array; its Buffer is the FINAL user
     * address so the caller can chase it in the copied-out block. */
    ULONG nameOffset =
        (ULONG)offsetof(SYSTEM_PROCESS_INFORMATION, ti) + threadCount * threadInfoSize;
    WCHAR *nameScratch = (WCHAR *)((BYTE *)entry + nameOffset);
    for (ULONG i = 0; i < nameChars; i++)
    {
        nameScratch[i] = (WCHAR)(unsigned char)baseName[i];
    }
    nameScratch[nameChars] = 0;
    entry->ProcessName.Length = (USHORT)(nameChars * sizeof(WCHAR));
    entry->ProcessName.MaximumLength = (USHORT)((nameChars + 1) * sizeof(WCHAR));
    entry->ProcessName.Buffer = (WCHAR *)(uintptr_t)(userEntry + nameOffset);
}

/* A process leaves the snapshot the moment it EXITS, not when its EPROCESS is
 * finally freed. PspActiveProcessListHead keeps a terminated process until the
 * last reference goes (a parent's still-open handle holds it for as long as it
 * likes), but NT's process list never shows an exited process — and listing one
 * is not cosmetic: `taskkill /im` matched a dead entry, reported a successful
 * kill, and made "nothing left to kill" unobservable. The signalled dispatcher
 * header is the exit marker (kernel/ps/thread.c publishes it). */
static BOOLEAN PspProcessIsLive(PEPROCESS process)
{
    return process->header.signalState == 0 && process->activeThreadCount > 0;
}

/* SystemProcessInformation (5) and SystemExtendedProcessInformation (57)
 * are ONE enumeration with two per-thread record widths — which is how the
 * oracle serves them too (dlls/ntdll/unix/system.c get_system_process_info
 * takes the class and picks `thread_info_size`). A second walk would be the
 * parallel-path shape Art. 11 forbids. */
static NTSTATUS PspQuerySystemProcessInformation(PVOID buffer, ULONG length, PULONG returnLength,
                                                 ULONG threadInfoSize)
{
    /* Pass 1: total size, list stable under the lock. */
    uint64_t flags = KiAcquireDispatcherLock();
    ULONG total = 0;
    for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
         p = p->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
        if (PspProcessIsLive(process))
        {
            total += PspProcessEntryLength(process, threadInfoSize);
        }
    }
    KiReleaseDispatcherLock(flags);

    if (returnLength != 0)
    {
        *returnLength = total;
    }
    if (length < total)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    NTSTATUS status = KiProbeForWrite(buffer, total, sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    BYTE *scratch = MiAllocatePool(total);
    if (scratch == 0)
    {
        return STATUS_NO_MEMORY;
    }

    /* Pass 2: fill the scratch (Buffer pointers computed against the user VA).
     * No blocking between the passes (Art. 3), so the same list is seen. */
    flags = KiAcquireDispatcherLock();
    ULONG offset = 0;
    ULONG lastOffset = 0;
    BOOLEAN wroteAny = FALSE;
    for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
         p = p->Flink)
    {
        PEPROCESS process = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
        if (!PspProcessIsLive(process))
        {
            continue;
        }
        ULONG entryLength = PspProcessEntryLength(process, threadInfoSize);
        if (offset + entryLength > total)
        {
            break; /* list grew between passes (cannot happen: no preemption) */
        }
        PspFillProcessEntry(process, (SYSTEM_PROCESS_INFORMATION *)(scratch + offset),
                            (uint64_t)(uintptr_t)buffer + offset, entryLength, FALSE,
                            threadInfoSize);
        lastOffset = offset;
        wroteAny = TRUE;
        offset += entryLength;
    }
    /* The chain terminator belongs to the last entry WRITTEN, which filtering
     * makes distinct from the last list member. */
    if (wroteAny)
    {
        ((SYSTEM_PROCESS_INFORMATION *)(scratch + lastOffset))->NextEntryOffset = 0;
    }
    KiReleaseDispatcherLock(flags);

    memcpy(buffer, scratch, offset);
    MiFreePool(scratch);
    return STATUS_SUCCESS;
}

/* --- SystemFirmwareTableInformation (76) ------------------------------------
 *
 * The RSMB provider, served from the machine's OWN firmware (arch/x86_64/
 * smbios.c) rather than from anything host-derived — this is ordinary OS work,
 * not an oracle imitation. The oracle synthesizes its answer from the host's
 * DMI files (dlls/ntdll/unix/system.c create_smbios_data) because it has no
 * firmware of its own to read; proskrnl does, so it passes the real table
 * through. Only the SHAPE is the contract (pinned by sem_ps/process_query
 * through GetSystemFirmwareTable) — never the bytes, which are the machine's.
 */

/* The provider signature callers spell as 'RSMB' (pinned Wine
 * dlls/ntdll/unix/system.c `#define RSMB 0x52534D42`). */
#define PSP_FIRMWARE_PROVIDER_RSMB 0x52534D42

/* The RawSMBIOSData prologue GetSystemFirmwareTable(RSMB) hands back, ahead of
 * the raw structure table (MS docs "GetSystemFirmwareTable"; the same five
 * fields the pinned Wine calls struct smbios_prologue,
 * dlls/ntdll/unix/system.c). */
/* NOLINTBEGIN(readability-identifier-naming) — a struct transcribed from an
 * external contract keeps the contract's member names (docs/15). */
typedef struct
{
    UCHAR Used20CallingMethod;
    UCHAR SmbiosMajorVersion;
    UCHAR SmbiosMinorVersion;
    UCHAR DmiRevision;
    ULONG Length;
} PSP_RAW_SMBIOS_DATA;
/* NOLINTEND(readability-identifier-naming) */

static NTSTATUS PspQueryFirmwareTable(PVOID buffer, ULONG length, PULONG returnLength)
{
    const ULONG fixed = (ULONG)offsetof(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
    /* Wine gates on the fixed part alone, then reports the full requirement
     * through returnLength — which is exactly what kernelbase's
     * get_firmware_table sizing call depends on (dlls/kernelbase/memory.c:
     * it allocates only the fixed part, then subtracts it from *returnLength
     * to learn the table size). */
    if (length < fixed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS status = KiProbeForWrite(buffer, length, 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SYSTEM_FIRMWARE_TABLE_INFORMATION request;
    status = KiCopyFromUser(&request, buffer, fixed);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (request.ProviderSignature != PSP_FIRMWARE_PROVIDER_RSMB)
    {
        /* ACPI/FIRM and the rest are unbuilt: refuse loudly (Art. 12). */
        return STATUS_NOT_IMPLEMENTED;
    }

    SYSTEM_FIRMWARE_TABLE_INFORMATION *reply = buffer;
    ULONG tableLength;
    if (request.Action == SystemFirmwareTable_Enumerate)
    {
        /* One RSMB table, id 0 — the whole SMBIOS blob is a single table. */
        tableLength = sizeof(ULONG);
    }
    else if (request.Action == SystemFirmwareTable_Get)
    {
        const KI_SMBIOS_TABLE *smbios = KiSmbiosGetTable();
        if (smbios == 0)
        {
            /* Firmware published no SMBIOS. Refusing is the honest answer —
             * a synthesized table would be the fabrication Art. 12 forbids —
             * and under QEMU (the only target) it never fires. */
            return STATUS_NOT_IMPLEMENTED;
        }
        tableLength = (ULONG)sizeof(PSP_RAW_SMBIOS_DATA) + smbios->tableLength;
    }
    else
    {
        return STATUS_NOT_IMPLEMENTED; /* an unbuilt action */
    }

    ULONG needed = fixed + tableLength;
    /* Written before the size gate, as the oracle does: the sizing call asks
     * with room for the fixed part only and still reads this back. */
    reply->TableBufferLength = tableLength;
    if (returnLength != 0)
    {
        *returnLength = needed;
    }
    if (length < needed)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (request.Action == SystemFirmwareTable_Enumerate)
    {
        ULONG tableId = 0;
        memcpy(reply->TableBuffer, &tableId, sizeof(tableId));
        return STATUS_SUCCESS;
    }

    const KI_SMBIOS_TABLE *smbios = KiSmbiosGetTable();
    PSP_RAW_SMBIOS_DATA prologue;
    prologue.Used20CallingMethod = 0; /* the 2.0 calling method is not used */
    prologue.SmbiosMajorVersion = smbios->majorVersion;
    prologue.SmbiosMinorVersion = smbios->minorVersion;
    prologue.DmiRevision = smbios->docRevision;
    prologue.Length = smbios->tableLength;
    memcpy(reply->TableBuffer, &prologue, sizeof(prologue));
    memcpy(reply->TableBuffer + sizeof(prologue), smbios->tableData, smbios->tableLength);
    return STATUS_SUCCESS;
}

/* --- SystemWineVersionInformation (1000) ------------------------------------
 *
 * HACK-005 (docs/10, docs/03): a class NT does not have, answered inside the
 * Nt* surface. It exists because the unmodified PE ntdll asks for it at every
 * process start (dlls/ntdll/version.c version_init), and Art. 12 makes an
 * unbuilt answer fatal — so the choice is to implement it or to stop booting.
 *
 * The reply is the oracle's own layout: four NUL-separated strings
 * version\0build\0sysname\0release, and *returnLength is their total including
 * the four terminators. Every value is a fact about THIS image, not an
 * imitation of a host:
 *   - version/build name the Wine the image's PE stack is built from, which is
 *     what wine_get_version's consumers mean by it (wined3d parses it as a
 *     version triple, shell32's About box prints the build id).
 *   - sysname is the host kernel, which here really is proskrnl —
 *     wine_get_host_version exists to answer exactly this.
 *   - release is empty: proskrnl has no release versioning to report, and
 *     inventing a number would be the plausible-answer stub Art. 12 forbids.
 *     Nothing in the tree reads it (only wine_get_host_version exposes it).
 */

/* Re-verify against the pinned Wine tree on a submodule pin bump:
 * third_party/wine/VERSION ("Wine version 11.13") and the wine_build string
 * it produces (dlls/ntdll/unix/version.c: `const char wine_build[]`). */
#define PSP_WINE_VERSION "11.13"
#define PSP_WINE_BUILD   "wine-" PSP_WINE_VERSION

/* The four strings back to back, each NUL-terminated — the trailing literal
 * "" contributes the empty release plus the array's own final NUL, so
 * sizeof() IS the oracle's length (strlen of all four, plus four). */
static const char PspWineVersionReply[] = PSP_WINE_VERSION "\0" PSP_WINE_BUILD "\0"
                                                           "proskrnl"
                                                           "\0"
                                                           "";

static NTSTATUS PspQueryWineVersion(PVOID buffer, ULONG length, PULONG returnLength)
{
    ULONG needed = (ULONG)sizeof(PspWineVersionReply);
    if (returnLength != 0)
    {
        *returnLength = needed;
    }
    if (length < needed)
    {
        /* The oracle fills what fits and still reports the shortfall
         * (dlls/ntdll/unix/system.c: snprintf into `size`, then
         * INFO_LENGTH_MISMATCH). version_init passes a 256-byte buffer, so
         * this is the pathological caller's path. */
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    NTSTATUS status = KiProbeForWrite(buffer, needed, 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(buffer, PspWineVersionReply, needed);
    return STATUS_SUCCESS;
}

/* CUI-7: the stored time-adjustment pair (SetSystemTimeAdjustment's state;
 * seeded to the oracle's fixed answer so the pre-set query is identical on
 * both sides). One home for the value; the query class reads it back. */
static ULONG PspTimeAdjustment = 156250;
static BOOLEAN PspTimeAdjustmentDisabled = TRUE;

static LUID PspSystemtimeLuid(void)
{
    LUID luid;
    luid.LowPart = SE_SYSTEMTIME_PRIVILEGE;
    luid.HighPart = 0;
    return luid;
}

NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS infoClass, PVOID buffer, ULONG length,
                                  PULONG returnLength)
{
    NTSTATUS probeStatus = PspProbeReturnLength(returnLength);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    switch (infoClass)
    {
    case SystemProcessInformation:
        return PspQuerySystemProcessInformation(buffer, length, returnLength,
                                                (ULONG)sizeof(SYSTEM_THREAD_INFORMATION));
    case SystemExtendedProcessInformation:
        return PspQuerySystemProcessInformation(buffer, length, returnLength,
                                                (ULONG)sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION));
    /* "Native" means the KERNEL's word size, not the caller's, so on an
     * x86_64-only kernel (ADR 0006) answering a 64-bit caller it is the
     * same class. The oracle spells it as this same fallthrough behind an
     * `if (!is_win64) return STATUS_INVALID_INFO_CLASS` guard that is
     * always false here (dlls/ntdll/unix/system.c). Pinned by
     * tests/ntapi/sem_ps/info_class_range.c. */
    case SystemNativeBasicInformation:
    /* "Emulation" is the 32-bit view: the same record with the address
     * space narrowed to what a WOW64 caller can reach. The oracle reaches
     * it via `virtual_get_system_info(&sbi, is_wow64())`, i.e. the split is
     * on the CALLER, not on the class — and wow64.dll's process_init reads
     * exactly this to derive both highest_user_address and the default
     * zero-bits it then injects into every guest allocation. A 64-bit
     * caller sees the native view here (its own emulated view IS native),
     * so only the wow64 arm below differs. */
    case SystemEmulationBasicInformation:
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
        info.NumberOfProcessors = KE_NUMBER_PROCESSORS; /* uniprocessor (Art. 3) */
        info.ActiveProcessorsAffinityMask = 1;
        info.LowestUserAddress = (void *)0x10000;
        info.HighestUserAddress = (void *)(KI_USER_SPACE_LIMIT - 1);
        {
            /* The narrowed views. A WOW64 process asking for its own
             * BASIC information gets the guest ceiling — it cannot address
             * anything above it — and the EMULATION class gives that same
             * ceiling to whoever asks about the 32-bit view. */
            PEPROCESS caller = KeGetCurrentThread()->process;
            if (caller->wow64 && caller->wowSpaceLimit != 0)
            {
                info.HighestUserAddress = (void *)(uintptr_t)(caller->wowSpaceLimit - 1);
            }
        }
        info.AllocationGranularity = 0x10000;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }
    case SystemHandleInformation:
    case SystemExtendedHandleInformation:
    {
        /* CUI-6 (sem_ps/sys_handles): the machine-wide snapshot — every
         * live process's table walked under the dispatcher lock into a pool
         * scratch, copied out only after release (the user copy can fault).
         * Entry facts via Ob's accessor; the object pointer is zero-filled
         * as the oracle leaves it (dlls/ntdll/unix/system.c says "FIXME:
         * Fill out Object" on its own extended path).
         *
         * The two classes are ONE walk with two serializations, not two
         * enumerations (Art. 11) — the extended form differs in its header
         * (a ULONG_PTR count plus a reserved word, rather than a ULONG) and
         * in its per-entry record, but it lists exactly the same handles.
         * The header and entry sizes are chosen once, here, and everything
         * below is written through them. */
        BOOLEAN extended = infoClass == SystemExtendedHandleInformation;
        ULONG headerBytes = extended ? (ULONG)offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles)
                                     : (ULONG)offsetof(SYSTEM_HANDLE_INFORMATION, Handle);
        ULONG entryBytes = extended ? (ULONG)sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
                                    : (ULONG)sizeof(SYSTEM_HANDLE_ENTRY);
        if (length < headerBytes + entryBytes)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        uint64_t flags = KiAcquireDispatcherLock();
        ULONG count = 0;
        for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
             p = p->Flink)
        {
            count += CONTAINING_RECORD(p, EPROCESS, activeProcessLinks)->handleTable.inUse;
        }
        ULONG needed = headerBytes + count * entryBytes;
        if (length < needed)
        {
            KiReleaseDispatcherLock(flags);
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        BYTE *snapshot = MiAllocatePool(needed);
        if (snapshot == 0)
        {
            KiReleaseDispatcherLock(flags);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(snapshot, 0, needed);
        ULONG filled = 0;
        for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
             p = p->Flink)
        {
            PEPROCESS owner = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
            for (ULONG index = 0; index < owner->handleTable.capacity && filled < count; index++)
            {
                HANDLE value;
                PVOID body;
                ACCESS_MASK access;
                ULONG attributes;
                if (!ObpHandleTableEntryAt(&owner->handleTable, index, &value, &body, &access,
                                           &attributes))
                {
                    continue;
                }
                BYTE *slot = snapshot + headerBytes + (SIZE_T)filled * entryBytes;
                filled++;
                USHORT typeIndex = ObpTypeIndex(ObpGetHeader(body)->type);
                if (extended)
                {
                    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *entry =
                        (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *)slot;
                    entry->Object = 0;
                    entry->UniqueProcessId = (ULONG_PTR)owner->uniqueProcessId;
                    entry->HandleValue = (ULONG_PTR)value;
                    entry->GrantedAccess = access;
                    entry->ObjectTypeIndex = typeIndex;
                    entry->HandleAttributes = attributes & (OBJ_INHERIT | OBJ_PROTECT_CLOSE);
                }
                else
                {
                    SYSTEM_HANDLE_ENTRY *entry = (SYSTEM_HANDLE_ENTRY *)slot;
                    entry->OwnerPid = (ULONG)owner->uniqueProcessId;
                    entry->ObjectType = typeIndex;
                    entry->HandleFlags = (BYTE)(attributes & (OBJ_INHERIT | OBJ_PROTECT_CLOSE));
                    entry->HandleValue = (USHORT)(ULONG_PTR)value;
                    entry->ObjectPointer = 0;
                    entry->AccessMask = access;
                }
            }
        }
        if (extended)
        {
            ((SYSTEM_HANDLE_INFORMATION_EX *)snapshot)->NumberOfHandles = filled;
        }
        else
        {
            ((SYSTEM_HANDLE_INFORMATION *)snapshot)->Count = filled;
        }
        KiReleaseDispatcherLock(flags);
        ULONG used = headerBytes + filled * entryBytes;
        NTSTATUS handleStatus = KiProbeForWrite(buffer, used, sizeof(uint64_t));
        if (NT_SUCCESS(handleStatus))
        {
            memcpy(buffer, snapshot, used);
            if (returnLength != 0)
            {
                *returnLength = used;
            }
        }
        MiFreePool(snapshot);
        return handleStatus;
    }
    case SystemModuleInformationEx:
    {
        /* The chained form of the class below, and the SAME one real
         * module: proskrnl reports the kernel and nothing else, never the
         * oracle's fabricated hal.dll/mountmgr.sys rows (docs/03 "CUI-6
         * notes" — the oracle's own comment there reads "return some fake
         * info for now", and reproducing invented drivers would be
         * reproducing a fiction rather than a behaviour).
         *
         * The shape is a chain terminated by a zero NextOffset word, and
         * the terminator is part of the reported length: ntdll:info walks
         * until NextOffset is 0 and then requires
         * `(walked - buffer) + sizeof(NextOffset) == size`
         * (info.c:866-878). Getting the terminator out of the length is the
         * easy mistake here. */
        static const char kernelName[] = "\\SystemRoot\\system32\\ntoskrnl.exe";
        const uint64_t kernelBase = 0xffffffff80000000ULL; /* linker.ld */
        ULONG needed = (ULONG)sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) + (ULONG)sizeof(ULONG);
        if (length < needed)
        {
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS moduleStatus = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(moduleStatus))
        {
            return moduleStatus;
        }
        BYTE *scratch = MiAllocatePool(needed);
        if (scratch == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(scratch, 0, needed);
        RTL_PROCESS_MODULE_INFORMATION_EX *entry = (RTL_PROCESS_MODULE_INFORMATION_EX *)scratch;
        entry->NextOffset = (ULONG)sizeof(RTL_PROCESS_MODULE_INFORMATION_EX);
        entry->BaseInfo.ImageBaseAddress = (PVOID)(uintptr_t)kernelBase;
        entry->BaseInfo.ImageSize = (ULONG)((uint64_t)(uintptr_t)KiImageEnd - kernelBase);
        entry->BaseInfo.LoadOrderIndex = 0;
        entry->BaseInfo.LoadCount = 1;
        memcpy(entry->BaseInfo.Name, kernelName, sizeof(kernelName));
        entry->BaseInfo.NameOffset = (WORD)(sizeof("\\SystemRoot\\system32\\") - 1);
        /* The trailing zero NextOffset is already there from the memset. */
        memcpy(buffer, scratch, needed);
        MiFreePool(scratch);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }
    case SystemModuleInformation:
    {
        /* CUI-6 (sem_ps/sys_handles): ONE real module — the kernel itself,
         * base and size from the link (arch/x86_64/linker.ld: image at
         * -2 GiB, KiImageEnd past .bss) — never the oracle's two fabricated
         * driver rows with fake bases (docs/03 "CUI-6 notes"). */
        static const char kernelName[] = "\\SystemRoot\\system32\\ntoskrnl.exe";
        const uint64_t kernelBase = 0xffffffff80000000ULL; /* linker.ld: ". = 0xffffffff80000000" */
        ULONG needed = (ULONG)offsetof(RTL_PROCESS_MODULES, Modules) +
                       (ULONG)sizeof(RTL_PROCESS_MODULE_INFORMATION);
        if (length < needed)
        {
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS moduleStatus = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(moduleStatus))
        {
            return moduleStatus;
        }
        RTL_PROCESS_MODULES *modules = MiAllocatePool(needed);
        if (modules == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(modules, 0, needed);
        modules->ModulesCount = 1;
        RTL_PROCESS_MODULE_INFORMATION *entry = &modules->Modules[0];
        entry->ImageBaseAddress = (PVOID)(uintptr_t)kernelBase;
        entry->ImageSize = (ULONG)((uint64_t)(uintptr_t)KiImageEnd - kernelBase);
        entry->LoadOrderIndex = 0;
        entry->LoadCount = 1;
        memcpy(entry->Name, kernelName, sizeof(kernelName));
        entry->NameOffset = (WORD)(sizeof("\\SystemRoot\\system32\\") - 1);
        memcpy(buffer, modules, needed);
        MiFreePool(modules);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }
    case SystemProcessorPerformanceInformation:
    {
        /* CUI-6 (sem_ps/times): one entry per CPU — one CPU here (Art. 3).
         * The answer scales to whole entries and a zero-entry buffer refuses
         * with length 0; kernel time folds idle IN, exactly the oracle's
         * Linux reading of /proc/stat (dlls/ntdll/unix/system.c: sys +=
         * idle). Idle/user/kernel come from the tick-charge totals. */
        if (length < sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION))
        {
            if (returnLength != 0)
            {
                *returnLength = 0;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        /* Alignment 1: this class is one of the ones wow64_NtQuerySystemInformation
         * forwards untranslated (dlls/wow64/system.c), so a 32-bit caller's
         * 4-aligned array reaches here as-is; the fill stages and copies out. */
        NTSTATUS perfStatus =
            KiProbeForWrite(buffer, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION), 1);
        if (!NT_SUCCESS(perfStatus))
        {
            return perfStatus;
        }
        SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION perf;
        memset(&perf, 0, sizeof(perf));
        uint64_t flags = KiAcquireDispatcherLock();
        perf.IdleTime.QuadPart = (LONGLONG)KiIdleTime100ns;
        perf.KernelTime.QuadPart = (LONGLONG)(KiTotalKernelTime100ns + KiIdleTime100ns);
        perf.UserTime.QuadPart = (LONGLONG)KiTotalUserTime100ns;
        KiReleaseDispatcherLock(flags);
        memcpy(buffer, &perf, sizeof(perf));
        if (returnLength != 0)
        {
            *returnLength = sizeof(perf);
        }
        return STATUS_SUCCESS;
    }
    /* 63 is the same CPU seen as a 32-bit machine: the architecture field
     * reports what a WOW64 caller would get (AMD64 -> INTEL) and every
     * other field is unchanged. Note the asymmetry with class 62, which is
     * NOT adjusted — the emulated BASIC view is identical to the native
     * one, the emulated CPU view is not. Both are pinned
     * (tests/ntapi/sem_ps/system_fixed_classes.c). */
    case SystemEmulationProcessorInformation:
    case SystemCpuInformation:
    {
        /* An OVERSIZED buffer is fine here (`size >= len` — Wine
         * dlls/ntdll/unix/system.c, unlike SystemBasicInformation's
         * exact-length rule); return length = sizeof. Consumer: wineboot's
         * create_hardware_registry_keys switches on ProcessorArchitecture
         * (CUI-1). Level/revision use Wine's get_cpuinfo encoding of CPUID
         * leaf 1 eax: level = family, revision = extended-model/model/
         * stepping nibbles. FeatureBits is the same KF_* word class 154
         * reports, truncated to the field's ULONG exactly as the oracle
         * truncates it (dlls/ntdll/unix/system.c `.ProcessorFeatureBits =
         * get_cpu_features()`), so the two classes cannot disagree about a
         * feature. Pinned by sem_ps/cpu_info + sem_ps/shared_machine. */
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
        info.ProcessorArchitecture = infoClass == SystemEmulationProcessorInformation
                                         ? PROCESSOR_ARCHITECTURE_INTEL
                                         : PROCESSOR_ARCHITECTURE_AMD64;
        info.ProcessorLevel = (USHORT)(((regs[0] >> 8) & 0xf) + ((regs[0] >> 20) & 0xff));
        info.ProcessorRevision = (USHORT)((((regs[0] >> 16) & 0xf) << 12) |
                                          (((regs[0] >> 4) & 0xf) << 8) | (regs[0] & 0xf));
        info.MaximumProcessors = 1; /* uniprocessor (Art. 3) */
        info.ProcessorFeatureBits = (ULONG)KiProcessorFeatureBits(PspProcessorFeatures());
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }
    case SystemTimeAdjustmentInformation:
    {
        /* Exact-length only (wine dlls/ntdll/unix/system.c class 28; pinned
         * by sem_ps/set_time BEFORE any set, where the oracle's fixed
         * {156250, 156250, TRUE} and this stored state coincide). The
         * post-set observability of the stored pair is the recorded
         * divergence from the oracle's fixed answer (docs/03 "CUI-7"). */
        SYSTEM_TIME_ADJUSTMENT_QUERY info;
        if (length != sizeof(info))
        {
            if (returnLength != 0)
            {
                *returnLength = sizeof(info);
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        info.TimeAdjustment = PspTimeAdjustment;
        info.TimeIncrement = 156250; /* the 15.625 ms tick, as the oracle */
        info.TimeAdjustmentDisabled = PspTimeAdjustmentDisabled;
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
        /* The boot instant IS the wall-clock base (ke.h: system time = base +
         * interrupt time), so read it rather than subtracting one sample of
         * the clock from another. Two samples no longer cancel: since the
         * clock became sub-tick (docs/03 "Sub-tick system time") they are
         * taken at different instants, and a boot time NT reports as fixed
         * would jitter by however long this call took. */
        info.BootTime.QuadPart = (LONGLONG)KiSystemTimeBase;
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
        static const char *const standardName = "@tzres.dll,-22000";
        static const char *const daylightName = "@tzres.dll,-22001";
        static const char *const keyName = "UTC";
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
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(SYSTEM_PERFORMANCE_INFORMATION), 1);
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
    /* --- the fixed-shape classes ntdll:info sweeps -----------------------
     * Each of these was unbuilt, so the armed boot panicked and the pair
     * died on whichever it reached first. The values are constants, which
     * is exactly the shape G12 warns about — the difference between an
     * implementation and a silent stub here is only that every one of them
     * is read off the oracle and pinned
     * (tests/ntapi/sem_ps/system_fixed_classes.c). Two are values the
     * oracle itself calls a stub; reproducing a stub's OUTPUT is not
     * stubbing, because Art. 6 makes the oracle the spec and no caller can
     * tell the difference. */
    case SystemKernelDebuggerInformation:
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        info.DebuggerEnabled = FALSE;
        info.DebuggerNotPresent = TRUE;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemRegistryQuotaInformation:
    {
        /* The oracle fakes a 32 MB registry because it has no limit to
         * report; proskrnl has no limit either, so it reports the same
         * numbers rather than inventing its own (dlls/ntdll/unix/system.c
         * says "almost certainly wrong" — but it is what callers see). */
        SYSTEM_REGISTRY_QUOTA_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        info.RegistryQuotaAllowed = 0x2000000;
        info.RegistryQuotaUsed = 0x200000;
        info.Reserved1 = (PVOID)(uintptr_t)0x200000;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemLeapSecondInformation:
    {
        SYSTEM_LEAP_SECOND_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        info.Enabled = TRUE;
        info.Flags = 0;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemProcessorFeaturesInformation:
    {
        /* The KF_* feature bitmap, composed from the shared page's
         * ProcessorFeatures array by KiProcessorFeatureBits — which is where
         * the derivation and its citations live, and is the same
         * array-reading shape the oracle's get_cpu_features has. */
        SYSTEM_PROCESSOR_FEATURES_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        info.ProcessorFeatureBits = KiProcessorFeatureBits(PspProcessorFeatures());
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemFileCacheInformation:
    {
        /* All zero, which is what the oracle reports and is honest here:
         * proskrnl's page cache never evicts (Art. 3), so there are no
         * working-set numbers to report. */
        SYSTEM_CACHE_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemRecommendedSharedDataAlignment:
    {
        /* A cache line. 64 on x86_64 — an architectural fact (Intel SDM
         * Vol. 3A, cache organisation), not a measurement, and the same
         * number the oracle reports for this machine. */
        ULONG alignment = 64;
        if (length < sizeof(alignment))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(alignment), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, &alignment, sizeof(alignment));
        if (returnLength != 0)
        {
            *returnLength = sizeof(alignment);
        }
        return STATUS_SUCCESS;
    }

    case SystemKernelDebuggerInformationEx:
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        info.DebuggerAllowed = FALSE;
        info.DebuggerEnabled = FALSE;
        info.DebuggerPresent = FALSE;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemProcessorFeaturesBitMapInformation:
    {
        /* The OVERFLOW half of the PF_* flag space, two words. EXACT length,
         * unlike its KF_* sibling at 154 which takes `size >= len`. It holds
         * the flags numbered at or above PROCESSOR_FEATURE_MAX, i.e. the ones
         * that do not fit KUSER_SHARED_DATA.ProcessorFeatures — the oracle
         * only ever sets bits here on aarch64 (dlls/ntdll/unix/system.c
         * set_feature_bitmap, whose `assert(flag >= PROCESSOR_FEATURE_MAX)`
         * states the split, and which is compiled only under __aarch64__).
         * x86_64 has no such flag, so both runners report two zero words —
         * an empty SET, not an unfilled field. */
        ULONGLONG bitmap[2] = {0, 0};
        if (length != sizeof(bitmap))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(bitmap), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, bitmap, sizeof(bitmap));
        if (returnLength != 0)
        {
            *returnLength = sizeof(bitmap);
        }
        return STATUS_SUCCESS;
    }

    case SystemLogicalProcessorInformation:
    {
        /* One record: one processor core, mask bit 0. That is not a
         * simplification of a richer truth — Art. 3 mandates uniprocessor,
         * so one core with one logical processor IS the machine, and
         * KE_NUMBER_PROCESSORS is the one authority that says so.
         *
         * ntdll:info sums the ProcessorMask bits of every
         * RelationProcessorCore record and requires the total to equal
         * GetSystemInfo's dwNumberOfProcessors (info.c:1259-1273), so this
         * answer is checked against the same count the rest of the kernel
         * reports rather than standing alone.
         *
         * Cache and NUMA records are deliberately absent: proskrnl models
         * neither, and inventing a cache hierarchy would be describing
         * hardware the kernel does not know it has. The test tolerates
         * their absence; a caller that needs them gets a short list, not a
         * wrong one. */
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION records[KE_NUMBER_PROCESSORS];
        ULONG needed = (ULONG)sizeof(records);
        if (length < needed)
        {
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(records, 0, sizeof(records));
        for (ULONG i = 0; i < KE_NUMBER_PROCESSORS; i++)
        {
            records[i].ProcessorMask = (ULONG_PTR)1 << i;
            records[i].Relationship = RelationProcessorCore;
        }
        memcpy(buffer, records, needed);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }

    case SystemProcessorIdleCycleTimeInformation:
    {
        /* One ULONG64 per processor. The oracle's plain arm just forwards
         * to the Ex form with group 0, so this is the same answer either
         * way (NtQuerySystemInformationEx below shares it).
         *
         * The value is a REAL fact, not a placeholder: KiIdleTime100ns is
         * the idle time the clock tick already charges (kernel/ke/timer.c)
         * and SystemPerformanceInformation already reports. It is a time,
         * not a cycle count, and that IS a divergence — but a monotonic
         * idle measure is what a caller of this class actually uses, and
         * inventing a cycle count from a made-up frequency would be worse
         * than reporting the measure the kernel really keeps. Recorded in
         * docs/03. */
        ULONG needed = KE_NUMBER_PROCESSORS * (ULONG)sizeof(uint64_t);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        /* STATUS_BUFFER_TOO_SMALL, not the INFO_LENGTH_MISMATCH most of
         * this switch gives. The status is not uniform across the classes
         * and a caller sizing a buffer in a loop tests for one of them: the
         * two classes that answer through the Ex form (this one and
         * SystemCpuSetInformation) say BUFFER_TOO_SMALL, and the rest say
         * INFO_LENGTH_MISMATCH. This arm said the wrong one until
         * tests/ntapi/sem_ps/system_variable_classes.c covered it. */
        if (length < needed)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        /* Alignment 1: forwarded untranslated by wow64_NtQuerySystemInformation
         * (dlls/wow64/system.c lists it as `ULONG64[]` and passes the pointer
         * straight down), and an i386 caller's ULONG64 array is 4-aligned. */
        NTSTATUS status = KiProbeForWrite(buffer, needed, 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        uint64_t idle[KE_NUMBER_PROCESSORS];
        for (ULONG i = 0; i < KE_NUMBER_PROCESSORS; i++)
        {
            idle[i] = KiIdleTime100ns;
        }
        memcpy(buffer, idle, needed);
        return STATUS_SUCCESS;
    }

    case SystemProcessIdInformation:
    {
        /* IN-OUT: the caller supplies the pid and its own buffer through
         * ImageName.MaximumLength; the class fills in the image path.
         *
         * The refusal order is the whole contract and it is not the obvious
         * one (dlls/ntdll/unix/system.c): the LENGTH check comes first, and
         * returnLength is written BEFORE any of them — a caller that passes
         * a short buffer still learns the structure size. Then a non-zero
         * ImageName.Length is STATUS_INVALID_PARAMETER (the field is an
         * out-parameter and must arrive empty), and only then is a zero pid
         * STATUS_INVALID_CID — not INVALID_PARAMETER, which is the status
         * an implementation reaches for.
         *
         * A buffer too small for the name is STATUS_INFO_LENGTH_MISMATCH
         * with MaximumLength set to what is needed, so the caller can size
         * and retry. */
        ULONG needed = (ULONG)sizeof(SYSTEM_PROCESS_ID_INFORMATION);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        if (length < needed)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SYSTEM_PROCESS_ID_INFORMATION request;
        memcpy(&request, buffer, sizeof(request));
        if (request.ImageName.Length != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (request.ProcessId == 0)
        {
            return STATUS_INVALID_CID;
        }

        uint64_t flags = KiAcquireDispatcherLock();
        PEPROCESS found = 0;
        for (PLIST_ENTRY p = PspActiveProcessListHead.Flink; p != &PspActiveProcessListHead;
             p = p->Flink)
        {
            PEPROCESS candidate = CONTAINING_RECORD(p, EPROCESS, activeProcessLinks);
            if (PspProcessIsLive(candidate) &&
                candidate->uniqueProcessId == (uint64_t)(uintptr_t)request.ProcessId)
            {
                found = candidate;
                break;
            }
        }
        WCHAR name[260];
        USHORT nameBytes = 0;
        if (found != 0 && found->imageName != 0)
        {
            const char *source = found->imageName;
            USHORT units = 0;
            while (source[units] != 0 && units < 259)
            {
                name[units] = (WCHAR)(unsigned char)source[units];
                units++;
            }
            nameBytes = (USHORT)(units * sizeof(WCHAR));
        }
        KiReleaseDispatcherLock(flags);
        if (found == 0)
        {
            return STATUS_INVALID_CID;
        }

        if ((ULONG)nameBytes + sizeof(WCHAR) > request.ImageName.MaximumLength)
        {
            request.ImageName.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
            memcpy(buffer, &request, sizeof(request));
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        status = KiProbeForWrite(request.ImageName.Buffer, (SIZE_T)nameBytes + sizeof(WCHAR),
                                 sizeof(WCHAR));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(request.ImageName.Buffer, name, nameBytes);
        request.ImageName.Buffer[nameBytes / sizeof(WCHAR)] = 0;
        request.ImageName.Length = nameBytes;
        request.ImageName.MaximumLength = (USHORT)(nameBytes + sizeof(WCHAR));
        memcpy(buffer, &request, sizeof(request));
        return STATUS_SUCCESS;
    }

    case SystemCodeIntegrityInformation:
    {
        /* CODEINTEGRITY_OPTION_ENABLED, which is what the oracle reports.
         * proskrnl enforces no code-integrity policy, and saying so by
         * reporting the flag CLEAR would be the more literal answer — but
         * the oracle is the spec (Art. 6) and callers branch on this to
         * decide whether to attempt an unsigned load, where "disabled" is
         * the answer that changes behaviour. Pinned rather than reasoned:
         * this is the oracle's value. */
        SYSTEM_CODEINTEGRITY_INFORMATION info;
        if (length < sizeof(info))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(info), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memset(&info, 0, sizeof(info));
        info.Length = (ULONG)sizeof(info);
        info.CodeIntegrityOptions = CODEINTEGRITY_OPTION_ENABLED;
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = (ULONG)sizeof(info);
        }
        return STATUS_SUCCESS;
    }

    case SystemProcessorBrandString:
    {
        /* The 48-character CPUID brand string plus its NUL, exactly 49
         * bytes — the size the oracle reports (`static char cpu_name[49]`).
         * Read from CPUID leaves 0x80000002..0x80000004 (Intel SDM Vol. 2A,
         * CPUID: "Processor Brand String"), so it is this machine's real
         * name and not a label.
         *
         * The misalignment refusal is part of the contract and comes BEFORE
         * the length check: a buffer that is not 4-byte aligned is
         * STATUS_DATATYPE_MISALIGNMENT whatever its size. A CPU without the
         * extended leaves has no brand string at all, which is
         * STATUS_NOT_SUPPORTED rather than an empty one. */
        uint32_t regs[4];
        KiCpuid(0x80000000, 0, regs);
        if (regs[0] < 0x80000004)
        {
            return STATUS_NOT_SUPPORTED;
        }
        if (((uintptr_t)buffer & 3) != 0)
        {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        char brand[49];
        memset(brand, 0, sizeof(brand));
        for (uint32_t leaf = 0; leaf < 3; leaf++)
        {
            KiCpuid(0x80000002 + leaf, 0, regs);
            memcpy(brand + leaf * 16, regs, 16);
        }
        brand[48] = 0;
        if (length < sizeof(brand))
        {
            if (returnLength != 0)
            {
                *returnLength = (ULONG)sizeof(brand);
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, sizeof(brand), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(buffer, brand, sizeof(brand));
        if (returnLength != 0)
        {
            *returnLength = (ULONG)sizeof(brand);
        }
        return STATUS_SUCCESS;
    }

    case SystemCpuSetInformation:
    {
        /* The class IS implemented — but only through
         * NtQuerySystemInformationEx, whose arm needs a process handle in
         * the query blob. The oracle's PLAIN arm forwards with a NULL query
         * and length 0, which that arm rejects, so the plain form's answer
         * is always STATUS_INVALID_PARAMETER.
         *
         * Not INVALID_INFO_CLASS (what a refusal-by-default would give) and
         * not success (what "the class exists" would suggest). Measured on
         * the oracle and pinned by tests/ntapi/sem_ps/info_class_range.c —
         * the Ex arm is separate work. */
        return STATUS_INVALID_PARAMETER;
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
    case SystemFirmwareTableInformation:
        return PspQueryFirmwareTable(buffer, length, returnLength);
    case SystemWineVersionInformation:
        return PspQueryWineVersion(buffer, length, returnLength);
    default:
        /* TWO refusals, and the difference is the whole point (Art. 12,
         * docs/21 W1). A class NUMBER outside the enum the pinned header
         * defines is INVALID — the caller asked for nothing that exists,
         * and STATUS_INVALID_INFO_CLASS is an IMPLEMENTED answer, pinned by
         * tests/ntapi/sem_ps/info_class_range.c. A class that IS in the
         * enum and merely unbuilt keeps STATUS_NOT_IMPLEMENTED, which the
         * armed boot turns into a panic; collapsing the two would make
         * every unbuilt class answer plausibly instead of stopping, which
         * is the defect G12 exists to prevent.
         *
         * Wine cannot make this distinction and says so in its own default
         * arm (dlls/ntdll/unix/system.c): "in 95% of the cases it's
         * STATUS_INVALID_INFO_CLASS, so use this as the default". It
         * answers INVALID_INFO_CLASS for both, so the oracle agrees with us
         * on the invalid half and is simply quieter on the other.
         *
         * The bound is abi/'s, never typed (Art. 4):
         * SystemHandleCountInformation is the last enumerator the pinned
         * winternl.h defines, and SystemWineVersionInformation (1000) — the
         * fork's own extension above it — has its own case above. */
        if ((LONG)infoClass < 0 || (ULONG)infoClass > (ULONG)SystemHandleCountInformation)
        {
            return STATUS_INVALID_INFO_CLASS;
        }
        /* Being IN the enum is not enough to make a class a hole, and the
         * paragraph above was too coarse about it. Of the 262 enumerators,
         * the oracle serves 37; the other 225 reach its default arm and get
         * STATUS_INVALID_INFO_CLASS. For those, INVALID_INFO_CLASS is not a
         * guess we are making, it is the ANSWER — pinned behaviour of the
         * spec (tests/ntapi/sem_ps/info_class_range.c covers two), so
         * giving it is an implementation and not the plausible-stub Art. 12
         * forbids.
         *
         * What must stay loud is the genuinely narrower set: a class the
         * ORACLE implements and proskrnl does not. There the refusal really
         * would be hiding a hole a caller depends on. That set is listed
         * below rather than derived, because it is the honest inventory of
         * what this call still owes — and it shrinks, one entry per commit,
         * as the classes get built. It was 16 when this list was written and
         * is now EMPTY: the plain entry point owes nothing.
         *
         * An empty list is spelled as no `switch` at all, not as a `switch`
         * whose only arm is `default`. The intermediate state — case labels
         * deleted while the `DbgPrint`/`STATUS_NOT_IMPLEMENTED` pair was
         * left stranded above the first label — compiles silently and reads
         * as though the loud refusal were still reachable when it is dead
         * code. Re-opening the list means writing the arm back with its
         * classes, in the commit that adds them.
         *
         * Deriving the list the other way round (225 refusals) would need
         * the same information and would rot silently; this way a class
         * leaving the list is a visible edit in the same commit that builds
         * it.
         *
         * Note the list is about THIS entry point. Some classes are served
         * only by NtQuerySystemInformationEx — the oracle's plain switch
         * has no arm for SystemLogicalProcessorInformationEx (107) or
         * SystemSupportedProcessorArchitectures2 (230), so on this path
         * they are ordinary refusals and belong in the 225, not here. Their
         * Ex arms are separate work with their own refusal domain. */
        /* In the enum, and the oracle refuses it too. */
        return STATUS_INVALID_INFO_CLASS;
    }
}

NTSTATUS NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS infoClass, PVOID query,
                                    ULONG queryLength, PVOID buffer, ULONG length,
                                    PULONG returnLength)
{
    NTSTATUS probeStatus = PspProbeReturnLength(returnLength);
    if (!NT_SUCCESS(probeStatus))
    {
        return probeStatus;
    }
    switch (infoClass)
    {
    case SystemLogicalProcessorInformationEx:
    {
        /* The relationship-filtered topology. One record per relationship
         * the caller asks for, each carrying its own Size so the caller can
         * walk a heterogeneous list.
         *
         * The machine is one core, one package, one NUMA node, one group,
         * and one cache level — all of which follow from Art. 3's
         * uniprocessor mandate plus CPUID, not from invention. The cache
         * record is the one that needs hardware: level, line size,
         * associativity and size come from CPUID leaf 4 (Intel SDM Vol. 2A,
         * "Deterministic Cache Parameters"), so it describes this CPU
         * rather than a plausible one. A CPU without leaf 4 reports no
         * cache record at all rather than a made-up one.
         *
         * RelationAll returns every record; a specific relationship returns
         * just its own. ntdll:info asks for each in turn and requires a
         * non-empty answer for every one (info.c:1300-1330), then requires
         * the union of the filtered lengths to equal the RelationAll
         * length. */
        ULONG relationship;
        if (query == 0 || queryLength < sizeof(relationship))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS probe = KiProbeForRead(query, sizeof(relationship), sizeof(relationship));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        memcpy(&relationship, query, sizeof(relationship));

        /* Per-record sizes: each is its fixed part plus the one group
         * affinity / group info the single group needs. */
        ULONG headerBytes = (ULONG)offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor);
        ULONG processorBytes = headerBytes + (ULONG)offsetof(PROCESSOR_RELATIONSHIP, GroupMask) +
                               (ULONG)sizeof(GROUP_AFFINITY);
        ULONG numaBytes = headerBytes + (ULONG)offsetof(NUMA_NODE_RELATIONSHIP, GroupMask) +
                          (ULONG)sizeof(GROUP_AFFINITY);
        ULONG cacheBytes = headerBytes + (ULONG)offsetof(CACHE_RELATIONSHIP, GroupMask) +
                           (ULONG)sizeof(GROUP_AFFINITY);
        ULONG groupBytes = headerBytes + (ULONG)offsetof(GROUP_RELATIONSHIP, GroupInfo) +
                           (ULONG)sizeof(PROCESSOR_GROUP_INFO);

        uint32_t cacheRegs[4];
        KiCpuid(4, 0, cacheRegs);
        BOOLEAN haveCache = (cacheRegs[0] & 0x1f) != 0;

        BOOLEAN wantCore = relationship == RelationAll || relationship == RelationProcessorCore;
        BOOLEAN wantNuma = relationship == RelationAll || relationship == RelationNumaNode;
        BOOLEAN wantCache =
            haveCache && (relationship == RelationAll || relationship == RelationCache);
        BOOLEAN wantPackage =
            relationship == RelationAll || relationship == RelationProcessorPackage;
        BOOLEAN wantGroup = relationship == RelationAll || relationship == RelationGroup;

        ULONG needed = 0;
        needed += wantCore ? processorBytes : 0;
        needed += wantNuma ? numaBytes : 0;
        needed += wantCache ? cacheBytes : 0;
        needed += wantPackage ? processorBytes : 0;
        needed += wantGroup ? groupBytes : 0;
        if (needed == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        if (length < needed)
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        BYTE *scratch = MiAllocatePool(needed);
        if (scratch == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(scratch, 0, needed);
        ULONG offset = 0;
        const KAFFINITY allProcessors = ((KAFFINITY)1 << KE_NUMBER_PROCESSORS) - 1;

        if (wantCore || wantPackage)
        {
            for (int pass = 0; pass < 2; pass++)
            {
                BOOLEAN emit = pass == 0 ? wantCore : wantPackage;
                if (!emit)
                {
                    continue;
                }
                SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *record =
                    (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(scratch + offset);
                record->Relationship = pass == 0 ? RelationProcessorCore : RelationProcessorPackage;
                record->Size = processorBytes;
                record->Processor.GroupCount = 1;
                record->Processor.GroupMask[0].Mask = allProcessors;
                offset += processorBytes;
            }
        }
        if (wantNuma)
        {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *record =
                (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(scratch + offset);
            record->Relationship = RelationNumaNode;
            record->Size = numaBytes;
            record->NumaNode.NodeNumber = 0;
            record->NumaNode.GroupCount = 1;
            record->NumaNode.GroupMask.Mask = allProcessors;
            offset += numaBytes;
        }
        if (wantCache)
        {
            /* CPUID.4:EAX bits 7:5 = level, bits 4:0 = type (1 data,
             * 2 instruction, 3 unified); EBX packs associativity, line
             * partitions and line size; ECX is the set count. */
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *record =
                (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(scratch + offset);
            ULONG ways = ((cacheRegs[1] >> 22) & 0x3ff) + 1;
            ULONG partitions = ((cacheRegs[1] >> 12) & 0x3ff) + 1;
            ULONG lineSize = (cacheRegs[1] & 0xfff) + 1;
            ULONG sets = cacheRegs[2] + 1;
            record->Relationship = RelationCache;
            record->Size = cacheBytes;
            record->Cache.Level = (BYTE)((cacheRegs[0] >> 5) & 0x7);
            record->Cache.Associativity = (BYTE)(ways > 255 ? 255 : ways);
            record->Cache.LineSize = (WORD)lineSize;
            record->Cache.CacheSize = ways * partitions * lineSize * sets;
            switch (cacheRegs[0] & 0x1f)
            {
            case 1:
                record->Cache.Type = CacheData;
                break;
            case 2:
                record->Cache.Type = CacheInstruction;
                break;
            default:
                record->Cache.Type = CacheUnified;
                break;
            }
            record->Cache.GroupCount = 1;
            record->Cache.GroupMask.Mask = allProcessors;
            offset += cacheBytes;
        }
        if (wantGroup)
        {
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *record =
                (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)(scratch + offset);
            record->Relationship = RelationGroup;
            record->Size = groupBytes;
            record->Group.MaximumGroupCount = 1;
            record->Group.ActiveGroupCount = 1;
            record->Group.GroupInfo[0].MaximumProcessorCount = KE_NUMBER_PROCESSORS;
            record->Group.GroupInfo[0].ActiveProcessorCount = KE_NUMBER_PROCESSORS;
            record->Group.GroupInfo[0].ActiveProcessorMask = allProcessors;
            offset += groupBytes;
        }
        /* The emitted bytes and the sized bytes are computed by two separate
         * passes over the same five `want*` decisions, so they can disagree
         * — and a disagreement would copy out either a truncated list or the
         * uninitialized tail of the scratch block. Stated as an invariant
         * rather than trusted, which also gives the last `offset +=` above a
         * reader (it is otherwise a dead store `make format` rejects). */
        ASSERT(offset == needed);
        memcpy(buffer, scratch, needed);
        MiFreePool(scratch);
        return STATUS_SUCCESS;
    }

    case SystemCpuSetInformation:
    {
        /* One record per logical processor. The query blob is a process
         * HANDLE — it may be NULL, but it must be PRESENT and at least
         * pointer-sized, which is what makes the plain entry point's
         * forward (a NULL query of length 0) an INVALID_PARAMETER rather
         * than an answer.
         *
         * Ids start at 0x100, which is the oracle's numbering and is
         * observable: callers pass these back to
         * SetProcessDefaultCpuSets. CoreIndex, NumaNodeIndex and
         * LastLevelCacheIndex are all 0 because there is one of each
         * (Art. 3), not because they are unfilled. */
        if (query == 0 || queryLength < sizeof(HANDLE))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS probe = KiProbeForRead(query, sizeof(HANDLE), sizeof(HANDLE));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        HANDLE target;
        memcpy(&target, query, sizeof(target));
        if (target != 0)
        {
            /* A handle that is present must be a real process handle; the
             * oracle validates it with a ProcessBasicInformation query and
             * returns whatever that says. */
            PVOID body;
            NTSTATUS refStatus =
                ObReferenceObjectByHandle(target, PROCESS_QUERY_LIMITED_INFORMATION,
                                          &PspProcessType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(refStatus))
            {
                return refStatus;
            }
            ObDereferenceObject(body);
        }
        ULONG needed = KE_NUMBER_PROCESSORS * (ULONG)sizeof(SYSTEM_CPU_SET_INFORMATION);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        if (length < needed)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        NTSTATUS status = KiProbeForWrite(buffer, needed, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        SYSTEM_CPU_SET_INFORMATION sets[KE_NUMBER_PROCESSORS];
        memset(sets, 0, sizeof(sets));
        for (ULONG i = 0; i < KE_NUMBER_PROCESSORS; i++)
        {
            sets[i].Size = (ULONG)sizeof(SYSTEM_CPU_SET_INFORMATION);
            sets[i].Type = CpuSetInformation;
            sets[i].CpuSet.Id = 0x100 + i;
            sets[i].CpuSet.LogicalProcessorIndex = (BYTE)i;
        }
        memcpy(buffer, sets, needed);
        return STATUS_SUCCESS;
    }

    case SystemProcessorIdleCycleTimeInformation:
    {
        /* The same answer the plain form gives, and the plain form is
         * literally this one on the oracle (it forwards with group 0). What
         * the Ex form adds is the group check, and it is strict: the query
         * must be present, at least a USHORT, and that USHORT must be ZERO
         * — group 0 is the only group on a machine with one processor
         * group, and asking for any other is STATUS_INVALID_PARAMETER
         * rather than an empty answer. */
        USHORT group;
        if (query == 0 || queryLength < sizeof(group))
        {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS probe = KiProbeForRead(query, sizeof(group), sizeof(group));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        memcpy(&group, query, sizeof(group));
        if (group != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return NtQuerySystemInformation(SystemProcessorIdleCycleTimeInformation, buffer, length,
                                        returnLength);
    }

    /* 224 and 230 are the same answer; the oracle serves them from one arm
     * and so does this one. */
    case SystemSupportedProcessorArchitectures2:
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
        /* The target's own machine decides the Process bits below, so the
         * reference is held long enough to read it rather than only to
         * validate the handle. ONE authority for the value
         * (MI_ADDRESS_SPACE.machine, which mm/section.c already judges image
         * views against) rather than a second derivation from `wow64` that
         * could drift from it. */
        USHORT targetMachine = 0;
        if (processHandle == NtCurrentProcess())
        {
            targetMachine = KeGetCurrentThread()->process->addressSpace.machine;
        }
        else if (processHandle != 0)
        {
            PVOID body;
            status = ObReferenceObjectByHandle(processHandle, PROCESS_QUERY_LIMITED_INFORMATION,
                                               &PspProcessType, ExGetPreviousMode(), &body, 0);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            PEPROCESS target = body;
            targetMachine = target->addressSpace.machine;
            ObDereferenceObject(body);
        }
        SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION machines[3];
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
        /* Native first, then the WOW64 container, then the terminator —
         * the order and the flag pattern the oracle answers with
         * (dlls/ntdll/unix/system.c). RtlWow64GetProcessMachines reads
         * exactly this to tell wow64.dll which machine it is emulating, so
         * the I386 row is what makes a WOW64 process possible at all.
         * Process marks the row whose machine the TARGET runs; a NULL
         * handle names no process and so sets none. */
        machines[0].Machine = IMAGE_FILE_MACHINE_AMD64;
        machines[0].KernelMode = 1;
        machines[0].UserMode = 1;
        machines[0].Native = 1;
        machines[0].Process = targetMachine == IMAGE_FILE_MACHINE_AMD64;
        machines[1].Machine = IMAGE_FILE_MACHINE_I386;
        machines[1].UserMode = 1;
        machines[1].WoW64Container = 1;
        machines[1].Process = targetMachine == IMAGE_FILE_MACHINE_I386;
        memcpy(buffer, machines, needed);
        if (returnLength != 0)
        {
            *returnLength = needed;
        }
        return STATUS_SUCCESS;
    }
    /* 230 is 224 with a wider row — the oracle serves both from one arm,
     * and so does the case above. */
    default:
        /* The same split the plain entry point makes, applied to this one
         * (see NtQuerySystemInformation's default arm for the reasoning):
         * a class the ORACLE does not serve HERE is an ordinary refusal,
         * because INVALID_INFO_CLASS is the answer its default gives. Only
         * a class the oracle serves through THIS entry point and proskrnl
         * does not is a hole worth panicking over.
         *
         * The oracle's Ex switch serves eight classes. This is the list of
         * those proskrnl still owes, and it shrinks by one per commit that
         * builds one. */
        switch (infoClass)
        {
        case SystemBatteryState:
        case SystemExecutionState:
        case SystemPowerCapabilities:
            DbgPrint("NtQuerySystemInformationEx: unbuilt info class %d\n", (int)infoClass);
            return STATUS_NOT_IMPLEMENTED;
        default:
            return STATUS_INVALID_INFO_CLASS;
        }
    }
}

NTSTATUS NtQuerySystemTime(PLARGE_INTEGER time)
{
    /* Alignment 1 for the same reason as NtQueryPerformanceCounter above:
     * the WOW64 thunk forwards the caller's 4-aligned pointer untranslated
     * (dlls/wow64/system.c wow64_NtQuerySystemTime); pinned by
     * sem_ps/misaligned_out. The staged-local + memcpy shape below already
     * never dereferences the user address at ring 0. */
    NTSTATUS status = KiProbeForWrite(time, sizeof(LARGE_INTEGER), 1);
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

NTSTATUS NtSetSystemTime(const LARGE_INTEGER *newTime, LARGE_INTEGER *oldTime)
{
    /* The oracle's shape first (wine dlls/ntdll/unix/sync.c NtSetSystemTime;
     * pinned by sem_ps/set_time): *old always carries the current time, a
     * set within half a second is a success no-op, and only then does the
     * privilege speak. The privileged arm is beyond_oracle (MS
     * SetSystemTime): really move the clock, and write the CMOS back so the
     * set survives a reboot (the CUI-1 RTC read's inverse). */
    NTSTATUS status = KiProbeForRead(newTime, sizeof(*newTime), sizeof(uint64_t));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LARGE_INTEGER target;
    memcpy(&target, newTime, sizeof(target));
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    if (oldTime != 0)
    {
        status = KiProbeForWrite(oldTime, sizeof(*oldTime), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        memcpy(oldTime, &now, sizeof(now));
    }
    LONGLONG diff = target.QuadPart - now.QuadPart;
    if (diff > -10000000 / 2 && diff < 10000000 / 2)
    {
        return STATUS_SUCCESS; /* within half a second: the oracle's no-op */
    }
    if (!SeSinglePrivilegeCheck(PspSystemtimeLuid(), ExGetPreviousMode()))
    {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    KeSetSystemTime(target.QuadPart);
    KiWriteRtcTime((uint64_t)target.QuadPart);
    return STATUS_SUCCESS;
}

NTSTATUS NtShutdownSystem(SHUTDOWN_ACTION action)
{
    /* Built against the MS contract (NtShutdownSystem + Privilege Constants,
     * learn.microsoft.com; the pinned oracle stubs the service) and pinned
     * beyond_oracle by sem_ps/shutdown; the live arms are the tests/run
     * cui7 (ring-3 poweroff) and acpi (QEMU exits 0 on its own) legs. Every
     * mutation is already durable at syscall return (Art. 3 immediate
     * writeback), so there is nothing to flush before stopping the machine. */
    LUID luid;
    luid.LowPart = SE_SHUTDOWN_PRIVILEGE;
    luid.HighPart = 0;
    if (!SeSinglePrivilegeCheck(luid, ExGetPreviousMode()))
    {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if (action != ShutdownNoReboot && action != ShutdownReboot && action != ShutdownPowerOff)
    {
        return STATUS_INVALID_PARAMETER;
    }
    DbgPrint("[KTEST] shutdown action=%u (ring-3 NtShutdownSystem)\n", (unsigned)action);
    if (action == ShutdownReboot)
    {
        /* 8042 keyboard-controller command 0xFE pulses the CPU reset line
         * (IBM PC AT convention; pinned QEMU hw/input/pckbd.c
         * KBD_CCMD_RESET 0xFE -> qemu_system_reset_request). */
        KiOutByte(0x64, 0xfe);
    }
    else
    {
        /* NoReboot and PowerOff both power the machine off through ACPI S5
         * (arch/x86_64/power.c; the debug-exit port only as its said
         * fallback) — NoReboot powers off rather than parking at "safe to
         * turn off", a VM having nobody to press the button (docs/03). */
        KiPowerOff();
    }
    /* The reset is asynchronous; park until it lands. */
    for (;;)
    {
        __asm__ volatile("hlt");
    }
}

NTSTATUS NtSetSystemInformation(SYSTEM_INFORMATION_CLASS infoClass, PVOID information, ULONG length)
{
    /* One served class - SystemTimeAdjustmentInformation, the only one the
     * baked stack issues (kernelbase SetSystemTimeAdjustment) - built
     * against the MS contract (SetSystemTimeAdjustment; pinned
     * beyond_oracle by sem_ps/set_time). Everything else refuses with the
     * specific NT failure, a recorded divergence from the oracle's blanket
     * FIXME-success (docs/03 "CUI-7"; G12: never a fabricated success). */
    switch (infoClass)
    {
    case SystemTimeAdjustmentInformation:
    {
        SYSTEM_TIME_ADJUSTMENT adjustment;
        if (length != sizeof(adjustment))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        NTSTATUS status = KiProbeForRead(information, sizeof(adjustment), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (!SeSinglePrivilegeCheck(PspSystemtimeLuid(), ExGetPreviousMode()))
        {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        memcpy(&adjustment, information, sizeof(adjustment));
        PspTimeAdjustment = adjustment.TimeAdjustment;
        PspTimeAdjustmentDisabled = adjustment.TimeAdjustmentDisabled;
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
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

/* Nothing to flush: one processor, no store buffer another CPU could still
 * see (Art. 3 uniprocessor — the cross-CPU membarrier this call exists for
 * has no second CPU to reach; Wine's wrapper likewise always succeeds,
 * dlls/ntdll/unix/virtual.c NtFlushProcessWriteBuffers). */
NTSTATUS NtFlushProcessWriteBuffers(void)
{
    return STATUS_SUCCESS;
}

/* The only processor there is (Art. 3 uniprocessor; SystemBasicInformation
 * reports NumberOfProcessors = 1 and sem_ps/exec_state pins the bound). */
ULONG NtGetCurrentProcessorNumber(void)
{
    return 0;
}

/* The per-process latch of Wine's NtSetThreadExecutionState
 * (dlls/ntdll/unix/system.c): report the current state, replace it unless
 * the current state is continuous and the new one is a mere pulse. No power
 * management exists to act on it — the latch IS the pinned behaviour
 * (sem_ps/exec_state), not a stub. */
NTSTATUS NtSetThreadExecutionState(EXECUTION_STATE newState, EXECUTION_STATE *oldState)
{
    NTSTATUS status = KiProbeForWrite(oldState, sizeof(EXECUTION_STATE), sizeof(EXECUTION_STATE));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PEPROCESS process = KeGetCurrentThread()->process;
    EXECUTION_STATE current = process->executionState;
    memcpy(oldState, &current, sizeof(current));
    if (!(current & ES_CONTINUOUS) || (newState & ES_CONTINUOUS))
    {
        process->executionState = newState;
    }
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
    /* Alignment 1, not 8: a WOW64 caller's output LARGE_INTEGER is an i386
     * stack local at addr % 8 == 4, and the pinned Wine forwards the 32-bit
     * pointer untranslated (dlls/wow64/sync.c wow64_NtQueryPerformanceCounter
     * — the write-side twin of the KiCaptureTimeout rule). Pinned by
     * sem_ps/misaligned_out. The value is staged in an aligned local below
     * and leaves through memcpy, so no ring-0 code dereferences the user
     * address. 1 is knowingly wider than the pin (the oracle checks no
     * alignment at all, so it cannot say what 1-mod-4 should do). */
    NTSTATUS status = KiProbeForWrite(counter, sizeof(LARGE_INTEGER), 1);
    if (NT_SUCCESS(status) && frequency != 0)
    {
        status = KiProbeForWrite(frequency, sizeof(LARGE_INTEGER), 1);
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
        freq.QuadPart = KI_PERFORMANCE_FREQUENCY;
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
    case SystemPowerCapabilities:
    {
        /* A fixed capability block. Every value is the oracle's
         * (dlls/ntdll/unix/system.c), including the ones its own comment
         * calls "based off a native XP desktop" — reproducing a stub's
         * OUTPUT is not stubbing, because Art. 6 makes the oracle the spec
         * and no caller can tell the difference. proskrnl has no ACPI, so
         * it has nothing truer to say.
         *
         * A short buffer is STATUS_BUFFER_TOO_SMALL, not
         * INFO_LENGTH_MISMATCH: this call follows the power-management
         * convention rather than the info-class one. */
        SYSTEM_POWER_CAPABILITIES caps;
        if (outputLength < sizeof(caps))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        NTSTATUS probe = KiProbeForWrite(output, sizeof(caps), 1);
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        memset(&caps, 0, sizeof(caps));
        caps.PowerButtonPresent = TRUE;
        caps.SystemS1 = TRUE;
        caps.SystemS4 = TRUE;
        caps.SystemS5 = TRUE;
        caps.HiberFilePresent = TRUE;
        caps.FullWake = TRUE;
        caps.ProcessorMinThrottle = 100;
        caps.ProcessorMaxThrottle = 100;
        caps.DiskSpinDown = TRUE;
        caps.AcOnLineWake = PowerSystemUnspecified;
        caps.SoftLidWake = PowerSystemUnspecified;
        caps.RtcWake = PowerSystemSleeping1;
        caps.MinDeviceWakeState = PowerSystemUnspecified;
        caps.DefaultLowLatencyWake = PowerSystemUnspecified;
        memcpy(output, &caps, sizeof(caps));
        return STATUS_SUCCESS;
    }
    case SystemBatteryState:
    {
        /* All zero: no battery. That is the truth on this machine, not a
         * placeholder — the oracle memsets the block and then fills it from
         * the host's power supply, which under QEMU reports none either, so
         * both runners answer the same way for the same reason. A caller
         * reads BatteryPresent 0 and stops. */
        SYSTEM_BATTERY_STATE battery;
        if (outputLength < sizeof(battery))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        NTSTATUS probe = KiProbeForWrite(output, sizeof(battery), 1);
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        memset(&battery, 0, sizeof(battery));
        /* No battery means running on mains, and that is not a detail:
         * kernelbase derives GetSystemPowerStatus's ACLineStatus from this
         * field, and kernel32:power asserts AC_LINE_ONLINE on exactly the
         * "no battery detected" branch (power.c:69). An all-zero block
         * would report a machine on battery power with no battery. */
        battery.AcOnLine = TRUE;
        memcpy(output, &battery, sizeof(battery));
        return STATUS_SUCCESS;
    }
    default:
        /* other levels: unbuilt, loud (Art. 12) — and named, so the log says
         * WHICH level rather than only which syscall */
        DbgPrint("NtPowerInformation: unbuilt level %d\n", (int)level);
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* --- scheduling ----------------------------------------------------------- */

NTSTATUS NtDelayExecution(BOOLEAN alertable, const LARGE_INTEGER *interval)
{
    /* KiCopyFromUser, not KiCaptureTimeout: the interval here is MANDATORY,
     * so there is no NULL case for this service to have an opinion about and
     * a NULL keeps answering whatever probing it answers -- unchanged by this
     * commit, and not a fixed answer this code invents (Art. 12). What does
     * change is the alignment: the capture reads a 4-mod-8 WOW64 interval
     * instead of refusing it (uaccess.h KiCaptureTimeout). */
    LARGE_INTEGER captured;
    NTSTATUS status = KiCopyFromUser(&captured, interval, sizeof(captured));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
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
    size_t n = KiWideStringLength(prefix);
    memcpy(path, prefix, n * sizeof(WCHAR));
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
     * PEB->KernelCallbackTable is null, so this is never reached -- and if
     * it ever IS reached, that unreachability argument has broken and the
     * caller needs to hear about it. STATUS_UNSUCCESSFUL was a hardwired
     * plausible answer, invisible to the KiPanicOnNotImplemented net that
     * exists to catch exactly this (docs/review-2026-07 §5). */
    return STATUS_NOT_IMPLEMENTED;
}
