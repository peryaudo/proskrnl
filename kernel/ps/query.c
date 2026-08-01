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
#include "kernel/io/io.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/smbios.h"

#include "abi/ntpsapi.h"
#include "abi/ntimage.h"
#include "abi/ntpebteb.h"
#include "abi/ntioapi.h"
#include "abi/ntregapi.h"

/* --- process information -------------------------------------------------- */

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
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
        status = (length > sizeof(PROCESS_BASIC_INFORMATION)) ? STATUS_INFO_LENGTH_MISMATCH
                                                              : STATUS_SUCCESS;
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
        status = KiProbeForWrite(buffer, sizeof(KERNEL_USER_TIMES), sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            break;
        }
        KERNEL_USER_TIMES times;
        memset(&times, 0, sizeof(times));
        uint64_t flags = KiAcquireDispatcherLock();
        times.CreateTime = process->createTime;
        times.ExitTime = process->exitTime;
        uint64_t kernel100ns = process->exitedKernelTime100ns;
        uint64_t user100ns = process->exitedUserTime100ns;
        for (PLIST_ENTRY entry = process->threadListHead.Flink; entry != &process->threadListHead;
             entry = entry->Flink)
        {
            PKTHREAD tcb = CONTAINING_RECORD(entry, ETHREAD, threadListEntry)->tcb;
            kernel100ns += tcb->kernelTime100ns;
            user100ns += tcb->userTime100ns;
        }
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
    {
        /* CUI-6 (sem_ps/proc_classes): UNICODE_STRING + embedded
         * NUL-terminated buffer, NT (\??\) form; min-size refusal reports
         * header + name (dlls/ntdll/unix/process.c). Boot/flat processes
         * with no NT path answer an empty string. */
        ULONG minSize = sizeof(UNICODE_STRING) + sizeof(WCHAR);
        ULONG nameBytes = process->imageNtPath.Length;
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
            memcpy(userBuffer, process->imageNtPath.Buffer, nameBytes);
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
static ULONG PspProcessEntryLength(PEPROCESS process)
{
    ULONG threadCount = (ULONG)process->activeThreadCount;
    ULONG nameChars = PspImageBaseNameChars(process->imageName);
    ULONG length = (ULONG)sizeof(SYSTEM_PROCESS_INFORMATION) +
                   threadCount * (ULONG)sizeof(SYSTEM_THREAD_INFORMATION) +
                   (nameChars + 1) * (ULONG)sizeof(WCHAR);
    return (length + 7) & ~7u;
}

/* Fill one process entry into `entry` (a kernel scratch pointer); the name
 * Buffer points at `userEntry` (the entry's final user VA) so the copied-out
 * chain resolves. Lock held. */
static void PspFillProcessEntry(PEPROCESS process, SYSTEM_PROCESS_INFORMATION *entry,
                                uint64_t userEntry, ULONG entryLength, BOOLEAN isLast)
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
    entry->dwBasePriority = process->mainThread != 0 ? process->mainThread->priority : 8;

    ULONG threadIndex = 0;
    for (PLIST_ENTRY p = process->threadListHead.Flink;
         p != &process->threadListHead && threadIndex < threadCount; p = p->Flink)
    {
        PETHREAD ethread = CONTAINING_RECORD(p, ETHREAD, threadListEntry);
        SYSTEM_THREAD_INFORMATION *ti = &entry->ti[threadIndex++];
        ti->ClientId.UniqueProcess = (HANDLE)(uintptr_t)process->uniqueProcessId;
        ti->ClientId.UniqueThread = (HANDLE)(uintptr_t)ethread->uniqueThreadId;
        LONG priority = ethread->tcb != 0 ? ethread->tcb->priority : 8;
        ti->dwCurrentPriority = (DWORD)priority;
        ti->dwBasePriority = (DWORD)priority;
    }

    /* The name sits just past the thread array; its Buffer is the FINAL user
     * address so the caller can chase it in the copied-out block. */
    ULONG nameOffset =
        (ULONG)offsetof(SYSTEM_PROCESS_INFORMATION, ti) + threadCount * (ULONG)sizeof(*entry->ti);
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

static NTSTATUS PspQuerySystemProcessInformation(PVOID buffer, ULONG length, PULONG returnLength)
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
            total += PspProcessEntryLength(process);
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
        ULONG entryLength = PspProcessEntryLength(process);
        if (offset + entryLength > total)
        {
            break; /* list grew between passes (cannot happen: no preemption) */
        }
        PspFillProcessEntry(process, (SYSTEM_PROCESS_INFORMATION *)(scratch + offset),
                            (uint64_t)(uintptr_t)buffer + offset, entryLength, FALSE);
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
typedef struct
{
    UCHAR Used20CallingMethod;
    UCHAR SmbiosMajorVersion;
    UCHAR SmbiosMinorVersion;
    UCHAR DmiRevision;
    ULONG Length;
} PSP_RAW_SMBIOS_DATA;

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
        return PspQuerySystemProcessInformation(buffer, length, returnLength);
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
    case SystemHandleInformation:
    {
        /* CUI-6 (sem_ps/sys_handles): the machine-wide snapshot — every
         * live process's table walked under the dispatcher lock into a pool
         * scratch, copied out only after release (the user copy can fault).
         * Entry facts via Ob's accessor; ObjectPointer zero-filled as the
         * oracle leaves it (dlls/ntdll/unix/system.c). */
        if (length < sizeof(SYSTEM_HANDLE_INFORMATION))
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
        ULONG headerBytes = (ULONG)offsetof(SYSTEM_HANDLE_INFORMATION, Handle);
        ULONG needed = headerBytes + count * (ULONG)sizeof(SYSTEM_HANDLE_ENTRY);
        if (length < needed)
        {
            KiReleaseDispatcherLock(flags);
            if (returnLength != 0)
            {
                *returnLength = needed;
            }
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        SYSTEM_HANDLE_INFORMATION *snapshot = MiAllocatePool(needed);
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
                SYSTEM_HANDLE_ENTRY *entry = &snapshot->Handle[filled++];
                entry->OwnerPid = (ULONG)owner->uniqueProcessId;
                entry->ObjectType = ObpTypeIndex(ObpGetHeader(body)->type);
                entry->HandleFlags = (BYTE)(attributes & (OBJ_INHERIT | OBJ_PROTECT_CLOSE));
                entry->HandleValue = (USHORT)(ULONG_PTR)value;
                entry->ObjectPointer = 0;
                entry->AccessMask = access;
            }
        }
        snapshot->Count = filled;
        KiReleaseDispatcherLock(flags);
        ULONG used = headerBytes + filled * (ULONG)sizeof(SYSTEM_HANDLE_ENTRY);
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
    case SystemModuleInformation:
    {
        /* CUI-6 (sem_ps/sys_handles): ONE real module — the kernel itself,
         * base and size from the link (arch/x86_64/linker.ld: image at
         * -2 GiB, KiImageEnd past .bss) — never the oracle's two fabricated
         * driver rows with fake bases (docs/03 "CUI-6 notes"). */
        static const char kernelName[] = "\\SystemRoot\\system32\\ntoskrnl.exe";
        extern char KiImageEnd[];                          /* linker.ld */
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
        NTSTATUS perfStatus = KiProbeForWrite(
            buffer, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION), sizeof(uint64_t));
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
    case SystemFirmwareTableInformation:
        return PspQueryFirmwareTable(buffer, length, returnLength);
    case SystemWineVersionInformation:
        return PspQueryWineVersion(buffer, length, returnLength);
    default:
        return STATUS_NOT_IMPLEMENTED;
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
