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
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

#include "abi/ntpsapi.h"
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
        info.ExitStatus = STATUS_PENDING;
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

NTSTATUS NtSetInformationProcess(HANDLE processHandle, PROCESSINFOCLASS infoClass, PVOID buffer,
                                 ULONG length)
{
    (void)processHandle;
    (void)infoClass;
    (void)buffer;
    (void)length;
    /* The classes ntdll sets at startup (default hard-error mode, fault
     * policy, etc.) have no observable effect here; accept them. */
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
    default:
        /* version_init tolerates a failure here (docs/03). */
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

/* --- registry (graceful failure until Cm at M8) --------------------------- */

NTSTATUS NtOpenKey(PHANDLE keyHandle, ACCESS_MASK desiredAccess,
                   const OBJECT_ATTRIBUTES *attributes)
{
    (void)desiredAccess;
    (void)attributes;
    if (keyHandle != 0 && NT_SUCCESS(KiProbeForWrite(keyHandle, sizeof(HANDLE), sizeof(HANDLE))))
    {
        *keyHandle = 0;
    }
    /* ntdll's load_global_options / version_init tolerate a missing key. */
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS NtQueryValueKey(HANDLE keyHandle, const UNICODE_STRING *valueName,
                         KEY_VALUE_INFORMATION_CLASS infoClass, void *information, DWORD length,
                         DWORD *resultLength)
{
    (void)keyHandle;
    (void)valueName;
    (void)infoClass;
    (void)information;
    (void)length;
    (void)resultLength;
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* --- NLS (furniture; the data files arrive with the Wine integration) ----- */

NTSTATUS NtInitializeNlsFiles(void **baseAddress, LCID *lcid, LARGE_INTEGER *size)
{
    (void)baseAddress;
    (void)lcid;
    (void)size;
    /* locale_init tolerates a failure here and continues with a degraded (but
     * non-crashing) codepage state (docs/03 M7 map); the real locale.nls
     * mapping lands with the Wine bring-up. */
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtGetNlsSectionPtr(ULONG type, ULONG codePage, PVOID contextData, PVOID *sectionPointer,
                            PSIZE_T sectionSize)
{
    (void)type;
    (void)codePage;
    (void)contextData;
    (void)sectionPointer;
    (void)sectionSize;
    return STATUS_NOT_IMPLEMENTED;
}

/* --- volume information (RtlSetCurrentDirectory_U at startup) -------------- */

NTSTATUS NtQueryVolumeInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlock,
                                      PVOID buffer, ULONG length, FS_INFORMATION_CLASS infoClass)
{
    (void)fileHandle;
    (void)ioStatusBlock;
    if (infoClass == FileFsDeviceInformation && length >= sizeof(FILE_FS_DEVICE_INFORMATION))
    {
        NTSTATUS status =
            KiProbeForWrite(buffer, sizeof(FILE_FS_DEVICE_INFORMATION), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        FILE_FS_DEVICE_INFORMATION info;
        memset(&info, 0, sizeof(info));
        info.DeviceType = FILE_DEVICE_DISK;
        memcpy(buffer, &info, sizeof(info));
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_IMPLEMENTED;
}

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
