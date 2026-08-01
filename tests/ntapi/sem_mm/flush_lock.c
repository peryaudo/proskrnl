/*
 * sem_mm/flush_lock.c — NtFlushVirtualMemory, NtLock/UnlockVirtualMemory
 * and NtSetInformationVirtualMemory (CUI-7).
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/virtual.c NtFlushVirtualMemory / NtLockVirtualMemory /
 * NtUnlockVirtualMemory / NtSetInformationVirtualMemory + prefetch_memory):
 *
 *   - Flush: an address outside any region -> STATUS_INVALID_PARAMETER; a
 *     zero in/out size comes back as the WHOLE region's size and the
 *     address rounds down to the page; the IOSB is accepted and never
 *     written; a file-backed view flushes SUCCESS (under Art. 3 the cache
 *     is written through, so proskrnl's flush routes the covered bytes to
 *     the FS writeback — strictly stronger, same observable).
 *   - Lock/unlock round the range and echo it back; a committed,
 *     accessible range succeeds (mlock on the oracle, a validating no-op
 *     on proskrnl — everything is resident, docs/03); reserved-only or
 *     unmapped ranges are STATUS_ACCESS_DENIED (the oracle's mlock cannot
 *     populate PROT_NONE). The fourth argument is ignored.
 *   - SetInformationVirtualMemory, VmPrefetchInformation: NULL flags ptr ->
 *     STATUS_INVALID_PARAMETER_5, wrong flags size -> _6, zero count ->
 *     _3, a zero-length range entry -> _4; otherwise SUCCESS without
 *     validating the addresses (an unmapped range prefetches fine).
 *     VmPageDirtyStateInformation -> STATUS_NOT_SUPPORTED; an unknown
 *     class -> STATUS_INVALID_PARAMETER_2.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE, LPCVOID *, SIZE_T *, PVOID);
NTSYSAPI NTSTATUS NTAPI NtLockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnlockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtSetInformationVirtualMemory(HANDLE, ULONG, ULONG_PTR, PVOID, PVOID,
                                                      ULONG);

/* VIRTUAL_MEMORY_INFORMATION_CLASS values (wine/include/winternl.h). */
#define VM_PREFETCH_INFO         0
#define VM_PAGE_DIRTY_STATE_INFO 3

typedef struct
{
    PVOID virtual_address;
    SIZE_T number_of_bytes;
} mm_range_entry;

START_TEST(flush_lock)
{
    NTSTATUS status;
    PVOID base = NULL;
    SIZE_T size = 3 * 0x1000;
    LPCVOID flushAddr;
    SIZE_T flushSize;
    unsigned char iosb[16];
    unsigned i;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "alloc -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* --- flush ladder + rounding echo --------------------------------------- */
    flushAddr = (LPCVOID)(ULONG_PTR)0x1000; /* far below any region */
    flushSize = 0x1000;
    status = NtFlushVirtualMemory(NtCurrentProcess(), &flushAddr, &flushSize, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "flush unmapped -> %08lx", (unsigned long)status);

    for (i = 0; i < sizeof(iosb); i++)
        iosb[i] = 0xa5;
    flushAddr = (const unsigned char *)base + 0x10;
    flushSize = 0;
    status = NtFlushVirtualMemory(NtCurrentProcess(), &flushAddr, &flushSize, iosb);
    ok(status == STATUS_SUCCESS, "flush anon -> %08lx", (unsigned long)status);
    ok(flushAddr == base, "flush addr rounded (%p)", flushAddr);
    ok(flushSize == 3 * 0x1000, "flush size is the whole region (%lx)", (unsigned long)flushSize);
    for (i = 0; i < sizeof(iosb); i++)
    {
        if (iosb[i] != 0xa5)
            break;
    }
    ok(i == sizeof(iosb), "flush IOSB untouched (byte %u)", i);

    flushAddr = base;
    flushSize = 0x1000;
    status = NtFlushVirtualMemory(NtCurrentProcess(), &flushAddr, &flushSize, NULL);
    ok(status == STATUS_SUCCESS && flushSize == 0x1000, "flush partial -> %08lx (%lx)",
       (unsigned long)status, (unsigned long)flushSize);

    /* --- a file-backed view flushes ----------------------------------------- */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        IO_STATUS_BLOCK fileIosb;
        HANDLE file = NULL, section = NULL;
        static const char seed[0x1000] = "flush me";
        init_ustr(&name, W("\\??\\C:\\prsk_mm_flush.tmp"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &fileIosb,
                              NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                              FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        ok(status == STATUS_SUCCESS, "create file -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            status = NtWriteFile(file, NULL, NULL, NULL, &fileIosb, seed, sizeof(seed), NULL, NULL);
            ok(status == STATUS_SUCCESS, "seed file -> %08lx", (unsigned long)status);
            status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE,
                                     SEC_COMMIT, file);
            ok(status == STATUS_SUCCESS, "file section -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                PVOID view = NULL;
                SIZE_T viewSize = 0;
                status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, NULL,
                                            &viewSize, ViewShare, 0, PAGE_READWRITE);
                ok(status == STATUS_SUCCESS, "map file view -> %08lx", (unsigned long)status);
                if (NT_SUCCESS(status))
                {
                    *(volatile unsigned char *)view = 'F';
                    flushAddr = view;
                    flushSize = 0;
                    status = NtFlushVirtualMemory(NtCurrentProcess(), &flushAddr, &flushSize, NULL);
                    ok(status == STATUS_SUCCESS, "flush file view -> %08lx", (unsigned long)status);
                    ok(flushSize != 0, "flush file view size (%lx)", (unsigned long)flushSize);
                    NtUnmapViewOfSection(NtCurrentProcess(), view);
                }
                NtClose(section);
            }
            NtClose(file);
            /* delete the scratch file */
            status = NtCreateFile(&file, DELETE | SYNCHRONIZE, &attr, &fileIosb, NULL,
                                  FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN,
                                  FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE |
                                      FILE_SYNCHRONOUS_IO_NONALERT,
                                  NULL, 0);
            if (NT_SUCCESS(status))
                NtClose(file);
        }
    }

    /* --- lock/unlock --------------------------------------------------------- */
    {
        PVOID lockAddr = (unsigned char *)base + 0x10;
        SIZE_T lockSize = 0x20;
        status = NtLockVirtualMemory(NtCurrentProcess(), &lockAddr, &lockSize, 1 /* ignored */);
        ok(status == STATUS_SUCCESS, "lock -> %08lx", (unsigned long)status);
        ok(lockAddr == base && lockSize == 0x1000, "lock rounded (%p %lx)", lockAddr,
           (unsigned long)lockSize);
        status = NtUnlockVirtualMemory(NtCurrentProcess(), &lockAddr, &lockSize, 1);
        ok(status == STATUS_SUCCESS, "unlock -> %08lx", (unsigned long)status);

        /* Reserved-only memory refuses: the oracle's mlock cannot populate
         * PROT_NONE, and proskrnl's committed-and-accessible rule mirrors
         * that. */
        {
            PVOID reserved = NULL;
            SIZE_T reservedSize = 0x1000;
            status = NtAllocateVirtualMemory(NtCurrentProcess(), &reserved, 0, &reservedSize,
                                             MEM_RESERVE, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "reserve -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                PVOID r = reserved;
                SIZE_T rs = 0x1000;
                status = NtLockVirtualMemory(NtCurrentProcess(), &r, &rs, 1);
                ok(status == STATUS_ACCESS_DENIED, "lock reserved -> %08lx",
                   (unsigned long)status);
                reservedSize = 0;
                NtFreeVirtualMemory(NtCurrentProcess(), &reserved, &reservedSize, MEM_RELEASE);
            }
        }

        /* A range touching unmapped space refuses. */
        lockAddr = (PVOID)(ULONG_PTR)0x1000;
        lockSize = 0x1000;
        status = NtLockVirtualMemory(NtCurrentProcess(), &lockAddr, &lockSize, 0);
        ok(status == STATUS_ACCESS_DENIED, "lock unmapped -> %08lx", (unsigned long)status);
        lockAddr = (PVOID)(ULONG_PTR)0x1000;
        lockSize = 0x1000;
        status = NtUnlockVirtualMemory(NtCurrentProcess(), &lockAddr, &lockSize, 0);
        ok(status == STATUS_ACCESS_DENIED, "unlock unmapped -> %08lx", (unsigned long)status);
    }

    /* --- SetInformationVirtualMemory ----------------------------------------- */
    {
        mm_range_entry ranges[2];
        ULONG flags = 0;
        ranges[0].virtual_address = base;
        ranges[0].number_of_bytes = 0x1000;
        ranges[1].virtual_address = (PVOID)(ULONG_PTR)0x30000000; /* unmapped: fine */
        ranges[1].number_of_bytes = 0x1000;

        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PREFETCH_INFO, 2, ranges,
                                               NULL, sizeof(flags));
        ok(status == STATUS_INVALID_PARAMETER_5, "prefetch NULL flags -> %08lx",
           (unsigned long)status);
        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PREFETCH_INFO, 2, ranges,
                                               &flags, 2);
        ok(status == STATUS_INVALID_PARAMETER_6, "prefetch bad flags size -> %08lx",
           (unsigned long)status);
        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PREFETCH_INFO, 0, ranges,
                                               &flags, sizeof(flags));
        ok(status == STATUS_INVALID_PARAMETER_3, "prefetch zero count -> %08lx",
           (unsigned long)status);
        ranges[1].number_of_bytes = 0;
        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PREFETCH_INFO, 2, ranges,
                                               &flags, sizeof(flags));
        ok(status == STATUS_INVALID_PARAMETER_4, "prefetch empty range -> %08lx",
           (unsigned long)status);
        ranges[1].number_of_bytes = 0x1000;
        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PREFETCH_INFO, 2, ranges,
                                               &flags, sizeof(flags));
        ok(status == STATUS_SUCCESS, "prefetch -> %08lx", (unsigned long)status);

        status = NtSetInformationVirtualMemory(NtCurrentProcess(), VM_PAGE_DIRTY_STATE_INFO, 1,
                                               ranges, &flags, sizeof(flags));
        ok(status == STATUS_NOT_SUPPORTED, "page dirty state -> %08lx", (unsigned long)status);
        status =
            NtSetInformationVirtualMemory(NtCurrentProcess(), 99, 1, ranges, &flags, sizeof(flags));
        ok(status == STATUS_INVALID_PARAMETER_2, "unknown class -> %08lx", (unsigned long)status);
    }

    size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
}
