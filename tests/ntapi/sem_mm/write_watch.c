/*
 * sem_mm/write_watch.c — NtGetWriteWatch / NtResetWriteWatch (CUI-7).
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/virtual.c NtGetWriteWatch / NtResetWriteWatch — real
 * implementations, fully differential; the user-facing expectations match
 * wine dlls/kernel32/tests/virtual.c's write-watch block re-expressed at
 * the Nt layer):
 *
 *   - The validation ladder, in order: NULL count or granularity ->
 *     STATUS_ACCESS_VIOLATION; zero *count or zero size ->
 *     STATUS_INVALID_PARAMETER; flags beyond WRITE_WATCH_FLAG_RESET ->
 *     STATUS_INVALID_PARAMETER; NULL addresses -> STATUS_ACCESS_VIOLATION;
 *     a range not inside one MEM_WRITE_WATCH region ->
 *     STATUS_INVALID_PARAMETER.
 *   - Written pages report in ascending page order, granularity 0x1000;
 *     *count is in/out and bounds the scan: WRITE_WATCH_FLAG_RESET re-arms
 *     only the SCANNED subrange [base, last-visited), so overflowed dirty
 *     pages stay dirty. A plain get does not consume.
 *   - NtResetWriteWatch re-arms the whole range (zero size ->
 *     INVALID_PARAMETER, non-watch range -> INVALID_PARAMETER).
 *   - NtProtectVirtualMemory does not disturb the watch, and the reported
 *     protection of a watched page is its true protection (the write-watch
 *     write-protection is invisible).
 *   - KERNEL-side writes mark too: NtWriteVirtualMemory into one's own
 *     watched page, and a syscall out-buffer (NtQueryVirtualMemory) placed
 *     inside a watched page, both report the page written.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtGetWriteWatch(HANDLE, ULONG, PVOID, SIZE_T, PVOID *, ULONG_PTR *,
                                        ULONG *);
NTSYSAPI NTSTATUS NTAPI NtResetWriteWatch(HANDLE, PVOID, SIZE_T);
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);

#ifndef MEM_WRITE_WATCH
#define MEM_WRITE_WATCH 0x00200000
#endif
#ifndef WRITE_WATCH_FLAG_RESET
#define WRITE_WATCH_FLAG_RESET 0x00000001
#endif

#define WATCH_PAGES 4

START_TEST(write_watch)
{
    NTSTATUS status;
    PVOID base = NULL;
    SIZE_T size = WATCH_PAGES * 0x1000;
    PVOID addresses[WATCH_PAGES + 1];
    ULONG_PTR count;
    ULONG granularity;
    unsigned char *bytes;

    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                     MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "watch alloc -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    bytes = base;

    /* --- the validation ladder --------------------------------------------- */
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, NULL, &granularity);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL count -> %08lx", (unsigned long)status);
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL granularity -> %08lx", (unsigned long)status);
    count = 0;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_INVALID_PARAMETER, "zero count -> %08lx", (unsigned long)status);
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, 0, addresses, &count, &granularity);
    ok(status == STATUS_INVALID_PARAMETER, "zero size -> %08lx", (unsigned long)status);
    status = NtGetWriteWatch(NtCurrentProcess(), 2, base, size, addresses, &count, &granularity);
    ok(status == STATUS_INVALID_PARAMETER, "bad flags -> %08lx", (unsigned long)status);
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, NULL, &count, &granularity);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL addresses -> %08lx", (unsigned long)status);
    {
        PVOID plain = NULL;
        SIZE_T plainSize = 0x1000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &plain, 0, &plainSize,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "plain alloc -> %08lx", (unsigned long)status);
        count = WATCH_PAGES;
        status = NtGetWriteWatch(NtCurrentProcess(), 0, plain, plainSize, addresses, &count,
                                 &granularity);
        ok(status == STATUS_INVALID_PARAMETER, "non-watch range -> %08lx", (unsigned long)status);
        status = NtResetWriteWatch(NtCurrentProcess(), plain, plainSize);
        ok(status == STATUS_INVALID_PARAMETER, "reset non-watch -> %08lx", (unsigned long)status);
        plainSize = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &plain, &plainSize, MEM_RELEASE);
    }
    status = NtResetWriteWatch(NtCurrentProcess(), base, 0);
    ok(status == STATUS_INVALID_PARAMETER, "reset zero size -> %08lx", (unsigned long)status);

    /* --- fresh region reports nothing --------------------------------------- */
    count = WATCH_PAGES;
    granularity = 0;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_SUCCESS, "initial get -> %08lx", (unsigned long)status);
    ok(count == 0, "initially clean (%lu)", (unsigned long)count);
    ok(granularity == 0x1000, "granularity %lu", (unsigned long)granularity);

    /* --- ring-3 writes report ascending; a plain get does not consume ------- */
    bytes[0 * 0x1000] = 1;
    bytes[2 * 0x1000] = 1;
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_SUCCESS, "get after writes -> %08lx", (unsigned long)status);
    ok(count == 2, "two dirty (%lu)", (unsigned long)count);
    ok(addresses[0] == bytes && addresses[1] == bytes + 2 * 0x1000, "ascending (%p %p)",
       addresses[0], addresses[1]);
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_SUCCESS && count == 2, "plain get did not consume (%lu)",
       (unsigned long)count);

    /* --- the count-limited scan + partial reset ------------------------------ */
    bytes[1 * 0x1000] = 1;
    bytes[3 * 0x1000] = 1; /* all four dirty now */
    count = 2;
    status = NtGetWriteWatch(NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, base, size, addresses,
                             &count, &granularity);
    ok(status == STATUS_SUCCESS, "partial reset get -> %08lx", (unsigned long)status);
    ok(count == 2 && addresses[0] == bytes && addresses[1] == bytes + 0x1000,
       "first two reported (%lu %p %p)", (unsigned long)count, addresses[0], addresses[1]);
    /* Only the scanned subrange was re-armed: pages 2 and 3 stay dirty. */
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_SUCCESS, "get after partial reset -> %08lx", (unsigned long)status);
    ok(count == 2 && addresses[0] == bytes + 2 * 0x1000 && addresses[1] == bytes + 3 * 0x1000,
       "tail stayed dirty (%lu %p %p)", (unsigned long)count, addresses[0], addresses[1]);

    /* --- the full reset ------------------------------------------------------ */
    status = NtResetWriteWatch(NtCurrentProcess(), base, size);
    ok(status == STATUS_SUCCESS, "reset -> %08lx", (unsigned long)status);
    count = WATCH_PAGES;
    status = NtGetWriteWatch(NtCurrentProcess(), 0, base, size, addresses, &count, &granularity);
    ok(status == STATUS_SUCCESS && count == 0, "clean after reset (%lu)", (unsigned long)count);

    /* --- protection changes do not disturb the watch ------------------------- */
    {
        PVOID protBase = base;
        SIZE_T protSize = 0x1000;
        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_READONLY,
                                        &oldProtect);
        ok(status == STATUS_SUCCESS && oldProtect == PAGE_READWRITE, "protect ro -> %08lx (%lx)",
           (unsigned long)status, (unsigned long)oldProtect);
        status = NtProtectVirtualMemory(NtCurrentProcess(), &protBase, &protSize, PAGE_READWRITE,
                                        &oldProtect);
        ok(status == STATUS_SUCCESS && oldProtect == PAGE_READONLY, "protect rw -> %08lx (%lx)",
           (unsigned long)status, (unsigned long)oldProtect);
        bytes[0] = 2;
        count = WATCH_PAGES;
        status = NtGetWriteWatch(NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, base, size, addresses,
                                 &count, &granularity);
        ok(status == STATUS_SUCCESS && count == 1 && addresses[0] == bytes,
           "watch survived protect (%lu)", (unsigned long)count);
    }

    /* --- the reported protection is the true one ----------------------------- */
    {
        MEMORY_BASIC_INFORMATION info;
        SIZE_T returned = 0;
        status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, &info,
                                      sizeof(info), &returned);
        ok(status == STATUS_SUCCESS, "query -> %08lx", (unsigned long)status);
        ok(info.Protect == PAGE_READWRITE, "reported protect %lx", (unsigned long)info.Protect);
        ok(info.State == MEM_COMMIT, "reported state %lx", (unsigned long)info.State);
    }

    /* --- kernel-side writes mark too ----------------------------------------- */
    {
        static const unsigned char payload[4] = {1, 2, 3, 4};
        SIZE_T written = 0;
        status = NtWriteVirtualMemory(NtCurrentProcess(), bytes + 1 * 0x1000, payload,
                                      sizeof(payload), &written);
        ok(status == STATUS_SUCCESS && written == sizeof(payload), "write vm -> %08lx",
           (unsigned long)status);
        count = WATCH_PAGES;
        status = NtGetWriteWatch(NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, base, size, addresses,
                                 &count, &granularity);
        ok(status == STATUS_SUCCESS && count == 1 && addresses[0] == bytes + 0x1000,
           "NtWriteVirtualMemory marked (%lu)", (unsigned long)count);

        /* A syscall writing its out-buffer into a watched page marks it. */
        MEMORY_BASIC_INFORMATION *info = (MEMORY_BASIC_INFORMATION *)(bytes + 2 * 0x1000);
        SIZE_T returned = 0;
        status = NtQueryVirtualMemory(NtCurrentProcess(), base, MEMORY_BASIC_INFO_CLASS, info,
                                      sizeof(*info), &returned);
        ok(status == STATUS_SUCCESS, "query into watch -> %08lx", (unsigned long)status);
        count = WATCH_PAGES;
        status = NtGetWriteWatch(NtCurrentProcess(), WRITE_WATCH_FLAG_RESET, base, size, addresses,
                                 &count, &granularity);
        ok(status == STATUS_SUCCESS && count == 1 && addresses[0] == bytes + 2 * 0x1000,
           "syscall out-buffer marked (%lu)", (unsigned long)count);
    }

    /* --- a watched reservation watches later commits ------------------------- */
    {
        PVOID reserved = NULL;
        SIZE_T reservedSize = 2 * 0x1000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &reserved, 0, &reservedSize,
                                         MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "watch reserve -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            PVOID commitBase = reserved;
            SIZE_T commitSize = 0x1000;
            status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitBase, 0, &commitSize,
                                             MEM_COMMIT, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "commit into watch -> %08lx", (unsigned long)status);
            *(volatile unsigned char *)reserved = 7;
            count = WATCH_PAGES;
            status = NtGetWriteWatch(NtCurrentProcess(), 0, reserved, 0x1000, addresses, &count,
                                     &granularity);
            ok(status == STATUS_SUCCESS && count == 1 && addresses[0] == reserved,
               "late commit watched (%lu)", (unsigned long)count);
            reservedSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &reserved, &reservedSize, MEM_RELEASE);
        }
    }

    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "free watch -> %08lx", (unsigned long)status);
}
