/*
 * sem_ps/virtual_memory.c — NtRead/WriteVirtualMemory.
 *
 * The cross-process memory surface toolhelp/debug readers use. Contract from
 * ntdll's unix side (dlls/ntdll/unix/virtual.c): a self read is a memmove
 * whose fault path is STATUS_PARTIAL_COPY with bytes_read 0; a foreign read
 * copies out of the target address space; bytes_read/bytes_written report the
 * amount moved. The cross-process read is exercised against the child's PEB,
 * whose address the parent learns from ProcessBasicInformation (so the test
 * is independent of ASLR). Green on the pinned Wine oracle first (Art. 5).
 *
 * THE PARTIAL COPY IS NOT SYMMETRIC, and that asymmetry is what
 * kernel32:virtual:261 and :275 convict. Both syscalls answer
 * STATUS_PARTIAL_COPY when the range runs into memory they cannot touch, but
 * they report DIFFERENT counts, because the reporting lives on the PE side and
 * only one of the two arms keeps the server's number (third_party/wine
 * dlls/ntdll/unix/virtual.c):
 *
 *   NtWriteVirtualMemory:  size = reply->written;   ...  *bytes_written = size;
 *   NtReadVirtualMemory:   if ((status = wine_server_call( req ))) size = 0;
 *
 * — so a failed READ always reports zero and a failed WRITE reports the prefix
 * it managed. The server's own count is the byte count, not a page count
 * (server/ptrace.c write_process_memory_vm: `*written = max( len, 0 )` off
 * process_vm_writev), so a write that starts mid-page and runs into a
 * read-only page reports the bytes up to that page and not a rounded figure.
 * An implementation that zeroes both — proskrnl did, by writing the slot only
 * on full success — is right about every status here and wrong about every
 * count.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);

/* Four pages, the second half re-protected so a copy across the middle has to
 * stop there. `arm` names the handle the caller is driving the syscalls
 * through: the pseudo-handle takes the oracle's own-process path and a real
 * handle to ourselves takes the same server round trip a foreign target does,
 * so "both arms agree" stays a measurement (docs/21 §4 trap 4).
 */
static void test_partial_counts(HANDLE process, const char *arm)
{
    unsigned char source[0x4000];
    unsigned char sink[0x4000];
    NTSTATUS status;
    ULONG oldProtect;
    SIZE_T moved, size;
    PVOID base, addr;

    base = NULL;
    size = sizeof(source);
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "%s: commit 4 pages -> %08lx", arm, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    memset(source, 0x5a, sizeof(source));

    /* --- the WRITE side: the prefix is reported ------------------------- */
    addr = (char *)base + 0x2000;
    size = 0x2000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READONLY, &oldProtect);
    ok(status == STATUS_SUCCESS, "%s: protect the tail read-only -> %08lx", arm,
       (unsigned long)status);

    moved = 0xdeadbeef;
    status = NtWriteVirtualMemory(process, base, source, 0x4000, &moved);
    ok(status == STATUS_PARTIAL_COPY, "%s: write across the boundary -> %08lx", arm,
       (unsigned long)status);
    ok(moved == 0x2000, "%s: partial write reports %llx, expected 2000", arm,
       (unsigned long long)moved);

    /* The count is in BYTES, not whole pages: start 0x10 short of the
     * boundary and only those 0x10 bytes can land. A page-granular
     * implementation reports 0 here and passes the case above.
     *
     * MEASURED, and worth saying because the oracle's own documentation
     * points the other way: process_vm_writev(2) states that partial
     * transfers apply at iovec granularity and that a single element is
     * never split, while the server passes this whole 0x1010-byte request
     * as ONE element (server/ptrace.c write_process_memory_vm) and Linux
     * reports 0x10. NT's STATUS_PARTIAL_COPY contract is byte-accurate, so
     * if a future host ever rounds this to 0 the ORACLE has moved away from
     * NT and this case belongs in a beyond_oracle block — not the kernel. */
    moved = 0xdeadbeef;
    status = NtWriteVirtualMemory(process, (char *)base + 0x1ff0, source, 0x1010, &moved);
    ok(status == STATUS_PARTIAL_COPY, "%s: unaligned write across the boundary -> %08lx", arm,
       (unsigned long)status);
    ok(moved == 0x10, "%s: unaligned partial write reports %llx, expected 10", arm,
       (unsigned long long)moved);

    /* Nothing writable at all: PARTIAL_COPY with a count of zero, which is
     * the case a "report the prefix" implementation must not turn into a
     * success. */
    moved = 0xdeadbeef;
    status = NtWriteVirtualMemory(process, (char *)base + 0x2000, source, 0x2000, &moved);
    ok(status == STATUS_PARTIAL_COPY, "%s: write into read-only memory -> %08lx", arm,
       (unsigned long)status);
    ok(moved == 0, "%s: fully refused write reports %llx", arm, (unsigned long long)moved);

    /* The success control: without it every count above would also pass on a
     * kernel that reported the prefix and never completed anything. */
    moved = 0xdeadbeef;
    status = NtWriteVirtualMemory(process, base, source, 0x2000, &moved);
    ok(status == STATUS_SUCCESS, "%s: write inside the writable half -> %08lx", arm,
       (unsigned long)status);
    ok(moved == 0x2000, "%s: full write reports %llx", arm, (unsigned long long)moved);

    /* --- the READ side: zero, always ------------------------------------ */
    addr = (char *)base + 0x2000;
    size = 0x2000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_NOACCESS, &oldProtect);
    ok(status == STATUS_SUCCESS, "%s: protect the tail no-access -> %08lx", arm,
       (unsigned long)status);

    memset(sink, 0, sizeof(sink));
    moved = 0xdeadbeef;
    status = NtReadVirtualMemory(process, base, sink, 0x4000, &moved);
    ok(status == STATUS_PARTIAL_COPY, "%s: read across the boundary -> %08lx", arm,
       (unsigned long)status);
    ok(moved == 0, "%s: partial read reports %llx, expected 0", arm, (unsigned long long)moved);

    size = 0;
    addr = base;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
}

/* Local wide-string helpers: the harness is -nostdlib and links only
 * ntdll/kernel32/kernelbase, so no CRT wcs* / user32 wsprintfW. */
static int wstr_contains(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return 1;
    }
    return 0;
}

static void child_main(void)
{
    /* Idle long enough for the parent to read our address space, then exit on
     * our own — the parent joins us (foreign terminate is a later CUI-4
     * commit, so the pin must not depend on it). The bounded sleep keeps the
     * suite finite. */
    Sleep(2000);
    ExitProcess(0);
}

START_TEST(virtual_memory)
{
    if (wstr_contains(GetCommandLineW(), L"--vm-child"))
        child_main(); /* never returns meaningfully */

    NTSTATUS status;
    SIZE_T moved;

    /* --- self read: a plain memmove ------------------------------------- */
    unsigned char source[64];
    unsigned char sink[64];
    for (int i = 0; i < 64; i++)
        source[i] = (unsigned char)(i * 7 + 1);
    memset(sink, 0, sizeof(sink));
    moved = 0;
    status = NtReadVirtualMemory(NtCurrentProcess(), source, sink, sizeof(source), &moved);
    ok(status == STATUS_SUCCESS, "self read -> %08lx", (unsigned long)status);
    ok(moved == sizeof(source), "self read moved %lu", (unsigned long)moved);
    ok(memcmp(source, sink, sizeof(source)) == 0, "self read content mismatch");

    /* --- self write ----------------------------------------------------- */
    unsigned char dest[64];
    memset(dest, 0, sizeof(dest));
    moved = 0;
    status = NtWriteVirtualMemory(NtCurrentProcess(), dest, source, sizeof(source), &moved);
    ok(status == STATUS_SUCCESS, "self write -> %08lx", (unsigned long)status);
    ok(moved == sizeof(source), "self write moved %lu", (unsigned long)moved);
    ok(memcmp(source, dest, sizeof(source)) == 0, "self write content mismatch");

    /* --- self read from an unmapped source: STATUS_PARTIAL_COPY --------- */
    moved = 0xdead;
    status =
        NtReadVirtualMemory(NtCurrentProcess(), (const void *)(ULONG_PTR)0x1000, sink, 16, &moved);
    ok(status == STATUS_PARTIAL_COPY, "read of an unmapped page -> %08lx", (unsigned long)status);
    ok(moved == 0, "failed read reports %lu bytes", (unsigned long)moved);

    /* --- the partial-copy COUNTS, through both handle arms --------------- */
    test_partial_counts(NtCurrentProcess(), "self");
    {
        HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        ok(self != NULL, "OpenProcess(ALL_ACCESS) -> %lu", (unsigned long)GetLastError());
        if (self)
        {
            test_partial_counts(self, "remote");
            NtClose(self);
        }
    }

    /* --- cross-process read of the child's PEB -------------------------- */
    WCHAR self[512];
    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");

    /* Build "\"<self>\" --vm-child" by hand (no wsprintfW under -nostdlib). */
    WCHAR cmdline[600];
    int n = 0;
    cmdline[n++] = L'"';
    for (int i = 0; self[i] && n < 560; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    const WCHAR *tail = L" --vm-child";
    for (int i = 0; tail[i]; i++)
        cmdline[n++] = tail[i];
    cmdline[n] = 0;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi),
       "CreateProcessW child");

    if (pi.hProcess)
    {
        PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;
        status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi),
                                           &retLen);
        ok(status == STATUS_SUCCESS, "query child basic info -> %08lx", (unsigned long)status);
        ok(pbi.PebBaseAddress != NULL, "child has no PEB address");

        if (pbi.PebBaseAddress)
        {
            /* Read the first bytes of the child's PEB out of its address
             * space; the read must move the full request. */
            unsigned char pebHead[16];
            memset(pebHead, 0, sizeof(pebHead));
            moved = 0;
            status = NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, pebHead, sizeof(pebHead),
                                         &moved);
            ok(status == STATUS_SUCCESS, "cross-process read -> %08lx", (unsigned long)status);
            ok(moved == sizeof(pebHead), "cross-process read moved %lu", (unsigned long)moved);
        }

        WaitForSingleObject(pi.hProcess, 10000);
        NtClose(pi.hProcess);
        NtClose(pi.hThread);
    }
}
