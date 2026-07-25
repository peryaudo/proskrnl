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
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);

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
