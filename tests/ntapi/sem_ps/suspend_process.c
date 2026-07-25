/*
 * sem_ps/suspend_process.c — NtSuspendProcess / NtResumeProcess.
 *
 * Suspends every thread of a target process; the suspension takes effect at
 * each thread's next return to user mode (server/process.c suspend_process
 * over the unix-signal suspend). Observed behaviourally: a child appending to
 * a file in a loop stops advancing while suspended and resumes after — then
 * finishes its bounded run on its own (foreign terminate is a later CUI-4
 * commit, so the pin must not depend on it). Green on the pinned Wine oracle
 * first (Art. 5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtResumeProcess(HANDLE);

/* Local wide helpers: -nostdlib, no CRT wcs* / user32 wsprintfW. */
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

#define VMSUSP_ITERS 200
#define VMSUSP_PATH  L"C:\\suspproc.dat"

static ULONGLONG file_size(void)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(VMSUSP_PATH, GetFileExInfoStandard, &data))
        return 0;
    return ((ULONGLONG)data.nFileSizeHigh << 32) | data.nFileSizeLow;
}

static void child_main(void)
{
    for (int i = 0; i < VMSUSP_ITERS; i++)
    {
        HANDLE h = CreateFileW(VMSUSP_PATH, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD wrote = 0;
            const char byte = 'x';
            WriteFile(h, &byte, 1, &wrote, NULL);
            CloseHandle(h);
        }
        Sleep(20);
    }
    ExitProcess(0);
}

START_TEST(suspend_process)
{
    if (wstr_contains(GetCommandLineW(), L"--susp-child"))
        child_main(); /* never returns meaningfully */

    DeleteFileW(VMSUSP_PATH);

    WCHAR self[512];
    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    WCHAR cmdline[600];
    int n = 0;
    cmdline[n++] = L'"';
    for (int i = 0; self[i] && n < 560; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    const WCHAR *tail = L" --susp-child";
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
    if (!pi.hProcess)
        return;

    /* Let it get going, then freeze it. */
    Sleep(250);
    ULONGLONG before = file_size();

    NTSTATUS status = NtSuspendProcess(pi.hProcess);
    ok(status == STATUS_SUCCESS, "suspend -> %08lx", (unsigned long)status);

    /* While suspended the child makes at most an in-flight iteration or two;
     * an unsuspended child would add ~20 in this window. */
    Sleep(500);
    ULONGLONG frozen = file_size();
    ok(frozen - before <= 5, "suspended child advanced %llu bytes",
       (unsigned long long)(frozen - before));

    /* Resume: it makes progress again. */
    status = NtResumeProcess(pi.hProcess);
    ok(status == STATUS_SUCCESS, "resume -> %08lx", (unsigned long)status);

    ok(WaitForSingleObject(pi.hProcess, 20000) == WAIT_OBJECT_0, "child ran to completion");
    ULONGLONG done = file_size();
    ok(done > frozen, "child made no progress after resume (%llu -> %llu)",
       (unsigned long long)frozen, (unsigned long long)done);

    NtClose(pi.hProcess);
    NtClose(pi.hThread);
    DeleteFileW(VMSUSP_PATH);
}
