/*
 * sem_ps/create_process.c — CreateProcessW end-to-end (M10).
 *
 * The whole point of M10's NtCreateUserProcess rework: kernelbase's
 * CreateProcessInternalW (third_party/wine dlls/kernelbase/process.c) builds
 * a normalized RTL_USER_PROCESS_PARAMETERS block (command line, environment,
 * cwd, title), passes it to NtCreateUserProcess with the initial thread
 * CREATE_SUSPENDED, and resumes it after wiring the handles. The child must
 * observe every one of those values — a kernel that rebuilds default params
 * (the M8 shape) silently drops them all.
 *
 * Parent/child protocol: this same .exe re-executes itself with a --child
 * marker; the child asserts its inherited state silently and encodes the
 * results in its EXIT CODE (0x40 | bitmask), which the parent asserts.
 */
#include "util.h"

#define CHILD_BASE    0x40
#define CHILD_ENV     0x01
#define CHILD_CWD     0x02
#define CHILD_CMDLINE 0x04
#define CHILD_TITLE   0x08
#define CHILD_ALL     (CHILD_BASE | CHILD_ENV | CHILD_CWD | CHILD_CMDLINE | CHILD_TITLE)

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

static int wstr_equal(const WCHAR *a, const WCHAR *b)
{
    while (*a && *a == *b)
    {
        a++;
        b++;
    }
    return *a == *b;
}

/* The child: silent; result bits in the exit code. */
static void child_main(void)
{
    UINT code = CHILD_BASE;
    WCHAR buffer[512];

    if (GetEnvironmentVariableW(L"PRSTEST_MARKER", buffer, 512) && wstr_equal(buffer, L"42"))
        code |= CHILD_ENV;
    if (GetCurrentDirectoryW(512, buffer) &&
        (wstr_equal(buffer, L"C:\\prstest") || wstr_equal(buffer, L"C:\\prstest\\")))
        code |= CHILD_CWD;
    if (wstr_contains(GetCommandLineW(), L"--child payload-argument"))
        code |= CHILD_CMDLINE;
    STARTUPINFOW si;
    GetStartupInfoW(&si);
    if (si.lpTitle && wstr_equal(si.lpTitle, L"prstest-title"))
        code |= CHILD_TITLE;
    ExitProcess(code);
}

START_TEST(create_process)
{
    if (wstr_contains(GetCommandLineW(), L"--child"))
        child_main(); /* never returns */

    WCHAR self[512];
    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    CreateDirectoryW(L"C:\\prstest", NULL);

    /* --- the full plumbing: cmdline, env, cwd, title, exit code ------------ */
    WCHAR cmdline[600];
    {
        int n = 0;
        cmdline[n++] = '"';
        for (int i = 0; self[i]; i++)
            cmdline[n++] = self[i];
        cmdline[n] = 0;
        const WCHAR *tail = L"\" --child payload-argument";
        for (int i = 0; tail[i]; i++)
            cmdline[n + i] = tail[i], cmdline[n + i + 1] = 0;
    }
    /* CREATE_UNICODE_ENVIRONMENT block: the marker + SystemRoot (ntdll reads
     * it during startup on both runners). */
    WCHAR env[] = L"PRSTEST_MARKER=42\0SystemRoot=C:\\windows\0";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpTitle = (WCHAR *)L"prstest-title";
    BOOL created = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, env,
                                  L"C:\\prstest", &si, &pi);
    ok(created, "CreateProcessW -> %lu", (unsigned long)GetLastError());
    if (created)
    {
        ok(pi.dwProcessId != 0 && pi.dwProcessId != GetCurrentProcessId(),
           "child pid %lu (self %lu)", (unsigned long)pi.dwProcessId,
           (unsigned long)GetCurrentProcessId());
        ok(pi.dwThreadId != 0, "child tid");
        ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "child wait");
        DWORD code = 0;
        ok(GetExitCodeProcess(pi.hProcess, &code), "GetExitCodeProcess -> %lu",
           (unsigned long)GetLastError());
        ok(code == CHILD_ALL, "child observed %02lx, want %02x", (unsigned long)code, CHILD_ALL);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    /* --- CREATE_SUSPENDED gates execution ---------------------------------- */
    created = CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                             CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, env, L"C:\\prstest",
                             &si, &pi);
    ok(created, "CreateProcessW suspended -> %lu", (unsigned long)GetLastError());
    if (created)
    {
        ok(WaitForSingleObject(pi.hProcess, 200) == WAIT_TIMEOUT, "suspended child ran");
        DWORD code = 0;
        ok(GetExitCodeProcess(pi.hProcess, &code) && code == STILL_ACTIVE,
           "suspended child not STILL_ACTIVE (%08lx)", (unsigned long)code);
        ok(ResumeThread(pi.hThread) == 1, "ResumeThread");
        ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "resumed child wait");
        ok(GetExitCodeProcess(pi.hProcess, &code) && code == CHILD_ALL,
           "resumed child observed %02lx", (unsigned long)code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    /* --- error shapes ------------------------------------------------------- */
    /* A non-PE file: STATUS_INVALID_IMAGE_NOT_MZ -> ERROR_BAD_EXE_FORMAT
     * (this is also what routes .bat files to cmd.exe — CreateProcessInternalW
     * retries only for recognized extensions). */
    HANDLE file = CreateFileW(L"C:\\prstest\\notape.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    ok(file != INVALID_HANDLE_VALUE, "create notape.txt");
    DWORD written;
    WriteFile(file, "just text\r\n", 11, &written, NULL);
    CloseHandle(file);
    WCHAR badcmd[] = L"C:\\prstest\\notape.txt";
    created = CreateProcessW(NULL, badcmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ok(!created, "text file created a process");
    ok(GetLastError() == ERROR_BAD_EXE_FORMAT, "text file -> %lu", (unsigned long)GetLastError());
    DeleteFileW(L"C:\\prstest\\notape.txt");

    WCHAR misscmd[] = L"C:\\prstest\\no-such-program.exe";
    created = CreateProcessW(NULL, misscmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ok(!created, "missing image created a process");
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "missing image -> %lu",
       (unsigned long)GetLastError());
}
