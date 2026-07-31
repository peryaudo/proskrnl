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

/* The maximal-command-line child (see test_long_command_line below): the
 * length it saw and its last character are the two things that matter, so
 * they get their own bits. */
#define CHILD_LONG_BASE 0x80
#define CHILD_LONG_LEN  0x01
#define CHILD_LONG_TAIL 0x02

/* The longest process-parameter strings a CreateProcessW caller can actually
 * deliver. MEASURED against the oracle, not assumed: both the command line
 * and the window title come back clamped to 32766 characters (Length 0xFFFC)
 * however much longer the caller's buffer is, so this is the real ceiling of
 * the ring-3-reachable path.
 *
 * It matters that it is 0xFFFC and not 0xFFFE: the kernel sizes each string's
 * slot in the parameter block from (USHORT)(Length + sizeof(WCHAR)), which
 * wraps to 0 at Length 0xFFFE and to 1 at 0xFFFF. Those two lengths are one
 * and two bytes past what this test can reach, so the wrap itself is guarded
 * structurally in PspCaptureString rather than pinned here; what this pins is
 * that the largest reachable string survives the trip intact, which is the
 * regression a careless "just clamp it" fix would cause. */
#define LONG_CMDLINE_CHARS 32766
#define LONG_TITLE_CHARS   32766

/* The exit code the hostile-RSP child would report if it somehow kept
 * running. Any other code means it died, which is the point. */
#define CHILD_RSP_SURVIVED 0x55

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

/* Static, not stack: 32768 WCHARs is 64 KiB and both runners start a thread
 * on a 1 MiB stack that ntdll has already dug into. */
static WCHAR long_cmdline[LONG_CMDLINE_CHARS + 1];
static WCHAR long_title[LONG_TITLE_CHARS + 1];

static int wstr_length(const WCHAR *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

/* Fault with RSP pointing into the kernel half. The kernel must kill this
 * process; it must not write the exception frame where RSP says.
 *
 * This is the end-to-end half of the KiIsUserRange bound. The kmt case tests
 * the predicate, but nothing tested that KiMaterializeUserRange actually
 * consults it before the three frame writers memcpy -- delete the call and
 * the kmt case still passes. Here the kernel really does have to build an
 * exception frame at a ring-3-chosen RSP, which is the exploit: a user PML4
 * shares the kernel's upper half, so the page walk alone reports the target
 * present and writable, and the KiProbeForWrite alongside it is a no-op on
 * this path (previousMode is KernelMode during exception dispatch).
 *
 * Run in a child so the failure is observable: on a kernel without the bound
 * this halts the machine, and the parent's verdict never prints at all. */
static void child_bad_rsp_main(void)
{
    __asm__ volatile("movq %0, %%rsp\n\tud2" ::"r"(0xFFFFFFFF80100000ULL) : "memory");
    ExitProcess(CHILD_RSP_SURVIVED); /* not reached */
}

/* The maximal-string child: report what actually arrived. */
static void child_long_main(void)
{
    UINT code = CHILD_LONG_BASE;
    const WCHAR *cmd = GetCommandLineW();
    int len = wstr_length(cmd);

    if (len == LONG_CMDLINE_CHARS && cmd[len - 1] == 'Z')
        code |= CHILD_LONG_LEN;

    /* The title travels the same capture path as the command line but through
     * a different STARTUPINFO field, so it is worth its own bit: a slot-sizing
     * bug that drops one string tends to drop them all. */
    STARTUPINFOW si;
    GetStartupInfoW(&si);
    if (si.lpTitle && wstr_length(si.lpTitle) == LONG_TITLE_CHARS &&
        si.lpTitle[LONG_TITLE_CHARS - 1] == 'T')
        code |= CHILD_LONG_TAIL;
    ExitProcess(code);
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

/* Maximal process-parameter strings must reach the child intact. The kernel
 * copies Length bytes into a heap slot it sizes from MaximumLength, and
 * proskrnl computed that as (USHORT)(Length + sizeof(WCHAR)) -- which wraps
 * for exactly the lengths an ordinary CreateProcessW caller can produce. */
static void test_long_strings(const WCHAR *self)
{
    int n = 0;
    long_cmdline[n++] = '"';
    for (int i = 0; self[i]; i++)
        long_cmdline[n++] = self[i];
    long_cmdline[n++] = '"';
    const WCHAR *tail = L" --child-long ";
    for (int i = 0; tail[i]; i++)
        long_cmdline[n++] = tail[i];
    /* Pad to exactly LONG_CMDLINE_CHARS, last character a sentinel. */
    while (n < LONG_CMDLINE_CHARS - 1)
        long_cmdline[n++] = 'x';
    long_cmdline[n++] = 'Z';
    long_cmdline[n] = 0;
    ok(n == LONG_CMDLINE_CHARS, "built %d chars, wanted %d", n, LONG_CMDLINE_CHARS);

    for (int i = 0; i < LONG_TITLE_CHARS - 1; i++)
        long_title[i] = 't';
    long_title[LONG_TITLE_CHARS - 1] = 'T';
    long_title[LONG_TITLE_CHARS] = 0;

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.lpTitle = long_title;
    BOOL created = CreateProcessW(NULL, long_cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessW (maximal cmdline + title) -> %lu", (unsigned long)GetLastError());
    if (!created)
        return;
    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "long-string child wait");
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    ok(code == (CHILD_LONG_BASE | CHILD_LONG_LEN | CHILD_LONG_TAIL),
       "long-string child exit %#lx (want %#x)", (unsigned long)code,
       CHILD_LONG_BASE | CHILD_LONG_LEN | CHILD_LONG_TAIL);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

START_TEST(create_process)
{
    if (wstr_contains(GetCommandLineW(), L"--child-badrsp"))
        child_bad_rsp_main(); /* never returns */
    /* --child-long is checked first: it also contains "--child". */
    if (wstr_contains(GetCommandLineW(), L"--child-long"))
        child_long_main(); /* never returns */
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

    test_long_strings(self);
    /* Faulting with a kernel-half RSP must kill only the child. */
    {
        WCHAR badcmdline[600];
        int n = 0;
        badcmdline[n++] = '"';
        for (int i = 0; self[i]; i++)
            badcmdline[n++] = self[i];
        badcmdline[n++] = '"';
        const WCHAR *tail = L" --child-badrsp";
        for (int i = 0; tail[i]; i++)
            badcmdline[n++] = tail[i];
        badcmdline[n] = 0;

        STARTUPINFOW bsi;
        PROCESS_INFORMATION bpi;
        memset(&bsi, 0, sizeof(bsi));
        bsi.cb = sizeof(bsi);
        BOOL made = CreateProcessW(NULL, badcmdline, NULL, NULL, FALSE, 0, NULL, NULL, &bsi, &bpi);
        ok(made, "CreateProcessW (hostile RSP child) -> %lu", (unsigned long)GetLastError());
        if (made)
        {
            ok(WaitForSingleObject(bpi.hProcess, 30000) == WAIT_OBJECT_0, "hostile-RSP child wait");
            DWORD bcode = 0;
            GetExitCodeProcess(bpi.hProcess, &bcode);
            ok(bcode != CHILD_RSP_SURVIVED, "hostile-RSP child survived (%#lx)",
               (unsigned long)bcode);
            CloseHandle(bpi.hThread);
            CloseHandle(bpi.hProcess);
        }
        /* Reaching here at all is the real assertion: the machine is alive. */
        ok(1, "parent survived the hostile-RSP child");
    }

}
