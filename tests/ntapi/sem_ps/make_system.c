/*
 * sem_ps/make_system.c — ProcessWineMakeProcessSystem (CUI-3): the
 * Wine-private class services.exe (programs/services/rpc.c RPC_Init) and
 * every service process (dlls/sechost/service.c service_run_main_thread)
 * set at startup. The call marks the target process "system" and returns a
 * SYNCHRONIZE handle to the one global shutdown event, signalled when the
 * last non-system user process exits (wine/server/process.c
 * make_process_system). A silently-successful stub that leaves the handle
 * unwritten is exactly the planted bug that would tear services.exe down at
 * boot (Art. 12).
 *
 * The test marks a suspended CHILD system, never itself: on the oracle a
 * lone test process marking itself system would trip wineserver's
 * prefix-shutdown timer mid-run.
 */
#include "util.h"

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

START_TEST(make_system)
{
    WCHAR self[512], cmdline[600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE event = NULL, event2 = NULL;
    NTSTATUS status;
    DWORD wait;
    int n = 0;

    if (wstr_contains(GetCommandLineW(), L"--mps-child"))
        ExitProcess(0); /* never returns */

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    cmdline[n++] = '"';
    for (int i = 0; self[i]; i++)
        cmdline[n++] = self[i];
    cmdline[n] = 0;
    const WCHAR *tail = L"\" --mps-child";
    for (int i = 0; tail[i]; i++)
        cmdline[n + i] = tail[i], cmdline[n + i + 1] = 0;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi),
       "spawn suspended child -> %lu", (unsigned long)GetLastError());

    /* The size gate: anything but sizeof(HANDLE *) is rejected
     * (wine/dlls/ntdll/unix/process.c). */
    status = NtSetInformationProcess(pi.hProcess, PS_ProcessWineMakeProcessSystem, &event, 4);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "wrong size -> %08lx", (unsigned long)status);

    /* The real call: SUCCESS and a live waitable handle out. */
    status = NtSetInformationProcess(pi.hProcess, PS_ProcessWineMakeProcessSystem, &event,
                                     sizeof(HANDLE *));
    ok(status == STATUS_SUCCESS, "make-system -> %08lx", (unsigned long)status);
    ok(event != NULL, "shutdown event handle out");
    /* Not signalled: this test process is still a live user process. */
    wait = event ? WaitForSingleObject(event, 0) : WAIT_FAILED;
    ok(wait == WAIT_TIMEOUT, "shutdown event unsignalled -> %lu", (unsigned long)wait);

    /* Marking an already-system process still hands out a handle. */
    status = NtSetInformationProcess(pi.hProcess, PS_ProcessWineMakeProcessSystem, &event2,
                                     sizeof(HANDLE *));
    ok(status == STATUS_SUCCESS, "make-system again -> %08lx", (unsigned long)status);
    ok(event2 != NULL, "second event handle out");

    ok(ResumeThread(pi.hThread) != (DWORD)-1, "resume child");
    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "child wait");

    if (event)
        NtClose(event);
    if (event2)
        NtClose(event2);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
