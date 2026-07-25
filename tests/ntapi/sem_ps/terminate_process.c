/*
 * sem_ps/terminate_process.c — foreign NtTerminateProcess (taskkill's engine).
 *
 * Killing another process from outside: the process object signals, its exit
 * code becomes what the killer passed, and it works whether the target is
 * spinning in user code or blocked in a kernel wait. Under Art. 3 the target
 * is never torn down from the killer's context — it reaps itself at its next
 * return to user mode (a wait is aborted so it gets there). Green on the
 * pinned Wine oracle first (Art. 5).
 */
#include "util.h"

/* Local wide helper (no CRT wcs* under -nostdlib). */
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

static void spawn_self(const WCHAR *marker, PROCESS_INFORMATION *pi)
{
    WCHAR self[512];
    GetModuleFileNameW(NULL, self, 512);
    WCHAR cmdline[600];
    int n = 0;
    cmdline[n++] = L'"';
    for (int i = 0; self[i] && n < 540; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    cmdline[n++] = L' ';
    for (int i = 0; marker[i]; i++)
        cmdline[n++] = marker[i];
    cmdline[n] = 0;

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi, 0, sizeof(*pi));
    CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi);
}

#define KILL_CODE 0x1234u

START_TEST(terminate_process)
{
    if (wstr_contains(GetCommandLineW(), L"--kill-spin"))
    {
        for (;;)
        {
        } /* busy in user code; the parent kills us */
    }
    if (wstr_contains(GetCommandLineW(), L"--kill-wait"))
    {
        HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        WaitForSingleObject(ev, INFINITE); /* blocked in a kernel wait */
        ExitProcess(0);
    }

    /* --- kill a busy-looping child ------------------------------------- */
    PROCESS_INFORMATION spin;
    spawn_self(L"--kill-spin", &spin);
    ok(spin.hProcess != NULL, "spawn spinner");
    if (spin.hProcess)
    {
        Sleep(150); /* let it get into the loop */
        ok(TerminateProcess(spin.hProcess, KILL_CODE), "terminate spinner -> %lu",
           (unsigned long)GetLastError());
        ok(WaitForSingleObject(spin.hProcess, 10000) == WAIT_OBJECT_0, "spinner did not die");
        DWORD code = 0;
        ok(GetExitCodeProcess(spin.hProcess, &code), "GetExitCodeProcess spinner");
        ok(code == KILL_CODE, "spinner exit code %#lx, wanted %#x", (unsigned long)code, KILL_CODE);
        NtClose(spin.hProcess);
        NtClose(spin.hThread);
    }

    /* --- kill a child blocked in a wait -------------------------------- */
    PROCESS_INFORMATION waiter;
    spawn_self(L"--kill-wait", &waiter);
    ok(waiter.hProcess != NULL, "spawn waiter");
    if (waiter.hProcess)
    {
        Sleep(150); /* let it reach the wait */
        ok(TerminateProcess(waiter.hProcess, KILL_CODE), "terminate waiter -> %lu",
           (unsigned long)GetLastError());
        ok(WaitForSingleObject(waiter.hProcess, 10000) == WAIT_OBJECT_0, "waiter did not die");
        DWORD code = 0;
        ok(GetExitCodeProcess(waiter.hProcess, &code), "GetExitCodeProcess waiter");
        ok(code == KILL_CODE, "waiter exit code %#lx, wanted %#x", (unsigned long)code, KILL_CODE);
        NtClose(waiter.hProcess);
        NtClose(waiter.hThread);
    }
}
