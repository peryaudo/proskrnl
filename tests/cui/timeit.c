/* tests/cui/timeit.c — the CUI-6 acceptance's process/thread times reader.
 *
 * The shape a timeit-style tool relies on: spawn a child that burns CPU,
 * wait for it, then read GetProcessTimes and GetThreadTimes and confirm the
 * kernel accounted real user+kernel time and sane create/exit stamps. A
 * third-party CUI app (mingw + its own CRT), driven from the interactive cmd
 * session.
 *
 * Prints "timeit-cpu-<n>" (1 if the child accrued CPU time), "timeit-order-1"
 * (create <= exit), and "timeit-done" — digits the typed command cannot
 * supply.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static ULONGLONG to_u64(FILETIME ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--spin") == 0)
    {
        /* Burn ~200 ms of CPU, then exit. */
        volatile unsigned sink = 0;
        DWORD start = GetTickCount();
        while (GetTickCount() - start < 200)
            for (int i = 0; i < 20000; i++)
                sink += (unsigned)i;
        return 0;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char cmdline[MAX_PATH + 32];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" --spin", self);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        printf("timeit-nospawn\n");
        return 1;
    }
    WaitForSingleObject(pi.hProcess, 30000);

    FILETIME create, exit, kernel, user;
    if (!GetProcessTimes(pi.hProcess, &create, &exit, &kernel, &user))
    {
        printf("timeit-notimes\n");
        return 1;
    }
    ULONGLONG cpu = to_u64(kernel) + to_u64(user);
    printf("timeit-cpu-%d\n", cpu > 0 ? 1 : 0);
    printf("timeit-order-%d\n", to_u64(create) <= to_u64(exit) ? 1 : 0);

    /* GetThreadTimes on our own thread must also carry real accounting. */
    FILETIME tc, te, tk, tu;
    if (GetThreadTimes(GetCurrentThread(), &tc, &te, &tk, &tu))
    {
        printf("timeit-thread-%d\n", tc.dwLowDateTime || tc.dwHighDateTime ? 1 : 0);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("timeit-done\n");
    return 0;
}
