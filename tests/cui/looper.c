/* tests/cui/looper.c — the CUI-4 acceptance's interruptible program.
 *
 * A plain third-party CUI app (mingw + its own CRT against the baked Wine
 * userland, the hello_crt precedent). It installs a console control handler
 * and then spins in a BUSY loop that issues no blocking call — so being
 * interrupted proves the whole delivery path: the kernel notices ^C on the
 * console transport, starts a thread in this process at ntdll's
 * __wine_ctrl_routine, kernelbase's CtrlRoutine runs the handler below, and
 * the process exits. A loop that merely slept could be woken by other means;
 * a busy one can only be reached this way.
 *
 * "loop-alive" tells the harness it is running; "loop-caught-<n>" (printed
 * from the handler) is the interrupt proof, and its digits cannot appear in
 * the typed command line.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static volatile LONG caught;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT)
    {
        InterlockedIncrement(&caught);
        printf("loop-caught-%ld\n", (long)caught);
        fflush(stdout);
        ExitProcess(77);
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    /* `looper --spawn` starts a detached copy sharing this console and
     * returns immediately, so the shell gets its prompt back with a live
     * process to kill. cmd's `start` cannot serve: it delegates to
     * system32\start.exe, which proskrnl does not bake. */
    if (argc > 1 && strcmp(argv[1], "--spawn") == 0)
    {
        char self[MAX_PATH];
        GetModuleFileNameA(NULL, self, MAX_PATH);
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (!CreateProcessA(self, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
        {
            printf("loop-nospawn\n");
            fflush(stdout);
            return 1;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    printf("loop-alive\n");
    fflush(stdout);

    /* Bounded so a missed interrupt fails the run instead of hanging it. */
    ULONGLONG deadline = GetTickCount64() + 60000;
    while (GetTickCount64() < deadline)
    {
        /* Busy: no wait, no alertable point, no I/O. */
        for (volatile int i = 0; i < 1000000; i++)
        {
        }
    }
    printf("loop-timeout\n");
    fflush(stdout);
    return 1;
}
