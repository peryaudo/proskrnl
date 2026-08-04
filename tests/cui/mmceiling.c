/* tests/cui/mmceiling.c — the CUI-9 step-1 measurement (docs/17 §2).
 *
 * A plain third-party CUI app (mingw + its own CRT against the baked Wine
 * userland, the looper/watchapp shape). It spawns resident copies of
 * itself — each child maps the full baked DLL set, which under the
 * Article 3 "no COW" mandate is a full private copy per process — until
 * process creation refuses, then reports the ceiling.
 *
 * Two output channels, deliberately split:
 *  - printf drives the console_expect.py flow ("mmceiling-refused",
 *    "mmceiling-done") through conhost's screen-diff renderer, which may
 *    interleave escape sequences into the text (tolerant regexes there);
 *  - the machine-verdict numbers go out via NtDisplayString — the same
 *    transport as the kernel's own [KTEST] lines (the ntapi_out precedent,
 *    tests/ntapi/ntapi.c) — so tests/run/run.sh cui9 can grep them
 *    unmangled:
 *        [KTEST] cui9 ceiling procs=<N> err=<code> availmb0=<a> availmb=<b>
 *        [KTEST] cui9 perproc kb=<n>
 *
 * The numbers are only comparable at the leg's fixed MEM= size; docs/17 §1
 * records them.
 *
 * A child ("mmceiling.exe wait <event>") signals a named event once its
 * loader has finished (main is running, so every DLL is mapped and paid
 * for) and then sleeps forever; the parent waits on {event, process} so a
 * child that dies mid-load (the loader's own STATUS_NO_MEMORY surfacing)
 * counts as the refusal, not as a resident process.
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_CHILDREN 512

typedef NTSTATUS(NTAPI *NT_DISPLAY_STRING)(UNICODE_STRING *);

static void serial_out(const char *text)
{
    static NT_DISPLAY_STRING display;
    if (display == NULL)
    {
        display = (NT_DISPLAY_STRING)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                            "NtDisplayString");
    }
    if (display == NULL)
    {
        return;
    }
    WCHAR wide[256];
    USHORT n = 0;
    while (text[n] != '\0' && n < 255)
    {
        wide[n] = (WCHAR)(unsigned char)text[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    display(&string);
}

static ULONGLONG avail_mb(void)
{
    MEMORYSTATUSEX status;
    memset(&status, 0, sizeof(status));
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status))
    {
        printf("mmceiling-memstatus-FAIL (%lu)\n", GetLastError());
        fflush(stdout);
        return 0;
    }
    return status.ullAvailPhys >> 20;
}

int main(int argc, char **argv)
{
    if (argc > 2 && strcmp(argv[1], "wait") == 0)
    {
        HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[2]);
        if (ready != NULL)
        {
            SetEvent(ready);
            CloseHandle(ready);
        }
        Sleep(INFINITE);
        return 0;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);

    static HANDLE children[MAX_CHILDREN];
    int resident = 0;
    DWORD refuseError = 0;
    ULONGLONG first = 0, last = 0;

    printf("mmceiling-start availmb=%llu\n", (unsigned long long)avail_mb());
    fflush(stdout);

    while (resident < MAX_CHILDREN)
    {
        char eventName[64];
        snprintf(eventName, sizeof(eventName), "mmceiling-ready-%d", resident);
        HANDLE ready = CreateEventA(NULL, FALSE, FALSE, eventName);
        if (ready == NULL)
        {
            refuseError = GetLastError();
            break;
        }

        char cmdline[MAX_PATH + 96];
        snprintf(cmdline, sizeof(cmdline), "\"%s\" wait %s", self, eventName);
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        if (!CreateProcessA(self, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            refuseError = GetLastError();
            CloseHandle(ready);
            break;
        }
        CloseHandle(pi.hThread);

        /* Resident only once the loader is done (the event); the process
         * handle winning means it died on load — a refusal too. */
        HANDLE pair[2] = {ready, pi.hProcess};
        DWORD wait = WaitForMultipleObjects(2, pair, FALSE, 120000);
        CloseHandle(ready);
        if (wait != WAIT_OBJECT_0)
        {
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            refuseError = wait == WAIT_OBJECT_0 + 1 ? exitCode : (DWORD)-1;
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            break;
        }

        children[resident] = pi.hProcess;
        resident++;
        ULONGLONG mb = avail_mb();
        if (first == 0)
        {
            first = mb;
        }
        last = mb;
        printf("mmceiling-spawn-%d availmb=%llu\n", resident, (unsigned long long)mb);
        fflush(stdout);
    }

    /* err=0 means the loop ended because the children[] array filled, NOT
     * because creation refused — the ceiling is then a lower bound, not a
     * measurement. Say so distinctly (the same "refused" console token so
     * the expect flow completes either way); tests/run/run.sh cui9 fails
     * the leg on err=0 so a future past-the-cap improvement raises the cap
     * instead of shipping a fabricated ceiling. */
    int capped = resident >= MAX_CHILDREN && refuseError == 0;
    char line[256];
    snprintf(line, sizeof(line),
             "[KTEST] cui9 ceiling procs=%d err=%lu capped=%d availmb0=%llu availmb=%llu\n",
             resident, (unsigned long)refuseError, capped, (unsigned long long)first,
             (unsigned long long)last);
    serial_out(line);
    if (resident > 1 && first > last)
    {
        snprintf(line, sizeof(line), "[KTEST] cui9 perproc kb=%llu\n",
                 (unsigned long long)((first - last) * 1024 / (ULONGLONG)(resident - 1)));
        serial_out(line);
    }
    printf("mmceiling-refused procs=%d err=%lu capped=%d\n", resident, (unsigned long)refuseError,
           capped);
    fflush(stdout);

    for (int i = 0; i < resident; i++)
    {
        TerminateProcess(children[i], 0);
        CloseHandle(children[i]);
    }

    printf("mmceiling-done\n");
    fflush(stdout);
    return 0;
}
