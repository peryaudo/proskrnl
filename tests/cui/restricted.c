/* tests/cui/restricted.c — the CUI-6 acceptance's restricted-token launch.
 *
 * The CreateRestrictedToken idiom sandboxing launchers use: take the current
 * process token, drop a privilege and turn a group deny-only, then launch a
 * child under the restricted token with CreateProcessAsUser. The child
 * inspects its own token to confirm the restriction stuck. A third-party CUI
 * app (mingw + its own CRT, importing advapi32), driven from cmd.
 *
 * Prints "restricted-child-ok" (from the child) and "restricted-ok" (from the
 * parent) when the launch and the restriction both held.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int has_privilege(HANDLE token, LUID luid)
{
    BYTE buf[1024];
    DWORD len = 0;
    if (!GetTokenInformation(token, TokenPrivileges, buf, sizeof(buf), &len))
        return 0;
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)buf;
    for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == luid.LowPart &&
            tp->Privileges[i].Luid.HighPart == luid.HighPart)
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
    {
        HANDLE token = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            printf("restricted-child-notoken\n");
            return 1;
        }
        LUID changeNotify;
        LookupPrivilegeValueA(NULL, SE_CHANGE_NOTIFY_NAME, &changeNotify);
        /* The dropped privilege must be gone from the restricted child. */
        int gone = !has_privilege(token, changeNotify);
        CloseHandle(token);
        printf("restricted-child-%s\n", gone ? "ok" : "fail");
        return 0;
    }

    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                          &token))
    {
        printf("restricted-notoken\n");
        return 1;
    }

    /* Delete SeChangeNotifyPrivilege via the restricted-token filter. */
    LUID_AND_ATTRIBUTES del;
    LookupPrivilegeValueA(NULL, SE_CHANGE_NOTIFY_NAME, &del.Luid);
    del.Attributes = 0;

    HANDLE restricted = NULL;
    if (!CreateRestrictedToken(token, 0, 0, NULL, 1, &del, 0, NULL, &restricted))
    {
        printf("restricted-nofilter\n");
        return 1;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char cmdline[MAX_PATH + 32];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" --child", self);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessAsUserA(restricted, NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                              &pi))
    {
        printf("restricted-nolaunch\n");
        return 1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(restricted);
    CloseHandle(token);
    printf("restricted-ok\n");
    return 0;
}
