/* tests/cui/redirchain.c — the CUI-6 acceptance's handle-inheritance redirect
 * chain.
 *
 * The SetHandleInformation stdio-redirect idiom real shells and build tools
 * use: open a file, mark its handle inheritable, hand it to a child as
 * hStdOutput, and read back what the child wrote through the inherited
 * handle. Then flip inherit OFF and confirm a second child does NOT inherit
 * it. A third-party CUI app (mingw + its own CRT), driven from cmd.
 *
 * Prints "redirchain-ok" when the inherited child's marker came back and the
 * non-inherited child's did not.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
    {
        /* Write a marker to the inherited stdout handle. */
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD written = 0;
        WriteFile(out, "MARK", 4, &written, NULL);
        return 0;
    }

    char path[MAX_PATH];
    GetTempPathA(sizeof(path), path);
    strncat(path, "redirchain.txt", sizeof(path) - strlen(path) - 1);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    HANDLE file =
        CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        printf("redirchain-nofile\n");
        return 1;
    }

    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char cmdline[MAX_PATH + 32];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" --child", self);

    /* First child: the file handle is inheritable and wired as stdout. */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = file;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        printf("redirchain-nospawn\n");
        return 1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* Read the marker the child wrote through the inherited handle. */
    SetFilePointer(file, 0, NULL, FILE_BEGIN);
    char buf[8] = {0};
    DWORD read = 0;
    ReadFile(file, buf, 4, &read, NULL);
    int inherited_ok = (read == 4 && memcmp(buf, "MARK", 4) == 0);

    /* Now flip inherit OFF: a second child must NOT inherit the file. */
    SetHandleInformation(file, HANDLE_FLAG_INHERIT, 0);
    DWORD flags = 0;
    GetHandleInformation(file, &flags);
    int flag_cleared = (flags & HANDLE_FLAG_INHERIT) == 0;

    printf("redirchain-%s\n", (inherited_ok && flag_cleared) ? "ok" : "fail");
    CloseHandle(file);
    DeleteFileA(path);
    return 0;
}
