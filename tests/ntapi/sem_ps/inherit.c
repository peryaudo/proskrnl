/*
 * sem_ps/inherit.c — handle inheritance across CreateProcessW (M10).
 *
 * The operative spec is wineserver's copy_handle_table + new_process fixups
 * (third_party/wine server/handle.c, server/process.c): with
 * bInheritHandles=TRUE every inherit-marked handle is copied into the child
 * AT THE SAME HANDLE VALUE (index-preserving copy) and non-inheritable
 * handles are absent; with a PROC_THREAD_ATTRIBUTE_HANDLE_LIST only the
 * listed handles (plus the three std handles) are copied; with
 * bInheritHandles=FALSE the three std handles are still duplicated into the
 * child (any value) with invalid ones tolerated. cmd.exe's pipes and
 * redirection are exactly this machinery.
 *
 * Same silent-child / exit-code-bitmask protocol as sem_ps/create_process.c:
 * child modes are selected by a marker and handle values travel as hex text
 * on the command line.
 */
#include "util.h"

#define CHILD_BASE 0x40

/* --inh1: write through two handle values; bit0 = first succeeded,
 * bit1 = second FAILED (as it must — non-inheritable). */
#define INH1_FIRST          0x01
#define INH1_SECOND_BLOCKED 0x02
/* --inh2 (handle list): bit0 = listed handle works, bit1 = unlisted
 * inheritable handle is absent. */
#define INH2_LISTED           0x01
#define INH2_UNLISTED_BLOCKED 0x02
/* --inh3 (std handles): bit0 = GetStdHandle(STD_OUTPUT_HANDLE) write works. */
#define INH3_STD 0x01

static const WCHAR *wstr_find(const WCHAR *haystack, const WCHAR *needle)
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
            return haystack;
    }
    return NULL;
}

static HANDLE parse_handle(const WCHAR *hex)
{
    ULONG_PTR value = 0;
    while ((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f'))
    {
        value = value * 16 + (*hex <= '9' ? (ULONG_PTR)(*hex - '0') : (ULONG_PTR)(*hex - 'a' + 10));
        hex++;
    }
    return (HANDLE)value;
}

static int emit_hex(WCHAR *out, HANDLE handle)
{
    ULONG_PTR value = (ULONG_PTR)handle;
    WCHAR digits[17];
    int n = 0;
    do
    {
        int d = value & 0xf;
        digits[n++] = (WCHAR)(d <= 9 ? '0' + d : 'a' + d - 10);
        value >>= 4;
    } while (value);
    for (int i = 0; i < n; i++)
        out[i] = digits[n - 1 - i];
    return n;
}

static int try_write(HANDLE handle, const char *tag)
{
    DWORD written = 0;
    return WriteFile(handle, tag, 4, &written, NULL) && written == 4;
}

static void child_main(const WCHAR *cmdline)
{
    UINT code = CHILD_BASE;
    const WCHAR *mode;

    if ((mode = wstr_find(cmdline, L"--inh1 ")) != NULL)
    {
        const WCHAR *first = mode + 7;
        const WCHAR *second = wstr_find(first, L" ") + 1;
        if (try_write(parse_handle(first), "ONE."))
            code |= INH1_FIRST;
        if (!try_write(parse_handle(second), "TWO."))
            code |= INH1_SECOND_BLOCKED;
    }
    else if ((mode = wstr_find(cmdline, L"--inh2 ")) != NULL)
    {
        const WCHAR *listed = mode + 7;
        const WCHAR *unlisted = wstr_find(listed, L" ") + 1;
        if (try_write(parse_handle(listed), "LST."))
            code |= INH2_LISTED;
        if (!try_write(parse_handle(unlisted), "UNL."))
            code |= INH2_UNLISTED_BLOCKED;
    }
    else if (wstr_find(cmdline, L"--inh3") != NULL)
    {
        if (try_write(GetStdHandle(STD_OUTPUT_HANDLE), "STD."))
            code |= INH3_STD;
    }
    ExitProcess(code);
}

/* Read whatever is buffered in the pipe read end (child has exited, data is
 * in flight); empty pipe returns 0 bytes without blocking via peek. */
static DWORD drain_pipe(HANDLE rd, char *buffer, DWORD capacity)
{
    DWORD avail = 0;
    if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) || avail == 0)
        return 0;
    DWORD got = 0;
    if (!ReadFile(rd, buffer, avail < capacity ? avail : capacity, &got, NULL))
        return 0;
    return got;
}

static BOOL run_child(WCHAR *cmdline, STARTUPINFOW *si, BOOL inherit, DWORD flags, DWORD *codeOut)
{
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, inherit, flags, NULL, NULL, si, &pi))
        return FALSE;
    if (WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0)
        return FALSE;
    BOOL got = GetExitCodeProcess(pi.hProcess, codeOut);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return got;
}

static int build_cmdline(WCHAR *out, const WCHAR *self, const WCHAR *marker)
{
    int n = 0;
    out[n++] = '"';
    for (int i = 0; self[i]; i++)
        out[n++] = self[i];
    out[n++] = '"';
    out[n++] = ' ';
    for (int i = 0; marker[i]; i++)
        out[n++] = marker[i];
    out[n] = 0;
    return n;
}

START_TEST(inherit)
{
    const WCHAR *cl = GetCommandLineW();
    if (wstr_find(cl, L"--inh"))
        child_main(cl); /* never returns */

    WCHAR self[512];
    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    STARTUPINFOW si;
    WCHAR cmdline[600];
    char data[64];
    DWORD code, got;

    /* --- inherit-all: value-preserving copy of inheritable handles;
     * non-inheritable handles absent --------------------------------------- */
    HANDLE rd1, wr1, rd2, wr2;
    ok(CreatePipe(&rd1, &wr1, &sa, 0), "CreatePipe inheritable");
    ok(CreatePipe(&rd2, &wr2, NULL, 0), "CreatePipe private");
    int n = build_cmdline(cmdline, self, L"--inh1 ");
    n += emit_hex(cmdline + n, wr1);
    cmdline[n++] = ' ';
    n += emit_hex(cmdline + n, wr2);
    cmdline[n] = 0;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    ok(run_child(cmdline, &si, TRUE, 0, &code), "inh1 child");
    ok(code == (CHILD_BASE | INH1_FIRST | INH1_SECOND_BLOCKED), "inh1 observed %02lx",
       (unsigned long)code);
    got = drain_pipe(rd1, data, sizeof(data));
    ok(got == 4 && memcmp(data, "ONE.", 4) == 0, "inherited write arrived (%lu)",
       (unsigned long)got);
    ok(drain_pipe(rd2, data, sizeof(data)) == 0, "private pipe stayed empty");
    CloseHandle(rd1);
    CloseHandle(wr1);
    CloseHandle(rd2);
    CloseHandle(wr2);

    /* --- PROC_THREAD_ATTRIBUTE_HANDLE_LIST: listed only -------------------- */
    HANDLE rdl, wrl, rdu, wru;
    ok(CreatePipe(&rdl, &wrl, &sa, 0), "CreatePipe listed");
    ok(CreatePipe(&rdu, &wru, &sa, 0), "CreatePipe unlisted");
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    STARTUPINFOEXW six;
    memset(&six, 0, sizeof(six));
    six.StartupInfo.cb = sizeof(six);
    six.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    ok(InitializeProcThreadAttributeList(six.lpAttributeList, 1, 0, &attrSize),
       "InitializeProcThreadAttributeList");
    ok(UpdateProcThreadAttribute(six.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &wrl,
                                 sizeof(wrl), NULL, NULL),
       "UpdateProcThreadAttribute");
    n = build_cmdline(cmdline, self, L"--inh2 ");
    n += emit_hex(cmdline + n, wrl);
    cmdline[n++] = ' ';
    n += emit_hex(cmdline + n, wru);
    cmdline[n] = 0;
    ok(run_child(cmdline, &six.StartupInfo, TRUE, EXTENDED_STARTUPINFO_PRESENT, &code),
       "inh2 child");
    ok(code == (CHILD_BASE | INH2_LISTED | INH2_UNLISTED_BLOCKED), "inh2 observed %02lx",
       (unsigned long)code);
    got = drain_pipe(rdl, data, sizeof(data));
    ok(got == 4 && memcmp(data, "LST.", 4) == 0, "listed write arrived (%lu)", (unsigned long)got);
    ok(drain_pipe(rdu, data, sizeof(data)) == 0, "unlisted pipe stayed empty");
    DeleteProcThreadAttributeList(six.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, six.lpAttributeList);
    CloseHandle(rdl);
    CloseHandle(wrl);
    CloseHandle(rdu);
    CloseHandle(wru);

    /* --- STARTF_USESTDHANDLES + bInheritHandles=TRUE ------------------------ */
    HANDLE rds, wrs;
    ok(CreatePipe(&rds, &wrs, &sa, 0), "CreatePipe std");
    build_cmdline(cmdline, self, L"--inh3");
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wrs;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    ok(run_child(cmdline, &si, TRUE, 0, &code), "inh3 child");
    ok(code == (CHILD_BASE | INH3_STD), "inh3 observed %02lx", (unsigned long)code);
    got = drain_pipe(rds, data, sizeof(data));
    ok(got == 4 && memcmp(data, "STD.", 4) == 0, "std write arrived (%lu)", (unsigned long)got);
    CloseHandle(rds);
    CloseHandle(wrs);

    /* bInheritHandles=FALSE + STARTF_USESTDHANDLES is deliberately NOT
     * pinned: on the oracle the console-less parent hands the child
     * CONSOLE_HANDLE_ALLOC, whose headless console allocation displaces the
     * server-duplicated std handles — the observable result is environment-
     * dependent, and nothing on the CUI path relies on it (cmd.exe always
     * redirects with bInheritHandles=TRUE). */
}
