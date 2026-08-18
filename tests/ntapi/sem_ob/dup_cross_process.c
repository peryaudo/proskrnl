/*
 * sem_ob/dup_cross_process.c — NtDuplicateObject across a process boundary.
 *
 * The three same-process shapes are pinned by sem_ob/handle_life.c; this
 * pins the two FOREIGN directions and the refusals, which is the part a
 * one-process kernel can answer wrongly without anything noticing.
 *
 * Operative spec is wineserver's duplicate_handle (third_party/wine
 * server/handle.c) reached through dlls/ntdll/unix/server.c: the source and
 * target processes are named by handle, each must grant PROCESS_DUP_HANDLE,
 * the object is looked up in the SOURCE process's table and the new handle is
 * created in the TARGET's, and DUPLICATE_CLOSE_SOURCE closes the source entry
 * in whichever process owns it — not in the caller's.
 *
 * Identity is proved by SIGNALLING, not by comparing handle values: a
 * duplicate that named a different object would leave the waiter asleep.
 *
 * Child protocol follows sem_ps/inherit.c: the child is this same binary
 * re-run with a marker, it inherits two pipe ends at their parent handle
 * values (inheritance is value-preserving), and it reports through an exit
 * code bitmask. Handle values travel as fixed-width hex over the pipes.
 */
#include "util.h"

#define CHILD_BASE        0x50
#define DUP_IN_SIGNALLED  0x01 /* parent duplicated an event INTO the child   */
#define DUP_OUT_SIGNALLED 0x02 /* parent duplicated an event OUT of the child */
#define DUP_CLOSE_SOURCE  0x04 /* DUPLICATE_CLOSE_SOURCE closed it in HERE    */

#define HEX_WIDTH 16

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

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
    for (int i = 0; i < HEX_WIDTH; i++)
    {
        WCHAR c = hex[i];
        ULONG_PTR digit = (c >= '0' && c <= '9') ? (ULONG_PTR)(c - '0') : (ULONG_PTR)(c - 'a' + 10);
        value = value * 16 + digit;
    }
    return (HANDLE)value;
}

/* Fixed-width so the reader never has to frame: 16 hex digits, no separator. */
static void emit_hex(WCHAR *out, HANDLE handle)
{
    ULONG_PTR value = (ULONG_PTR)handle;
    for (int i = HEX_WIDTH - 1; i >= 0; i--)
    {
        int d = (int)(value & 0xf);
        out[i] = (WCHAR)(d <= 9 ? '0' + d : 'a' + d - 10);
        value >>= 4;
    }
}

static BOOL write_handle(HANDLE pipe, HANDLE value)
{
    char text[HEX_WIDTH];
    WCHAR wide[HEX_WIDTH];
    DWORD written = 0;
    emit_hex(wide, value);
    for (int i = 0; i < HEX_WIDTH; i++)
        text[i] = (char)wide[i];
    return WriteFile(pipe, text, HEX_WIDTH, &written, NULL) && written == HEX_WIDTH;
}

/* Blocking, exact-length read: the pipe carries fixed-width records, but a
 * pipe may still hand them over in pieces. */
static BOOL read_handle(HANDLE pipe, HANDLE *out)
{
    char text[HEX_WIDTH];
    WCHAR wide[HEX_WIDTH];
    DWORD total = 0;
    while (total < HEX_WIDTH)
    {
        DWORD got = 0;
        if (!ReadFile(pipe, text + total, HEX_WIDTH - total, &got, NULL) || got == 0)
            return FALSE;
        total += got;
    }
    for (int i = 0; i < HEX_WIDTH; i++)
        wide[i] = (WCHAR)text[i];
    *out = parse_handle(wide);
    return TRUE;
}

static void child_main(const WCHAR *cmdline)
{
    const WCHAR *args = wstr_find(cmdline, L"--dupx ");
    HANDLE fromParent, toParent, duped, mine, closed;
    UINT code = CHILD_BASE;
    DWORD written = 0;
    char ack;
    DWORD got = 0;

    if (!args)
        ExitProcess(code);
    args += 7;
    fromParent = parse_handle(args);
    toParent = parse_handle(args + HEX_WIDTH + 1);

    /* (1) The parent duplicated one of ITS events into this process and sent
     * the handle value it landed on. Signalling it is what proves the
     * duplicate names the parent's object. */
    if (read_handle(fromParent, &duped) && NtSetEvent(duped, NULL) == STATUS_SUCCESS)
        code |= DUP_IN_SIGNALLED;

    /* (2) Now the other direction: make an event here, hand its value over,
     * and wait for the parent to signal it through a duplicate it pulled OUT
     * of this process. */
    if (NtCreateEvent(&mine, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE) == STATUS_SUCCESS)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000ll; /* 10s, relative */
        if (write_handle(toParent, mine) &&
            NtWaitForSingleObject(mine, FALSE, &timeout) == STATUS_WAIT_0)
            code |= DUP_OUT_SIGNALLED;
    }

    /* (3) DUPLICATE_CLOSE_SOURCE names the SOURCE process's table, not the
     * caller's: after the parent duplicates this handle out with that flag,
     * it must be gone from HERE. */
    if (NtCreateEvent(&closed, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE) ==
            STATUS_SUCCESS &&
        write_handle(toParent, closed) && ReadFile(fromParent, &ack, 1, &got, NULL) && got == 1)
    {
        if (NtSetEvent(closed, NULL) != STATUS_SUCCESS)
            code |= DUP_CLOSE_SOURCE;
    }

    (void)written;
    ExitProcess(code);
}

static int build_cmdline(WCHAR *out, const WCHAR *self, HANDLE first, HANDLE second)
{
    int n = 0;
    out[n++] = '"';
    for (int i = 0; self[i]; i++)
        out[n++] = self[i];
    out[n++] = '"';
    out[n++] = ' ';
    for (const WCHAR *m = L"--dupx "; *m; m++)
        out[n++] = *m;
    emit_hex(out + n, first);
    n += HEX_WIDTH;
    out[n++] = ' ';
    emit_hex(out + n, second);
    n += HEX_WIDTH;
    out[n] = 0;
    return n;
}

START_TEST(dup_cross_process)
{
    const WCHAR *cl = GetCommandLineW();
    if (wstr_find(cl, L"--dupx"))
        child_main(cl); /* never returns */

    WCHAR self[512], cmdline[700];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE toChildRd, toChildWr, fromChildRd, fromChildWr;
    HANDLE intoChild = NULL, childEvent, pulled = NULL, closeSrc, pulledClosed = NULL;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    DWORD code = 0, written = 0;

    timeout.QuadPart = -300000000ll; /* 30s, relative */

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    ok(CreatePipe(&toChildRd, &toChildWr, &sa, 0), "CreatePipe to child");
    ok(CreatePipe(&fromChildRd, &fromChildWr, &sa, 0), "CreatePipe from child");

    build_cmdline(cmdline, self, toChildRd, fromChildWr);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi), "CreateProcessW");

    /* --- into the child ---------------------------------------------------- */
    HANDLE ours;
    ok(NtCreateEvent(&ours, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE) == STATUS_SUCCESS,
       "NtCreateEvent");
    status = NtDuplicateObject(NtCurrentProcess(), ours, pi.hProcess, &intoChild, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate into child -> %08lx", (unsigned long)status);
    ok(write_handle(toChildWr, intoChild), "sent the child its handle value");
    ok(NtWaitForSingleObject(ours, FALSE, &timeout) == STATUS_WAIT_0,
       "the child signalled OUR event through the duplicate");

    /* --- out of the child -------------------------------------------------- */
    ok(read_handle(fromChildRd, &childEvent), "received the child's handle value");
    status = NtDuplicateObject(pi.hProcess, childEvent, NtCurrentProcess(), &pulled, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate out of child -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        ok(NtSetEvent(pulled, NULL) == STATUS_SUCCESS, "signalled the child's event from here");

    /* --- DUPLICATE_CLOSE_SOURCE reaches into the child --------------------- */
    ok(read_handle(fromChildRd, &closeSrc), "received the child's second handle value");
    status = NtDuplicateObject(pi.hProcess, closeSrc, NtCurrentProcess(), &pulledClosed, 0, 0,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    ok(status == STATUS_SUCCESS, "duplicate out with CLOSE_SOURCE -> %08lx", (unsigned long)status);
    ok(WriteFile(toChildWr, "K", 1, &written, NULL) && written == 1, "acked the child");

    /* --- refusals ---------------------------------------------------------- */
    HANDLE bogus = NULL;
    status = NtDuplicateObject(pi.hProcess, (HANDLE)(ULONG_PTR)0xfffc, NtCurrentProcess(), &bogus,
                               0, 0, DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_INVALID_HANDLE, "bogus handle in the child -> %08lx",
       (unsigned long)status);

    /* A process handle that does not grant PROCESS_DUP_HANDLE cannot be
     * either end of a duplication. */
    HANDLE weak = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi.dwProcessId);
    ok(weak != NULL, "OpenProcess(PROCESS_QUERY_INFORMATION)");
    if (weak)
    {
        HANDLE denied = NULL;
        status = NtDuplicateObject(weak, childEvent, NtCurrentProcess(), &denied, 0, 0,
                                   DUPLICATE_SAME_ACCESS);
        ok(status == STATUS_ACCESS_DENIED, "source without PROCESS_DUP_HANDLE -> %08lx",
           (unsigned long)status);
        status =
            NtDuplicateObject(NtCurrentProcess(), ours, weak, &denied, 0, 0, DUPLICATE_SAME_ACCESS);
        ok(status == STATUS_ACCESS_DENIED, "target without PROCESS_DUP_HANDLE -> %08lx",
           (unsigned long)status);
        NtClose(weak);
    }

    /* --- a pseudo SOURCE handle names the CALLER, not the source process --- */
    /* wineserver resolves the magic handles against `current` inside
     * get_handle_obj, before the source process's table is consulted at all
     * (third_party/wine server/handle.c get_magic_handle), so naming the child
     * as the source process does not make -1 mean the child. The same-process
     * half of this subject is sem_ob/dup_pseudo.c. */
    HANDLE pseudoDup = NULL;
    status = NtDuplicateObject(pi.hProcess, NtCurrentProcess(), NtCurrentProcess(), &pseudoDup, 0,
                               0, DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "pseudo source against the child -> %08lx", (unsigned long)status);
    ok(GetProcessId(pseudoDup) == GetCurrentProcessId(),
       "names the CALLER's process %lu, not the child's %lu",
       (unsigned long)GetProcessId(pseudoDup), (unsigned long)pi.dwProcessId);
    if (pseudoDup)
        NtClose(pseudoDup);

    ok(WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0, "child exited");
    ok(GetExitCodeProcess(pi.hProcess, &code), "GetExitCodeProcess");
    ok(code == (CHILD_BASE | DUP_IN_SIGNALLED | DUP_OUT_SIGNALLED | DUP_CLOSE_SOURCE),
       "child observed %02lx", (unsigned long)code);

    if (pulled)
        NtClose(pulled);
    if (pulledClosed)
        NtClose(pulledClosed);
    NtClose(ours);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(toChildRd);
    CloseHandle(toChildWr);
    CloseHandle(fromChildRd);
    CloseHandle(fromChildWr);
}
