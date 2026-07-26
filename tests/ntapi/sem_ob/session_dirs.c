/*
 * sem_ob/session_dirs.c - the per-session namespace (GUI-2, docs/07).
 *
 * NT gives every session a namespace under \Sessions\<id>, and window
 * stations live in \Sessions\<id>\Windows\WindowStations. Wine's server
 * builds the same tree (server/directory.c, create_session), and win32u
 * depends on it: NtUserCreateWindowStation names "WinSta0" RELATIVE to a
 * handle on that directory (dlls/win32u/winstation.c, winstation_init +
 * get_winstations_dir_handle), so without the directory there is nowhere to
 * put a window station.
 *
 * Pinned here as three separate promises: the tree exists for THIS process's
 * session id (whatever the PEB says it is), it is a real directory that
 * accepts a child object, and a relative open through it finds that child --
 * which is exactly the shape NtUserCreateWindowStation needs.
 */
#include "util.h"


static const void *winsta_name = W("prsk_gui2_winsta");

/* Compose \Sessions\<id>\Windows\WindowStations for the running session. */
static void build_path(WCHAR *out, ULONG session)
{
    static const WCHAR head[] = W("\\Sessions\\");
    static const WCHAR tail[] = W("\\Windows\\WindowStations");
    WCHAR digits[16];
    unsigned count = 0, i = 0, j;

    for (j = 0; head[j]; j++)
        out[i++] = head[j];
    do
    {
        digits[count++] = (WCHAR)('0' + session % 10);
        session /= 10;
    } while (session);
    while (count)
        out[i++] = digits[--count];
    for (j = 0; tail[j]; j++)
        out[i++] = tail[j];
    out[i] = 0;
}

START_TEST(session_dirs)
{
    PROCESS_BASIC_INFORMATION basic;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    WCHAR path[128];
    HANDLE dir, event, other;
    NTSTATUS status;
    ULONG session = 0;

    /* The session id the process is actually in: win32u reads it from the
     * PEB, so the test must look in the same place rather than assume 0. */
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &basic,
                                       sizeof(basic), NULL);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status) && basic.PebBaseAddress)
        session = *(volatile ULONG *)((char *)basic.PebBaseAddress + 0x2c0 /* PEB.SessionId */);

    build_path(path, session);
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(
        &dir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT, &attr);
    ok(status == STATUS_SUCCESS, "open session %lu WindowStations -> %08lx", (unsigned long)session,
       (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* It takes children, and a relative open through it finds them: the
     * exact sequence NtUserCreateWindowStation performs with "WinSta0". */
    init_ustr(&name, winsta_name);
    init_attr(&attr, dir, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create relative to WindowStations -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
        ok(status == STATUS_SUCCESS, "relative reopen -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            ok(wait_now(other) == STATUS_SUCCESS, "relative reopen bound a different object");
            NtClose(other);
        }
        NtClose(event);
    }

    NtClose(dir);
}
