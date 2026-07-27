/*
 * sem_ob/session_bno.c - the per-session BaseNamedObjects directory (GUI-5).
 *
 * Every named kernel object a Win32 app creates goes through kernelbase's
 * BaseGetNamedObjectDirectory, which opens EXACTLY
 * \Sessions\<PEB SessionId>\BaseNamedObjects with
 * DIRECTORY_CREATE_OBJECT|DIRECTORY_TRAVERSE and no fallback
 * (dlls/kernelbase/sync.c) - when that open fails, every CreateEventW /
 * CreateMutexW / CreateSemaphoreW with a name fails ERROR_BAD_PATHNAME.
 * Wine's server creates the directory per session (server/directory.c,
 * create_session); user32:msg's WaitForInputIdle test was the first real
 * caller to trip its absence here.
 *
 * Pinned as session_dirs.c pins the WindowStations tree: the directory
 * exists for THIS process's session (whatever the PEB says), opens with
 * kernelbase's own access mask, accepts a child, and a relative reopen
 * finds that child - the whole CreateEventW(named) shape one level down.
 */
#include "util.h"

static const void *event_name = W("prsk_gui5_bno_event");

/* Compose \Sessions\<id>\BaseNamedObjects for the running session. */
static void build_path(WCHAR *out, ULONG session)
{
    static const WCHAR head[] = W("\\Sessions\\");
    static const WCHAR tail[] = W("\\BaseNamedObjects");
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

START_TEST(session_bno)
{
    PROCESS_BASIC_INFORMATION basic;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    WCHAR path[128];
    HANDLE dir, event, other;
    NTSTATUS status;
    ULONG session = 0;

    /* The session id the process is actually in: kernelbase reads it from
     * the PEB, so the test must look in the same place rather than assume. */
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &basic,
                                       sizeof(basic), NULL);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status) && basic.PebBaseAddress)
        /* PEB.SessionId at 0x2c0 on x86_64; offset as annotated in the
         * pinned tree's winternl.h (`ULONG SessionId; /* 1d4/2c0 *\/`). */
        session = *(volatile ULONG *)((char *)basic.PebBaseAddress + 0x2c0);

    build_path(path, session);
    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    /* kernelbase's exact mask (BaseGetNamedObjectDirectory). */
    status = NtOpenDirectoryObject(&dir, DIRECTORY_CREATE_OBJECT | DIRECTORY_TRAVERSE, &attr);
    ok(status == STATUS_SUCCESS, "open session %lu BaseNamedObjects -> %08lx",
       (unsigned long)session, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* A named create relative to it, and a reopen finding the same object:
     * CreateEventW(name) + OpenEventW(name), one layer down. */
    init_ustr(&name, event_name);
    init_attr(&attr, dir, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "create relative to BaseNamedObjects -> %08lx",
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
