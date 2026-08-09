/*
 * sem_pipe/ioctl_event.c — two rules ntdll:pipe reaches once the completion
 * APC leg (W4a) stops it panicking, both about WHEN state changes rather
 * than about what a call returns.
 *
 * 1. A request that fails IMMEDIATELY still leaves the caller's completion
 *    event CLEAR, with the IOSB untouched. dlls/ntdll/tests/pipe.c:408-413
 *    sets the event, issues a listen against an already-connected instance
 *    (STATUS_PIPE_CONNECTED, answered from the call itself), and reads the
 *    event and the IOSB together — so the returned status alone cannot
 *    satisfy it. The oracle's shape is `else if (status != STATUS_PENDING &&
 *    event) NtResetEvent(event)` at the tail of each entry point; whether
 *    one calls that "cleared at submission" or "reset on failure" is not
 *    observable here, and this case pins only the end state it can see.
 *
 * 2. FileIoCompletionNotificationInformation (class 41) — what
 *    SetFileCompletionNotificationModes reads and writes.
 *
 * Both are measured here before either is built; the second especially,
 * because the oracle's own info_sizes[] carries 0 for the class and it is
 * not obvious from the source whether the QUERY direction answers at all.
 */
#include "util.h"

typedef struct
{
    ULONG Flags;
} SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

#ifndef FileIoCompletionNotificationInformation
#define FileIoCompletionNotificationInformation 41
#endif
#ifndef FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE        0x2
#endif

NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, PLONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);

/* Is `event` signalled right now? A zero-timeout wait, which does not
 * consume a notification event's signal. */
static BOOLEAN is_signaled(HANDLE event)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(event, FALSE, &zero) == STATUS_SUCCESS;
}

/* THE submit-time clear. */
static void test_event_cleared_on_submit(void)
{
    IO_STATUS_BLOCK iosb, clientIosb;
    HANDLE server = NULL, client = NULL, event = NULL;
    NTSTATUS status;

    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_ioctlevt"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_ioctlevt"), &clientIosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* Signal it, then issue a listen that is refused ON THE SPOT. */
    NtSetEvent(event, NULL);
    ok(is_signaled(event), "event not signalled before the call");

    poison_iosb(&iosb);
    status = NtFsControlFile(server, event, NULL, NULL, &iosb, FSCTL_PIPE_LISTEN, NULL, 0, NULL, 0);
    ok(status == STATUS_PIPE_CONNECTED, "listen when connected -> %08lx", (unsigned long)status);

    /* The IOSB is untouched — nothing completed... */
    ok(iosb.Status == IOSB_POISON_STATUS, "iosb written by an immediate answer %08lx",
       (unsigned long)iosb.Status);
    /* ...and yet the event is CLEAR, because submission cleared it. */
    ok(!is_signaled(event), "event still signalled after an immediate refusal");

    NtClose(client);
    NtClose(server);
    NtClose(event);
}

/* Class 41, both directions. */
static void test_completion_notification_class(void)
{
    SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION info;
    IO_STATUS_BLOCK iosb, clientIosb;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_pipe_instance_async(&server, W("\\??\\pipe\\prstest_ioctlnotify"), 1, &iosb);
    ok(status == STATUS_SUCCESS, "async server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_ioctlnotify"), &clientIosb);
    ok(status == STATUS_SUCCESS, "client connect -> %08lx", (unsigned long)status);

    /* The QUERY direction. dlls/ntdll/tests/pipe.c:1512 needs this to
     * SUCCEED — its else-branch is a win_skip, which winetest scores as a
     * failure on a non-Windows platform. */
    memset(&info, 0xcc, sizeof(info));
    status = NtQueryInformationFile(server, &iosb, &info, sizeof(info),
                                    FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "query class 41 -> %08lx", (unsigned long)status);
    ok(info.Flags == 0, "fresh handle flags %lx", (unsigned long)info.Flags);

    /* A buffer too short for the one ULONG. */
    status =
        NtQueryInformationFile(server, &iosb, &info, 2, FileIoCompletionNotificationInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short query -> %08lx", (unsigned long)status);

    /* The SET direction, and the query reading it back — the flags are
     * per-HANDLE state, which is the only thing that makes the modes
     * meaningful. */
    info.Flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    status = NtSetInformationFile(server, &iosb, &info, sizeof(info),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "set SKIP_COMPLETION_PORT -> %08lx", (unsigned long)status);

    memset(&info, 0xcc, sizeof(info));
    status = NtQueryInformationFile(server, &iosb, &info, sizeof(info),
                                    FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "re-query -> %08lx", (unsigned long)status);
    ok(info.Flags == FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, "flags read back %lx",
       (unsigned long)info.Flags);

    /* The OTHER handle is unaffected: this is handle state, not pipe state. */
    memset(&info, 0xcc, sizeof(info));
    status = NtQueryInformationFile(client, &iosb, &info, sizeof(info),
                                    FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "query the client end -> %08lx", (unsigned long)status);
    ok(info.Flags == 0, "client end flags %lx", (unsigned long)info.Flags);

    /* A second SET does not REPLACE the mode word — it ORs into it. Measured:
     * this case first asserted that setting SKIP_SET_EVENT_ON_HANDLE alone
     * would leave exactly that flag, and the oracle answered 3. The modes are
     * cumulative for the life of the handle and there is no way to clear one
     * (wineserver's set_fd_completion_mode ORs into fd->comp_flags), which
     * matches the Win32 surface: SetFileCompletionNotificationModes is
     * documented as set-once-per-flag with no paired clear. */
    info.Flags = FILE_SKIP_SET_EVENT_ON_HANDLE;
    status = NtSetInformationFile(server, &iosb, &info, sizeof(info),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "set SKIP_SET_EVENT -> %08lx", (unsigned long)status);

    memset(&info, 0xcc, sizeof(info));
    status = NtQueryInformationFile(server, &iosb, &info, sizeof(info),
                                    FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "re-query 2 -> %08lx", (unsigned long)status);
    ok(info.Flags == (FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE),
       "flags accumulate rather than replace %lx", (unsigned long)info.Flags);

    /* An UNKNOWN bit is not stored: the oracle masks the caller's word to
     * the three it defines (wineserver's set_fd_completion_mode ORs
     * `req->flags & (the three)`), so a set of 0x8 reads back as whatever
     * was there before and never as 0x8. Without the mask a caller could
     * park arbitrary bits in the handle's word and read them out again. */
    info.Flags = 0x8;
    status = NtSetInformationFile(server, &iosb, &info, sizeof(info),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "set an unknown bit -> %08lx", (unsigned long)status);

    memset(&info, 0xcc, sizeof(info));
    status = NtQueryInformationFile(server, &iosb, &info, sizeof(info),
                                    FileIoCompletionNotificationInformation);
    ok(status == STATUS_SUCCESS, "re-query 3 -> %08lx", (unsigned long)status);
    ok((info.Flags & 0x8) == 0, "an unknown bit was stored %lx", (unsigned long)info.Flags);

    NtClose(client);
    NtClose(server);
}

/* The modes are an OVERLAPPED-handle concept, and a SYNCHRONOUS handle is
 * refused rather than quietly accepted (wineserver's set_fd_completion_mode:
 * `if (!is_fd_overlapped(fd)) STATUS_INVALID_PARAMETER`). Measured on its own
 * handle because every other case here uses an async pipe, so nothing above
 * could see this. */
static void test_modes_need_an_overlapped_handle(void)
{
    SEM_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL;
    NTSTATUS status;

    /* create_pipe_instance passes FILE_SYNCHRONOUS_IO_NONALERT. */
    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_ioctlsync"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "sync server create -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    info.Flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
    status = NtSetInformationFile(server, &iosb, &info, sizeof(info),
                                  FileIoCompletionNotificationInformation);
    ok(status == STATUS_INVALID_PARAMETER, "set on a synchronous handle -> %08lx",
       (unsigned long)status);

    NtClose(server);
}

START_TEST(ioctl_event)
{
    test_event_cleared_on_submit();
    test_completion_notification_class();
    test_modes_need_an_overlapped_handle();
}
