/*
 * sem_pipe/device_ioctl.c — the FSCTL ladder the named-pipe DEVICE ROOT
 * answers, i.e. every pipe verb asked of a handle that is not a pipe end.
 *
 * docs/21 W11, the eight assertions at dlls/ntdll/tests/pipe.c:2751 —
 * subtest_empty_name_pipe_operations' eight-row FSCTL matrix, run twice
 * (once through `\Device\NamedPipe`, once through `\Device\NamedPipe\`).
 *
 * The whole rule is one switch, third_party/wine server/named_pipe.c
 * named_pipe_device_ioctl:
 *
 *     FSCTL_PIPE_WAIT / _LISTEN / _IMPERSONATE  -> STATUS_ILLEGAL_FUNCTION
 *     FSCTL_PIPE_DISCONNECT / _TRANSCEIVE       -> STATUS_PIPE_DISCONNECTED
 *     FSCTL_PIPE_QUERY_CLIENT_PROCESS           -> STATUS_INVALID_PARAMETER
 *     default                                   -> default_fd_ioctl, whose
 *                                                  own default is
 *                                                  STATUS_NOT_SUPPORTED
 *                                                  (server/fd.c)
 *
 * Four things an implementation reaching for the obvious grouping gets
 * wrong, and each has its own case below:
 *
 *   - THE THREE ANSWERS DO NOT FOLLOW FROM "THIS IS NOT A PIPE END". A
 *     single refusal for the whole group — the reading that makes
 *     STATUS_ILLEGAL_FUNCTION ("this object does not have this verb") the
 *     natural answer to all of them — is right for LISTEN and IMPERSONATE,
 *     and wrong for the other three. DISCONNECT and TRANSCEIVE report a
 *     STATE the device does not have, and QUERY_CLIENT_PROCESS reports its
 *     ARGUMENTS. Only a matrix can see that; a status table cannot.
 *   - FSCTL_PIPE_PEEK IS NOT IN THE SWITCH. It is as much a per-instance
 *     verb as LISTEN is, so ILLEGAL_FUNCTION is the plausible answer and it
 *     is not the measured one: the oracle never names PEEK here, so it falls
 *     through to default_fd_ioctl and is STATUS_NOT_SUPPORTED like every
 *     verb the device has never heard of. This is the case that separates a
 *     ladder transcribed from the oracle from one grouped by meaning (§2).
 *   - THE REFUSAL PRECEDES THE ARGUMENTS. Every arm answers before any
 *     buffer is looked at, so a TRANSCEIVE carrying a legal input and output
 *     buffer is still STATUS_PIPE_DISCONNECTED and a QUERY_CLIENT_PROCESS
 *     with room for its reply is still STATUS_INVALID_PARAMETER — which is
 *     the opposite of what "INVALID_PARAMETER" invites you to implement
 *     (§3).
 *   - AND THE DEVICE AND ITS ROOT DIRECTORY ANSWER THE SAME, for every verb
 *     in this file. They are two objects on the oracle
 *     (named_pipe_device_file_ops vs named_pipe_dir_ops) and
 *     named_pipe_dir_ioctl's default arm is a tail call onto the device's,
 *     so the two ladders differ in FSCTL_PIPE_WAIT and in nothing else. The
 *     winetest asks the matrix through both handles, and so does §4 — "the
 *     two arms must agree" is a measurement here, not an argument.
 *
 * What this file deliberately does NOT pin: FSCTL_PIPE_WAIT, whose answer is
 * the ONE place the two ladders part (the device refuses it,
 * ILLEGAL_FUNCTION; the directory serves it, which sem_pipe/pipe_wait.c
 * pins). proskrnl cannot tell the two apart — ObpLookupName hands the FS an
 * empty remainder for both spellings, docs/21 W7's parser question, the same
 * one `\??\C:` vs `\??\C:\` asks — so it serves the lookup through both, and
 * that is the winetest's remaining :2787. Pinning it here would be pinning a
 * behaviour this change does not build.
 */
#include "util.h"

struct verb_row
{
    const char *name;
    ULONG code;
    NTSTATUS status;
};

/* The winetest's own eight rows, minus the win10-1507 `broken()` alternative
 * it carries for QUERY_CLIENT_PROCESS (a pin measures the pinned oracle, not
 * the union of every Windows build). */
static const struct verb_row VerbRows[] = {
    {"FSCTL_PIPE_ASSIGN_EVENT", FSCTL_PIPE_ASSIGN_EVENT, STATUS_NOT_SUPPORTED},
    {"FSCTL_PIPE_DISCONNECT", FSCTL_PIPE_DISCONNECT, STATUS_PIPE_DISCONNECTED},
    {"FSCTL_PIPE_LISTEN", FSCTL_PIPE_LISTEN, STATUS_ILLEGAL_FUNCTION},
    {"FSCTL_PIPE_QUERY_EVENT", FSCTL_PIPE_QUERY_EVENT, STATUS_NOT_SUPPORTED},
    {"FSCTL_PIPE_TRANSCEIVE", FSCTL_PIPE_TRANSCEIVE, STATUS_PIPE_DISCONNECTED},
    {"FSCTL_PIPE_IMPERSONATE", FSCTL_PIPE_IMPERSONATE, STATUS_ILLEGAL_FUNCTION},
    {"FSCTL_PIPE_SET_CLIENT_PROCESS", FSCTL_PIPE_SET_CLIENT_PROCESS, STATUS_NOT_SUPPORTED},
    {"FSCTL_PIPE_QUERY_CLIENT_PROCESS", FSCTL_PIPE_QUERY_CLIENT_PROCESS, STATUS_INVALID_PARAMETER},
};

/* Open one of the two spellings of the device root. `wideName` is absolute;
 * the caller says which. */
static NTSTATUS open_root(HANDLE *handle, const void *wideName)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    poison_iosb(&iosb);
    return NtCreateFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0,
                        NULL, 0);
}

/* The eight-row matrix, exactly as subtest_empty_name_pipe_operations runs
 * it: no input, no output, no event. */
static void run_matrix(HANDLE root, const char *which)
{
    for (unsigned i = 0; i < sizeof(VerbRows) / sizeof(VerbRows[0]); i++)
    {
        IO_STATUS_BLOCK iosb;
        poison_iosb(&iosb);
        NTSTATUS status = pipe_fsctl(root, VerbRows[i].code, &iosb);
        ok(status == VerbRows[i].status, "%s on %s -> %08lx, want %08lx", VerbRows[i].name, which,
           (unsigned long)status, (unsigned long)VerbRows[i].status);
    }
}

START_TEST(device_ioctl)
{
    HANDLE device = NULL, dir = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    /* §1 — the DEVICE itself, the name the winetest opens. */
    status = open_root(&device, W("\\Device\\NamedPipe"));
    ok(status == STATUS_SUCCESS, "open \\Device\\NamedPipe -> %08lx", (unsigned long)status);
    if (device == NULL)
    {
        skip("no named-pipe device root");
        return;
    }
    run_matrix(device, "the device");

    /* §2 — PEEK is not in the switch, so it is the device's unknown-verb
     * answer and not the "wrong object for this verb" one the neighbouring
     * LISTEN row gets. The winetest's own :2721 asks the same call and is
     * marked todo_wine (it wants NT's STATUS_INVALID_PARAMETER), so the
     * oracle is the only authority for what falls out here — which is
     * exactly why it is measured rather than reasoned about. */
    {
        SEM_FILE_PIPE_PEEK_BUFFER peek;
        poison_iosb(&iosb);
        status = NtFsControlFile(device, NULL, NULL, NULL, &iosb, FSCTL_PIPE_PEEK, NULL, 0, &peek,
                                 sizeof(peek));
        ok(status == STATUS_NOT_SUPPORTED, "PEEK on the device -> %08lx", (unsigned long)status);
    }

    /* §3 — the refusal precedes the arguments. Same two verbs, now with the
     * buffers a real caller would pass: the answer does not move, and the
     * IOSB the refusal never reached is left as the caller poisoned it (the
     * rule sem_pipe/ioctl_event.c pins for an ioctl refused on the spot). */
    {
        unsigned char message[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        unsigned char reply[32];
        ULONG clientPid = 0;

        poison_iosb(&iosb);
        status = NtFsControlFile(device, NULL, NULL, NULL, &iosb, FSCTL_PIPE_TRANSCEIVE, message,
                                 sizeof(message), reply, sizeof(reply));
        ok(status == STATUS_PIPE_DISCONNECTED, "TRANSCEIVE with buffers -> %08lx",
           (unsigned long)status);
        ok(iosb.Status == IOSB_POISON_STATUS, "TRANSCEIVE refusal left the IOSB alone (%08lx)",
           (unsigned long)iosb.Status);

        poison_iosb(&iosb);
        status = NtFsControlFile(device, NULL, NULL, NULL, &iosb, FSCTL_PIPE_QUERY_CLIENT_PROCESS,
                                 NULL, 0, &clientPid, sizeof(clientPid));
        ok(status == STATUS_INVALID_PARAMETER, "QUERY_CLIENT_PROCESS with a reply buffer -> %08lx",
           (unsigned long)status);
        ok(iosb.Status == IOSB_POISON_STATUS,
           "QUERY_CLIENT_PROCESS refusal left the IOSB alone (%08lx)", (unsigned long)iosb.Status);
    }

    /* §4 — the device's ROOT DIRECTORY answers the same matrix. Two objects
     * on the oracle, one tail call apart. */
    status = open_root(&dir, W("\\Device\\NamedPipe\\"));
    ok(status == STATUS_SUCCESS, "open \\Device\\NamedPipe\\ -> %08lx", (unsigned long)status);
    if (dir != NULL)
    {
        run_matrix(dir, "the root directory");
        NtClose(dir);
    }

    NtClose(device);
}
