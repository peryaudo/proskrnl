/*
 * sem_pipe/pipe_mode_set.c — what NtSetInformationFile(FilePipeInformation)
 * validates, and in what ORDER.
 *
 * docs/21 W11, the last item inside ntdll:pipe's measured prefix
 * (dlls/ntdll/tests/pipe.c test_filepipeinfo, :886-:989). The class is two
 * ULONGs and every one of its twelve failing assertions is a guard that is
 * missing or in the wrong place, so the order is the content here.
 *
 * The ladder is split across the two halves of the oracle, and that split is
 * exactly what decides which mistake is reported:
 *
 *   dlls/ntdll/unix/file.c  NtSetInformationFile, case FilePipeInformation
 *       if (len >= sizeof(FILE_PIPE_INFORMATION)) {
 *           if ((info->CompletionMode | info->ReadMode) & ~1)
 *               status = STATUS_INVALID_PARAMETER;
 *           else SERVER_START_REQ( set_named_pipe_info ) ...
 *       } else status = STATUS_INVALID_PARAMETER_3;
 *
 *   server/named_pipe.c     DECL_HANDLER(set_named_pipe_info)
 *       get_handle_obj( ..., FILE_WRITE_ATTRIBUTES, &pipe_server_ops )
 *       — and, only on STATUS_OBJECT_TYPE_MISMATCH, a retry as
 *       get_handle_obj( ..., 0, &pipe_client_ops )
 *       if (!pipe_end->pipe)                     -> STATUS_PIPE_DISCONNECTED
 *       else if (flags & ~(READ|NONBLOCKING) ||
 *                (message read mode && !pipe->message_mode))
 *                                                -> STATUS_INVALID_PARAMETER
 *       else pipe_end->flags = req->flags;
 *
 * So: LENGTH, then RANGE, then the HANDLE (type before access, server/handle.c
 * get_handle_obj), then DISCONNECTED, then the byte-pipe rule. The first two
 * run before the handle exists at all, which is why a junk handle with an
 * out-of-range value reports the value.
 *
 * Two asymmetries no status table shows, and each is a way an implementation
 * reaching for the tidy rule diverges:
 *
 *   - the SERVER end demands FILE_WRITE_ATTRIBUTES and the CLIENT end demands
 *     NOTHING. The retry is what makes that true — a client handle fails the
 *     first lookup on TYPE (checked before access, so its zero access never
 *     shows) and the second asks for no access at all;
 *   - `pipe_end->flags = req->flags` REPLACES both fields together. The
 *     neighbouring class 41 (FileIoCompletionNotificationInformation) ORs, and
 *     nothing here does.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG,
                                          ULONG);
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0) /* wine/include/winternl.h */

static NTSTATUS set_pipe_mode_len(HANDLE handle, ULONG readMode, ULONG completionMode, ULONG length,
                                  IO_STATUS_BLOCK *iosb)
{
    SEM_FILE_PIPE_INFORMATION info;

    info.ReadMode = readMode;
    info.CompletionMode = completionMode;
    poison_iosb(iosb);
    return NtSetInformationFile(handle, iosb, &info, length, FilePipeInformation);
}

static NTSTATUS set_pipe_mode(HANDLE handle, ULONG readMode, ULONG completionMode,
                              IO_STATUS_BLOCK *iosb)
{
    return set_pipe_mode_len(handle, readMode, completionMode, sizeof(SEM_FILE_PIPE_INFORMATION),
                             iosb);
}

/* Read the pair back. The handle must carry FILE_READ_ATTRIBUTES for this
 * (pinned by create_refusals.c); every handle below that is queried has it. */
static void check_mode(int line, HANDLE handle, ULONG readMode, ULONG completionMode,
                       const char *what)
{
    IO_STATUS_BLOCK iosb;
    SEM_FILE_PIPE_INFORMATION info;
    NTSTATUS status;

    info.ReadMode = 0x55555555;
    info.CompletionMode = 0x55555555;
    poison_iosb(&iosb);
    status = NtQueryInformationFile(handle, &iosb, &info, sizeof(info), FilePipeInformation);
    ntapi_okv(status == STATUS_SUCCESS, __FILE__, line, "%s: query -> %08lx", what,
              (unsigned long)status);
    ntapi_okv(info.ReadMode == readMode, __FILE__, line, "%s: ReadMode %lu, wanted %lu", what,
              (unsigned long)info.ReadMode, (unsigned long)readMode);
    ntapi_okv(info.CompletionMode == completionMode, __FILE__, line,
              "%s: CompletionMode %lu, wanted %lu", what, (unsigned long)info.CompletionMode,
              (unsigned long)completionMode);
}
#define CHECK_MODE(h, r, c, what) check_mode(__LINE__, (h), (r), (c), (what))

/* One server-end instance with a chosen access word and a chosen pipe type.
 * The completion mode is set at CREATE to 1 so a wrongly-accepted set is
 * visible as a state change rather than as a no-op. */
static NTSTATUS create_server(HANDLE *handle, const void *wideName, ULONG access, ULONG type,
                              ULONG readMode, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    LARGE_INTEGER timeout;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    *handle = NULL;
    return NtCreateNamedPipeFile(handle, access, &attr, iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, type, readMode,
                                 FILE_PIPE_COMPLETE_OPERATION, 1, 4096, 4096, &timeout);
}

static NTSTATUS open_client(HANDLE *handle, const void *wideName, ULONG access,
                            IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    init_ustr(&name, wideName);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access | SYNCHRONIZE, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* A distinct pipe name per sub-case: one leaked instance would turn a later
 * create into INSTANCE_NOT_AVAILABLE and the failure would name the wrong
 * rule (the argument create_refusals.c already makes). */
static unsigned short NameBuffer[64];
static const void *pipe_name(unsigned index)
{
    static const unsigned short base[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e',
                                          '\\', 'p', 'r', 's',  't', 'e', 's', 't',
                                          '_',  'm', 'o', 'd',  'e', '_', 0};
    unsigned i = 0;
    while (base[i] != 0)
    {
        NameBuffer[i] = base[i];
        i++;
    }
    NameBuffer[i++] = (unsigned short)('a' + (index / 10));
    NameBuffer[i++] = (unsigned short)('0' + (index % 10));
    NameBuffer[i] = 0;
    return NameBuffer;
}

/* The two checks the oracle makes in ntdll, above the server call — so above
 * the handle entirely. INVALID_HANDLE_VALUE is the pseudo-handle for the
 * current PROCESS, which get_magic_handle resolves and neither pipe ops table
 * matches, so a well-formed request through it is STATUS_OBJECT_TYPE_MISMATCH
 * (dlls/ntdll/tests/pipe.c:866 asserts exactly that). Every case below uses
 * it as the handle that CANNOT be the answer: whatever these report, they
 * reported it without looking. */
static void test_length_and_range_precede_the_handle(void)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = set_pipe_mode(INVALID_HANDLE_VALUE, 0, 0, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "well-formed on a non-pipe handle -> %08lx",
       (unsigned long)status);

    /* Range beats the handle. */
    status = set_pipe_mode(INVALID_HANDLE_VALUE, 2, 0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "ReadMode 2 on a non-pipe handle -> %08lx",
       (unsigned long)status);
    status = set_pipe_mode(INVALID_HANDLE_VALUE, 0, 2, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "CompletionMode 2 on a non-pipe handle -> %08lx",
       (unsigned long)status);

    /* The bound is `& ~1`, not "> 1": every bit above the low one is out of
     * range, including the sign bit, and an implementation testing `> 1` on a
     * signed type would admit the last of these. */
    status = set_pipe_mode(INVALID_HANDLE_VALUE, 0x80000000u, 0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "ReadMode 0x80000000 -> %08lx", (unsigned long)status);

    /* Length beats the handle AND beats the range — a short buffer with
     * out-of-range values still reports the length, and reports it as
     * STATUS_INVALID_PARAMETER_3 rather than the INFO_LENGTH_MISMATCH the
     * QUERY direction gives for the same class (that one is table-driven,
     * info_sizes[]; this one is hand-written per class). */
    status = set_pipe_mode_len(INVALID_HANDLE_VALUE, 0, 0, 4, &iosb);
    ok(status == STATUS_INVALID_PARAMETER_3, "short buffer -> %08lx", (unsigned long)status);
    status = set_pipe_mode_len(INVALID_HANDLE_VALUE, 2, 2, 4, &iosb);
    ok(status == STATUS_INVALID_PARAMETER_3, "short buffer with out-of-range values -> %08lx",
       (unsigned long)status);

    /* Longer than the class is fine: the oracle tests `len >=`. */
    status =
        set_pipe_mode_len(INVALID_HANDLE_VALUE, 0, 0, sizeof(SEM_FILE_PIPE_INFORMATION) + 4, &iosb);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "oversized buffer -> %08lx", (unsigned long)status);

    /* "Names no pipe END" includes the npfs ROOT device: `\??\pipe\` opens as
     * the oracle's named_pipe_device_file, which matches neither ops table, so
     * BOTH lookups leave on the type and the answer is the same as any other
     * non-pipe handle. A kernel that routes the class into its pipe FS and
     * lets the FS notice it has no stream answers a device status instead —
     * which is what makes this worth a case rather than a remark. */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE root = NULL;

        init_ustr(&name, W("\\??\\pipe\\"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateFile(&root, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                              FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        ok(status == STATUS_SUCCESS, "open of the npfs root -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            status = set_pipe_mode(root, 0, 0, &iosb);
            ok(status == STATUS_OBJECT_TYPE_MISMATCH, "set on the npfs root -> %08lx",
               (unsigned long)status);
            NtClose(root);
        }
    }
}

/* The SERVER end's FILE_WRITE_ATTRIBUTES, and the fact that it is checked
 * ABOVE the byte-pipe rule. dlls/ntdll/tests/pipe.c:894 is exactly this: a
 * message read mode on a byte pipe, through an unentitled server handle,
 * answers ACCESS_DENIED and not INVALID_PARAMETER. */
static void test_server_end_needs_write_attributes(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE weak = NULL, strong = NULL;
    NTSTATUS status;

    status = create_server(&weak, pipe_name(0), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "weak server create -> %08lx", (unsigned long)status);
    CHECK_MODE(weak, 0, 1, "weak server at create");

    status = set_pipe_mode(weak, 0, 0, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "in-range set on a READ_ATTRIBUTES server -> %08lx",
       (unsigned long)status);
    CHECK_MODE(weak, 0, 1, "after the refused in-range set");

    /* Access before the byte-pipe rule. */
    status = set_pipe_mode(weak, 1, 1, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "message read mode on a READ_ATTRIBUTES server -> %08lx",
       (unsigned long)status);
    CHECK_MODE(weak, 0, 1, "after the refused message-mode set");

    /* Range before access: the same unentitled handle reports the VALUE when
     * the value is out of range, because that check never reaches the pipe. */
    status = set_pipe_mode(weak, 0, 2, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "out-of-range set on a READ_ATTRIBUTES server -> %08lx",
       (unsigned long)status);

    NtClose(weak);

    status = create_server(&strong, pipe_name(1),
                           FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                           FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "strong server create -> %08lx", (unsigned long)status);

    status = set_pipe_mode(strong, 0, 0, &iosb);
    ok(status == STATUS_SUCCESS, "in-range set on a WRITE_ATTRIBUTES server -> %08lx",
       (unsigned long)status);
    CHECK_MODE(strong, 0, 0, "after the accepted set");

    /* The byte-pipe rule, now reachable. */
    status = set_pipe_mode(strong, 1, 1, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "message read mode on a byte pipe -> %08lx",
       (unsigned long)status);
    CHECK_MODE(strong, 0, 0, "after the refused message-mode set");

    /* The access is the HANDLE's, not the OPEN's, and only a second handle to
     * one file object can tell those apart. NtDuplicateObject grants the
     * specific bits verbatim, so this duplicate names the same pipe end
     * through a handle that lacks the one bit — and the oracle's
     * `get_handle_obj( ..., FILE_WRITE_ATTRIBUTES, ... )` reads
     * `entry->access`, the duplicate's own word. An implementation that keeps
     * the create's granted access on the file object and tests THAT passes
     * every other case in this file. */
    {
        HANDLE weakDup = NULL;

        status = NtDuplicateObject(NtCurrentProcess(), strong, NtCurrentProcess(), &weakDup,
                                   FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, 0);
        ok(status == STATUS_SUCCESS, "duplicate without WRITE_ATTRIBUTES -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            status = set_pipe_mode(weakDup, 0, 1, &iosb);
            ok(status == STATUS_ACCESS_DENIED, "set through the weakened duplicate -> %08lx",
               (unsigned long)status);
            CHECK_MODE(strong, 0, 0, "after the refused set through the duplicate");
            NtClose(weakDup);
        }
    }

    NtClose(strong);
}

/* The other half of the asymmetry: a CLIENT end needs no access word at all.
 * The handle below carries FILE_READ_ATTRIBUTES so the state can be read back
 * and SYNCHRONIZE because the open is synchronous — and deliberately NOT
 * FILE_WRITE_ATTRIBUTES, which is the whole discrimination. An implementation
 * that hoisted the server's requirement into the class's access table refuses
 * this and passes every other case here. */
static void test_client_end_needs_no_access(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    /* A MESSAGE-type pipe whose SERVER end reads in byte mode: the server's
     * pair is then (0, 1) and the client's target below is (1, 1), so "the
     * server did not move" is a statement the two states can tell apart. With
     * both ends at (1, 1) the assertion passes on a kernel that writes the
     * mode into the shared instance instead of into the end. */
    status = create_server(&server, pipe_name(2),
                           FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                           FILE_PIPE_TYPE_MESSAGE, FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_client(&client, pipe_name(2), FILE_READ_ATTRIBUTES, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    /* A fresh client end is byte read mode / queue completion whatever the
     * server end was created with — the modes are per END. */
    CHECK_MODE(server, 0, 1, "server at create");
    CHECK_MODE(client, 0, 0, "fresh client");

    status = set_pipe_mode(client, 1, 1, &iosb);
    ok(status == STATUS_SUCCESS, "set on a client without WRITE_ATTRIBUTES -> %08lx",
       (unsigned long)status);
    CHECK_MODE(client, 1, 1, "client after the set");
    CHECK_MODE(server, 0, 1, "server end unmoved by the client's set");

    /* Both fields REPLACE together — there is no accumulation and no way to
     * leave one alone (contrast class 41, which ORs and cannot be cleared). */
    status = set_pipe_mode(client, 0, 0, &iosb);
    ok(status == STATUS_SUCCESS, "clearing set -> %08lx", (unsigned long)status);
    CHECK_MODE(client, 0, 0, "client after the clearing set");

    /* Out of range is still out of range on the end that needs no access. */
    status = set_pipe_mode(client, 2, 0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "ReadMode 2 on a client -> %08lx",
       (unsigned long)status);
    status = set_pipe_mode(client, 0, 2, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "CompletionMode 2 on a client -> %08lx",
       (unsigned long)status);
    CHECK_MODE(client, 0, 0, "client after the out-of-range sets");

    NtClose(client);
    NtClose(server);
}

/* `if (!pipe_end->pipe) STATUS_PIPE_DISCONNECTED` — the end a server
 * DISCONNECTED out from under, and the same quantity NpfsFlush already reads
 * as end->pipe == 0. It sits ABOVE the byte-pipe rule, which is measurable:
 * a message read mode on a byte pipe's disconnected client reports the
 * disconnect, not the mode. (It has to be above it — with no pipe there is no
 * message_mode to test.) */
static void test_disconnected_client(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE server = NULL, client = NULL;
    NTSTATUS status;

    status = create_server(&server, pipe_name(3),
                           FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                           FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE, &iosb);
    ok(status == STATUS_SUCCESS, "server create -> %08lx", (unsigned long)status);
    status = open_client(&client, pipe_name(3), FILE_READ_ATTRIBUTES, &iosb);
    ok(status == STATUS_SUCCESS, "client open -> %08lx", (unsigned long)status);

    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    status = set_pipe_mode(client, 0, 0, &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "in-range set on a disconnected client -> %08lx",
       (unsigned long)status);
    status = set_pipe_mode(client, 1, 1, &iosb);
    ok(status == STATUS_PIPE_DISCONNECTED, "message-mode set on a disconnected client -> %08lx",
       (unsigned long)status);

    /* Range still precedes it, for the same reason it precedes everything:
     * that check is in ntdll. */
    status = set_pipe_mode(client, 2, 0, &iosb);
    ok(status == STATUS_INVALID_PARAMETER, "out-of-range set on a disconnected client -> %08lx",
       (unsigned long)status);

    /* The QUERY direction reads the same field one function over
     * (pipe_end_get_file_info's `if (!pipe) STATUS_PIPE_DISCONNECTED`, below
     * its own access and length guards), so the disconnected client cannot
     * read its modes back either — and BOTH pipe classes carry that guard,
     * which is why it belongs to the pipe's info path rather than to this
     * class. FilePipeLocalInformation reports a NamedPipeState field, so
     * "answer it with the disconnected state" is the plausible-looking
     * alternative and the oracle does not do it. */
    {
        SEM_FILE_PIPE_INFORMATION info;
        FILE_PIPE_LOCAL_INFORMATION local;

        poison_iosb(&iosb);
        status = NtQueryInformationFile(client, &iosb, &info, sizeof(info), FilePipeInformation);
        ok(status == STATUS_PIPE_DISCONNECTED, "pipe info on a disconnected client -> %08lx",
           (unsigned long)status);

        poison_iosb(&iosb);
        status =
            NtQueryInformationFile(client, &iosb, &local, sizeof(local), FilePipeLocalInformation);
        ok(status == STATUS_PIPE_DISCONNECTED, "local info on a disconnected client -> %08lx",
           (unsigned long)status);
    }

    /* The SERVER's own end keeps its pipe across its own disconnect — the
     * asymmetry NpfsFlush's comment already records for this quantity. */
    status = set_pipe_mode(server, 0, 1, &iosb);
    ok(status == STATUS_SUCCESS, "set on the disconnecting server -> %08lx", (unsigned long)status);
    CHECK_MODE(server, 0, 1, "server after its own disconnect");

    NtClose(client);
    NtClose(server);
}

START_TEST(pipe_mode_set)
{
    test_length_and_range_precede_the_handle();
    test_server_end_needs_write_attributes();
    test_client_end_needs_no_access();
    test_disconnected_client();
}
