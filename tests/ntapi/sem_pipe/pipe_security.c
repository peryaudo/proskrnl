/*
 * sem_pipe/pipe_security.c — WHOSE security descriptor a pipe handle reports.
 *
 * docs/21 W11's largest remaining cluster: dlls/ntdll/tests/pipe.c
 * test_security_info (:2605-:2664) sets a group through one end of a named
 * pipe and reads it back through the other, through a second INSTANCE, and
 * after the end that set it is gone. Ten assertions, one subject, and the
 * subject is not an npfs one — it is WHICH OBJECT the Se surface is asked
 * about when the handle names a pipe end.
 *
 * The oracle's shape (third_party/wine):
 *
 *   server/handle.c   DECL_HANDLER(get_security_object) / (set_security_object)
 *                     check the HANDLE's access first (READ_CONTROL to query,
 *                     WRITE_OWNER/WRITE_DAC/ACCESS_SYSTEM_SECURITY per info
 *                     bit to set) and only then call the type's hook
 *   server/named_pipe.c
 *     pipe_end_get_sd  `if (pipe_end->pipe) return default_get_sd(
 *     pipe_end_set_sd   &pipe_end->pipe->obj );` — an END has no descriptor of
 *                       its own, it DEFERS to its pipe; with no pipe the
 *                       answer is STATUS_PIPE_DISCONNECTED
 *     DECL_HANDLER(create_named_pipe)
 *                      `if (sd) default_set_sd( &pipe->obj, sd, OWNER|GROUP|
 *                       DACL|SACL )`, inside the arm that runs only when the
 *                       pipe did not already exist
 *   server/object.c   set_sd_defaults_from_token — the same merge
 *                     NtSetSecurityObject uses, so a create-time descriptor is
 *                     not a raw copy: its missing parts default from the token
 *
 * Three things an implementation gets wrong by reaching for the obvious:
 *
 *   - THE DESCRIPTOR BELONGS TO THE PIPE, NOT THE HANDLE, NOT THE END AND NOT
 *     THE INSTANCE. Storing it per handle passes every set-then-query-the-
 *     same-handle case and fails the moment a second end or a second instance
 *     asks — which is exactly the half of the winetest that fails today. §2-§5
 *     ask it from all four directions.
 *   - "NO PIPE" IS A REFUSAL, NOT AN EMPTY ANSWER. A client end whose server
 *     disconnected it still answers every other class; this one refuses with
 *     STATUS_PIPE_DISCONNECTED (§6), and the refusal is BELOW the handle's
 *     access check, so a query that was not entitled to ask gets
 *     STATUS_ACCESS_DENIED instead (§6 again — the two are separable and only
 *     an under-privileged query on a disconnected end can see the order).
 *   - A CREATE-TIME DESCRIPTOR BINDS ONCE. It is applied by the arm that MINTS
 *     the pipe, so a further instance of an existing pipe carries its
 *     descriptor along and silently drops its own (§7). An implementation that
 *     applied it per instance passes the winetest — which never sets a
 *     different one on a second instance — and rewrites the pipe's security
 *     from any caller that can open it.
 *
 * §8 is a handle on the pipe device's ROOT, which has no end at all. It is here
 * because the redirect above has to answer SOMETHING for it and an unmeasured
 * answer is a fabricated one (Art. 12). The answer is PER OPEN: the oracle
 * mints a fresh `named_pipe_dir` on every open of `\??\pipe\` and its
 * `default_get_sd` reads that object's own descriptor
 * (server/named_pipe.c named_pipe_dir_ops), so a set through one root handle
 * is invisible to the next — which is the discriminating case, and the only
 * one that can tell it from a descriptor kept on the shared device.
 *
 * The identity SIDs come from sem_se/util.h, i.e. from wineserver's
 * token_create_admin, which proskrnl's SeInitializeSecuritySubsystem mints
 * identically (that file's header has the whole argument).
 */
#include "util.h"
#include "../sem_se/util.h"

#define PIPE_SECURITY_NAME  W("\\??\\pipe\\prstest_security")
#define PIPE_SECURITY_NAME2 W("\\??\\pipe\\prstest_security2")

/* Every handle here wants the two rights the Se surface asks for, on top of
 * the data access the pipe helpers use: READ_CONTROL to query (it rides in
 * FILE_GENERIC_READ already, spelled out so a reader does not have to know
 * that) and WRITE_OWNER, which no generic mapping grants. */
#define PIPE_SECURITY_ACCESS                                                                       \
    (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL | WRITE_OWNER)

/* One server-end instance, optionally carrying a create-time descriptor. */
static NTSTATUS create_server(HANDLE *handle, const void *wide_name, void *sd, ULONG maxInstances)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    attr.SecurityDescriptor = sd;
    timeout.QuadPart = -100 * 10000; /* 100 ms, relative */
    poison_iosb(&iosb);
    *handle = NULL;
    return NtCreateNamedPipeFile(
        handle, PIPE_SECURITY_ACCESS, &attr, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
        FILE_PIPE_QUEUE_OPERATION, maxInstances, 4096, 4096, &timeout);
}

static NTSTATUS open_client(HANDLE *handle, const void *wide_name)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, wide_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    poison_iosb(&iosb);
    *handle = NULL;
    return NtCreateFile(handle, PIPE_SECURITY_ACCESS, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

/* The pipe device's ROOT DIRECTORY: "\??\pipe\", WITH the trailing separator.
 * The spelling without it is the DEVICE FILE, which proskrnl cannot yet tell
 * from the directory (docs/21 W7's parser item, the same one `\??\C:` vs
 * `\??\C:\` asks) — so this file never uses it. */
static NTSTATUS open_pipe_root(HANDLE *handle)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, W("\\??\\pipe\\"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    poison_iosb(&iosb);
    *handle = NULL;
    return NtCreateFile(handle, PIPE_SECURITY_ACCESS, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);
}

/* GROUP_SECURITY_INFORMATION into `buf`; returns the status. */
static NTSTATUS query_group(HANDLE handle, BYTE *buf, ULONG length, ULONG *retlen)
{
    memset(buf, 0xcc, length);
    *retlen = 0;
    return NtQuerySecurityObject(handle, GROUP_SECURITY_INFORMATION, buf, length, retlen);
}

/* "Does this handle report `sid` as the group?" — one call, so the eight
 * places that ask it read as the one question they are. */
static void expect_group(HANDLE handle, const void *sid, const char *what)
{
    BYTE buf[512];
    SECURITY_DESCRIPTOR_RELATIVE *sd = (SECURITY_DESCRIPTOR_RELATIVE *)buf;
    ULONG retlen = 0;
    NTSTATUS status = query_group(handle, buf, sizeof(buf), &retlen);

    ok(status == STATUS_SUCCESS, "%s: query -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(sd->Group != 0, "%s: no group in the reported descriptor", what);
    if (sd->Group == 0)
        return;
    ok(equal_sid(buf + sd->Group, sid), "%s: group is not the one that was set", what);
}

static NTSTATUS set_group(HANDLE handle, const void *sid)
{
    BYTE buf[256];
    build_sd(buf, NULL, sid, 0, NULL, 0);
    return NtSetSecurityObject(handle, GROUP_SECURITY_INFORMATION, buf);
}

START_TEST(pipe_security)
{
    NTSTATUS status;
    HANDLE server = NULL, server2 = NULL, client = NULL, root = NULL;
    IO_STATUS_BLOCK iosb;
    BYTE buf[512], sdbuf[256];
    SECURITY_DESCRIPTOR_RELATIVE *sd = (SECURITY_DESCRIPTOR_RELATIVE *)buf;
    ULONG retlen;
    sid_buf world, local, users;

    sid_world(&world);
    sid_local(&local);
    sid_domain_users(&users);

    /* --- §1: a fresh pipe carries no descriptor, through either end -------- */
    status = create_server(&server, PIPE_SECURITY_NAME, NULL, 4);
    ok(status == STATUS_SUCCESS, "create server -> %08lx", (unsigned long)status);
    status = open_client(&client, PIPE_SECURITY_NAME);
    ok(status == STATUS_SUCCESS, "open client -> %08lx", (unsigned long)status);

    retlen = 0;
    status = query_group(server, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "fresh server query -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(SECURITY_DESCRIPTOR_RELATIVE), "fresh server retlen %lu",
       (unsigned long)retlen);
    ok(sd->Group == 0, "fresh server group offset %lu", (unsigned long)sd->Group);
    retlen = 0;
    status = query_group(client, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "fresh client query -> %08lx", (unsigned long)status);
    ok(sd->Group == 0, "fresh client group offset %lu", (unsigned long)sd->Group);

    /* --- §2: what the SERVER end sets, the CLIENT end reports -------------- */
    status = set_group(server, world.buf);
    ok(status == STATUS_SUCCESS, "set group on server -> %08lx", (unsigned long)status);
    expect_group(server, world.buf, "server after its own set");
    expect_group(client, world.buf, "client after the server's set");

    /* --- §3: and so does a second INSTANCE of the same pipe ---------------- */
    status = create_server(&server2, PIPE_SECURITY_NAME, NULL, 4);
    ok(status == STATUS_SUCCESS, "create second instance -> %08lx", (unsigned long)status);
    expect_group(server2, world.buf, "second instance");

    /* --- §4: the other direction — a CLIENT's set reaches every end -------- */
    status = set_group(client, local.buf);
    ok(status == STATUS_SUCCESS, "set group on client -> %08lx", (unsigned long)status);
    expect_group(server, local.buf, "server after the client's set");
    expect_group(server2, local.buf, "second instance after the client's set");

    /* --- §5: the descriptor outlives the end that set it ------------------- */
    NtClose(server);
    server = NULL;
    expect_group(client, local.buf, "client after the first server end closed");
    expect_group(server2, local.buf, "second instance after the first closed");

    /* ...and dies with the PIPE. Every handle goes, so the pipe object goes
     * with them, and the next pipe of that name is a different object with a
     * fresh (absent) descriptor — not a name that remembers. */
    NtClose(client);
    client = NULL;
    NtClose(server2);
    server2 = NULL;
    status = create_server(&server, PIPE_SECURITY_NAME, NULL, 4);
    ok(status == STATUS_SUCCESS, "recreate -> %08lx", (unsigned long)status);
    retlen = 0;
    status = query_group(server, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "recreated query -> %08lx", (unsigned long)status);
    ok(sd->Group == 0, "recreated group offset %lu", (unsigned long)sd->Group);

    /* --- §6: a disconnected CLIENT end has no pipe to defer to ------------- */
    status = open_client(&client, PIPE_SECURITY_NAME);
    ok(status == STATUS_SUCCESS, "reopen client -> %08lx", (unsigned long)status);
    status = set_group(server, world.buf);
    ok(status == STATUS_SUCCESS, "set group before disconnect -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = pipe_fsctl(server, FSCTL_PIPE_DISCONNECT, &iosb);
    ok(status == STATUS_SUCCESS, "disconnect -> %08lx", (unsigned long)status);

    retlen = 0;
    status = query_group(client, buf, sizeof(buf), &retlen);
    ok(status == STATUS_PIPE_DISCONNECTED, "disconnected client query -> %08lx",
       (unsigned long)status);
    status = set_group(client, local.buf);
    ok(status == STATUS_PIPE_DISCONNECTED, "disconnected client set -> %08lx",
       (unsigned long)status);
    /* The SERVER end kept its pipe: the disconnect throws the CLIENT out, not
     * the end that issued it. */
    expect_group(server, world.buf, "server after disconnecting its client");

    /* The refusal is BELOW the handle's access check, and this is the only
     * shape that can tell the two apart: no handle here carries
     * ACCESS_SYSTEM_SECURITY, so asking for the SACL is refused for the
     * ACCESS reason even on the end that has nothing else to say. */
    memset(buf, 0xcc, sizeof(buf));
    retlen = 0;
    status = NtQuerySecurityObject(client, SACL_SECURITY_INFORMATION, buf, sizeof(buf), &retlen);
    ok(status == STATUS_ACCESS_DENIED, "disconnected client SACL query -> %08lx",
       (unsigned long)status);

    NtClose(client);
    client = NULL;
    NtClose(server);
    server = NULL;

    /* --- §7: a create-time descriptor binds to the pipe, once -------------- */
    build_sd(sdbuf, NULL, world.buf, 0, NULL, 0);
    status = create_server(&server, PIPE_SECURITY_NAME2, sdbuf, 4);
    ok(status == STATUS_SUCCESS, "create with sd -> %08lx", (unsigned long)status);
    expect_group(server, world.buf, "create-time descriptor");

    /* The merge is the one NtSetSecurityObject uses, not a raw copy: the
     * descriptor above names no owner, and the token's fills it in. */
    memset(buf, 0xcc, sizeof(buf));
    retlen = 0;
    status = NtQuerySecurityObject(server, OWNER_SECURITY_INFORMATION, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "create-time owner query -> %08lx", (unsigned long)status);
    ok(sd->Owner != 0, "create-time descriptor has no defaulted owner");
    if (sd->Owner != 0)
        ok(equal_sid(buf + sd->Owner, users.buf), "defaulted owner is not the token owner");

    /* A further instance of an EXISTING pipe carries a descriptor of its own
     * and it is DROPPED — the pipe already exists, so the arm that applies it
     * never runs. */
    build_sd(sdbuf, NULL, local.buf, 0, NULL, 0);
    status = create_server(&server2, PIPE_SECURITY_NAME2, sdbuf, 4);
    ok(status == STATUS_SUCCESS, "second instance with sd -> %08lx", (unsigned long)status);
    expect_group(server2, world.buf, "second instance keeps the pipe's descriptor");
    expect_group(server, world.buf, "first instance unchanged by it");

    NtClose(server2);
    server2 = NULL;
    NtClose(server);
    server = NULL;

    /* --- §8: the device's root handle, which has no end ------------------- */
    {
        HANDLE root2 = NULL;

        status = open_pipe_root(&root);
        ok(status == STATUS_SUCCESS, "open pipe root -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            retlen = 0;
            status = query_group(root, buf, sizeof(buf), &retlen);
            ok(status == STATUS_SUCCESS, "pipe root query -> %08lx", (unsigned long)status);
            ok(retlen == sizeof(SECURITY_DESCRIPTOR_RELATIVE), "pipe root retlen %lu",
               (unsigned long)retlen);
            ok(sd->Group == 0, "pipe root group offset %lu", (unsigned long)sd->Group);

            /* Per OPEN, not per device: what this handle sets, a handle opened
             * beside it does not see — and it dies with the handle rather than
             * outliving the boot on the one device object. */
            status = set_group(root, world.buf);
            ok(status == STATUS_SUCCESS, "pipe root set -> %08lx", (unsigned long)status);
            expect_group(root, world.buf, "pipe root after its own set");

            status = open_pipe_root(&root2);
            ok(status == STATUS_SUCCESS, "reopen pipe root -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                retlen = 0;
                status = query_group(root2, buf, sizeof(buf), &retlen);
                ok(status == STATUS_SUCCESS, "second pipe root query -> %08lx",
                   (unsigned long)status);
                ok(sd->Group == 0, "second pipe root group offset %lu", (unsigned long)sd->Group);
                NtClose(root2);
            }
            NtClose(root);
        }
    }
}
