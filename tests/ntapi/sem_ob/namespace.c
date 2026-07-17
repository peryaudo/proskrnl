/*
 * sem_ob/namespace.c — object directories and symbolic links (M3, docs/02).
 *
 * The namespace contract: directories can be created and used as
 * RootDirectory for relative lookups; symbolic links resolve inside a path
 * so two different paths can name ONE object; NtQuerySymbolicLinkObject
 * returns the stored target, including the too-small-buffer convention.
 */
#include "util.h"

static const void *dir_name = W("\\BaseNamedObjects\\prsk_m3_dir");
static const void *link_name = W("\\BaseNamedObjects\\prsk_m3_link");
static const void *event_abs = W("\\BaseNamedObjects\\prsk_m3_dir\\evt");
static const void *event_via_link = W("\\BaseNamedObjects\\prsk_m3_link\\evt");
static const void *event_rel = W("evt");

START_TEST(namespace)
{
    UNICODE_STRING name, target;
    OBJECT_ATTRIBUTES attr;
    HANDLE dir, link, event, other;
    NTSTATUS status;

    /* Create a directory object to hold the rest of the test's names. */
    init_ustr(&name, dir_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateDirectoryObject(&dir, DIRECTORY_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "NtCreateDirectoryObject -> %08lx", (unsigned long)status);

    /* An absolute create inside it, then a RELATIVE open via RootDirectory:
     * both must bind the same object. */
    init_ustr(&name, event_abs);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event in dir -> %08lx", (unsigned long)status);

    init_ustr(&name, event_rel);
    init_attr(&attr, dir, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "relative open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtSetEvent(other, NULL);
        ok(wait_now(event) == STATUS_SUCCESS, "relative open bound a different object");
        NtResetEvent(other, NULL);
        NtClose(other);
    }

    /* A symbolic link to the directory: the linked path and the real path
     * must resolve to ONE object. */
    init_ustr(&name, link_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    init_ustr(&target, dir_name);
    status = NtCreateSymbolicLinkObject(&link, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_SUCCESS, "NtCreateSymbolicLinkObject -> %08lx", (unsigned long)status);

    init_ustr(&name, event_via_link);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "open through symlink -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtSetEvent(other, NULL);
        ok(wait_now(event) == STATUS_SUCCESS, "symlink path bound a different object");
        NtResetEvent(other, NULL);
        NtClose(other);
    }

    /* NtQuerySymbolicLinkObject returns the stored target string. */
    {
        WCHAR buffer[64];
        UNICODE_STRING out;
        ULONG needed = 0;
        out.Length = 0;
        out.MaximumLength = sizeof(buffer);
        out.Buffer = buffer;
        status = NtQuerySymbolicLinkObject(link, &out, &needed);
        ok(status == STATUS_SUCCESS, "NtQuerySymbolicLinkObject -> %08lx", (unsigned long)status);
        init_ustr(&target, dir_name);
        ok(out.Length == target.Length, "target length %u, expected %u", out.Length, target.Length);
        if (out.Length == target.Length)
        {
            int same = 1;
            for (unsigned i = 0; i < out.Length / 2; i++)
                if (out.Buffer[i] != target.Buffer[i])
                    same = 0;
            ok(same, "target text differs");
        }

        /* Too-small buffer: STATUS_BUFFER_TOO_SMALL, needed = full size. */
        out.Length = 0;
        out.MaximumLength = 2;
        out.Buffer = buffer;
        needed = 0;
        status = NtQuerySymbolicLinkObject(link, &out, &needed);
        ok(status == STATUS_BUFFER_TOO_SMALL, "tiny buffer -> %08lx", (unsigned long)status);
        ok(needed >= target.Length, "needed %lu < target %u", (unsigned long)needed, target.Length);
    }

    /* A directory is not an event: opening it as one is a type mismatch. */
    init_ustr(&name, dir_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "open dir as event -> %08lx", (unsigned long)status);

    /* Reopening the directory by name binds the same directory object. */
    status = NtOpenDirectoryObject(&other, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "NtOpenDirectoryObject -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(other);

    NtClose(event);
    NtClose(link);
    NtClose(dir);
}
