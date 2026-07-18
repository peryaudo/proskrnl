/*
 * sem_ob/namespace_errors.c — object-namespace corner cases the differential
 * fuzzer surfaced (docs/08). Every expectation here is the pinned Wine oracle's
 * behaviour; Wine is the operative oracle (docs/09 Art. 6), so a divergence from
 * it is a proskrnl bug. Pinned on the oracle first (Art. 5).
 */
#include "util.h"

static const void *link_name = W("\\BaseNamedObjects\\prsk_nse_link");
static const void *link2_name = W("\\BaseNamedObjects\\prsk_nse_link2");
static const void *dangler_name = W("\\BaseNamedObjects\\prsk_nse_dangler");
static const void *missing_tgt = W("\\BaseNamedObjects\\prsk_nse_missing");
static const void *base_name = W("\\BaseNamedObjects");
static const void *root_name = W("\\");

START_TEST(namespace_errors)
{
    UNICODE_STRING name, target, empty;
    OBJECT_ATTRIBUTES attr;
    HANDLE h, h2;
    NTSTATUS status;

    /* A zero-length ObjectName on CREATE is treated as unnamed (anonymous), and
     * the object is real — set/wait work. (Open, by contrast, rejects it.) */
    empty.Length = 0;
    empty.MaximumLength = 0;
    empty.Buffer = (PWSTR)(void *)W("");
    init_attr(&attr, NULL, &empty, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&h, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "empty-name create -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtSetEvent(h, NULL);
        ok(wait_now(h) == STATUS_SUCCESS, "empty-name object is usable");
        NtClose(h);
    }

    /* The name "\" denotes the namespace root directory: creating an event
     * there collides with the existing root, opening it as an event is a type
     * mismatch, opening it as a directory succeeds. */
    init_ustr(&name, root_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&h, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "create \"\\\" -> %08lx", (unsigned long)status);
    status = NtOpenEvent(&h, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "open \"\\\" as event -> %08lx",
       (unsigned long)status);
    status = NtOpenDirectoryObject(&h, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open \"\\\" as directory -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(h);

    /* A symbolic-link loop: resolving through it exhausts the reparse budget and
     * NT reports STATUS_INVALID_PARAMETER (not a name error). */
    init_ustr(&name, link_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    init_ustr(&target, link_name); /* the link points at itself */
    status = NtCreateSymbolicLinkObject(&h, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_SUCCESS, "create self-link -> %08lx", (unsigned long)status);
    status = NtOpenEvent(&h2, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_INVALID_PARAMETER, "resolve through link loop -> %08lx",
       (unsigned long)status);
    NtClose(h);

    /* Creating a symbolic link does not follow a link already at the name:
     * a duplicate is a collision, and OBJ_OPENIF reuse is plain SUCCESS (not
     * STATUS_OBJECT_NAME_EXISTS, unlike every other object type). */
    init_ustr(&name, link2_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    init_ustr(&target, base_name);
    status = NtCreateSymbolicLinkObject(&h, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_SUCCESS, "create link2 -> %08lx", (unsigned long)status);
    status = NtCreateSymbolicLinkObject(&h2, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "duplicate link -> %08lx", (unsigned long)status);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF);
    status = NtCreateSymbolicLinkObject(&h2, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
    ok(status == STATUS_SUCCESS, "link OPENIF reopen -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(h2);

    /* Creating a non-link object whose name is a symlink to a not-yet-existing
     * target: NT follows the final link but will not materialize the object at
     * the missing target, so it is PATH_NOT_FOUND, not a silent create. */
    {
        HANDLE dlink;
        init_ustr(&name, dangler_name);
        init_ustr(&target, missing_tgt);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtCreateSymbolicLinkObject(&dlink, SYMBOLIC_LINK_ALL_ACCESS, &attr, &target);
        ok(status == STATUS_SUCCESS, "create dangling link -> %08lx", (unsigned long)status);
        status = NtCreateEvent(&h2, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
        ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "create over link to missing target -> %08lx",
           (unsigned long)status);
        NtClose(dlink);
    }
    NtClose(h);
}
