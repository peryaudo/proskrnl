/*
 * sem_ob/bno_links.c — the Local / Global / Session symlinks INSIDE a
 * session's BaseNamedObjects, and \Sessions\BNOLINKS behind them.
 *
 * session_bno.c pins the directory. These are the three names that live in
 * it, and they are what makes "Local\Foo" and "Global\Foo" work: kernelbase
 * hands the WHOLE name — prefix included — to the object manager relative to
 * \Sessions\<id>\BaseNamedObjects, so the prefix is resolved as an ordinary
 * path component and there is nothing anywhere that special-cases the word
 * (dlls/kernelbase/sync.c BaseGetNamedObjectDirectory).
 *
 * The oracle builds them in server/directory.c create_session:
 *
 *     link_global  = symlink( dir_bno, "Global",  dir_bno_global );
 *     link_local   = symlink( dir_bno, "Local",   dir_bno );      <- itself
 *     link_session = symlink( dir_bno, "Session", dir_bnolinks );
 *     link_bno     = symlink( dir_bnolinks, "<id>", dir_bno );
 *
 * "Local" pointing AT ITS OWN PARENT is the part worth pinning rather than
 * assuming: it means Local\X and X are the same object, which is the whole
 * behaviour a caller depends on.
 */
#include "util.h"

/* Compose \Sessions\<id>\BaseNamedObjects<suffix> for the running session,
 * the way session_bno.c does — the id comes from the PEB, because that is
 * where kernelbase reads it. */
static ULONG current_session(void)
{
    PROCESS_BASIC_INFORMATION basic;
    NTSTATUS status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &basic,
                                                sizeof(basic), NULL);
    /* Asserted rather than defaulted: a failed query here would otherwise
     * surface as three confusing "\Sessions\0\... failed" messages that
     * misattribute the cause (session_bno.c asserts it for the same reason). */
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ok(basic.PebBaseAddress != NULL, "no PEB");
    if (!NT_SUCCESS(status) || !basic.PebBaseAddress)
        return 0;
    /* PEB.SessionId at 0x2c0 on x86_64 (pinned tree's winternl.h). */
    return *(volatile ULONG *)((char *)basic.PebBaseAddress + 0x2c0);
}

static void build_path(WCHAR *out, ULONG session, const void *suffix)
{
    static const WCHAR head[] = W("\\Sessions\\");
    static const WCHAR tail[] = W("\\BaseNamedObjects");
    const WCHAR *suffixW = (const WCHAR *)suffix;
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
    if (suffixW)
        for (j = 0; suffixW[j]; j++)
            out[i++] = suffixW[j];
    out[i] = 0;
}

static NTSTATUS open_dir(const WCHAR *path, HANDLE *out)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;

    init_ustr(&name, path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *out = NULL;
    return NtOpenDirectoryObject(out, DIRECTORY_CREATE_OBJECT | DIRECTORY_TRAVERSE, &attr);
}

/* Create an event at `path`, then reopen it at `other` and check the two
 * names bound the SAME object — the only way to tell a working symlink from
 * a second directory that merely accepts the name. */
static void same_object_through(const WCHAR *createPath, const WCHAR *openPath, const char *what)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    HANDLE event = NULL, other = NULL;
    NTSTATUS status;

    init_ustr(&name, createPath);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    /* Signalled at birth, so a successful wait on the REOPENED handle proves
     * it is this object and not a fresh one. */
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, TRUE);
    ok(status == STATUS_SUCCESS, "%s: create -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    init_ustr(&name, openPath);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&other, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "%s: reopen by the other name -> %08lx", what,
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(wait_now(other) == STATUS_SUCCESS, "%s: the two names are different objects", what);
        NtClose(other);
    }
    NtClose(event);
}

START_TEST(bno_links)
{
    ULONG session = current_session();
    WCHAR bno[160], local[160], global[160], sessionLink[160];
    WCHAR createPath[200], openPath[200];
    HANDLE handle;
    NTSTATUS status;
    unsigned i;

    build_path(bno, session, NULL);
    build_path(local, session, W("\\Local"));
    build_path(global, session, W("\\Global"));
    build_path(sessionLink, session, W("\\Session"));

    /* All three open AS DIRECTORIES: a symbolic link is traversed by the
     * open, so the caller never sees the link object. */
    status = open_dir(local, &handle);
    ok(status == STATUS_SUCCESS, "open ...\\BaseNamedObjects\\Local -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    status = open_dir(global, &handle);
    ok(status == STATUS_SUCCESS, "open ...\\BaseNamedObjects\\Global -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    status = open_dir(sessionLink, &handle);
    ok(status == STATUS_SUCCESS, "open ...\\BaseNamedObjects\\Session -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* Local points at its own parent: Local\X IS X. */
    for (i = 0; bno[i]; i++)
        createPath[i] = bno[i];
    {
        static const WCHAR leaf[] = W("\\Local\\prsk_bno_local");
        static const WCHAR bare[] = W("\\prsk_bno_local");
        unsigned j, k = i;
        for (j = 0; leaf[j]; j++)
            createPath[k++] = leaf[j];
        createPath[k] = 0;
        for (j = 0; bno[j]; j++)
            openPath[j] = bno[j];
        k = j;
        for (j = 0; bare[j]; j++)
            openPath[k++] = bare[j];
        openPath[k] = 0;
    }
    same_object_through(createPath, openPath, "Local is its own parent");

    /* Global points at the ROOT \BaseNamedObjects, which is a different
     * directory from the session's — so Global\X is NOT X. */
    {
        static const WCHAR leaf[] = W("\\Global\\prsk_bno_global");
        static const WCHAR root[] = W("\\BaseNamedObjects\\prsk_bno_global");
        unsigned j, k;
        for (j = 0; bno[j]; j++)
            createPath[j] = bno[j];
        k = j;
        for (j = 0; leaf[j]; j++)
            createPath[k++] = leaf[j];
        createPath[k] = 0;
        for (j = 0; root[j]; j++)
            openPath[j] = root[j];
        openPath[j] = 0;
    }
    same_object_through(createPath, openPath, "Global reaches the root BaseNamedObjects");

    /* Session points at \Sessions\BNOLINKS, which carries one link per live
     * session id — so Session\<id>\X is this session's X again. */
    {
        static const WCHAR head[] = W("\\Sessions\\BNOLINKS\\");
        static const WCHAR leaf[] = W("\\prsk_bno_bnolinks");
        static const WCHAR bare[] = W("\\prsk_bno_bnolinks");
        WCHAR digits[16];
        unsigned count = 0, j, k = 0;
        ULONG id = session;

        for (j = 0; head[j]; j++)
            createPath[k++] = head[j];
        do
        {
            digits[count++] = (WCHAR)('0' + id % 10);
            id /= 10;
        } while (id);
        while (count)
            createPath[k++] = digits[--count];
        for (j = 0; leaf[j]; j++)
            createPath[k++] = leaf[j];
        createPath[k] = 0;

        for (j = 0; bno[j]; j++)
            openPath[j] = bno[j];
        k = j;
        for (j = 0; bare[j]; j++)
            openPath[k++] = bare[j];
        openPath[k] = 0;
    }
    same_object_through(createPath, openPath, "BNOLINKS reaches this session");
}
