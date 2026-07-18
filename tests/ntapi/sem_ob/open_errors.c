/*
 * sem_ob/open_errors.c — NtOpen* name-error classification.
 *
 * The Nt*Open* calls agree on how a missing name fails: a NULL ObjectName is a
 * degenerate path -> STATUS_OBJECT_PATH_SYNTAX_BAD (as is an empty-string name),
 * while a NULL OBJECT_ATTRIBUTES pointer is STATUS_INVALID_PARAMETER. Pinned on
 * the Wine oracle first (docs/09 Art. 5/6 — Wine is the operative oracle).
 */
#include "util.h"

START_TEST(open_errors)
{
    NTSTATUS s;
    HANDLE h;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING empty;

    /* NULL ObjectName, valid attributes: PATH_SYNTAX_BAD across every type. */
    init_attr(&attr, NULL, NULL, OBJ_CASE_INSENSITIVE);
    s = NtOpenEvent(&h, EVENT_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open event NULL name -> %08lx", (unsigned long)s);
    s = NtOpenMutant(&h, MUTANT_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open mutant NULL name -> %08lx", (unsigned long)s);
    s = NtOpenSemaphore(&h, SEMAPHORE_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open semaphore NULL name -> %08lx", (unsigned long)s);
    s = NtOpenDirectoryObject(&h, DIRECTORY_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open directory NULL name -> %08lx", (unsigned long)s);
    s = NtOpenSymbolicLinkObject(&h, SYMBOLIC_LINK_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open symlink NULL name -> %08lx", (unsigned long)s);

    /* An empty-string (zero-length) name is likewise PATH_SYNTAX_BAD. */
    empty.Length = 0;
    empty.MaximumLength = 0;
    empty.Buffer = (PWSTR)(void *)W("");
    init_attr(&attr, NULL, &empty, OBJ_CASE_INSENSITIVE);
    s = NtOpenEvent(&h, EVENT_ALL_ACCESS, &attr);
    ok(s == STATUS_OBJECT_PATH_SYNTAX_BAD, "open event empty name -> %08lx", (unsigned long)s);

    /* A NULL OBJECT_ATTRIBUTES pointer is a parameter error, not a name error. */
    s = NtOpenEvent(&h, EVENT_ALL_ACCESS, NULL);
    ok(s == STATUS_INVALID_PARAMETER, "open event NULL attributes -> %08lx", (unsigned long)s);
}
