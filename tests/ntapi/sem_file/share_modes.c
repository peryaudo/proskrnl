/*
 * sem_file/share_modes.c — NT share-mode semantics (M6 "Done when": a
 * share-mode violation is STATUS_SHARING_VIOLATION).
 *
 * The NT rule (two directions, both checked on every open): the new opener's
 * desired access must be permitted by every existing opener's share mode, AND
 * the new opener's share mode must permit every existing opener's desired
 * access. Attribute-only opens (no data access) bypass the check entirely.
 */
#include "util.h"

static HANDLE dir;

/* One combination probe: h1 = (access1, share1) then h2 = (access2, share2). */
static NTSTATUS probe(ACCESS_MASK access1, ULONG share1, ACCESS_MASK access2, ULONG share2)
{
    IO_STATUS_BLOCK iosb;
    HANDLE h1, h2;
    NTSTATUS status;

    status =
        open_file(&h1, dir, W("shared.dat"), access1 | SYNCHRONIZE, share1, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "probe first open (%lx/%lx) -> %08lx", (unsigned long)access1,
       (unsigned long)share1, (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return status;
    status =
        open_file(&h2, dir, W("shared.dat"), access2 | SYNCHRONIZE, share2, FILE_OPEN, 0, &iosb);
    if (NT_SUCCESS(status))
        NtClose(h2);
    NtClose(h1);
    return status;
}

START_TEST(share_modes)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE h1, h2;

    dir = open_test_dir(W("\\??\\C:\\prstest\\share"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("shared.dat"));

    status = open_file(&h1, dir, W("shared.dat"), FILE_GENERIC_WRITE, 0, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create shared.dat -> %08lx", (unsigned long)status);
    NtClose(h1);

    /* --- exclusive first open blocks everything. --------------------------- */
    status = probe(FILE_READ_DATA, 0, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SHARING_VIOLATION, "exclusive vs read -> %08lx", (unsigned long)status);
    status = probe(FILE_WRITE_DATA, 0, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SHARING_VIOLATION, "exclusive vs write -> %08lx", (unsigned long)status);

    /* --- read/read sharing works when both sides allow it. ----------------- */
    status = probe(FILE_READ_DATA, FILE_SHARE_READ, FILE_READ_DATA, FILE_SHARE_READ);
    ok(status == STATUS_SUCCESS, "read+share-read vs read+share-read -> %08lx",
       (unsigned long)status);

    /* --- the second opener must ALSO share what the first holds. ----------- */
    status = probe(FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_READ_DATA, 0);
    ok(status == STATUS_SHARING_VIOLATION, "second opener shares nothing -> %08lx",
       (unsigned long)status);

    /* --- writer allowed only if the reader shared write. ------------------- */
    status =
        probe(FILE_READ_DATA, FILE_SHARE_READ, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SHARING_VIOLATION, "share-read only vs writer -> %08lx",
       (unsigned long)status);
    status = probe(FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_WRITE_DATA,
                   FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SUCCESS, "share-read+write vs writer -> %08lx", (unsigned long)status);

    /* --- DELETE access needs FILE_SHARE_DELETE from the first opener. ------ */
    status = probe(FILE_READ_DATA, FILE_SHARE_READ, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SHARING_VIOLATION, "no share-delete vs DELETE -> %08lx",
       (unsigned long)status);
    status = probe(FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, DELETE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE);
    ok(status == STATUS_SUCCESS, "share-delete vs DELETE -> %08lx", (unsigned long)status);

    /* --- attribute-only opens bypass the share check. ---------------------- */
    status =
        open_file(&h1, dir, W("shared.dat"), FILE_READ_DATA | SYNCHRONIZE, 0, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "exclusive open -> %08lx", (unsigned long)status);
    status = open_file(&h2, dir, W("shared.dat"), FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0, FILE_OPEN,
                       0, &iosb);
    ok(status == STATUS_SUCCESS, "attribute-only open bypasses sharing -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(h2);

    /* --- share state is released on close. --------------------------------- */
    NtClose(h1);
    status = open_file(&h1, dir, W("shared.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "exclusive reopen after close -> %08lx", (unsigned long)status);
    NtClose(h1);

    /* --- a create disposition hitting a share conflict still violates. ----- */
    status = open_file(&h1, dir, W("shared.dat"), FILE_READ_DATA | SYNCHRONIZE, FILE_SHARE_READ,
                       FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "read open -> %08lx", (unsigned long)status);
    status =
        open_file(&h2, dir, W("shared.dat"), FILE_GENERIC_WRITE, 0, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SHARING_VIOLATION, "overwrite over reader -> %08lx", (unsigned long)status);
    NtClose(h1);

    scrub_file(dir, W("shared.dat"));
    NtClose(dir);
}
