/*
 * sem_file/rename.c — FileRenameInformation(Ex) / FileLinkInformation via
 * NtSetInformationFile (CUI-5).
 *
 * kernelbase's MoveFileWithProgressW is the primary consumer (third_party/
 * wine dlls/kernelbase/file.c): it opens the source DELETE|SYNCHRONIZE,
 * builds FILE_RENAME_INFORMATION with the full NT path of the target,
 * RootDirectory = NULL, and a buffer sized offsetof(FileName) +
 * FileNameLength — cmd.exe's `ren` and `move` builtins reach it through
 * MoveFile(Ex)W. The contract is Wine's own implementation (dlls/ntdll/
 * unix/file.c NtSetInformationFile FileRenameInformation case + server/fd.c
 * set_fd_name): target-exists collisions, replace rules for open/read-only/
 * directory targets, rename-to-self, and the handle's cached name following
 * the rename.
 *
 * The union's upper bytes: kernelbase writes ReplaceIfExists as a BOOLEAN
 * into heap it never zeroed, so bytes 1-3 of the Flags arm are garbage on
 * every real call — the helpers below replicate that on purpose (a kernel
 * that reads the whole ULONG for the non-Ex class fails the collision case).
 */
#include "util.h"

#include <stddef.h> /* offsetof */

/* wine/include/winternl.h FILE_INFORMATION_CLASS value 65; the mingw-w64
 * header's enum predates the Ex classes. */
#define FileRenameInformationEx ((FILE_INFORMATION_CLASS)65)

/* wine/include/winternl.h rename flag bits (mingw-w64 winternl.h lacks
 * them). */
#ifndef FILE_RENAME_REPLACE_IF_EXISTS
#define FILE_RENAME_REPLACE_IF_EXISTS 0x00000001
#endif
#ifndef FILE_RENAME_IGNORE_READONLY_ATTRIBUTE
#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE 0x00000040
#endif

#define RENAME_BUF_CAP (sizeof(FILE_RENAME_INFORMATION) + 260 * sizeof(WCHAR))

static ULONG wlen_bytes(const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    ULONG len = 0;
    while (p[len])
        len++;
    return len * sizeof(WCHAR);
}

/* Build the buffer exactly as kernelbase does: size = offsetof(FileName) +
 * FileNameLength, union bytes 1-3 uninitialized (0xcc here). */
static NTSTATUS do_rename_class(HANDLE handle, HANDLE root, const void *target, BOOLEAN replace,
                                FILE_INFORMATION_CLASS class, ULONG ex_flags, IO_STATUS_BLOCK *iosb)
{
    char buf[RENAME_BUF_CAP];
    FILE_RENAME_INFORMATION *info = (FILE_RENAME_INFORMATION *)buf;
    ULONG name_bytes = wlen_bytes(target);

    memset(buf, 0xcc, sizeof(buf));
    if (class == FileRenameInformationEx)
        *(ULONG *)buf = ex_flags; /* the union's Flags arm (wine winternl.h) */
    else
        info->ReplaceIfExists = replace;
    info->RootDirectory = root;
    info->FileNameLength = name_bytes;
    memcpy(info->FileName, target, name_bytes);
    poison_iosb(iosb);
    return NtSetInformationFile(handle, iosb, info,
                                (ULONG)(offsetof(FILE_RENAME_INFORMATION, FileName) + name_bytes),
                                class);
}

static NTSTATUS do_rename(HANDLE handle, const void *target, BOOLEAN replace, IO_STATUS_BLOCK *iosb)
{
    return do_rename_class(handle, NULL, target, replace, FileRenameInformation, 0, iosb);
}

/* Open the source the way MoveFileWithProgressW does. */
static NTSTATUS open_source(HANDLE *handle, HANDLE root, const void *name, IO_STATUS_BLOCK *iosb)
{
    return open_file(handle, root, name, DELETE | SYNCHRONIZE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, iosb);
}

/* Create a small file with known content, closed. */
static void make_file(HANDLE root, const void *name, const char *content, ULONG length)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = open_file(&handle, root, name, FILE_GENERIC_WRITE | SYNCHRONIZE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "make_file -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    status = NtWriteFile(handle, NULL, NULL, NULL, &iosb, content, length, NULL, NULL);
    ok(status == STATUS_SUCCESS, "make_file write -> %08lx", (unsigned long)status);
    NtClose(handle);
}

/* Read a file's content by name; returns bytes read (0 on failure). */
static ULONG read_back(HANDLE root, const void *name, char *buffer, ULONG capacity)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status =
        open_file(&handle, root, name, FILE_GENERIC_READ | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    if (!NT_SUCCESS(status))
        return 0;
    status = NtReadFile(handle, NULL, NULL, NULL, &iosb, buffer, capacity, NULL, NULL);
    NtClose(handle);
    if (!NT_SUCCESS(status))
        return 0;
    return (ULONG)iosb.Information;
}

/* Does the handle's FileNameInformation end with the given tail? */
static int name_ends_with(HANDLE handle, const void *tail)
{
    char buf[sizeof(FILE_NAME_INFORMATION) + 260 * sizeof(WCHAR)];
    FILE_NAME_INFORMATION *info = (FILE_NAME_INFORMATION *)buf;
    IO_STATUS_BLOCK iosb;
    ULONG tail_bytes = wlen_bytes(tail);
    NTSTATUS status = NtQueryInformationFile(handle, &iosb, info, sizeof(buf), FileNameInformation);
    if (!NT_SUCCESS(status) || info->FileNameLength < tail_bytes)
        return 0;
    return memcmp((char *)info->FileName + info->FileNameLength - tail_bytes, tail, tail_bytes) ==
           0;
}

/* Clear attributes (drop READONLY) so a scrub can delete leftovers. */
static void clear_attributes(HANDLE root, const void *name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status =
        open_file(&handle, root, name, FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    if (!NT_SUCCESS(status))
        return;
    memset(&basic, 0, sizeof(basic)); /* zero times = leave unchanged */
    basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    NtSetInformationFile(handle, &iosb, &basic, sizeof(basic), FileBasicInformation);
    NtClose(handle);
}

/* Remove a leftover directory (empty) by name. */
static void scrub_dir(HANDLE root, const void *name)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status = open_file(&handle, root, name, DELETE | SYNCHRONIZE, 0, FILE_OPEN,
                                FILE_DELETE_ON_CLOSE | FILE_DIRECTORY_FILE, &iosb);
    if (NT_SUCCESS(status))
        NtClose(handle);
}

static HANDLE make_dir(HANDLE root, const void *name)
{
    UNICODE_STRING ustr;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    init_ustr(&ustr, name);
    init_attr(&attr, root, &ustr, OBJ_CASE_INSENSITIVE);
    status = NtCreateFile(&handle,
                          FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY |
                              FILE_TRAVERSE | DELETE | SYNCHRONIZE,
                          &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "make_dir -> %08lx", (unsigned long)status);
    return NT_SUCCESS(status) ? handle : NULL;
}

START_TEST(rename)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, src, other;
    char content[64];
    ULONG got;

    dir = open_test_dir(W("\\??\\C:\\prstest\\rename"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    /* Reruns on the oracle reuse the prefix: scrub every name this test
     * mints (clearing READONLY first where it may linger). */
    clear_attributes(dir, W("ro.txt"));
    {
        static const void *const names[] = {
            W("src.txt"),
            W("dst.txt"),
            W("dst2.txt"),
            W("DST2.txt"),
            W("open_tgt.txt"),
            W("ro.txt"),
            W("self.txt"),
            W("longsrc.txt"),
            W("rel.txt"),
            W("reltarget.txt"),
            W("linksrc.txt"),
            W("linktgt.txt"),
            W("a-rather-long-file-name-that-needs-several-directory-slots-on-fat32-0123456789.txt"),
        };
        for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            scrub_file(dir, names[i]);
        scrub_file(dir, W("sub\\moved.txt"));
        scrub_file(dir, W("sub\\movedagain\\child.txt"));
        scrub_dir(dir, W("sub\\movedagain"));
        scrub_file(dir, W("newdir\\child.txt"));
        scrub_file(dir, W("olddir\\child.txt"));
        scrub_dir(dir, W("newdir"));
        scrub_dir(dir, W("olddir"));
        scrub_dir(dir, W("dirtgt"));
        scrub_dir(dir, W("sub"));
    }

    /* --- 1. plain same-directory rename ------------------------------------ */
    make_file(dir, W("src.txt"), "hello", 5);
    status = open_source(&src, dir, W("src.txt"), &iosb);
    ok(status == STATUS_SUCCESS, "open source -> %08lx", (unsigned long)status);

    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\dst.txt"), FALSE, &iosb);
    ok(status == STATUS_SUCCESS, "rename -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "rename iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "rename iosb.Information %lu", (unsigned long)iosb.Information);

    /* The handle's cached name follows the rename (wine server/fd.c
     * set_fd_name rewrites the fd's nt_name). */
    ok(name_ends_with(src, W("\\rename\\dst.txt")), "name did not follow rename");
    NtClose(src);

    status = open_file(&other, dir, W("src.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0, FILE_OPEN, 0,
                       &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "old name still opens -> %08lx",
       (unsigned long)status);
    got = read_back(dir, W("dst.txt"), content, sizeof(content));
    ok(got == 5 && memcmp(content, "hello", 5) == 0, "content moved (%lu bytes)",
       (unsigned long)got);

    /* --- 2. collision without ReplaceIfExists ------------------------------ */
    make_file(dir, W("dst2.txt"), "other", 5);
    status = open_source(&src, dir, W("dst.txt"), &iosb);
    ok(status == STATUS_SUCCESS, "reopen source -> %08lx", (unsigned long)status);
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\dst2.txt"), FALSE, &iosb);
    ok(status == STATUS_OBJECT_NAME_COLLISION, "collision -> %08lx", (unsigned long)status);

    /* --- 3. ReplaceIfExists over a closed target --------------------------- */
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\dst2.txt"), TRUE, &iosb);
    ok(status == STATUS_SUCCESS, "replace -> %08lx", (unsigned long)status);
    got = read_back(dir, W("dst2.txt"), content, sizeof(content));
    ok(got == 5 && memcmp(content, "hello", 5) == 0, "replaced content (%lu bytes)",
       (unsigned long)got);
    status = open_file(&other, dir, W("dst.txt"), FILE_GENERIC_READ | SYNCHRONIZE, 0, FILE_OPEN, 0,
                       &iosb);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "moved-from name still opens -> %08lx",
       (unsigned long)status);

    /* --- 4. rename to self is a success no-op ------------------------------ */
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\dst2.txt"), FALSE, &iosb);
    ok(status == STATUS_SUCCESS, "rename to self -> %08lx", (unsigned long)status);
    ok(name_ends_with(src, W("\\rename\\dst2.txt")), "self-rename changed the name");

    /* --- 5. case-change rename --------------------------------------------- */
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\DST2.txt"), FALSE, &iosb);
    ok(status == STATUS_SUCCESS, "case-change rename -> %08lx", (unsigned long)status);
    got = read_back(dir, W("DST2.txt"), content, sizeof(content));
    ok(got == 5, "case-changed name opens (%lu bytes)", (unsigned long)got);

    /* --- 6. replacing an open target refuses ------------------------------- */
    make_file(dir, W("open_tgt.txt"), "busy", 4);
    status = open_file(&other, dir, W("open_tgt.txt"), FILE_GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "open target -> %08lx", (unsigned long)status);
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\open_tgt.txt"), TRUE, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "replace open target -> %08lx", (unsigned long)status);
    NtClose(other);
    scrub_file(dir, W("open_tgt.txt"));

    /* --- 7. replacing a read-only target refuses; the Ex flag overrides ---- */
    {
        UNICODE_STRING ustr;
        OBJECT_ATTRIBUTES attr;
        HANDLE ro = NULL;
        init_ustr(&ustr, W("\\??\\C:\\prstest\\rename\\ro.txt"));
        init_attr(&attr, NULL, &ustr, OBJ_CASE_INSENSITIVE);
        status = NtCreateFile(&ro, FILE_GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, NULL,
                              FILE_ATTRIBUTE_READONLY, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        ok(status == STATUS_SUCCESS, "create read-only target -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(ro);
    }
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\ro.txt"), TRUE, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "replace read-only target -> %08lx", (unsigned long)status);
    status = do_rename_class(
        src, NULL, W("\\??\\C:\\prstest\\rename\\ro.txt"), FALSE, FileRenameInformationEx,
        FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_IGNORE_READONLY_ATTRIBUTE, &iosb);
    ok(status == STATUS_SUCCESS, "Ex ignore-readonly replace -> %08lx", (unsigned long)status);
    ok(name_ends_with(src, W("\\rename\\ro.txt")), "name did not follow Ex rename");

    /* --- 8. replacing a directory target refuses --------------------------- */
    {
        HANDLE dirtgt = make_dir(dir, W("dirtgt"));
        if (dirtgt)
            NtClose(dirtgt);
    }
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\dirtgt"), TRUE, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "replace directory target -> %08lx", (unsigned long)status);
    scrub_dir(dir, W("dirtgt"));

    /* --- 9. error shapes ---------------------------------------------------- */
    /* Missing target parent. */
    status = do_rename(src, W("\\??\\C:\\prstest\\rename\\nosuchdir\\x.txt"), FALSE, &iosb);
    ok(status == STATUS_OBJECT_PATH_NOT_FOUND, "missing parent -> %08lx", (unsigned long)status);
    /* Short buffer: wine's NtSetInformationFile requires the full struct
     * size (24) before it reads anything. */
    {
        char small[offsetof(FILE_RENAME_INFORMATION, FileName)];
        memset(small, 0, sizeof(small));
        poison_iosb(&iosb);
        status = NtSetInformationFile(src, &iosb, small, sizeof(small), FileRenameInformation);
        ok(status == STATUS_INVALID_PARAMETER_3, "short buffer -> %08lx", (unsigned long)status);
    }

    /* --- 9b. the target path resolves BEFORE the handle (fuzzer-found) ------ */
    /* Wine's order (unix/file.c rename case): length check, then
     * get_nt_and_unix_names on the target, and only the server call touches
     * the handle — so a bad handle with a bad target reports the PATH
     * error, and a wrong-type handle with a good target reports the type
     * mismatch from the handle resolution. */
    {
        NTSTATUS order_status = do_rename_class((HANDLE)(ULONG_PTR)0xdead0, NULL,
                                                W("\\??\\C:\\prstest\\rename\\nosuchdir\\x.txt"),
                                                FALSE, FileRenameInformation, 0, &iosb);
        ok(order_status == STATUS_OBJECT_PATH_NOT_FOUND, "bad handle + bad path -> %08lx",
           (unsigned long)order_status);
        HANDLE order_event = NULL;
        order_status =
            NtCreateEvent(&order_event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        ok(order_status == STATUS_SUCCESS, "order event -> %08lx", (unsigned long)order_status);
        order_status =
            do_rename_class(order_event, NULL, W("\\??\\C:\\prstest\\rename\\nosuchdir\\x.txt"),
                            FALSE, FileRenameInformation, 0, &iosb);
        ok(order_status == STATUS_OBJECT_PATH_NOT_FOUND, "event handle + bad path -> %08lx",
           (unsigned long)order_status);
        order_status = do_rename_class(order_event, NULL, W("\\??\\C:\\prstest\\rename\\evt.txt"),
                                       FALSE, FileRenameInformation, 0, &iosb);
        ok(order_status == STATUS_OBJECT_TYPE_MISMATCH, "event handle + good path -> %08lx",
           (unsigned long)order_status);
        NtClose(order_event);
    }

    /* --- 10. RootDirectory-relative rename --------------------------------- */
    status = do_rename_class(src, dir, W("reltarget.txt"), FALSE, FileRenameInformation, 0, &iosb);
    ok(status == STATUS_SUCCESS, "relative rename -> %08lx", (unsigned long)status);
    ok(name_ends_with(src, W("\\rename\\reltarget.txt")), "relative rename name");
    NtClose(src);

    /* --- 11. cross-directory move + directory rename/move ------------------ */
    {
        HANDLE sub = make_dir(dir, W("sub"));
        HANDLE olddir = make_dir(dir, W("olddir"));
        HANDLE moved;
        if (sub)
            NtClose(sub);
        make_file(dir, W("olddir\\child.txt"), "kid", 3);

        /* Move a file into the subdirectory. */
        status = open_source(&moved, dir, W("reltarget.txt"), &iosb);
        ok(status == STATUS_SUCCESS, "open for move -> %08lx", (unsigned long)status);
        status = do_rename(moved, W("\\??\\C:\\prstest\\rename\\sub\\moved.txt"), FALSE, &iosb);
        ok(status == STATUS_SUCCESS, "move into subdir -> %08lx", (unsigned long)status);
        NtClose(moved);
        got = read_back(dir, W("sub\\moved.txt"), content, sizeof(content));
        ok(got == 5, "moved file readable through new path (%lu bytes)", (unsigned long)got);

        /* Rename a directory (with a child) in place... */
        ok(olddir != NULL, "olddir handle");
        status = do_rename(olddir, W("\\??\\C:\\prstest\\rename\\newdir"), FALSE, &iosb);
        ok(status == STATUS_SUCCESS, "rename directory -> %08lx", (unsigned long)status);
        got = read_back(dir, W("newdir\\child.txt"), content, sizeof(content));
        ok(got == 3 && memcmp(content, "kid", 3) == 0, "child follows dir rename (%lu bytes)",
           (unsigned long)got);
        status = open_file(&moved, dir, W("olddir"), FILE_LIST_DIRECTORY | SYNCHRONIZE, 0,
                           FILE_OPEN, FILE_DIRECTORY_FILE, &iosb);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "old dir name still opens -> %08lx",
           (unsigned long)status);

        /* ...then move it under another parent. */
        status = do_rename(olddir, W("\\??\\C:\\prstest\\rename\\sub\\movedagain"), FALSE, &iosb);
        ok(status == STATUS_SUCCESS, "move directory -> %08lx", (unsigned long)status);
        got = read_back(dir, W("sub\\movedagain\\child.txt"), content, sizeof(content));
        ok(got == 3, "child follows dir move (%lu bytes)", (unsigned long)got);
        NtClose(olddir);

        /* Clean up so reruns start from nothing. */
        scrub_file(dir, W("sub\\moved.txt"));
        scrub_file(dir, W("sub\\movedagain\\child.txt"));
        scrub_dir(dir, W("sub\\movedagain"));
        scrub_dir(dir, W("sub"));
    }

    /* --- 12. a long name that needs LFN slot growth on FAT ------------------ */
    make_file(dir, W("longsrc.txt"), "long", 4);
    status = open_source(&src, dir, W("longsrc.txt"), &iosb);
    ok(status == STATUS_SUCCESS, "open longsrc -> %08lx", (unsigned long)status);
    status = do_rename(src,
                       W("\\??\\C:\\prstest\\rename\\a-rather-long-file-name-that-needs-several-"
                         "directory-slots-on-fat32-0123456789.txt"),
                       FALSE, &iosb);
    ok(status == STATUS_SUCCESS, "long-name rename -> %08lx", (unsigned long)status);
    NtClose(src);
    got = read_back(
        dir,
        W("a-rather-long-file-name-that-needs-several-directory-slots-on-fat32-0123456789.txt"),
        content, sizeof(content));
    ok(got == 4, "long name opens (%lu bytes)", (unsigned long)got);
    scrub_file(
        dir,
        W("a-rather-long-file-name-that-needs-several-directory-slots-on-fat32-0123456789.txt"));

    /* --- 13. FileLinkInformation ------------------------------------------- */
    make_file(dir, W("linksrc.txt"), "lnk", 3);
    status = open_source(&src, dir, W("linksrc.txt"), &iosb);
    ok(status == STATUS_SUCCESS, "open linksrc -> %08lx", (unsigned long)status);

    /* Short buffer refuses before the volume is consulted — identical on
     * both backends (wine unix/file.c FileLinkInformation case). */
    {
        char small[offsetof(FILE_RENAME_INFORMATION, FileName)];
        memset(small, 0, sizeof(small));
        status = NtSetInformationFile(src, &iosb, small, sizeof(small), FileLinkInformation);
        ok(status == STATUS_INVALID_PARAMETER_3, "link short buffer -> %08lx",
           (unsigned long)status);
    }

    /* The oracle's backing filesystem (ext4) has hard links, so it cannot
     * answer for FAT32; on a FAT volume NT refuses hard links with
     * STATUS_INVALID_DEVICE_REQUEST (MS "Hard Links and Junctions":
     * CreateHardLink is NTFS-only; kernelbase maps the status to
     * ERROR_INVALID_FUNCTION). The block runs on both sides — on the oracle
     * the call succeeds and creates a link, which the scrub below removes. */
    status = do_rename_class(src, NULL, W("\\??\\C:\\prstest\\rename\\linktgt.txt"), FALSE,
                             FileLinkInformation, 0, &iosb);
    beyond_oracle
    {
        ok(status == STATUS_INVALID_DEVICE_REQUEST, "link on FAT -> %08lx", (unsigned long)status);
    }
    NtClose(src);
    scrub_file(dir, W("linktgt.txt"));
    scrub_file(dir, W("linksrc.txt"));

    /* Final scrub of the surviving names. */
    scrub_file(dir, W("ro.txt"));
    NtClose(dir);
}
