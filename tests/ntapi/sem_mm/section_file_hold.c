/*
 * sem_mm/section_file_hold.c — what a live SECTION holds against a later
 * OPEN of the same file.
 *
 * NT models a section as a pseudo-open of the file, and the pinned oracle
 * says so literally: server/mapping.c create_mapping keeps the file's fd
 * with a magic access word — FILE_MAPPING_ACCESS always, plus
 * FILE_MAPPING_IMAGE under SEC_IMAGE, plus FILE_MAPPING_WRITE when the
 * section's own file access carried FILE_WRITE_DATA (server/file.h:303-305)
 * — and sharing FILE_SHARE_READ|WRITE|DELETE. server/fd.c check_sharing
 * then reads those three bits back as four rules:
 *
 *   FILE_MAPPING_WRITE  && !(sharing & FILE_SHARE_WRITE) -> SHARING_VIOLATION
 *   FILE_MAPPING_IMAGE  && (access & FILE_WRITE_DATA)    -> SHARING_VIOLATION
 *   FILE_MAPPING_IMAGE  && FILE_DELETE_ON_CLOSE          -> CANNOT_DELETE
 *   FILE_MAPPING_ACCESS && a truncating disposition      -> USER_MAPPED_FILE
 *
 * and — this is the part an implementation gets wrong by being tidy — it
 * runs all four ABOVE its own `if (!(access & all_access)) return 0`, so a
 * zero-data-access open is exempt from ordinary share modes and NOT from
 * these. The magic bits carry no read/write/delete bit of their own, so a
 * section never demands anything of the opener's *sharing* except through
 * FILE_MAPPING_WRITE.
 *
 * kernel32:file convicts the set 126 times. 120 of those are inside
 * test_file_sharing's mapping loop (file.c:2635-:2714): 96 at :2672 (the
 * write rule), 16 at :2663 (the image rule reading FILE_APPEND_DATA as a
 * write), 3+3 at :2695/:2696 (the truncate rule) and 1+1 at :2707/:2708 (the
 * delete rule). The other 6 are the same two rules in Win32 spelling —
 * CopyFile and CopyFile2 onto a mapped destination (:847/:848, :1174/:1175)
 * and DeleteFile of a mapped image (:1931/:1932). This case pins the rules
 * rather than those points, because each is a different word of the same
 * ladder and the ORDER between them is observable — see sections 5 and 6.
 *
 * The kernel side is IoCheckShareAccess (kernel/io/file.c) over the FCB's
 * three section counters; the existing image deny-write half is pinned by
 * sem_mm/image_deny_write.c and stays green.
 */
#include "imagefile.h"

NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           const LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
#ifndef ViewShare
#define ViewShare 1
#endif
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

static const void *data_name = W("hold.bin");
static const void *image_name = W("hold.dll");

/* The mask kernelbase builds for CreateFileA(..., dwDesiredAccess = 0, ...)
 * — no FILE_READ_DATA / FILE_WRITE_DATA / DELETE, so ordinary share modes
 * ignore it entirely. That is exactly the opener the winetest's a2 == 0
 * column uses, and the one the mapping rules must still reach. */
#define NO_DATA_ACCESS (SYNCHRONIZE | FILE_READ_ATTRIBUTES)
#define SHARE_ALL      (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/* Open the file and throw the handle away: every assertion here is about the
 * STATUS, and a handle left open would join the share ledger and change the
 * next case's answer. */
static NTSTATUS try_open(HANDLE dir, const void *name, ACCESS_MASK access, ULONG share,
                         ULONG disposition, ULONG options)
{
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status =
        open_file(&handle, dir, name, access | SYNCHRONIZE, share, disposition, options, &iosb);
    if (NT_SUCCESS(status))
        NtClose(handle);
    return status;
}

/* A section over the file, built through a handle that is closed again
 * immediately — so the hold that remains is the SECTION's, not a file
 * handle's. Returns NULL (having asserted) on failure. */
static HANDLE hold_section(HANDLE dir, const void *name, ULONG protect, ULONG secFlags,
                           const char *what)
{
    IO_STATUS_BLOCK iosb;
    ACCESS_MASK access = GENERIC_READ | SYNCHRONIZE;
    HANDLE file = NULL, section = NULL;
    NTSTATUS status;

    if ((secFlags & SEC_IMAGE) == 0 && (protect == PAGE_READWRITE))
        access |= GENERIC_WRITE;
    status = open_file(&file, dir, name, access, SHARE_ALL, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "%s: open backing -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return NULL;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, protect, secFlags, file);
    ok(status == STATUS_SUCCESS, "%s: create section -> %08lx", what, (unsigned long)status);
    NtClose(file);
    return NT_SUCCESS(status) ? section : NULL;
}

/* Re-make the data file from scratch, so a case that deletes it (the
 * delete-on-close arm) cannot decide the next case's answer. */
static void reset_data_file(HANDLE dir)
{
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    NTSTATUS status;
    static char buf[4096];

    scrub_file(dir, data_name);
    status = open_file(&file, dir, data_name, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create %s -> %08lx", "hold.bin", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    memset(buf, 'h', sizeof(buf));
    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, buf, sizeof(buf), NULL, NULL);
    ok(status == STATUS_SUCCESS, "write %s -> %08lx", "hold.bin", (unsigned long)status);
    NtClose(file);
}

START_TEST(section_file_hold)
{
    NTSTATUS status;
    HANDLE dir, section;

    dir = open_test_dir(W("\\??\\C:\\prstest\\secthold"));
    if (!dir)
        return;

    /* --- 1. a PAGE_READWRITE data section demands FILE_SHARE_WRITE --------- */
    reset_data_file(dir);
    section = hold_section(dir, data_name, PAGE_READWRITE, SEC_COMMIT, "rw");
    if (section != NULL)
    {
        /* The discriminating case: an opener with no data access at all.
         * Ordinary share modes ignore it; the mapping rule does not. */
        status = try_open(dir, data_name, NO_DATA_ACCESS, 0, FILE_OPEN, 0);
        ok(status == STATUS_SHARING_VIOLATION, "rw section vs no-access unshared open -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_READ, FILE_SHARE_READ, FILE_OPEN, 0);
        ok(status == STATUS_SHARING_VIOLATION, "rw section vs read/share-read -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_READ, FILE_SHARE_DELETE, FILE_OPEN, 0);
        ok(status == STATUS_SHARING_VIOLATION, "rw section vs read/share-delete -> %08lx",
           (unsigned long)status);
        /* Sharing WRITE is the whole of the requirement: what the opener
         * ASKS for is irrelevant, so a writer that shares write gets in. */
        status = try_open(dir, data_name, GENERIC_READ, FILE_SHARE_WRITE, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "rw section vs read/share-write -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, FILE_SHARE_WRITE, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "rw section vs write/share-write -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, NO_DATA_ACCESS, SHARE_ALL, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "rw section vs no-access/share-all -> %08lx",
           (unsigned long)status);
        NtClose(section);
        status = try_open(dir, data_name, NO_DATA_ACCESS, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "after section closed -> %08lx", (unsigned long)status);
    }

    /* --- 2. and NO other data protection does ------------------------------ */
    /* PAGE_WRITECOPY is the one that looks writable and is not: the section's
     * required file access is the discriminator (FILE_READ_DATA), not the
     * word "write" in the protection's name. */
    section = hold_section(dir, data_name, PAGE_READONLY, SEC_COMMIT, "ro");
    if (section != NULL)
    {
        status = try_open(dir, data_name, GENERIC_READ, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "ro section vs read/unshared -> %08lx", (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "ro section vs write/unshared -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }
    section = hold_section(dir, data_name, PAGE_WRITECOPY, SEC_COMMIT, "wc");
    if (section != NULL)
    {
        status = try_open(dir, data_name, GENERIC_READ, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "writecopy section vs read/unshared -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "writecopy section vs write/unshared -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }

    /* --- 3. ANY section refuses a TRUNCATING disposition ------------------- */
    section = hold_section(dir, data_name, PAGE_READONLY, SEC_COMMIT, "trunc");
    if (section != NULL)
    {
        status = try_open(dir, data_name, GENERIC_WRITE, SHARE_ALL, FILE_OVERWRITE_IF, 0);
        ok(status == STATUS_USER_MAPPED_FILE, "section vs FILE_OVERWRITE_IF -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, SHARE_ALL, FILE_OVERWRITE, 0);
        ok(status == STATUS_USER_MAPPED_FILE, "section vs FILE_OVERWRITE -> %08lx",
           (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, SHARE_ALL, FILE_SUPERSEDE, 0);
        ok(status == STATUS_USER_MAPPED_FILE, "section vs FILE_SUPERSEDE -> %08lx",
           (unsigned long)status);
        /* The non-truncating dispositions are untouched. */
        status = try_open(dir, data_name, GENERIC_WRITE, SHARE_ALL, FILE_OPEN_IF, 0);
        ok(status == STATUS_SUCCESS, "section vs FILE_OPEN_IF -> %08lx", (unsigned long)status);
        status = try_open(dir, data_name, GENERIC_WRITE, SHARE_ALL, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "section vs FILE_OPEN -> %08lx", (unsigned long)status);
        /* And a DATA section does not refuse a delete-on-close: that rule is
         * the image one, and reading it as "any mapping" fails here. This
         * arm DELETES the file, so it goes last and section 4 remakes it. */
        status = try_open(dir, data_name, GENERIC_READ | DELETE, SHARE_ALL, FILE_OPEN,
                          FILE_DELETE_ON_CLOSE);
        ok(status == STATUS_SUCCESS, "data section vs delete-on-close -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }

    /* --- 4. the hold is the SECTION's, and a mapped view keeps it alive ---- */
    reset_data_file(dir);
    section = hold_section(dir, data_name, PAGE_READWRITE, SEC_COMMIT, "view");
    if (section != NULL)
    {
        LARGE_INTEGER offset;
        SIZE_T viewSize = 0;
        void *view = NULL;

        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, &offset, &viewSize,
                                    ViewShare, 0, PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "map view -> %08lx", (unsigned long)status);
        NtClose(section);
        if (NT_SUCCESS(status))
        {
            status = try_open(dir, data_name, NO_DATA_ACCESS, 0, FILE_OPEN, 0);
            ok(status == STATUS_SHARING_VIOLATION, "view outlives section handle -> %08lx",
               (unsigned long)status);
            status = NtUnmapViewOfSection(NtCurrentProcess(), view);
            ok(status == STATUS_SUCCESS, "unmap -> %08lx", (unsigned long)status);
            status = try_open(dir, data_name, NO_DATA_ACCESS, 0, FILE_OPEN, 0);
            ok(status == STATUS_SUCCESS, "after unmap -> %08lx", (unsigned long)status);
        }
    }

    /* --- 5. SEC_IMAGE: FILE_WRITE_DATA, and only that bit ----------------- */
    if (!copy_system_image(dir, image_name))
    {
        NtClose(dir);
        return;
    }
    section = hold_section(dir, image_name, PAGE_READONLY, SEC_IMAGE, "image");
    if (section != NULL)
    {
        status = try_open(dir, image_name, FILE_WRITE_DATA, SHARE_ALL, FILE_OPEN, 0);
        ok(status == STATUS_SHARING_VIOLATION, "image vs FILE_WRITE_DATA -> %08lx",
           (unsigned long)status);
        /* FILE_APPEND_DATA is a different bit and the rule does not name it,
         * although every other share-mode rule in NT groups the two. */
        status = try_open(dir, image_name, FILE_APPEND_DATA, SHARE_ALL, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "image vs FILE_APPEND_DATA -> %08lx", (unsigned long)status);
        /* An image section demands nothing of the opener's SHARING. */
        status = try_open(dir, image_name, GENERIC_READ, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "image vs read/unshared -> %08lx", (unsigned long)status);
        status = try_open(dir, image_name, NO_DATA_ACCESS, 0, FILE_OPEN, 0);
        ok(status == STATUS_SUCCESS, "image vs no-access/unshared -> %08lx", (unsigned long)status);
        /* Delete-on-close is a THIRD status, not a sharing violation. */
        status = try_open(dir, image_name, GENERIC_READ | DELETE, SHARE_ALL, FILE_OPEN,
                          FILE_DELETE_ON_CLOSE);
        ok(status == STATUS_CANNOT_DELETE, "image vs delete-on-close -> %08lx",
           (unsigned long)status);

        /* --- 6. the ORDER between the four rules is observable ------------- */
        /* Write beats truncate: the same call reports the mapping's write
         * refusal, never STATUS_USER_MAPPED_FILE. */
        status = try_open(dir, image_name, GENERIC_WRITE, SHARE_ALL, FILE_OVERWRITE_IF, 0);
        ok(status == STATUS_SHARING_VIOLATION, "image write beats truncate -> %08lx",
           (unsigned long)status);
        /* Take the write away and the same disposition reports the truncate. */
        status = try_open(dir, image_name, GENERIC_READ, SHARE_ALL, FILE_OVERWRITE_IF, 0);
        ok(status == STATUS_USER_MAPPED_FILE, "image read + truncate -> %08lx",
           (unsigned long)status);
        /* Delete beats truncate too. */
        status = try_open(dir, image_name, GENERIC_READ | DELETE, SHARE_ALL, FILE_OVERWRITE_IF,
                          FILE_DELETE_ON_CLOSE);
        ok(status == STATUS_CANNOT_DELETE, "image delete beats truncate -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }
    section = hold_section(dir, data_name, PAGE_READWRITE, SEC_COMMIT, "order");
    if (section != NULL)
    {
        /* And the write rule beats the truncate rule on the data side as
         * well: an unshared-write opener asking to overwrite reports the
         * sharing violation. */
        status = try_open(dir, data_name, GENERIC_READ, FILE_SHARE_READ, FILE_OVERWRITE_IF, 0);
        ok(status == STATUS_SHARING_VIOLATION, "rw write beats truncate -> %08lx",
           (unsigned long)status);
        NtClose(section);
    }

    scrub_file(dir, data_name);
    scrub_file(dir, image_name);
    NtClose(dir);
}
