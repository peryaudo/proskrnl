/*
 * sem_file/info_classes.c — NtQueryInformationFile main info classes (M6):
 * FileBasic/Standard/Position/Name/All, the class/length error conventions,
 * and NtQueryAttributesFile by path.
 */
#include "util.h"

START_TEST(info_classes)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h;
    FILE_BASIC_INFORMATION basic;
    FILE_STANDARD_INFORMATION std;
    FILE_POSITION_INFORMATION pos;
    LARGE_INTEGER offset;

    dir = open_test_dir(W("\\??\\C:\\prstest\\info"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("probe.bin"));

    status = open_file(&h, dir, W("probe.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create probe.bin -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "0123456789", 10, &offset, NULL);
    ok(status == STATUS_SUCCESS, "fill 10 bytes -> %08lx", (unsigned long)status);

    /* --- FileBasicInformation: attributes + live timestamps. --------------- */
    poison_iosb(&iosb);
    memset(&basic, 0, sizeof(basic));
    status = NtQueryInformationFile(h, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(basic), "query basic: Information %lu",
       (unsigned long)iosb.Information);
    ok((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0, "file is not a directory (%lx)",
       (unsigned long)basic.FileAttributes);
    ok(basic.LastWriteTime.QuadPart != 0, "LastWriteTime is set");

    /* --- FileStandardInformation. ------------------------------------------ */
    memset(&std, 0, sizeof(std));
    status = NtQueryInformationFile(h, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS, "query standard -> %08lx", (unsigned long)status);
    ok(std.EndOfFile.QuadPart == 10, "EndOfFile %ld", (long)std.EndOfFile.QuadPart);
    ok(std.AllocationSize.QuadPart >= 10, "AllocationSize %ld covers EOF",
       (long)std.AllocationSize.QuadPart);
    ok(std.Directory == FALSE, "Directory flag clear");
    ok(std.DeletePending == FALSE, "DeletePending clear");
    ok(std.NumberOfLinks == 1, "NumberOfLinks %lu", (unsigned long)std.NumberOfLinks);

    /* --- FilePositionInformation round-trips. ------------------------------ */
    pos.CurrentByteOffset.QuadPart = 7;
    status = NtSetInformationFile(h, &iosb, &pos, sizeof(pos), FilePositionInformation);
    ok(status == STATUS_SUCCESS, "set position -> %08lx", (unsigned long)status);
    memset(&pos, 0, sizeof(pos));
    status = NtQueryInformationFile(h, &iosb, &pos, sizeof(pos), FilePositionInformation);
    ok(status == STATUS_SUCCESS && pos.CurrentByteOffset.QuadPart == 7, "position %ld",
       (long)pos.CurrentByteOffset.QuadPart);

    /* --- FileNameInformation: device-relative path, no drive letter. ------- */
    struct
    {
        FILE_NAME_INFORMATION info;
        WCHAR pad[128];
    } name;
    poison_iosb(&iosb);
    memset(&name, 0, sizeof(name));
    status = NtQueryInformationFile(h, &iosb, &name, sizeof(name), FileNameInformation);
    ok(status == STATUS_SUCCESS, "query name -> %08lx", (unsigned long)status);
    {
        /* Ends with "\prstest\info\probe.bin" and starts with '\'. */
        static const WCHAR suffix[] = W("\\prstest\\info\\probe.bin");
        unsigned suffix_units = (sizeof(suffix) / sizeof(WCHAR)) - 1;
        unsigned units = name.info.FileNameLength / sizeof(WCHAR);
        const WCHAR *file_name = name.info.FileName; /* flexible tail: index via pointer */
        int tail_ok = 0;
        if (units >= suffix_units)
        {
            tail_ok = 1;
            for (unsigned i = 0; i < suffix_units; i++)
            {
                WCHAR have = file_name[units - suffix_units + i];
                WCHAR want = suffix[i];
                if (have >= 'A' && have <= 'Z')
                    have = (WCHAR)(have - 'A' + 'a');
                if (want >= 'A' && want <= 'Z')
                    want = (WCHAR)(want - 'A' + 'a');
                if (have != want)
                    tail_ok = 0;
            }
        }
        ok(file_name[0] == '\\', "name starts with backslash");
        ok(tail_ok, "name ends with \\prstest\\info\\probe.bin (%u units)", units);
    }

    /* A too-small name buffer overflows with the length still reported. */
    struct
    {
        FILE_NAME_INFORMATION info;
        WCHAR pad[2];
    } tiny;
    poison_iosb(&iosb);
    status = NtQueryInformationFile(h, &iosb, &tiny, sizeof(tiny), FileNameInformation);
    ok(status == STATUS_BUFFER_OVERFLOW, "short name buffer -> %08lx", (unsigned long)status);
    ok(tiny.info.FileNameLength > sizeof(tiny.pad) + sizeof(WCHAR),
       "short name buffer still reports full length %lu", (unsigned long)tiny.info.FileNameLength);

    /* --- error conventions. ------------------------------------------------ */
    status = NtQueryInformationFile(h, &iosb, &std, sizeof(std) - 4, FileStandardInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short standard buffer -> %08lx",
       (unsigned long)status);
    /* An unsupported class is deliberately NOT pinned here: the pinned Wine
     * answers STATUS_NOT_IMPLEMENTED, which is the oracle being unbuilt
     * rather than a contract, and an unbuilt answer is never pinned
     * (Art. 12). proskrnl refuses it loudly and fatally instead. */

    /* --- FileAllInformation aggregates the pieces. ------------------------- */
    struct
    {
        FILE_ALL_INFORMATION all;
        WCHAR pad[128];
    } all;
    poison_iosb(&iosb);
    memset(&all, 0, sizeof(all));
    status = NtQueryInformationFile(h, &iosb, &all, sizeof(all), FileAllInformation);
    ok(status == STATUS_SUCCESS, "query all -> %08lx", (unsigned long)status);
    ok(all.all.StandardInformation.EndOfFile.QuadPart == 10, "all: EOF %ld",
       (long)all.all.StandardInformation.EndOfFile.QuadPart);
    ok(all.all.PositionInformation.CurrentByteOffset.QuadPart == 7, "all: position %ld",
       (long)all.all.PositionInformation.CurrentByteOffset.QuadPart);
    ok(all.all.NameInformation.FileNameLength != 0, "all: name filled");

    NtClose(h);

    /* --- FileEndOfFileInformation on a handle without FILE_WRITE_DATA ------ */
    /* (pinned Wine, fuzzer-found: the shrink path reports
     * STATUS_INVALID_PARAMETER, the grow path STATUS_INVALID_HANDLE —
     * regardless of whether the handle has read access). */
    {
        HANDLE weak;
        FILE_END_OF_FILE_INFORMATION eof2;
        status = open_file(&weak, dir, W("probe.bin"), FILE_GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
        ok(status == STATUS_SUCCESS, "read-only open -> %08lx", (unsigned long)status);
        eof2.EndOfFile.QuadPart = 1; /* below the 10-byte EOF: shrink */
        status = NtSetInformationFile(weak, &iosb, &eof2, sizeof(eof2), FileEndOfFileInformation);
        ok(status == STATUS_INVALID_PARAMETER, "eof shrink without write -> %08lx",
           (unsigned long)status);
        eof2.EndOfFile.QuadPart = 4096; /* above: grow */
        status = NtSetInformationFile(weak, &iosb, &eof2, sizeof(eof2), FileEndOfFileInformation);
        ok(status == STATUS_INVALID_HANDLE, "eof grow without write -> %08lx",
           (unsigned long)status);
        NtClose(weak);
    }

    /* --- ...but an OVERWRITE-disposition handle CAN (pinned Wine, fuzzer-
     * found): the server grants FILE_OVERWRITE/FILE_OVERWRITE_IF handles
     * FILE_WRITE_ATTRIBUTES (server/file.c create_file), which makes the
     * backing writable — so set-EOF succeeds in both directions even when
     * the caller asked for read access only. */
    {
        HANDLE weak;
        FILE_END_OF_FILE_INFORMATION eof2;
        scrub_file(dir, W("eofweak.bin"));
        status = open_file(&weak, dir, W("eofweak.bin"), FILE_GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
        ok(status == STATUS_SUCCESS, "overwrite-if read-only open -> %08lx", (unsigned long)status);
        eof2.EndOfFile.QuadPart = 4096; /* grow */
        status = NtSetInformationFile(weak, &iosb, &eof2, sizeof(eof2), FileEndOfFileInformation);
        ok(status == STATUS_SUCCESS, "eof grow on overwrite-if handle -> %08lx",
           (unsigned long)status);
        eof2.EndOfFile.QuadPart = 1; /* shrink */
        status = NtSetInformationFile(weak, &iosb, &eof2, sizeof(eof2), FileEndOfFileInformation);
        ok(status == STATUS_SUCCESS, "eof shrink on overwrite-if handle -> %08lx",
           (unsigned long)status);
        NtClose(weak);
        scrub_file(dir, W("eofweak.bin"));
    }

    /* --- a directory handle reports directory-ness. ------------------------ */
    status = NtQueryInformationFile(dir, &iosb, &std, sizeof(std), FileStandardInformation);
    ok(status == STATUS_SUCCESS, "query dir standard -> %08lx", (unsigned long)status);
    ok(std.Directory == TRUE, "dir Directory flag set");
    status = NtQueryInformationFile(dir, &iosb, &basic, sizeof(basic), FileBasicInformation);
    ok(status == STATUS_SUCCESS &&
           (basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY,
       "dir attributes %lx", (unsigned long)basic.FileAttributes);

    /* --- NtQueryAttributesFile by path. ------------------------------------ */
    {
        UNICODE_STRING path;
        OBJECT_ATTRIBUTES attr;
        init_ustr(&path, W("\\??\\C:\\prstest\\info\\probe.bin"));
        init_attr(&attr, NULL, &path, OBJ_CASE_INSENSITIVE);
        memset(&basic, 0, sizeof(basic));
        status = NtQueryAttributesFile(&attr, &basic);
        ok(status == STATUS_SUCCESS, "query attributes by path -> %08lx", (unsigned long)status);
        ok((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0, "path attributes %lx",
           (unsigned long)basic.FileAttributes);

        init_ustr(&path, W("\\??\\C:\\prstest\\info\\missing.bin"));
        status = NtQueryAttributesFile(&attr, &basic);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "query attributes missing -> %08lx",
           (unsigned long)status);
    }

    scrub_file(dir, W("probe.bin"));
    NtClose(dir);
}
