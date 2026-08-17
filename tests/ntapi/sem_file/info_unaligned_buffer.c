/*
 * sem_file/info_unaligned_buffer.c — NtQueryInformationFile and the two
 * by-NAME attribute queries do not require an 8-byte-aligned output buffer.
 *
 * The third of the same defect: dir_unaligned_buffer.c pinned it for
 * NtQueryDirectoryFile and volume_unaligned.c for
 * NtQueryVolumeInformationFile, and the by-handle and by-name info classes
 * were left with the same shape — a fixed struct that OPENS with a
 * LARGE_INTEGER, filled through a struct pointer aimed straight at the
 * caller's buffer. That is an 8-byte store at whatever alignment the caller
 * had; legal on x86 hardware, undefined in C, and a trap in a UBSan build.
 *
 * Every WOW64 caller proves NT does not require the alignment, because the
 * thunks hand the 32-bit caller's buffer down untranslated —
 * `NtQueryInformationFile( handle, iosb_32to64( &io, io32 ), info, len, class )`
 * converts only the IOSB (third_party/wine dlls/wow64/file.c
 * wow64_NtQueryInformationFile), and wow64_NtQueryAttributesFile /
 * wow64_NtQueryFullAttributesFile convert only the OBJECT_ATTRIBUTES — while
 * i386 gives a stack struct 4-byte alignment. The caller that makes this
 * ordinary rather than hostile is the pinned tree's own SxS loader: ntdll's
 * actctx.c asks FileEndOfFileInformation of every manifest file it maps.
 *
 * Deltas 4 (what i386 hands over), 2 and 1: nothing in these structs is
 * byte-aligned, but NT treats the buffer as bytes, so all three must answer
 * exactly like delta 0 — same status, same bytes.
 *
 * Values are read back with memcpy: the TEST must not commit the same
 * undefined access it is pinning against.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES *,
                                                  FILE_NETWORK_OPEN_INFORMATION *);

/* 8-aligned slab the deltas offset into (dir_unaligned_buffer.c's idiom). */
static long long aligned_store[256];

static const unsigned deltas[] = {4, 2, 1};

/* Query `cls` into aligned_store + delta and hand back the first `bytes`
 * bytes of the answer plus the status. */
static NTSTATUS query_at(HANDLE file, FILE_INFORMATION_CLASS cls, unsigned delta, void *out,
                         ULONG bytes, ULONG_PTR *informationOut)
{
    unsigned char *buffer = (unsigned char *)aligned_store + delta;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    memset(aligned_store, 0xa5, sizeof(aligned_store));
    poison_iosb(&iosb);
    status = NtQueryInformationFile(file, &iosb, buffer, bytes, cls);
    memcpy(out, buffer, bytes);
    *informationOut = NT_SUCCESS(status) ? iosb.Information : 0;
    return status;
}

START_TEST(info_unaligned_buffer)
{
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    HANDLE dir, file;
    unsigned i;

    dir = open_test_dir(W("\\??\\C:\\prstest\\infounal"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("unaligned.txt"));

    status =
        open_file(&file, dir, W("unaligned.txt"), GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, &iosb);
    ok(status == STATUS_SUCCESS, "create unaligned.txt -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    {
        static const char payload[] = "0123456789abcdef";
        status =
            NtWriteFile(file, NULL, NULL, NULL, &iosb, payload, sizeof(payload) - 1, NULL, NULL);
        ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);
    }

    /* --- 1. FileBasicInformation: four times and the attributes ---------- */
    {
        FILE_BASIC_INFORMATION base, got;
        ULONG_PTR information = 0;

        status = query_at(file, FileBasicInformation, 0, &base, sizeof(base), &information);
        ok(status == STATUS_SUCCESS, "basic aligned -> %08lx", (unsigned long)status);
        ok(information == sizeof(base), "basic aligned Information %llu", (unsigned long long)information);
        for (i = 0; i < 3; i++)
        {
            status =
                query_at(file, FileBasicInformation, deltas[i], &got, sizeof(got), &information);
            ok(status == STATUS_SUCCESS, "basic +%u -> %08lx", deltas[i], (unsigned long)status);
            ok(information == sizeof(got), "basic +%u Information %llu", deltas[i],
               (unsigned long long)information);
            ok(memcmp(&got, &base, sizeof(got)) == 0, "basic +%u differs", deltas[i]);
        }
    }

    /* --- 2. FileStandardInformation: the two sizes ------------------------ */
    {
        FILE_STANDARD_INFORMATION base, got;
        ULONG_PTR information = 0;

        status = query_at(file, FileStandardInformation, 0, &base, sizeof(base), &information);
        ok(status == STATUS_SUCCESS, "standard aligned -> %08lx", (unsigned long)status);
        ok(base.EndOfFile.QuadPart == 16, "standard EndOfFile %lld",
           (long long)base.EndOfFile.QuadPart);
        for (i = 0; i < 3; i++)
        {
            status =
                query_at(file, FileStandardInformation, deltas[i], &got, sizeof(got), &information);
            ok(status == STATUS_SUCCESS, "standard +%u -> %08lx", deltas[i], (unsigned long)status);
            ok(memcmp(&got, &base, sizeof(got)) == 0, "standard +%u differs", deltas[i]);
        }
    }

    /* --- 3. FilePositionInformation: one LARGE_INTEGER at offset 0 -------- */
    {
        FILE_POSITION_INFORMATION base, got;
        ULONG_PTR information = 0;

        status = query_at(file, FilePositionInformation, 0, &base, sizeof(base), &information);
        ok(status == STATUS_SUCCESS, "position aligned -> %08lx", (unsigned long)status);
        ok(base.CurrentByteOffset.QuadPart == 16, "position %lld",
           (long long)base.CurrentByteOffset.QuadPart);
        for (i = 0; i < 3; i++)
        {
            status =
                query_at(file, FilePositionInformation, deltas[i], &got, sizeof(got), &information);
            ok(status == STATUS_SUCCESS, "position +%u -> %08lx", deltas[i], (unsigned long)status);
            ok(memcmp(&got, &base, sizeof(got)) == 0, "position +%u differs", deltas[i]);
        }
    }

    /* --- 4. FileAllInformation: five structs and a name behind them ------- */
    {
        unsigned char base[512], got[512];
        ULONG_PTR baseInformation = 0, information = 0;
        ULONG bytes = (ULONG)sizeof(base);

        status = query_at(file, FileAllInformation, 0, base, bytes, &baseInformation);
        ok(status == STATUS_SUCCESS, "all aligned -> %08lx", (unsigned long)status);
        for (i = 0; i < 3; i++)
        {
            status = query_at(file, FileAllInformation, deltas[i], got, bytes, &information);
            ok(status == STATUS_SUCCESS, "all +%u -> %08lx", deltas[i], (unsigned long)status);
            ok(information == baseInformation, "all +%u Information %llu / %llu", deltas[i],
               (unsigned long long)information, (unsigned long long)baseInformation);
            ok(memcmp(got, base, baseInformation != 0 ? (unsigned)baseInformation : 0) == 0,
               "all +%u differs", deltas[i]);
        }
    }

    NtClose(file);

    /* --- 5. The by-NAME queries ------------------------------------------ *
     * Their whole output is the struct, so the misaligned pointer is the
     * OUT-parameter itself rather than a buffer the caller sizes. */
    init_ustr(&name, W("\\??\\C:\\prstest\\infounal\\unaligned.txt"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    {
        FILE_BASIC_INFORMATION base, got;

        memset(aligned_store, 0xa5, sizeof(aligned_store));
        status = NtQueryAttributesFile(&attr, (FILE_BASIC_INFORMATION *)aligned_store);
        ok(status == STATUS_SUCCESS, "attributes aligned -> %08lx", (unsigned long)status);
        memcpy(&base, aligned_store, sizeof(base));
        for (i = 0; i < 3; i++)
        {
            unsigned char *at = (unsigned char *)aligned_store + deltas[i];
            memset(aligned_store, 0xa5, sizeof(aligned_store));
            status = NtQueryAttributesFile(&attr, (FILE_BASIC_INFORMATION *)(void *)at);
            ok(status == STATUS_SUCCESS, "attributes +%u -> %08lx", deltas[i],
               (unsigned long)status);
            memcpy(&got, at, sizeof(got));
            ok(memcmp(&got, &base, sizeof(got)) == 0, "attributes +%u differs", deltas[i]);
        }
    }
    {
        FILE_NETWORK_OPEN_INFORMATION base, got;

        memset(aligned_store, 0xa5, sizeof(aligned_store));
        status = NtQueryFullAttributesFile(&attr, (FILE_NETWORK_OPEN_INFORMATION *)aligned_store);
        ok(status == STATUS_SUCCESS, "full attributes aligned -> %08lx", (unsigned long)status);
        memcpy(&base, aligned_store, sizeof(base));
        ok(base.EndOfFile.QuadPart == 16, "full attributes EndOfFile %lld",
           (long long)base.EndOfFile.QuadPart);
        for (i = 0; i < 3; i++)
        {
            unsigned char *at = (unsigned char *)aligned_store + deltas[i];
            memset(aligned_store, 0xa5, sizeof(aligned_store));
            status = NtQueryFullAttributesFile(&attr, (FILE_NETWORK_OPEN_INFORMATION *)(void *)at);
            ok(status == STATUS_SUCCESS, "full attributes +%u -> %08lx", deltas[i],
               (unsigned long)status);
            memcpy(&got, at, sizeof(got));
            ok(memcmp(&got, &base, sizeof(got)) == 0, "full attributes +%u differs", deltas[i]);
        }
    }

    scrub_file(dir, W("unaligned.txt"));
    NtClose(dir);
}
