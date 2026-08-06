/*
 * sem_file/dir_class_sizing.c — the buffer size at which each
 * NtQueryDirectoryFile info class stops complaining, and what it says next.
 *
 * Convicted by the winetest gate: ntdll:directory sweeps every class with a
 * zero-length buffer and then grows the buffer one byte at a time until the
 * status stops being STATUS_INFO_LENGTH_MISMATCH, asserting the exact size
 * at which that happens and the status that replaces it (directory.c:389,
 * :421-464). proskrnl failed 4 + 8 of those.
 *
 * Two rules, and both are off-by-something from the obvious implementation:
 *
 * 1. THE THRESHOLD IS align8(offsetof(FileName[1])), NOT offsetof(FileName).
 *    A buffer big enough for the fixed part alone is still too small: NT
 *    wants room for the fixed part plus one name character, rounded up to
 *    the 8-byte entry alignment. For FILE_BOTH_DIRECTORY_INFORMATION that
 *    is 112, not 104 — and an implementation that checks the fixed part
 *    reports STATUS_BUFFER_OVERFLOW eight bytes early.
 *
 * 2. THREE CLASSES LENGTH-CHECK BEFORE THEY REFUSE.
 *    FileObjectIdInformation, FileQuotaInformation and
 *    FileReparsePointInformation are not enumeration classes and answer
 *    STATUS_INVALID_INFO_CLASS — but only once the buffer is at least
 *    sizeof(their struct). Below that they answer INFO_LENGTH_MISMATCH like
 *    any directory class. So "is this class supported" is decided AFTER
 *    "is this buffer big enough", which is the reverse of how a refusal is
 *    normally written, and it is the difference between a class that is
 *    KNOWN-and-unsupported and one that is unknown: a class the enum does
 *    not contain refuses immediately, at any size.
 *
 * Neither rule is guessable, and both are checked here at the exact
 * boundary byte — one below the threshold and at it — because that is the
 * only place they differ from the natural implementation.
 *
 * Oracle-first (G5).
 */
#include "util.h"

static UCHAR dirBuffer[4096];

/* mingw's winternl.h has neither the class numbers nor the structs for the
 * three non-enumeration classes. Spelled here with their source cited
 * (G8): the pinned tree's include/winternl.h, from which the kernel's
 * abi/ntioapi.h is generated. The tests build against the system headers
 * on both runners by design, never against abi/ (ntapi.h says why). */
#define FileObjectIdInformation_        ((FILE_INFORMATION_CLASS)29)
#define FileQuotaInformation_           ((FILE_INFORMATION_CLASS)32)
#define FileReparsePointInformation_    ((FILE_INFORMATION_CLASS)33)
#define FileIdFullDirectoryInformation_ ((FILE_INFORMATION_CLASS)38)

/* sizeof() the three refusing classes' payloads, from the same header. */
#define OBJECTID_INFO_BYTES      72 /* LONGLONG + 3 x UCHAR[16] + UCHAR[16] */
#define REPARSE_POINT_INFO_BYTES 16 /* LONGLONG + ULONG, padded */

/* One probe: what does `class` say for a buffer of exactly `size` bytes? */
/* Always under a mask that selects ONE long-named entry. Without it the
 * first entry returned is "." — a single character, which fits in exactly
 * the threshold buffer — so the class answers SUCCESS there and the
 * overflow the winetest is measuring never happens. The winetest passes a
 * mask for the same reason. */
static NTSTATUS probe(HANDLE dir, FILE_INFORMATION_CLASS class, ULONG size, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING mask;
    mask.Buffer = (PWSTR)W("classprobe.tmp");
    mask.Length = 14 * sizeof(WCHAR);
    mask.MaximumLength = mask.Length;
    poison_iosb(iosb);
    return NtQueryDirectoryFile(dir, NULL, NULL, NULL, iosb, dirBuffer, size, class, FALSE, &mask,
                                TRUE);
}

/* Walk `size` upward until the status stops being INFO_LENGTH_MISMATCH;
 * returns that size, and leaves the status in *statusOut. */
static ULONG threshold(HANDLE dir, FILE_INFORMATION_CLASS class, NTSTATUS *statusOut)
{
    IO_STATUS_BLOCK iosb;
    for (ULONG size = 1; size < 512; size++)
    {
        NTSTATUS status = probe(dir, class, size, &iosb);
        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            *statusOut = status;
            return size;
        }
    }
    *statusOut = STATUS_INFO_LENGTH_MISMATCH;
    return 0;
}

START_TEST(dir_class_sizing)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, scratch;

    dir = open_test_dir(W("\\??\\C:\\prstest\\dirclass"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("classprobe.tmp"));
    status = open_file(&scratch, dir, W("classprobe.tmp"), FILE_GENERIC_WRITE | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create the fixture -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(scratch);

    /* --- a zero-length buffer is a LENGTH complaint for every enumeration
     * class, and leaves the IOSB alone ---------------------------------- */
    {
        static const FILE_INFORMATION_CLASS enumClasses[] = {
            FileDirectoryInformation,       FileFullDirectoryInformation,
            FileBothDirectoryInformation,   FileNamesInformation,
            FileIdBothDirectoryInformation, FileIdFullDirectoryInformation_,
        };
        for (unsigned i = 0; i < 6; i++)
        {
            status = probe(dir, enumClasses[i], 0, &iosb);
            ok(status == STATUS_INFO_LENGTH_MISMATCH, "class %u at 0 bytes -> %08lx",
               (unsigned)enumClasses[i], (unsigned long)status);
            ok(iosb.Status == IOSB_POISON_STATUS, "class %u at 0 bytes wrote the IOSB",
               (unsigned)enumClasses[i]);
        }
    }

    /* --- the threshold, per class: align8(offsetof(FileName[1])) -------- */
    {
        struct
        {
            FILE_INFORMATION_CLASS class;
            ULONG expected;
        } cases[] = {
            {FileDirectoryInformation,
             (offsetof(FILE_DIRECTORY_INFORMATION, FileName) + sizeof(WCHAR) + 7) & ~7u},
            {FileFullDirectoryInformation,
             (offsetof(FILE_FULL_DIRECTORY_INFORMATION, FileName) + sizeof(WCHAR) + 7) & ~7u},
            {FileBothDirectoryInformation,
             (offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName) + sizeof(WCHAR) + 7) & ~7u},
            {FileNamesInformation,
             (offsetof(FILE_NAMES_INFORMATION, FileName) + sizeof(WCHAR) + 7) & ~7u},
        };
        for (unsigned i = 0; i < 4; i++)
        {
            NTSTATUS at;
            ULONG size = threshold(dir, cases[i].class, &at);
            ok(size == cases[i].expected, "class %u turned over at %lu, expected %lu",
               (unsigned)cases[i].class, (unsigned long)size, (unsigned long)cases[i].expected);
            ok(at == STATUS_BUFFER_OVERFLOW, "class %u turned over with %08lx",
               (unsigned)cases[i].class, (unsigned long)at);
        }
    }

    /* --- one byte below the threshold is still a LENGTH complaint -------
     * The single assertion that catches an implementation checking the
     * fixed part instead of fixed-plus-one-character. */
    {
        ULONG fixed = (ULONG)offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName);
        status = probe(dir, FileBothDirectoryInformation, fixed, &iosb);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "Both at exactly its fixed size -> %08lx",
           (unsigned long)status);
    }

    /* --- and at the threshold the IOSB reports the overflow -------------- */
    {
        ULONG over =
            (ULONG)((offsetof(FILE_BOTH_DIRECTORY_INFORMATION, FileName) + sizeof(WCHAR) + 7) &
                    ~7u);
        status = probe(dir, FileBothDirectoryInformation, over, &iosb);
        ok(status == STATUS_BUFFER_OVERFLOW, "Both at its threshold -> %08lx",
           (unsigned long)status);
        ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "overflow iosb.Status %08lx",
           (unsigned long)iosb.Status);
    }

    /* --- the three classes that length-check BEFORE refusing ------------ */
    {
        NTSTATUS at;
        ULONG size;

        size = threshold(dir, FileObjectIdInformation_, &at);
        ok(size == OBJECTID_INFO_BYTES, "FileObjectIdInformation turned over at %lu",
           (unsigned long)size);
        ok(at == STATUS_INVALID_INFO_CLASS, "FileObjectIdInformation -> %08lx", (unsigned long)at);

        size = threshold(dir, FileReparsePointInformation_, &at);
        ok(size == REPARSE_POINT_INFO_BYTES, "FileReparsePointInformation turned over at %lu",
           (unsigned long)size);
        ok(at == STATUS_INVALID_INFO_CLASS, "FileReparsePointInformation -> %08lx",
           (unsigned long)at);

        /* Below its size it is a LENGTH complaint, not a class complaint —
         * the assertion that makes "known but unsupported" a distinct state
         * from "unknown". */
        status = probe(dir, FileReparsePointInformation_, 1, &iosb);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "ReparsePoint at 1 byte -> %08lx",
           (unsigned long)status);
    }

    /* --- an UNKNOWN class refuses immediately, at any size --------------- */
    {
        status = probe(dir, (FILE_INFORMATION_CLASS)0x7000, 0, &iosb);
        ok(status == STATUS_INVALID_INFO_CLASS, "class 0x7000 at 0 bytes -> %08lx",
           (unsigned long)status);
        status = probe(dir, (FILE_INFORMATION_CLASS)0x7000, sizeof(dirBuffer), &iosb);
        ok(status == STATUS_INVALID_INFO_CLASS, "class 0x7000 with room -> %08lx",
           (unsigned long)status);
    }

    scrub_file(dir, W("classprobe.tmp"));
    NtClose(dir);
}
