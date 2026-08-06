/*
 * sem_file/id_info.c — NtQueryInformationFile(FileIdInformation): the volume
 * serial plus the 128-bit file id.
 *
 * Convicted by the winetest gate: ntdll:directory reaches this class at
 * directory.c:1461 and proskrnl answered STATUS_NOT_IMPLEMENTED, which the
 * armed boot turns into a panic (Art. 12) — so the class did not merely fail
 * a few assertions, it ENDED the pair, taking every test after it with it.
 * That is the loud refusal working exactly as designed: the hole announced
 * itself instead of being papered over, and this pin is the answer to it.
 *
 * The class is a JOIN of two facts proskrnl already serves separately, and
 * the whole content of the contract is that the three answers must agree:
 *
 *   FileIdInformation.VolumeSerialNumber  ==  FileFsVolumeInformation's
 *   FileIdInformation.FileId (low 8 bytes) ==  FileInternalInformation's
 *
 * ntdll:file's test_file_id_information says the same thing against the
 * Win32 spelling (`dwords[0] == info.dwVolumeSerialNumber`,
 * `dwords[0]/[1] == info.nFileIndexLow/High`), and adds the part that is
 * easy to get wrong: the UPPER eight bytes of the 128-bit id are ZERO, and
 * they are WRITTEN — the test poisons the buffer with 0x11 first and checks
 * the poison is gone. A 64-bit-only implementation that filled just the
 * bottom half would pass every equality above and fail that.
 *
 * The oracle's implementation is the join too (dlls/ntdll/unix/file.c,
 * FileIdInformation): serial from the mount manager, id from st_ino,
 * `memset(&info->FileId, 0, sizeof(info->FileId))` and then the low
 * ULONGLONG assigned over it.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);

/* mingw's winternl.h stops its FILE_INFORMATION_CLASS enum at 54 and has
 * neither the class nor the struct, so both are spelled here — the same
 * arrangement util.h already uses for the Nt* prototypes that header omits.
 * The tests deliberately build against the SYSTEM headers on both runners
 * and never against abi/ (ntapi.h says why: abi/ is the kernel's generated
 * contract, and proving it against independent headers at run time is the
 * whole point of the gate). So 59 and this layout are hand-written, and
 * cited as G8 requires: Microsoft's FILE_ID_INFORMATION documentation, and
 * the pinned tree's include/winternl.h (FILE_ID_128 / _FILE_ID_INFORMATION,
 * FileIdInformation = 59 in _FILE_INFORMATION_CLASS) which the kernel's
 * abi/ntioapi.h is generated from. If the two ever disagree this test fails
 * on proskrnl rather than passing quietly. */
#define FileIdInformation ((FILE_INFORMATION_CLASS)59)
typedef struct
{
    ULONGLONG VolumeSerialNumber;
    UCHAR FileId[16]; /* FILE_ID_128, flattened: mingw already has that name */
} PRS_FILE_ID_INFORMATION;

START_TEST(id_info)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, a, a2, b;
    PRS_FILE_ID_INFORMATION ida, ida2, idb;
    FILE_INTERNAL_INFORMATION internal;
    FILE_FS_VOLUME_INFORMATION *volume;
    UCHAR volumeBuffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 64];

    dir = open_test_dir(W("\\??\\C:\\prstest\\idinfo"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("ida.bin"));
    scrub_file(dir, W("idb.bin"));

    status = open_file(&a, dir, W("ida.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ida.bin -> %08lx", (unsigned long)status);
    status = open_file(&b, dir, W("idb.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create idb.bin -> %08lx", (unsigned long)status);

    /* --- the class answers, and writes the WHOLE structure ------------------
     * The poison is the point: every byte the class owns must be overwritten,
     * including the upper half of the 128-bit id that carries no information
     * on a volume whose ids are 64-bit. */
    memset(&ida, 0x11, sizeof(ida));
    poison_iosb(&iosb);
    status = NtQueryInformationFile(a, &iosb, &ida, sizeof(ida), FileIdInformation);
    ok(status == STATUS_SUCCESS, "query id info -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == sizeof(ida), "Information %lu", (unsigned long)iosb.Information);

    {
        const UCHAR *upper = &ida.FileId[8];
        int poisoned = 0;
        for (int i = 0; i < 8; i++)
        {
            if (upper[i] != 0)
                poisoned = 1;
        }
        ok(!poisoned, "the upper 8 bytes of the 128-bit id are zero, and written");
    }

    /* --- it agrees with FileInternalInformation ----------------------------- */
    memset(&internal, 0, sizeof(internal));
    status = NtQueryInformationFile(a, &iosb, &internal, sizeof(internal), FileInternalInformation);
    ok(status == STATUS_SUCCESS, "query internal -> %08lx", (unsigned long)status);
    {
        ULONGLONG low;
        memcpy(&low, &ida.FileId[0], sizeof(low));
        ok(low == (ULONGLONG)internal.IndexNumber.QuadPart,
           "FileId low half %llx != IndexNumber %llx", (unsigned long long)low,
           (unsigned long long)internal.IndexNumber.QuadPart);
        ok(low != 0, "the file id is nonzero for a regular file");
    }

    /* --- and with FileFsVolumeInformation ----------------------------------- */
    volume = (FILE_FS_VOLUME_INFORMATION *)volumeBuffer;
    memset(volumeBuffer, 0, sizeof(volumeBuffer));
    status = NtQueryVolumeInformationFile(a, &iosb, volume, sizeof(volumeBuffer),
                                          FileFsVolumeInformation);
    ok(status == STATUS_SUCCESS, "query volume -> %08lx", (unsigned long)status);
    ok((ULONG)ida.VolumeSerialNumber == volume->VolumeSerialNumber,
       "serial %08lx != volume serial %08lx", (unsigned long)ida.VolumeSerialNumber,
       (unsigned long)volume->VolumeSerialNumber);

    /* --- identity, the same three ways internal_info pins it ---------------- */
    status = open_file(&a2, dir, W("ida.bin"), FILE_GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "reopen ida.bin -> %08lx", (unsigned long)status);
    memset(&ida2, 0x11, sizeof(ida2));
    status = NtQueryInformationFile(a2, &iosb, &ida2, sizeof(ida2), FileIdInformation);
    ok(status == STATUS_SUCCESS, "query second handle -> %08lx", (unsigned long)status);
    ok(memcmp(&ida2.FileId, &ida.FileId, sizeof(ida.FileId)) == 0,
       "two handles to one file report one id");
    ok(ida2.VolumeSerialNumber == ida.VolumeSerialNumber, "and one serial");
    NtClose(a2);

    memset(&idb, 0x11, sizeof(idb));
    status = NtQueryInformationFile(b, &iosb, &idb, sizeof(idb), FileIdInformation);
    ok(status == STATUS_SUCCESS, "query the other file -> %08lx", (unsigned long)status);
    ok(memcmp(&idb.FileId, &ida.FileId, sizeof(ida.FileId)) != 0,
       "two different files report different ids");
    ok(idb.VolumeSerialNumber == ida.VolumeSerialNumber, "but the same volume serial");

    /* --- a short buffer is a LENGTH complaint ------------------------------- */
    status = NtQueryInformationFile(a, &iosb, &ida, sizeof(ida) - 1, FileIdInformation);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);

    NtClose(a);
    NtClose(b);
    scrub_file(dir, W("ida.bin"));
    scrub_file(dir, W("idb.bin"));
    NtClose(dir);
}
