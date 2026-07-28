/*
 * sem_file/ea_volume.c — NtQueryEaFile / NtSetEaFile / NtFlushBuffersFileEx
 * / NtSetVolumeInformationFile (CUI-5).
 *
 * None of the four has a PE-side caller in the baked CUI set; the contract
 * is the pinned Wine's own behaviour (dlls/ntdll/unix/file.c) where it is
 * built, and NT's FAT driver where the oracle is a stub:
 *   - NtQueryEaFile zeroes the caller's buffer and answers
 *     STATUS_NO_EAS_ON_FILE with the IOSB untouched (no EAs exist on
 *     either backend);
 *   - NtSetEaFile refuses STATUS_ACCESS_DENIED;
 *   - NtFlushBuffersFileEx requires a writable handle (ACCESS_DENIED on a
 *     read-only one — the plain NtFlushBuffersFile is the Ex form with
 *     flags 0 in the pinned tree, so it shares the requirement) and
 *     ignores unknown flags;
 *   - NtSetVolumeInformationFile: the oracle's arm is an unconditional-
 *     success FIXME stub — unbuilt, so only the label class's SUCCESS is
 *     pinned on both sides; the real label write and the refusal of other
 *     classes are pinned beyond_oracle against NT's FAT driver
 *     (microsoft/Windows-driver-samples filesys/fastfat/volinfo.c
 *     FatCommonSetVolumeInfo: FileFsLabelInformation -> FatSetFsLabelInfo,
 *     default -> STATUS_INVALID_PARAMETER).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryEaFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG,
                                      PULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetEaFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFlushBuffersFileEx(HANDLE, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK);
/* NtQuery/SetVolumeInformationFile come from mingw's winternl.h (its Set
 * prototype spells the class enum FILE_INFORMATION_CLASS — cast at the
 * call sites). */
#define FS_CLASS(c) ((FILE_INFORMATION_CLASS)(c))
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);

START_TEST(ea_volume)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, h;

    dir = open_test_dir(W("\\??\\C:\\prstest\\eavol"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("ea.bin"));

    status = open_file(&h, dir, W("ea.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create ea.bin -> %08lx", (unsigned long)status);
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "data", 4, NULL, NULL);
    ok(status == STATUS_SUCCESS, "write -> %08lx", (unsigned long)status);

    /* --- NtQueryEaFile: no EAs, buffer zeroed, IOSB untouched --------------- */
    {
        unsigned char buffer[64];
        memset(buffer, 0xcc, sizeof(buffer));
        poison_iosb(&iosb);
        status = NtQueryEaFile(h, &iosb, buffer, sizeof(buffer), TRUE, NULL, 0, NULL, TRUE);
        ok(status == STATUS_NO_EAS_ON_FILE, "query ea -> %08lx", (unsigned long)status);
        int zeroed = 1;
        for (unsigned i = 0; i < sizeof(buffer); i++)
        {
            if (buffer[i] != 0)
                zeroed = 0;
        }
        ok(zeroed, "query ea zeroed the buffer");
        ok(iosb.Status == IOSB_POISON_STATUS, "query ea iosb untouched %08lx",
           (unsigned long)iosb.Status);
    }

    /* --- NtSetEaFile refuses ------------------------------------------------ */
    {
        unsigned char buffer[32];
        memset(buffer, 0, sizeof(buffer));
        status = NtSetEaFile(h, &iosb, buffer, sizeof(buffer));
        ok(status == STATUS_ACCESS_DENIED, "set ea -> %08lx", (unsigned long)status);
        /* The refusal never looks at the handle (fuzzer-found: the pinned
         * Wine's arm is an unconditional ACCESS_DENIED stub). */
        status = NtSetEaFile((HANDLE)(ULONG_PTR)0xdead0, &iosb, buffer, sizeof(buffer));
        ok(status == STATUS_ACCESS_DENIED, "set ea bad handle -> %08lx", (unsigned long)status);
    }

    /* --- NtFlushBuffersFileEx ----------------------------------------------- */
    poison_iosb(&iosb);
    status = NtFlushBuffersFileEx(h, 0, NULL, 0, &iosb);
    ok(status == STATUS_SUCCESS, "flush-ex -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "flush-ex iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "flush-ex Information %lu", (unsigned long)iosb.Information);
    /* Unknown flags are ignored (the oracle FIXMEs and continues). */
    status = NtFlushBuffersFileEx(h, 0x80, NULL, 0, &iosb);
    ok(status == STATUS_SUCCESS, "flush-ex unknown flags -> %08lx", (unsigned long)status);
    NtClose(h);

    /* A read-only handle refuses the flush — Ex and the plain form alike
     * (the pinned tree's NtFlushBuffersFile IS the Ex form with flags 0). */
    status = open_file(&h, dir, W("ea.bin"), FILE_GENERIC_READ | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, &iosb);
    ok(status == STATUS_SUCCESS, "read-only open -> %08lx", (unsigned long)status);
    status = NtFlushBuffersFileEx(h, 0, NULL, 0, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "flush-ex read-only -> %08lx", (unsigned long)status);
    status = NtFlushBuffersFile(h, &iosb);
    ok(status == STATUS_ACCESS_DENIED, "flush read-only -> %08lx", (unsigned long)status);
    NtClose(h);
    scrub_file(dir, W("ea.bin"));

    /* --- NtSetVolumeInformationFile ----------------------------------------- */
    {
        HANDLE root = NULL;
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        init_ustr(&name, W("\\??\\C:"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenFile(&root, FILE_GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        ok(status == STATUS_SUCCESS, "open volume root -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            /* Remember the current label so the set below can restore it. */
            char volbuf[sizeof(FILE_FS_VOLUME_INFORMATION) + 32 * sizeof(WCHAR)];
            FILE_FS_VOLUME_INFORMATION *vol = (FILE_FS_VOLUME_INFORMATION *)volbuf;
            memset(volbuf, 0, sizeof(volbuf));
            status = NtQueryVolumeInformationFile(root, &iosb, volbuf, sizeof(volbuf),
                                                  FileFsVolumeInformation);
            ok(status == STATUS_SUCCESS, "query label -> %08lx", (unsigned long)status);
            char oldbuf[sizeof(FILE_FS_LABEL_INFORMATION) + 32 * sizeof(WCHAR)];
            FILE_FS_LABEL_INFORMATION *old = (FILE_FS_LABEL_INFORMATION *)oldbuf;
            old->VolumeLabelLength = vol->VolumeLabelLength;
            memcpy(old->VolumeLabel, vol->VolumeLabel, vol->VolumeLabelLength);

            char newbuf[sizeof(FILE_FS_LABEL_INFORMATION) + 32 * sizeof(WCHAR)];
            FILE_FS_LABEL_INFORMATION *label = (FILE_FS_LABEL_INFORMATION *)newbuf;
            static const WCHAR newLabel[] = W("PRSLBL");
            label->VolumeLabelLength = 6 * sizeof(WCHAR);
            memcpy(label->VolumeLabel, newLabel, label->VolumeLabelLength);
            status = NtSetVolumeInformationFile(
                root, &iosb, label,
                (ULONG)(sizeof(FILE_FS_LABEL_INFORMATION) + label->VolumeLabelLength),
                FS_CLASS(FileFsLabelInformation));
            ok(status == STATUS_SUCCESS, "set label -> %08lx", (unsigned long)status);

            /* The oracle's set is an unconditional-success FIXME stub, so it
             * cannot answer for the write-back; NT's FAT driver really sets
             * the label (fastfat volinfo.c FatSetFsLabelInfo). */
            memset(volbuf, 0, sizeof(volbuf));
            status = NtQueryVolumeInformationFile(root, &iosb, volbuf, sizeof(volbuf),
                                                  FileFsVolumeInformation);
            ok(status == STATUS_SUCCESS, "re-query label -> %08lx", (unsigned long)status);
            beyond_oracle
            {
                ok(vol->VolumeLabelLength == 6 * sizeof(WCHAR) &&
                       memcmp(vol->VolumeLabel, newLabel, 6 * sizeof(WCHAR)) == 0,
                   "label readback (%lu bytes)", (unsigned long)vol->VolumeLabelLength);
            }

            /* Any other set class refuses on FAT (fastfat volinfo.c default
             * arm); the oracle stub answers success for those too, so the
             * pin is beyond_oracle. */
            {
                FILE_FS_SIZE_INFORMATION size;
                memset(&size, 0, sizeof(size));
                status = NtSetVolumeInformationFile(root, &iosb, &size, sizeof(size),
                                                    FS_CLASS(FileFsSizeInformation));
                beyond_oracle
                {
                    ok(status == STATUS_INVALID_PARAMETER, "set size class -> %08lx",
                       (unsigned long)status);
                }
            }

            /* Restore the original label (a no-op on the oracle stub). */
            status = NtSetVolumeInformationFile(
                root, &iosb, old,
                (ULONG)(sizeof(FILE_FS_LABEL_INFORMATION) + old->VolumeLabelLength),
                FS_CLASS(FileFsLabelInformation));
            ok(status == STATUS_SUCCESS, "restore label -> %08lx", (unsigned long)status);
            NtClose(root);
        }
    }

    NtClose(dir);
}
