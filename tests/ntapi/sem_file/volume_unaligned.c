/*
 * sem_file/volume_unaligned.c — NtQueryVolumeInformationFile does not
 * require its output buffer to be 8-byte aligned.
 *
 * FILE_FS_VOLUME/SIZE/FULL_SIZE_INFORMATION all open with a LARGE_INTEGER,
 * which invites a kernel to fill them through a struct pointer and inherit
 * the buffer's alignment on every 8-byte store — legal on x86 hardware,
 * undefined C, and this build traps it. NT copies bytes wherever the caller
 * asked: every WOW64 caller proves it, because dlls/wow64/file.c
 * wow64_NtQueryVolumeInformationFile passes the 32-bit caller's buffer
 * through untranslated (get_ptr) and i386 gives stack buffers 4-byte
 * alignment.
 *
 * Convicted by a real caller, not by a sweep: SAFlashPlayer.exe's File>Open
 * Browse dialog (comdlg32 building the drive list via GetVolumeInformationW
 * / GetDiskFreeSpaceExW, dlls/kernelbase/volume.c) handed exactly such a
 * buffer over and proskrnl took a #UD in NtQueryVolumeInformationFile's
 * FileFsVolumeInformation fill — the same defect class dir_unaligned_buffer.c
 * pinned for NtQueryDirectoryFile (IopFillDirEntry, winemine's SxS lookup).
 *
 * Deltas 4 (what i386 hands over), 2 and 1 (nothing in the structs is
 * byte-aligned, but NT treats the buffer as bytes, so all three answer
 * alike). Values are read back with memcpy — the TEST must not commit the
 * same undefined read it is pinning against.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);

/* 8-aligned slab the deltas offset into (dir_unaligned_buffer.c's idiom). */
static long long aligned_store[128];

static const unsigned deltas[] = {4, 2, 1};

START_TEST(volume_unaligned)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    unsigned i;

    /* The drive-root handle kernelbase's volume queries run on (volume_info.c). */
    HANDLE root = NULL;
    init_ustr(&name, W("\\??\\C:"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenFile(&root, SYNCHRONIZE, &attr, &iosb, 0,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    ok(status == STATUS_SUCCESS, "open \\??\\C: -> %08lx", (unsigned long)status);

    /* Aligned baselines: the unaligned answers must be THESE bytes, not
     * merely a success status. Free space may move between calls, so the
     * size classes compare the total (stable) and bound the available. */
    FILE_FS_VOLUME_INFORMATION vol_base;
    memset(&vol_base, 0, sizeof(vol_base));
    status = NtQueryVolumeInformationFile(root, &iosb, &vol_base, sizeof(vol_base),
                                          FileFsVolumeInformation);
    ok(status == STATUS_SUCCESS, "aligned volume info -> %08lx", (unsigned long)status);

    FILE_FS_SIZE_INFORMATION size_base;
    memset(&size_base, 0, sizeof(size_base));
    status = NtQueryVolumeInformationFile(root, &iosb, &size_base, sizeof(size_base),
                                          FileFsSizeInformation);
    ok(status == STATUS_SUCCESS, "aligned size info -> %08lx", (unsigned long)status);

    FILE_FS_ATTRIBUTE_INFORMATION attr_base;
    memset(&attr_base, 0, sizeof(attr_base));
    status = NtQueryVolumeInformationFile(root, &iosb, &attr_base, sizeof(attr_base),
                                          FileFsAttributeInformation);
    ok(status == STATUS_SUCCESS, "aligned attribute info -> %08lx", (unsigned long)status);

    /* Not a fixed constant: the oracle's mountmgr drive-root handle answers
     * DeviceType 0 where proskrnl's FAT volume answers FILE_DEVICE_DISK.
     * The pin is alignment-independence, not the device type itself. */
    FILE_FS_DEVICE_INFORMATION dev_base;
    memset(&dev_base, 0, sizeof(dev_base));
    status = NtQueryVolumeInformationFile(root, &iosb, &dev_base, sizeof(dev_base),
                                          FileFsDeviceInformation);
    ok(status == STATUS_SUCCESS, "aligned device info -> %08lx", (unsigned long)status);

    for (i = 0; i < sizeof(deltas) / sizeof(deltas[0]); i++)
    {
        unsigned delta = deltas[i];
        unsigned char *buffer = (unsigned char *)aligned_store + delta;

        /* FileFsVolumeInformation: serial + label, LARGE_INTEGER first. */
        FILE_FS_VOLUME_INFORMATION vol;
        memset(aligned_store, 0xcc, sizeof(aligned_store));
        poison_iosb(&iosb);
        status =
            NtQueryVolumeInformationFile(root, &iosb, buffer, sizeof(vol), FileFsVolumeInformation);
        ok(status == STATUS_SUCCESS, "volume info at +%u -> %08lx", delta, (unsigned long)status);
        memcpy(&vol, buffer, sizeof(vol));
        ok(vol.VolumeSerialNumber == vol_base.VolumeSerialNumber,
           "volume serial at +%u %08lx expected %08lx", delta,
           (unsigned long)vol.VolumeSerialNumber, (unsigned long)vol_base.VolumeSerialNumber);
        ok(iosb.Information ==
               offsetof(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + vol.VolumeLabelLength,
           "volume Information at +%u %lu (label %lu bytes)", delta,
           (unsigned long)iosb.Information, (unsigned long)vol.VolumeLabelLength);

        /* FileFsSizeInformation: two LARGE_INTEGERs up front. */
        FILE_FS_SIZE_INFORMATION size;
        memset(aligned_store, 0xcc, sizeof(aligned_store));
        poison_iosb(&iosb);
        status =
            NtQueryVolumeInformationFile(root, &iosb, buffer, sizeof(size), FileFsSizeInformation);
        ok(status == STATUS_SUCCESS, "size info at +%u -> %08lx", delta, (unsigned long)status);
        memcpy(&size, buffer, sizeof(size));
        ok(size.TotalAllocationUnits.QuadPart == size_base.TotalAllocationUnits.QuadPart,
           "size total at +%u %lld expected %lld", delta,
           (long long)size.TotalAllocationUnits.QuadPart,
           (long long)size_base.TotalAllocationUnits.QuadPart);
        ok(size.AvailableAllocationUnits.QuadPart >= 0 &&
               size.AvailableAllocationUnits.QuadPart <= size.TotalAllocationUnits.QuadPart,
           "size available at +%u %lld of %lld", delta,
           (long long)size.AvailableAllocationUnits.QuadPart,
           (long long)size.TotalAllocationUnits.QuadPart);
        ok(size.BytesPerSector == size_base.BytesPerSector, "BytesPerSector at +%u %lu", delta,
           (unsigned long)size.BytesPerSector);

        /* FileFsFullSizeInformation: three LARGE_INTEGERs up front. */
        FILE_FS_FULL_SIZE_INFORMATION full;
        memset(aligned_store, 0xcc, sizeof(aligned_store));
        poison_iosb(&iosb);
        status = NtQueryVolumeInformationFile(root, &iosb, buffer, sizeof(full),
                                              FileFsFullSizeInformation);
        ok(status == STATUS_SUCCESS, "full size info at +%u -> %08lx", delta,
           (unsigned long)status);
        memcpy(&full, buffer, sizeof(full));
        ok(full.TotalAllocationUnits.QuadPart == size_base.TotalAllocationUnits.QuadPart,
           "full size total at +%u %lld expected %lld", delta,
           (long long)full.TotalAllocationUnits.QuadPart,
           (long long)size_base.TotalAllocationUnits.QuadPart);
        ok(full.SectorsPerAllocationUnit == size_base.SectorsPerAllocationUnit,
           "full SectorsPerAllocationUnit at +%u %lu", delta,
           (unsigned long)full.SectorsPerAllocationUnit);

        /* FileFsAttributeInformation: ULONGs + the fs name. */
        FILE_FS_ATTRIBUTE_INFORMATION fsattr;
        memset(aligned_store, 0xcc, sizeof(aligned_store));
        poison_iosb(&iosb);
        status = NtQueryVolumeInformationFile(root, &iosb, buffer, sizeof(fsattr),
                                              FileFsAttributeInformation);
        ok(status == STATUS_SUCCESS, "attribute info at +%u -> %08lx", delta,
           (unsigned long)status);
        memcpy(&fsattr, buffer, sizeof(fsattr));
        ok(fsattr.FileSystemAttributes == attr_base.FileSystemAttributes,
           "fs attributes at +%u %08lx expected %08lx", delta,
           (unsigned long)fsattr.FileSystemAttributes,
           (unsigned long)attr_base.FileSystemAttributes);
        ok(fsattr.MaximumComponentNameLength == attr_base.MaximumComponentNameLength,
           "max component at +%u %lu", delta, (unsigned long)fsattr.MaximumComponentNameLength);

        /* FileFsDeviceInformation: ULONGs only, but the same contract. */
        FILE_FS_DEVICE_INFORMATION dev;
        memset(aligned_store, 0xcc, sizeof(aligned_store));
        poison_iosb(&iosb);
        status =
            NtQueryVolumeInformationFile(root, &iosb, buffer, sizeof(dev), FileFsDeviceInformation);
        ok(status == STATUS_SUCCESS, "device info at +%u -> %08lx", delta, (unsigned long)status);
        memcpy(&dev, buffer, sizeof(dev));
        ok(dev.DeviceType == dev_base.DeviceType, "device type at +%u %lu expected %lu", delta,
           (unsigned long)dev.DeviceType, (unsigned long)dev_base.DeviceType);
    }

    NtClose(root);
}
