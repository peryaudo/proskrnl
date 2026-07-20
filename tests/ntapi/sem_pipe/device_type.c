/*
 * sem_pipe/device_type.c — FileFsDeviceInformation.DeviceType per device
 * (M10).
 *
 * kernelbase's GetFileType is a straight NtQueryVolumeInformationFile(
 * FileFsDeviceInformation) switch on DeviceType (third_party/wine
 * dlls/kernelbase/file.c GetFileType) — msvcrt classifies its stdio streams
 * with it and cmd.exe detects console vs pipe vs file redirection through
 * it. A kernel that reports every handle as FILE_DEVICE_DISK makes `dir |
 * more` misdetect. Pinned here: disk handles report FILE_DEVICE_DISK, pipe
 * handles FILE_DEVICE_NAMED_PIPE (Wine dlls/ntdll/unix/file.c
 * get_device_info; wineserver's console reports FILE_DEVICE_CONSOLE —
 * server/console.c console_get_volume_info — but no console handle exists
 * under either harness runner, so that leg is exercised by the interactive
 * console acceptance instead).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

START_TEST(device_type)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    FILE_FS_DEVICE_INFORMATION info;

    /* --- a disk handle (the boot volume's root directory) ------------------ */
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE disk = NULL;
    init_ustr(&name, W("\\??\\C:\\"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateFile(&disk, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_SUCCESS, "open C:\\ -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    memset(&info, 0xcc, sizeof(info));
    status =
        NtQueryVolumeInformationFile(disk, &iosb, &info, sizeof(info), FileFsDeviceInformation);
    ok(status == STATUS_SUCCESS, "disk device info -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(info), "disk info length %lu", (unsigned long)iosb.Information);
    /* A mounted disk filesystem is FILE_DEVICE_DISK_FILE_SYSTEM (0x8), not
     * bare FILE_DEVICE_DISK — Wine dlls/ntdll/unix/file.c get_device_info's
     * regular-file default; GetFileType maps both to FILE_TYPE_DISK. */
    ok(info.DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM, "disk DeviceType %08lx",
       (unsigned long)info.DeviceType);

    /* A short buffer is STATUS_BUFFER_TOO_SMALL (Wine dlls/ntdll/unix/file.c
     * NtQueryVolumeInformationFile). */
    status =
        NtQueryVolumeInformationFile(disk, &iosb, &info, sizeof(info) - 1, FileFsDeviceInformation);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short buffer -> %08lx", (unsigned long)status);
    NtClose(disk);

    /* --- both ends of a named pipe ----------------------------------------- */
    HANDLE server = NULL, client = NULL;
    status = create_pipe_instance(&server, W("\\??\\pipe\\prstest_devtype"),
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_PIPE_TYPE_BYTE,
                                  FILE_PIPE_BYTE_STREAM_MODE, 1, &iosb);
    ok(status == STATUS_SUCCESS, "create pipe -> %08lx", (unsigned long)status);

    status = open_pipe_client(&client, W("\\??\\pipe\\prstest_devtype"), &iosb);
    ok(status == STATUS_SUCCESS, "open client end -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    memset(&info, 0xcc, sizeof(info));
    status =
        NtQueryVolumeInformationFile(server, &iosb, &info, sizeof(info), FileFsDeviceInformation);
    ok(status == STATUS_SUCCESS, "server device info -> %08lx", (unsigned long)status);
    ok(iosb.Information == sizeof(info), "server info length %lu", (unsigned long)iosb.Information);
    ok(info.DeviceType == FILE_DEVICE_NAMED_PIPE, "server DeviceType %08lx",
       (unsigned long)info.DeviceType);

    memset(&info, 0xcc, sizeof(info));
    status =
        NtQueryVolumeInformationFile(client, &iosb, &info, sizeof(info), FileFsDeviceInformation);
    ok(status == STATUS_SUCCESS, "client device info -> %08lx", (unsigned long)status);
    ok(info.DeviceType == FILE_DEVICE_NAMED_PIPE, "client DeviceType %08lx",
       (unsigned long)info.DeviceType);

    NtClose(client);
    NtClose(server);
}
