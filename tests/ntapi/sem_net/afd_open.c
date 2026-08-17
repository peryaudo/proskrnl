/*
 * sem_net/afd_open.c — \Device\Afd opens (trailing names swallowed) and
 * IOCTL_AFD_WINE_CREATE turns the open into a socket.
 *
 * The shapes ws2_32 actually issues (dlls/ws2_32/socket.c WSASocketW):
 * NtOpenFile of \Device\Afd with GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
 * FILE_SYNCHRONOUS_IO_NONALERT unless WSA_FLAG_OVERLAPPED, then
 * IOCTL_AFD_WINE_CREATE with the 16-byte family/type/protocol/flags
 * params. ws2_32:afd's test_open_device pins that ANY trailing name
 * opens (condrv's trailing-name swallow, same shape).
 *
 * The FileFsDeviceInformation leg is the GetFileType path
 * (dlls/kernelbase/file.c GetFileType is a straight switch on
 * DeviceType): msvcrt classifies every stdio handle with it, so a socket
 * on stdout must answer, not refuse (G12's known trap — a NULL
 * QueryVolumeInfo op refuses STATUS_NOT_IMPLEMENTED and the armed panic
 * fires).
 */
#include "util.h"

static void test_device_opens(void)
{
    static const void *names[] = {W("\\Device\\Afd"), W("\\Device\\Afd\\"),
                                  W("\\Device\\Afd\\foobar")};
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status;
    unsigned i;

    for (i = 0; i < 3; i++)
    {
        init_ustr(&name, names[i]);
        init_attr(&attr, NULL, &name, 0);
        handle = NULL;
        status = NtOpenFile(&handle, SYNCHRONIZE, &attr, &iosb, 0, 0);
        ok(status == STATUS_SUCCESS, "open form %u -> %08lx", i, (unsigned long)status);
        if (status == STATUS_SUCCESS)
            NtClose(handle);
    }
}

static void test_create(void)
{
    struct afd_create_params create;
    struct afd_get_info_params info;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    NTSTATUS status;

    /* The full ws2_32 shape via the helper. */
    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* WINE_GET_INFO reads the triple back (getsockopt SO_PROTOCOL_INFOW's
     * substrate, socket.c ws_protocol_info). */
    memset(&info, 0xcc, sizeof(info));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_GET_INFO, NULL, 0,
                                   &info, sizeof(info));
    ok(status == STATUS_SUCCESS, "get info -> %08lx", (unsigned long)status);
    ok(info.family == AF_INET, "family %d", info.family);
    ok(info.type == SOCK_STREAM, "type %d", info.type);
    ok(info.protocol == IPPROTO_TCP, "protocol %d", info.protocol);

    /* A short params buffer refuses without becoming a socket. */
    NtClose(s);
    status = afd_open(&s, FALSE);
    ok(status == STATUS_SUCCESS, "reopen -> %08lx", (unsigned long)status);
    memset(&create, 0, sizeof(create));
    create.family = AF_INET;
    create.type = SOCK_STREAM;
    create.protocol = IPPROTO_TCP;
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_CREATE, &create,
                                   sizeof(create) - 1, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "short create -> %08lx", (unsigned long)status);
    NtClose(s);
}

static void test_device_type(void)
{
    FILE_FS_DEVICE_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    memset(&info, 0xcc, sizeof(info));
    status = NtQueryVolumeInformationFile(s, &iosb, &info, sizeof(info), FileFsDeviceInformation);
    ok(status == STATUS_SUCCESS, "device info -> %08lx", (unsigned long)status);
    /* Sockets report FILE_DEVICE_NAMED_PIPE (measured on the oracle) —
     * which is exactly why kernelbase's GetFileType answers
     * FILE_TYPE_PIPE for a socket handle (dlls/kernelbase/file.c). */
    ok(info.DeviceType == FILE_DEVICE_NAMED_PIPE, "DeviceType %08lx",
       (unsigned long)info.DeviceType);

    NtClose(s);
}

START_TEST(afd_open)
{
    test_device_opens();
    test_create();
    test_device_type();
}
