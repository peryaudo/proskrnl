/*
 * sem_nsi/nsi_open.c — \Device\Nsi opens: the nsi.dll shape and the name
 * forms around it.
 *
 * nsi.dll reaches the device exactly once, as CreateFileW(L"\\\\.\\Nsi", 0,
 * FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL)
 * (dlls/nsi/nsi.c get_nsi_device) — the \??\Nsi symbolic link into
 * \Device\Nsi. Both spellings must open, and the handle must answer an
 * ioctl (a handle that opens but refuses the dialect is the GetFileType
 * trap of sem_net/afd_open.c in a new coat).
 */
#include "util.h"

static void test_open_forms(void)
{
    static const void *names[] = {W("\\Device\\Nsi"), W("\\??\\Nsi"), W("\\Device\\Nsi\\")};
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
        status = NtOpenFile(&handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
        ok(status == STATUS_SUCCESS, "open form %u -> %08lx", i, (unsigned long)status);
        if (status == STATUS_SUCCESS)
            NtClose(handle);
    }

    /* A trailing NAME refuses — unlike \Device\Afd, which swallows any
     * trailing path (sem_net/afd_open.c), \Device\Nsi resolves only
     * itself and the bare trailing backslash. */
    init_ustr(&name, W("\\Device\\Nsi\\foobar"));
    init_attr(&attr, NULL, &name, 0);
    handle = NULL;
    status = NtOpenFile(&handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "trailing name -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
        NtClose(handle);

    /* GENERIC_READ|GENERIC_WRITE also opens: the device carries no
     * access-mask policy of its own. */
    init_ustr(&name, W("\\Device\\Nsi"));
    init_attr(&attr, NULL, &name, 0);
    handle = NULL;
    status = NtOpenFile(&handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    ok(status == STATUS_SUCCESS, "rw open -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
        NtClose(handle);
}

static void test_open_answers(void)
{
    HANDLE h = NULL;
    UINT count = 0;
    NTSTATUS status;

    status = nsi_open(&h);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;

    /* The handle serves the dialect: the ifinfo count probe answers at
     * least one interface (a machine with no loopback row is not a
     * machine either runner produces). */
    status = nsi_count(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &count);
    ok(status == STATUS_SUCCESS, "count probe -> %08lx", (unsigned long)status);
    ok(count >= 1, "ifinfo count %u", count);

    NtClose(h);
}

START_TEST(nsi_open)
{
    test_open_forms();
    test_open_answers();
}
