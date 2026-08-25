/*
 * sem_console/server_multi.c — every \Device\ConDrv\Server open mints its
 * own console server (M11).
 *
 * The operative spec is wineserver's console_device_lookup_name "Server"
 * arm (third_party/wine server/console.c create_console_server): a server
 * open is an unconditional mint — a second open is a second server, not a
 * conflict — and closing one server never disturbs another. This is the
 * exact shape kernelbase's alloc_console starts with, and the shape a
 * one-console kernel refuses with STATUS_ACCESS_DENIED.
 */
#include "util.h"

START_TEST(server_multi)
{
    HANDLE s1 = NULL, s2 = NULL, s3 = NULL;
    NTSTATUS status;

    /* Normalize: this process never binds a console in this test. */
    FreeConsole();

    status = open_server(&s1);
    ok(status == STATUS_SUCCESS, "first server open -> %08lx", (unsigned long)status);

    /* The second, concurrent server: a fresh console server of its own. */
    status = open_server(&s2);
    ok(status == STATUS_SUCCESS, "second server open -> %08lx", (unsigned long)status);

    /* Closing the first does not invalidate the second, and a third open
     * mints again — no slot is being recycled. */
    close_if(s1);
    s1 = NULL;
    status = open_server(&s3);
    ok(status == STATUS_SUCCESS, "third server open -> %08lx", (unsigned long)status);

    close_if(s2);
    close_if(s3);
    close_if(s1);
}
