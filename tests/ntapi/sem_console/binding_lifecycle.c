/*
 * sem_console/binding_lifecycle.c — a process's console binding is made by
 * the Connection open, routed at call time, and unmade by the connection
 * handle's close (M11).
 *
 * The operative spec is wineserver (third_party/wine server/console.c):
 *   - Input/Output/ScreenBuffer opens refuse STATUS_INVALID_HANDLE while
 *     the CALLER is unbound (console_device_lookup_name);
 *   - an absolute Connection open does not bind (create_console_connection
 *     with a NULL console) — but refuses STATUS_ACCESS_DENIED if the caller
 *     is already bound;
 *   - "Reference" relative to a connection answers the caller's BOUND
 *     console, so an unbound caller gets STATUS_INVALID_HANDLE
 *     (console_connection_lookup_name);
 *   - "Connection" relative to a console binds the caller
 *     (console_lookup_name -> create_console_connection(console));
 *   - I/O on an Input handle resolves current->process->console at CALL
 *     time (console_input_ioctl), so a handle opened while bound answers
 *     STATUS_INVALID_HANDLE after the unbind;
 *   - closing the connection handle unbinds the closing process
 *     (console_connection_close_handle).
 */
#include "util.h"

START_TEST(binding_lifecycle)
{
    HANDLE s = NULL, console = NULL, conn0 = NULL, conn = NULL, conn2 = NULL;
    HANDLE probe = NULL, input = NULL, stale = NULL;
    ULONG mode = 0;
    NTSTATUS status;

    FreeConsole();

    /* --- unbound refusals -------------------------------------------------- */
    status = open_input(&probe);
    ok(status == STATUS_INVALID_HANDLE, "unbound input open -> %08lx", (unsigned long)status);
    close_if(probe);
    probe = NULL;

    status = open_output(&probe);
    ok(status == STATUS_INVALID_HANDLE, "unbound output open -> %08lx", (unsigned long)status);
    close_if(probe);
    probe = NULL;

    status = open_screen_buffer(&probe);
    ok(status == STATUS_INVALID_HANDLE, "unbound screen-buffer open -> %08lx",
       (unsigned long)status);
    close_if(probe);
    probe = NULL;

    /* An absolute Connection opens fine unbound — and binds nothing. */
    status = open_connection(&conn0, NULL);
    ok(status == STATUS_SUCCESS, "absolute connection open -> %08lx", (unsigned long)status);
    status = open_reference(&probe, conn0);
    ok(status == STATUS_INVALID_HANDLE, "reference under unbound connection -> %08lx",
       (unsigned long)status);
    close_if(probe);
    probe = NULL;
    close_if(conn0);
    conn0 = NULL;

    /* --- mint, bind, use --------------------------------------------------- */
    status = open_server(&s);
    ok(status == STATUS_SUCCESS, "server open -> %08lx", (unsigned long)status);
    status = open_reference(&console, s);
    ok(status == STATUS_SUCCESS, "reference open -> %08lx", (unsigned long)status);

    /* Minting still is not binding. */
    status = open_input(&probe);
    ok(status == STATUS_INVALID_HANDLE, "input open after mint, before bind -> %08lx",
       (unsigned long)status);
    close_if(probe);
    probe = NULL;

    /* The bind-and-use half needs the minted console above; the guard keeps
     * a failed mint from turning open_connection's null root into the
     * ABSOLUTE open, which would assert a different rule than the one this
     * section is about. */
    if (console != NULL)
    {
        /* "Connection" relative to the console binds this process. */
        status = open_connection(&conn, console);
        ok(status == STATUS_SUCCESS, "binding connection open -> %08lx", (unsigned long)status);

        status = open_input(&input);
        ok(status == STATUS_SUCCESS, "input open while bound -> %08lx", (unsigned long)status);

        /* A second connection while bound refuses (wineserver
         * create_console_connection's ACCESS_DENIED arm). */
        status = open_connection(&conn2, NULL);
        ok(status == STATUS_ACCESS_DENIED, "absolute connection while bound -> %08lx",
           (unsigned long)status);
        close_if(conn2);
        conn2 = NULL;

        /* --- unbind -------------------------------------------------------- */
        close_if(conn);
        conn = NULL;

        status = open_input(&stale);
        ok(status == STATUS_INVALID_HANDLE, "input open after unbind -> %08lx",
           (unsigned long)status);
        close_if(stale);
        stale = NULL;

        /* The Input handle opened while bound routes through the CURRENT
         * binding, so it refuses now too (fails at the binding check, before
         * anything could wait on the console's — unserved — server). */
        status = get_mode(input, &mode);
        ok(status == STATUS_INVALID_HANDLE, "stale input handle ioctl -> %08lx",
           (unsigned long)status);
    }

    close_if(input);
    close_if(console);
    close_if(s);
}
