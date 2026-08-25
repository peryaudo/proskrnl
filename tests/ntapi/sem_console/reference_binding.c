/*
 * sem_console/reference_binding.c — "Reference" relative to a server mints
 * that server's console, exactly once; minting is not binding (M11).
 *
 * The operative spec is wineserver's console_server_lookup_name
 * (third_party/wine server/console.c): the first relative "Reference" open
 * creates THE console for that server (and its initial screen buffer); a
 * second one answers STATUS_INVALID_HANDLE; each server minted its own
 * console. Minting leaves the opener UNBOUND — Input opens still refuse —
 * because binding is the Connection open's job (console_lookup_name), not
 * the Reference's.
 */
#include "util.h"

START_TEST(reference_binding)
{
    HANDLE s1 = NULL, s2 = NULL, c1 = NULL, c1b = NULL, c2 = NULL, input = NULL;
    NTSTATUS status;

    FreeConsole();

    todo_proskrnl
    {
        status = open_server(&s1);
        ok(status == STATUS_SUCCESS, "server 1 open -> %08lx", (unsigned long)status);

        status = open_reference(&c1, s1);
        ok(status == STATUS_SUCCESS, "reference mints console 1 -> %08lx", (unsigned long)status);

        /* One console per server: the second Reference refuses. */
        status = open_reference(&c1b, s1);
        ok(status == STATUS_INVALID_HANDLE, "second reference on server 1 -> %08lx",
           (unsigned long)status);

        /* An independent server mints an independent console. */
        status = open_server(&s2);
        ok(status == STATUS_SUCCESS, "server 2 open -> %08lx", (unsigned long)status);
        status = open_reference(&c2, s2);
        ok(status == STATUS_SUCCESS, "reference mints console 2 -> %08lx", (unsigned long)status);
    }

    /* Minting bound nothing: this process still has no console, so the
     * caller-binding Input open refuses (wineserver console_device_lookup_name
     * "Input": no current->process->console -> STATUS_INVALID_HANDLE). */
    todo_proskrnl
    {
        status = open_input(&input);
        ok(status == STATUS_INVALID_HANDLE, "input open while unbound -> %08lx",
           (unsigned long)status);
    }

    close_if(input);
    close_if(c1b);
    close_if(c1);
    close_if(c2);
    close_if(s1);
    close_if(s2);
}
