/*
 * sem_console/bind_pid_adopt.c — IOCTL_CONDRV_BIND_PID adopts another process's
 * console, with wineserver's exact refusals (M11).
 *
 * The operative spec is wineserver's console_connection_ioctl BIND_PID arm
 * (third_party/wine server/console.c): an already-bound caller refuses
 * STATUS_INVALID_HANDLE; a target with no console refuses
 * STATUS_ACCESS_DENIED; ATTACH_PARENT_PROCESS resolves to the caller's
 * parent. This is AttachConsole's whole kernel surface
 * (dlls/kernelbase/console.c 368-401).
 *
 * Same silent-child / exit-code-bitmask protocol as sem_ps/inherit.c: the
 * parent allocates a console the stock way and the DETACHED (console-less)
 * child does every probe, reporting bits.
 */
#include "util.h"

#define BP_CONN_OPEN        0x01 /* absolute connection opened while unbound  */
#define BP_SELF_DENIED      0x02 /* bind to console-less self -> ACCESS_DENIED */
#define BP_PARENT_BOUND     0x04 /* bind to parent's console succeeded         */
#define BP_INPUT_OPEN       0x08 /* input open works once bound                */
#define BP_REBIND_REFUSED   0x10 /* second bind -> INVALID_HANDLE (bound now)  */
#define BP_REFERENCE_OPEN   0x20 /* Reference under the connection -> console  */
#define BP_UNBOUND_ON_CLOSE 0x40 /* closing the connection unbinds            */
#define BP_ATTACH_PARENT    0x80 /* ATTACH_PARENT_PROCESS resolves to parent   */
#define BP_ALL              0xff

static void child_main(const WCHAR *cmdline)
{
    DWORD code = CHILD_BASE;
    DWORD parent_pid = parse_dword(wstr_find(cmdline, W("--bind ")) + 7);
    HANDLE conn = NULL, conn2 = NULL, input = NULL, console = NULL;

    if (open_connection(&conn, NULL) == STATUS_SUCCESS)
        code |= BP_CONN_OPEN;
    if (bind_pid(conn, GetCurrentProcessId()) == STATUS_ACCESS_DENIED)
        code |= BP_SELF_DENIED;
    if (bind_pid(conn, parent_pid) == STATUS_SUCCESS)
        code |= BP_PARENT_BOUND;
    if (open_input(&input) == STATUS_SUCCESS)
        code |= BP_INPUT_OPEN;
    if (bind_pid(conn, parent_pid) == STATUS_INVALID_HANDLE)
        code |= BP_REBIND_REFUSED;
    if (open_reference(&console, conn) == STATUS_SUCCESS)
        code |= BP_REFERENCE_OPEN;
    close_if(input);
    close_if(console);
    close_if(conn);
    input = NULL;
    if (open_input(&input) == STATUS_INVALID_HANDLE)
        code |= BP_UNBOUND_ON_CLOSE;
    close_if(input);
    if (open_connection(&conn2, NULL) == STATUS_SUCCESS &&
        bind_pid(conn2, ATTACH_PARENT_PROCESS) == STATUS_SUCCESS)
        code |= BP_ATTACH_PARENT;
    close_if(conn2);
    ExitProcess(code);
}

START_TEST(bind_pid_adopt)
{
    const WCHAR *cl = GetCommandLineW();
    if (wstr_find(cl, W("--bind ")))
        child_main(cl); /* never returns */

    WCHAR self[512], cmdline[600];
    DWORD code = 0;
    BOOL alloced;

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    FreeConsole();

    /* The parent needs a console for the child to adopt: the stock
     * AllocConsole (conhost spawn and all). */
    alloced = AllocConsole();
    ok(alloced, "AllocConsole -> %lu", (unsigned long)GetLastError());

    int n = build_cmdline(cmdline, self, W("--bind "));
    n += emit_hex(cmdline + n, GetCurrentProcessId());
    cmdline[n] = 0;
    ok(run_child(cmdline, DETACHED_PROCESS, &code), "child ran");
    ok(code == (CHILD_BASE | BP_ALL), "child observed %04lx, expected %04x",
       (unsigned long)code, CHILD_BASE | BP_ALL);

    FreeConsole();
}
