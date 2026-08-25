/*
 * sem_console/inherit_console.c — a child of a console-attached parent
 * arrives bound to the parent's console, through a real (non-sentinel)
 * ConsoleHandle (M11).
 *
 * The operative spec is kernelbase's create-time handoff
 * (dlls/kernelbase/process.c: the child's params->ConsoleHandle is the
 * parent's) plus the child-side init_console (dlls/kernelbase/console.c
 * 2400-2407): a real inherited handle means "open Connection relative to
 * it" — which binds the child to that console (wineserver
 * console_lookup_name). The observable: the child's ConsoleHandle is a
 * real handle, and caller-bound opens (Input) work immediately.
 */
#include "util.h"

#define IC_HANDLE_REAL 0x01 /* ConsoleHandle != NULL and not a sentinel */
#define IC_BOUND       0x02 /* absolute Input open works               */
#define IC_ALL         0x03

static void child_main(void)
{
    DWORD code = CHILD_BASE;
    HANDLE console = console_handle(), input = NULL;

    if (console != NULL && !is_console_sentinel(console))
        code |= IC_HANDLE_REAL;
    if (open_input(&input) == STATUS_SUCCESS)
        code |= IC_BOUND;
    close_if(input);
    ExitProcess(code);
}

START_TEST(inherit_console)
{
    const WCHAR *cl = GetCommandLineW();
    if (wstr_find(cl, W("--con-child")))
        child_main(); /* never returns */

    WCHAR self[512], cmdline[600];
    DWORD code = 0;
    BOOL alloced;

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    FreeConsole();
    alloced = AllocConsole();
    ok(alloced, "AllocConsole -> %lu", (unsigned long)GetLastError());

    /* Default flags: the child inherits the parent's ConsoleHandle (no
     * sentinel is minted — dlls/kernelbase/process.c's else-branch). */
    build_cmdline(cmdline, self, W("--con-child"));
    ok(run_child(cmdline, 0, &code), "child ran");
    ok(code == (CHILD_BASE | IC_ALL), "child observed %04lx, expected %04x",
       (unsigned long)code, CHILD_BASE | IC_ALL);

    FreeConsole();
}
