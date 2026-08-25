/*
 * sem_console/subsystem_gate.c — the console-at-startup decision is the
 * CHILD image's subsystem field, applied in the child (M11).
 *
 * The operative spec is kernelbase: CreateProcess hands any non-detached
 * child of a console-less parent the CONSOLE_HANDLE_ALLOC sentinel,
 * subsystem-blind (dlls/kernelbase/process.c 189-204); the CHILD's
 * init_console then allocates a console only when its own PE header says
 * IMAGE_SUBSYSTEM_WINDOWS_CUI (dlls/kernelbase/console.c 2391-2398). So a
 * CUI child arrives with a live console it allocated itself, and a GUI
 * child (tests/ntapi/dll/conprobe_gui.c, linked --subsystem,windows)
 * arrives with no console at all — no handle, no window, no binding. The
 * gate has a second, create-time half: the startup info hands the console
 * to the child ONLY when the child image's subsystem is CUI
 * (dlls/ntdll/unix/env.c create_startup_info 2164-2165), so a GUI child
 * of a console-ATTACHED parent gets no console either — measured here,
 * not assumed.
 *
 * conprobe_gui.exe reports the same bit protocol from the GUI side: it is
 * baked at C:\ (not under C:\ntapi, so the proskrnl sweep never grades it
 * as a test — the m9_smoke.exe arrangement) and built beside the test
 * .exes for the oracle.
 */
#include "util.h"

/* CUI self-re-exec child bits. */
#define SG_CUI_HANDLE 0x01 /* ConsoleHandle real (AllocConsole ran)  */
#define SG_CUI_STDOUT 0x02 /* stdout is a handle                     */
#define SG_CUI_BOUND  0x04 /* absolute Input open works              */
#define SG_CUI_ALL    0x07

/* conprobe_gui.exe bits (mirrored in tests/ntapi/dll/conprobe_gui.c). */
#define SG_GUI_NULL     0x01 /* ConsoleHandle == NULL                */
#define SG_GUI_SENTINEL 0x02 /* an ALLOC sentinel survived (never)   */
#define SG_GUI_WINDOW   0x04 /* GetConsoleWindow() != NULL           */
#define SG_GUI_BOUND    0x08 /* absolute Input open works            */

static void cui_child_main(void)
{
    DWORD code = CHILD_BASE;
    HANDLE console = console_handle(), input = NULL;

    if (console != NULL && !is_console_sentinel(console))
        code |= SG_CUI_HANDLE;
    if (GetStdHandle(STD_OUTPUT_HANDLE) != NULL)
        code |= SG_CUI_STDOUT;
    if (open_input(&input) == STATUS_SUCCESS)
        code |= SG_CUI_BOUND;
    close_if(input);
    ExitProcess(code);
}

/* The GUI probe lives beside this .exe under the oracle and at C:\ on
 * proskrnl (the runner-side probe is the documented harness contract —
 * ntapi.h's header comment). */
static void probe_cmdline(WCHAR *out, const WCHAR *self)
{
    int n = 0;
    out[n++] = '"';
    if (ntapi_ctx.on_proskrnl)
    {
        static const WCHAR baked[] = W("C:\\conprobe_gui.exe");
        for (int i = 0; baked[i]; i++)
            out[n++] = baked[i];
    }
    else
    {
        int last = 0;
        for (int i = 0; self[i]; i++)
            if (self[i] == '\\')
                last = i;
        for (int i = 0; i <= last; i++)
            out[n++] = self[i];
        static const WCHAR name[] = W("conprobe_gui.exe");
        for (int i = 0; name[i]; i++)
            out[n++] = name[i];
    }
    out[n++] = '"';
    out[n] = 0;
}

START_TEST(subsystem_gate)
{
    const WCHAR *cl = GetCommandLineW();
    if (wstr_find(cl, W("--cui-child")))
        cui_child_main(); /* never returns */

    WCHAR self[512], cmdline[600];
    DWORD code = 0;
    BOOL alloced;

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    FreeConsole();

    /* --- a CUI child of a console-less parent allocates its own console --- */
    build_cmdline(cmdline, self, W("--cui-child"));
    ok(run_child(cmdline, 0, &code), "cui child ran");
    todo_proskrnl
    {
        ok(code == (CHILD_BASE | SG_CUI_ALL), "cui child observed %04lx, expected %04x",
           (unsigned long)code, CHILD_BASE | SG_CUI_ALL);
    }

    /* --- a GUI child of a console-less parent gets NO console at all ------ */
    probe_cmdline(cmdline, self);
    ok(run_child(cmdline, 0, &code), "gui probe ran");
    todo_proskrnl
    {
        ok(code == (CHILD_BASE | SG_GUI_NULL), "gui probe observed %04lx, expected %04x",
           (unsigned long)code, CHILD_BASE | SG_GUI_NULL);
    }

    /* --- a GUI child of a console-ATTACHED parent STILL gets no console ---
     * (the create-time half of the gate: ntdll create_startup_info withholds
     * the console from a non-CUI child). */
    alloced = AllocConsole();
    todo_proskrnl
    {
        ok(alloced, "AllocConsole -> %lu", (unsigned long)GetLastError());
    }
    probe_cmdline(cmdline, self);
    ok(run_child(cmdline, 0, &code), "bound gui probe ran");
    todo_proskrnl
    {
        ok(code == (CHILD_BASE | SG_GUI_NULL), "bound gui probe observed %04lx, expected %04x",
           (unsigned long)code, CHILD_BASE | SG_GUI_NULL);
    }

    FreeConsole();
}
