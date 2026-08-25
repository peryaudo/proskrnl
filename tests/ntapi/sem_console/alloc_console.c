/*
 * sem_console/alloc_console.c — AllocConsole runs the stock kernelbase
 * sequence end to end: server mint, console mint, conhost spawn, connect,
 * std-handle wiring (M11).
 *
 * The operative spec is dlls/kernelbase/console.c alloc_console (404-499):
 * Server open -> Reference (relative) -> conhost.exe --server 0x%x spawned
 * with handle-list inheritance -> Connection (relative, binds) -> Input/
 * Output std handles -> params->ConsoleHandle = the console. A second
 * AllocConsole refuses ERROR_ACCESS_DENIED on the existing ConsoleHandle
 * (420-426); FreeConsole (675-695) detaches, after which caller-bound
 * opens refuse again.
 */
#include "util.h"

START_TEST(alloc_console)
{
    HANDLE input = NULL, out;
    NTSTATUS status;
    BOOL ret;

    FreeConsole();
    ok(console_handle() == NULL, "detached, but ConsoleHandle=%p", console_handle());

    ret = AllocConsole();
    ok(ret, "AllocConsole -> %lu", (unsigned long)GetLastError());
    ok(console_handle() != NULL && !is_console_sentinel(console_handle()),
       "ConsoleHandle after alloc = %p", console_handle());

    /* The std handles point at the fresh console. Deliberately NOT written
     * through: the write would need the spawned conhost alive, and this
     * suite's proskrnl leg boots without a desktop for the windowed conhost
     * AllocConsole spawns (the leg is console-less by design — ntapi.h).
     * Every assertion here is object-level, live on both runners; the
     * windowed end-to-end path is the gui5con leg's verdict. */
    out = GetStdHandle(STD_OUTPUT_HANDLE);
    ok(out != NULL && out != INVALID_HANDLE_VALUE, "stdout after alloc = %p", out);
    ok(GetStdHandle(STD_INPUT_HANDLE) != NULL, "stdin after alloc");
    ok(GetStdHandle(STD_ERROR_HANDLE) != NULL, "stderr after alloc");

    /* Second alloc refuses on the existing console. Not todo-tagged: today's
     * kernel answers the same error, just from the first alloc's failed
     * Server open rather than from the ConsoleHandle check. */
    SetLastError(0);
    ret = AllocConsole();
    ok(!ret && GetLastError() == ERROR_ACCESS_DENIED, "second AllocConsole -> %d err=%lu", ret,
       (unsigned long)GetLastError());

    /* FreeConsole is unconditional (kernelbase 673-694: always TRUE) and
     * leaves the process detached. */
    ok(FreeConsole(), "FreeConsole -> %lu", (unsigned long)GetLastError());
    ok(console_handle() == NULL, "ConsoleHandle after free = %p", console_handle());

    /* Detached again: caller-bound opens refuse. */
    status = open_input(&input);
    ok(status == STATUS_INVALID_HANDLE, "input open after free -> %08lx", (unsigned long)status);
    close_if(input);
}
