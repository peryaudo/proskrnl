/* tests/clients/m9_echo.c — the M9 interactive-echo client (docs/02 "Done when":
 * input typed into the serial console echoes through conhost).
 *
 * Baked only into the console-mode image (make console-img / run.sh
 * console): it BLOCKS on console input, which the plain headless loop must
 * never do. The runner (tests/run/console_expect.py) waits for the ready
 * marker, types "ping\r" into the QEMU serial socket, watches conhost's
 * line-discipline echo come back, and then sees the cooked line arrive
 * here through ReadFile on the console input handle.
 *
 * User clients follow the test-code conventions (Wine style, docs/15
 * exemption). Exit code 0 = PASS.
 */
#include <windows.h>

static DWORD out_write(const char *text, DWORD length)
{
    DWORD written = 0;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), text, length, &written, NULL);
    return written;
}

void m9_start(void *peb)
{
    char line[64];
    DWORD count = 0;
    static const char ready[] = "m9_echo: ready\r\n";
    static const char got[] = "m9_echo: got ";

    (void)peb;
    out_write(ready, sizeof(ready) - 1);

    /* The cooked read: conhost's line discipline echoes each keystroke to
     * the tty (the serial wire) and completes on Enter. */
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), line, sizeof(line) - 1, &count, NULL))
        ExitProcess(1);
    while (count && (line[count - 1] == '\r' || line[count - 1] == '\n'))
        count--;
    line[count] = 0;

    out_write(got, sizeof(got) - 1);
    out_write(line, count);
    out_write("\r\n", 2);

    /* The runner types "ping": the cooked line must be exactly that. The
     * kernel's [KTEST] module verdict carries this exit code, which is what
     * console_expect.py asserts — conhost's screen-diff renderer does not
     * replay literal bytes, so the wire text itself is not the contract. */
    if (count != 4 || line[0] != 'p' || line[1] != 'i' || line[2] != 'n' || line[3] != 'g')
        ExitProcess(2);
    ExitProcess(0);
}
