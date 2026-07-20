/*
 * tests/cui/hello_crt.c — the "off-the-shelf CUI app" stand-in (M10).
 *
 * Built with the PLAIN mingw toolchain and its FULL CRT (no -nostdlib, no
 * Wine import libraries): the produced .exe imports msvcrt.dll +
 * kernel32.dll and runs third-party CRT startup (argv/env construction,
 * stdio buffering over GetFileType) against the baked Wine userland —
 * the same observable class as an MSVC-built binary, produced by a
 * toolchain this repo does not control. The console acceptance runs it
 * from cmd.exe and asserts the output and the %errorlevel%.
 */
#include <stdio.h>

int main(void)
{
    printf("hello-crt %d\n", 6 * 7);
    fflush(stdout);
    return 7;
}
