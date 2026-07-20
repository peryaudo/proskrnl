/*
 * tests/cui/upcase.c — the pipe-transform stand-in (M10).
 *
 * Same full-mingw-CRT build as hello_crt.c. cmd.exe pipes `type` output
 * through it (`type file | upcase`): stdin arrives on an inherited
 * anonymous pipe, stdout goes back to the console — the transform proves
 * the data crossed the pipe (the typed command line contains only
 * lowercase, so the uppercased text can only have come through here).
 */
#include <ctype.h>
#include <stdio.h>

int main(void)
{
    int c;
    while ((c = getchar()) != EOF)
        putchar(toupper(c));
    fflush(stdout);
    return 0;
}
