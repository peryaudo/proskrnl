/* tests/cui/hello32.c — the WOW64 milestone's acceptance client (docs/02:
 * "Done when: a 32-bit CUI app runs").
 *
 * An ordinary 32-bit Win32 console program: built by the i686 mingw cross
 * against the SAME Wine import libraries the 64-bit CUI clients use, with a
 * full CRT above them. Nothing here knows it is running under WOW64 — that
 * is the point. It reaches the kernel only the way any Win32 app does, and
 * every syscall it makes has travelled guest -> wow64cpu -> wow64.dll ->
 * the 64-bit ntdll before arriving.
 *
 * It prints one marker line the run.sh leg greps for, then reports what it
 * believes about itself so a WRONG answer is visible rather than silent:
 * IsWow64Process must be true, and the pointer width must be 4.
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);

    printf("hello32: pointer=%u wow64=%d\n", (unsigned)sizeof(void *), wow64 ? 1 : 0);
    fflush(stdout);

    if (sizeof(void *) != 4)
    {
        printf("hello32: FAIL not a 32-bit process\n");
        fflush(stdout);
        return 2;
    }
    if (!wow64)
    {
        printf("hello32: FAIL IsWow64Process says no\n");
        fflush(stdout);
        return 3;
    }

    /* A heap round trip and a Win32 call with a real return value, so the
     * marker cannot be printed by a process that died right after entry. */
    char *buffer = HeapAlloc(GetProcessHeap(), 0, 64);
    if (buffer == NULL)
    {
        printf("hello32: FAIL HeapAlloc\n");
        fflush(stdout);
        return 4;
    }
    DWORD length = GetCurrentDirectoryA(64, buffer);
    HeapFree(GetProcessHeap(), 0, buffer);
    if (length == 0)
    {
        printf("hello32: FAIL GetCurrentDirectoryA\n");
        fflush(stdout);
        return 5;
    }

    printf("hello32: OK\n");
    fflush(stdout);
    return 0;
}
