/*
 * tests/ntapi/dll/prshelper.c — the search-order probe DLL (M10).
 *
 * Baked BESIDE the test .exes (C:\ntapi\prshelper.dll on proskrnl; the
 * build directory under the oracle), never in system32: sem_ps/dll_load.c
 * loading it by bare name proves ntdll resolves the application directory
 * first (get_dll_load_path). CRT-less like every harness binary; not a
 * test itself (tests/run/run.sh excludes this directory from the sweep).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllexport) int __cdecl prs_helper_value(void)
{
    return 42;
}

BOOL WINAPI DllMainCRTStartup(HINSTANCE instance, DWORD reason, void *reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
