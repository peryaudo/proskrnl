/*
 * sem_ps/dll_load.c — the M10 DLL set loads + DLL search order.
 *
 * cmd.exe and any MSVC-built CUI app import msvcrt/ucrtbase (the CRT),
 * advapi32+sechost (registry), rpcrt4 and version — all baked at
 * C:\windows\system32 (Makefile WINFILES). The loader running them is the
 * PE ntdll itself on both runners (LdrLoadDll + get_dll_load_path); the
 * kernel's contribution is only correct file semantics, which is exactly
 * why this is a boundary test: every attach walks
 * open/map/SEC_IMAGE/registry paths. Search order pinned: a bare name
 * resolves from the application directory first, and an explicit
 * system32 path works.
 */
#include "util.h"

START_TEST(dll_load)
{
    /* --- the CRTs ---------------------------------------------------------- */
    HMODULE msvcrt = LoadLibraryW(L"msvcrt.dll");
    ok(msvcrt != NULL, "msvcrt.dll -> %lu", (unsigned long)GetLastError());
    if (msvcrt)
    {
        typedef int(__cdecl * snwprintf_fn)(WCHAR *, SIZE_T, const WCHAR *, ...);
        snwprintf_fn snw = (snwprintf_fn)(void *)GetProcAddress(msvcrt, "_snwprintf");
        ok(snw != NULL, "_snwprintf missing");
        if (snw)
        {
            WCHAR buffer[32];
            int n = snw(buffer, 32, L"%d-%s", 7, L"ok");
            ok(n == 4 && buffer[0] == '7', "msvcrt _snwprintf produced %d", n);
        }
    }
    HMODULE ucrt = LoadLibraryW(L"ucrtbase.dll");
    ok(ucrt != NULL, "ucrtbase.dll -> %lu", (unsigned long)GetLastError());

    /* --- advapi32 (drags sechost): a real registry round-trip -------------- */
    HMODULE advapi = LoadLibraryW(L"advapi32.dll");
    ok(advapi != NULL, "advapi32.dll -> %lu", (unsigned long)GetLastError());
    if (advapi)
    {
        typedef LONG(WINAPI * create_fn)(HKEY, const WCHAR *, DWORD, WCHAR *, DWORD, DWORD, void *,
                                         HKEY *, DWORD *);
        typedef LONG(WINAPI * close_fn)(HKEY);
        typedef LONG(WINAPI * delete_fn)(HKEY, const WCHAR *);
        create_fn reg_create = (create_fn)(void *)GetProcAddress(advapi, "RegCreateKeyExW");
        close_fn reg_close = (close_fn)(void *)GetProcAddress(advapi, "RegCloseKey");
        delete_fn reg_delete = (delete_fn)(void *)GetProcAddress(advapi, "RegDeleteKeyW");
        ok(reg_create != NULL && reg_close != NULL && reg_delete != NULL,
           "advapi32 registry exports missing");
        if (reg_create && reg_close && reg_delete)
        {
            HKEY key = NULL;
            LONG r = reg_create((HKEY)(ULONG_PTR)0x80000002 /* HKEY_LOCAL_MACHINE */,
                                L"Software\\prstest-dll-load", 0, NULL, 0,
                                0x000F003F /* KEY_ALL_ACCESS */, NULL, &key, NULL);
            ok(r == 0, "RegCreateKeyExW -> %ld", (long)r);
            if (r == 0)
            {
                reg_close(key);
                reg_delete((HKEY)(ULONG_PTR)0x80000002, L"Software\\prstest-dll-load");
            }
        }
    }

    /* --- rpcrt4 + version: attach and resolve ------------------------------ */
    HMODULE rpcrt4 = LoadLibraryW(L"rpcrt4.dll");
    ok(rpcrt4 != NULL, "rpcrt4.dll -> %lu", (unsigned long)GetLastError());
    ok(rpcrt4 == NULL || GetProcAddress(rpcrt4, "RpcStringFreeW") != NULL,
       "RpcStringFreeW missing");
    HMODULE version = LoadLibraryW(L"version.dll");
    ok(version != NULL, "version.dll -> %lu", (unsigned long)GetLastError());
    ok(version == NULL || GetProcAddress(version, "VerQueryValueW") != NULL,
       "VerQueryValueW missing");

    /* --- search order: bare name resolves from the application directory
     * first (ntdll get_dll_load_path) ------------------------------------- */
    HMODULE helper = LoadLibraryW(L"prshelper.dll");
    ok(helper != NULL, "prshelper.dll by bare name -> %lu", (unsigned long)GetLastError());
    if (helper)
    {
        typedef int(__cdecl * value_fn)(void);
        value_fn value = (value_fn)(void *)GetProcAddress(helper, "prs_helper_value");
        ok(value != NULL, "prs_helper_value missing");
        ok(value == NULL || value() == 42, "helper answered wrong");
        FreeLibrary(helper);
    }

    /* An explicit system32 path also works. */
    HMODULE by_path = LoadLibraryW(L"C:\\windows\\system32\\msvcrt.dll");
    ok(by_path != NULL, "msvcrt by system32 path -> %lu", (unsigned long)GetLastError());
    ok(by_path == msvcrt, "same-module identity (loader path canonicalization)");
}
