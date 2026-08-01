/* tests/cui/regtool.c — the CUI-7 acceptance's registry driver.
 *
 * The reg save/load round trip the milestone's "done when" names, driven
 * through the real advapi32 surface a third-party tool would use
 * (RegSaveKey/RegLoadKey/RegUnLoadKey ride NtSaveKey/NtLoadKey/NtUnloadKey;
 * wine's own reg.exe has no save/load subcommands at all). Subcommands are
 * one per console line so tests/run/console_expect.py can drive and verify
 * each phase; every marker carries content the typed command cannot supply.
 *
 *   seed      create HKLM\Software\PrskCui7 {num=42, str="cui7", sub\inner=7}
 *   save      SeBackupPrivilege + RegSaveKey -> C:\prsk7.hiv
 *   load      SeRestorePrivilege + RegLoadKey at HKLM\PrskCui7Load,
 *             verify the loaded values, RegUnLoadKey
 *   watch     RegNotifyChangeKeyValue armed, a set fires the event
 *   verify    (after reboot) the seeded key survived, and the saved hive
 *             file still loads with its content intact
 *   shutdown  SeShutdownPrivilege + NtShutdownSystem(ShutdownPowerOff)
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int enable_privilege(const char *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return 0;
    if (!LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid))
    {
        CloseHandle(token);
        return 0;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static int check_content(HKEY root, const char *path, const char *tag)
{
    HKEY key;
    DWORD num = 0, size = sizeof(num), type = 0;
    char sub[64];
    LONG rc = RegOpenKeyExA(root, path, 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS)
    {
        printf("%s-open-fail-%ld\n", tag, (long)rc);
        return 0;
    }
    rc = RegQueryValueExA(key, "num", NULL, &type, (BYTE *)&num, &size);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || num != 42)
    {
        printf("%s-num-fail\n", tag);
        RegCloseKey(key);
        return 0;
    }
    snprintf(sub, sizeof(sub), "%s\\sub", path);
    RegCloseKey(key);
    rc = RegOpenKeyExA(root, sub, 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS)
    {
        printf("%s-sub-fail\n", tag);
        return 0;
    }
    size = sizeof(num);
    num = 0;
    rc = RegQueryValueExA(key, "inner", NULL, &type, (BYTE *)&num, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || num != 7)
    {
        printf("%s-inner-fail\n", tag);
        return 0;
    }
    return 1;
}

static int do_seed(void)
{
    HKEY key, sub;
    DWORD value = 42, inner = 7;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\PrskCui7", 0, NULL, 0, KEY_ALL_ACCESS, NULL,
                        &key, NULL) != ERROR_SUCCESS)
        return 0;
    RegSetValueExA(key, "num", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    RegSetValueExA(key, "str", 0, REG_SZ, (const BYTE *)"cui7", 5);
    if (RegCreateKeyExA(key, "sub", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &sub, NULL) != ERROR_SUCCESS)
    {
        RegCloseKey(key);
        return 0;
    }
    RegSetValueExA(sub, "inner", 0, REG_DWORD, (const BYTE *)&inner, sizeof(inner));
    RegCloseKey(sub);
    RegCloseKey(key);
    return check_content(HKEY_LOCAL_MACHINE, "Software\\PrskCui7", "regtool-seed");
}

static int do_save(void)
{
    HKEY key;
    if (!enable_privilege("SeBackupPrivilege"))
        return 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\PrskCui7", 0, KEY_READ, &key) != ERROR_SUCCESS)
        return 0;
    DeleteFileA("C:\\prsk7.hiv");
    LONG rc = RegSaveKeyA(key, "C:\\prsk7.hiv", NULL);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS)
    {
        printf("regtool-save-rc-%ld\n", (long)rc);
        return 0;
    }
    return GetFileAttributesA("C:\\prsk7.hiv") != INVALID_FILE_ATTRIBUTES;
}

static int do_load(const char *tag)
{
    if (!enable_privilege("SeRestorePrivilege"))
        return 0;
    LONG rc = RegLoadKeyA(HKEY_LOCAL_MACHINE, "PrskCui7Load", "C:\\prsk7.hiv");
    if (rc != ERROR_SUCCESS)
    {
        printf("%s-load-rc-%ld\n", tag, (long)rc);
        return 0;
    }
    int ok = check_content(HKEY_LOCAL_MACHINE, "PrskCui7Load", tag);
    rc = RegUnLoadKeyA(HKEY_LOCAL_MACHINE, "PrskCui7Load");
    if (rc != ERROR_SUCCESS)
    {
        printf("%s-unload-rc-%ld\n", tag, (long)rc);
        return 0;
    }
    return ok;
}

static int do_watch(void)
{
    HKEY key;
    HANDLE event;
    DWORD value = 99;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\PrskCui7", 0, KEY_ALL_ACCESS, &key) !=
        ERROR_SUCCESS)
        return 0;
    event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (event == NULL)
    {
        RegCloseKey(key);
        return 0;
    }
    if (RegNotifyChangeKeyValue(key, TRUE, REG_NOTIFY_CHANGE_LAST_SET, event, TRUE) !=
        ERROR_SUCCESS)
    {
        CloseHandle(event);
        RegCloseKey(key);
        return 0;
    }
    RegSetValueExA(key, "poke", 0, REG_DWORD, (const BYTE *)&value, sizeof(value));
    DWORD wait = WaitForSingleObject(event, 5000);
    RegDeleteValueA(key, "poke");
    CloseHandle(event);
    RegCloseKey(key);
    return wait == WAIT_OBJECT_0;
}

typedef LONG NTAPI NtShutdownSystem_t(ULONG);

static int do_shutdown(void)
{
    NtShutdownSystem_t *shutdown = (NtShutdownSystem_t *)(void *)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtShutdownSystem");
    if (shutdown == NULL || !enable_privilege("SeShutdownPrivilege"))
        return 0;
    printf("regtool-shutdown-go\n");
    fflush(stdout);
    shutdown(2 /* ShutdownPowerOff */);
    /* Unreached on success. */
    printf("regtool-shutdown-returned\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd = argc > 1 ? argv[1] : "";
    int ok = 0;
    if (strcmp(cmd, "seed") == 0)
        ok = do_seed(), printf(ok ? "regtool-seed-ok\n" : "regtool-seed-FAIL\n");
    else if (strcmp(cmd, "save") == 0)
        ok = do_save(), printf(ok ? "regtool-save-ok\n" : "regtool-save-FAIL\n");
    else if (strcmp(cmd, "load") == 0)
        ok = do_load("regtool-loadchk"), printf(ok ? "regtool-load-ok\n" : "regtool-load-FAIL\n");
    else if (strcmp(cmd, "watch") == 0)
        ok = do_watch(), printf(ok ? "regtool-watch-ok\n" : "regtool-watch-FAIL\n");
    else if (strcmp(cmd, "verify") == 0)
    {
        ok = check_content(HKEY_LOCAL_MACHINE, "Software\\PrskCui7", "regtool-verify") &&
             do_load("regtool-verify2");
        printf(ok ? "regtool-verify-ok\n" : "regtool-verify-FAIL\n");
    }
    else if (strcmp(cmd, "shutdown") == 0)
        ok = do_shutdown();
    else
        printf("regtool-usage\n");
    fflush(stdout);
    return ok ? 0 : 1;
}
