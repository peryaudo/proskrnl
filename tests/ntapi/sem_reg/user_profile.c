/*
 * sem_reg/user_profile.c — the user profile, as furniture.
 *
 * Convicted by the winetest gate: kernel32:environ's test_Predefined
 * (environ.c:74) resolves GetUserProfileDirectoryA and, when userenv.dll is
 * present, requires it to succeed and to agree with %USERPROFILE%. On
 * proskrnl it failed with ERROR_FILE_NOT_FOUND, and the two assertions behind
 * it (:78 and :80) were skipped rather than run — the pair's one failure, and
 * a lower bound on it.
 *
 * The chain the winetest is exercising is entirely furniture, and every link
 * of it is registry or environment state that `wineboot --init` writes into
 * the oracle's prefix and that proskrnl — which has no prefix — must seed for
 * itself, the Session Manager / time-zone / LicenseInformation precedent in
 * kernel/cm/registry.c. Read down from the consumer:
 *
 *   GetUserProfileDirectoryW (third_party/wine/dlls/userenv/userenv_main.c)
 *     = GetProfilesDirectoryW() + L"\\" + LookupAccountSidW(TokenUser)
 *
 *   GetProfilesDirectoryW (same file) opens
 *     HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList,
 *     reads `ProfilesDirectory` and expands it through
 *     ExpandEnvironmentStringsW. A missing key or value is the ERROR_FILE_NOT_FOUND
 *     the pair reported;
 *
 *   LookupAccountSidW (dlls/advapi32/security.c) recognises the fixed identity
 *     as <computer SID>-1000 and answers its RID-1000 arm, which is
 *     GetUserNameW — and Wine implements THAT as
 *     GetEnvironmentVariableW(L"WINEUSERNAME") (dlls/advapi32/advapi.c:62).
 *     So the name half of the composition is an environment read on both
 *     runners, which is why this test reads the same variable rather than
 *     linking advapi32 (the ntapi harness links ntdll + kernel32 + kernelbase
 *     only, tests/run/run.sh WINE_LIBS).
 *
 * What this pin measures, and why each part is here:
 *
 *   - the key and the value SEPARATELY. `ProfilesDirectory` absent from a
 *     present key and the key absent altogether are the same
 *     ERROR_FILE_NOT_FOUND to the consumer, so a run that only checked the
 *     final composition could not say which link broke;
 *   - the COMPOSITION RULE rather than a literal path. The two runners
 *     disagree about the user name by construction — the oracle's is the host
 *     account (`WINEUSERNAME` comes from the unix side,
 *     dlls/ntdll/unix/env.c append_envA), proskrnl's is the fixed `wine` of
 *     the CUI-2 default environment (kernel/ps/peb.c) — so a pin asserting
 *     `C:\users\wine` would be a pin on this developer's box, the exact
 *     host-dependence the winetest manifest header spends its longest
 *     paragraph on. What must hold on BOTH is
 *     `USERPROFILE == ProfilesDirectory\<user name>`, which is precisely the
 *     equality environ.c:80 asserts through two different APIs;
 *   - the value is EXPANDED before the comparison, because the consumer
 *     expands it. The pinned oracle's prefix stores a literal `C:\users`
 *     (shell32's _SHGetProfilesValue default, dlls/shell32/shellpath.c: the
 *     system directory's drive plus `users`, written as REG_EXPAND_SZ), so
 *     the expansion is a no-op there today — asserting on the raw value would
 *     pass anyway and would silently become wrong the day either side stores
 *     `%SystemDrive%\users`, which is what NT itself stores. Its TYPE is
 *     accepted either way for the same reason: the consumer expands whatever
 *     it finds and never looks at the type, so pinning `REG_EXPAND_SZ` would
 *     hold the kernel to something no caller can observe;
 *   - the per-SID subkey, named by the TOKEN's user SID rather than by a
 *     string typed here. `RtlFormatCurrentUserKeyPath` already resolves that
 *     SID (it is what every HKCU open goes through — sem_se/se_hkcu.c pins
 *     the whole path), so its tail is the one authority for the subkey's
 *     name. `ProfileImagePath` under it must be the same string USERPROFILE
 *     names: wineboot writes it from CSIDL_PROFILE
 *     (programs/wineboot/wineboot.c update_user_profile), i.e. from the same
 *     answer, so a seed that let the two drift would describe a profile
 *     nothing lives in;
 *   - the DIRECTORY exists. USERPROFILE naming a path that is not there is
 *     the same class of wrong answer as a zeroed field: every consumer that
 *     writes under it fails, and no query reports the problem. `Flags` beside
 *     `ProfileImagePath` is deliberately NOT pinned and deliberately not
 *     seeded — nothing in the baked stack reads it (Art. 5), and seeding a
 *     value because the oracle's prefix has one is the claim about "which
 *     lines matter" that the LicenseInformation entry in kernel/cm/registry.c
 *     records going stale.
 *
 * Read-only throughout: nothing here creates or deletes a key or a file, so
 * an oracle run leaves the prefix exactly as it found it.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#define PROFILE_LIST_PATH                                                                          \
    W("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")

/* winternl.h omits it; declared as wine/include/winternl.h does. */
NTSYSAPI NTSTATUS NTAPI RtlFormatCurrentUserKeyPath(PUNICODE_STRING);
NTSYSAPI void NTAPI RtlFreeUnicodeString(PUNICODE_STRING);

/* MAX_PATH — every string here is a filesystem path, and userenv's own
 * buffers are this size (third_party/wine/include/minwindef.h). Spelled out
 * rather than used by name so the array bounds do not depend on which of the
 * two toolchains' headers is in scope. */
#define PRSK_PATH_CHARS 260

static ULONG wide_length(const WCHAR *text)
{
    ULONG n = 0;
    while (text[n])
        n++;
    return n;
}

static int wide_same(const WCHAR *left, const WCHAR *right)
{
    ULONG i = 0;
    while (left[i] && left[i] == right[i])
        i++;
    return left[i] == right[i];
}

/* Render an ASCII path into a narrow buffer for a failure message — the
 * harness's printf has no wide specifier (tests/ntapi/ntapi.c). A non-ASCII
 * unit becomes '?', which is enough to see WHICH string was wrong. */
static void wide_to_ascii(char *out, ULONG outBytes, const WCHAR *text)
{
    ULONG i = 0;
    for (; text[i] && i + 1 < outBytes; i++)
        out[i] = (text[i] < 0x80) ? (char)text[i] : '?';
    out[i] = '\0';
}

/* Read a value through KeyValuePartialInformation, reporting type and length. */
static NTSTATUS read_value(HANDLE key, const void *valueName, UCHAR *buffer, ULONG bufferBytes,
                           ULONG *type, ULONG *dataBytes)
{
    UNICODE_STRING name;
    UCHAR raw[1024];
    ULONG returned = 0;
    NTSTATUS status;
    reg_kv_partial_info *info = (reg_kv_partial_info *)raw;

    *type = 0;
    *dataBytes = 0;
    init_ustr(&name, valueName);
    status = NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, raw, sizeof(raw), &returned);
    if (!NT_SUCCESS(status))
        return status;
    *type = info->type;
    *dataBytes = info->data_length;
    if (info->data_length <= bufferBytes)
        memcpy(buffer, info->data, info->data_length);
    return status;
}

/* Open an existing DIRECTORY by DOS path, through the \??\ prefix every
 * drive-absolute Win32 path resolves to. */
static NTSTATUS open_directory(const WCHAR *dosPath, HANDLE *out)
{
    WCHAR ntPath[4 + PRSK_PATH_CHARS];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    ULONG i, chars = wide_length(dosPath);
    const WCHAR *prefix = (const WCHAR *)W("\\??\\");

    if (chars >= PRSK_PATH_CHARS)
        return STATUS_NAME_TOO_LONG;
    for (i = 0; i < 4; i++)
        ntPath[i] = prefix[i];
    for (i = 0; i <= chars; i++)
        ntPath[4 + i] = dosPath[i];

    init_ustr(&name, ntPath);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    *out = NULL;
    return NtCreateFile(out, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

START_TEST(user_profile)
{
    HANDLE key = NULL, sub = NULL, dir = NULL;
    UNICODE_STRING hkcuPath;
    NTSTATUS status;
    ULONG type = 0, bytes = 0, i, tail;
    WCHAR stored[PRSK_PATH_CHARS], profilesDir[PRSK_PATH_CHARS];
    WCHAR userName[PRSK_PATH_CHARS], userProfile[PRSK_PATH_CHARS];
    WCHAR composed[PRSK_PATH_CHARS], sid[PRSK_PATH_CHARS];
    char shownA[PRSK_PATH_CHARS], shownB[PRSK_PATH_CHARS];
    DWORD len;

    /* 1. The key GetProfilesDirectoryW opens. */
    status = reg_open_path_access(PROFILE_LIST_PATH, KEY_READ, &key);
    ok(status == STATUS_SUCCESS, "open ProfileList -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* 2. ProfilesDirectory: present, a string, non-empty, and with no
     *    trailing separator — the consumer appends one unconditionally, so a
     *    stored `C:\users\` composes `C:\users\\wine`. */
    status = read_value(key, W("ProfilesDirectory"), (UCHAR *)stored,
                        sizeof(stored) - sizeof(WCHAR), &type, &bytes);
    ok(status == STATUS_SUCCESS, "query ProfilesDirectory -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(key);
        return;
    }
    ok(type == REG_SZ || type == REG_EXPAND_SZ, "ProfilesDirectory type %lu", (unsigned long)type);
    ok(bytes > sizeof(WCHAR) && bytes < sizeof(stored), "ProfilesDirectory %lu bytes",
       (unsigned long)bytes);
    if (bytes >= sizeof(stored))
    {
        NtClose(key);
        return;
    }
    stored[bytes / sizeof(WCHAR)] = 0; /* a REG_SZ need not carry its terminator */

    len = ExpandEnvironmentStringsW(stored, profilesDir, PRSK_PATH_CHARS);
    ok(len > 1 && len <= PRSK_PATH_CHARS, "expand ProfilesDirectory -> %lu", (unsigned long)len);
    if (!(len > 1 && len <= PRSK_PATH_CHARS))
    {
        NtClose(key);
        return;
    }
    tail = wide_length(profilesDir);
    wide_to_ascii(shownA, sizeof(shownA), profilesDir);
    ok(tail > 2 && profilesDir[1] == ':' && profilesDir[2] == '\\',
       "ProfilesDirectory '%s' is not drive-absolute", shownA);
    ok(profilesDir[tail - 1] != '\\', "ProfilesDirectory '%s' ends in a separator", shownA);

    /* 3. USERPROFILE, in the process environment. */
    len = GetEnvironmentVariableW((const WCHAR *)W("USERPROFILE"), userProfile, PRSK_PATH_CHARS);
    ok(len > 0 && len < PRSK_PATH_CHARS, "USERPROFILE -> %lu chars", (unsigned long)len);
    if (!(len > 0 && len < PRSK_PATH_CHARS))
    {
        NtClose(key);
        return;
    }

    /* 4. The name LookupAccountSidW's RID-1000 arm resolves to. */
    len = GetEnvironmentVariableW((const WCHAR *)W("WINEUSERNAME"), userName, PRSK_PATH_CHARS);
    ok(len > 0 && len < PRSK_PATH_CHARS, "WINEUSERNAME -> %lu chars", (unsigned long)len);
    if (!(len > 0 && len < PRSK_PATH_CHARS))
    {
        NtClose(key);
        return;
    }

    /* 5. The composition GetUserProfileDirectoryW performs — environ.c:80's
     *    equality, reached through the registry and the environment instead of
     *    through userenv and advapi32. Both halves are bounded separately
     *    above and their SUM is not, so it is checked here: a long enough host
     *    account name would otherwise walk off `composed`. */
    ok(tail + 1 + wide_length(userName) < PRSK_PATH_CHARS, "composed path too long");
    if (tail + 1 + wide_length(userName) >= PRSK_PATH_CHARS)
    {
        NtClose(key);
        return;
    }
    for (i = 0; i < tail; i++)
        composed[i] = profilesDir[i];
    composed[tail] = '\\';
    for (i = 0; i <= wide_length(userName); i++)
        composed[tail + 1 + i] = userName[i];
    wide_to_ascii(shownA, sizeof(shownA), userProfile);
    wide_to_ascii(shownB, sizeof(shownB), composed);
    ok(wide_same(userProfile, composed), "USERPROFILE '%s' != ProfilesDirectory\\user '%s'", shownA,
       shownB);

    /* 6. The per-SID subkey, named by the token's own user SID. */
    memset(&hkcuPath, 0, sizeof(hkcuPath));
    status = RtlFormatCurrentUserKeyPath(&hkcuPath);
    ok(status == STATUS_SUCCESS, "RtlFormatCurrentUserKeyPath -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        NtClose(key);
        return;
    }
    tail = 0;
    for (i = 0; i < hkcuPath.Length / sizeof(WCHAR); i++)
        if (hkcuPath.Buffer[i] == '\\')
            tail = i + 1;
    ok(hkcuPath.Length / sizeof(WCHAR) - tail < PRSK_PATH_CHARS, "HKCU path tail too long");
    if (hkcuPath.Length / sizeof(WCHAR) - tail >= PRSK_PATH_CHARS)
    {
        RtlFreeUnicodeString(&hkcuPath);
        NtClose(key);
        return;
    }
    for (i = tail; i < hkcuPath.Length / sizeof(WCHAR); i++)
        sid[i - tail] = hkcuPath.Buffer[i];
    sid[hkcuPath.Length / sizeof(WCHAR) - tail] = 0;
    RtlFreeUnicodeString(&hkcuPath);

    status = reg_open_sub_access(key, sid, KEY_READ, &sub);
    wide_to_ascii(shownA, sizeof(shownA), sid);
    ok(status == STATUS_SUCCESS, "open ProfileList\\%s -> %08lx", shownA, (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = read_value(sub, W("ProfileImagePath"), (UCHAR *)stored,
                            sizeof(stored) - sizeof(WCHAR), &type, &bytes);
        ok(status == STATUS_SUCCESS, "query ProfileImagePath -> %08lx", (unsigned long)status);
        ok(!NT_SUCCESS(status) || bytes < sizeof(stored), "ProfileImagePath %lu bytes",
           (unsigned long)bytes);
        if (NT_SUCCESS(status) && bytes < sizeof(stored))
        {
            stored[bytes / sizeof(WCHAR)] = 0;
            ok(type == REG_SZ, "ProfileImagePath type %lu", (unsigned long)type);
            wide_to_ascii(shownA, sizeof(shownA), stored);
            wide_to_ascii(shownB, sizeof(shownB), userProfile);
            ok(wide_same(stored, userProfile), "ProfileImagePath '%s' != USERPROFILE '%s'", shownA,
               shownB);
        }
        NtClose(sub);
    }
    NtClose(key);

    /* 7. The profile directory is really there. */
    status = open_directory(userProfile, &dir);
    wide_to_ascii(shownA, sizeof(shownA), userProfile);
    ok(status == STATUS_SUCCESS, "open directory '%s' -> %08lx", shownA, (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(dir);
}
