/*
 * sem_file/nt_path_syntax.c — NT path syntax at the file-open boundary.
 *
 * NT does not TIDY a path; it refuses a malformed one. The distinction is
 * the whole content of this file, because a kernel that resolves "." and
 * ".." the way every POSIX path walker does still opens the right file and
 * looks correct until something asks what happens to the wrong one.
 *
 * The rules and their statuses come from the oracle's own two checks:
 *
 *   - the component-syntax loop at the head of lookup_unix_name
 *     (third_party/wine dlls/ntdll/unix/file.c), which refuses an EMPTY
 *     component, a "." element and a ".." element with
 *     STATUS_OBJECT_NAME_INVALID;
 *   - "allow a second backslash" in nt_to_unix_file_name_no_root, which
 *     skips exactly ONE extra separator after the device prefix — so
 *     "\??\C:\\windows" is legal and "\??\C:\\\windows" is not;
 *   - `if (name_len && name[0] == '\\') return STATUS_INVALID_PARAMETER;`
 *     in the with-root path, which is a DIFFERENT status from the
 *     STATUS_OBJECT_PATH_SYNTAX_BAD a relative name with no root earns.
 *
 * ntdll:path's test_nt_names table is the full 60-entry version of this and
 * it is the gate that convicted proskrnl (16 failures, eleven of them dot
 * components being walked as ordinary names). What is here is the subset
 * that states each RULE once, so a regression names the rule rather than an
 * index into someone else's table.
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* Open `name` (absolute, or relative to `root`) and return the status. */
static NTSTATUS open_path(HANDLE root, const WCHAR *name, ULONG options)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING nameString;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&nameString, name);
    InitializeObjectAttributes(&attributes, &nameString, OBJ_CASE_INSENSITIVE, root, NULL);
    status = NtOpenFile(&handle, FILE_GENERIC_READ, &attributes, &iosb, FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | options);
    if (handle != NULL)
    {
        NtClose(handle);
    }
    return status;
}

static void check(HANDLE root, const WCHAR *name, ULONG options, NTSTATUS expect, const char *what)
{
    NTSTATUS status = open_path(root, name, options);
    ok(status == expect, "%s -> %08lx, wanted %08lx", what, (unsigned long)status,
       (unsigned long)expect);
}

START_TEST(nt_path_syntax)
{
    HANDLE windows = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING nameString;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    /* --- the baseline: the same file, named correctly ------------------- */
    check(NULL, L"\\??\\C:\\windows\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE, STATUS_SUCCESS,
          "the plain absolute name");

    /* --- "." and ".." are REFUSED, not resolved ------------------------
     * Each of the three positions a dot element can occupy, because a
     * collapse-then-walk implementation gets all three "right" and a
     * refuse-on-sight one gets all three right too — but a walker that only
     * special-cases the leaf passes the last and fails the first two. */
    check(NULL, L"\\??\\C:\\windows\\system32\\.\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a \".\" element in the middle");
    check(NULL, L"\\??\\C:\\windows\\system32\\..\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a \"..\" element in the middle");
    check(NULL, L"\\??\\C:\\.\\windows\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a \".\" element first");

    /* A name whose LEAF is a dot element. Note the status a naive walker
     * gives instead is STATUS_OBJECT_NAME_NOT_FOUND — which is a perfectly
     * ordinary answer, and wrong. */
    check(NULL, L"\\??\\C:\\windows\\.", FILE_DIRECTORY_FILE, STATUS_OBJECT_NAME_INVALID,
          "a \".\" leaf");
    check(NULL, L"\\??\\C:\\windows\\..", FILE_DIRECTORY_FILE, STATUS_OBJECT_NAME_INVALID,
          "a \"..\" leaf");

    /* Names that merely START with a dot are ordinary names and must not be
     * caught by the rule above — the check is for the whole component. */
    check(NULL, L"\\??\\C:\\windows\\...nonexistent", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_NOT_FOUND, "a component beginning with dots");

    /* --- separators ----------------------------------------------------
     * ONE extra after the device is skipped; a second is an empty
     * component. And a single trailing separator is not an empty component
     * at all — it means "this had better be a directory". */
    check(NULL, L"\\??\\C:\\\\windows\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_SUCCESS, "one doubled separator after the device");
    check(NULL, L"\\??\\C:\\\\\\windows\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a tripled separator after the device");
    check(NULL, L"\\??\\C:\\windows\\\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a doubled separator mid-path");
    check(NULL, L"\\??\\C:\\windows\\system32\\", FILE_NON_DIRECTORY_FILE,
          STATUS_FILE_IS_A_DIRECTORY, "one trailing separator on a directory");
    check(NULL, L"\\??\\C:\\windows\\system32\\\\", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "two trailing separators");

    /* '/' is not a separator: it is a reserved CHARACTER, so a component
     * containing one is malformed rather than missing. */
    check(NULL, L"\\??\\C:\\windows/system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_NAME_INVALID, "a forward slash inside a component");

    /* --- root-relative names -------------------------------------------
     * The two "this name is wrong" statuses are not interchangeable, and
     * which one applies depends on which argument is at fault:
     *   a relative name with NO root  -> STATUS_OBJECT_PATH_SYNTAX_BAD
     *   an ABSOLUTE name WITH a root  -> STATUS_INVALID_PARAMETER
     */
    check(NULL, L"C:\\windows\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE,
          STATUS_OBJECT_PATH_SYNTAX_BAD, "a DOS name with no root");

    RtlInitUnicodeString(&nameString, L"\\??\\C:\\windows\\");
    InitializeObjectAttributes(&attributes, &nameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtOpenFile(
        &windows, SYNCHRONIZE | FILE_LIST_DIRECTORY, &attributes, &iosb, FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "open \\??\\C:\\windows\\ as a root -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check(windows, L"system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE, STATUS_SUCCESS,
              "a relative name under a root");
        check(windows, L"\\system32\\ntdll.dll", FILE_NON_DIRECTORY_FILE, STATUS_INVALID_PARAMETER,
              "an absolute name under a root");
        /* The component rules apply identically under a root — same
         * validator, different starting directory. */
        check(windows, L".", FILE_DIRECTORY_FILE, STATUS_OBJECT_NAME_INVALID,
              "a \".\" name under a root");
        check(windows, L"..", FILE_DIRECTORY_FILE, STATUS_OBJECT_NAME_INVALID,
              "a \"..\" name under a root");
        check(windows, L"system32\\\\", FILE_NON_DIRECTORY_FILE, STATUS_OBJECT_NAME_INVALID,
              "two trailing separators under a root");
        check(windows, L"system32\\", FILE_NON_DIRECTORY_FILE, STATUS_FILE_IS_A_DIRECTORY,
              "one trailing separator under a root");
        NtClose(windows);
    }
}
