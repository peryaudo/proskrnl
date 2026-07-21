/*
 * sem_se/se_hkcu.c — the integration pin CUI-2 exists for: HKCU resolution.
 *
 * RtlFormatCurrentUserKeyPath (dlls/ntdll/reg.c) queries TokenUser through
 * the thread-effective pseudo-handle and formats the registry path every
 * RegOpenKeyEx(HKEY_CURRENT_USER) in every baked tool depends on
 * (dlls/kernelbase/registry.c -> RtlOpenCurrentUser). With the fixed
 * identity S-1-5-21-0-0-0-1000 the result is one exact string.
 */
#include "util.h"

START_TEST(se_hkcu)
{
    static const WCHAR expected[] = W("\\Registry\\User\\S-1-5-21-0-0-0-1000");
    UNICODE_STRING path;
    NTSTATUS status;

    memset(&path, 0, sizeof(path));
    status = RtlFormatCurrentUserKeyPath(&path);
    ok(status == STATUS_SUCCESS, "RtlFormatCurrentUserKeyPath -> %08lx", (unsigned long)status);
    ok(path.Length == sizeof(expected) - sizeof(WCHAR), "path length %u", path.Length);
    ok(path.Buffer && memcmp(path.Buffer, expected, sizeof(expected) - sizeof(WCHAR)) == 0,
       "HKCU path mismatch");
    RtlFreeUnicodeString(&path);
}
