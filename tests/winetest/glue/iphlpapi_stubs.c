/*
 * tests/winetest/glue/iphlpapi_stubs.c — iphlpapi stand-ins for the
 * standalone ws2_32 test binary (Net-2, Makefile `wtests`).
 *
 * ws2_32's tests declare IMPORTS = iphlpapi, but iphlpapi's answers come
 * from the NSI surface (\Device\Nsi), which is Net-3's milestone — and
 * baking iphlpapi.dll would drag nsi.dll and dnsapi.dll onto the CUI
 * image for a handful of adapter-enumeration calls. Same policy as
 * user32_stubs.c beside it: honest, loud failure for every entry — a
 * subtest whose assertions need real adapter tables fails IDENTICALLY
 * under the oracle and on proskrnl and parks in the manifest with this
 * file named as the cause.
 */
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

ULONG WINAPI GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved, void *addresses,
                                  PULONG size)
{
    (void)family;
    (void)flags;
    (void)reserved;
    (void)addresses;
    (void)size;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI GetAdaptersInfo(void *info, PULONG size)
{
    (void)info;
    (void)size;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI GetIpForwardTable(void *table, PULONG size, BOOL order)
{
    (void)table;
    (void)size;
    (void)order;
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* ---- dllimport indirection (the user32_stubs.c pattern) ------------------- */

ULONG(WINAPI *__imp_GetAdaptersAddresses)
(ULONG, ULONG, PVOID, void *, PULONG) = GetAdaptersAddresses;
DWORD(WINAPI *__imp_GetAdaptersInfo)(void *, PULONG) = GetAdaptersInfo;
DWORD(WINAPI *__imp_GetIpForwardTable)(void *, PULONG, BOOL) = GetIpForwardTable;
