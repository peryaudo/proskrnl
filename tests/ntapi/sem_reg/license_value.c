/*
 * sem_reg/license_value.c — NtQueryLicenseValue.
 *
 * Convicted by the winetest gate, and by the loudest possible signal: the
 * syscall was entirely absent, so ntdll:reg PANICKED the machine partway
 * through (the armed boot turns a missing syscall into a panic by design,
 * Art. 12) and every test after reg.c:880 never ran.
 *
 * The call is a named lookup with an unusually strict argument contract,
 * and the whole value of pinning it is that the strictness is ORDERED —
 * the argument checks happen before the lookup, and each failure leaves the
 * caller's out-params untouched. ntdll:reg checks the untouched-ness after
 * every single refusal (`type == 0xdead`, `len == 0xbeef`), so an
 * implementation that zeroed its out-params on the way in would return the
 * right statuses and still fail a dozen assertions.
 *
 *   name NULL, or name->Buffer NULL, or name->Length 0   -> INVALID_PARAMETER
 *   retlen NULL                                          -> INVALID_PARAMETER
 *   a name that is not a license value                   -> OBJECT_NAME_NOT_FOUND
 *   a real value, buffer too small                       -> BUFFER_TOO_SMALL,
 *                                                           with type and
 *                                                           retlen FILLED
 *   a real value with room                               -> SUCCESS
 *
 * `type` is optional throughout; `retlen` never is. That asymmetry is the
 * shape the oracle states in one line (dlls/ntdll/unix/registry.c:
 * `if (!name || !name->Buffer || !name->Length || !retlen) return
 * STATUS_INVALID_PARAMETER;`) and it is worth pinning because the natural
 * implementation makes both optional or neither.
 *
 * The one value asserted by name is `Kernel-MUI-Language-Allowed`, REG_SZ,
 * data `"EMPTY"` — the literal five-letter word, not an empty string; the
 * winetest's variable is spelled `emptyW` and reading it as "the empty
 * string" cost this pin a round on the oracle. ntdll:reg asserts the value
 * with no `broken()` guard, so it is Windows-verified spec (docs/08) and
 * not merely a prefix default, even though the pinned prefix does also seed
 * it (loader/wine.inf.in:1212). proskrnl has no prefix, so its kernel seeds
 * the same value — the Session Manager / time-zone precedent in
 * kernel/cm/registry.c.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryLicenseValue(const UNICODE_STRING *, ULONG *, PVOID, ULONG, ULONG *);

START_TEST(license_value)
{
    NTSTATUS status;
    UNICODE_STRING name;
    UCHAR buffer[64];
    ULONG type, length;

    /* --- an empty UNICODE_STRING is INVALID, and touches nothing --------- */
    memset(&name, 0, sizeof(name));
    type = 0xdead;
    length = 0xbeef;
    status = NtQueryLicenseValue(&name, &type, buffer, sizeof(buffer), &length);
    ok(status == STATUS_INVALID_PARAMETER, "empty name -> %08lx", (unsigned long)status);
    ok(type == 0xdead, "empty name wrote type (%lu)", (unsigned long)type);
    ok(length == 0xbeef, "empty name wrote retlen (%lu)", (unsigned long)length);

    /* --- so is a NULL name ------------------------------------------------ */
    type = 0xdead;
    length = 0xbeef;
    status = NtQueryLicenseValue(NULL, &type, buffer, sizeof(buffer), &length);
    ok(status == STATUS_INVALID_PARAMETER, "NULL name -> %08lx", (unsigned long)status);
    ok(type == 0xdead, "NULL name wrote type (%lu)", (unsigned long)type);
    ok(length == 0xbeef, "NULL name wrote retlen (%lu)", (unsigned long)length);

    /* --- a real name with a NULL retlen is INVALID too --------------------
     * This is the assertion that separates the two out-params: `type` may
     * be NULL everywhere below, `retlen` may not be anywhere. */
    init_ustr(&name, W("Kernel-MUI-Language-Allowed"));
    type = 0xdead;
    status = NtQueryLicenseValue(&name, &type, buffer, sizeof(buffer), NULL);
    ok(status == STATUS_INVALID_PARAMETER, "NULL retlen -> %08lx", (unsigned long)status);
    ok(type == 0xdead, "NULL retlen wrote type (%lu)", (unsigned long)type);

    /* --- the argument checks come BEFORE the lookup ----------------------
     * A name that does not exist still gets INVALID_PARAMETER when retlen
     * is NULL, not OBJECT_NAME_NOT_FOUND: order matters. */
    {
        UNICODE_STRING missing;
        init_ustr(&missing, W("Nonexistent-License-Value"));
        type = 0xdead;
        status = NtQueryLicenseValue(&missing, &type, buffer, sizeof(buffer), NULL);
        ok(status == STATUS_INVALID_PARAMETER, "missing name + NULL retlen -> %08lx",
           (unsigned long)status);

        /* --- and with a valid retlen it is a NAME complaint, out-params
         * still untouched. */
        type = 0xdead;
        length = 0xbeef;
        status = NtQueryLicenseValue(&missing, &type, buffer, sizeof(buffer), &length);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing name -> %08lx", (unsigned long)status);
        ok(type == 0xdead, "missing name wrote type (%lu)", (unsigned long)type);
        ok(length == 0xbeef, "missing name wrote retlen (%lu)", (unsigned long)length);

        /* type is optional: the same call without it behaves identically. */
        length = 0xbeef;
        status = NtQueryLicenseValue(&missing, NULL, buffer, sizeof(buffer), &length);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "missing name, no type -> %08lx",
           (unsigned long)status);
    }

    /* --- a real value, with no room: BUFFER_TOO_SMALL, and unlike every
     * refusal above this one DOES fill type and retlen ------------------- */
    type = 0xdead;
    length = 0;
    status = NtQueryLicenseValue(&name, &type, buffer, 0, &length);
    ok(status == STATUS_BUFFER_TOO_SMALL, "no room -> %08lx", (unsigned long)status);
    ok(type == REG_SZ, "no room reported type %lu", (unsigned long)type);
    ok(length == 6 * sizeof(WCHAR), "no room reported %lu bytes", (unsigned long)length);

    /* same, without the optional type */
    length = 0;
    status = NtQueryLicenseValue(&name, NULL, buffer, 0, &length);
    ok(status == STATUS_BUFFER_TOO_SMALL, "no room, no type -> %08lx", (unsigned long)status);
    ok(length == 6 * sizeof(WCHAR), "no room, no type reported %lu bytes",
       (unsigned long)length);

    /* --- and with room, the value itself ---------------------------------- */
    type = 0xdead;
    length = 0;
    memset(buffer, 0x11, sizeof(buffer));
    status = NtQueryLicenseValue(&name, &type, buffer, sizeof(buffer), &length);
    ok(status == STATUS_SUCCESS, "with room -> %08lx", (unsigned long)status);
    ok(type == REG_SZ, "type %lu", (unsigned long)type);
    ok(length == 6 * sizeof(WCHAR), "returned %lu bytes", (unsigned long)length);
    {
        static const WCHAR expected[] = W("EMPTY");
        ok(memcmp(buffer, expected, sizeof(expected)) == 0, "the value is not \"EMPTY\"");
    }
}
