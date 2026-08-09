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
 * The first value asserted by name is `Kernel-MUI-Language-Allowed`, REG_SZ,
 * data `"EMPTY"` — the literal five-letter word, not an empty string; the
 * winetest's variable is spelled `emptyW` and reading it as "the empty
 * string" cost this pin a round on the oracle. ntdll:reg asserts the value
 * with no `broken()` guard, so it is Windows-verified spec (docs/08) and
 * not merely a prefix default, even though the pinned prefix does also seed
 * it (loader/wine.inf.in:1212). proskrnl has no prefix, so its kernel seeds
 * the same value — the Session Manager / time-zone precedent in
 * kernel/cm/registry.c.
 *
 * The block at the end repeats the size/type protocol against REG_DWORD
 * values, which is what convicts a seed that carries only the string half:
 * the type and the length are read out of the STORED value, so every
 * assertion above passes on a kernel that knows one value and one type.
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
    ok(length == 6 * sizeof(WCHAR), "no room, no type reported %lu bytes", (unsigned long)length);

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

    /* --- the REG_DWORD half ----------------------------------------------
     * The same five shapes again against a value of a DIFFERENT TYPE, and
     * that is the whole point of repeating them: `type` and `retlen` are
     * read out of the stored value, so an implementation that hardwired the
     * REG_SZ answers above — or that seeded only the string value the block
     * above asks for — passes every assertion up to here.
     *
     * `Kernel-MUI-Number-Allowed` is REG_DWORD on both runners because both
     * read the same pinned payload: the oracle from its prefix, which
     * loader/wine.inf.in:1214 wrote, and proskrnl from the table
     * tools/gen_license.py generates out of that same INF section
     * (kernel/cm/license.h). ntdll:reg reaches exactly this value at
     * reg.c:1005-:1032. */
    {
        ULONG value;

        init_ustr(&name, W("Kernel-MUI-Number-Allowed"));

        /* no room: the type and the size come back, the buffer does not.
         * The oracle reaches this through NtQueryValueKey's
         * STATUS_BUFFER_OVERFLOW arm and copies NOTHING on it
         * (dlls/ntdll/unix/registry.c NtQueryLicenseValue). */
        type = 0xdead;
        length = 0;
        value = 0xdeadbeef;
        status = NtQueryLicenseValue(&name, &type, &value, 0, &length);
        ok(status == STATUS_BUFFER_TOO_SMALL, "dword, no room -> %08lx", (unsigned long)status);
        ok(type == REG_DWORD, "dword, no room reported type %lu", (unsigned long)type);
        ok(length == sizeof(value), "dword, no room reported %lu bytes", (unsigned long)length);
        ok(value == 0xdeadbeef, "dword, no room wrote the buffer (%08lx)", (unsigned long)value);

        /* SHORT but not empty is the same refusal — the rule is "shorter
         * than the value", not "zero-length". An implementation that only
         * special-cased a zero length would copy two bytes here. */
        type = 0xdead;
        length = 0;
        value = 0xdeadbeef;
        status = NtQueryLicenseValue(&name, &type, &value, 2, &length);
        ok(status == STATUS_BUFFER_TOO_SMALL, "dword, 2 bytes -> %08lx", (unsigned long)status);
        ok(type == REG_DWORD, "dword, 2 bytes reported type %lu", (unsigned long)type);
        ok(length == sizeof(value), "dword, 2 bytes reported %lu bytes", (unsigned long)length);
        ok(value == 0xdeadbeef, "dword, 2 bytes wrote the buffer (%08lx)", (unsigned long)value);

        /* and with room, the value. 1000 is not an NT constant and this pin
         * does not claim it is — ntdll:reg deliberately asserts only
         * `value != 0xdeadbeef` (reg.c:1025). It is the pinned tree's own
         * datum, and asserting it is what makes the two legs prove they read
         * the SAME payload rather than each inventing a plausible number. */
        type = 0xdead;
        length = 0;
        value = 0xdeadbeef;
        status = NtQueryLicenseValue(&name, &type, &value, sizeof(value), &length);
        ok(status == STATUS_SUCCESS, "dword, with room -> %08lx", (unsigned long)status);
        ok(type == REG_DWORD, "dword type %lu", (unsigned long)type);
        ok(length == sizeof(value), "dword returned %lu bytes", (unsigned long)length);
        ok(value == 1000, "dword value %lu", (unsigned long)value);

        /* a value from the section's OTHER shape, so the seed is proven to
         * be the whole [LicenseInformation] payload and not the three names
         * ntdll:reg happens to ask for. */
        init_ustr(&name, W("Kernel-MUI-Language-Disallowed"));
        type = 0xdead;
        length = 0;
        memset(buffer, 0x11, sizeof(buffer));
        status = NtQueryLicenseValue(&name, &type, buffer, sizeof(buffer), &length);
        ok(status == STATUS_SUCCESS, "disallowed -> %08lx", (unsigned long)status);
        ok(type == REG_SZ, "disallowed type %lu", (unsigned long)type);
        ok(length == 6 * sizeof(WCHAR), "disallowed returned %lu bytes", (unsigned long)length);
        {
            static const WCHAR expected[] = W("EMPTY");
            ok(memcmp(buffer, expected, sizeof(expected)) == 0,
               "the disallowed value is not \"EMPTY\"");
        }

        init_ustr(&name, W("Shell-InBoxGames-Solitaire-EnableGame"));
        type = 0xdead;
        length = 0;
        value = 0xdeadbeef;
        status = NtQueryLicenseValue(&name, &type, &value, sizeof(value), &length);
        ok(status == STATUS_SUCCESS, "solitaire -> %08lx", (unsigned long)status);
        ok(type == REG_DWORD, "solitaire type %lu", (unsigned long)type);
        ok(length == sizeof(value), "solitaire returned %lu bytes", (unsigned long)length);
        ok(value == 1, "solitaire value %lu", (unsigned long)value);
    }
}
