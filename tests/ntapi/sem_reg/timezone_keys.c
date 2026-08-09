/*
 * sem_reg/timezone_keys.c — the HKLM Time Zones table, as furniture.
 *
 * Convicted by the winetest gate: kernel32:time's
 * test_GetTimeZoneInformationForYear walks a table of named zones and years
 * (Greenland, Easter Island, Egypt, Altai) and gets ERROR_FILE_NOT_FOUND for
 * every one of them, because kernelbase resolves a zone by OPENING
 * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time Zones\<name>` and
 * proskrnl seeded exactly one subkey there, UTC — the one kernelbase needs to
 * boot. On the oracle the whole table is prefix furniture, written at
 * `wineboot --init` by the WINE_REGISTRY resource in kernelbase itself
 * (dlls/kernelbase/kernelbase.rgs, applied by dlls/setupapi/fakedll.c
 * `register_resource` through atl's IRegistrar). proskrnl has no prefix, so
 * its kernel seeds the same payload — the Session Manager / LicenseInformation
 * precedent in kernel/cm/registry.c — GENERATED out of that .rgs
 * (kernel/cm/timezones.h, tools/gen_timezones.py) rather than transcribed.
 *
 * What this pin measures, and why each part is here:
 *
 *   - a zone key carries THREE value types in one key — REG_SZ (Std, Dlt,
 *     Display, the MUI_* indirections), REG_BINARY (TZI, exactly 44 bytes,
 *     the REG_TZI_FORMAT), REG_DWORD (First/LastEntry, under Dynamic DST).
 *     A seed that stored the DWORDs as text would satisfy every string
 *     assertion and fail only the two typed ones — the shape that already
 *     cost ntdll:reg twelve assertions on the license values;
 *   - the per-year `Dynamic DST` subkey is a SECOND level below the zone, and
 *     its year values are what the test's table actually reads: the zone's own
 *     TZI is only the fallback (dlls/kernelbase/locale.c
 *     GetTimeZoneInformationForYear tries `Dynamic DST\<year>` first). A seed
 *     that flattened the subtree answers every zone-level assertion;
 *   - a zone with NO Dynamic DST subkey (Afghanistan) must not grow one, and
 *     asking for it is STATUS_OBJECT_NAME_NOT_FOUND. That is the case a
 *     "give every zone the same shape" implementation gets wrong;
 *   - a DAYLIGHT name is not a key name. `Greenland Daylight Time` is a real
 *     string in the table (the zone's `Dlt` value) and is not a subkey —
 *     kernel32:time probes exactly that name expecting the refusal, so an
 *     implementation that indexed the table by every name it contains would
 *     turn that probe into a success and skip the rest of the test;
 *   - the subkey COUNT is asserted only as a lower bound, deliberately. The
 *     claim being made is "the whole section, not the names a test happens to
 *     ask for", and the thing that ENFORCES that claim is
 *     `gen_timezones.py --check` against the pin, not a number typed here — a
 *     number here would only re-state the pinned tree's current tzdata and go
 *     stale at the next pin bump. What the bound does convict is the state
 *     this pin was written against: one zone, UTC.
 *
 * The byte-level expectations below are the pinned tree's own data
 * (kernelbase.rgs, and byte-for-byte the same in the oracle's prefix), chosen
 * to be the same rows kernel32:time asserts about, so this pin and that pair
 * cannot disagree about what the table says.
 *
 * Read-only throughout: nothing here creates or deletes a key, so an oracle
 * run leaves the prefix exactly as it found it.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#define TZ_KEY_PATH                                                                                \
    W("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones")

/* The TZI blob's layout, as the CONSUMER of these bytes declares it: the
 * anonymous `data` struct at the head of GetTimeZoneInformationForYear
 * (third_party/wine/dlls/kernelbase/locale.c) — LONG bias, LONG std_bias,
 * LONG dlt_bias, SYSTEMTIME std_date, SYSTEMTIME dlt_date, 44 bytes, with
 * `wMonth` the second field of a SYSTEMTIME. Re-verify there, not against
 * TIME_ZONE_INFORMATION, whose field ORDER is different (it interleaves the
 * name arrays) — that is the wrong struct with the right field names. The
 * offsets are spelled out rather than cast through a struct so the test
 * depends on no header the two toolchains might lay out differently. */
#define TZI_BYTES         44
#define TZI_OFF_BIAS      0
#define TZI_OFF_DLT_BIAS  8
#define TZI_OFF_STD_MONTH (12 + 2)
#define TZI_OFF_DLT_MONTH (28 + 2)

static LONG tzi_long(const UCHAR *data, unsigned offset)
{
    return (LONG)((ULONG)data[offset] | ((ULONG)data[offset + 1] << 8) |
                  ((ULONG)data[offset + 2] << 16) | ((ULONG)data[offset + 3] << 24));
}

static USHORT tzi_word(const UCHAR *data, unsigned offset)
{
    return (USHORT)((ULONG)data[offset] | ((ULONG)data[offset + 1] << 8));
}

/* Read a value into `buffer` through KeyValuePartialInformation, reporting the
 * type and the data length. Returns the query status. */
static NTSTATUS read_value(HANDLE key, const void *valueName, UCHAR *buffer, ULONG bufferBytes,
                           ULONG *type, ULONG *dataBytes)
{
    UNICODE_STRING name;
    UCHAR raw[512];
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

/* Compare a REG_SZ payload (with its terminator) against a wide literal. */
static int wide_equals(const UCHAR *data, ULONG bytes, const void *expected)
{
    const unsigned short *want = (const unsigned short *)expected;
    const unsigned short *got = (const unsigned short *)(const void *)data;
    ULONG units = bytes / 2;
    ULONG i;

    for (i = 0; i < units; i++)
    {
        if (got[i] != want[i])
            return 0;
        if (got[i] == 0)
            return 1;
    }
    return 0;
}

static void check_string(HANDLE key, const void *valueName, const void *expected, const char *what)
{
    UCHAR data[256];
    ULONG type = 0, bytes = 0;
    NTSTATUS status = read_value(key, valueName, data, sizeof(data), &type, &bytes);

    ok(NT_SUCCESS(status), "%s -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(type == REG_SZ, "%s type %lu", what, (unsigned long)type);
    ok(bytes <= sizeof(data) && wide_equals(data, bytes, expected), "%s payload (%lu bytes)", what,
       (unsigned long)bytes);
}

static void check_dword(HANDLE key, const void *valueName, ULONG expected, const char *what)
{
    UCHAR data[16];
    ULONG type = 0, bytes = 0;
    NTSTATUS status = read_value(key, valueName, data, sizeof(data), &type, &bytes);

    ok(NT_SUCCESS(status), "%s -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(type == REG_DWORD, "%s type %lu", what, (unsigned long)type);
    ok(bytes == 4, "%s length %lu", what, (unsigned long)bytes);
    if (bytes == 4)
        ok((ULONG)tzi_long(data, 0) == expected, "%s value %lu", what,
           (unsigned long)(ULONG)tzi_long(data, 0));
}

/* A TZI-shaped REG_BINARY: 44 bytes, with the three fields kernel32:time
 * asserts about. */
static void check_tzi(HANDLE key, const void *valueName, LONG bias, LONG daylightBias,
                      USHORT standardMonth, USHORT daylightMonth, const char *what)
{
    UCHAR data[TZI_BYTES];
    ULONG type = 0, bytes = 0;
    NTSTATUS status = read_value(key, valueName, data, sizeof(data), &type, &bytes);

    ok(NT_SUCCESS(status), "%s -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    ok(type == REG_BINARY, "%s type %lu", what, (unsigned long)type);
    ok(bytes == TZI_BYTES, "%s length %lu", what, (unsigned long)bytes);
    if (bytes != TZI_BYTES)
        return;
    ok(tzi_long(data, TZI_OFF_BIAS) == bias, "%s bias %ld", what,
       (long)tzi_long(data, TZI_OFF_BIAS));
    ok(tzi_long(data, TZI_OFF_DLT_BIAS) == daylightBias, "%s daylight bias %ld", what,
       (long)tzi_long(data, TZI_OFF_DLT_BIAS));
    ok(tzi_word(data, TZI_OFF_STD_MONTH) == standardMonth, "%s standard month %u", what,
       (unsigned)tzi_word(data, TZI_OFF_STD_MONTH));
    ok(tzi_word(data, TZI_OFF_DLT_MONTH) == daylightMonth, "%s daylight month %u", what,
       (unsigned)tzi_word(data, TZI_OFF_DLT_MONTH));
}

START_TEST(timezone_keys)
{
    NTSTATUS status;
    HANDLE zones = NULL, zone = NULL, dynamic = NULL;
    UCHAR raw[512];
    ULONG returned = 0;

    /* --- the table's own key ---------------------------------------------- */
    status = reg_open_path_access(TZ_KEY_PATH, KEY_READ, &zones);
    ok(NT_SUCCESS(status), "open Time Zones -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* A lower bound, not a count: see the header comment. 100 is far above
     * the one subkey (UTC) this pin was written against and far below the
     * pinned tree's own 139, so tzdata churn cannot make it lie either way. */
    status = NtQueryKey(zones, KEY_FULL_INFO_CLASS, raw, sizeof(raw), &returned);
    ok(NT_SUCCESS(status), "query Time Zones -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        reg_key_full_info *full = (reg_key_full_info *)raw;
        ok(full->sub_keys >= 100, "Time Zones has %lu subkeys", (unsigned long)full->sub_keys);
    }

    /* --- a zone with dynamic rules: values, types, and the year subkey ----- */
    status = reg_open_sub_access(zones, W("Greenland Standard Time"), KEY_READ, &zone);
    ok(NT_SUCCESS(status), "open Greenland -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_string(zone, W("Std"), W("Greenland Standard Time"), "Greenland Std");
        check_string(zone, W("Dlt"), W("Greenland Daylight Time"), "Greenland Dlt");
        check_string(zone, W("Display"), W("(UTC-03:00) Greenland"), "Greenland Display");
        check_string(zone, W("MUI_Std"), W("@tzres.dll,-58096"), "Greenland MUI_Std");
        /* The zone-level TZI is the FALLBACK arm; 2015 below is the one the
         * lookup actually takes, and they differ (120 vs 180). */
        check_tzi(zone, W("TZI"), 120, -60, 10, 1, "Greenland TZI");

        status = reg_open_sub_access(zone, W("Dynamic DST"), KEY_READ, &dynamic);
        ok(NT_SUCCESS(status), "open Greenland Dynamic DST -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            /* kernel32:time asserts bias 180 and months 10/3 for this year. */
            check_tzi(dynamic, W("2015"), 180, -60, 10, 3, "Greenland 2015");
            check_dword(dynamic, W("FirstEntry"), 2000, "Greenland FirstEntry");
            check_dword(dynamic, W("LastEntry"), 2030, "Greenland LastEntry");
            NtClose(dynamic);
            dynamic = NULL;
        }
        NtClose(zone);
        zone = NULL;
    }

    /* --- a second zone, whose 2016 rules invert the daylight bias ---------- */
    status = reg_open_sub_access(zones, W("Altai Standard Time"), KEY_READ, &zone);
    ok(NT_SUCCESS(status), "open Altai -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        status = reg_open_sub_access(zone, W("Dynamic DST"), KEY_READ, &dynamic);
        ok(NT_SUCCESS(status), "open Altai Dynamic DST -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            /* A POSITIVE daylight bias (+60), which is what kernel32:time's
             * Altai/2016 row is in the table for. */
            check_tzi(dynamic, W("2016"), -420, 60, 3, 1, "Altai 2016");
            check_dword(dynamic, W("LastEntry"), 2017, "Altai LastEntry");
            NtClose(dynamic);
            dynamic = NULL;
        }
        NtClose(zone);
        zone = NULL;
    }

    /* --- a zone with NO dynamic rules ------------------------------------- */
    status = reg_open_sub_access(zones, W("Afghanistan Standard Time"), KEY_READ, &zone);
    ok(NT_SUCCESS(status), "open Afghanistan -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_tzi(zone, W("TZI"), -270, -60, 0, 0, "Afghanistan TZI");
        status = reg_open_sub_access(zone, W("Dynamic DST"), KEY_READ, &dynamic);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "Afghanistan Dynamic DST -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(dynamic);
        dynamic = NULL;
        NtClose(zone);
        zone = NULL;
    }

    /* --- a daylight name is not a key name -------------------------------- */
    status = reg_open_sub_access(zones, W("Greenland Daylight Time"), KEY_READ, &zone);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "open Greenland Daylight Time -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(zone);

    NtClose(zones);
}
