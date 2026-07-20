/*
 * sem_reg/values.c — NtSetValueKey/NtQueryValueKey/NtDeleteValueKey.
 *
 * Value types round-trip byte-exactly (REG_SZ/REG_DWORD/REG_BINARY/
 * REG_MULTI_SZ); setting an existing name overwrites type and data; the
 * unnamed (default) value is a value like any other with an empty name; the
 * three query info classes carry the documented headers and their
 * short-buffer statuses differ (TOO_SMALL for a buffer smaller than the fixed
 * header, OVERFLOW when only the variable part is cut).
 */
#include "util.h"

static const void *key_path = W("\\Registry\\Machine\\Software\\prsk_m8_values");

static const WCHAR sz_data[] = W("registry-string");
static const WCHAR multi_data[] = W("one\0two\0"); /* + implicit terminating NUL */
static const UCHAR bin_data[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x55};

START_TEST(values)
{
    UNICODE_STRING name;
    HANDLE key;
    UCHAR buffer[256];
    ULONG result_len;
    NTSTATUS status;
    reg_kv_partial_info *partial = (reg_kv_partial_info *)buffer;
    reg_kv_full_info *full = (reg_kv_full_info *)buffer;
    reg_kv_basic_info *basic = (reg_kv_basic_info *)buffer;

    reg_ensure_software();
    reg_delete_path(key_path);
    status = reg_create_path(key_path, &key, NULL);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* REG_DWORD round-trip through KeyValuePartialInformation. */
    {
        ULONG val = 0xa1b2c3d4, got = 0;
        status = reg_set(key, W("dword"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set dword -> %08lx", (unsigned long)status);
        init_ustr(&name, W("dword"));
        result_len = 0;
        status =
            NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_SUCCESS, "query dword -> %08lx", (unsigned long)status);
        ok(partial->type == REG_DWORD, "type %lu", (unsigned long)partial->type);
        ok(partial->data_length == sizeof(val), "data_length %lu",
           (unsigned long)partial->data_length);
        __builtin_memcpy(&got, partial->data, sizeof(got));
        ok(got == val, "dword data %08lx", (unsigned long)got);
        ok(result_len == (ULONG)((UCHAR *)partial->data - buffer) + sizeof(val), "result_len %lu",
           (unsigned long)result_len);
    }

    /* REG_SZ round-trip (Length includes the terminating NUL as written). */
    status = reg_set(key, W("string"), REG_SZ, sz_data, sizeof(sz_data));
    ok(status == STATUS_SUCCESS, "set string -> %08lx", (unsigned long)status);
    init_ustr(&name, W("string"));
    status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query string -> %08lx", (unsigned long)status);
    ok(partial->type == REG_SZ && partial->data_length == sizeof(sz_data) &&
           __builtin_memcmp(partial->data, sz_data, sizeof(sz_data)) == 0,
       "string round-trip mismatch (type %lu len %lu)", (unsigned long)partial->type,
       (unsigned long)partial->data_length);

    /* REG_BINARY + REG_MULTI_SZ round-trip. */
    status = reg_set(key, W("binary"), REG_BINARY, bin_data, sizeof(bin_data));
    ok(status == STATUS_SUCCESS, "set binary -> %08lx", (unsigned long)status);
    status = reg_set(key, W("multi"), REG_MULTI_SZ, multi_data, sizeof(multi_data));
    ok(status == STATUS_SUCCESS, "set multi -> %08lx", (unsigned long)status);
    init_ustr(&name, W("binary"));
    status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS && partial->type == REG_BINARY &&
           partial->data_length == sizeof(bin_data) &&
           __builtin_memcmp(partial->data, bin_data, sizeof(bin_data)) == 0,
       "binary round-trip -> %08lx", (unsigned long)status);

    /* Overwrite: same name, new type and data. */
    {
        ULONG val = 7;
        status = reg_set(key, W("string"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "overwrite -> %08lx", (unsigned long)status);
        init_ustr(&name, W("string"));
        status =
            NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_SUCCESS && partial->type == REG_DWORD &&
               partial->data_length == sizeof(val),
           "overwrite left old type/data (%08lx type %lu)", (unsigned long)status,
           (unsigned long)partial->type);
    }

    /* The default value: an empty name. */
    {
        ULONG val = 0x5a5a5a5a;
        UNICODE_STRING empty;
        empty.Length = 0;
        empty.MaximumLength = 0;
        empty.Buffer = NULL;
        status = NtSetValueKey(key, &empty, 0, REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set default -> %08lx", (unsigned long)status);
        status = NtQueryValueKey(key, &empty, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer),
                                 &result_len);
        ok(status == STATUS_SUCCESS && partial->data_length == sizeof(val),
           "query default -> %08lx", (unsigned long)status);
        status = NtDeleteValueKey(key, &empty);
        ok(status == STATUS_SUCCESS, "delete default -> %08lx", (unsigned long)status);
    }

    /* KeyValueFullInformation carries name AND data (data at data_offset);
     * KeyValueBasicInformation carries the name only. */
    init_ustr(&name, W("binary"));
    result_len = 0;
    status = NtQueryValueKey(key, &name, KV_FULL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query full -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        ok(full->type == REG_BINARY && full->name_length == 6 * sizeof(WCHAR),
           "full header (type %lu name_length %lu)", (unsigned long)full->type,
           (unsigned long)full->name_length);
        ok(__builtin_memcmp(full->name, W("binary"), 6 * sizeof(WCHAR)) == 0, "full name bytes");
        ok(full->data_length == sizeof(bin_data) &&
               __builtin_memcmp(buffer + full->data_offset, bin_data, sizeof(bin_data)) == 0,
           "full data at data_offset %lu", (unsigned long)full->data_offset);
    }
    status = NtQueryValueKey(key, &name, KV_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    ok(basic->type == REG_BINARY && basic->name_length == 6 * sizeof(WCHAR),
       "basic header (type %lu name_length %lu)", (unsigned long)basic->type,
       (unsigned long)basic->name_length);

    /* Short-buffer statuses: smaller than the fixed header -> TOO_SMALL with
     * the needed size; header fits but data cut -> OVERFLOW. */
    init_ustr(&name, W("binary"));
    result_len = 0;
    status = NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, 4, &result_len);
    ok(status == STATUS_BUFFER_TOO_SMALL, "tiny buffer -> %08lx", (unsigned long)status);
    ok(result_len == (ULONG)((UCHAR *)partial->data - buffer) + sizeof(bin_data),
       "tiny buffer result_len %lu", (unsigned long)result_len);
    result_len = 0;
    status = NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer,
                             (ULONG)((UCHAR *)partial->data - buffer) + 2, &result_len);
    ok(status == STATUS_BUFFER_OVERFLOW, "cut data -> %08lx", (unsigned long)status);
    ok(result_len == (ULONG)((UCHAR *)partial->data - buffer) + sizeof(bin_data),
       "cut data result_len %lu", (unsigned long)result_len);

    /* Missing value name. */
    init_ustr(&name, W("prsk_no_such_value"));
    status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "query missing -> %08lx", (unsigned long)status);
    status = NtDeleteValueKey(key, &name);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "delete missing -> %08lx", (unsigned long)status);

    /* Value-name lookup is case-insensitive. */
    init_ustr(&name, W("BINARY"));
    status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "case-mangled value query -> %08lx", (unsigned long)status);

    /* Delete a value; it is gone. */
    init_ustr(&name, W("binary"));
    status = NtDeleteValueKey(key, &name);
    ok(status == STATUS_SUCCESS, "delete value -> %08lx", (unsigned long)status);
    status =
        NtQueryValueKey(key, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "query deleted value -> %08lx",
       (unsigned long)status);

    /* A non-key handle is a type mismatch, not a crash. */
    {
        HANDLE event;
        OBJECT_ATTRIBUTES attr;
        init_attr(&attr, NULL, NULL, 0);
        status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, 0 /* NotificationEvent */, FALSE);
        ok(status == STATUS_SUCCESS, "anonymous event -> %08lx", (unsigned long)status);
        init_ustr(&name, W("dword"));
        status = NtQueryValueKey(event, &name, KV_PARTIAL_INFO_CLASS, buffer, sizeof(buffer),
                                 &result_len);
        ok(status == STATUS_OBJECT_TYPE_MISMATCH, "query on event handle -> %08lx",
           (unsigned long)status);
        NtClose(event);
    }

    /* Cleanup. */
    status = NtDeleteKey(key);
    ok(status == STATUS_SUCCESS, "cleanup delete -> %08lx", (unsigned long)status);
    NtClose(key);
}
