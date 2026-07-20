/*
 * sem_reg/enum_key.c — NtEnumerateKey/NtEnumerateValueKey/NtQueryKey.
 *
 * Subkey enumeration is index-based and returns every subkey exactly once,
 * ending with STATUS_NO_MORE_ENTRIES; value enumeration likewise.
 * NtQueryKey(KeyFullInformation) reports the subkey/value counts and the
 * max name/data lengths the enumeration loop needs for buffer sizing.
 */
#include "util.h"

static const void *key_path = W("\\Registry\\Machine\\Software\\prsk_m8_enum");

/* Created deliberately out of alphabetical order. */
static const void *sub_names[3] = {W("zeta"), W("alpha"), W("mid")};
static const unsigned sub_name_chars[3] = {4, 5, 3};

START_TEST(enum_key)
{
    UNICODE_STRING name;
    HANDLE key, sub;
    UCHAR buffer[512];
    ULONG result_len, i;
    unsigned seen[3] = {0, 0, 0};
    NTSTATUS status;
    reg_key_basic_info *kinfo = (reg_key_basic_info *)buffer;
    reg_kv_full_info *vinfo = (reg_kv_full_info *)buffer;
    reg_key_full_info *finfo = (reg_key_full_info *)buffer;

    reg_ensure_software();

    for (i = 0; i < 3; i++)
    {
        HANDLE stale;
        UNICODE_STRING sname;
        OBJECT_ATTRIBUTES sattr;
        init_ustr(&sname, sub_names[i]);
        /* fresh slate: delete leftovers from a dead previous run */
        if (NT_SUCCESS(reg_open_path(key_path, &stale)))
        {
            OBJECT_ATTRIBUTES rel;
            HANDLE leftover;
            init_attr(&rel, stale, &sname, OBJ_CASE_INSENSITIVE);
            if (NT_SUCCESS(NtOpenKey(&leftover, KEY_ALL_ACCESS, &rel)))
            {
                NtDeleteKey(leftover);
                NtClose(leftover);
            }
            NtClose(stale);
        }
        (void)sattr;
    }
    reg_delete_path(key_path);

    status = reg_create_path(key_path, &key, NULL);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    /* An empty key: index 0 is already out of range, and full-info counts
     * are zero. */
    status = NtEnumerateKey(key, 0, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_NO_MORE_ENTRIES, "enumerate empty -> %08lx", (unsigned long)status);
    status = NtEnumerateValueKey(key, 0, KV_FULL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_NO_MORE_ENTRIES, "enumerate empty values -> %08lx", (unsigned long)status);
    status = NtQueryKey(key, KEY_FULL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query full (empty) -> %08lx", (unsigned long)status);
    ok(finfo->sub_keys == 0 && finfo->values == 0, "empty counts %lu/%lu",
       (unsigned long)finfo->sub_keys, (unsigned long)finfo->values);

    /* Three subkeys + two values. */
    for (i = 0; i < 3; i++)
    {
        status = reg_create_sub(key, sub_names[i], &sub, NULL);
        ok(status == STATUS_SUCCESS, "create sub %lu -> %08lx", (unsigned long)i,
           (unsigned long)status);
        NtClose(sub);
    }
    {
        ULONG val = 1;
        status = reg_set(key, W("value_one"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set value_one -> %08lx", (unsigned long)status);
        status = reg_set(key, W("v2"), REG_SZ, W("x"), 2 * sizeof(WCHAR));
        ok(status == STATUS_SUCCESS, "set v2 -> %08lx", (unsigned long)status);
    }

    /* Subkey enumeration: each name comes back exactly once. */
    for (i = 0; i < 3; i++)
    {
        ULONG j;
        status = NtEnumerateKey(key, i, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_SUCCESS, "enumerate %lu -> %08lx", (unsigned long)i,
           (unsigned long)status);
        if (status != STATUS_SUCCESS)
            continue;
        for (j = 0; j < 3; j++)
        {
            if (kinfo->name_length == sub_name_chars[j] * sizeof(WCHAR) &&
                __builtin_memcmp(kinfo->name, sub_names[j], kinfo->name_length) == 0)
            {
                seen[j]++;
                break;
            }
        }
        ok(j < 3, "enumerated name %lu not one of ours (name_length %lu)", (unsigned long)i,
           (unsigned long)kinfo->name_length);
    }
    ok(seen[0] == 1 && seen[1] == 1 && seen[2] == 1, "subkey coverage %u/%u/%u", seen[0], seen[1],
       seen[2]);
    status = NtEnumerateKey(key, 3, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_NO_MORE_ENTRIES, "enumerate past end -> %08lx", (unsigned long)status);

    /* Value enumeration: both names, then NO_MORE_ENTRIES. */
    {
        unsigned seen_one = 0, seen_two = 0;
        for (i = 0; i < 2; i++)
        {
            status = NtEnumerateValueKey(key, i, KV_FULL_INFO_CLASS, buffer, sizeof(buffer),
                                         &result_len);
            ok(status == STATUS_SUCCESS, "enumerate value %lu -> %08lx", (unsigned long)i,
               (unsigned long)status);
            if (status != STATUS_SUCCESS)
                continue;
            if (vinfo->name_length == 9 * sizeof(WCHAR) &&
                __builtin_memcmp(vinfo->name, W("value_one"), vinfo->name_length) == 0)
                seen_one++;
            if (vinfo->name_length == 2 * sizeof(WCHAR) &&
                __builtin_memcmp(vinfo->name, W("v2"), vinfo->name_length) == 0)
                seen_two++;
        }
        ok(seen_one == 1 && seen_two == 1, "value coverage %u/%u", seen_one, seen_two);
        status =
            NtEnumerateValueKey(key, 2, KV_FULL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
        ok(status == STATUS_NO_MORE_ENTRIES, "enumerate values past end -> %08lx",
           (unsigned long)status);
    }

    /* Full information counts + maxima over what we just created. */
    status = NtQueryKey(key, KEY_FULL_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query full -> %08lx", (unsigned long)status);
    ok(finfo->sub_keys == 3 && finfo->values == 2, "counts %lu/%lu", (unsigned long)finfo->sub_keys,
       (unsigned long)finfo->values);
    ok(finfo->max_name_len == 5 * sizeof(WCHAR), "max_name_len %lu",
       (unsigned long)finfo->max_name_len);
    ok(finfo->max_value_name_len == 9 * sizeof(WCHAR), "max_value_name_len %lu",
       (unsigned long)finfo->max_value_name_len);
    ok(finfo->max_value_data_len == sizeof(ULONG), "max_value_data_len %lu",
       (unsigned long)finfo->max_value_data_len);

    /* KeyBasicInformation on the key itself reports the key's leaf name. */
    status = NtQueryKey(key, KEY_BASIC_INFO_CLASS, buffer, sizeof(buffer), &result_len);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    ok(kinfo->name_length == 12 * sizeof(WCHAR) &&
           __builtin_memcmp(kinfo->name, W("prsk_m8_enum"), 12 * sizeof(WCHAR)) == 0,
       "query basic name_length %lu", (unsigned long)kinfo->name_length);

    /* Cleanup: subkeys, then the key. */
    for (i = 0; i < 3; i++)
        reg_delete_sub(key, sub_names[i]);
    {
        UNICODE_STRING vname;
        init_ustr(&vname, W("value_one"));
        NtDeleteValueKey(key, &vname);
        init_ustr(&vname, W("v2"));
        NtDeleteValueKey(key, &vname);
    }
    status = NtDeleteKey(key);
    ok(status == STATUS_SUCCESS, "cleanup delete -> %08lx", (unsigned long)status);
    NtClose(key);
    (void)name;
}
