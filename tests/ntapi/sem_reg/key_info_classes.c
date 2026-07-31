/*
 * sem_reg/key_info_classes.c — the three key/value info classes proskrnl used to
 * refuse.
 *
 * KeyNameInformation, KeyCachedInformation and
 * KeyValuePartialInformationAlign64 all returned STATUS_INVALID_PARAMETER,
 * credited to "wine's default arm" — but that arm sits BELOW the implemented
 * cases in both wine server/registry.c enumerate_key and
 * dlls/ntdll/unix/registry.c copy_key_value_info. Refusing
 * KeyNameInformation is what breaks RegOpenKeyEx with KEY_WOW64_32KEY.
 *
 * KeyNameInformation reports the FULL path, not the leaf component.
 */
#include "util.h"

/* Class numbers as wine/include/winternl.h orders KEY_INFORMATION_CLASS and
 * KEY_VALUE_INFORMATION_CLASS; the layouts as it declares them. mingw's
 * user-mode headers omit all three, so they are spelled here like every
 * other struct in this suite. */
#define KEY_NAME_INFO_CLASS      3 /* KeyNameInformation */
#define KEY_CACHED_INFO_CLASS    4 /* KeyCachedInformation */
#define KV_PARTIAL_ALIGN64_CLASS 4 /* KeyValuePartialInformationAlign64 */

typedef struct
{
    ULONG name_length;
    WCHAR name[1];
} key_name_info;

typedef struct
{
    LONGLONG last_write_time;
    ULONG title_index;
    ULONG subkeys;
    ULONG max_name_len;
    ULONG values;
    ULONG max_value_name_len;
    ULONG max_value_data_len;
    ULONG name_length;
} key_cached_info;

typedef struct
{
    ULONG type;
    ULONG data_length;
    UCHAR data[1];
} kv_partial_align64_info;


static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_infocls");

START_TEST(key_info_classes)
{
    HANDLE key = NULL;
    NTSTATUS status;
    ULONG length = 0;
    UNICODE_STRING valueName;
    unsigned char buffer[512];
    static const unsigned char payload[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

    reg_delete_path(base_path);
    status = reg_create_path(base_path, &key, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* --- KeyNameInformation: the whole path ------------------------------- */
    memset(buffer, 0, sizeof(buffer));
    status = NtQueryKey(key, KEY_NAME_INFO_CLASS, buffer, sizeof(buffer), &length);
    ok(status == STATUS_SUCCESS, "KeyNameInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        key_name_info *info = (key_name_info *)buffer;
        const WCHAR *want = (const WCHAR *)base_path;
        unsigned want_units = 0;
        while (want[want_units])
            want_units++;
        ok(info->name_length == want_units * sizeof(WCHAR),
           "KeyNameInformation NameLength %lu, wanted %lu", (unsigned long)info->name_length,
           (unsigned long)(want_units * sizeof(WCHAR)));
        ok(length == (ULONG)((ULONG)offsetof(key_name_info, name) + info->name_length),
           "KeyNameInformation ResultLength %lu", (unsigned long)length);
        if (info->name_length == want_units * sizeof(WCHAR))
        {
            unsigned i, same = 1;
            for (i = 0; i < want_units; i++)
            {
                WCHAR a = info->name[i], b = want[i];
                if (a >= 'A' && a <= 'Z')
                    a = (WCHAR)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z')
                    b = (WCHAR)(b - 'A' + 'a');
                if (a != b)
                    same = 0;
            }
            ok(same, "KeyNameInformation is the full path, not the leaf");
        }
    }

    /* A short buffer still reports the required size. */
    length = 0;
    status = NtQueryKey(key, KEY_NAME_INFO_CLASS, buffer,
                        (ULONG)(ULONG)offsetof(key_name_info, name), &length);
    ok(status == STATUS_BUFFER_OVERFLOW, "short KeyNameInformation -> %08lx",
       (unsigned long)status);
    ok(length > (ULONG)(ULONG)offsetof(key_name_info, name),
       "short KeyNameInformation ResultLength %lu", (unsigned long)length);

    /* --- KeyCachedInformation --------------------------------------------- */
    memset(buffer, 0, sizeof(buffer));
    length = 0;
    status = NtQueryKey(key, KEY_CACHED_INFO_CLASS, buffer, sizeof(buffer), &length);
    ok(status == STATUS_SUCCESS, "KeyCachedInformation -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        key_cached_info *info = (key_cached_info *)buffer;
        ok(length == sizeof(key_cached_info), "KeyCachedInformation ResultLength %lu",
           (unsigned long)length);
        ok(info->subkeys == 0, "KeyCachedInformation SubKeys %lu", (unsigned long)info->subkeys);
        ok(info->values == 0, "KeyCachedInformation Values %lu", (unsigned long)info->values);
        ok(info->name_length == sizeof(WCHAR) * 12 /* "prsk_infocls" */,
           "KeyCachedInformation NameLength %lu", (unsigned long)info->name_length);
    }

    /* --- KeyValuePartialInformationAlign64 -------------------------------- */
    init_ustr(&valueName, W("blob"));
    status = NtSetValueKey(key, &valueName, 0, REG_BINARY, (void *)payload, sizeof(payload));
    ok(status == STATUS_SUCCESS, "set blob -> %08lx", (unsigned long)status);

    memset(buffer, 0, sizeof(buffer));
    length = 0;
    status = NtQueryValueKey(key, &valueName, KV_PARTIAL_ALIGN64_CLASS, buffer,
                             sizeof(buffer), &length);
    ok(status == STATUS_SUCCESS, "KeyValuePartialInformationAlign64 -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        kv_partial_align64_info *info = (kv_partial_align64_info *)buffer;
        ok(info->type == REG_BINARY, "align64 Type %lu", (unsigned long)info->type);
        ok(info->data_length == sizeof(payload), "align64 DataLength %lu",
           (unsigned long)info->data_length);
        ok(memcmp(info->data, payload, sizeof(payload)) == 0, "align64 data round-trip");
        ok(length ==
               (ULONG)((ULONG)offsetof(kv_partial_align64_info, data) + sizeof(payload)),
           "align64 ResultLength %lu", (unsigned long)length);
    }

    /* The data really is 8-aligned, i.e. the header is 8 bytes not 12. */
    ok((ULONG)offsetof(kv_partial_align64_info, data) == 8, "align64 header size");

    NtDeleteKey(key);
    NtClose(key);
}
