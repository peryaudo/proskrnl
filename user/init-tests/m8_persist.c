/* user/init-tests/m8_persist.c — the M8 persistence acceptance client
 * (docs/02 "Done when: a value written by a user program survives reboot").
 *
 * A flat binary issuing raw Nt* through the generated stubs, run as a boot
 * module on EVERY boot. It is state-driven so one binary serves the
 * boot-twice harness (tests/run/run.sh persist): if its marker key is
 * absent this is the first boot — seed the values (and a volatile key that
 * must NOT survive) and say "m8_persist: seeded"; if present, verify every
 * byte survived the reboot, verify the volatile key vanished, and say
 * "m8_persist: verified". Exit 0 either way when the phase succeeded; a
 * distinct nonzero code per failed check.
 *
 * On a freshly built image (make test, run.sh proskrnl) only the seed phase
 * runs — cheap, and it keeps exercising the hive-write path every boot.
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntregapi.h"

#define WSTR(s) u##s

static void say(const char *ascii)
{
    WCHAR wide[64];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 63)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

static void init_ustr(UNICODE_STRING *str, const WCHAR *wide)
{
    USHORT n = 0;
    while (wide[n] != 0)
        n++;
    str->Length = (USHORT)(n * sizeof(WCHAR));
    str->MaximumLength = (USHORT)(str->Length + sizeof(WCHAR));
    str->Buffer = (PWSTR)wide;
}

static void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static const WCHAR software_path[] = WSTR("\\Registry\\Machine\\Software");
static const WCHAR key_path[] = WSTR("\\Registry\\Machine\\Software\\prsk_m8_persist");
static const WCHAR volatile_path[] = WSTR("\\Registry\\Machine\\Software\\prsk_m8_persist\\vol");
static const WCHAR stable_path[] = WSTR("\\Registry\\Machine\\Software\\prsk_m8_persist\\stable");

static const ULONG dword_data = 0x4d385247; /* 'M8RG' */
static const WCHAR sz_data[] = WSTR("survives-reboot");
static UCHAR binary_data[97];

static void fill_binary(void)
{
    for (unsigned i = 0; i < sizeof(binary_data); i++)
        binary_data[i] = (UCHAR)(i * 7 + 3);
}

static NTSTATUS create_key(const WCHAR *path, ULONG options, HANDLE *out, ULONG *disposition)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, 0, &name);
    return NtCreateKey(out, KEY_ALL_ACCESS, &attr, 0, 0, options, disposition);
}

static NTSTATUS open_key(const WCHAR *path, HANDLE *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, path);
    init_attr(&attr, 0, &name);
    return NtOpenKey(out, KEY_ALL_ACCESS, &attr);
}

static NTSTATUS set_value(HANDLE key, const WCHAR *valueName, ULONG type, const void *data,
                          ULONG bytes)
{
    UNICODE_STRING name;
    init_ustr(&name, valueName);
    return NtSetValueKey(key, &name, 0, type, data, bytes);
}

/* Query a value into buf; returns the status, fills *type/*bytes. */
static NTSTATUS get_value(HANDLE key, const WCHAR *valueName, void *buf, ULONG bufBytes,
                          ULONG *type, ULONG *bytes)
{
    UNICODE_STRING name;
    UCHAR info[192 + sizeof(KEY_VALUE_PARTIAL_INFORMATION)];
    ULONG resultLength = 0;
    init_ustr(&name, valueName);
    NTSTATUS status =
        NtQueryValueKey(key, &name, KeyValuePartialInformation, info, sizeof(info), &resultLength);
    if (status != STATUS_SUCCESS)
        return status;
    KEY_VALUE_PARTIAL_INFORMATION *partial = (KEY_VALUE_PARTIAL_INFORMATION *)info;
    *type = partial->Type;
    *bytes = partial->DataLength;
    if (partial->DataLength > bufBytes)
        return STATUS_BUFFER_OVERFLOW;
    for (ULONG i = 0; i < partial->DataLength; i++)
        ((UCHAR *)buf)[i] = partial->Data[i];
    return STATUS_SUCCESS;
}

static int seed(void)
{
    HANDLE software, key, vol, stable;
    ULONG disposition = 0;
    if (create_key(software_path, 0, &software, 0) != STATUS_SUCCESS)
        return 10;
    NtClose(software);
    if (create_key(key_path, 0, &key, &disposition) != STATUS_SUCCESS ||
        disposition != REG_CREATED_NEW_KEY)
        return 11;
    if (set_value(key, WSTR("dword"), REG_DWORD, &dword_data, sizeof(dword_data)) != STATUS_SUCCESS)
        return 12;
    if (set_value(key, WSTR("string"), REG_SZ, sz_data, sizeof(sz_data)) != STATUS_SUCCESS)
        return 13;
    if (set_value(key, WSTR("binary"), REG_BINARY, binary_data, sizeof(binary_data)) !=
        STATUS_SUCCESS)
        return 14;
    if (create_key(volatile_path, REG_OPTION_VOLATILE, &vol, 0) != STATUS_SUCCESS)
        return 15;
    if (set_value(vol, WSTR("gone"), REG_DWORD, &dword_data, sizeof(dword_data)) != STATUS_SUCCESS)
        return 16;
    NtClose(vol);
    if (create_key(stable_path, 0, &stable, 0) != STATUS_SUCCESS)
        return 17;
    NtClose(stable);
    NtClose(key);
    say("m8_persist: seeded\n");
    return 0;
}

static int verify(HANDLE key)
{
    UCHAR buf[128];
    ULONG type = 0, bytes = 0;
    HANDLE sub;

    if (get_value(key, WSTR("dword"), buf, sizeof(buf), &type, &bytes) != STATUS_SUCCESS ||
        type != REG_DWORD || bytes != sizeof(dword_data))
        return 20;
    if (*(ULONG *)buf != dword_data)
        return 21;
    if (get_value(key, WSTR("string"), buf, sizeof(buf), &type, &bytes) != STATUS_SUCCESS ||
        type != REG_SZ || bytes != sizeof(sz_data))
        return 22;
    for (unsigned i = 0; i < sizeof(sz_data); i++)
        if (buf[i] != ((const UCHAR *)sz_data)[i])
            return 23;
    if (get_value(key, WSTR("binary"), buf, sizeof(buf), &type, &bytes) != STATUS_SUCCESS ||
        type != REG_BINARY || bytes != sizeof(binary_data))
        return 24;
    for (unsigned i = 0; i < sizeof(binary_data); i++)
        if (buf[i] != binary_data[i])
            return 25;

    /* The volatile key must NOT have survived the reboot... */
    if (open_key(volatile_path, &sub) != STATUS_OBJECT_NAME_NOT_FOUND)
        return 26;
    /* ...the stable one must have. */
    if (open_key(stable_path, &sub) != STATUS_SUCCESS)
        return 27;
    NtClose(sub);

    say("m8_persist: verified\n");
    return 0;
}

int main(void)
{
    fill_binary();
    HANDLE key;
    NTSTATUS status = open_key(key_path, &key);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return seed(); /* first boot */
    if (status != STATUS_SUCCESS)
        return 9;
    int result = verify(key); /* second boot: the reboot survival check */
    NtClose(key);
    return result;
}
