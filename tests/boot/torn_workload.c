/* tests/boot/torn_workload.c — the deterministic torn-write workload
 * (tests/run/run.sh tornwrite; replayed prefix-by-prefix by
 * tests/run/tornreplay.py).
 *
 * A flat binary issuing raw Nt* through the generated stubs (the
 * m8_persist.c mold), baked ONLY into the tornwrite leg's image with
 * cmdline expect=0. It exercises every disk-write shape in a short,
 * deterministic burst — every block write QEMU logs during this run is a
 * reachable power-loss point:
 *
 *   - file data + chain growth: create \??\C:\torn\a.dat, write four
 *     512-byte generation-1 blocks, extend it (cluster allocation: FAT
 *     sectors x2 mirrored copies + the directory entry), overwrite with
 *     generation 2 in place
 *   - directory-entry churn: create + delete b.dat (0xE5 marks), create an
 *     LFN-requiring name (multi-slot runs)
 *   - hive rewrites: eight NtSetValueKey mutations under
 *     \Registry\Machine\Software\prsk_torn — each one a full hive rewrite
 *     (truncate, body with magic 0, then the magic: the exact torn window
 *     kernel/cm/hive.c promises falls back to an empty registry)
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntioapi.h"
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

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = 0;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

/* Sentinel block: byte j of block b, generation g. */
static void fill_block(unsigned char *block, unsigned b, unsigned g)
{
    for (unsigned j = 0; j < 512; j++)
        block[j] = (unsigned char)(b * 37 + g * 101 + j * 7 + 5);
}

static NTSTATUS open_file(HANDLE *h, const WCHAR *path, ACCESS_MASK access, ULONG disposition,
                          ULONG options)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    init_ustr(&name, path);
    init_attr(&attr, &name);
    *h = 0;
    return NtCreateFile(h, access, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, disposition,
                        options | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

static NTSTATUS write_blocks(HANDLE h, unsigned firstBlock, unsigned count, unsigned generation,
                             unsigned long long atByte)
{
    static unsigned char block[512];
    IO_STATUS_BLOCK iosb;
    for (unsigned b = 0; b < count; b++)
    {
        fill_block(block, firstBlock + b, generation);
        LARGE_INTEGER offset;
        offset.QuadPart = (LONGLONG)(atByte + (unsigned long long)b * 512);
        NTSTATUS status = NtWriteFile(h, 0, 0, 0, &iosb, block, 512, &offset, 0);
        if (status != STATUS_SUCCESS)
            return status;
    }
    return STATUS_SUCCESS;
}

static int run_files(void)
{
    HANDLE dir, h;
    IO_STATUS_BLOCK iosb;

    if (open_file(&dir, WSTR("\\??\\C:\\torn"), FILE_LIST_DIRECTORY | FILE_ADD_FILE | SYNCHRONIZE,
                  FILE_OPEN_IF, FILE_DIRECTORY_FILE) != STATUS_SUCCESS)
        return 30;
    NtClose(dir);

    /* a.dat: four generation-1 blocks, extend to eight, regen the middle. */
    if (open_file(&h, WSTR("\\??\\C:\\torn\\a.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE) != STATUS_SUCCESS)
        return 31;
    if (write_blocks(h, 0, 4, 1, 0) != STATUS_SUCCESS)
        return 32;
    if (write_blocks(h, 4, 4, 1, 4 * 512) != STATUS_SUCCESS)
        return 33;
    if (write_blocks(h, 1, 2, 2, 1 * 512) != STATUS_SUCCESS)
        return 34;
    NtClose(h);

    /* b.dat: create then delete (0xE5 free marks in the directory). */
    if (open_file(&h, WSTR("\\??\\C:\\torn\\b.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                  FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE) != STATUS_SUCCESS)
        return 35;
    if (write_blocks(h, 16, 2, 1, 0) != STATUS_SUCCESS)
        return 36;
    NtClose(h);
    if (open_file(&h, WSTR("\\??\\C:\\torn\\b.dat"), DELETE | SYNCHRONIZE, FILE_OPEN,
                  FILE_NON_DIRECTORY_FILE) != STATUS_SUCCESS)
        return 37;
    {
        FILE_DISPOSITION_INFORMATION disposition;
        disposition.DoDeleteFile = TRUE;
        if (NtSetInformationFile(h, &iosb, &disposition, sizeof(disposition),
                                 FileDispositionInformation) != STATUS_SUCCESS)
            return 38;
    }
    NtClose(h);

    /* An LFN-requiring name: a multi-slot directory-entry run. */
    if (open_file(&h, WSTR("\\??\\C:\\torn\\Torn Long Name File.dat"),
                  FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OVERWRITE_IF,
                  FILE_NON_DIRECTORY_FILE) != STATUS_SUCCESS)
        return 39;
    if (write_blocks(h, 32, 3, 1, 0) != STATUS_SUCCESS)
        return 40;
    NtClose(h);
    return 0;
}

static int run_registry(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key;
    ULONG disposition;

    /* NtCreateKey does not create intermediate keys, and the minimal
     * tornwrite image boots with an empty registry (no baked hive) — the
     * m8_persist precedent: create Software first. */
    init_ustr(&name, WSTR("\\Registry\\Machine\\Software"));
    init_attr(&attr, &name);
    if (NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, 0, 0, &disposition) != STATUS_SUCCESS)
        return 49;
    NtClose(key);

    init_ustr(&name, WSTR("\\Registry\\Machine\\Software\\prsk_torn"));
    init_attr(&attr, &name);
    if (NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, 0, 0, &disposition) != STATUS_SUCCESS)
        return 50;

    /* Eight mutations = eight full hive rewrites (each one a torn window). */
    static const WCHAR *const names[8] = {WSTR("v0"), WSTR("v1"), WSTR("v2"), WSTR("v3"),
                                          WSTR("v4"), WSTR("v5"), WSTR("v6"), WSTR("v7")};
    for (unsigned i = 0; i < 8; i++)
    {
        UNICODE_STRING valueName;
        UCHAR data[64];
        for (unsigned j = 0; j < sizeof(data); j++)
            data[j] = (UCHAR)(i * 53 + j * 11 + 7);
        init_ustr(&valueName, names[i]);
        if (NtSetValueKey(key, &valueName, 0, REG_BINARY, data, sizeof(data)) != STATUS_SUCCESS)
        {
            NtClose(key);
            return 51;
        }
    }
    NtClose(key);
    return 0;
}

int main(void)
{
    int rc = run_files();
    if (rc != 0)
        return rc;
    rc = run_registry();
    if (rc != 0)
        return rc;
    say("torn_workload: done\n");
    return 0;
}
