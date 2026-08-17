/*
 * sem_reg/key_name_unaligned.c — NtQueryKey/NtEnumerateKey treat the output
 * buffer as BYTES, at whatever alignment the caller chose.
 *
 * The registry classes are one of the sets wow64.dll forwards untranslated:
 * wow64_NtQueryKey / wow64_NtEnumerateKey / wow64_NtEnumerateValueKey are
 * each a bare `return NtQueryKey( handle, class, info, len, retlen )` over a
 * `get_ptr`-ed pointer (third_party/wine dlls/wow64/registry.c), because the
 * KEY_*_INFORMATION shapes are the same 32-bit and 64-bit. So the caller's
 * own alignment is what the 64-bit kernel is handed.
 *
 * Every fixed field of every class in these structs is already staged and
 * copied; the one that was not is KeyNameInformation's NAME, which follows a
 * single ULONG and so sits four bytes into the caller's buffer. Writing it
 * through a `WCHAR *` derived from the buffer is a 2-byte store at an odd
 * address whenever the buffer is odd — undefined in C, and a trap in a UBSan
 * build. NT copies bytes: buffer+1 and buffer+2 must answer exactly like
 * buffer+0.
 *
 * The answers are compared byte for byte against the aligned one; the name is
 * read back with memcpy, so the TEST does not commit the access it pins
 * against.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#define REG_KeyBasicInformation ((ULONG)0)
#define REG_KeyNameInformation  ((ULONG)3)

#define REG_ROOT W("\\Registry\\Machine\\Software\\prsk_m8_nameunal")

/* 8-aligned slab the deltas offset into. */
static long long aligned_store[128];

static const unsigned deltas[] = {4, 2, 1};

START_TEST(key_name_unaligned)
{
    NTSTATUS status;
    HANDLE root = NULL, sub = NULL;
    ULONG disposition = 0;
    unsigned char baseline[512];
    ULONG baseLength = 0;
    unsigned i;

    status = reg_create_path(REG_ROOT, &root, &disposition);
    ok(status == STATUS_SUCCESS, "create root -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    status = reg_create_sub(root, W("child"), &sub, &disposition);
    ok(status == STATUS_SUCCESS, "create child -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(root);
        return;
    }

    /* --- KeyNameInformation on the child handle -------------------------- */
    memset(baseline, 0xa5, sizeof(baseline));
    status = NtQueryKey(sub, REG_KeyNameInformation, baseline, sizeof(baseline), &baseLength);
    ok(status == STATUS_SUCCESS, "aligned KeyNameInformation -> %08lx", (unsigned long)status);
    ok(baseLength > sizeof(ULONG), "aligned KeyNameInformation length %lu",
       (unsigned long)baseLength);

    for (i = 0; i < 3; i++)
    {
        unsigned char *at = (unsigned char *)aligned_store + deltas[i];
        ULONG length = 0;

        memset(aligned_store, 0xa5, sizeof(aligned_store));
        status = NtQueryKey(sub, REG_KeyNameInformation, at, (ULONG)(sizeof(aligned_store) - 8),
                            &length);
        ok(status == STATUS_SUCCESS, "KeyNameInformation +%u -> %08lx", deltas[i],
           (unsigned long)status);
        ok(length == baseLength, "KeyNameInformation +%u length %lu / %lu", deltas[i],
           (unsigned long)length, (unsigned long)baseLength);
        if (length == baseLength && length <= sizeof(baseline))
        {
            unsigned char got[512];
            memcpy(got, at, length);
            ok(memcmp(got, baseline, length) == 0, "KeyNameInformation +%u differs", deltas[i]);
        }
    }

    /* --- KeyBasicInformation through NtEnumerateKey ----------------------- *
     * Its name follows a LARGE_INTEGER and three ULONGs, so an odd buffer
     * misaligns the timestamp as well as the name. */
    memset(baseline, 0xa5, sizeof(baseline));
    baseLength = 0;
    status =
        NtEnumerateKey(root, 0, REG_KeyBasicInformation, baseline, sizeof(baseline), &baseLength);
    ok(status == STATUS_SUCCESS, "aligned enumerate -> %08lx", (unsigned long)status);
    for (i = 0; i < 3; i++)
    {
        unsigned char *at = (unsigned char *)aligned_store + deltas[i];
        ULONG length = 0;

        memset(aligned_store, 0xa5, sizeof(aligned_store));
        status = NtEnumerateKey(root, 0, REG_KeyBasicInformation, at,
                                (ULONG)(sizeof(aligned_store) - 8), &length);
        ok(status == STATUS_SUCCESS, "enumerate +%u -> %08lx", deltas[i], (unsigned long)status);
        ok(length == baseLength, "enumerate +%u length %lu / %lu", deltas[i], (unsigned long)length,
           (unsigned long)baseLength);
        if (length == baseLength && length <= sizeof(baseline))
        {
            unsigned char got[512];
            memcpy(got, at, length);
            ok(memcmp(got, baseline, length) == 0, "enumerate +%u differs", deltas[i]);
        }
    }

    NtDeleteKey(sub);
    NtClose(sub);
    NtDeleteKey(root);
    NtClose(root);
}
