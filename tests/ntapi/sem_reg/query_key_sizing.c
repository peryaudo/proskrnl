/*
 * sem_reg/query_key_sizing.c — asking NtQueryKey how big a buffer to bring.
 *
 * Convicted by the winetest gate: ntdll:reg took proskrnl down with a
 * `#UD invalid opcode` panic whose RIP was the `ud1l` clang parks after
 * CmpFillKeyInfo — a UBSan trap, with RBX (the output buffer) zero. The
 * cause is the ordinary two-call idiom every registry caller uses:
 *
 *     NtQueryKey(key, KeyNameInformation, NULL, 0, &needed);   <-- traps
 *     buffer = alloc(needed);
 *     NtQueryKey(key, KeyNameInformation, buffer, needed, &needed);
 *
 * The first call computed `(WCHAR *)((UCHAR *)NULL + fixed)` before ever
 * looking at the length. Arithmetic on a null pointer is undefined even
 * when the result is never dereferenced, and the kernel is built with
 * -fsanitize=undefined -fsanitize-trap=undefined, so it was fatal.
 *
 * The sizing call is pinned here for every KEY_INFORMATION_CLASS the kernel
 * implements, because the buggy pointer form appeared in exactly one of
 * them and only a per-class pin says the others are safe. A short-but-
 * non-zero buffer is pinned alongside it: that is the other shape where
 * the fixed header is copied truncated and the variable part is cut, and
 * it distinguishes STATUS_BUFFER_TOO_SMALL from STATUS_BUFFER_OVERFLOW.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* KEY_INFORMATION_CLASS values, as wine/include/winternl.h orders them. */
#define KeyBasicInformation  0
#define KeyNodeInformation   1
#define KeyFullInformation   2
#define KeyNameInformation   3
#define KeyCachedInformation 4

static const struct
{
    ULONG cls;
    const char *name;
} classes[] = {
    {KeyBasicInformation, "KeyBasicInformation"},   {KeyNodeInformation, "KeyNodeInformation"},
    {KeyFullInformation, "KeyFullInformation"},     {KeyNameInformation, "KeyNameInformation"},
    {KeyCachedInformation, "KeyCachedInformation"},
};

START_TEST(query_key_sizing)
{
    NTSTATUS status;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key = NULL;
    ULONG needed;
    UCHAR buffer[512];

    init_ustr(&name, W("\\Registry\\Machine\\Software"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenKey(&key, KEY_READ, &attr);
    ok(status == STATUS_SUCCESS, "open Software -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    for (unsigned i = 0; i < ARRAY_SIZE(classes); i++)
    {
        /* --- the sizing call: NULL buffer, zero length ------------------- */
        needed = 0xdeadbeef;
        status = NtQueryKey(key, classes[i].cls, NULL, 0, &needed);
        ok(status == STATUS_BUFFER_TOO_SMALL, "%s: size query -> %08lx", classes[i].name,
           (unsigned long)status);
        ok(needed != 0 && needed != 0xdeadbeef, "%s: size query returned %lu", classes[i].name,
           (unsigned long)needed);
        if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > sizeof(buffer))
            continue;

        /* --- the buffer the sizing call asked for is enough --------------- */
        ULONG full = needed;
        needed = 0xdeadbeef;
        memset(buffer, 0xcc, sizeof(buffer));
        status = NtQueryKey(key, classes[i].cls, buffer, full, &needed);
        ok(status == STATUS_SUCCESS, "%s: full query -> %08lx", classes[i].name,
           (unsigned long)status);
        ok(needed == full, "%s: full query wanted %lu, sizing said %lu", classes[i].name,
           (unsigned long)needed, (unsigned long)full);

        /* --- one byte short of the FIXED header is TOO_SMALL -------------- */
        needed = 0xdeadbeef;
        status = NtQueryKey(key, classes[i].cls, buffer, 1, &needed);
        ok(status == STATUS_BUFFER_TOO_SMALL, "%s: 1-byte query -> %08lx", classes[i].name,
           (unsigned long)status);
        ok(needed == full, "%s: 1-byte query wanted %lu, expected %lu", classes[i].name,
           (unsigned long)needed, (unsigned long)full);
    }

    /* A NULL buffer with a NON-ZERO length is deliberately NOT pinned: the
     * oracle cannot specify it. Wine hands the server `data_ptr` computed
     * off the null info pointer as the reply buffer whenever
     * `length > fixed_size` (unix/registry.c enumerate_key), and the run
     * dies with "wine client error: read: Bad address" — measured. Only the
     * length == 0 sizing call above is a real contract. */
    NtClose(key);
}
