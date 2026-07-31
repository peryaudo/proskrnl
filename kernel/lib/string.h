/* kernel/lib/string.h — freestanding memory intrinsics + the NUL-terminated
 * string primitives the kernel has no libc for (M2). See string.c.
 *
 * The mem* four are the compiler-mandated set. Everything below them is the
 * strlen/strcmp corner a freestanding kernel still needs: boot-module
 * cmdlines, RAM-disk names, PE export names, device query names. They live
 * here as the ONE authority (Art. 11) — every department that used to carry
 * its own copy of the same three loops now calls these, and tests/kmt/lib.c
 * is where their behavior is pinned.
 *
 * They are `static inline` rather than out-of-line like the mem* four
 * because string.c is compiled UNINSTRUMENTED for KASAN (see its header
 * comment and the Makefile); inlined into the caller's translation unit,
 * these get the caller's instrumentation and a walk off the end of a pooled
 * name is caught.
 */
#ifndef PROSKRNL_KERNEL_LIB_STRING_H
#define PROSKRNL_KERNEL_LIB_STRING_H

#include "abi/ntdef.h"
#include <stddef.h>
#include <stdint.h>

/* Compiler-mandated names: clang emits calls to these under -ffreestanding,
 * so the docs/15 naming rules are waived for them. */
/* NOLINTBEGIN(readability-identifier-naming) */
void *memset(void *destination, int value, size_t length);
void *memcpy(void *destination, const void *source, size_t length);
void *memmove(void *destination, const void *source, size_t length);
int memcmp(const void *left, const void *right, size_t length);
/* NOLINTEND(readability-identifier-naming) */

/* strlen: characters before the NUL. NT does export strlen/wcslen from
 * ntoskrnl, but wcslen takes `const wchar_t *` (32-bit under this compiler)
 * while our WCHAR is 16-bit — a real NT name with the wrong signature is
 * what docs/15 forbids, so these carry internal Ki names. */
static inline uint64_t KiStringLength(const char *s)
{
    uint64_t n = 0;
    while (s[n] != '\0')
    {
        n++;
    }
    return n;
}

static inline uint64_t KiWideStringLength(const WCHAR *s)
{
    uint64_t n = 0;
    while (s[n] != 0)
    {
        n++;
    }
    return n;
}

/* strcmp()==0. Case-sensitive: every caller compares names the kernel or the
 * boot image produced, never user-facing text. */
static inline BOOLEAN KiStringEquals(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b)
    {
        a++;
        b++;
    }
    return *a == *b;
}

/* KiStringEquals for a `b` that is NOT known to be NUL-terminated: compares
 * at most `bBytes` bytes of it, and a run of bytes that ends without a NUL
 * inside that window is NOT equal. For parsing untrusted images, where the
 * "string" is whatever the file happens to hold at an offset. */
static inline BOOLEAN KiStringEqualsWithin(const char *a, const char *b, uint64_t bBytes)
{
    uint64_t i = 0;
    for (;;)
    {
        if (i == bBytes)
        {
            return FALSE; /* ran off the buffer before either string ended */
        }
        if (a[i] != b[i])
        {
            return FALSE;
        }
        if (a[i] == '\0')
        {
            return TRUE;
        }
        i++;
    }
}

/* Does `s` begin with `prefix`? An empty prefix matches everything. */
static inline BOOLEAN KiStringStartsWith(const char *s, const char *prefix)
{
    while (*prefix != '\0' && *s == *prefix)
    {
        s++;
        prefix++;
    }
    return *prefix == '\0';
}

#endif /* PROSKRNL_KERNEL_LIB_STRING_H */
