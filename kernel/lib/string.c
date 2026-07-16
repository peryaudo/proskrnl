/* kernel/lib/string.c — freestanding memory intrinsics (M2).
 *
 * Even under -ffreestanding, clang may lower struct assignment and array
 * initialization into calls to these four functions; the C ABI requires a
 * freestanding environment to provide them. Their names are fixed by the
 * compiler, so the docs/15 naming rules are waived here (NOLINT).
 */
#include "kernel/lib/string.h"

void *memset(void *destination, int value,
             size_t length) /* NOLINT(readability-identifier-naming) */
{
    unsigned char *out = destination;
    for (size_t i = 0; i < length; i++)
    {
        out[i] = (unsigned char)value;
    }
    return destination;
}

void *memcpy(void *destination, const void *source,
             size_t length) /* NOLINT(readability-identifier-naming) */
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (size_t i = 0; i < length; i++)
    {
        out[i] = in[i];
    }
    return destination;
}

void *memmove(void *destination, const void *source,
              size_t length) /* NOLINT(readability-identifier-naming) */
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    if (out < in)
    {
        for (size_t i = 0; i < length; i++)
        {
            out[i] = in[i];
        }
    }
    else
    {
        for (size_t i = length; i > 0; i--)
        {
            out[i - 1] = in[i - 1];
        }
    }
    return destination;
}

int memcmp(const void *left, const void *right,
           size_t length) /* NOLINT(readability-identifier-naming) */
{
    const unsigned char *a = left;
    const unsigned char *b = right;
    for (size_t i = 0; i < length; i++)
    {
        if (a[i] != b[i])
        {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}
