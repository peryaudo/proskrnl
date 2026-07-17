/*
 * ntapi.c — per-mode implementation of the harness declared in ntapi.h.
 *
 * The oracle path is complete and buildable today (host libc). The proskrnl
 * path has one seam, marked "M4", that lights up when user mode + the syscall
 * boundary land; until then only the oracle target is built (tests/run/run.sh).
 */
#include "ntapi.h"
#include <stdarg.h>
#if defined(NTAPI_ORACLE)
/* The oracle is allowed libc (docs/14); host headers stay gated to this mode
 * so the proskrnl build remains freestanding. (Hand-rolled externs do not
 * link against mingw's CRT, where stdout is a macro over __acrt_iob_func.) */
#include <stdio.h>
#include <stdlib.h>
#elif defined(NTAPI_PROSKRNL)
/* The proskrnl target is a flat binary issuing raw syscalls: no libc. Output
 * goes to the serial console via NtDisplayString and the exit code to
 * NtTerminateProcess (docs/14). */
#include "abi/ntpsapi.h"
#endif

/* Structured verdict prefixes — kept machine-greppable, separate from any
 * human free-text (docs/08). tests/run/ greps exactly these. */
#define PFX_ASSERT "[ASSERT] "
#define PFX_KTEST  "[KTEST] "

#if defined(NTAPI_PROSKRNL)
/* A tiny freestanding vsnprintf covering exactly what the tests' ok() format
 * strings use: %s %c %d/%i %u %x/%X %p, the l/ll/z length modifiers, and a
 * leading 0 / width / # flag. Mirrors the kernel's DbgPrint (docs/08); kept
 * here because the proskrnl target links no libc. */
static char *ntapi_emit_uint(char *out, char *end, unsigned long long value, unsigned base,
                             int upper, int width, char pad, int alt)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[24];
    int count = 0;
    if (value == 0)
        tmp[count++] = '0';
    while (value != 0)
    {
        tmp[count++] = digits[value % base];
        value /= base;
    }
    int prefix = (alt && base == 16) ? 2 : 0;
    int length = count + prefix;
    if (pad == '0' && prefix)
    {
        if (out < end)
            *out++ = '0';
        if (out < end)
            *out++ = upper ? 'X' : 'x';
    }
    for (int w = length; w < width; w++)
        if (out < end)
            *out++ = pad;
    if (pad != '0' && prefix)
    {
        if (out < end)
            *out++ = '0';
        if (out < end)
            *out++ = upper ? 'X' : 'x';
    }
    while (count > 0 && out < end)
        *out++ = tmp[--count];
    return out;
}

static void ntapi_vsnprintf(char *buf, unsigned long size, const char *fmt, va_list ap)
{
    char *out = buf;
    char *end = buf + (size > 0 ? size - 1 : 0);
    for (; *fmt != '\0'; fmt++)
    {
        if (*fmt != '%')
        {
            if (out < end)
                *out++ = *fmt;
            continue;
        }
        fmt++;
        int alt = 0;
        char pad = ' ';
        for (;;)
        {
            if (*fmt == '#')
                alt = 1, fmt++;
            else if (*fmt == '0')
                pad = '0', fmt++;
            else
                break;
        }
        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        int lng = 0; /* 0=int 1=long 2=long long 3=size_t */
        if (*fmt == 'l')
        {
            lng = 1, fmt++;
            if (*fmt == 'l')
                lng = 2, fmt++;
        }
        else if (*fmt == 'z')
            lng = 3, fmt++;
        switch (*fmt)
        {
        case '%':
            if (out < end)
                *out++ = '%';
            break;
        case 'c':
            if (out < end)
                *out++ = (char)va_arg(ap, int);
            break;
        case 's':
        {
            const char *s = va_arg(ap, const char *);
            if (s == 0)
                s = "(null)";
            while (*s != '\0' && out < end)
                *out++ = *s++;
            break;
        }
        case 'd':
        case 'i':
        {
            long long v = (lng == 0)   ? va_arg(ap, int)
                          : (lng == 2) ? va_arg(ap, long long)
                                       : va_arg(ap, long);
            if (v < 0)
            {
                if (out < end)
                    *out++ = '-';
                out = ntapi_emit_uint(out, end, (unsigned long long)(-v), 10, 0,
                                      width > 0 ? width - 1 : 0, pad, 0);
            }
            else
                out = ntapi_emit_uint(out, end, (unsigned long long)v, 10, 0, width, pad, 0);
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        {
            unsigned long long v = (lng == 0)   ? va_arg(ap, unsigned int)
                                   : (lng == 2) ? va_arg(ap, unsigned long long)
                                                : va_arg(ap, unsigned long);
            unsigned base = (*fmt == 'u') ? 10 : 16;
            out = ntapi_emit_uint(out, end, v, base, (*fmt == 'X'), width, pad, alt);
            break;
        }
        case 'p':
            out = ntapi_emit_uint(out, end, (unsigned long long)(ULONG_PTR)va_arg(ap, void *), 16,
                                  0, width, pad, 1);
            break;
        case '\0':
            goto done;
        default:
            if (out < end)
                *out++ = '%';
            if (out < end)
                *out++ = *fmt;
            break;
        }
    }
done:
    *out = '\0';
}
#endif /* NTAPI_PROSKRNL */

static void ntapi_vout(const char *fmt, va_list ap)
{
    char buf[512];
#if defined(NTAPI_ORACLE)
    /* host vsnprintf is available and correct; the oracle is allowed libc. */
    vsnprintf(buf, sizeof buf, fmt, ap);
#elif defined(NTAPI_PROSKRNL)
    ntapi_vsnprintf(buf, sizeof buf, fmt, ap);
#endif
    ntapi_out(buf);
}

static void ntapi_outf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ntapi_vout(fmt, ap);
    va_end(ap);
}

void ntapi_okv(int cond, const char *file, int line, const char *fmt, ...)
{
    if (ntapi_ctx.todo_depth > 0)
    {
#if defined(NTAPI_PROSKRNL)
        /* Inside todo_proskrnl on the target: failure is expected (silent);
         * an unexpected pass means the tag is stale. */
        if (cond)
        {
            ntapi_ctx.todo_unexpected++;
            ntapi_outf(PFX_ASSERT "%s:%d: todo_proskrnl succeeded (remove the tag): ", file, line);
            {
                va_list ap;
                va_start(ap, fmt);
                ntapi_vout(fmt, ap);
                va_end(ap);
            }
            ntapi_out("\n");
        }
        return;
#endif
        /* oracle: todo_proskrnl is transparent — fall through to normal check. */
    }

    if (!cond)
    {
        ntapi_ctx.failures++;
        ntapi_outf(PFX_ASSERT "%s:%d: ", file, line);
        {
            va_list ap;
            va_start(ap, fmt);
            ntapi_vout(fmt, ap);
            va_end(ap);
        }
        ntapi_out("\n");
    }
}

void ntapi_skipv(const char *file, int line, const char *fmt, ...)
{
    ntapi_ctx.skips++;
    ntapi_outf("[SKIP] %s:%d: ", file, line);
    {
        va_list ap;
        va_start(ap, fmt);
        ntapi_vout(fmt, ap);
        va_end(ap);
    }
    ntapi_out("\n");
}

int ntapi_finish(void)
{
    if (ntapi_ctx.failures == 0 && ntapi_ctx.todo_unexpected == 0)
    {
        ntapi_outf(PFX_KTEST "%s PASS\n", ntapi_ctx.name);
        return 0;
    }
    ntapi_outf(PFX_KTEST "%s FAIL failures=%d todo_unexpected=%d\n", ntapi_ctx.name,
               ntapi_ctx.failures, ntapi_ctx.todo_unexpected);
    return 1;
}

/* ---- the per-mode I/O + exit seam --------------------------------------- */

#if defined(NTAPI_ORACLE)

void ntapi_out(const char *text)
{
    fputs(text, stdout);
}

void ntapi_exit(int code)
{
    exit(code);
}

#elif defined(NTAPI_PROSKRNL)

void ntapi_out(const char *text)
{
    /* To the serial console via NtDisplayString — the same transport as the
     * kernel's [KTEST] lines (docs/08). ASCII widened to UTF-16 in place. */
    WCHAR wide[512];
    USHORT n = 0;
    while (text[n] != '\0' && n < 511)
    {
        wide[n] = (WCHAR)(unsigned char)text[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

void ntapi_exit(int code)
{
    /* The process exit status IS the verdict the kernel's boot-module runner
     * checks (0 = PASS); tests/run/run.sh also greps the [KTEST] lines above
     * (docs/14). */
    NtTerminateProcess(NtCurrentProcess(), code);
    for (;;)
    {
        /* NtTerminateProcess never returns. */
    }
}

#endif
