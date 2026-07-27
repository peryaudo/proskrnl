/*
 * ntapi.c — the harness behind ntapi.h: one freestanding implementation for
 * the one build (docs/14). The .exe links no CRT (-nostdlib), so everything
 * the tests and the compiler may lean on lives here: the mem/str helpers, a
 * tiny vsnprintf, the output sink, and the exit path. Which runner is
 * hosting us is probed once at entry: a std output handle (the oracle under
 * Wine, where the runner's pipe captures it) means NtWriteFile; none (the
 * proskrnl kernel runner launches tests console-less) means NtDisplayString
 * to the serial log — the same transport as the kernel's own [KTEST] lines.
 */
#include "ntapi.h"
#include <stdarg.h>

/* Prototypes winternl.h omits (declared as Wine's winternl.h defines them). */
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PVOID, PVOID, PVOID, const void *, ULONG,
                                    PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtDisplayString(PUNICODE_STRING);
NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* Structured verdict prefixes — kept machine-greppable, separate from any
 * human free-text (docs/08). tests/run/ greps exactly these. */
#define PFX_ASSERT "[ASSERT] "
#define PFX_KTEST  "[KTEST] "

static HANDLE ntapi_stdout;

/* Freestanding mem/str helpers — the .exe links no CRT, but the tests (and
 * the compiler, implicitly) may call these. External linkage on purpose so
 * compiler-emitted references resolve too. */
void *memset(void *destination, int value, size_t length)
{
    unsigned char *out = destination;
    for (size_t i = 0; i < length; i++)
        out[i] = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *out = destination;
    const unsigned char *in = source;
    for (size_t i = 0; i < length; i++)
        out[i] = in[i];
    return destination;
}

int memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *a = left;
    const unsigned char *b = right;
    for (size_t i = 0; i < length; i++)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}

/* GCC emits a call to __main at the top of main() (the no-CRT constructor
 * hook); there is nothing to construct, and defining it here beats libgcc's
 * atexit-hungry version at link time. */
void __main(void)
{
}

char *strcat(char *destination, const char *source)
{
    char *out = destination;
    while (*out != '\0')
        out++;
    while ((*out++ = *source++) != '\0')
        ;
    return destination;
}

/* A tiny freestanding vsnprintf covering exactly what the tests' ok() format
 * strings use: %s %c %d/%i %u %x/%X %p, the l/ll/z length modifiers, and a
 * leading 0 / width / # flag. Mirrors the kernel's DbgPrint (docs/08). */
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

static void ntapi_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
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
                          : (lng == 1) ? va_arg(ap, long)
                                       : va_arg(ap, long long);
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
                                   : (lng == 1) ? va_arg(ap, unsigned long)
                                                : va_arg(ap, unsigned long long);
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

void ntapi_out(const char *text)
{
    if (!ntapi_ctx.on_proskrnl)
    {
        /* The oracle side: straight to the std output handle the runner's
         * pipe captures. No CRT, so no CRLF translation — the runner greps
         * raw lines. */
        size_t n = 0;
        while (text[n] != '\0')
            n++;
        IO_STATUS_BLOCK iosb;
        NtWriteFile(ntapi_stdout, NULL, NULL, NULL, &iosb, text, (ULONG)n, NULL, NULL);
        return;
    }
    /* proskrnl: to the serial log via NtDisplayString — the same transport
     * as the kernel's [KTEST] lines (docs/08). ASCII widened in place. */
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

static void ntapi_vout(const char *fmt, va_list ap)
{
    char buf[512];
    ntapi_vsnprintf(buf, sizeof buf, fmt, ap);
    ntapi_out(buf);
}

void ntapi_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ntapi_vout(fmt, ap);
    va_end(ap);
}

void ntapi_okv(int cond, const char *file, int line, const char *fmt, ...)
{
    if (ntapi_ctx.oracle_depth > 0 && !ntapi_ctx.on_proskrnl)
    {
        /* Inside beyond_oracle on the ORACLE: the pinned Wine is unbuilt for
         * this case, so it is not a verdict either way — counted as a skip so
         * the oracle log still shows the case exists. On proskrnl the block is
         * transparent and the assertion is enforced. */
        ntapi_ctx.skips++;
        ntapi_printf("[SKIP] %s:%d: beyond_oracle (the pinned Wine does not implement it): ", file,
                     line);
        {
            va_list ap;
            va_start(ap, fmt);
            ntapi_vout(fmt, ap);
            va_end(ap);
        }
        ntapi_out("\n");
        return;
    }

    if (ntapi_ctx.todo_depth > 0 && ntapi_ctx.on_proskrnl)
    {
        /* Inside todo_proskrnl on the target: failure is expected (silent);
         * an unexpected pass means the tag is stale. On the oracle the
         * block is transparent — fall through to the normal check. */
        if (cond)
        {
            ntapi_ctx.todo_unexpected++;
            ntapi_printf(PFX_ASSERT "%s:%d: todo_proskrnl succeeded (remove the tag): ", file,
                         line);
            {
                va_list ap;
                va_start(ap, fmt);
                ntapi_vout(fmt, ap);
                va_end(ap);
            }
            ntapi_out("\n");
        }
        return;
    }

    if (!cond)
    {
        ntapi_ctx.failures++;
        ntapi_printf(PFX_ASSERT "%s:%d: ", file, line);
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
    ntapi_printf("[SKIP] %s:%d: ", file, line);
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
        ntapi_printf(PFX_KTEST "%s PASS\n", ntapi_ctx.name);
        return 0;
    }
    ntapi_printf(PFX_KTEST "%s FAIL failures=%d todo_unexpected=%d\n", ntapi_ctx.name,
                 ntapi_ctx.failures, ntapi_ctx.todo_unexpected);
    return 1;
}

void ntapi_exit(int code)
{
    /* The process exit status IS the verdict the proskrnl runner checks
     * (0 = PASS); both runners also grep the [KTEST] line (docs/14). */
    NtTerminateProcess(NtCurrentProcess(), code);
    for (;;)
    {
        /* NtTerminateProcess never returns. */
    }
}

/* ---- the .exe entry point ------------------------------------------------ */

int main(void);

/* -nostdlib entry (-Wl,--entry=ntapi_start): probe which runner is hosting
 * us — the oracle's Wine always populates hStdOutput; the proskrnl kernel
 * runner launches tests console-less, so there it is 0 — then run the test.
 * The probe is a runner contract (docs/14), not an OS sniff: proskrnl's
 * PEB/KUSER_SHARED_DATA deliberately mimic Windows 10 (G1), so version
 * fields could never discriminate. */
void ntapi_start(void *peb_arg)
{
    (void)peb_arg;
    ntapi_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    ntapi_ctx.on_proskrnl = (ntapi_stdout == NULL || ntapi_stdout == INVALID_HANDLE_VALUE);
    main();
    ntapi_exit(ntapi_finish());
}
