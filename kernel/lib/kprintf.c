/* kernel/lib/kprintf.c — see kprintf.h. Writes straight to COM1. */
#include "kernel/lib/kprintf.h"
#include "arch/x86_64/serial.h"

#include <stdint.h>
#include <stddef.h>

static void emit_str(const char *s)
{
    for (; *s != '\0'; s++) {
        if (*s == '\n') {
            serial_putc('\r');
        }
        serial_putc(*s);
    }
}

/* Unsigned integer in `base`, with optional field width, pad char, and the
 * "0x"/"0X" alternate-form prefix. */
static void emit_uint(uint64_t val, unsigned base, int upper,
                      int width, char pad, int alt)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buf[32];
    int n = 0;

    if (val == 0) {
        buf[n++] = '0';
    }
    while (val != 0) {
        buf[n++] = digits[val % base];
        val /= base;
    }

    int prefix = (alt && base == 16) ? 2 : 0;
    int len = n + prefix;

    if (pad == '0') {
        if (prefix) { serial_putc('0'); serial_putc(upper ? 'X' : 'x'); }
        for (int w = len; w < width; w++) serial_putc('0');
    } else {
        for (int w = len; w < width; w++) serial_putc(' ');
        if (prefix) { serial_putc('0'); serial_putc(upper ? 'X' : 'x'); }
    }

    while (n > 0) {
        serial_putc(buf[--n]);
    }
}

void kvprintf(const char *fmt, va_list ap)
{
    for (; *fmt != '\0'; fmt++) {
        if (*fmt != '%') {
            if (*fmt == '\n') serial_putc('\r');
            serial_putc(*fmt);
            continue;
        }
        fmt++;

        int alt = 0;
        char pad = ' ';
        for (;;) {
            if (*fmt == '#') { alt = 1; fmt++; }
            else if (*fmt == '0') { pad = '0'; fmt++; }
            else break;
        }

        int width = 0;
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }

        int lng = 0; /* 0=int 1=long 2=long long 3=size_t */
        if (*fmt == 'l') { lng = 1; fmt++; if (*fmt == 'l') { lng = 2; fmt++; } }
        else if (*fmt == 'z') { lng = 3; fmt++; }

        switch (*fmt) {
        case '%': serial_putc('%'); break;
        case 'c': serial_putc((char)va_arg(ap, int)); break;
        case 's': { const char *s = va_arg(ap, const char *); emit_str(s ? s : "(null)"); break; }
        case 'd': case 'i': {
            long long v;
            if (lng == 0) v = va_arg(ap, int);
            else if (lng == 1) v = va_arg(ap, long);
            else if (lng == 2) v = va_arg(ap, long long);
            else v = va_arg(ap, long);
            if (v < 0) {
                serial_putc('-');
                emit_uint((uint64_t)(-v), 10, 0, width > 0 ? width - 1 : 0, pad, 0);
            } else {
                emit_uint((uint64_t)v, 10, 0, width, pad, 0);
            }
            break;
        }
        case 'u': case 'x': case 'X': {
            unsigned long long v;
            if (lng == 0) v = va_arg(ap, unsigned int);
            else if (lng == 1) v = va_arg(ap, unsigned long);
            else if (lng == 2) v = va_arg(ap, unsigned long long);
            else v = va_arg(ap, size_t);
            unsigned base = (*fmt == 'u') ? 10 : 16;
            emit_uint(v, base, (*fmt == 'X'), width, pad, alt);
            break;
        }
        case 'p': {
            void *p = va_arg(ap, void *);
            emit_uint((uint64_t)(uintptr_t)p, 16, 0, width, pad, 1);
            break;
        }
        case '\0': return;
        default: serial_putc('%'); serial_putc(*fmt); break;
        }
    }
}

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);
}
