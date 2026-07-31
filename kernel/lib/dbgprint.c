/* kernel/lib/dbgprint.c — see dbgprint.h. Every byte goes out COM1, and
 * (until the GUI takes the framebuffer) onto the screen as well. */
#include "kernel/lib/dbgprint.h"
#include "arch/x86_64/serial.h"
#include "kernel/init/bootvid.h"

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

/* The one place kernel log text turns into output. Serial is written first
 * and unconditionally: it is the machine channel every verdict is grepped
 * off (docs/08), and the boot console must never be able to perturb it. */
void DbgPutChar(char c)
{
    KiSerialPutChar(c);
    KiBootVideoPutChar(c);
}

static void DbgpEmitString(const char *str)
{
    for (; *str != '\0'; str++)
    {
        if (*str == '\n')
        {
            DbgPutChar('\r');
        }
        DbgPutChar(*str);
    }
}

/* Unsigned integer in `base`, with optional field width, pad char, and the
 * "0x"/"0X" alternate-form prefix. */
static void DbgpEmitUnsigned(uint64_t value, unsigned base, int upper, int width, char pad, int alt)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buffer[32];
    int count = 0;

    if (value == 0)
    {
        buffer[count++] = '0';
    }
    while (value != 0)
    {
        buffer[count++] = digits[value % base];
        value /= base;
    }

    int prefix = (alt && base == 16) ? 2 : 0;
    int length = count + prefix;

    if (pad == '0')
    {
        if (prefix)
        {
            DbgPutChar('0');
            DbgPutChar(upper ? 'X' : 'x');
        }
        for (int w = length; w < width; w++)
        {
            DbgPutChar('0');
        }
    }
    else
    {
        for (int w = length; w < width; w++)
        {
            DbgPutChar(' ');
        }
        if (prefix)
        {
            DbgPutChar('0');
            DbgPutChar(upper ? 'X' : 'x');
        }
    }

    while (count > 0)
    {
        DbgPutChar(buffer[--count]);
    }
}

static void DbgpPrintV(const char *format, va_list args)
{
    for (; *format != '\0'; format++)
    {
        if (*format != '%')
        {
            if (*format == '\n')
            {
                DbgPutChar('\r');
            }
            DbgPutChar(*format);
            continue;
        }
        format++;

        int alt = 0;
        char pad = ' ';
        for (;;)
        {
            if (*format == '#')
            {
                alt = 1;
                format++;
            }
            else if (*format == '0')
            {
                pad = '0';
                format++;
            }
            else
                break;
        }

        int width = 0;
        while (*format >= '0' && *format <= '9')
        {
            width = width * 10 + (*format - '0');
            format++;
        }

        int lng = 0; /* 0=int 1=long 2=long long 3=size_t */
        if (*format == 'l')
        {
            lng = 1;
            format++;
            if (*format == 'l')
            {
                lng = 2;
                format++;
            }
        }
        else if (*format == 'z')
        {
            lng = 3;
            format++;
        }

        switch (*format)
        {
        case '%':
            DbgPutChar('%');
            break;
        case 'c':
            DbgPutChar((char)va_arg(args, int));
            break;
        case 's':
        {
            const char *str = va_arg(args, const char *);
            DbgpEmitString(str ? str : "(null)");
            break;
        }
        case 'd':
        case 'i':
        {
            long long value;
            if (lng == 0)
                value = va_arg(args, int);
            else if (lng == 2)
                value = va_arg(args, long long);
            else /* l or z: both long-sized on LP64 */
                value = va_arg(args, long);
            if (value < 0)
            {
                DbgPutChar('-');
                /* Negate in the UNSIGNED domain: -value on LLONG_MIN is
                 * signed overflow, and the kernel builds with
                 * -fsanitize-trap=undefined, so it is a ud2 INSIDE the
                 * logging path -- the one place that must never be the thing
                 * that dies (Art. 9). 0 - (uint64_t)value is the same
                 * magnitude for every other value and is defined for this
                 * one. */
                DbgpEmitUnsigned(0ULL - (uint64_t)value, 10, 0, width > 0 ? width - 1 : 0, pad, 0);
            }
            else
            {
                DbgpEmitUnsigned((uint64_t)value, 10, 0, width, pad, 0);
            }
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        {
            unsigned long long value;
            if (lng == 0)
                value = va_arg(args, unsigned int);
            else if (lng == 2)
                value = va_arg(args, unsigned long long);
            else /* l or z: both unsigned-long-sized on LP64 */
                value = va_arg(args, unsigned long);
            unsigned base = (*format == 'u') ? 10 : 16;
            DbgpEmitUnsigned(value, base, (*format == 'X'), width, pad, alt);
            break;
        }
        case 'p':
        {
            void *pointer = va_arg(args, void *);
            DbgpEmitUnsigned((uint64_t)(uintptr_t)pointer, 16, 0, width, pad, 1);
            break;
        }
        case '\0':
            return;
        default:
            DbgPutChar('%');
            DbgPutChar(*format);
            break;
        }
    }
}

int DbgPrint(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    DbgpPrintV(format, args);
    va_end(args);
    return 0; /* STATUS_SUCCESS */
}
