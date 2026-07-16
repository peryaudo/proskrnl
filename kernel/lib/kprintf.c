/* kernel/lib/kprintf.c — see kprintf.h. Writes straight to COM1. */
#include "kernel/lib/kprintf.h"
#include "arch/x86_64/serial.h"

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

static void DbgpEmitString(const char *str)
{
    for (; *str != '\0'; str++)
    {
        if (*str == '\n')
        {
            KiSerialPutChar('\r');
        }
        KiSerialPutChar(*str);
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
            KiSerialPutChar('0');
            KiSerialPutChar(upper ? 'X' : 'x');
        }
        for (int w = length; w < width; w++)
        {
            KiSerialPutChar('0');
        }
    }
    else
    {
        for (int w = length; w < width; w++)
        {
            KiSerialPutChar(' ');
        }
        if (prefix)
        {
            KiSerialPutChar('0');
            KiSerialPutChar(upper ? 'X' : 'x');
        }
    }

    while (count > 0)
    {
        KiSerialPutChar(buffer[--count]);
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
                KiSerialPutChar('\r');
            }
            KiSerialPutChar(*format);
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
            KiSerialPutChar('%');
            break;
        case 'c':
            KiSerialPutChar((char)va_arg(args, int));
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
            else if (lng == 1)
                value = va_arg(args, long);
            else if (lng == 2)
                value = va_arg(args, long long);
            else
                value = va_arg(args, long);
            if (value < 0)
            {
                KiSerialPutChar('-');
                DbgpEmitUnsigned((uint64_t)(-value), 10, 0, width > 0 ? width - 1 : 0, pad, 0);
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
            else if (lng == 1)
                value = va_arg(args, unsigned long);
            else if (lng == 2)
                value = va_arg(args, unsigned long long);
            else
                value = va_arg(args, size_t);
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
            KiSerialPutChar('%');
            KiSerialPutChar(*format);
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
