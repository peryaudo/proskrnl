/* kernel/lib/kprintf.c — see kprintf.h. Writes straight to COM1. */
#include "kernel/lib/kprintf.h"
#include "arch/x86_64/serial.h"

#include <stdint.h>
#include <stddef.h>

static void DbgpEmitString(const char *String)
{
    for (; *String != '\0'; String++)
    {
        if (*String == '\n')
        {
            HalPutChar('\r');
        }
        HalPutChar(*String);
    }
}

/* Unsigned integer in `Base`, with optional field width, pad char, and the
 * "0x"/"0X" alternate-form prefix. */
static void DbgpEmitUnsigned(uint64_t Value, unsigned Base, int Upper, int Width, char Pad, int Alt)
{
    const char *Digits = Upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char Buffer[32];
    int Count = 0;

    if (Value == 0)
    {
        Buffer[Count++] = '0';
    }
    while (Value != 0)
    {
        Buffer[Count++] = Digits[Value % Base];
        Value /= Base;
    }

    int Prefix = (Alt && Base == 16) ? 2 : 0;
    int Length = Count + Prefix;

    if (Pad == '0')
    {
        if (Prefix)
        {
            HalPutChar('0');
            HalPutChar(Upper ? 'X' : 'x');
        }
        for (int W = Length; W < Width; W++)
        {
            HalPutChar('0');
        }
    }
    else
    {
        for (int W = Length; W < Width; W++)
        {
            HalPutChar(' ');
        }
        if (Prefix)
        {
            HalPutChar('0');
            HalPutChar(Upper ? 'X' : 'x');
        }
    }

    while (Count > 0)
    {
        HalPutChar(Buffer[--Count]);
    }
}

void DbgPrintV(const char *Format, va_list Args)
{
    for (; *Format != '\0'; Format++)
    {
        if (*Format != '%')
        {
            if (*Format == '\n')
            {
                HalPutChar('\r');
            }
            HalPutChar(*Format);
            continue;
        }
        Format++;

        int Alt = 0;
        char Pad = ' ';
        for (;;)
        {
            if (*Format == '#')
            {
                Alt = 1;
                Format++;
            }
            else if (*Format == '0')
            {
                Pad = '0';
                Format++;
            }
            else
                break;
        }

        int Width = 0;
        while (*Format >= '0' && *Format <= '9')
        {
            Width = Width * 10 + (*Format - '0');
            Format++;
        }

        int Long = 0; /* 0=int 1=long 2=long long 3=size_t */
        if (*Format == 'l')
        {
            Long = 1;
            Format++;
            if (*Format == 'l')
            {
                Long = 2;
                Format++;
            }
        }
        else if (*Format == 'z')
        {
            Long = 3;
            Format++;
        }

        switch (*Format)
        {
        case '%':
            HalPutChar('%');
            break;
        case 'c':
            HalPutChar((char)va_arg(Args, int));
            break;
        case 's':
        {
            const char *String = va_arg(Args, const char *);
            DbgpEmitString(String ? String : "(null)");
            break;
        }
        case 'd':
        case 'i':
        {
            long long Value;
            if (Long == 0)
                Value = va_arg(Args, int);
            else if (Long == 1)
                Value = va_arg(Args, long);
            else if (Long == 2)
                Value = va_arg(Args, long long);
            else
                Value = va_arg(Args, long);
            if (Value < 0)
            {
                HalPutChar('-');
                DbgpEmitUnsigned((uint64_t)(-Value), 10, 0, Width > 0 ? Width - 1 : 0, Pad, 0);
            }
            else
            {
                DbgpEmitUnsigned((uint64_t)Value, 10, 0, Width, Pad, 0);
            }
            break;
        }
        case 'u':
        case 'x':
        case 'X':
        {
            unsigned long long Value;
            if (Long == 0)
                Value = va_arg(Args, unsigned int);
            else if (Long == 1)
                Value = va_arg(Args, unsigned long);
            else if (Long == 2)
                Value = va_arg(Args, unsigned long long);
            else
                Value = va_arg(Args, size_t);
            unsigned Base = (*Format == 'u') ? 10 : 16;
            DbgpEmitUnsigned(Value, Base, (*Format == 'X'), Width, Pad, Alt);
            break;
        }
        case 'p':
        {
            void *Pointer = va_arg(Args, void *);
            DbgpEmitUnsigned((uint64_t)(uintptr_t)Pointer, 16, 0, Width, Pad, 1);
            break;
        }
        case '\0':
            return;
        default:
            HalPutChar('%');
            HalPutChar(*Format);
            break;
        }
    }
}

void DbgPrint(const char *Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DbgPrintV(Format, Args);
    va_end(Args);
}
