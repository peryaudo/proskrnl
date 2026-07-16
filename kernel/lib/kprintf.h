/* kernel/lib/kprintf.h — minimal freestanding formatted output to serial (M1).
 * Supports: %% %c %s %d %i %u %x %X %p, flags '#' and '0', field width, and
 * length modifiers l / ll / z. Enough for structured logs and register dumps. */
#ifndef PROSKRNL_KERNEL_LIB_KPRINTF_H
#define PROSKRNL_KERNEL_LIB_KPRINTF_H

#include <stdarg.h>

void DbgPrint(const char *Format, ...);
void DbgPrintV(const char *Format, va_list Args);

#endif /* PROSKRNL_KERNEL_LIB_KPRINTF_H */
