/* kernel/lib/kprintf.h — minimal freestanding formatted output to serial (M1).
 * Supports: %% %c %s %d %i %u %x %X %p, flags '#' and '0', field width, and
 * length modifiers l / ll / z. Enough for structured logs and register dumps. */
#ifndef PROSKRNL_KERNEL_LIB_KPRINTF_H
#define PROSKRNL_KERNEL_LIB_KPRINTF_H

#include <stdarg.h>

void kprintf(const char *fmt, ...);
void kvprintf(const char *fmt, va_list ap);

#endif /* PROSKRNL_KERNEL_LIB_KPRINTF_H */
