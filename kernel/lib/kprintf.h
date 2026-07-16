/* kernel/lib/kprintf.h — minimal freestanding formatted output to serial (M1).
 * Supports: %% %c %s %d %i %u %x %X %p, flags '#' and '0', field width, and
 * length modifiers l / ll / z. Enough for structured logs and register dumps. */
#ifndef PROSKRNL_KERNEL_LIB_KPRINTF_H
#define PROSKRNL_KERNEL_LIB_KPRINTF_H

/* Matches the real NT export `NTSTATUS DbgPrint(LPCSTR Format, ...)`
 * (third_party/wine/include/winternl.h). We return an int stand-in for NTSTATUS
 * (0 == STATUS_SUCCESS) until abi/ntdef.h provides the type at M4. The va_list
 * backend is a private DbgpPrintV in kprintf.c (real NT's is vDbgPrintEx, a
 * different signature — docs/15). */
int DbgPrint(const char *Format, ...);

#endif /* PROSKRNL_KERNEL_LIB_KPRINTF_H */
