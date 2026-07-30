/* kernel/lib/dbgprint.h — minimal freestanding formatted output to serial (M1).
 * Supports: %% %c %s %d %i %u %x %X %p, flags '#' and '0', field width, and
 * length modifiers l / ll / z. Enough for structured logs and register dumps. */
#ifndef PROSKRNL_KERNEL_LIB_DBGPRINT_H
#define PROSKRNL_KERNEL_LIB_DBGPRINT_H

/* Matches the real NT export `NTSTATUS DbgPrint(LPCSTR format, ...)`
 * (third_party/wine/include/winternl.h). We return an int stand-in for NTSTATUS
 * (0 == STATUS_SUCCESS) until abi/ntdef.h provides the type at M4. The va_list
 * backend is a private DbgpPrintV in dbgprint.c (real NT's is vDbgPrintEx, a
 * different signature — docs/15). */
int DbgPrint(const char *format, ...);

/* One character of kernel log text, to every channel that carries it: COM1
 * always, plus the boot console while it holds the framebuffer
 * (kernel/init/bootvid.h). NtDisplayString writes user-mode text through the
 * same function so both halves of the boot log land on the same channels. */
void DbgPutChar(char c);

#endif /* PROSKRNL_KERNEL_LIB_DBGPRINT_H */
