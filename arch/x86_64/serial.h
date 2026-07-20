/* arch/x86_64/serial.h — COM1 16550 UART (M1). */
#ifndef PROSKRNL_ARCH_X86_64_SERIAL_H
#define PROSKRNL_ARCH_X86_64_SERIAL_H

void KiInitializeSerial(void);
void KiSerialPutChar(char ch);
void KiSerialPutString(const char *str);

/* Nonblocking RX poll: the next received byte, or -1 when the FIFO is
 * empty (M9, HACK-004: the UART's receive side is the console input). */
int KiSerialTryGetChar(void);

#endif /* PROSKRNL_ARCH_X86_64_SERIAL_H */
