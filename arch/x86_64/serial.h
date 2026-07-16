/* arch/x86_64/serial.h — COM1 16550 UART (M1). */
#ifndef PROSKRNL_ARCH_X86_64_SERIAL_H
#define PROSKRNL_ARCH_X86_64_SERIAL_H

void HalpInitializeSerial(void);
void HalpPutChar(char Char);
void HalpPutString(const char *String);

#endif /* PROSKRNL_ARCH_X86_64_SERIAL_H */
