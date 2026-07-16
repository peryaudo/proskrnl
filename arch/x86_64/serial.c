/* arch/x86_64/serial.c — COM1 16550 UART (M1). The kernel's first eyes; all
 * machine-verdict output goes here ([KTEST]/[PANIC]/[ASSERT], docs/08). */
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"

#define COM1 0x3F8

void HalInitializeSerial(void)
{
    __outbyte(COM1 + 1, 0x00); /* disable interrupts                       */
    __outbyte(COM1 + 3, 0x80); /* DLAB: set baud divisor                   */
    __outbyte(COM1 + 0, 0x03); /* divisor low  (115200 / 3 = 38400 baud)   */
    __outbyte(COM1 + 1, 0x00); /* divisor high                             */
    __outbyte(COM1 + 3, 0x03); /* 8 bits, no parity, one stop; clear DLAB  */
    __outbyte(COM1 + 2, 0xC7); /* enable + clear FIFO, 14-byte threshold   */
    __outbyte(COM1 + 4, 0x0B); /* RTS/DSR set, OUT2 (needed for IRQs later)*/
}

static int HalpTransmitReady(void)
{
    return __inbyte(COM1 + 5) & 0x20; /* line status: transmit holding empty */
}

void HalPutChar(char Char)
{
    while (!HalpTransmitReady())
    {
    }
    __outbyte(COM1, (uint8_t)Char);
}

void HalPutString(const char *String)
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
