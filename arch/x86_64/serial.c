/* arch/x86_64/serial.c — COM1 16550 UART (M1). The kernel's first eyes; all
 * machine-verdict output goes here ([KTEST]/[PANIC]/[ASSERT], docs/08).
 *
 * Constants cross-check: the TI PC16550D datasheet (register offsets 0..5,
 * DLAB, LCR/FCR/MCR/LSR bit layouts); the pinned QEMU (third_party/qemu)
 * hw/char/serial.c carries the same defines (UART_LCR_DLAB 0x80,
 * UART_MCR_DTR 0x01 / RTS 0x02 / OUT2 0x08, UART_LSR_THRE 0x20, FCR ITL
 * 0xC0 = 14 bytes). Divisor base is 115200 Hz, so divisor 3 = 38400 baud. */
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"

#define COM1 0x3F8

void KiInitializeSerial(void)
{
    KiOutByte(COM1 + 1, 0x00); /* disable interrupts                       */
    KiOutByte(COM1 + 3, 0x80); /* DLAB: set baud divisor                   */
    KiOutByte(COM1 + 0, 0x03); /* divisor low  (115200 / 3 = 38400 baud)   */
    KiOutByte(COM1 + 1, 0x00); /* divisor high                             */
    KiOutByte(COM1 + 3, 0x03); /* 8 bits, no parity, one stop; clear DLAB  */
    KiOutByte(COM1 + 2, 0xC7); /* enable + clear FIFO, 14-byte threshold   */
    KiOutByte(COM1 + 4, 0x0B); /* DTR + RTS, OUT2 (needed for IRQs later)  */
}

static int KiSerialTransmitReady(void)
{
    return KiInByte(COM1 + 5) & 0x20; /* line status: transmit holding empty */
}

void KiSerialPutChar(char ch)
{
    while (!KiSerialTransmitReady())
    {
    }
    KiOutByte(COM1, (uint8_t)ch);
}

void KiSerialPutString(const char *str)
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
