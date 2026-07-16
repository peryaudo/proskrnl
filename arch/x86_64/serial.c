/* arch/x86_64/serial.c — COM1 16550 UART (M1). The kernel's first eyes;
 * all machine-verdict output goes here ([KTEST]/[PANIC]/[ASSERT], docs/08). */
#include "arch/x86_64/serial.h"
#include "arch/x86_64/io.h"

#define COM1 0x3F8

void serial_init(void)
{
    outb(COM1 + 1, 0x00); /* disable interrupts                       */
    outb(COM1 + 3, 0x80); /* DLAB: set baud divisor                   */
    outb(COM1 + 0, 0x03); /* divisor low  (115200 / 3 = 38400 baud)   */
    outb(COM1 + 1, 0x00); /* divisor high                             */
    outb(COM1 + 3, 0x03); /* 8 bits, no parity, one stop; clear DLAB  */
    outb(COM1 + 2, 0xC7); /* enable + clear FIFO, 14-byte threshold   */
    outb(COM1 + 4, 0x0B); /* RTS/DSR set, OUT2 (needed for IRQs later)*/
}

static int tx_ready(void)
{
    return inb(COM1 + 5) & 0x20; /* line status: transmit holding empty */
}

void serial_putc(char c)
{
    while (!tx_ready()) { }
    outb(COM1, (uint8_t)c);
}

void serial_puts(const char *s)
{
    for (; *s != '\0'; s++) {
        if (*s == '\n') {
            serial_putc('\r');
        }
        serial_putc(*s);
    }
}
