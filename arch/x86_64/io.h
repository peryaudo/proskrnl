/* arch/x86_64/io.h — port I/O + QEMU debug-exit (M1). */
#ifndef PROSKRNL_ARCH_X86_64_IO_H
#define PROSKRNL_ARCH_X86_64_IO_H

#include <stdint.h>

static inline void outb(uint16_t port, uint8_t val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    __asm__ volatile("wrmsr"
                     : : "c"(msr), "a"((uint32_t)val), "d"((uint32_t)(val >> 32)));
}

/* QEMU isa-debug-exit (iobase 0xf4): host exit code becomes (code << 1) | 1,
 * so it can never be 0 — the real M1 verdict is the [KTEST] line on serial
 * (docs/08). This just terminates the VM promptly. */
static inline void qemu_exit(uint8_t code)
{
    outb(0xf4, code);
}

#endif /* PROSKRNL_ARCH_X86_64_IO_H */
