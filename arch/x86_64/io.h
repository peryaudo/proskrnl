/* arch/x86_64/io.h — port I/O, MSR access, QEMU debug-exit (M1). */
#ifndef PROSKRNL_ARCH_X86_64_IO_H
#define PROSKRNL_ARCH_X86_64_IO_H

#include <stdint.h>

static inline void KiOutByte(uint16_t port, uint8_t value)
{
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t KiInByte(uint16_t port)
{
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void KiOutWord(uint16_t port, uint16_t value)
{
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t KiInWord(uint16_t port)
{
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void KiOutLong(uint16_t port, uint32_t value)
{
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t KiInLong(uint16_t port)
{
    uint32_t value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline uint64_t KiReadMsr(uint32_t msr)
{
    uint32_t low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void KiWriteMsr(uint32_t msr, uint64_t value)
{
    __asm__ volatile("wrmsr" : : "c"(msr), "a"((uint32_t)value), "d"((uint32_t)(value >> 32)));
}

/* QEMU isa-debug-exit (iobase 0xf4, set in tools/qemu.sh): host exit code
 * becomes (code << 1) | 1 — see third_party/qemu hw/misc/debugexit.c — so
 * it can never be 0; the real M1 verdict is the [KTEST] line on serial
 * (docs/08). This just terminates the VM promptly. */
static inline void KiQemuExit(uint8_t code)
{
    KiOutByte(0xf4, code);
}

#endif /* PROSKRNL_ARCH_X86_64_IO_H */
