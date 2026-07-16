/* arch/x86_64/io.h — port I/O, MSR access, QEMU debug-exit (M1). */
#ifndef PROSKRNL_ARCH_X86_64_IO_H
#define PROSKRNL_ARCH_X86_64_IO_H

#include <stdint.h>

static inline void __outbyte(uint16_t Port, uint8_t Value)
{
    __asm__ volatile("outb %0, %1" : : "a"(Value), "Nd"(Port));
}

static inline uint8_t __inbyte(uint16_t Port)
{
    uint8_t Value;
    __asm__ volatile("inb %1, %0" : "=a"(Value) : "Nd"(Port));
    return Value;
}

static inline uint64_t __readmsr(uint32_t Register)
{
    uint32_t Low, High;
    __asm__ volatile("rdmsr" : "=a"(Low), "=d"(High) : "c"(Register));
    return ((uint64_t)High << 32) | Low;
}

static inline void __writemsr(uint32_t Register, uint64_t Value)
{
    __asm__ volatile("wrmsr" : : "c"(Register), "a"((uint32_t)Value), "d"((uint32_t)(Value >> 32)));
}

/* QEMU isa-debug-exit (iobase 0xf4): host exit code becomes (Code << 1) | 1, so
 * it can never be 0 — the real M1 verdict is the [KTEST] line on serial
 * (docs/08). This just terminates the VM promptly. */
static inline void HalpQemuExit(uint8_t Code)
{
    __outbyte(0xf4, Code);
}

#endif /* PROSKRNL_ARCH_X86_64_IO_H */
