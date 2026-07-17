/* arch/x86_64/gdt.c — GDT, TSS, syscall MSRs (M4). See gdt.h.
 *
 * Long mode ignores segmentation almost entirely: the descriptors below only
 * carry the privilege level, the L (64-bit) bit, and presence. What actually
 * matters is the selector LAYOUT (syscall/sysret derive CS/SS from STAR by
 * fixed offsets) and the TSS (RSP0 = the ring-crossing stack).
 */
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/io.h"
#include "kernel/init/panic.h"

#include <stddef.h>

#define IA32_EFER           0xC0000080
#define IA32_EFER_SCE       (1ULL << 0)
#define IA32_STAR           0xC0000081
#define IA32_LSTAR          0xC0000082
#define IA32_FMASK          0xC0000084
#define IA32_GS_BASE        0xC0000101
#define IA32_KERNEL_GS_BASE 0xC0000102

/* RFLAGS bits cleared on syscall entry: IF (the entry stub runs lock-free
 * until it is on the kernel stack), plus TF/DF/AC hygiene. */
#define KI_SYSCALL_RFLAGS_MASK 0x47700ULL

KIPCR KiPcr;

/* entry.S offsets. */
_Static_assert(offsetof(KIPCR, kernelRsp) == 0, "KIPCR.kernelRsp offset welded into entry.S");
_Static_assert(offsetof(KIPCR, userRsp) == 8, "KIPCR.userRsp offset welded into entry.S");

/* 64-bit TSS (Intel SDM vol. 3 figure 8-11). Only RSP0 is used. */
typedef struct
{
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t ioMapBase;
} __attribute__((packed)) KTSS;

static KTSS KiTss;

/* 5 slots + the 16-byte TSS descriptor (2 slots). */
static uint64_t KiGdt[8];

typedef struct
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) KDESCRIPTOR;

void KiSystemCall64(void); /* kernel/syscall/entry.S */

void KiSetKernelStack(uint64_t stackTop)
{
    KiTss.rsp0 = stackTop;
    KiPcr.kernelRsp = stackTop;
}

void KiSetUserGsBase(uint64_t base)
{
    /* While in kernel mode the live GS base is the PCR; KERNEL_GS_BASE holds
     * the half swapgs will hand to user mode. */
    KiWriteMsr(IA32_KERNEL_GS_BASE, base);
}

void KiInitializeGdt(void)
{
    /* Access bytes: P|S|type. Code 0x9A/0xFA (exec/read, DPL 0/3), data
     * 0x92/0xF2 (read/write, DPL 0/3); code adds L (bit 53). */
    KiGdt[0] = 0;
    KiGdt[KI_GDT_KERNEL_CS / 8] = (0x9AULL << 40) | (1ULL << 53);
    KiGdt[KI_GDT_KERNEL_DS / 8] = 0x92ULL << 40;
    KiGdt[KI_GDT_USER_DS / 8] = 0xF2ULL << 40;
    KiGdt[KI_GDT_USER_CS / 8] = (0xFAULL << 40) | (1ULL << 53);

    /* The 16-byte TSS descriptor: type 0x89 (available 64-bit TSS). */
    uint64_t base = (uint64_t)(uintptr_t)&KiTss;
    uint64_t limit = sizeof(KiTss) - 1;
    KiGdt[KI_GDT_TSS / 8] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (0x89ULL << 40) |
                            (((limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    KiGdt[KI_GDT_TSS / 8 + 1] = base >> 32;

    KiTss.ioMapBase = sizeof(KiTss); /* no I/O permission map */

    KDESCRIPTOR descriptor = {(uint16_t)(sizeof(KiGdt) - 1), (uint64_t)(uintptr_t)KiGdt};
    __asm__ volatile("lgdt %0" : : "m"(descriptor));

    /* Reload the selectors: data via mov, CS via a far return. */
    __asm__ volatile("mov %0, %%ds\n\t"
                     "mov %0, %%es\n\t"
                     "mov %0, %%ss\n\t"
                     "xor %%eax, %%eax\n\t"
                     "mov %%eax, %%fs\n\t"
                     "mov %%eax, %%gs\n\t"
                     :
                     : "r"((uint32_t)KI_GDT_KERNEL_DS)
                     : "rax");
    __asm__ volatile("pushq %0\n\t"
                     "leaq 1f(%%rip), %%rax\n\t"
                     "pushq %%rax\n\t"
                     "lretq\n\t"
                     "1:"
                     :
                     : "i"((uint64_t)KI_GDT_KERNEL_CS)
                     : "rax", "memory");
    __asm__ volatile("ltr %0" : : "r"((uint16_t)KI_GDT_TSS));

    /* GS = the PCR while in kernel mode; KERNEL_GS_BASE holds the outgoing
     * user GS base (the TEB), swapped at every crossing. */
    KiWriteMsr(IA32_GS_BASE, (uint64_t)(uintptr_t)&KiPcr);
    KiWriteMsr(IA32_KERNEL_GS_BASE, 0);

    /* Arm syscall/sysret. syscall: CS = STAR[47:32], SS = +8. sysretq:
     * CS = STAR[63:48] + 16, SS = STAR[63:48] + 8 — so the sysret base sits
     * one slot BELOW user data (yielding CS 0x20|3, SS 0x18|3). */
    KiWriteMsr(IA32_STAR,
               ((uint64_t)KI_GDT_KERNEL_CS << 32) | ((uint64_t)((KI_GDT_USER_DS - 8) | 3) << 48));
    KiWriteMsr(IA32_LSTAR, (uint64_t)(uintptr_t)KiSystemCall64);
    KiWriteMsr(IA32_FMASK, KI_SYSCALL_RFLAGS_MASK);
    KiWriteMsr(IA32_EFER, KiReadMsr(IA32_EFER) | IA32_EFER_SCE);
}
