/* arch/x86_64/gdt.h — GDT, TSS, and the syscall machine state (M4).
 *
 * M1–M3 ran on Limine's GDT; user mode needs our own: ring-3 code/data
 * selectors laid out for syscall/sysret, a TSS for the ring-crossing stack
 * (RSP0), and the KPCR the syscall entry stub reaches through GS. One CPU,
 * so one static PCR/TSS (Art. 3).
 */
#ifndef PROSKRNL_ARCH_X86_64_GDT_H
#define PROSKRNL_ARCH_X86_64_GDT_H

/* The selector constants are shared with assembly (kernel/syscall/entry.S). */
#ifndef __ASSEMBLER__
#include <stdint.h>
#endif

/* Selector layout. syscall loads CS/SS from STAR[47:32] (+0/+8); sysretq
 * loads them from STAR[63:48] (+16/+8), which forces user data BELOW user
 * code. */
#define KI_GDT_KERNEL_CS 0x08
#define KI_GDT_KERNEL_DS 0x10
#define KI_GDT_USER_DS   0x18
#define KI_GDT_USER_CS   0x20
#define KI_GDT_TSS       0x28

/* IST slot (1-based, TSS.IST[n-1]) for #DF: a kernel-stack overflow must
 * land the dump on a known-good stack instead of triple-faulting silently
 * (Art. 9 — the panic dump is the debugger). Intel SDM Vol. 3A §6.14.5
 * "Interrupt Stack Table". */
#define KI_IST_DOUBLE_FAULT 1

#define KI_USER_CS_SELECTOR (KI_GDT_USER_CS | 3)
#define KI_USER_DS_SELECTOR (KI_GDT_USER_DS | 3)

#ifndef __ASSEMBLER__

/* The processor control region, reached as GS while in kernel mode (swapgs
 * on every user<->kernel crossing). Offsets are welded into
 * kernel/syscall/entry.S; the static_asserts live in gdt.c. */
typedef struct
{
    uint64_t kernelRsp; /* current thread's kernel stack top; syscall entry loads this */
    uint64_t userRsp;   /* scratch: user RSP saved across the entry stub */
} KIPCR, *PKIPCR;

extern KIPCR KiPcr;

/* Install the GDT + TSS, load the kernel selectors, point GS at KiPcr, and
 * arm the syscall MSRs (STAR/LSTAR/SFMASK, EFER.SCE). Call before
 * KiInitializeIdt so the IDT gates capture our kernel CS. */
void KiInitializeGdt(void);

/* Ring-crossing stack for interrupts/exceptions arriving from ring 3, and
 * the stack the syscall entry stub switches to. Updated at context switch. */
void KiSetKernelStack(uint64_t stackTop);

/* The GS base user mode sees after the crossing swapgs — i.e. the current
 * thread's TEB (0 for kernel-only threads). Updated at context switch. */
void KiSetUserGsBase(uint64_t base);

#endif /* __ASSEMBLER__ */

#endif /* PROSKRNL_ARCH_X86_64_GDT_H */
