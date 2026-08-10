/* arch/x86_64/gdt.c — GDT, TSS, syscall MSRs (M4). See gdt.h.
 *
 * Long mode ignores segmentation almost entirely: the descriptors below only
 * carry the privilege level, the L (64-bit) bit, and presence. What actually
 * matters is the selector LAYOUT (syscall/sysret derive CS/SS from STAR by
 * fixed offsets) and the TSS (RSP0 = the ring-crossing stack).
 *
 * Constants cross-check: Intel SDM Vol. 3A, "Protection" (segment descriptor
 * access bytes 0x9A/0x92/0xFA/0xF2, L bit 53, TSS descriptor type 0x89) and
 * "Task Management" (the 104-byte 64-bit TSS layout); SDM Vol. 2B SYSCALL/
 * SYSRET (CS/SS derivation from STAR[47:32] / STAR[63:48]); the MSR numbers
 * are in SDM Vol. 4 and mirrored by the pinned QEMU (third_party/qemu)
 * target/i386/cpu.h: MSR_EFER 0xC0000080 (SCE bit 0), MSR_STAR 0xC0000081,
 * MSR_LSTAR 0xC0000082, MSR_FMASK 0xC0000084, MSR_GSBASE 0xC0000101,
 * MSR_KERNELGSBASE 0xC0000102.
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
 * until it is on the kernel stack), plus TF/DF/IOPL/NT/AC hygiene
 * (bits 8-10, 12-14, 18 — SDM Vol. 1, EFLAGS). Our choice, not a spec
 * value: SFMASK may clear any bits. */
#define KI_SYSCALL_RFLAGS_MASK 0x47700ULL

KIPCR KiPcr;

/* entry.S offsets. */
_Static_assert(offsetof(KIPCR, kernelRsp) == 0, "KIPCR.kernelRsp offset welded into entry.S");
_Static_assert(offsetof(KIPCR, userRsp) == 8, "KIPCR.userRsp offset welded into entry.S");
_Static_assert(offsetof(KIPCR, userFs32Selector) == 16,
               "KIPCR.userFs32Selector offset welded into entry.S");

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

/* Dedicated #DF stack (see KI_IST_DOUBLE_FAULT in gdt.h): 8 KiB is plenty
 * for one trap frame + the dump path; 16-byte aligned per the ABI. */
static uint8_t KiDoubleFaultStack[8192] __attribute__((aligned(16)));

/* NT's KGDT64_* layout (gdt.h): null, kernel CS/DS, the three ring-3
 * descriptors, the 16-byte TSS (2 slots), and the per-thread compat-mode
 * FS. Slots 0x08 and 0x38 stay zero — NT leaves them unused too. */
static uint64_t KiGdt[KI_GDT_ENTRIES];

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

/* Build a legacy (8-byte) descriptor. Field split per Intel SDM Vol. 3A
 * §3.4.5 Fig. 3-8: limit[15:0] | base[23:0]<<16 | access<<40 |
 * limit[19:16]<<48 | flags<<52 | base[31:24]<<56. */
static uint64_t KiMakeDescriptor(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
{
    return (uint64_t)(limit & 0xFFFF) | ((uint64_t)(base & 0xFFFFFF) << 16) |
           ((uint64_t)access << 40) | ((uint64_t)((limit >> 16) & 0xF) << 48) |
           ((uint64_t)(flags & 0xF) << 52) | ((uint64_t)((base >> 24) & 0xFF) << 56);
}

void KiSetUserFs32Base(uint64_t teb32)
{
    if (!teb32)
    {
        KiGdt[KI_GDT_USER_FS32 / 8] = 0; /* not present */
        KiPcr.userFs32Selector = 0;      /* ...and the return path loads null */
        return;
    }
    /* A WOW64 TEB32 always lives under 4GB (the guest addresses it with a
     * 32-bit base), so the descriptor can carry it whole. */
    ASSERT(teb32 < (1ULL << 32));
    /* Byte granularity, one page of limit — what NT's KGDT64_R3_CMTEB
     * reports and what ntdll:wow64's test_selectors reads back (limit
     * 0xfff, type 0x13 data, D/B set, G clear). */
    KiGdt[KI_GDT_USER_FS32 / 8] = KiMakeDescriptor((uint32_t)teb32, 0xFFF, 0xF2, 1u << 2 /* D/B */);
    KiPcr.userFs32Selector = KI_USER_FS32_SELECTOR;
}

/* The LDT descriptor is a 16-byte SYSTEM descriptor in long mode (type 0x2,
 * available LDT), same shape as the TSS one below; `lldt` with a null
 * selector is how NT marks a process without an LDT. Intel SDM Vol. 3A
 * §3.5.1 "Segment Descriptor Tables" and Table 3-2 (system descriptor
 * types). */
void KiSetProcessLdt(uint64_t base, uint32_t limit)
{
    if (base == 0)
    {
        KiGdt[KI_GDT_LDT / 8] = 0;
        KiGdt[KI_GDT_LDT / 8 + 1] = 0;
        __asm__ volatile("lldt %w0" : : "r"((uint16_t)0));
        return;
    }
    KiGdt[KI_GDT_LDT / 8] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (0x82ULL << 40) |
                            (((uint64_t)(limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    KiGdt[KI_GDT_LDT / 8 + 1] = base >> 32;
    __asm__ volatile("lldt %w0" : : "r"((uint16_t)KI_GDT_LDT));
}

void KiInitializeGdt(void)
{
    /* Access bytes: P|S|type. Code 0x9A/0xFA (exec/read, DPL 0/3), data
     * 0x92/0xF2 (read/write, DPL 0/3); code adds L (bit 53). */
    for (unsigned slot = 0; slot < KI_GDT_ENTRIES; slot++)
        KiGdt[slot] = 0;
    KiGdt[KI_GDT_KERNEL_CS / 8] = (0x9AULL << 40) | (1ULL << 53);
    KiGdt[KI_GDT_KERNEL_DS / 8] = 0x92ULL << 40;
    KiGdt[KI_GDT_USER_CS / 8] = (0xFAULL << 40) | (1ULL << 53);
    /* The two compat-mode-capable ring-3 descriptors carry a REAL flat
     * limit. In long mode the CPU ignores limits, so the data descriptor
     * looked fine at limit 0 for every 64-bit process; in compatibility
     * mode limits are enforced again, and a zero-limit SS would fault the
     * guest's first push. Flat 4 GiB = limit 0xFFFFF with G (4 KiB
     * granularity); D/B selects 32-bit operand/stack width (Intel SDM
     * Vol. 3A §3.4.5). */
    KiGdt[KI_GDT_USER_DS / 8] =
        KiMakeDescriptor(0, 0xFFFFF, 0xF2, (1u << 2) /* D/B */ | (1u << 3) /* G */);
    KiGdt[KI_GDT_USER_CS32 / 8] =
        KiMakeDescriptor(0, 0xFFFFF, 0xFA, (1u << 2) /* D */ | (1u << 3) /* G */);
    /* KI_GDT_USER_FS32 stays absent until a WOW64 thread is scheduled
     * (KiSetUserFs32Base at context switch). */

    /* The 16-byte TSS descriptor: type 0x89 (available 64-bit TSS). */
    uint64_t base = (uint64_t)(uintptr_t)&KiTss;
    uint64_t limit = sizeof(KiTss) - 1;
    KiGdt[KI_GDT_TSS / 8] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (0x89ULL << 40) |
                            (((limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    KiGdt[KI_GDT_TSS / 8 + 1] = base >> 32;

    KiTss.ioMapBase = sizeof(KiTss); /* no I/O permission map */
    /* ist[] is TSS.IST1..IST7 (SDM Vol. 3A Fig. 8-11); slot n-1 backs the
     * gates whose IST field is n (idt.c arms #DF with KI_IST_DOUBLE_FAULT). */
    KiTss.ist[KI_IST_DOUBLE_FAULT - 1] =
        (uint64_t)(uintptr_t)KiDoubleFaultStack + sizeof(KiDoubleFaultStack);

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

    /* M7: enable SSE for ring 3 (Wine's PE ntdll is compiled with it) and
     * for the context switch's FXSAVE/FXRSTOR of the per-thread XMM state.
     * CR4.OSFXSR (bit 9) legalizes SSE + gives FXSAVE the XMM registers;
     * CR4.OSXMMEXCPT (bit 10) routes unmasked SSE exceptions to #XM.
     * CR0.MP (bit 1) set, CR0.EM (bit 2) and CR0.TS (bit 3) clear — no
     * lazy-FPU trapping; the switch saves eagerly (Intel SDM Vol. 3A
     * "System Programming For Instruction Set Extensions" / Vol. 1 10.5).
     * Kernel code itself stays -mno-sse. */
    uint64_t cr = 0;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr));
    cr |= (1ULL << 9) | (1ULL << 10);
    /* SMEP (CR4 bit 20) and SMAP (CR4 bit 21) are put into a DEFINED state
     * rather than inherited from whatever the bootloader left behind
     * (docs/review-2026-07 §8). Both are cleared, and that is a decision,
     * not an omission: kernel/syscall/uaccess.c dereferences user addresses
     * from ring 0 directly (KiCopyFromUser, the probes, MiCopyToUserRange)
     * and kernel/init/panic.c walks a user RBP chain for the dump, so SMAP
     * would fault every one of them; and turning SMEP on without SMAP would
     * leave the weaker half of the pair guarding nothing this kernel does.
     * Enabling them belongs with STAC/CLAC annotations on the copy routines,
     * which is a change of its own. Bits: Intel SDM Vol. 3A §2.5
     * "Control Registers", Table 2-2. */
    cr &= ~((1ULL << 20) | (1ULL << 21));
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr));
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr));
    cr = (cr | (1ULL << 1)) & ~((1ULL << 2) | (1ULL << 3));
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr));

    /* GS = the PCR while in kernel mode; KERNEL_GS_BASE holds the outgoing
     * user GS base (the TEB), swapped at every crossing. */
    KiWriteMsr(IA32_GS_BASE, (uint64_t)(uintptr_t)&KiPcr);
    KiWriteMsr(IA32_KERNEL_GS_BASE, 0);

    /* Arm syscall/sysret. syscall: CS = STAR[47:32], SS = +8 (kernel CS then
     * kernel DS). sysretq: CS = STAR[63:48] + 16, SS = STAR[63:48] + 8 —
     * so the sysret base is the COMPAT code slot, and the ring-3 trio reads
     * 0x23/0x2b/0x33 exactly as NT's does. proskrnl always returns to user
     * mode by iretq (kernel/syscall/entry.S — an iret frame is what makes
     * NtContinue and exception dispatch expressible), so these bases are
     * armed for correctness rather than used. */
    KiWriteMsr(IA32_STAR,
               ((uint64_t)KI_GDT_KERNEL_CS << 32) | ((uint64_t)KI_USER_CS32_SELECTOR << 48));
    KiWriteMsr(IA32_LSTAR, (uint64_t)(uintptr_t)KiSystemCall64);
    KiWriteMsr(IA32_FMASK, KI_SYSCALL_RFLAGS_MASK);
    KiWriteMsr(IA32_EFER, KiReadMsr(IA32_EFER) | IA32_EFER_SCE);
}
