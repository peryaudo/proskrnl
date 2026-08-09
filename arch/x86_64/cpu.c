/* arch/x86_64/cpu.c — the machine's feature set, stated once.
 *
 * KUSER_SHARED_DATA.ProcessorFeatures is the boundary's answer to "may I
 * execute this instruction": Wine's PE ntdll implements
 * RtlIsProcessorFeaturePresent as nothing but a load from the array
 * (third_party/wine dlls/ntdll/signal_x86_64.c
 * `user_shared_data->ProcessorFeatures[feature]`), and msvcrt/ucrtbase pick
 * their string and math routines from the answer. So a zeroed array is a
 * machine on which nothing is available, and an entry set for a feature ring
 * 3 cannot actually use is a fault waiting for a caller that believes it —
 * which is the fabricated-plausible-answer failure Art. 12 is about, in the
 * one place where the fabrication is not a status but a bit.
 *
 * Derived from CPUID exactly as the oracle derives it
 * (dlls/ntdll/unix/system.c init_shared_data_cpuinfo), with one difference
 * that is a difference in the MACHINE and not in the rule: a feature whose
 * register state this kernel does not preserve is not available on it. See
 * KiXstateFeaturesUsable below; docs/03 "Processor features" carries it.
 *
 * CPUID leaf/bit numbers: Intel SDM Vol. 2A, the CPUID instruction — the
 * feature-information rows for leaf 1 ECX and EDX and the
 * structured-extended-feature rows for leaf 7 (cited by leaf and register
 * rather than by table number, which moves between SDM revisions); the
 * 0x80000001 rows from AMD64 APM Vol. 3, CPUID Fn8000_0001_E[CD]X. Which
 * PF_* number each one feeds is the oracle's assignment, cited above; the
 * numbers themselves are generated (abi/ntkeapi.h, Art. 4).
 */
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/io.h"

/* CR4.FSGSBASE (Intel SDM Vol. 3A §2.5, Table 2-2 — bit 16): with it clear,
 * RDFSBASE and its siblings raise #UD in ring 3 however capable the CPU is.
 * arch/x86_64/gdt.c does not set it. */
#define KI_CR4_FSGSBASE (1ULL << 16)

static uint64_t KiReadCr4(void)
{
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    return cr4;
}

void KiInitializeProcessorFeatures(BOOLEAN *features)
{
    uint32_t regs[4];

    /* Neither is a CPUID bit on the oracle either: __fastfail is an OS
     * service, and CMPXCHG8B is architecturally present on every x86_64. */
    features[PF_FASTFAIL_AVAILABLE] = TRUE;
    features[PF_COMPARE_EXCHANGE_DOUBLE] = TRUE;

    KiCpuid(1, 0, regs);
    features[PF_RDTSC_INSTRUCTION_AVAILABLE] = !!(regs[3] & (1u << 4));
    features[PF_PAE_ENABLED] = !!(regs[3] & (1u << 6));
    features[PF_MMX_INSTRUCTIONS_AVAILABLE] = !!(regs[3] & (1u << 23));
    /* SSE needs FXSR beside it, because the OS saves the XMM registers with
     * FXSAVE — the oracle spells the same pair, and here it is literally
     * true: arch/x86_64/ctxswitch.S is an fxsave64. */
    features[PF_XMMI_INSTRUCTIONS_AVAILABLE] = (regs[3] & (1u << 24)) && (regs[3] & (1u << 25));
    features[PF_XMMI64_INSTRUCTIONS_AVAILABLE] = !!(regs[3] & (1u << 26));
    features[PF_SSE3_INSTRUCTIONS_AVAILABLE] = !!(regs[2] & (1u << 0));
    features[PF_VIRT_FIRMWARE_ENABLED] = !!(regs[2] & (1u << 5));
    features[PF_SSSE3_INSTRUCTIONS_AVAILABLE] = !!(regs[2] & (1u << 9));
    features[PF_COMPARE_EXCHANGE128] = !!(regs[2] & (1u << 13));
    features[PF_SSE4_1_INSTRUCTIONS_AVAILABLE] = !!(regs[2] & (1u << 19));
    features[PF_SSE4_2_INSTRUCTIONS_AVAILABLE] = !!(regs[2] & (1u << 20));
    /* Bit 27 is OSXSAVE, not bit 26's XSAVE: the flag reports whether the
     * RUNNING KERNEL enabled the extended state, and the CPU's own XSAVE bit
     * says nothing about that. It mirrors CR4.OSXSAVE, which this kernel
     * never sets (the context switch is an FXSAVE image, kernel/ke/ke.h), so
     * it reads FALSE here — measured, not hardwired. */
    features[PF_XSAVE_ENABLED] = !!(regs[2] & (1u << 27));
    features[PF_AVX_INSTRUCTIONS_AVAILABLE] = !!(regs[2] & (1u << 28));
    features[PF_RDRAND_INSTRUCTION_AVAILABLE] = !!(regs[2] & (1u << 30));
    /* Every x86_64 has SSE2, and every SSE2 implementation has DAZ — which
     * is why the oracle's have_sse_daz_mode() is `return TRUE` off i386. */
    features[PF_SSE_DAZ_MODE_AVAILABLE] = features[PF_XMMI64_INSTRUCTIONS_AVAILABLE];

    KiCpuid(0, 0, regs);
    if (regs[0] >= 7)
    {
        KiCpuid(7, 0, regs);
        features[PF_RDWRFSGSBASE_AVAILABLE] = !!(regs[1] & (1u << 0));
        features[PF_AVX2_INSTRUCTIONS_AVAILABLE] = !!(regs[1] & (1u << 5));
        features[PF_BMI2_INSTRUCTIONS_AVAILABLE] = !!(regs[1] & (1u << 8));
        features[PF_ERMS_AVAILABLE] = !!(regs[1] & (1u << 9));
        features[PF_AVX512F_INSTRUCTIONS_AVAILABLE] = !!(regs[1] & (1u << 16));
        features[PF_RDPID_INSTRUCTION_AVAILABLE] = !!(regs[2] & (1u << 22));
        features[PF_MOVDIR64B_INSTRUCTION_AVAILABLE] = !!(regs[2] & (1u << 28));
    }

    KiCpuid(0x80000000, 0, regs);
    if (regs[0] >= 0x80000001)
    {
        KiCpuid(0x80000001, 0, regs);
        features[PF_MONITORX_INSTRUCTION_AVAILABLE] = !!(regs[2] & (1u << 29));
        features[PF_NX_ENABLED] = !!(regs[3] & (1u << 20));
        features[PF_RDTSCP_INSTRUCTION_AVAILABLE] = !!(regs[3] & (1u << 27));
        features[PF_VIRT_FIRMWARE_ENABLED] |= !!(regs[2] & (1u << 2));
        features[PF_3DNOW_INSTRUCTIONS_AVAILABLE] = !!(regs[3] & (1u << 31));
    }

    /* --- what the OS has not enabled is not available ------------------- */

    /* The oracle applies this shape to exactly one flag — on Linux it ANDs
     * PF_RDWRFSGSBASE_AVAILABLE with the host kernel's AT_HWCAP2 bit, i.e.
     * with whether that kernel set CR4.FSGSBASE. Here the same question is
     * answered by reading CR4 directly, because here we are that kernel.
     *
     * The AVX family needs the same treatment and the oracle does not give
     * it, because the OS it runs on always enables XSAVE: VEX-encoded
     * instructions raise #UD while CR4.OSXSAVE is clear, so reporting them
     * available would hand a caller a fault. This is the whole of the
     * difference from init_shared_data_cpuinfo, and it makes the array a
     * statement about the machine as ring 3 finds it rather than about the
     * silicon. When XSAVE is enabled here, this gate must become the XCR0
     * state test (the YMM/ZMM bits), not simply be deleted — CR4.OSXSAVE
     * alone does not say which states the kernel actually saves. */
    if (!features[PF_XSAVE_ENABLED])
    {
        features[PF_AVX_INSTRUCTIONS_AVAILABLE] = FALSE;
        features[PF_AVX2_INSTRUCTIONS_AVAILABLE] = FALSE;
        features[PF_AVX512F_INSTRUCTIONS_AVAILABLE] = FALSE;
    }
    if ((KiReadCr4() & KI_CR4_FSGSBASE) == 0)
    {
        features[PF_RDWRFSGSBASE_AVAILABLE] = FALSE;
    }
}

ULONGLONG KiProcessorFeatureBits(const BOOLEAN *features)
{
    /* The AMD64 arm of the oracle's get_cpu_features, bit for bit
     * (dlls/ntdll/unix/system.c, whose comment cites the KF_* flags and
     * Geoff Chappell's documentation of them). The base word is the set
     * every x86_64 implementation is architecturally required to have —
     * tsc, vme, cmov, pge, pse, mtrr, cx8, mmx, pat, fxsr, sep, sse, sse2,
     * nx — so it is a fact about the architecture; every optional bit is
     * the ProcessorFeatures array's answer restated, never a second read of
     * CPUID (Art. 11). */
    ULONGLONG bits = 0x20013dfe;

    if (features[PF_RDRAND_INSTRUCTION_AVAILABLE])
    {
        bits |= 0x100000000ULL; /* rdrand */
    }
    if (features[PF_XSAVE_ENABLED])
    {
        bits |= 0x00800000ULL; /* xstate */
    }
    if (features[PF_COMPARE_EXCHANGE128])
    {
        bits |= 0x00100000ULL; /* cx16 */
    }
    if (features[PF_SSE3_INSTRUCTIONS_AVAILABLE])
    {
        bits |= 0x00080000ULL; /* sse3 */
    }
    if (features[PF_RDTSCP_INSTRUCTION_AVAILABLE])
    {
        bits |= 0x400000000ULL; /* rdtscp */
    }
    if (features[PF_RDWRFSGSBASE_AVAILABLE])
    {
        bits |= 0x10000000ULL; /* fsgsbase */
    }

    /* The vendor bit. The string is EBX:EDX:ECX of leaf 0 (Intel SDM Vol. 2A,
     * CPUID leaf 0) and is not a ProcessorFeatures entry on either side, so
     * this is the one thing here read from the CPU rather than from the
     * array. */
    uint32_t regs[4];
    KiCpuid(0, 0, regs);
    if (regs[1] == 0x68747541 && regs[3] == 0x69746E65 && regs[2] == 0x444D4163)
    {
        bits |= 0x00200000ULL; /* "AuthenticAMD" */
    }
    else if (regs[1] == 0x756E6547 && regs[3] == 0x49656E69 && regs[2] == 0x6C65746E)
    {
        bits |= 0x01000000ULL; /* "GenuineIntel" */
    }
    return bits;
}
