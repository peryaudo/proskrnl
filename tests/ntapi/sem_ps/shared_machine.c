/*
 * sem_ps/shared_machine.c — what KUSER_SHARED_DATA says about the MACHINE.
 *
 * The time fields are sem_ps/time.c's subject; this pins the other half of
 * the shared page, the description of the box: how much physical memory it
 * has, how many processors are running, and which instructions ring 3 may
 * execute. Wine's PE ntdll reads the last of those directly —
 * RtlIsProcessorFeaturePresent is nothing but
 * `user_shared_data->ProcessorFeatures[feature]` (third_party/wine
 * dlls/ntdll/signal_x86_64.c:867) — so a zeroed array is a machine on which
 * every capability query answers "no", and a WRONGLY SET entry is a machine
 * on which a caller executes an instruction that faults.
 *
 * The oracle fills the array in dlls/ntdll/unix/system.c
 * init_shared_data_cpuinfo and derives the KF_* word class 154 reports from
 * that same array (get_cpu_features's `const BOOLEAN *pf =
 * user_shared_data->ProcessorFeatures`). That ONE-authority relation is
 * pinned here too: it is what stops the two answers drifting (Art. 11).
 *
 * WHAT THIS TEST DELIBERATELY DOES NOT DO is hard-code a feature set. The
 * developer box, CI's TCG guest and the oracle's host are three different
 * CPUs; a pin that named features would measure the box. So every optional
 * feature is checked against CPUID *executed by this test*, which both
 * runners can do from ring 3, and only the bits x86-64 architecturally
 * mandates are asserted outright.
 */
#include "util.h"

/* mingw's winnt.h has the PF_* numbers, but not all of the ones used here
 * (PF_BMI2_INSTRUCTIONS_AVAILABLE / PF_MOVDIR64B_INSTRUCTION_AVAILABLE are
 * recent). Spelled as wine/include/winnt.h numbers them — the same list the
 * kernel's generated abi/ntkeapi.h carries. */
#ifndef PF_RDTSC_INSTRUCTION_AVAILABLE
#define PF_RDTSC_INSTRUCTION_AVAILABLE 8
#endif
#ifndef PF_COMPARE_EXCHANGE_DOUBLE
#define PF_COMPARE_EXCHANGE_DOUBLE 2
#endif
#ifndef PF_MMX_INSTRUCTIONS_AVAILABLE
#define PF_MMX_INSTRUCTIONS_AVAILABLE 3
#endif
#ifndef PF_XMMI_INSTRUCTIONS_AVAILABLE
#define PF_XMMI_INSTRUCTIONS_AVAILABLE 6
#endif
#ifndef PF_XMMI64_INSTRUCTIONS_AVAILABLE
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE 10
#endif
#ifndef PF_PAE_ENABLED
#define PF_PAE_ENABLED 9
#endif
#ifndef PF_SSE_DAZ_MODE_AVAILABLE
#define PF_SSE_DAZ_MODE_AVAILABLE 11
#endif
#ifndef PF_SSE3_INSTRUCTIONS_AVAILABLE
#define PF_SSE3_INSTRUCTIONS_AVAILABLE 13
#endif
#ifndef PF_COMPARE_EXCHANGE128
#define PF_COMPARE_EXCHANGE128 14
#endif
#ifndef PF_XSAVE_ENABLED
#define PF_XSAVE_ENABLED 17
#endif
#ifndef PF_FASTFAIL_AVAILABLE
#define PF_FASTFAIL_AVAILABLE 23
#endif
#ifndef PF_RDRAND_INSTRUCTION_AVAILABLE
#define PF_RDRAND_INSTRUCTION_AVAILABLE 28
#endif
#ifndef PF_RDTSCP_INSTRUCTION_AVAILABLE
#define PF_RDTSCP_INSTRUCTION_AVAILABLE 32
#endif
#ifndef PF_SSSE3_INSTRUCTIONS_AVAILABLE
#define PF_SSSE3_INSTRUCTIONS_AVAILABLE 36
#endif
#ifndef PF_SSE4_1_INSTRUCTIONS_AVAILABLE
#define PF_SSE4_1_INSTRUCTIONS_AVAILABLE 37
#endif
#ifndef PF_SSE4_2_INSTRUCTIONS_AVAILABLE
#define PF_SSE4_2_INSTRUCTIONS_AVAILABLE 38
#endif
#ifndef PF_AVX_INSTRUCTIONS_AVAILABLE
#define PF_AVX_INSTRUCTIONS_AVAILABLE 39
#endif
#ifndef PF_AVX2_INSTRUCTIONS_AVAILABLE
#define PF_AVX2_INSTRUCTIONS_AVAILABLE 40
#endif
#ifndef PF_AVX512F_INSTRUCTIONS_AVAILABLE
#define PF_AVX512F_INSTRUCTIONS_AVAILABLE 41
#endif
#ifndef PF_ERMS_AVAILABLE
#define PF_ERMS_AVAILABLE 42
#endif
#ifndef PF_BMI2_INSTRUCTIONS_AVAILABLE
#define PF_BMI2_INSTRUCTIONS_AVAILABLE 60
#endif
#ifndef PF_MOVDIR64B_INSTRUCTION_AVAILABLE
#define PF_MOVDIR64B_INSTRUCTION_AVAILABLE 61
#endif

/* The x64 shared page VA and the three fields read here, at their fixed
 * offsets as wine/include/ddk/wdm.h lays them out (mingw's user-mode headers
 * omit KUSER_SHARED_DATA, a DDK type — sem_ps/time.c does the same). The
 * offsets are static_assert-pinned on the kernel side in abi/ntkeapi.h. */
#define USD_BASE                  ((volatile BYTE *)0x7ffe0000)
#define USD_PROCESSOR_FEATURES    ((volatile BYTE *)(USD_BASE + 0x274))
#define USD_NUMBER_PHYSICAL_PAGES (*(volatile ULONG *)(USD_BASE + 0x2e8))
#define USD_ACTIVE_PROCESSORS     (*(volatile ULONG *)(USD_BASE + 0x3c0))
#define USD_ACTIVE_GROUPS         (*(volatile UCHAR *)(USD_BASE + 0x3c4))
#define USD_XSTATE_ENABLED        (*(volatile ULONGLONG *)(USD_BASE + 0x3d8))

/* wine/include/winternl.h SystemProcessorFeaturesInformation = 154; the
 * struct is one ULONGLONG (SYSTEM_PROCESSOR_FEATURES_INFORMATION). */
#define PS_SystemProcessorFeaturesInformation ((SYSTEM_INFORMATION_CLASS)154)

/* The KF_* bits get_cpu_features composes, by the same values and in the
 * same order (dlls/ntdll/unix/system.c; the file cites Geoff Chappell's
 * documentation of the KF_* flags for them). */
#define KF_BASE_AMD64                                                                              \
    0x20013dfeULL /* tsc|vme|cmov|pge|pse|mtrr|cx8|mmx|pat|fxsr|sep|sse|sse2|nx                    \
                   */
#define KF_SSE3       0x00080000ULL
#define KF_CMPXCHG16B 0x00100000ULL
#define KF_XSTATE     0x00800000ULL
#define KF_FSGSBASE   0x10000000ULL
#define KF_RDRAND     0x100000000ULL
#define KF_RDTSCP     0x400000000ULL

static void test_cpuid(unsigned leaf, unsigned subleaf, unsigned regs[4])
{
    __asm__ volatile("cpuid"
                     : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
                     : "a"(leaf), "c"(subleaf));
}

/* Read one PF_* entry as the BOOLEAN byte it is. */
static int pf(unsigned feature)
{
    return USD_PROCESSOR_FEATURES[feature] != 0;
}

START_TEST(shared_machine)
{
    NTSTATUS status;
    SYSTEM_BASIC_INFORMATION sbi;
    ULONG len = 0;
    unsigned regs[4], leaf1ecx = 0, leaf1edx = 0, leaf7ebx = 0, leaf7ecx = 0;
    unsigned ext1ecx = 0, ext1edx = 0, maxLeaf, maxExtLeaf;

    /* --- the memory and processor counts -------------------------------- */

    memset(&sbi, 0, sizeof(sbi));
    status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), &len);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);

    /* The shared page and SystemBasicInformation report the SAME number,
     * because on the oracle they are one variable (dlls/ntdll/unix/system.c
     * fills both from the host's page count). ntdll:virtual's
     * test_user_shared_data compares them field to field, so the agreement
     * is the contract and neither value alone is. */
    ok(USD_NUMBER_PHYSICAL_PAGES != 0, "NumberOfPhysicalPages is zero");
    ok(USD_NUMBER_PHYSICAL_PAGES == sbi.NumberOfPhysicalPages,
       "NumberOfPhysicalPages %#lx vs SystemBasicInformation %#lx",
       (unsigned long)USD_NUMBER_PHYSICAL_PAGES, (unsigned long)sbi.NumberOfPhysicalPages);

    /* ActiveProcessorCount is the RUNNING count, which on both runners is
     * what SystemBasicInformation reports (Wine's PEB->NumberOfProcessors,
     * which the winetest compares against, is filled from the same value). */
    ok(USD_ACTIVE_PROCESSORS == (ULONG)(UCHAR)sbi.NumberOfProcessors,
       "ActiveProcessorCount %lu vs SystemBasicInformation %u",
       (unsigned long)USD_ACTIVE_PROCESSORS, (unsigned)(UCHAR)sbi.NumberOfProcessors);

    /* One processor GROUP. Not a count of anything measurable — a machine
     * that has processors has at least one group, and both runners report
     * exactly one. */
    ok(USD_ACTIVE_GROUPS == 1, "ActiveGroupCount %u", (unsigned)USD_ACTIVE_GROUPS);

    /* --- the features x86-64 mandates ----------------------------------- */

    /* Every x86-64 implementation has these, so they are facts about the
     * architecture rather than measurements of this box: an assertion here
     * cannot go red for a host reason. */
    ok(pf(PF_RDTSC_INSTRUCTION_AVAILABLE), "PF_RDTSC_INSTRUCTION_AVAILABLE clear");
    ok(pf(PF_COMPARE_EXCHANGE_DOUBLE), "PF_COMPARE_EXCHANGE_DOUBLE clear");
    ok(pf(PF_MMX_INSTRUCTIONS_AVAILABLE), "PF_MMX_INSTRUCTIONS_AVAILABLE clear");
    ok(pf(PF_XMMI_INSTRUCTIONS_AVAILABLE), "PF_XMMI_INSTRUCTIONS_AVAILABLE clear");
    ok(pf(PF_XMMI64_INSTRUCTIONS_AVAILABLE), "PF_XMMI64_INSTRUCTIONS_AVAILABLE clear");
    ok(pf(PF_PAE_ENABLED), "PF_PAE_ENABLED clear");
    /* Not a CPUID bit on either side: the oracle sets it unconditionally
     * (init_shared_data_cpuinfo's first two lines) because __fastfail is an
     * OS service, not an instruction feature. */
    ok(pf(PF_FASTFAIL_AVAILABLE), "PF_FASTFAIL_AVAILABLE clear");
    /* x86-64 implies SSE2, and every SSE2 implementation has DAZ — which is
     * why the oracle's have_sse_daz_mode() is `return TRUE` outside i386. */
    ok(pf(PF_SSE_DAZ_MODE_AVAILABLE), "PF_SSE_DAZ_MODE_AVAILABLE clear");

    /* --- the optional features, against CPUID as ring 3 sees it --------- */

    test_cpuid(0, 0, regs);
    maxLeaf = regs[0];
    test_cpuid(1, 0, regs);
    leaf1ecx = regs[2];
    leaf1edx = regs[3];
    if (maxLeaf >= 7)
    {
        test_cpuid(7, 0, regs);
        leaf7ebx = regs[1];
        leaf7ecx = regs[2];
    }
    test_cpuid(0x80000000, 0, regs);
    maxExtLeaf = regs[0];
    if (maxExtLeaf >= 0x80000001)
    {
        test_cpuid(0x80000001, 0, regs);
        ext1ecx = regs[2];
        ext1edx = regs[3];
    }

    /* CPUID leaf/bit numbers: Intel SDM Vol. 2A, the CPUID instruction —
     * the feature-information rows for leaf 1 ECX and the
     * structured-extended-feature rows for leaf 7 (cited by leaf and
     * register rather than by table number, which moves between SDM
     * revisions); the AMD one from AMD64 APM Vol. 3, CPUID Fn8000_0001. The
     * assignment of each to a PF_* number is the oracle's
     * (init_shared_data_cpuinfo). */
    ok(pf(PF_SSE3_INSTRUCTIONS_AVAILABLE) == !!(leaf1ecx & (1u << 0)), "PF_SSE3 vs CPUID.1:ECX.0");
    ok(pf(PF_SSSE3_INSTRUCTIONS_AVAILABLE) == !!(leaf1ecx & (1u << 9)),
       "PF_SSSE3 vs CPUID.1:ECX.9");
    ok(pf(PF_COMPARE_EXCHANGE128) == !!(leaf1ecx & (1u << 13)), "PF_CMPXCHG16B vs CPUID.1:ECX.13");
    ok(pf(PF_SSE4_1_INSTRUCTIONS_AVAILABLE) == !!(leaf1ecx & (1u << 19)),
       "PF_SSE4_1 vs CPUID.1:ECX.19");
    ok(pf(PF_SSE4_2_INSTRUCTIONS_AVAILABLE) == !!(leaf1ecx & (1u << 20)),
       "PF_SSE4_2 vs CPUID.1:ECX.20");
    ok(pf(PF_RDRAND_INSTRUCTION_AVAILABLE) == !!(leaf1ecx & (1u << 30)),
       "PF_RDRAND vs CPUID.1:ECX.30");
    ok(pf(PF_ERMS_AVAILABLE) == !!(leaf7ebx & (1u << 9)), "PF_ERMS vs CPUID.7:EBX.9");
    ok(pf(PF_BMI2_INSTRUCTIONS_AVAILABLE) == !!(leaf7ebx & (1u << 8)), "PF_BMI2 vs CPUID.7:EBX.8");
    ok(pf(PF_MOVDIR64B_INSTRUCTION_AVAILABLE) == !!(leaf7ecx & (1u << 28)),
       "PF_MOVDIR64B vs CPUID.7:ECX.28");
    ok(pf(PF_RDTSCP_INSTRUCTION_AVAILABLE) == !!(ext1edx & (1u << 27)),
       "PF_RDTSCP vs CPUID.80000001:EDX.27");
    (void)ext1ecx;
    (void)leaf1edx;

    /* PF_XSAVE_ENABLED is the OS-ENABLE bit, not the CPU's XSAVE bit: the
     * oracle reads CPUID.1:ECX.27 (OSXSAVE), which mirrors CR4.OSXSAVE and
     * is therefore a statement about the running kernel. Reading ECX.26
     * (the CPU's XSAVE) instead reports "enabled" on a kernel that never
     * enabled it — which is the whole failure mode this flag exists to
     * prevent. */
    ok(pf(PF_XSAVE_ENABLED) == !!(leaf1ecx & (1u << 27)), "PF_XSAVE_ENABLED vs CPUID.1:ECX.27");

    /* The AVX family needs XSAVE-managed state, so a kernel that has not
     * enabled XSAVE cannot offer it however capable the silicon is. The
     * implication is what both runners share: the oracle runs on a kernel
     * that DOES enable it, so this is not vacuous there. */
    if (!pf(PF_XSAVE_ENABLED))
    {
        ok(!pf(PF_AVX_INSTRUCTIONS_AVAILABLE), "PF_AVX set without XSAVE enabled");
        ok(!pf(PF_AVX2_INSTRUCTIONS_AVAILABLE), "PF_AVX2 set without XSAVE enabled");
        ok(!pf(PF_AVX512F_INSTRUCTIONS_AVAILABLE), "PF_AVX512F set without XSAVE enabled");
    }
    else
    {
        ok(pf(PF_AVX_INSTRUCTIONS_AVAILABLE) == !!(leaf1ecx & (1u << 28)),
           "PF_AVX vs CPUID.1:ECX.28");
        ok(pf(PF_AVX2_INSTRUCTIONS_AVAILABLE) == !!(leaf7ebx & (1u << 5)),
           "PF_AVX2 vs CPUID.7:EBX.5");
        ok(pf(PF_AVX512F_INSTRUCTIONS_AVAILABLE) == !!(leaf7ebx & (1u << 16)),
           "PF_AVX512F vs CPUID.7:EBX.16");
    }

    /* XState.EnabledFeatures is the other half of the same statement:
     * nothing may be enumerated there while XSAVE is off, or
     * RtlGetEnabledExtendedFeatures reports state no context record
     * carries. */
    if (!pf(PF_XSAVE_ENABLED))
    {
        ok(USD_XSTATE_ENABLED == 0, "XState.EnabledFeatures %#llx without XSAVE enabled",
           (unsigned long long)USD_XSTATE_ENABLED);
    }

    /* --- class 154 derives from the array, and does not re-derive ------- */

    /* The oracle composes the KF_* word by READING this array
     * (get_cpu_features's `pf` pointer), so every conditional bit is the
     * array's answer restated. Two derivations of one fact drift; this is
     * the assertion that catches it (Art. 11).
     *
     * Only the bits get_cpu_features gates on a PF_* entry are checked —
     * the base word is the architecture's, and the vendor bits are a string
     * comparison this test has no business repeating. */
    {
        /* The class's buffer is FOUR words, not one — the oracle refuted the
         * obvious guess here: a `ULONGLONG` buffer is
         * STATUS_INFO_LENGTH_MISMATCH with ret_size 32
         * (SYSTEM_PROCESSOR_FEATURES_INFORMATION is ProcessorFeatureBits
         * plus `ULONGLONG Reserved[3]`, wine/include/winternl.h). Only the
         * first word carries anything. */
        ULONGLONG info[4] = {0, 0, 0, 0};
        ULONGLONG kf;
        len = 0;
        status = NtQuerySystemInformation(PS_SystemProcessorFeaturesInformation, info, sizeof(info),
                                          &len);
        ok(status == STATUS_SUCCESS, "SystemProcessorFeaturesInformation -> %08lx",
           (unsigned long)status);
        ok(len == sizeof(info), "return length %lu", (unsigned long)len);
        kf = info[0];
        ok((kf & KF_BASE_AMD64) == KF_BASE_AMD64, "KF base word missing from %#llx",
           (unsigned long long)kf);
        ok(!!(kf & KF_SSE3) == pf(PF_SSE3_INSTRUCTIONS_AVAILABLE), "KF sse3 vs PF_SSE3");
        ok(!!(kf & KF_CMPXCHG16B) == pf(PF_COMPARE_EXCHANGE128), "KF cx16 vs PF_CMPXCHG16B");
        ok(!!(kf & KF_XSTATE) == pf(PF_XSAVE_ENABLED), "KF xstate vs PF_XSAVE_ENABLED");
        ok(!!(kf & KF_RDRAND) == pf(PF_RDRAND_INSTRUCTION_AVAILABLE), "KF rdrand vs PF_RDRAND");
        ok(!!(kf & KF_RDTSCP) == pf(PF_RDTSCP_INSTRUCTION_AVAILABLE), "KF rdtscp vs PF_RDTSCP");
        ok(!!(kf & KF_FSGSBASE) == pf(22 /* PF_RDWRFSGSBASE_AVAILABLE */),
           "KF fsgsbase vs PF_RDWRFSGSBASE");

        /* SystemCpuInformation reports the SAME word in a ULONG field, so
         * the two classes cannot answer a feature question differently.
         * The oracle spells that as one call (`.ProcessorFeatureBits =
         * get_cpu_features()`, get_cpuinfo); an implementation with a
         * private derivation behind either class passes every assertion
         * above and fails this one. */
        struct
        {
            USHORT ProcessorArchitecture;
            USHORT ProcessorLevel;
            USHORT ProcessorRevision;
            USHORT MaximumProcessors;
            ULONG ProcessorFeatureBits;
        } sci;
        memset(&sci, 0, sizeof(sci));
        len = 0;
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)1, &sci, sizeof(sci), &len);
        ok(status == STATUS_SUCCESS, "SystemCpuInformation -> %08lx", (unsigned long)status);
        ok(sci.ProcessorFeatureBits == (ULONG)kf, "SystemCpuInformation bits %#lx vs KF %#llx",
           (unsigned long)sci.ProcessorFeatureBits, (unsigned long long)kf);
    }
}
