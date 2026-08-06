/*
 * sem_ps/system_fixed_classes.c — the fixed-shape NtQuerySystemInformation
 * classes ntdll:info sweeps.
 *
 * Each of these was unbuilt, and unbuilt means the armed boot PANICS
 * (Art. 12) — so ntdll:info was not failing on them, it was dying on the
 * first one it reached and never seeing the rest. That is the loud refusal
 * working, and clearing them is a walk: fix one, the pair advances to the
 * next.
 *
 * What these five have in common is that their answers do not depend on
 * anything proskrnl measures — they are shape plus a constant. That makes
 * them the easiest possible class to get WRONG in the way G12 forbids,
 * because "return a plausible constant" is both the right implementation
 * and the classic silent stub. The difference is only this file: a fixed
 * answer is legitimate exactly when it is pinned oracle behaviour, and
 * illegitimate when it is invented. Every value below was read off the
 * oracle, and two of them are values the oracle itself calls a stub
 * (SystemRegistryQuotaInformation's 32 MB and SystemLeapSecondInformation's
 * Enabled flag). Reproducing a stub's OUTPUT is not stubbing: Art. 6 makes
 * the oracle the spec, and a caller cannot tell the difference.
 *
 *   35  SystemKernelDebuggerInformation   DebuggerEnabled 0, NotPresent 1
 *   37  SystemRegistryQuotaInformation    allowed 0x2000000, used 0x200000
 *   62  SystemEmulationBasicInformation   == SystemBasicInformation here
 *   154 SystemProcessorFeaturesInformation a feature bitmap
 *   206 SystemLeapSecondInformation       Enabled 1, Flags 0
 *
 * Class 62 is an alias for the same reason 114 is: "emulation" means the
 * 32-bit view a WOW64 caller would get, and proskrnl has no WOW64, so the
 * emulated view IS the native one.
 *
 * The length rule is NOT uniform across them and that is worth pinning
 * too: most take `size >= len`, but the basic-shaped ones demand an EXACT
 * length. Both are asserted below.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

#define SystemKernelDebuggerInformation_    ((SYSTEM_INFORMATION_CLASS)35)
#define SystemRegistryQuotaInformation_     ((SYSTEM_INFORMATION_CLASS)37)
#define SystemEmulationBasicInformation_    ((SYSTEM_INFORMATION_CLASS)62)
#define SystemProcessorFeaturesInformation_ ((SYSTEM_INFORMATION_CLASS)154)
#define SystemLeapSecondInformation_        ((SYSTEM_INFORMATION_CLASS)206)

START_TEST(system_fixed_classes)
{
    NTSTATUS status;
    ULONG returnLength;
    UCHAR buffer[128];

    /* --- 35: the debugger is off and absent ------------------------------ */
    {
        UCHAR debugger[2];
        returnLength = 0;
        status = NtQuerySystemInformation(SystemKernelDebuggerInformation_, debugger,
                                          sizeof(debugger), &returnLength);
        ok(status == STATUS_SUCCESS, "KernelDebugger -> %08lx", (unsigned long)status);
        ok(returnLength == 2, "KernelDebugger returned %lu bytes", (unsigned long)returnLength);
        ok(debugger[0] == 0, "DebuggerEnabled is %u", (unsigned)debugger[0]);
        ok(debugger[1] == 1, "DebuggerNotPresent is %u", (unsigned)debugger[1]);

        /* A short buffer is a LENGTH complaint. */
        status =
            NtQuerySystemInformation(SystemKernelDebuggerInformation_, debugger, 1, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "KernelDebugger short -> %08lx",
           (unsigned long)status);

        /* An OVER-sized buffer is accepted: this class is `size >= len`,
         * unlike the basic-shaped ones below. */
        status = NtQuerySystemInformation(SystemKernelDebuggerInformation_, buffer, sizeof(buffer),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "KernelDebugger oversized -> %08lx", (unsigned long)status);
        ok(returnLength == 2, "KernelDebugger oversized returned %lu", (unsigned long)returnLength);
    }

    /* --- 37: the registry quota ------------------------------------------ */
    {
        ULONG quota[4];
        returnLength = 0;
        status = NtQuerySystemInformation(SystemRegistryQuotaInformation_, quota, sizeof(quota),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "RegistryQuota -> %08lx", (unsigned long)status);
        ok(quota[0] == 0x2000000, "RegistryQuotaAllowed %08lx", (unsigned long)quota[0]);
        ok(quota[1] == 0x200000, "RegistryQuotaUsed %08lx", (unsigned long)quota[1]);

        status = NtQuerySystemInformation(SystemRegistryQuotaInformation_, quota, 4, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "RegistryQuota short -> %08lx",
           (unsigned long)status);
    }

    /* --- 62: the emulated basic view is the native one ------------------- */
    {
        UCHAR native[64], emulated[64];
        ULONG nativeLength = 0, emulatedLength = 0;
        NTSTATUS nativeStatus =
            NtQuerySystemInformation(SystemBasicInformation, native, sizeof(native), &nativeLength);
        ok(nativeStatus == STATUS_SUCCESS, "SystemBasicInformation -> %08lx",
           (unsigned long)nativeStatus);
        status = NtQuerySystemInformation(SystemEmulationBasicInformation_, emulated, nativeLength,
                                          &emulatedLength);
        ok(status == STATUS_SUCCESS, "EmulationBasic -> %08lx", (unsigned long)status);
        ok(emulatedLength == nativeLength, "EmulationBasic returned %lu, basic %lu",
           (unsigned long)emulatedLength, (unsigned long)nativeLength);
        ok(memcmp(native, emulated, nativeLength) == 0,
           "the emulated basic view differs from the native one");

        /* The basic shape wants an EXACT length — both directions. */
        status = NtQuerySystemInformation(SystemEmulationBasicInformation_, emulated,
                                          nativeLength + 8, &emulatedLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "EmulationBasic oversized -> %08lx",
           (unsigned long)status);
    }

    /* --- 154: the processor feature bitmap ------------------------------- */
    {
        /* Four ULONGLONGs: the bitmap plus three reserved. */
        ULONGLONG features[4];
        returnLength = 0;
        memset(features, 0, sizeof(features));
        status = NtQuerySystemInformation(SystemProcessorFeaturesInformation_, features,
                                          sizeof(features), &returnLength);
        ok(status == STATUS_SUCCESS, "ProcessorFeatures -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(features), "ProcessorFeatures returned %lu",
           (unsigned long)returnLength);
        /* The VALUE is a CPU fact and differs between the runners' hosts,
         * so only its presence is pinned: some feature is always set on any
         * x86_64 that can run this test. */
        ok(features[0] != 0, "the processor feature bitmap is empty");

        status = NtQuerySystemInformation(SystemProcessorFeaturesInformation_, features, 4,
                                          &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "ProcessorFeatures short -> %08lx",
           (unsigned long)status);
    }

    /* --- 206: leap seconds ------------------------------------------------ */
    {
        /* { BOOLEAN Enabled; ULONG Flags; } — 8 bytes with the padding. */
        UCHAR leap[16];
        ULONG flags;
        returnLength = 0;
        memset(leap, 0xcc, sizeof(leap));
        status = NtQuerySystemInformation(SystemLeapSecondInformation_, leap, 8, &returnLength);
        ok(status == STATUS_SUCCESS, "LeapSecond -> %08lx", (unsigned long)status);
        ok(leap[0] == 1, "LeapSecond Enabled is %u", (unsigned)leap[0]);
        memcpy(&flags, leap + 4, sizeof(flags));
        ok(flags == 0, "LeapSecond Flags is %lu", (unsigned long)flags);

        status = NtQuerySystemInformation(SystemLeapSecondInformation_, leap, 4, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "LeapSecond short -> %08lx",
           (unsigned long)status);
    }
}
