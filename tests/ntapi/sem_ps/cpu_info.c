/*
 * sem_ps/cpu_info.c — NtQuerySystemInformation(SystemCpuInformation) (CUI-1).
 *
 * wineboot reads this at startup into a stack SYSTEM_CPU_INFORMATION and
 * switches on ProcessorArchitecture (third_party/wine
 * programs/wineboot/wineboot.c create_hardware_registry_keys), so an
 * unimplemented class leaves it steering on stack garbage. Pinned on the
 * oracle first (Art. 5). Semantics from third_party/wine
 * dlls/ntdll/unix/system.c: `size >= len` succeeds — unlike
 * SystemBasicInformation an OVERSIZED buffer is fine — and ret_size always
 * reports sizeof(SYSTEM_CPU_INFORMATION).
 */
#include "util.h"

/* wine/include/winternl.h: SystemCpuInformation = 1. mingw's winternl.h
 * names class 1 SystemProcessorInformation with the same shape; the wine
 * spelling is the contract (mirrored in generated abi/ntpsapi.h). */
#define PS_SystemCpuInformation ((SYSTEM_INFORMATION_CLASS)1)

/* wine/include/winternl.h SYSTEM_CPU_INFORMATION (mingw's equivalent is
 * SYSTEM_PROCESSOR_INFORMATION; declared under the wine name/fields). */
typedef struct
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} PS_SYSTEM_CPU_INFORMATION;

START_TEST(cpu_info)
{
    NTSTATUS status;
    PS_SYSTEM_CPU_INFORMATION sci;
    ULONG returnLength = 0;

    memset(&sci, 0xcc, sizeof(sci));
    status = NtQuerySystemInformation(PS_SystemCpuInformation, &sci, sizeof(sci), &returnLength);
    ok(status == STATUS_SUCCESS, "SystemCpuInformation -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(sci), "return length %lu", (unsigned long)returnLength);
    ok(sci.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64, "architecture %u",
       (unsigned)sci.ProcessorArchitecture);
    ok(sci.ProcessorLevel != 0, "processor level %u", (unsigned)sci.ProcessorLevel);

    /* Undersized is STATUS_INFO_LENGTH_MISMATCH; ret_size still reports the
     * needed length (the common epilogue writes len unconditionally). */
    returnLength = 0;
    status =
        NtQuerySystemInformation(PS_SystemCpuInformation, &sci, sizeof(sci) - 1, &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(sci), "short-buffer return length %lu", (unsigned long)returnLength);

    /* OVERSIZED succeeds (`size >= len`, system.c) — the divergence from
     * SystemBasicInformation's exact-length rule that makes this worth
     * pinning. */
    unsigned char big[sizeof(sci) + 16];
    memset(big, 0xcc, sizeof(big));
    returnLength = 0;
    status = NtQuerySystemInformation(PS_SystemCpuInformation, big, sizeof(big), &returnLength);
    ok(status == STATUS_SUCCESS, "oversized buffer -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(sci), "oversized return length %lu", (unsigned long)returnLength);
}
