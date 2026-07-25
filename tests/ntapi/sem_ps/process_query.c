/*
 * sem_ps/process_query.c — the mechanical M7 Ps/Ke query surface (docs/02).
 *
 * The pieces of M7 a flat binary can reach: process/system information, the
 * performance counter, and the scheduling primitives. Distilled from the
 * behaviour Wine's ntdll relies on at startup (dlls/ntdll/unix/process.c,
 * system.c) and greened on the pinned Wine oracle first (Art. 5). The PE-only
 * M7 surface — the byte-exact PEB/TEB and the KiUser* return protocol — is
 * covered by the m7_smoke.exe boot module, which a flat ntapi binary cannot
 * express.
 */
#include "util.h"

START_TEST(process_query)
{
    NTSTATUS status;

    /* --- ProcessBasicInformation ---------------------------------------- */
    PS_PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, &pbi,
                                       sizeof(pbi), &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(pbi), "return length %lu", (unsigned long)returnLength);
    ok(pbi.UniqueProcessId != 0, "process id nonzero (%lu)", (unsigned long)pbi.UniqueProcessId);

    /* A too-small buffer is STATUS_INFO_LENGTH_MISMATCH. */
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, &pbi,
                                       sizeof(pbi) - 1, NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);

    /* ProcessBasicInformation wants an EXACT length: a LARGER buffer is also
     * STATUS_INFO_LENGTH_MISMATCH (Wine dlls/ntdll/unix/process.c:
     * `if (size > sizeof(PROCESS_BASIC_INFORMATION)) ret = ..._MISMATCH`).
     * Fuzzer-found (sem_ps was previously exact/short only). */
    unsigned char pbi_big[sizeof(pbi) + 16];
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessBasicInformation, pbi_big,
                                       sizeof(pbi_big), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "oversized buffer -> %08lx", (unsigned long)status);

    /* --- SystemBasicInformation: allocation granularity ----------------- */
    PS_SYSTEM_BASIC_INFORMATION sbi;
    status = NtQuerySystemInformation(PS_SystemBasicInformation, &sbi, sizeof(sbi), &returnLength);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);
    ok(sbi.AllocationGranularity == 0x10000, "allocation granularity %lu",
       (unsigned long)sbi.AllocationGranularity);

    /* SystemBasicInformation also wants an EXACT length (Wine system.c:
     * `if (size == len) ...; else ret = ..._MISMATCH`) — both under- and
     * over-sized buffers are STATUS_INFO_LENGTH_MISMATCH. */
    unsigned char sbi_big[sizeof(sbi) + 16];
    status = NtQuerySystemInformation(PS_SystemBasicInformation, sbi_big, sizeof(sbi_big), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "system oversized -> %08lx", (unsigned long)status);

    /* --- NtQueryPerformanceCounter: monotonic, nonzero frequency -------- */
    LARGE_INTEGER first, second, frequency;
    status = NtQueryPerformanceCounter(&first, &frequency);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter -> %08lx", (unsigned long)status);
    ok(frequency.QuadPart > 0, "frequency %lld", (long long)frequency.QuadPart);
    status = NtQueryPerformanceCounter(&second, NULL);
    ok(status == STATUS_SUCCESS, "QueryPerformanceCounter(2) -> %08lx", (unsigned long)status);
    ok(second.QuadPart >= first.QuadPart, "counter monotonic (%lld -> %lld)",
       (long long)first.QuadPart, (long long)second.QuadPart);

    /* --- NtDelayExecution: a short relative delay completes -------------- */
    LARGE_INTEGER interval;
    interval.QuadPart = -10000; /* 1 ms, relative (negative = relative 100 ns) */
    status = NtDelayExecution(FALSE, &interval);
    ok(status == STATUS_SUCCESS, "DelayExecution -> %08lx", (unsigned long)status);

    /* A zero delay is a yield (STATUS_SUCCESS or, when there is no other
     * runnable thread, STATUS_NO_YIELD_PERFORMED). */
    interval.QuadPart = 0;
    status = NtDelayExecution(FALSE, &interval);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED,
       "DelayExecution(0) -> %08lx", (unsigned long)status);

    /* --- NtYieldExecution / NtTestAlert accept and return --------------- */
    status = NtYieldExecution();
    ok(status == STATUS_SUCCESS || status == STATUS_NO_YIELD_PERFORMED, "YieldExecution -> %08lx",
       (unsigned long)status);

    status = NtTestAlert();
    ok(status == STATUS_SUCCESS, "TestAlert -> %08lx", (unsigned long)status);

    /* --- ProcessCookie: the RtlEncodePointer/RtlDecodePointer obfuscator.
     * ntdll's get_process_cookie IGNORES this call's status (an
     * uninitialized cookie poisons every encoded pointer — vectored
     * handlers included), so the kernel must serve it: exactly
     * sizeof(ULONG), nonzero, stable for the process's lifetime. -------- */
    ULONG cookie = 0, cookie_again = 0;
    status =
        NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie, &cookie, sizeof(cookie), NULL);
    ok(status == STATUS_SUCCESS, "ProcessCookie -> %08lx", (unsigned long)status);
    ok(cookie != 0, "ProcessCookie is zero");
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie, &cookie_again,
                                       sizeof(cookie_again), NULL);
    ok(status == STATUS_SUCCESS, "ProcessCookie(2) -> %08lx", (unsigned long)status);
    ok(cookie_again == cookie, "ProcessCookie unstable (%08lx -> %08lx)", (unsigned long)cookie,
       (unsigned long)cookie_again);
    /* The size must be exact (Wine dlls/ntdll/unix/process.c ProcessCookie). */
    ULONGLONG wide_cookie = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie, &wide_cookie,
                                       sizeof(wide_cookie), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "ProcessCookie oversize -> %08lx",
       (unsigned long)status);

    /* --- ProcessDebugPort: not debugged -> 0; EXACT DWORD_PTR size -------
     * ntdll's loader_init queries this at every process start and calls
     * process_breakpoint on a nonzero answer. Wine dlls/ntdll/unix/
     * process.c: `size != sizeof(DWORD_PTR)` -> INFO_LENGTH_MISMATCH;
     * no debugger (STATUS_PORT_NOT_SET from the server) -> *info = 0,
     * STATUS_SUCCESS. */
    ULONG_PTR debug_port = ~(ULONG_PTR)0;
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &debug_port,
                                       sizeof(debug_port), &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessDebugPort -> %08lx", (unsigned long)status);
    ok(debug_port == 0, "debug port %p with no debugger", (void *)debug_port);
    ok(returnLength == sizeof(debug_port), "debug port return length %lu",
       (unsigned long)returnLength);
    ULONG narrow_port = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDebugPort, &narrow_port,
                                       sizeof(narrow_port), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "ProcessDebugPort short -> %08lx",
       (unsigned long)status);

    /* --- ProcessWow64Information: a 64-bit process answers 0 (no WOW64
     * PEB); EXACT ULONG_PTR size (Wine dlls/ntdll/unix/process.c: `size !=
     * len` returns INFO_LENGTH_MISMATCH before touching returnLength).
     * Consumer: kernelbase's IsWow64Process, on the CreateProcess path. */
    ULONG_PTR wow64_peb = ~(ULONG_PTR)0;
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow64_peb,
                                       sizeof(wow64_peb), &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessWow64Information -> %08lx", (unsigned long)status);
    ok(wow64_peb == 0, "wow64 peb %p in a 64-bit process", (void *)wow64_peb);
    ok(returnLength == sizeof(wow64_peb), "wow64 return length %lu", (unsigned long)returnLength);
    ULONG narrow_wow64 = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &narrow_wow64,
                                       sizeof(narrow_wow64), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "wow64 short -> %08lx", (unsigned long)status);

    /* --- ProcessImageInformation: the main image's facts, EXACT size -----
     * ntdll's build_main_module reads this at every process start and
     * terminates the process on IMAGE_FILE_DLL. Wine dlls/ntdll/unix/
     * process.c: `size == len` else INFO_LENGTH_MISMATCH; returnLength =
     * sizeof either way. The values describe THIS test .exe. */
    ps_section_image_info image_info;
    returnLength = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageInformation, &image_info,
                                       sizeof(image_info), &returnLength);
    ok(status == STATUS_SUCCESS, "ProcessImageInformation -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(image_info), "image info return length %lu",
       (unsigned long)returnLength);
    ok(image_info.machine == IMAGE_FILE_MACHINE_AMD64, "machine %04x", image_info.machine);
    ok((image_info.image_characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0,
       "characteristics %04x lack EXECUTABLE_IMAGE", image_info.image_characteristics);
    ok((image_info.image_characteristics & IMAGE_FILE_DLL) == 0, "characteristics %04x have DLL",
       image_info.image_characteristics);
    ok(image_info.maximum_stack_size != 0, "maximum stack size 0");
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageInformation, &image_info,
                                       sizeof(image_info) - 8, NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "image info short -> %08lx", (unsigned long)status);

    /* --- SystemWineVersionInformation (1000): the oracle's unix layer
     * answers version\0build\0sysname\0release (dlls/ntdll/unix/system.c);
     * proskrnl PINS a refusal instead — it is not Wine-on-unix and has no
     * truthful uname to fabricate, and ntdll's version_init ignores the
     * status (docs/03). */
    char wine_version[512];
    wine_version[0] = 0;
    status = NtQuerySystemInformation(PS_SystemWineVersionInformation, wine_version,
                                      sizeof(wine_version), NULL);
    todo_proskrnl
    {
        ok(status == STATUS_SUCCESS, "SystemWineVersionInformation -> %08lx",
           (unsigned long)status);
        ok(wine_version[0] != 0, "wine version string empty");
    }

    /* --- ProcessDefaultHardErrorMode: SetErrorMode's kernel half ---------
     * Per-process, round-trips through the query/set pair; EXACT UINT size
     * (Wine dlls/ntdll/unix/process.c: query mismatch is
     * INFO_LENGTH_MISMATCH, set mismatch is INVALID_PARAMETER). */
    ULONG error_mode_before = 0xdead, error_mode = 0;
    status =
        NtQueryInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode,
                                  &error_mode_before, sizeof(error_mode_before), &returnLength);
    ok(status == STATUS_SUCCESS, "hard error mode query -> %08lx", (unsigned long)status);
    ok(returnLength == sizeof(ULONG), "hard error mode retlen %lu", (unsigned long)returnLength);
    ULONG new_error_mode = 3;
    status = NtSetInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode,
                                     &new_error_mode, sizeof(new_error_mode));
    ok(status == STATUS_SUCCESS, "hard error mode set -> %08lx", (unsigned long)status);
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode, &error_mode,
                                       sizeof(error_mode), NULL);
    ok(status == STATUS_SUCCESS && error_mode == 3, "hard error mode round-trip -> %08lx (%lu)",
       (unsigned long)status, (unsigned long)error_mode);
    UCHAR tiny_mode = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode, &tiny_mode,
                                       sizeof(tiny_mode), NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "hard error mode short query -> %08lx",
       (unsigned long)status);
    status = NtSetInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode, &tiny_mode,
                                     sizeof(tiny_mode));
    ok(status == STATUS_INVALID_PARAMETER, "hard error mode short set -> %08lx",
       (unsigned long)status);
    NtSetInformationProcess(NtCurrentProcess(), ProcessDefaultHardErrorMode, &error_mode_before,
                            sizeof(error_mode_before));

    /* --- NtPowerInformation(ProcessorInformation): wineboot's ~MHz source.
     * Contract (Wine dlls/ntdll/unix/system.c): NULL/0 output ->
     * INVALID_PARAMETER; a buffer under one record per CPU ->
     * BUFFER_TOO_SMALL; else one PROCESSOR_POWER_INFORMATION per CPU with
     * nonzero MaxMhz (the oracle's no-cpufreq fallback is a canned
     * 1000 MHz, so nonzero always holds). */
    ps_processor_power_info power_info[64];
    status = NtPowerInformation(ProcessorInformation, NULL, 0, power_info, sizeof(power_info));
    ok(status == STATUS_SUCCESS, "ProcessorInformation -> %08lx", (unsigned long)status);
    ok(power_info[0].number == 0, "cpu 0 Number %lu", (unsigned long)power_info[0].number);
    ok(power_info[0].max_mhz != 0, "cpu 0 MaxMhz 0");
    status = NtPowerInformation(ProcessorInformation, NULL, 0, power_info, 4);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short power buffer -> %08lx", (unsigned long)status);
    status = NtPowerInformation(ProcessorInformation, NULL, 0, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "null power buffer -> %08lx", (unsigned long)status);

    /* --- SystemFirmwareTableInformation (76): host SMBIOS pass-through --
     * The oracle serves the RSMB provider from the host's DMI tables
     * (dlls/ntdll/unix/system.c create_smbios_data); proskrnl pins a
     * refusal — host-derived data with no kernel source, and wineboot's
     * create_bios_key tolerates it (docs/03). GetSystemFirmwareTable is
     * kernelbase's thin wrapper over the class. */
    UINT smbios_len =
        GetSystemFirmwareTable(('R' << 24) | ('S' << 16) | ('M' << 8) | 'B', 0, NULL, 0);
    todo_proskrnl
    {
        ok(smbios_len != 0, "RSMB firmware table absent on the oracle");
    }
}
