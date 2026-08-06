/*
 * sem_ps/info_class_range.c — an out-of-range info class is INVALID, not
 * unbuilt.
 *
 * This is the refusal SHAPE, and it is the structural blocker the winetest
 * sweep exposed (docs/21 W1). Wine's own suites sweep info classes and
 * TOLERATE a refusal — `dlls/ntdll/tests/info.c:149` probes class -1 and
 * accepts STATUS_INVALID_INFO_CLASS *or* STATUS_NOT_IMPLEMENTED, and
 * `dlls/kernel32/tests/thread.c` test_thread_info loops over every thread
 * class doing `if (status == STATUS_NOT_IMPLEMENTED) continue;`.
 *
 * proskrnl cannot answer STATUS_NOT_IMPLEMENTED to any of them, because the
 * armed boot turns that status into a panic by design (Art. 12) — so the
 * tolerant loop kills the machine before it can tolerate anything. The
 * resolution is NOT to soften the panic. It is that the two refusals are
 * different answers to different questions:
 *
 *   - a class NUMBER outside the enum the pinned header defines is
 *     INVALID. The caller asked for nothing that exists, and
 *     STATUS_INVALID_INFO_CLASS is an IMPLEMENTED answer — pinned here,
 *     exactly as Art. 12's last paragraph requires of a refusal a real
 *     caller depends on.
 *
 *   - a class that IS in the enum and simply unbuilt keeps
 *     STATUS_NOT_IMPLEMENTED, and keeps panicking. That is the loud
 *     refusal, and collapsing the two would make every unbuilt class in
 *     the kernel answer plausibly instead of stopping — the exact defect
 *     G12 exists to prevent.
 *
 * Only the INVALID side can be pinned: the unbuilt side is, by
 * construction, a boot that dies. Wine's default arm for
 * NtQuerySystemInformation says the same thing in a comment worth quoting
 * (dlls/ntdll/unix/system.c): "Several Information Classes are not
 * implemented on Windows and return 2 different values ... in 95% of the
 * cases it's STATUS_INVALID_INFO_CLASS, so use this as the default".
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

START_TEST(info_class_range)
{
    NTSTATUS status;
    ULONG returnLength;
    UCHAR buffer[64];

    /* --- ntdll:info's own probe: class -1 --------------------------------- */
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)-1, NULL, 0, NULL);
    ok(status == STATUS_INVALID_INFO_CLASS, "class -1 -> %08lx", (unsigned long)status);

    /* --- and one far above the last enumerator the header defines --------- */
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x7000, buffer, sizeof(buffer),
                                      &returnLength);
    ok(status == STATUS_INVALID_INFO_CLASS, "class 0x7000 -> %08lx", (unsigned long)status);

    /* --- a REAL class with a zero-length buffer is a LENGTH complaint, not
     * a class complaint. The two must not collapse into each other, which
     * is the other half of this contract (info.c:154). */
    status = NtQuerySystemInformation(SystemBasicInformation, NULL, 0, NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "SystemBasicInformation, 0 bytes -> %08lx",
       (unsigned long)status);

    /* --- and the same real class with room answers ------------------------ */
    returnLength = 0;
    status =
        NtQuerySystemInformation(SystemBasicInformation, buffer, sizeof(buffer), &returnLength);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);
    ok(returnLength != 0, "SystemBasicInformation returned %lu bytes", (unsigned long)returnLength);

    /* --- a class that IS in the enum but that NOBODY implements ----------
     * SystemPathInformation (4) and SystemFlagsInformation (9) are real
     * enumerators that neither the oracle nor proskrnl serves. The oracle
     * answers STATUS_INVALID_INFO_CLASS — its default arm, whose comment
     * explains that Windows itself splits between two statuses here and
     * that INVALID_INFO_CLASS is the 95% case.
     *
     * That makes INVALID_INFO_CLASS the PINNED answer for these, which is
     * what lets proskrnl give it without violating Art. 12: it is an
     * implemented refusal, not a stub. The distinction that matters is the
     * one this file's header draws — a class the oracle IMPLEMENTS and
     * proskrnl does not must still answer STATUS_NOT_IMPLEMENTED and must
     * still panic, because there the refusal would be hiding a real hole.
     * Those cannot be pinned here, by construction: the pin would be a boot
     * that dies. */
    {
        ULONG refusedLength = 0; /* separate: the comparison below still
                                  * needs `returnLength` from the basic
                                  * query above */
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)4, buffer, sizeof(buffer),
                                          &refusedLength);
        ok(status == STATUS_INVALID_INFO_CLASS, "SystemPathInformation -> %08lx",
           (unsigned long)status);
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)9, buffer, sizeof(buffer),
                                          &refusedLength);
        ok(status == STATUS_INVALID_INFO_CLASS, "SystemFlagsInformation -> %08lx",
           (unsigned long)status);
    }

    /* --- a class whose PLAIN form is a refusal because of how it forwards
     * SystemCpuSetInformation (175) is implemented — but only through
     * NtQuerySystemInformationEx, whose arm requires a process HANDLE in
     * the query blob. The plain form forwards with a NULL query and a
     * length of 0, so it always lands on that arm's
     * `if (!query || query_len < sizeof(HANDLE)) return
     * STATUS_INVALID_PARAMETER` (dlls/ntdll/unix/system.c).
     *
     * So the plain entry point's answer for 175 is INVALID_PARAMETER — not
     * INVALID_INFO_CLASS, which is what a refusal-by-default would give,
     * and not success, which is what "the class is implemented" would
     * suggest. It is measured here rather than reasoned from the class
     * being present somewhere. */
    {
        ULONG cpuSetLength = 0;
        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)175, buffer, sizeof(buffer),
                                          &cpuSetLength);
        ok(status == STATUS_INVALID_PARAMETER, "SystemCpuSetInformation (plain) -> %08lx",
           (unsigned long)status);
    }

    /* --- SystemNativeBasicInformation (114) is the SAME class on x64 ------
     * "Native" means "the kernel's own word size rather than the caller's",
     * so on a 64-bit kernel answering a 64-bit caller it is
     * SystemBasicInformation and nothing else — the oracle spells that as a
     * fallthrough guarded by `if (!is_win64) return
     * STATUS_INVALID_INFO_CLASS` (dlls/ntdll/unix/system.c). proskrnl is
     * x86_64-only (ADR 0006), so the guard is always false here and the two
     * classes must agree byte for byte.
     *
     * ntdll:info reaches it at info.c:218 and compares the two answers
     * field by field; proskrnl had it unbuilt, which the armed boot turns
     * into a panic — so this one class was ending the pair. */
    {
        UCHAR nativeBuffer[64];
        ULONG nativeLength = 0;
        NTSTATUS nativeStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)114,
                                                         nativeBuffer, sizeof(nativeBuffer),
                                                         &nativeLength);
        ok(nativeStatus == STATUS_SUCCESS, "SystemNativeBasicInformation -> %08lx",
           (unsigned long)nativeStatus);
        ok(nativeLength == returnLength, "native returned %lu bytes, basic returned %lu",
           (unsigned long)nativeLength, (unsigned long)returnLength);
        /* Compared up to and including NumberOfProcessors, which is the
         * span ntdll:info itself compares (info.c:224) — the fields past it
         * are pointers into the caller's own address space. */
        ok(memcmp(nativeBuffer, buffer, returnLength) == 0,
           "the two classes disagree about the same facts");
    }
}
