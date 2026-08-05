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
}
