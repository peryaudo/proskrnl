/*
 * sem_ps/ldt.c — ThreadDescriptorTableEntry over the whole selector byte.
 *
 * ntdll:wow64's test_selectors sweeps selectors 0x00..0xff through
 * RtlWow64GetThreadSelectorEntry, which asks the KERNEL first
 * (NtQueryInformationThread(ThreadDescriptorTableEntry)) and only synthesizes
 * a descriptor PE-side when the kernel refuses (third_party/wine
 * dlls/ntdll/process.c). So what the kernel owes that sweep is not entries —
 * it is the right REFUSAL for every selector in the range, because a wrong
 * one either sends ntdll down the wrong branch or, worse, is a fabricated
 * descriptor (Art. 12).
 *
 * Measured from a 64-bit caller, the answer is uniform: every selector in
 * 0x00..0xff is refused with STATUS_UNSUCCESSFUL, whichever table its
 * indicator bit names (Intel SDM Vol. 3A §3.4.2: bit 2 chooses GDT=0 /
 * LDT=1). The kernel's GDT is not a thread property, and a 64-bit thread has
 * no LDT for the lookup to reach -- STATUS_NO_LDT is a 32-bit caller's
 * answer, which this test cannot be.
 *
 * sem_ps/thread_info_sweep.c already pins the zeroed-descriptor case; this
 * file pins the rest of the range, and in particular the LDT half, which the
 * pre-WOW64 kernel left as a loud STATUS_NOT_IMPLEMENTED -- fatal the moment
 * ntdll:wow64's sweep walked past selector 3.
 *
 * NtSetLdtEntries closes the file in a `beyond_oracle` block. The oracle
 * answers STATUS_NOT_IMPLEMENTED for a 64-bit caller
 * (dlls/ntdll/unix/virtual.c: `if (is_win64 && !is_wow64()) return
 * STATUS_NOT_IMPLEMENTED`), and G12 forbids pinning that status — an oracle
 * answering "unbuilt" is unbuilt, not authoritative. So the case is built
 * against NT's own contract instead: MS documents NtSetLdtEntries as taking
 * two selector/descriptor pairs and installing them in the calling
 * process's LDT, where a subsequent ThreadDescriptorTableEntry query reads
 * them back. ntdll:wow64's test_selectors is the caller that depends on it,
 * and its own branch (`if (status != STATUS_NOT_IMPLEMENTED)`) then holds
 * the kernel to exactly that round trip.
 *
 * Oracle-first (G5): every assert here is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* wine/include/winternl.h ThreadDescriptorTableEntry = 6, and the struct it
 * takes (LDT_ENTRY from winnt.h preceded by the selector). */
#define PS_ThreadDescriptorTableEntry ((THREADINFOCLASS)6)

/* wine/include/winternl.h; mingw's headers omit it. */
NTSYSAPI NTSTATUS NTAPI NtSetLdtEntries(ULONG, ULONG, ULONG, ULONG, ULONG, ULONG);

typedef struct
{
    DWORD Selector;
    LDT_ENTRY Entry;
} NTAPI_THREAD_DESCRIPTOR_INFORMATION;

START_TEST(ldt)
{
    NTAPI_THREAD_DESCRIPTOR_INFORMATION info;
    NTSTATUS status;
    ULONG selector;

    /* --- the length rule, before anything looks at the selector -------- */
    ULONG returnLength = 0xdeadbeef;
    memset(&info, 0, sizeof(info));
    status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadDescriptorTableEntry, &info,
                                      sizeof(info) - 1, &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short buffer -> %08lx", (unsigned long)status);
    ok(returnLength == 0xdeadbeef, "return length written on refusal: %lu",
       (unsigned long)returnLength);

    returnLength = 0xdeadbeef;
    status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadDescriptorTableEntry, &info,
                                      sizeof(info) + 1, &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "long buffer -> %08lx", (unsigned long)status);
    ok(returnLength == 0xdeadbeef, "return length written on refusal: %lu",
       (unsigned long)returnLength);

    /* --- a selector that does not fit in 16 bits ---------------------- */
    memset(&info, 0, sizeof(info));
    info.Selector = 0x10000;
    status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadDescriptorTableEntry, &info,
                                      sizeof(info), NULL);
    ok(status == STATUS_UNSUCCESSFUL, "oversized selector -> %08lx", (unsigned long)status);

    /* --- the whole byte -------------------------------------------------
     * MEASURED, and it collapses the split the header comment sets up: the
     * oracle refuses EVERY selector in the range with STATUS_UNSUCCESSFUL,
     * LDT ones included. A 64-bit thread has no LDT to look in, so the
     * lookup never gets far enough to answer STATUS_NO_LDT -- that status
     * is reachable only from a 32-bit caller, which this test cannot be.
     * The winetest's sweep accepts STATUS_UNSUCCESSFUL for both families
     * (`status == STATUS_UNSUCCESSFUL || ((sel & 4) && status ==
     * STATUS_NO_LDT)`), so one answer for all 256 is conformant and is what
     * proskrnl must give. */
    ULONG refusals = 0;
    for (selector = 0; selector < 0x100; selector++)
    {
        returnLength = 0xdeadbeef;
        memset(&info, 0, sizeof(info));
        info.Selector = selector;
        status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadDescriptorTableEntry, &info,
                                          sizeof(info), &returnLength);
        if (status != STATUS_UNSUCCESSFUL)
        {
            ok(0, "selector %lx -> %08lx", (unsigned long)selector, (unsigned long)status);
            break;
        }
        if (returnLength != 0xdeadbeef)
        {
            ok(0, "selector %lx wrote a return length %lu", (unsigned long)selector,
               (unsigned long)returnLength);
            break;
        }
        refusals++;
    }
    ok(refusals == 0x100, "selectors refused: %lu of 256", (unsigned long)refusals);

    /* --- set, then read back ------------------------------------------- */
    beyond_oracle
    {
        /* A ring-3 data descriptor: base 0, limit 0xfffff, type 0x13
         * (read/write data, accessed), DPL 3, present, big, granular — the
         * same shape test_selectors synthesizes for the 32-bit data
         * selector and then hands to NtSetLdtEntries. Spelled as the two
         * raw ULONGs the call takes (Intel SDM Vol. 3A §3.4.5, Figure 3-8:
         * low = base15:0 | limit15:0, high = the rest). */
        ULONG entryLow = 0x0000ffff;
        ULONG entryHigh = 0x00cff300;

        /* Selector 0 names the null descriptor and is accepted as a no-op:
         * the winetest's first call passes it deliberately. */
        status = NtSetLdtEntries(0, entryLow, entryHigh, 0, entryLow, entryHigh);
        ok(status == STATUS_SUCCESS, "NtSetLdtEntries(null selector) -> %08lx",
           (unsigned long)status);

        status = NtSetLdtEntries(0x000f, entryLow, entryHigh, 0x001f, entryLow, entryHigh);
        ok(status == STATUS_SUCCESS, "NtSetLdtEntries -> %08lx", (unsigned long)status);

        /* Byte-exact read-back, for both entries. */
        ULONG which;
        ULONG selectors[2] = {0x000f, 0x001f};
        for (which = 0; which < 2; which++)
        {
            memset(&info, 0x9a, sizeof(info));
            info.Selector = selectors[which];
            status = NtQueryInformationThread(GetCurrentThread(), PS_ThreadDescriptorTableEntry,
                                              &info, sizeof(info), NULL);
            ok(status == STATUS_SUCCESS, "read back %lx -> %08lx",
               (unsigned long)selectors[which], (unsigned long)status);
            ULONG gotLow, gotHigh;
            memcpy(&gotLow, &info.Entry, sizeof(gotLow));
            memcpy(&gotHigh, (const char *)&info.Entry + 4, sizeof(gotHigh));
            ok(gotLow == entryLow && gotHigh == entryHigh, "entry %lx read back %08lx/%08lx",
               (unsigned long)selectors[which], (unsigned long)gotLow, (unsigned long)gotHigh);
        }

        /* A selector that does not fit in 16 bits is refused, and a ring-0
         * or SYSTEM descriptor is refused outright rather than silently
         * masked — an installed descriptor is a capability, so the kernel
         * must not accept one that crosses a ring boundary. */
        status = NtSetLdtEntries(0x10000, entryLow, entryHigh, 0, 0, 0);
        ok(status == STATUS_INVALID_LDT_DESCRIPTOR, "oversized selector -> %08lx",
           (unsigned long)status);
        status = NtSetLdtEntries(0x0027, entryLow, entryHigh & ~0x00006000u, 0, 0, 0);
        ok(status == STATUS_INVALID_LDT_DESCRIPTOR, "DPL 0 descriptor -> %08lx",
           (unsigned long)status);
        status = NtSetLdtEntries(0x0027, entryLow, entryHigh & ~0x00001000u, 0, 0, 0);
        ok(status == STATUS_INVALID_LDT_DESCRIPTOR, "system descriptor -> %08lx",
           (unsigned long)status);
    }
}
