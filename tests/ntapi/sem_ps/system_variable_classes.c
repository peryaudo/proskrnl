/*
 * sem_ps/system_variable_classes.c — the VARIABLE-LENGTH
 * NtQuerySystemInformation / NtQuerySystemInformationEx classes proskrnl
 * built while clearing ntdll:info.
 *
 * WHY THIS FILE EXISTS. Eleven classes were implemented in this branch with
 * no tests/ntapi pin of their own, on the strength of `run.sh proskrnl`
 * staying green — which exercises none of them. The winetest pair that
 * would have (ntdll:info) is commented out. So they were verified by
 * nothing on either runner, which is the situation Art. 5 exists to
 * prevent, and the gate-check on this PR said so.
 *
 * WHAT IS PINNED, and why it is these things. None of these classes has a
 * fixed answer — the CONTENT is the machine's, and a test that asserted it
 * would be asserting the runner rather than the boundary. What a caller
 * actually depends on is the PROTOCOL around the content, and that protocol
 * is not uniform:
 *
 *   - the "buffer too small" status DIFFERS per class.
 *     STATUS_INFO_LENGTH_MISMATCH for most, STATUS_BUFFER_TOO_SMALL for the
 *     two that answer through NtQuerySystemInformationEx (83, 175). A
 *     caller sizing a buffer in a loop keys off exactly this, and a kernel
 *     that picked one status for the whole switch would break the half it
 *     guessed wrong. This is the single most valuable thing in the file.
 *   - the Ex classes REQUIRE their query buffer, and refuse with
 *     STATUS_INVALID_PARAMETER when it is missing or short — before they
 *     look at the output buffer at all.
 *   - two classes have an ORDER that is observable because more than one
 *     rule can fail at once: 105 checks ALIGNMENT before length, and 88
 *     checks length, then a non-empty ImageName, then a zero pid — each
 *     with its own status, STATUS_INVALID_CID being one no other class here
 *     uses.
 *
 * Every status below was measured on the pinned oracle; where the kernel
 * and the oracle could plausibly differ, the assertion is the oracle's
 * (Art. 6).
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS, void *, ULONG, void *,
                                                   ULONG, ULONG *);

#define SystemExtendedProcessInformation_        ((SYSTEM_INFORMATION_CLASS)57)
#define SystemExtendedHandleInformation_         ((SYSTEM_INFORMATION_CLASS)64)
#define SystemLogicalProcessorInformation_       ((SYSTEM_INFORMATION_CLASS)73)
#define SystemModuleInformationEx_               ((SYSTEM_INFORMATION_CLASS)77)
#define SystemProcessorIdleCycleTimeInformation_ ((SYSTEM_INFORMATION_CLASS)83)
#define SystemProcessIdInformation_              ((SYSTEM_INFORMATION_CLASS)88)
#define SystemCodeIntegrityInformation_          ((SYSTEM_INFORMATION_CLASS)103)
#define SystemProcessorBrandString_              ((SYSTEM_INFORMATION_CLASS)105)
#define SystemLogicalProcessorInformationEx_     ((SYSTEM_INFORMATION_CLASS)107)
#define SystemCpuSetInformation_                 ((SYSTEM_INFORMATION_CLASS)175)
#define SystemSupportedProcessorArchitectures2_  ((SYSTEM_INFORMATION_CLASS)230)

/* RelationAll, the "every relationship" selector
 * SystemLogicalProcessorInformationEx takes as its query word (winnt.h
 * LOGICAL_PROCESSOR_RELATIONSHIP). */
#define PRS_RELATION_ALL 0xffff

static void expect_grows(SYSTEM_INFORMATION_CLASS infoClass, const char *name, NTSTATUS tooSmall)
{
    /* One byte is smaller than any of these answers, so the class must
     * REFUSE and — where it can — say how much it wanted. A class that
     * succeeded here would be writing past the caller's buffer. */
    UCHAR small = 0;
    ULONG returned = 0;
    NTSTATUS status = NtQuerySystemInformation(infoClass, &small, 1, &returned);
    ntapi_okv(status == tooSmall, __FILE__, __LINE__, "%s with a 1-byte buffer -> %08lx", name,
              (unsigned long)status);
}

START_TEST(system_variable_classes)
{
    NTSTATUS status;
    ULONG returned;
    UCHAR buffer[4096];

    /* --- the classes that refuse a short buffer with INFO_LENGTH_MISMATCH -
     * Grouped because the STATUS is the assertion; the payload is the
     * machine's and is not this file's business. */
    expect_grows(SystemExtendedProcessInformation_, "SystemExtendedProcessInformation",
                 STATUS_INFO_LENGTH_MISMATCH);
    expect_grows(SystemExtendedHandleInformation_, "SystemExtendedHandleInformation",
                 STATUS_INFO_LENGTH_MISMATCH);
    expect_grows(SystemLogicalProcessorInformation_, "SystemLogicalProcessorInformation",
                 STATUS_INFO_LENGTH_MISMATCH);
    expect_grows(SystemModuleInformationEx_, "SystemModuleInformationEx",
                 STATUS_INFO_LENGTH_MISMATCH);
    expect_grows(SystemCodeIntegrityInformation_, "SystemCodeIntegrityInformation",
                 STATUS_INFO_LENGTH_MISMATCH);

    /* --- and the two that refuse with BUFFER_TOO_SMALL instead -----------
     * Both answer through NtQuerySystemInformationEx, which is where the
     * difference comes from. A caller's sizing loop tests for one status,
     * so this split is load-bearing. */
    expect_grows(SystemProcessorIdleCycleTimeInformation_,
                 "SystemProcessorIdleCycleTimeInformation", STATUS_BUFFER_TOO_SMALL);

    /* 175 is the odd one: its PLAIN form forwards to the Ex form with a
     * NULL query, and the Ex form requires one — so the plain form can
     * never do anything but refuse with STATUS_INVALID_PARAMETER, whatever
     * buffer it is handed. That is not a "too small" answer at all, and a
     * kernel that treated the two forms as one call would answer
     * BUFFER_TOO_SMALL here and mislead every caller that sizes in a loop.
     * The Ex form's real sizing answer is pinned further down. */
    {
        UCHAR small = 0;
        returned = 0;
        status = NtQuerySystemInformation(SystemCpuSetInformation_, &small, 1, &returned);
        ok(status == STATUS_INVALID_PARAMETER, "plain SystemCpuSetInformation -> %08lx",
           (unsigned long)status);
        status =
            NtQuerySystemInformation(SystemCpuSetInformation_, buffer, sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "plain SystemCpuSetInformation with room -> %08lx",
           (unsigned long)status);
    }

    /* --- 105: ALIGNMENT is checked BEFORE length ------------------------
     * Both rules fail for the call below — the buffer is misaligned AND
     * one byte long — so the answer names which check runs first. A kernel
     * that validated length first would return INFO_LENGTH_MISMATCH and no
     * caller would notice until one passed a misaligned buffer that was
     * big enough. */
    {
        status = NtQuerySystemInformation(SystemProcessorBrandString_, buffer + 1, 1, &returned);
        ok(status == STATUS_DATATYPE_MISALIGNMENT, "a misaligned, too-small brand string -> %08lx",
           (unsigned long)status);
        status = NtQuerySystemInformation(SystemProcessorBrandString_, buffer, 1, &returned);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "an aligned, too-small brand string -> %08lx",
           (unsigned long)status);
        returned = 0;
        status = NtQuerySystemInformation(SystemProcessorBrandString_, buffer, sizeof(buffer),
                                          &returned);
        ok(status == STATUS_SUCCESS, "the brand string -> %08lx", (unsigned long)status);
        ok(returned > 0 && returned <= sizeof(buffer), "the brand string is %lu bytes",
           (unsigned long)returned);
    }

    /* --- 88: three rules, three statuses, in order -----------------------
     * SYSTEM_PROCESS_ID_INFORMATION is an IN/OUT shape — the caller writes
     * the pid and an empty ImageName, the kernel fills the name — so more
     * than one field can be wrong at once and the order is observable.
     * STATUS_INVALID_CID appears nowhere else in this file. */
    {
        struct
        {
            HANDLE ProcessId;
            UNICODE_STRING ImageName;
        } id;

        memset(&id, 0, sizeof(id));
        status =
            NtQuerySystemInformation(SystemProcessIdInformation_, &id, sizeof(id) - 1, &returned);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "a short SystemProcessIdInformation -> %08lx",
           (unsigned long)status);

        /* Full length, but the caller left a non-empty name behind: that is
         * INVALID_PARAMETER, and it is checked before the pid. */
        memset(&id, 0, sizeof(id));
        id.ImageName.Length = 2;
        status = NtQuerySystemInformation(SystemProcessIdInformation_, &id, sizeof(id), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "a pre-filled ImageName -> %08lx",
           (unsigned long)status);

        /* Empty name, but pid 0 — the CID is what is wrong now. */
        memset(&id, 0, sizeof(id));
        status = NtQuerySystemInformation(SystemProcessIdInformation_, &id, sizeof(id), &returned);
        ok(status == STATUS_INVALID_CID, "process id 0 -> %08lx", (unsigned long)status);
    }

    /* --- the Ex classes need their QUERY buffer --------------------------
     * Each refuses a missing or short query with STATUS_INVALID_PARAMETER,
     * and does so before touching the output buffer — the calls below pass
     * a full-size output buffer, so nothing else can be at fault. */
    {
        ULONG relation = PRS_RELATION_ALL;
        HANDLE self = 0;

        status = NtQuerySystemInformationEx(SystemLogicalProcessorInformationEx_, NULL, 0, buffer,
                                            sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "107 with no query -> %08lx", (unsigned long)status);
        status =
            NtQuerySystemInformationEx(SystemLogicalProcessorInformationEx_, &relation,
                                       sizeof(relation) - 1, buffer, sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "107 with a short query -> %08lx",
           (unsigned long)status);

        status = NtQuerySystemInformationEx(SystemCpuSetInformation_, NULL, 0, buffer,
                                            sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "175 with no query -> %08lx", (unsigned long)status);

        status = NtQuerySystemInformationEx(SystemSupportedProcessorArchitectures2_, NULL, 0,
                                            buffer, sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "230 with no query -> %08lx", (unsigned long)status);

        /* A NULL process handle in the query means "this process" for both
         * handle-taking classes, so these are the calls that must SUCCEED
         * — the assertion that keeps the refusals above from being
         * "refuse everything". */
        returned = 0;
        status = NtQuerySystemInformationEx(SystemCpuSetInformation_, &self, sizeof(self), buffer,
                                            sizeof(buffer), &returned);
        ok(status == STATUS_SUCCESS, "175 for this process -> %08lx", (unsigned long)status);
        ok(returned > 0, "175 returned nothing");

        /* The Ex form's real sizing answer, which the plain form above can
         * never reach: BUFFER_TOO_SMALL, not INFO_LENGTH_MISMATCH. */
        status = NtQuerySystemInformationEx(SystemCpuSetInformation_, &self, sizeof(self), buffer,
                                            1, &returned);
        ok(status == STATUS_BUFFER_TOO_SMALL, "175 with a 1-byte buffer -> %08lx",
           (unsigned long)status);

        returned = 0;
        status = NtQuerySystemInformationEx(SystemSupportedProcessorArchitectures2_, &self,
                                            sizeof(self), buffer, sizeof(buffer), &returned);
        ok(status == STATUS_SUCCESS, "230 for this process -> %08lx", (unsigned long)status);
        ok(returned > 0, "230 returned nothing");

        /* 83's query word is a processor GROUP id, and proskrnl has exactly
         * one group — group 0. Anything else is INVALID_PARAMETER. */
        USHORT group = 0;
        returned = 0;
        status = NtQuerySystemInformationEx(SystemProcessorIdleCycleTimeInformation_, &group,
                                            sizeof(group), buffer, sizeof(buffer), &returned);
        ok(status == STATUS_SUCCESS, "83 for group 0 -> %08lx", (unsigned long)status);
        ok(returned > 0, "83 returned nothing");
        group = 1;
        status = NtQuerySystemInformationEx(SystemProcessorIdleCycleTimeInformation_, &group,
                                            sizeof(group), buffer, sizeof(buffer), &returned);
        ok(status == STATUS_INVALID_PARAMETER, "83 for group 1 -> %08lx", (unsigned long)status);
    }

    /* --- and each variable class SUCCEEDS at a generous size -------------
     * The other half of every refusal above: a class that only ever refused
     * would pass this file's first section and be useless. */
    {
        static const struct
        {
            SYSTEM_INFORMATION_CLASS infoClass;
            const char *name;
        } succeeds[] = {
            {SystemExtendedProcessInformation_, "SystemExtendedProcessInformation"},
            {SystemExtendedHandleInformation_, "SystemExtendedHandleInformation"},
            {SystemModuleInformationEx_, "SystemModuleInformationEx"},
            {SystemCodeIntegrityInformation_, "SystemCodeIntegrityInformation"},
        };
        static UCHAR large[0x20000];
        for (unsigned i = 0; i < sizeof(succeeds) / sizeof(succeeds[0]); i++)
        {
            returned = 0;
            status =
                NtQuerySystemInformation(succeeds[i].infoClass, large, sizeof(large), &returned);
            ntapi_okv(status == STATUS_SUCCESS, __FILE__, __LINE__, "%s -> %08lx", succeeds[i].name,
                      (unsigned long)status);
            ntapi_okv(returned > 0, __FILE__, __LINE__, "%s returned nothing", succeeds[i].name);
        }
    }
}
