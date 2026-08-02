/* tests/kmt/preventive.c — regression guards for the issue #96 mechanisms.
 *
 * The mechanisms themselves (non-blocking regions, the obligation ledger,
 * probe tokens) are ASSERTS: they convict by killing the machine, so nothing
 * they catch can be a passing test. What can be tested is the other half —
 * that the bookkeeping they depend on is exact — and that half is where the
 * bugs actually live: a release skipped on an early-return path, a region
 * left raised, a token minted at the wrong moment.
 *
 * So these cases assert the LEDGERS ARE BALANCED across real work: the
 * counters are zero on both sides of every representative gated operation.
 * A pairing bug that a hand-written test would never think to reach shows up
 * here as a nonzero count after an ordinary create/write/read/close.
 *
 * Per Art. 6 this names suspects; the conviction for a re-entrancy defect is
 * still file_coherence_mt and the differential fuzzer.
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/io/io.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/syscall/uaccess.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

#define PREVENTIVE_FILE WSTR("\\??\\C:\\preventive.tmp")

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    attr->Length = sizeof(*attr);
    attr->RootDirectory = 0;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

/* --- non-blocking regions (issue #96 A) ------------------------------------ */

static void test_no_block_regions(void)
{
    /* Nothing may leave a region raised: a stuck depth would make the NEXT
     * park panic, arbitrarily far from the code that leaked it. Checked here
     * after every earlier suite has run, so a leak anywhere in M2-CUI8
     * surfaces attributed to this line instead of to its victim. */
    ok(KiNoBlockDepth == 0, "no-block depth leaked: %lu ('%s')", (unsigned long)KiNoBlockDepth,
       KiNoBlockReason);

    KiEnterNoBlockRegion("kmt: the region nests");
    ok(KiNoBlockDepth == 1, "depth after enter %lu", (unsigned long)KiNoBlockDepth);
    KiEnterNoBlockRegion("kmt: inner");
    ok(KiNoBlockDepth == 2, "depth after nested enter %lu", (unsigned long)KiNoBlockDepth);
    KiLeaveNoBlockRegion();
    KiLeaveNoBlockRegion();
    ok(KiNoBlockDepth == 0, "depth after leave %lu", (unsigned long)KiNoBlockDepth);

    /* A park is legal again immediately: the region is a bracket, not a mode
     * the thread stays in. */
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    KeDelayExecutionThread(KernelMode, FALSE, &zero);
    ok(KiNoBlockDepth == 0, "depth after a park %lu", (unsigned long)KiNoBlockDepth);
}

/* --- the obligation ledger (issue #96 B) ----------------------------------- */

static void test_obligation_ledger(void)
{
    PKTHREAD self = KeGetCurrentThread();
    ok(self->obligationCount == 0, "entered owing %lu", (unsigned long)self->obligationCount);

    /* The gate pair, on a private event of the same shape the volume gate and
     * the file-object lock use. */
    KEVENT gate;
    KeInitializeEvent(&gate, SynchronizationEvent, TRUE);
    KiAcquireEventGate(&gate);
    ok(self->obligationCount == 1, "gate held, count %lu", (unsigned long)self->obligationCount);
    KiReleaseEventGate(&gate);
    ok(self->obligationCount == 0, "gate released, count %lu",
       (unsigned long)self->obligationCount);

    /* Two gates nest (a file-object lock outside a volume gate is exactly
     * this shape), and release in the reverse order. */
    KEVENT outer;
    KeInitializeEvent(&outer, SynchronizationEvent, TRUE);
    KiAcquireEventGate(&outer);
    KiAcquireEventGate(&gate);
    ok(self->obligationCount == 2, "two gates, count %lu", (unsigned long)self->obligationCount);
    KiReleaseEventGate(&gate);
    KiReleaseEventGate(&outer);
    ok(self->obligationCount == 0, "both released, count %lu",
       (unsigned long)self->obligationCount);
}

/* Every gated FS verb, driven for real, must give everything back. This is
 * the case that catches the bug class: an early return, an error path, or a
 * cancel break that skips a release. */
static void test_obligations_balanced_across_fs_ops(void)
{
    PKTHREAD self = KeGetCurrentThread();
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0;
    LARGE_INTEGER offset;
    static char block[512];
    FILE_BASIC_INFORMATION basic;

    init_attr(&attr, &name, PREVENTIVE_FILE);

    NTSTATUS status = NtCreateFile(&file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                   FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ok(status == STATUS_SUCCESS, "create %#x", (unsigned)status);
    ok(self->obligationCount == 0, "create left %lu", (unsigned long)self->obligationCount);
    if (status != STATUS_SUCCESS)
    {
        return;
    }

    memset(block, 0x9e, sizeof(block));
    offset.QuadPart = 0;
    status = NtWriteFile(file, 0, 0, 0, &iosb, block, sizeof(block), &offset, 0);
    ok(status == STATUS_SUCCESS, "write %#x", (unsigned)status);
    ok(self->obligationCount == 0, "write left %lu", (unsigned long)self->obligationCount);

    offset.QuadPart = 0;
    status = NtReadFile(file, 0, 0, 0, &iosb, block, sizeof(block), &offset, 0);
    ok(status == STATUS_SUCCESS, "read %#x", (unsigned)status);
    ok(self->obligationCount == 0, "read left %lu", (unsigned long)self->obligationCount);

    /* An op that FAILS inside the gate: reading at EOF takes the short exit,
     * which is exactly the shape a missed release hides on. */
    offset.QuadPart = (LONGLONG)sizeof(block) * 4;
    status = NtReadFile(file, 0, 0, 0, &iosb, block, sizeof(block), &offset, 0);
    ok(status == STATUS_END_OF_FILE, "read past EOF %#x", (unsigned)status);
    ok(self->obligationCount == 0, "failed read left %lu", (unsigned long)self->obligationCount);

    status = NtFlushBuffersFile(file, &iosb);
    ok(status == STATUS_SUCCESS, "flush %#x", (unsigned)status);
    ok(self->obligationCount == 0, "flush left %lu", (unsigned long)self->obligationCount);

    NtClose(file);
    ok(self->obligationCount == 0, "close left %lu", (unsigned long)self->obligationCount);

    /* The transient-handle services: open-op-close inside one call. */
    status = NtQueryAttributesFile(&attr, &basic);
    ok(status == STATUS_SUCCESS, "query attributes %#x", (unsigned)status);
    ok(self->obligationCount == 0, "query attributes left %lu",
       (unsigned long)self->obligationCount);

    status = NtDeleteFile(&attr);
    ok(status == STATUS_SUCCESS, "delete %#x", (unsigned)status);
    ok(self->obligationCount == 0, "delete left %lu", (unsigned long)self->obligationCount);

    /* And the same services on a name that does NOT exist — the error paths
     * out of a gated create. */
    UNICODE_STRING missingName;
    OBJECT_ATTRIBUTES missing;
    init_attr(&missing, &missingName, WSTR("\\??\\C:\\preventive.absent"));
    status = NtQueryAttributesFile(&missing, &basic);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "query missing %#x", (unsigned)status);
    ok(self->obligationCount == 0, "query missing left %lu", (unsigned long)self->obligationCount);
    status = NtDeleteFile(&missing);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "delete missing %#x", (unsigned)status);
    ok(self->obligationCount == 0, "delete missing left %lu", (unsigned long)self->obligationCount);
}

/* --- probe tokens (issue #96 C) -------------------------------------------- */

/* The mechanism convicts by panicking, so what is testable is its PREDICATE:
 * that a park really does move the generation a token is compared against.
 * If it did not, KiAssertProbeToken would pass on stale tokens and the whole
 * mechanism would be decorative — the failure mode docs/17 §8 and docs/19
 * §8.4 both warn about (correct but inert). */
static void test_probe_token_generation(void)
{
    PKTHREAD self = KeGetCurrentThread();
    static char scratch[64];

    KI_PROBE_TOKEN token = KiKernelToken(scratch, sizeof(scratch));
    ok(token.generation == self->parkGeneration, "fresh token %lu vs thread %lu",
       (unsigned long)token.generation, (unsigned long)self->parkGeneration);

    /* A fresh token accepts the copy it was minted for, and a sub-range of
     * it — the containment half of the check. */
    KiAssertProbeToken(&token, scratch, sizeof(scratch));
    KiAssertProbeToken(&token, scratch + 16, 8);

    /* A real park: a timed delay yields the CPU to the idle thread, which is
     * a genuine switch. */
    uint64_t before = self->parkGeneration;
    LARGE_INTEGER interval;
    interval.QuadPart = -20000; /* 2 ms, relative (100 ns units) */
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    ok(self->parkGeneration > before, "park did not advance the generation: %lu -> %lu",
       (unsigned long)before, (unsigned long)self->parkGeneration);

    /* Which is exactly the condition KiAssertProbeToken would die on — the
     * old token is now detectably stale. Asserted as a comparison rather
     * than by calling it, because calling it is the panic. */
    ok(token.generation != self->parkGeneration, "the pre-park token still looks fresh");
}

int kmt_run_preventive(void)
{
    int before = kmt_failures;
    KMT_RUN(test_no_block_regions);
    KMT_RUN(test_obligation_ledger);
    KMT_RUN(test_obligations_balanced_across_fs_ops);
    KMT_RUN(test_probe_token_generation);
    return kmt_failures - before;
}
