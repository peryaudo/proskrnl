/* tests/kmt/cui8_async.c — the CUI-8 machine verdicts (docs/19 §8.3/§8.4).
 *
 * The semantic net (sem_file, file_coherence_mt) cannot convict this
 * milestone: an implementation that pends but never overlaps passes every
 * semantic test because it is behaviourally the old kernel. These cases
 * measure the MACHINE, from kernel mode where the in-flight window can be
 * held open deterministically (VioBlkSetAwaitSpinBound(0) forces every
 * await to park, so "a transfer is in flight and the issuer is parked" is
 * a controlled state, not a race):
 *
 *   - progress: a counter thread observably advances while another
 *     thread's cold cache fill is parked on the device — the property the
 *     milestone exists for (docs/02 "Done when", first clause);
 *   - depth: the batched fill genuinely overlaps device work, reported as
 *     the machine-readable [KTEST] blk depth line against the committed
 *     floor (docs/19 §8.4: the win must be a verdict, not an inference);
 *   - cancellation: a landed cancel is observed by a parked fill, which
 *     stops issuing, awaits what is out (docs/20 R4), and answers
 *     STATUS_CANCELLED (docs/19 §9.9) — driven at the mechanism level
 *     (the syncIoCancelled mark NtCancelSynchronousIoFile sets); the
 *     boundary conviction is sem_file/cancel_data_io.c on both runners.
 */
#include "tests/kmt/kmt.h"
#include "drivers/virtio/blk.h"
#include "kernel/io/io.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/mm/pool.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

/* The committed depth floor (docs/19 §8.4; docs/02 "Done when"). The fill
 * batches VIO_BLK_MAX_INFLIGHT (16) requests, so a healthy run reaches 16;
 * the floor only ratchets UP, and only in the commit that earns it. */
#define CUI8_DEPTH_FLOOR 8

#define CUI8_FILE_PAGES 64u /* 256 KiB: 4 full batches per cold fill */
#define CUI8_FILE_BYTES (CUI8_FILE_PAGES * 4096u)

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

/* Create the working file at full size and CLOSE it: the FCB dies with the
 * last reference, so the next open's read is a genuinely cold fill. */
static int cui8_build_cold_file(const WCHAR *path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0;
    LARGE_INTEGER offset;
    static char block[4096];

    init_attr(&attr, &name, path);
    NTSTATUS status = NtCreateFile(&file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                   FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ok(status == STATUS_SUCCESS, "create %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return 0;
    memset(block, 0x6b, sizeof(block));
    for (unsigned p = 0; p < CUI8_FILE_PAGES; p++)
    {
        offset.QuadPart = (LONGLONG)p * 4096;
        status = NtWriteFile(file, 0, 0, 0, &iosb, block, sizeof(block), &offset, 0);
        if (status != STATUS_SUCCESS)
            break;
    }
    ok(status == STATUS_SUCCESS, "fill %#x", (unsigned)status);
    NtClose(file);
    return status == STATUS_SUCCESS;
}


/* Give the working file's clusters back to the volume. The kmt suites share
 * one FAT volume with everything that boots after them — on the fatstress
 * nearfull leg that is a churn whose early mkdirs are entitled to the ~150
 * KiB the image was ballasted to keep free, and a leftover cold file (or
 * its DISK_FULL-truncated wreck, which is what a failed build leaves) was
 * exactly enough to starve them (PR #98 CI). Every test deletes its file on
 * every exit, success or not. */
static void cui8_delete_file(const WCHAR *path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_attr(&attr, &name, path);
    NtDeleteFile(&attr);
}

/* Whole-file read on a fresh handle — the cold fill under test. */
static NTSTATUS cui8_cold_read(const WCHAR *path, ULONG_PTR *bytesOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0;
    LARGE_INTEGER offset;
    static char whole[CUI8_FILE_BYTES];

    init_attr(&attr, &name, path);
    NTSTATUS status = NtCreateFile(&file, FILE_GENERIC_READ, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                                   FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status != STATUS_SUCCESS)
        return status;
    offset.QuadPart = 0;
    status = NtReadFile(file, 0, 0, 0, &iosb, whole, CUI8_FILE_BYTES, &offset, 0);
    if (bytesOut != 0)
        *bytesOut = NT_SUCCESS(status) ? iosb.Information : 0;
    NtClose(file);
    return status;
}

/* --- progress during I/O (docs/19 §8.3.1) ---------------------------------- */

static volatile LONG cui8_counter_stop;
static volatile uint64_t cui8_counter;

static void cui8_counter_thread(void *context)
{
    (void)context;
    while (!cui8_counter_stop)
    {
        cui8_counter++;
        KiYield(); /* cooperative: hand the CPU back every step */
    }
}

static void test_cui8_progress_during_io(void)
{
    if (!cui8_build_cold_file(WSTR("\\??\\C:\\cui8prog.bin")))
    {
        cui8_delete_file(WSTR("\\??\\C:\\cui8prog.bin"));
        return;
    }

    cui8_counter_stop = 0;
    cui8_counter = 0;
    PKTHREAD counter = KiCreateThread(8, cui8_counter_thread, 0);
    ok(counter != 0, "counter thread");
    if (counter == 0)
    {
        cui8_delete_file(WSTR("\\??\\C:\\cui8prog.bin"));
        return; /* the FAIL is recorded; don't turn it into a NULL deref */
    }

    /* Every await parks: the machine is provably NOT single-threaded while
     * the disk is busy, or the counter stays frozen and this fails. The
     * CONFIGURED bound is restored, not the compile-time default — on a
     * stress boot the configured bound is already 0, and restoring the
     * default here de-stressed every test after this one (blk.h). */
    ULONG savedSpins = VioBlkSetAwaitSpinBound(0);
    uint64_t before = cui8_counter;
    ULONG_PTR bytes = 0;
    NTSTATUS status = cui8_cold_read(WSTR("\\??\\C:\\cui8prog.bin"), &bytes);
    uint64_t after = cui8_counter;
    VioBlkSetAwaitSpinBound(savedSpins);

    ok(status == STATUS_SUCCESS && bytes == CUI8_FILE_BYTES, "cold read %#x/%lu", (unsigned)status,
       (unsigned long)bytes);
    ok(after > before, "counter advanced during the parked fill (%lu -> %lu)",
       (unsigned long)before, (unsigned long)after);

    cui8_counter_stop = 1;
    NTSTATUS join = KeWaitForSingleObject(counter, Executive, 0, FALSE, 0);
    ok(join == STATUS_SUCCESS, "join %#x", (unsigned)join);
    KiDeleteThread(counter);
    cui8_delete_file(WSTR("\\??\\C:\\cui8prog.bin"));
}

/* --- the depth verdict (docs/19 §8.4) -------------------------------------- */

static void test_cui8_depth(void)
{
    if (!cui8_build_cold_file(WSTR("\\??\\C:\\cui8dpth.bin")))
    {
        cui8_delete_file(WSTR("\\??\\C:\\cui8dpth.bin"));
        return;
    }

    VioBlkResetDepthStats();
    ULONG_PTR bytes = 0;
    NTSTATUS status = cui8_cold_read(WSTR("\\??\\C:\\cui8dpth.bin"), &bytes);
    ok(status == STATUS_SUCCESS && bytes == CUI8_FILE_BYTES, "cold read %#x/%lu", (unsigned)status,
       (unsigned long)bytes);

    ULONG maxDepth = 0, meanTimes100 = 0;
    VioBlkQueryDepthStats(&maxDepth, &meanTimes100);
    /* The machine-readable verdict the cui8 leg greps (docs/19 §8.4). */
    DbgPrint("[KTEST] blk depth max=%lu mean=%lu.%02lu floor=%d\n", (unsigned long)maxDepth,
             (unsigned long)(meanTimes100 / 100), (unsigned long)(meanTimes100 % 100),
             CUI8_DEPTH_FLOOR);
    ok(maxDepth >= CUI8_DEPTH_FLOOR, "in-flight depth %lu under the committed floor %d",
       (unsigned long)maxDepth, CUI8_DEPTH_FLOOR);
    cui8_delete_file(WSTR("\\??\\C:\\cui8dpth.bin"));
}

/* --- cancellation of a parked fill (docs/19 §9.9) -------------------------- */

static volatile NTSTATUS cui8_cancel_status;

static void cui8_cancel_reader(void *context)
{
    (void)context;
    cui8_cancel_status = cui8_cold_read(WSTR("\\??\\C:\\cui8cxl.bin"), 0);
}

static void test_cui8_cancel_in_flight(void)
{
    if (!cui8_build_cold_file(WSTR("\\??\\C:\\cui8cxl.bin")))
    {
        cui8_delete_file(WSTR("\\??\\C:\\cui8cxl.bin"));
        return;
    }

    cui8_cancel_status = STATUS_PENDING;
    /* The reader's fill parks on every batch; the configured bound comes
     * back afterwards (blk.h — never the compile-time default). */
    ULONG savedSpins = VioBlkSetAwaitSpinBound(0);
    PKTHREAD reader = KiCreateThread(8, cui8_cancel_reader, 0);
    ok(reader != 0, "reader thread");
    if (reader == 0)
    {
        VioBlkSetAwaitSpinBound(savedSpins);
        cui8_delete_file(WSTR("\\??\\C:\\cui8cxl.bin"));
        return; /* the FAIL is recorded; don't turn it into a NULL deref */
    }

    /* Wait for the reader to be provably inside its marked I/O span (set
     * by rw.c before the fill can park), then land the cancel — the same
     * mark-and-wake NtCancelSynchronousIoFile performs, driven at the
     * mechanism level (the boundary form is pinned by cancel_data_io.c). */
    int sawSpan = 0;
    for (uint64_t spins = 0; spins < 1000000000ULL; spins++)
    {
        if (reader->syncIoActive)
        {
            sawSpan = 1;
            break;
        }
        KiYield();
    }
    ok(sawSpan, "reader reached its synchronous-I/O span");
    if (sawSpan)
    {
        reader->syncIoCancelled = TRUE;
        KeSetEvent(&reader->syncIoCancelEvent, 0, FALSE);
    }
    VioBlkSetAwaitSpinBound(savedSpins);

    NTSTATUS join = KeWaitForSingleObject(reader, Executive, 0, FALSE, 0);
    ok(join == STATUS_SUCCESS, "join %#x", (unsigned)join);
    KiDeleteThread(reader);
    ok(cui8_cancel_status == STATUS_CANCELLED, "cancelled fill -> %#x",
       (unsigned)cui8_cancel_status);

    /* The aftermath is ordinary: a fresh read redoes the fill and sees
     * every byte (a cancelled fill never leaves a torn cache). */
    ULONG_PTR bytes = 0;
    NTSTATUS status = cui8_cold_read(WSTR("\\??\\C:\\cui8cxl.bin"), &bytes);
    ok(status == STATUS_SUCCESS && bytes == CUI8_FILE_BYTES, "re-read after cancel %#x/%lu",
       (unsigned)status, (unsigned long)bytes);
    cui8_delete_file(WSTR("\\??\\C:\\cui8cxl.bin"));
}

int kmt_run_cui8(void)
{
    int before = kmt_failures;
    DbgPrint("kmt: CUI-8 async suite\n");
    KMT_RUN(test_cui8_progress_during_io);
    KMT_RUN(test_cui8_depth);
    KMT_RUN(test_cui8_cancel_in_flight);
    return kmt_failures - before;
}
