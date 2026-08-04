/* tests/kmt/sched_explore.c — bounded-exhaustive interleaving search with a
 * linearizability verdict (issue #96 D).
 *
 * WHY THIS AND NOT MORE ASSERTS. docs/20 §10.6 is the sharpest thing the
 * CUI-8 post-mortems concluded: almost every defect the reviews and the blind
 * re-sweep convicted was a COMPOSITION — a value sampled before a park and
 * used after, two gated ops in sequence, a gate held across a callback. None
 * is a false claim at a single line, so a site-by-site census walks past all
 * of them however honestly it is done, and so does any assert placed at a
 * site. What finds a composition is running the composition under a hostile
 * interleaving.
 *
 * WHY IT IS FEASIBLE HERE. The kernel is cooperative (Art. 3): switches
 * happen only at enumerable yield points, so for two threads the interleaving
 * space is finite and controllable rather than a hardware lottery. Three
 * knobs make it exhaustive instead of lucky:
 *
 *   1. every scheduling decision is steered by a schedule string
 *      (KiArmSchedule, kernel/ke/sched.c);
 *   2. VioBlkSetAwaitSpinBound(0) forces every device await to PARK, so the
 *      interesting yield points actually occur instead of being spun through;
 *   3. the search is depth-first over choice vectors with a PREEMPTION BOUND
 *      — the CHESS insight that nearly all real concurrency bugs surface
 *      within two or three deviations from the default schedule, which turns
 *      an exponential space into a small one without giving up the bugs.
 *
 * THE ORACLE PROBLEM, AND THE ANSWER. A concurrent execution cannot be
 * differentially tested against Wine: Wine will not reproduce the
 * interleaving, so there is no per-call answer to compare (G6's usual
 * instrument does not apply). The oracle here is LINEARIZABILITY: record the
 * concurrent history, then search for SOME sequential order of those
 * operations, consistent with real-time non-overlap, that the sequential
 * semantics would produce. If none exists, the kernel did something no NT
 * could have done — a machine verdict with no reviewer opinion in it.
 *
 * G6 is satisfied through the sequential model, not around it: the model
 * below implements only behaviour already pinned on the oracle by
 * tests/ntapi/sem_file (append.c for FILE_WRITE_TO_END_OF_FILE placement,
 * read_write.c for offsets/short transfers, zero_length_write.c for the
 * no-extend rule). Wine remains the authority for each candidate sequential
 * history; this only asks whether one of them explains what happened.
 *
 * The two scenarios are the two compositions the CUI-8 reviews actually
 * convicted (docs/20 §9): the append race that truncated a concurrent
 * writer's extension, and the shared synchronous handle whose file position
 * two threads both captured and both advanced.
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/io/io.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "drivers/virtio/blk.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

/* --- the search's bounds, all of them loud ------------------------------- */

/* Deviations from the default schedule (CHESS's preemption bound). 2 is the
 * knee of the published curve; raising it is a cost decision, not a
 * correctness one. */
#define EXPLORE_PREEMPTION_BOUND 2
/* A wall on total runs so a scenario that grows choice points cannot turn a
 * boot into an hour. Hitting it is REPORTED, never silent: a truncated search
 * that reads as exhaustive is worse than no search (Art. 12). */
#define EXPLORE_MAX_RUNS     240
#define EXPLORE_MAX_SCHEDULE KI_SCHEDULE_MAX_CHOICES

/* THREE workers, not two, and that number is load-bearing. In a cooperative
 * kernel a context switch only has a CHOICE when two threads are READY at
 * once; with two workers one is always the one that just parked, so every
 * switch has a single candidate and the interleaving is fully determined —
 * the search space is empty and the harness passes while testing nothing
 * (docs/19 §8.4's correct-but-inert shape, which is why the run reports its
 * own choice-point count as part of the verdict). With three, a park leaves
 * two candidates and the space opens up. */
#define EXPLORE_WORKERS 3

/* And each worker issues a SEQUENCE of operations, for two reasons. It keeps
 * threads cycling between ready and parked so choice points keep arising
 * after the initial dispatch — with one op each, every switch past the first
 * has a single candidate again. And it is the shape docs/20 §10.6's fifth
 * question is about ("what spans more than one gated operation?"), which is
 * the class a per-site census cannot see. */
#define EXPLORE_OPS_PER_WORKER 2

#define EXPLORE_WRITE_BYTES 96u
#define EXPLORE_FILE_MAX    1024u

/* --- the recorded concurrent history ------------------------------------- */

#define LIN_MAX_OPS (EXPLORE_WORKERS * EXPLORE_OPS_PER_WORKER)

#define LIN_APPEND   0
#define LIN_WRITE_AT 1

typedef struct
{
    UCHAR kind;
    ULONG offset; /* LIN_WRITE_AT only */
    ULONG length;
    UCHAR pattern;
    ULONG startSeq; /* real-time interval: invocation .. response */
    ULONG endSeq;
    NTSTATUS status;
    ULONG transferred;
} LIN_OP;

static LIN_OP lin_ops[LIN_MAX_OPS];
static ULONG lin_op_count;
static ULONG lin_sequence;

/* A real-time stamp. Taken under the dispatcher lock so the counter and the
 * scheduling decision that may follow it cannot interleave — the stamps have
 * to totally order non-overlapping operations for the linearizability search
 * to mean anything. */
static ULONG lin_stamp(void)
{
    uint64_t flags = KiAcquireDispatcherLock();
    ULONG value = ++lin_sequence;
    KiReleaseDispatcherLock(flags);
    return value;
}

static void lin_record(const LIN_OP *op)
{
    uint64_t flags = KiAcquireDispatcherLock();
    if (lin_op_count < LIN_MAX_OPS)
    {
        lin_ops[lin_op_count++] = *op;
    }
    KiReleaseDispatcherLock(flags);
}

/* --- the sequential model (only oracle-pinned behaviour; see the header) -- */

typedef struct
{
    UCHAR bytes[EXPLORE_FILE_MAX];
    ULONG size;
} LIN_FILE;

/* Apply one operation to the model. Returns FALSE when the observed result
 * disagrees with what the sequential semantics produce at this point, which
 * disqualifies the candidate order. */
static BOOLEAN lin_apply(LIN_FILE *file, const LIN_OP *op)
{
    ULONG offset = op->kind == LIN_APPEND ? file->size : op->offset;
    if (offset + op->length > EXPLORE_FILE_MAX)
    {
        return FALSE;
    }
    /* A zero-length write extends nothing (pinned sem_file/zero_length_write.c). */
    if (op->length != 0)
    {
        memset(file->bytes + offset, op->pattern, op->length);
        if (offset + op->length > file->size)
        {
            file->size = offset + op->length;
        }
    }
    return op->status == STATUS_SUCCESS && op->transferred == op->length;
}

/* Real-time order: an operation that RESPONDED before another was INVOKED
 * must precede it in any legal linearization. Overlapping operations may go
 * either way — that freedom is exactly what makes this a linearizability
 * check rather than a fixed expectation. */
static BOOLEAN lin_order_allowed(const ULONG *order, ULONG count)
{
    for (ULONG i = 0; i < count; i++)
    {
        for (ULONG j = i + 1; j < count; j++)
        {
            if (lin_ops[order[j]].endSeq < lin_ops[order[i]].startSeq)
            {
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOLEAN lin_try_orders(ULONG *order, ULONG placed, ULONG count, const UCHAR *finalBytes,
                              ULONG finalSize)
{
    if (placed == count)
    {
        if (!lin_order_allowed(order, count))
        {
            return FALSE;
        }
        /* static: the checker is single-threaded and LIN_FILE is a kilobyte,
         * which has no business on a 16 KiB kernel stack four frames deep. */
        static LIN_FILE model;
        memset(&model, 0, sizeof(model));
        for (ULONG i = 0; i < count; i++)
        {
            if (!lin_apply(&model, &lin_ops[order[i]]))
            {
                return FALSE;
            }
        }
        return model.size == finalSize && memcmp(model.bytes, finalBytes, finalSize) == 0;
    }
    for (ULONG candidate = 0; candidate < count; candidate++)
    {
        BOOLEAN used = FALSE;
        for (ULONG i = 0; i < placed; i++)
        {
            used = used || order[i] == candidate;
        }
        if (used)
        {
            continue;
        }
        order[placed] = candidate;
        if (lin_try_orders(order, placed + 1, count, finalBytes, finalSize))
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* THE VERDICT: does any legal sequential order explain the observed state? */
static BOOLEAN lin_is_linearizable(const UCHAR *finalBytes, ULONG finalSize)
{
    ULONG order[LIN_MAX_OPS];
    return lin_try_orders(order, 0, lin_op_count, finalBytes, finalSize);
}

/* --- the file under test -------------------------------------------------- */

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

#define EXPLORE_PATH WSTR("\\??\\C:\\linearz.tmp")

static BOOLEAN explore_reset_file(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = 0;
    init_attr(&attr, &name, EXPLORE_PATH);
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                                   FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status != STATUS_SUCCESS)
    {
        return FALSE;
    }
    NtClose(handle);
    return TRUE;
}

/* Read the whole file back — the observed final state the model is checked
 * against. Runs alone, after every worker has responded. */
static BOOLEAN explore_read_back(UCHAR *bytes, ULONG *sizeOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = 0;
    LARGE_INTEGER offset;
    init_attr(&attr, &name, EXPLORE_PATH);
    NTSTATUS status =
        NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status != STATUS_SUCCESS)
    {
        return FALSE;
    }
    offset.QuadPart = 0;
    memset(bytes, 0, EXPLORE_FILE_MAX);
    status = NtReadFile(handle, 0, 0, 0, &iosb, bytes, EXPLORE_FILE_MAX, &offset, 0);
    *sizeOut = status == STATUS_SUCCESS ? (ULONG)iosb.Information : 0;
    if (status == STATUS_END_OF_FILE)
    {
        status = STATUS_SUCCESS; /* an empty file reads as EOF */
    }
    NtClose(handle);
    return status == STATUS_SUCCESS;
}

/* --- scenario 1: the append race ------------------------------------------
 *
 * Two threads, two handles, each appending EXPLORE_WRITE_BYTES at
 * FILE_WRITE_TO_END_OF_FILE. This is the composition docs/20 §9 records as
 * convicted by the PR #95 review: the placement was decided from a pre-park
 * size snapshot and pushed through SetEndOfFile, so two writers truncated
 * each other. The linearizability verdict is decisive on it and needs no
 * expectation written down — no sequential order of two successful 96-byte
 * appends produces a 96-byte file. */

typedef struct
{
    ULONG index;
    UCHAR pattern;
    KEVENT done;
} EXPLORE_WORKER;

static EXPLORE_WORKER explore_workers[EXPLORE_WORKERS];

static void explore_append_worker(void *context)
{
    EXPLORE_WORKER *worker = context;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = 0;
    LARGE_INTEGER offset;
    static UCHAR payload[EXPLORE_WORKERS][EXPLORE_WRITE_BYTES];
    UCHAR *block = payload[worker->index];
    LIN_OP op;

    memset(block, worker->pattern, EXPLORE_WRITE_BYTES);
    init_attr(&attr, &name, EXPLORE_PATH);

    memset(&op, 0, sizeof(op));
    op.kind = LIN_APPEND;
    op.length = EXPLORE_WRITE_BYTES;
    op.pattern = worker->pattern;

    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status == STATUS_SUCCESS)
    {
        for (ULONG i = 0; i < EXPLORE_OPS_PER_WORKER; i++)
        {
            /* The operation's real-time interval brackets the syscall only:
             * the open and close are setup, not part of the history. */
            offset.QuadPart = -1; /* FILE_WRITE_TO_END_OF_FILE (pinned append.c) */
            op.startSeq = lin_stamp();
            status = NtWriteFile(handle, 0, 0, 0, &iosb, block, EXPLORE_WRITE_BYTES, &offset, 0);
            op.endSeq = lin_stamp();
            op.status = status;
            op.transferred = NT_SUCCESS(status) ? (ULONG)iosb.Information : 0;
            lin_record(&op);
        }
        NtClose(handle);
    }
    else
    {
        op.startSeq = op.endSeq = lin_stamp();
        op.status = status;
        lin_record(&op);
    }
    KeSetEvent(&worker->done, 0, FALSE);
}

/* --- scenario 2: the shared synchronous handle ----------------------------
 *
 * One synchronous handle, two threads, NULL byte offset — so the KERNEL owns
 * the position and both writes must land at distinct offsets. docs/20 §9
 * records this as the row that sat outside the enumeration entirely
 * (FILE_OBJECT.currentByteOffset mutated across parks), repaired by
 * syncIoLock and pinned at the boundary by sem_file/shared_handle_offset.c —
 * which, being sequential, cannot convict the interleaving. This can. */

static HANDLE explore_shared_handle;

static void explore_shared_worker(void *context)
{
    EXPLORE_WORKER *worker = context;
    IO_STATUS_BLOCK iosb;
    static UCHAR payload[EXPLORE_WORKERS][EXPLORE_WRITE_BYTES];
    UCHAR *block = payload[worker->index];
    LIN_OP op;

    memset(block, worker->pattern, EXPLORE_WRITE_BYTES);
    memset(&op, 0, sizeof(op));
    op.kind = LIN_APPEND; /* the kernel-owned position advances like an append */
    op.length = EXPLORE_WRITE_BYTES;
    op.pattern = worker->pattern;

    for (ULONG i = 0; i < EXPLORE_OPS_PER_WORKER; i++)
    {
        op.startSeq = lin_stamp();
        NTSTATUS status =
            NtWriteFile(explore_shared_handle, 0, 0, 0, &iosb, block, EXPLORE_WRITE_BYTES, 0, 0);
        op.endSeq = lin_stamp();
        op.status = status;
        op.transferred = NT_SUCCESS(status) ? (ULONG)iosb.Information : 0;
        lin_record(&op);
    }
    KeSetEvent(&worker->done, 0, FALSE);
}

/* --- one run under one schedule ------------------------------------------- */

/* Returns TRUE when the run was linearizable. `trace` reports the choice
 * points this schedule actually reached, which is what drives the search. */
static BOOLEAN explore_run(void (*worker)(void *), BOOLEAN sharedHandle, const UCHAR *schedule,
                           ULONG scheduleLength, PKI_SCHEDULE_TRACE trace)
{
    static UCHAR observed[EXPLORE_FILE_MAX];
    static KWAIT_BLOCK joinBlocks[EXPLORE_WORKERS]; /* > KI_THREAD_WAIT_OBJECTS needs an array */
    ULONG observedSize = 0;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    lin_op_count = 0;
    lin_sequence = 0;
    /* Cleared before the first early return: the caller reads the trace on
     * every run, including the ones that give up before the schedule runs. */
    memset(trace, 0, sizeof(*trace));
    if (!explore_reset_file())
    {
        return FALSE;
    }

    if (sharedHandle)
    {
        init_attr(&attr, &name, EXPLORE_PATH);
        if (NtCreateFile(&explore_shared_handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr,
                         &iosb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0) != STATUS_SUCCESS)
        {
            return FALSE;
        }
    }

    PKTHREAD threads[EXPLORE_WORKERS];
    void *joinObjects[EXPLORE_WORKERS];
    for (int i = 0; i < EXPLORE_WORKERS; i++)
    {
        explore_workers[i].index = (ULONG)i;
        explore_workers[i].pattern = (UCHAR)(0xa0 + i);
        KeInitializeEvent(&explore_workers[i].done, NotificationEvent, FALSE);
        /* Created suspended so ALL of them are ready before the first steered
         * decision — otherwise the schedule's early bytes fall on
         * one-candidate switches and mean nothing. */
        threads[i] = KiCreateThreadSuspended(8, worker, &explore_workers[i], 0, 0);
        joinObjects[i] = &explore_workers[i].done;
    }

    KiArmSchedule(schedule, scheduleLength);
    for (int i = 0; i < EXPLORE_WORKERS; i++)
    {
        KiReadyCreatedThread(threads[i]);
    }
    KeWaitForMultipleObjects(EXPLORE_WORKERS, joinObjects, WaitAll, Executive, KernelMode, FALSE, 0,
                             joinBlocks);
    KiDisarmSchedule(trace);

    for (int i = 0; i < EXPLORE_WORKERS; i++)
    {
        KeWaitForSingleObject(threads[i], Executive, KernelMode, FALSE, 0);
        KiDeleteThread(threads[i]);
    }
    if (sharedHandle)
    {
        NtClose(explore_shared_handle);
        explore_shared_handle = 0;
    }

    if (!explore_read_back(observed, &observedSize))
    {
        return FALSE;
    }
    return lin_is_linearizable(observed, observedSize);
}

/* --- the depth-first search ----------------------------------------------- */

static void explore_print_schedule(const char *label, const UCHAR *schedule, ULONG length)
{
    DbgPrint("[KTEST] sched %s schedule len=%lu:", label, (unsigned long)length);
    for (ULONG i = 0; i < length; i++)
    {
        DbgPrint(" %u", (unsigned)schedule[i]);
    }
    DbgPrint("\n");
}

/* Delta-debug a failing schedule: drop trailing choices while the failure
 * survives, then zero out individual deviations. What is left is the minimal
 * interleaving, which is the artifact worth pinning — "flaky" becomes a
 * [KTEST] line with a schedule. */
static void explore_minimize(void (*worker)(void *), BOOLEAN sharedHandle, UCHAR *schedule,
                             ULONG *length)
{
    KI_SCHEDULE_TRACE trace;
    while (*length > 0)
    {
        ULONG shorter = *length - 1;
        if (explore_run(worker, sharedHandle, schedule, shorter, &trace))
        {
            break; /* the failure needs this suffix */
        }
        *length = shorter;
    }
    for (ULONG i = 0; i < *length; i++)
    {
        if (schedule[i] == 0)
        {
            continue;
        }
        UCHAR saved = schedule[i];
        schedule[i] = 0;
        if (explore_run(worker, sharedHandle, schedule, *length, &trace))
        {
            schedule[i] = saved; /* this deviation is load-bearing */
        }
    }
}

static ULONG explore_deviations(const UCHAR *schedule, ULONG length)
{
    ULONG count = 0;
    for (ULONG i = 0; i < length; i++)
    {
        count += schedule[i] != 0 ? 1 : 0;
    }
    return count;
}

/* Depth-first over choice vectors. Each run reports the branching factor it
 * saw at every choice point; the next schedule is the current one with its
 * last still-unexplored choice advanced — standard systematic exploration,
 * pruned by the preemption bound. */
static void explore_scenario(const char *label, void (*worker)(void *), BOOLEAN sharedHandle)
{
    static UCHAR schedule[EXPLORE_MAX_SCHEDULE];
    ULONG length = 0;
    ULONG runs = 0;
    ULONG maxChoices = 0;
    BOOLEAN truncated = FALSE;
    BOOLEAN traceOverflowed = FALSE;
    BOOLEAN skipped = FALSE;
    KI_SCHEDULE_TRACE trace;

    /* Force every device await to park: without this the interesting yield
     * points are spun through and the search explores an empty space. Restore
     * the PREVIOUS bound, never the compile-time default — a stress boot
     * configures 0 globally (drivers/virtio/blk.h). */
    ULONG savedSpins = VioBlkSetAwaitSpinBound(0);

    memset(schedule, 0, sizeof(schedule));
    for (;;)
    {
        BOOLEAN linearizable = explore_run(worker, sharedHandle, schedule, length, &trace);
        runs++;
        /* A volume too full to hold the scenario's few hundred bytes cannot
         * be searched: a DISK_FULL op would surface as "not linearizable"
         * only because the model has no pinned DISK_FULL timing to check
         * against. Skip LOUDLY (Art. 12) instead of failing on the wrong
         * claim or passing on an empty history. */
        BOOLEAN diskFull = FALSE;
        for (ULONG i = 0; i < lin_op_count; i++)
        {
            diskFull = diskFull || lin_ops[i].status == STATUS_DISK_FULL;
        }
        if (diskFull)
        {
            DbgPrint("[KTEST] sched %s SKIP (STATUS_DISK_FULL: volume too full to search)\n",
                     label);
            skipped = TRUE;
            break;
        }
        maxChoices = trace.choiceCount > maxChoices ? trace.choiceCount : maxChoices;
        traceOverflowed = traceOverflowed || trace.overflowed;
        if (runs == 1)
        {
            /* The harness's own premise (docs/19 §8.1): the zero-length
             * schedule must reproduce the default policy exactly, or the
             * search's baseline is not the kernel every other boot runs. */
            ok(trace.preemptions == 0, "%s: the empty schedule deviated %lu times", label,
               (unsigned long)trace.preemptions);
        }

        if (!linearizable)
        {
            explore_print_schedule(label, schedule, length);
            explore_minimize(worker, sharedHandle, schedule, &length);
            explore_print_schedule(label, schedule, length);
            ok(0, "%s: not linearizable — no sequential order explains the result", label);
            break;
        }

        /* Advance the last choice that has an untried alternative and stays
         * inside the preemption bound. */
        ULONG next =
            trace.choiceCount < EXPLORE_MAX_SCHEDULE ? trace.choiceCount : EXPLORE_MAX_SCHEDULE;
        BOOLEAN advanced = FALSE;
        while (next-- > 0)
        {
            UCHAR taken = trace.chosen[next];
            if (taken + 1u >= trace.options[next])
            {
                continue;
            }
            if (explore_deviations(schedule, next) + 1 > EXPLORE_PREEMPTION_BOUND)
            {
                continue;
            }
            schedule[next] = (UCHAR)(taken + 1);
            length = next + 1;
            memset(schedule + length, 0, sizeof(schedule) - length);
            advanced = TRUE;
            break;
        }
        if (!advanced)
        {
            break; /* the bounded space is exhausted */
        }
        if (runs >= EXPLORE_MAX_RUNS)
        {
            truncated = TRUE;
            break;
        }
    }

    VioBlkSetAwaitSpinBound(savedSpins);

    /* Give the working file's clusters back. The nearfull churn leg runs
     * AFTER this suite on the same volume with only a handful of free
     * clusters, and leaving linearz.tmp behind was exactly enough to push
     * its first directory create into STATUS_DISK_FULL (CI, PR #98): a
     * test that consumes shared state it does not return is itself the
     * composition class this file exists to catch. */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        init_attr(&attr, &name, EXPLORE_PATH);
        NtDeleteFile(&attr);
    }

    /* The coverage IS part of the verdict: a search that explored one
     * interleaving and passed is not evidence of anything, and neither is a
     * truncated one that reads as exhaustive (Art. 12, docs/19 §8.4's
     * correct-but-inert failure shape). */
    DbgPrint("[KTEST] sched %s runs=%lu maxchoices=%lu bound=%d%s%s\n", label, (unsigned long)runs,
             (unsigned long)maxChoices, EXPLORE_PREEMPTION_BOUND,
             truncated ? " TRUNCATED(run cap)" : "",
             traceOverflowed ? " TRUNCATED(trace cap)" : "");
    if (!skipped)
    {
        ok(runs > 1, "%s: only %lu run — the schedule steered nothing", label,
           (unsigned long)runs);
        ok(!truncated, "%s: hit the %d-run cap; the search was not exhaustive", label,
           EXPLORE_MAX_RUNS);
        ok(!traceOverflowed, "%s: more than %d choice points; the trace was truncated", label,
           KI_SCHEDULE_MAX_CHOICES);
    }
}

static void test_linearizable_append_race(void)
{
    explore_scenario("append", explore_append_worker, FALSE);
}

static void test_linearizable_shared_handle(void)
{
    explore_scenario("sharedhandle", explore_shared_worker, TRUE);
}

int kmt_run_sched_explore(void)
{
    int before = kmt_failures;
    KMT_RUN(test_linearizable_append_race);
    KMT_RUN(test_linearizable_shared_handle);
    return kmt_failures - before;
}
