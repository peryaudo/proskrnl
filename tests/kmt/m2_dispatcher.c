/* tests/kmt/m2_dispatcher.c — the M2 in-kernel suite (docs/02).
 *
 * "Done when: in-kernel test — threads ping-pong on events/mutexes; timed
 * waits time out correctly." Plus the contract corners Article 5 calls out as
 * must-test-first: notification vs synchronization events, wait-any index
 * return, wait-all atomicity (nothing consumed until everything is
 * available), mutex ownership/recursion/abandonment, semaphore counting,
 * timer notification/synchronization/periodic behaviour, and the priority
 * scheduler's ordering.
 *
 * Scheduling here is cooperative and uniprocessor (Art. 3), so tests are
 * deterministic: a created thread runs only once the creator blocks or
 * yields. Timing assertions measure the same KeTickCount the timeouts are
 * implemented against, with slack only for tick-boundary rounding.
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/init/verify.h"
#include "kernel/lib/string.h"
#include "arch/x86_64/lapic.h"

int kmt_failures;
int kmt_todo;

/* Relative NT timeout: `ms` milliseconds as negative 100 ns units. */
static LARGE_INTEGER rel_ms(int ms)
{
    LARGE_INTEGER t;
    t.QuadPart = -(LONGLONG)ms * 10000;
    return t;
}

static void sleep_ms(int ms)
{
    LARGE_INTEGER t = rel_ms(ms);
    KeDelayExecutionThread(0 /*KernelMode*/, FALSE, &t);
}

static void join_and_delete(PKTHREAD thread)
{
    NTSTATUS status = KeWaitForSingleObject(thread, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "join: got %#x", (unsigned)status);
    KiDeleteThread(thread);
}

/* --- ping-pong on synchronization events --------------------------------- */

#define PINGPONG_ROUNDS 500

static KEVENT pingpong_ping;
static KEVENT pingpong_pong;
static int pingpong_count;

static void pingpong_worker(void *context)
{
    for (int i = 0; i < PINGPONG_ROUNDS; i++)
    {
        KeWaitForSingleObject(&pingpong_ping, Executive, 0, FALSE, 0);
        pingpong_count++;
        KeSetEvent(&pingpong_pong, 0, FALSE);
    }
}

static void test_event_pingpong(void)
{
    KeInitializeEvent(&pingpong_ping, SynchronizationEvent, FALSE);
    KeInitializeEvent(&pingpong_pong, SynchronizationEvent, FALSE);
    pingpong_count = 0;

    PKTHREAD worker = KiCreateThread(8, pingpong_worker, 0);
    for (int i = 0; i < PINGPONG_ROUNDS; i++)
    {
        KeSetEvent(&pingpong_ping, 0, FALSE);
        NTSTATUS status = KeWaitForSingleObject(&pingpong_pong, Executive, 0, FALSE, 0);
        ok(status == STATUS_SUCCESS, "pong wait %d: got %#x", i, (unsigned)status);
        ok(pingpong_count == i + 1, "round %d: count %d (lockstep broken)", i, pingpong_count);
    }
    join_and_delete(worker);
    ok(pingpong_count == PINGPONG_ROUNDS, "final count %d", pingpong_count);
    /* Both synchronization events must have been consumed back to 0. */
    ok(KeReadStateEvent(&pingpong_ping) == 0, "ping still signalled");
    ok(KeReadStateEvent(&pingpong_pong) == 0, "pong still signalled");
}

/* --- notification event: one set wakes ALL waiters, stays signalled ------ */

static KEVENT notif_event;
static int notif_woken;

static void notif_waiter(void *context)
{
    NTSTATUS status = KeWaitForSingleObject(&notif_event, Executive, 0, FALSE, 0);
    if (status == STATUS_SUCCESS)
    {
        notif_woken++;
    }
}

static void test_notification_event(void)
{
    KeInitializeEvent(&notif_event, NotificationEvent, FALSE);
    notif_woken = 0;

    void *waiters[3];
    for (int i = 0; i < 3; i++)
    {
        waiters[i] = KiCreateThread(8, notif_waiter, 0);
    }
    sleep_ms(10); /* let all three block on the event */
    ok(notif_woken == 0, "waiters woke early (%d)", notif_woken);

    KeSetEvent(&notif_event, 0, FALSE);

    NTSTATUS status = KeWaitForMultipleObjects(3, waiters, WaitAll, Executive, 0, FALSE, 0, 0);
    ok(status == STATUS_SUCCESS, "join-all: got %#x", (unsigned)status);
    ok(notif_woken == 3, "one set woke %d of 3 waiters", notif_woken);

    /* Notification events stay signalled: an immediate re-wait completes. */
    ok(KeReadStateEvent(&notif_event) == 1, "notification event was consumed");
    status = KeWaitForSingleObject(&notif_event, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "re-wait on signalled notification event: %#x", (unsigned)status);
    ok(KeReadStateEvent(&notif_event) == 1, "re-wait consumed a notification event");

    for (int i = 0; i < 3; i++)
    {
        KiDeleteThread(waiters[i]);
    }
}

/* --- synchronization event: one set wakes exactly ONE waiter -------------- */

static KEVENT sync_event;
static int sync_woken;

static void sync_waiter(void *context)
{
    KeWaitForSingleObject(&sync_event, Executive, 0, FALSE, 0);
    sync_woken++;
}

static void test_synchronization_event(void)
{
    KeInitializeEvent(&sync_event, SynchronizationEvent, FALSE);
    sync_woken = 0;

    void *waiters[3];
    for (int i = 0; i < 3; i++)
    {
        waiters[i] = KiCreateThread(8, sync_waiter, 0);
    }
    sleep_ms(10);

    KeSetEvent(&sync_event, 0, FALSE);
    sleep_ms(10);
    ok(sync_woken == 1, "one set woke %d waiters (must be exactly 1)", sync_woken);
    ok(KeReadStateEvent(&sync_event) == 0, "auto-reset did not happen");

    KeSetEvent(&sync_event, 0, FALSE);
    sleep_ms(10);
    ok(sync_woken == 2, "second set woke %d in total, want 2", sync_woken);

    KeSetEvent(&sync_event, 0, FALSE);
    NTSTATUS status = KeWaitForMultipleObjects(3, waiters, WaitAll, Executive, 0, FALSE, 0, 0);
    ok(status == STATUS_SUCCESS, "join-all: got %#x", (unsigned)status);
    ok(sync_woken == 3, "final woken %d", sync_woken);

    /* Set with no waiters: state stays 1 until one wait consumes it. */
    KeSetEvent(&sync_event, 0, FALSE);
    ok(KeReadStateEvent(&sync_event) == 1, "set with no waiter did not latch");
    status = KeWaitForSingleObject(&sync_event, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "latched wait: %#x", (unsigned)status);
    ok(KeReadStateEvent(&sync_event) == 0, "latched wait did not consume");

    for (int i = 0; i < 3; i++)
    {
        KiDeleteThread(waiters[i]);
    }
}

/* --- wait-any: correct index, one-object side effects --------------------- */

static KEVENT any_a;
static KEVENT any_b;
static NTSTATUS any_status = -1;

static void any_waiter(void *context)
{
    void *objects[2] = {&any_a, &any_b};
    any_status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, 0, FALSE, 0, 0);
}

static void test_wait_any(void)
{
    KeInitializeEvent(&any_a, NotificationEvent, FALSE);
    KeInitializeEvent(&any_b, SynchronizationEvent, FALSE);

    PKTHREAD worker = KiCreateThread(8, any_waiter, 0);
    sleep_ms(10);
    ok(any_status == -1, "wait-any returned before any signal (%#x)", (unsigned)any_status);

    KeSetEvent(&any_b, 0, FALSE); /* index 1 */
    join_and_delete(worker);
    ok(any_status == STATUS_WAIT_0 + 1, "wait-any index: got %#x, want 1", (unsigned)any_status);
    ok(KeReadStateEvent(&any_b) == 0, "satisfying wait-any did not consume the sync event");

    /* Already-signalled object: immediate return with the right index. */
    KeSetEvent(&any_a, 0, FALSE);
    void *objects[2] = {&any_b, &any_a};
    NTSTATUS status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, 0, FALSE, 0, 0);
    ok(status == STATUS_WAIT_0 + 1, "immediate wait-any index: got %#x, want 1", (unsigned)status);
}

/* --- wait-all: atomic — consumes nothing until everything is available ---- */

static KEVENT all_a;
static KEVENT all_b;
static int all_done;

static void all_waiter(void *context)
{
    void *objects[2] = {&all_a, &all_b};
    NTSTATUS status = KeWaitForMultipleObjects(2, objects, WaitAll, Executive, 0, FALSE, 0, 0);
    if (status == STATUS_SUCCESS)
    {
        all_done = 1;
    }
}

static void test_wait_all(void)
{
    KeInitializeEvent(&all_a, SynchronizationEvent, FALSE);
    KeInitializeEvent(&all_b, SynchronizationEvent, FALSE);
    all_done = 0;

    PKTHREAD worker = KiCreateThread(8, all_waiter, 0);
    sleep_ms(10);

    KeSetEvent(&all_a, 0, FALSE);
    sleep_ms(10);
    ok(all_done == 0, "wait-all completed with only one object signalled");
    /* THE wait-all contract: the pending wait-all must NOT have consumed the
     * signalled sync event while the other object is unsignalled. */
    ok(KeReadStateEvent(&all_a) == 1, "wait-all consumed event A before B was signalled");

    KeSetEvent(&all_b, 0, FALSE);
    join_and_delete(worker);
    ok(all_done == 1, "wait-all did not complete after both signalled");
    ok(KeReadStateEvent(&all_a) == 0, "wait-all completion did not consume A");
    ok(KeReadStateEvent(&all_b) == 0, "wait-all completion did not consume B");
}

/* --- mutex: ownership, recursion, waiter hand-off ------------------------- */

static KMUTEX mutex;
static int mutex_got;

static void mutex_contender(void *context)
{
    KeWaitForSingleObject(&mutex, Executive, 0, FALSE, 0);
    mutex_got = 1;
    KeReleaseMutex(&mutex, FALSE);
}

static void test_mutex(void)
{
    KeInitializeMutex(&mutex, 0);
    mutex_got = 0;

    NTSTATUS status = KeWaitForSingleObject(&mutex, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "acquire: %#x", (unsigned)status);
    status = KeWaitForSingleObject(&mutex, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "recursive acquire blocked: %#x", (unsigned)status);

    PKTHREAD contender = KiCreateThread(8, mutex_contender, 0);
    sleep_ms(10);
    ok(mutex_got == 0, "contender acquired a held mutex");

    LONG previous = KeReleaseMutex(&mutex, FALSE);
    ok(previous == -1, "first release returned %d, want -1 (recursion depth)", previous);
    sleep_ms(10);
    ok(mutex_got == 0, "contender acquired a recursively-held mutex after one release");

    previous = KeReleaseMutex(&mutex, FALSE);
    ok(previous == 0, "second release returned %d, want 0", previous);
    join_and_delete(contender);
    ok(mutex_got == 1, "contender never got the mutex");
}

/* --- mutex abandonment: dying owner -> STATUS_ABANDONED_WAIT_0 ------------ */

static KMUTEX abandoned_mutex;

static void abandoning_owner(void *context)
{
    KeWaitForSingleObject(&abandoned_mutex, Executive, 0, FALSE, 0);
    /* Terminate while owning it: KiTerminateThread must abandon it. */
}

static void test_mutex_abandonment(void)
{
    KeInitializeMutex(&abandoned_mutex, 0);

    PKTHREAD owner = KiCreateThread(8, abandoning_owner, 0);
    join_and_delete(owner);

    NTSTATUS status = KeWaitForSingleObject(&abandoned_mutex, Executive, 0, FALSE, 0);
    ok(status == STATUS_ABANDONED_WAIT_0, "abandoned mutex wait: got %#x, want %#x",
       (unsigned)status, (unsigned)STATUS_ABANDONED_WAIT_0);

    /* We own it now; a clean release and re-acquire reports no abandonment. */
    KeReleaseMutex(&abandoned_mutex, FALSE);
    status = KeWaitForSingleObject(&abandoned_mutex, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "abandonment did not clear: %#x", (unsigned)status);
    KeReleaseMutex(&abandoned_mutex, FALSE);
}

/* --- semaphore: counting, blocking, release return value ------------------ */

static KSEMAPHORE semaphore;
static int sema_got;

static void sema_waiter(void *context)
{
    KeWaitForSingleObject(&semaphore, Executive, 0, FALSE, 0);
    sema_got++;
}

static void test_semaphore(void)
{
    KeInitializeSemaphore(&semaphore, 2, 3);
    sema_got = 0;

    /* Two immediate acquisitions drain the initial count. */
    NTSTATUS status = KeWaitForSingleObject(&semaphore, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "first acquire: %#x", (unsigned)status);
    status = KeWaitForSingleObject(&semaphore, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "second acquire: %#x", (unsigned)status);

    PKTHREAD waiter = KiCreateThread(8, sema_waiter, 0);
    sleep_ms(10);
    ok(sema_got == 0, "wait on a drained semaphore did not block");

    LONG previous = KeReleaseSemaphore(&semaphore, 0, 1, FALSE);
    ok(previous == 0, "release returned %d, want 0", previous);
    join_and_delete(waiter);
    ok(sema_got == 1, "release did not wake the waiter");

    previous = KeReleaseSemaphore(&semaphore, 0, 2, FALSE);
    ok(previous == 0, "release-by-2 returned %d, want 0", previous);
    /* Count is 2 now: two more waits complete without blocking. */
    status = KeWaitForSingleObject(&semaphore, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "post-release acquire 1: %#x", (unsigned)status);
    status = KeWaitForSingleObject(&semaphore, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "post-release acquire 2: %#x", (unsigned)status);
}

/* --- timeouts: expiry status + duration, zero-timeout polling ------------- */

static KEVENT never_event;

static void test_timeouts(void)
{
    KeInitializeEvent(&never_event, NotificationEvent, FALSE);

    /* A 50 ms wait on a never-signalled event times out, after >= 50 ms. */
    LARGE_INTEGER timeout = rel_ms(50);
    uint64_t start = KeTickCount;
    NTSTATUS status = KeWaitForSingleObject(&never_event, Executive, 0, FALSE, &timeout);
    uint64_t elapsed = KeTickCount - start;
    ok(status == STATUS_TIMEOUT, "timed-out wait: got %#x", (unsigned)status);
    ok(elapsed >= 49, "50 ms wait returned after %lu ms", (unsigned long)elapsed);
    ok(elapsed < 1000, "50 ms wait took %lu ms", (unsigned long)elapsed);

    /* Zero timeout: pure poll — immediate STATUS_TIMEOUT, no wait. */
    timeout.QuadPart = 0;
    start = KeTickCount;
    status = KeWaitForSingleObject(&never_event, Executive, 0, FALSE, &timeout);
    elapsed = KeTickCount - start;
    ok(status == STATUS_TIMEOUT, "zero-timeout poll: got %#x", (unsigned)status);
    ok(elapsed <= 2, "zero-timeout poll took %lu ms", (unsigned long)elapsed);

    /* Satisfaction wins over a zero timeout (the NT ordering). */
    KeSetEvent(&never_event, 0, FALSE);
    status = KeWaitForSingleObject(&never_event, Executive, 0, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "signalled + zero timeout: got %#x, want success",
       (unsigned)status);
    KeResetEvent(&never_event);

    /* KeDelayExecutionThread sleeps the interval and reports success. */
    start = KeTickCount;
    LARGE_INTEGER interval = rel_ms(30);
    status = KeDelayExecutionThread(0, FALSE, &interval);
    elapsed = KeTickCount - start;
    ok(status == STATUS_SUCCESS, "delay: got %#x", (unsigned)status);
    ok(elapsed >= 29, "30 ms delay slept %lu ms", (unsigned long)elapsed);
}

/* A signal arriving before the timeout must win and cancel the timer. */
static KEVENT race_event;

static void race_setter(void *context)
{
    sleep_ms(20);
    KeSetEvent(&race_event, 0, FALSE);
}

static void test_signal_beats_timeout(void)
{
    KeInitializeEvent(&race_event, SynchronizationEvent, FALSE);
    PKTHREAD setter = KiCreateThread(8, race_setter, 0);

    LARGE_INTEGER timeout = rel_ms(5000);
    uint64_t start = KeTickCount;
    NTSTATUS status = KeWaitForSingleObject(&race_event, Executive, 0, FALSE, &timeout);
    uint64_t elapsed = KeTickCount - start;
    ok(status == STATUS_SUCCESS, "signalled timed wait: got %#x", (unsigned)status);
    ok(elapsed >= 19 && elapsed < 4000, "signalled at ~20 ms, wait took %lu ms",
       (unsigned long)elapsed);
    join_and_delete(setter);
}

/* --- KTIMER objects: one-shot, notification latch, periodic sync ---------- */

static void test_timers(void)
{
    KTIMER timer;
    KeInitializeTimer(&timer); /* notification timer */

    ok(KeCancelTimer(&timer) == FALSE, "cancel of idle timer returned TRUE");

    uint64_t start = KeTickCount;
    ok(KeSetTimer(&timer, rel_ms(40), 0) == FALSE, "set of idle timer returned TRUE");
    NTSTATUS status = KeWaitForSingleObject(&timer, Executive, 0, FALSE, 0);
    uint64_t elapsed = KeTickCount - start;
    ok(status == STATUS_SUCCESS, "timer wait: got %#x", (unsigned)status);
    ok(elapsed >= 39, "40 ms timer fired after %lu ms", (unsigned long)elapsed);

    /* Notification timer stays signalled after expiry. */
    status = KeWaitForSingleObject(&timer, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "expired notification timer re-wait: %#x", (unsigned)status);

    /* Re-setting a pending timer reports it was pending. */
    ok(KeSetTimer(&timer, rel_ms(5000), 0) == FALSE, "set of expired timer returned TRUE");
    ok(KeSetTimer(&timer, rel_ms(5000), 0) == TRUE, "re-set of pending timer returned FALSE");
    ok(KeCancelTimer(&timer) == TRUE, "cancel of pending timer returned FALSE");

    /* Periodic synchronization timer: each expiry satisfies one wait and
     * auto-resets, so three consecutive waits take ~3 periods. */
    KTIMER periodic;
    KeInitializeTimerEx(&periodic, SynchronizationTimer);
    start = KeTickCount;
    KeSetTimerEx(&periodic, rel_ms(20), 20, 0);
    for (int i = 0; i < 3; i++)
    {
        status = KeWaitForSingleObject(&periodic, Executive, 0, FALSE, 0);
        ok(status == STATUS_SUCCESS, "periodic wait %d: got %#x", i, (unsigned)status);
        ok(periodic.header.signalState == 0, "synchronization timer did not auto-reset");
    }
    elapsed = KeTickCount - start;
    ok(elapsed >= 55, "three 20 ms periods completed in %lu ms", (unsigned long)elapsed);
    ok(KeCancelTimer(&periodic) == TRUE, "periodic timer was not pending after expiries");
}

/* --- the query clock spans a late tick (docs/03 "Sub-tick system time") --- */

/* A loaded host delivers the LAPIC tick whole milliseconds late while the
 * TSC keeps counting. Holding the dispatcher lock IS that window, exactly:
 * interrupts off, no tick can land, real time passes. The query clock must
 * keep moving through it — monotonically, and past the one-tick mark a
 * one-tick interpolation clamp froze it at — and the catch-up tick that
 * lands on release must not step it back. This is the deterministic
 * conviction of the freeze kernel32:time's time.c:843 flaked on in CI
 * (every query in a late-tick window answered the same saturated value, and
 * the tick after it published the whole catch-up as one >= 1 ms step);
 * sem_ps/precise_time.c pins the same property at the boundary but cannot
 * hold the tick off. */
static void test_query_time_spans_late_ticks(void)
{
    if (KiTscPerMillisecond == 0)
    {
        ok(1, "no calibrated TSC; nothing to interpolate");
        return;
    }
    uint64_t flags = KiAcquireDispatcherLock();
    uint64_t tscStart = KiReadTimestampCounter();
    ULONGLONG start = KeQueryInterruptTime();
    ULONGLONG previous = start;
    int backwards = 0;
    /* Three tick periods with interrupts off: a real 3 ms late-tick window. */
    while (KiReadTimestampCounter() - tscStart < 3 * KiTscPerMillisecond)
    {
        ULONGLONG now = KeQueryInterruptTime();
        if (now < previous)
        {
            backwards++;
        }
        previous = now;
    }
    KiReleaseDispatcherLock(flags);
    ok(backwards == 0, "query clock stepped back %d times inside the window", backwards);
    ok(previous - start >= 2 * KI_100NS_PER_TICK,
       "query clock advanced only %llu (100 ns units) across a 3 ms tickless window",
       (unsigned long long)(previous - start));
    /* And no further than real time: the interpolation must ride the window,
     * not run ahead of it (the docs/03 divergence bound is 40 ms and the 3 ms
     * window must come nowhere near it — 10 ticks is generous slack for the
     * spin's own overshoot). */
    ok(previous - start < 10 * KI_100NS_PER_TICK,
       "query clock advanced %llu (100 ns units) across a 3 ms tickless window",
       (unsigned long long)(previous - start));
    /* The coalesced tick lands here with its catch-up (KiTicksElapsed);
     * continuity means it must not step the clock back. */
    sleep_ms(2);
    ULONGLONG after = KeQueryInterruptTime();
    ok(after >= previous, "catch-up tick stepped the clock back (%llu -> %llu)",
       (unsigned long long)previous, (unsigned long long)after);
}

/* --- priority scheduling: strict highest-first ----------------------------- */

static int prio_order[3];
static int prio_recorded;

static void prio_recorder(void *context)
{
    if (prio_recorded < 3)
    {
        prio_order[prio_recorded++] = (int)(uintptr_t)context;
    }
}

static void test_priority(void)
{
    prio_recorded = 0;

    /* Created ready but never run (no preemption) until this thread blocks;
     * then the scheduler must run high (12) before mid (9) before low (4),
     * regardless of creation order. */
    PKTHREAD low = KiCreateThread(4, prio_recorder, (void *)4);
    PKTHREAD high = KiCreateThread(12, prio_recorder, (void *)12);
    PKTHREAD mid = KiCreateThread(9, prio_recorder, (void *)9);

    sleep_ms(10);
    ok(prio_recorded == 3, "recorded %d of 3", prio_recorded);
    ok(prio_order[0] == 12 && prio_order[1] == 9 && prio_order[2] == 4,
       "priority order was %d,%d,%d, want 12,9,4", prio_order[0], prio_order[1], prio_order[2]);

    join_and_delete(low);
    join_and_delete(high);
    join_and_delete(mid);
}

/* --- thread objects are waitable ------------------------------------------ */

static void quick_worker(void *context)
{
    *(int *)context = 1;
}

static void test_thread_join(void)
{
    int ran = 0;
    PKTHREAD worker = KiCreateThread(8, quick_worker, &ran);
    NTSTATUS status = KeWaitForSingleObject(worker, Executive, 0, FALSE, 0);
    ok(status == STATUS_SUCCESS, "thread join: got %#x", (unsigned)status);
    ok(ran == 1, "joined thread had not run");

    /* Terminated threads stay signalled (notification semantics). */
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    status = KeWaitForSingleObject(worker, Executive, 0, FALSE, &zero);
    ok(status == STATUS_SUCCESS, "second join: got %#x", (unsigned)status);
    KiDeleteThread(worker);
}

/* --- the kernel-mode deadlock detector's walk ----------------------------- */

/* KiFindWaitCycle (kernel/init/verify.c) is what the consistency sweep runs
 * over every thread, treating a cycle as fatal — so it can never be
 * convicted by letting a real deadlock form: the sweep would panic the boot
 * before the test could report. Build the graph by hand instead. The walk
 * reads exactly four things — a thread's state, its timed/alertable flags,
 * its wait-block chain, and a mutant's ownerThread — so a hand-wired
 * snapshot exercises the same code the live sweep runs, with no thread ever
 * parked and nothing to unwind.
 *
 * The negative cases matter as much as the positive one: this walk runs on
 * every thread of every sweep, so a false positive would panic a healthy
 * boot. Each exclusion the detector makes (timed waits, alertable waits, a
 * WaitAny with alternatives) gets its own check. */
static void test_deadlock_walk(void)
{
    KTHREAD a, b;
    KMUTEX m1, m2;
    KWAIT_BLOCK block_a, block_b;

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    KeInitializeMutex(&m1, 0);
    KeInitializeMutex(&m2, 0);

    /* The textbook ABBA: A holds m1 and waits on m2; B holds m2 and waits
     * on m1. Neither can proceed and neither has a timeout. */
    a.state = KI_THREAD_STATE_WAITING;
    b.state = KI_THREAD_STATE_WAITING;
    m1.ownerThread = &a;
    m2.ownerThread = &b;
    memset(&block_a, 0, sizeof(block_a));
    block_a.thread = &a;
    block_a.object = &m2.header;
    block_a.waitType = WaitAny;
    a.waitBlockList = &block_a;
    memset(&block_b, 0, sizeof(block_b));
    block_b.thread = &b;
    block_b.object = &m1.header;
    block_b.waitType = WaitAny;
    b.waitBlockList = &block_b;

    ok(KiFindWaitCycle(&a) == 2, "the ABBA cycle was not found from A");
    ok(KiFindWaitCycle(&b) == 2, "the ABBA cycle was not found from B");

    /* A timed wait wakes on its own — not a deadlock. */
    a.timerArmed = TRUE;
    ok(KiFindWaitCycle(&a) == 0, "a timed waiter was called deadlocked");
    ok(KiFindWaitCycle(&b) == 0, "a cycle through a timed waiter was called a deadlock");
    a.timerArmed = FALSE;

    /* An alertable wait can be broken by an APC or an alert. */
    a.waitAlertable = TRUE;
    ok(KiFindWaitCycle(&a) == 0, "an alertable waiter was called deadlocked");
    a.waitAlertable = FALSE;
    ok(KiFindWaitCycle(&a) == 2, "the cycle did not come back after clearing the flags");

    /* A running thread is not waiting on anything. */
    b.state = KI_THREAD_STATE_RUNNING;
    ok(KiFindWaitCycle(&a) == 0, "a cycle through a RUNNING thread was called a deadlock");
    b.state = KI_THREAD_STATE_WAITING;

    /* A free mutant has no owner: the chain terminates. */
    m2.ownerThread = 0;
    ok(KiFindWaitCycle(&a) == 0, "a wait on an unowned mutant was called a deadlock");
    m2.ownerThread = &b;

    /* WaitAny over SEVERAL objects: either may release A, so no single edge
     * is necessary and nothing may be concluded. */
    KWAIT_BLOCK spare;
    KEVENT other;
    KeInitializeEvent(&other, NotificationEvent, FALSE);
    memset(&spare, 0, sizeof(spare));
    spare.thread = &a;
    spare.object = &other.header;
    spare.waitType = WaitAny;
    block_a.nextWaitBlock = &spare;
    ok(KiFindWaitCycle(&a) == 0, "a WaitAny with an alternative was called a deadlock");

    /* WaitAll over the same pair: now BOTH must be satisfied, so the edge
     * into the cycle is necessary again. */
    block_a.waitType = WaitAll;
    spare.waitType = WaitAll;
    ok(KiFindWaitCycle(&a) == 2, "a WaitAll into the cycle was not called a deadlock");
    block_a.nextWaitBlock = 0;

    /* A self-cycle is not a cycle: a mutant is recursive for its owner. */
    m2.ownerThread = &a;
    block_a.waitType = WaitAny;
    ok(KiFindWaitCycle(&a) == 0, "a thread waiting on its own mutant was called a deadlock");
}

int kmt_run_m2(void)
{
    kmt_failures = 0;
    KMT_RUN(test_thread_join);
    KMT_RUN(test_event_pingpong);
    KMT_RUN(test_notification_event);
    KMT_RUN(test_synchronization_event);
    KMT_RUN(test_wait_any);
    KMT_RUN(test_wait_all);
    KMT_RUN(test_mutex);
    KMT_RUN(test_mutex_abandonment);
    KMT_RUN(test_semaphore);
    KMT_RUN(test_timeouts);
    KMT_RUN(test_signal_beats_timeout);
    KMT_RUN(test_timers);
    KMT_RUN(test_query_time_spans_late_ticks);
    KMT_RUN(test_priority);
    KMT_RUN(test_deadlock_walk);
    return kmt_failures;
}
