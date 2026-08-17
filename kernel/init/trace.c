/* kernel/init/trace.c — see trace.h. One static ring, guarded by THE
 * dispatcher lock (Art. 3: no lock-free tricks, no second lock). */
#include "kernel/init/trace.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/syscall/syscall.h"

#include "arch/x86_64/lapic.h"

/* 256 slots: the ring now records syscall RETURNS as well as entries, so 64
 * covered only ~32 calls of lead-up — too short to show what preceded a
 * wedge. ~12 KiB of static data. */
#define KI_TRACE_RING_SIZE 256 /* power of two */

typedef struct
{
    uint64_t tick; /* KeTickCount at the event, ms since boot */
    uint64_t tsc;  /* KiReadTimestampCounter() at the event: a lazy-init race
                    * resolves in microseconds, so every relevant event lands
                    * on ONE tick and only the TSC can show the ordering */
    uint32_t type; /* KI_TRACE_TYPE */
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
} KI_TRACE_EVENT;

static KI_TRACE_EVENT KiTraceRing[KI_TRACE_RING_SIZE];
static uint32_t KiTraceNext; /* next slot to write; monotonically grows */

void KiTraceEvent(KI_TRACE_TYPE type, uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    uint64_t flags = KiAcquireDispatcherLock();
    KI_TRACE_EVENT *slot = &KiTraceRing[KiTraceNext % KI_TRACE_RING_SIZE];
    slot->tick = KeTickCount;
    slot->tsc = KiReadTimestampCounter();
    slot->type = (uint32_t)type;
    slot->arg0 = arg0;
    slot->arg1 = arg1;
    slot->arg2 = arg2;
    KiTraceNext++;
    KiReleaseDispatcherLock(flags);
}

void KiDumpTraceRing(void)
{
    DbgPrint("[TRACE] recent events (oldest first):\n");
    for (uint32_t index = 0; index < KI_TRACE_RING_SIZE; index++)
    {
        /* KiTraceNext % SIZE is the oldest slot once the ring has wrapped;
         * before that the tail slots are still KiTraceNone and are skipped. */
        const KI_TRACE_EVENT *event = &KiTraceRing[(KiTraceNext + index) % KI_TRACE_RING_SIZE];
        if (event->type == KiTraceNone)
        {
            continue;
        }
        /* tsc beside tick: consecutive events routinely share a tick, and
         * the ordering question this ring answers (which of two lazy inits
         * ran first) lives in the microseconds the tick cannot show. */
        DbgPrint("[TRACE]   tick=%lu tsc=%lu ", event->tick, event->tsc);
        switch (event->type)
        {
        case KiTraceSyscall:
            DbgPrint("syscall num=%#lx (%s) a0=%#lx a1=%#lx\n", event->arg0,
                     KiSystemCallName(event->arg0), event->arg1, event->arg2);
            break;
        case KiTraceSyscallRet:
            DbgPrint("sysret num=%#lx (%s) status=%#x thread=%#lx\n", event->arg0,
                     KiSystemCallName(event->arg0), (unsigned)event->arg1, event->arg2);
            break;
        case KiTraceSwap:
            DbgPrint("swap old=%#lx new=%#lx\n", event->arg0, event->arg1);
            break;
        case KiTraceThreadCreate:
            DbgPrint("thread-create thread=%#lx start=%#lx process=%#lx\n", event->arg0,
                     event->arg1, event->arg2);
            break;
        case KiTraceThreadExit:
            DbgPrint("thread-exit thread=%#lx\n", event->arg0);
            break;
        case KiTraceUserFault:
            /* %#018lx: user addresses keep the dump's fixed width so the
             * display-time symbolizer (tools/symbolize.py) recognizes them. */
            DbgPrint("userfault vector=%lu rip=%#018lx cr2=%#018lx\n", event->arg0, event->arg1,
                     event->arg2);
            break;
        case KiTraceProcessExit:
            DbgPrint("process-exit process=%#lx status=%#x\n", event->arg0, (unsigned)event->arg1);
            break;
        default:
            DbgPrint("type=%u a0=%#lx a1=%#lx a2=%#lx\n", event->type, event->arg0, event->arg1,
                     event->arg2);
            break;
        }
    }
}
