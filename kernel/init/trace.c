/* kernel/init/trace.c — see trace.h. One static ring, guarded by THE
 * dispatcher lock (Art. 3: no lock-free tricks, no second lock). */
#include "kernel/init/trace.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/syscall/syscall.h"

#define KI_TRACE_RING_SIZE 64 /* power of two; ~2.5 KiB of static data */

typedef struct
{
    uint64_t tick; /* KeTickCount at the event, ms since boot */
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
        switch (event->type)
        {
        case KiTraceNone:
            break;
        case KiTraceSyscall:
            DbgPrint("[TRACE]   tick=%lu syscall num=%#lx (%s) a0=%#lx a1=%#lx\n", event->tick,
                     event->arg0, KiSystemCallName(event->arg0), event->arg1, event->arg2);
            break;
        case KiTraceSwap:
            DbgPrint("[TRACE]   tick=%lu swap old=%#lx new=%#lx\n", event->tick, event->arg0,
                     event->arg1);
            break;
        case KiTraceThreadCreate:
            DbgPrint("[TRACE]   tick=%lu thread-create thread=%#lx start=%#lx process=%#lx\n",
                     event->tick, event->arg0, event->arg1, event->arg2);
            break;
        case KiTraceThreadExit:
            DbgPrint("[TRACE]   tick=%lu thread-exit thread=%#lx\n", event->tick, event->arg0);
            break;
        case KiTraceUserFault:
            /* %#018lx: user addresses keep the dump's fixed width so the
             * display-time symbolizer (tools/symbolize.py) recognizes them. */
            DbgPrint("[TRACE]   tick=%lu userfault vector=%lu rip=%#018lx cr2=%#018lx\n",
                     event->tick, event->arg0, event->arg1, event->arg2);
            break;
        case KiTraceProcessExit:
            DbgPrint("[TRACE]   tick=%lu process-exit process=%#lx status=%#x\n", event->tick,
                     event->arg0, (unsigned)event->arg1);
            break;
        default:
            DbgPrint("[TRACE]   tick=%lu type=%u a0=%#lx a1=%#lx a2=%#lx\n", event->tick,
                     event->type, event->arg0, event->arg1, event->arg2);
            break;
        }
    }
}
