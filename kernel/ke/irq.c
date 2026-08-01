/* kernel/ke/irq.c — interrupt dispatch (M2).
 *
 * No IRQL, no DPCs (docs/03): a plain top half. The trap path (panic.c) sends
 * every vector >= 32 here; the clock tick advances time and readies threads
 * but never context-switches — under Art. 3 switches happen only at explicit
 * waits and yields, so returning from the interrupt resumes the interrupted
 * thread unconditionally.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/lapic.h"

void KiDispatchInterrupt(uint64_t vector, BOOLEAN interruptedUser)
{
    if (vector == TIMER_VECTOR)
    {
        KiUpdateClock(interruptedUser);
        KiEndOfInterrupt();
        return;
    }
    KiPanic("KiDispatchInterrupt: unexpected interrupt vector");
}
