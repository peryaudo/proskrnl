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
    /* Interrupt context is the archetypal non-blocking region (issue #96 A;
     * docs/20 §1 F2 calls it "a third execution context"): it interrupted an
     * arbitrary thread mid-anything, so a park here would resume that thread
     * only via a wake nobody will perform. The header's "never
     * context-switches" claim is now checked rather than stated. Returning to
     * ring 3 DOES switch (KiPreemptAtUserReturn), but that runs after this
     * returns, outside the region. */
    KiEnterNoBlockRegion("interrupt dispatch");
    if (vector == TIMER_VECTOR)
    {
        KiUpdateClock(interruptedUser);
        KiEndOfInterrupt();
        KiLeaveNoBlockRegion();
        return;
    }
    KiPanic("KiDispatchInterrupt: unexpected interrupt vector");
}
