/* kernel/ke/irq.c — interrupt dispatch (M2).
 *
 * No IRQL, no DPCs (docs/03): a plain top half. The trap path (panic.c) sends
 * every vector >= 32 here; both device-facing vectors — the clock tick and
 * the blk completion MSI (docs/19 §11b) — advance state and ready threads
 * but never context-switch — under Art. 3 switches happen only at explicit
 * waits and yields, so returning from the interrupt resumes the interrupted
 * thread unconditionally.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/lapic.h"

/* Delivery counter for the blk completion vector (docs/19 §11e: the win is
 * a verdict, not an inference — tests/kmt/cui8_async.c asserts it moved).
 * Honest zero until the ISR arm lands: no deliveries exist. */
uint64_t KiBlkInterruptCount;

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
    if (vector == BLK_VECTOR)
    {
        /* The blk completion ISR (docs/19 §11b): the existing drain, at a
         * new entry — harvest, store, wake, nothing else (docs/20 R2). No
         * lock acquire: the dispatcher lock IS interrupt-disable (docs/18
         * §6d), so this ISR holds it by arriving and every lock hold
         * excludes it by construction — the explicit uniprocessor
         * interrupt-versus-lock policy, asserted by the no-block bracket. */
        KiBlkInterruptCount++;
        IoDrainDeviceCompletions();
        KiEndOfInterrupt();
        KiLeaveNoBlockRegion();
        return;
    }
    KiPanic("KiDispatchInterrupt: unexpected interrupt vector");
}
