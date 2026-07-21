/* kernel/init/verify.h — the kernel-state consistency sweep (Art. 9 tooling).
 *
 * "fsck for the executive": one function that walks every process, thread,
 * handle table, object, wait list, ready queue and namespace entry and
 * asserts the cross-department invariants no path-local ASSERT can see.
 * Verification infrastructure like ASSERT/KASAN/the trace ring (docs/08) —
 * not an NT entity, not observable at the boundary. */
#ifndef PROSKRNL_KERNEL_INIT_VERIFY_H
#define PROSKRNL_KERNEL_INIT_VERIFY_H

#include <stdint.h>

/* Completed sweeps since boot; every one either passed or panicked. */
extern uint64_t KiSweepCount;

/* Run one full sweep (takes the dispatcher lock). Callable from any thread
 * context at a blocking-point boundary — never from interrupt context. A
 * violated invariant is fatal through the ASSERT path. */
void KiVerifyKernelState(void);

/* The idle-loop cadence: run a sweep at most once per interval. Called by
 * KiIdleLoop with interrupts already disabled. */
void KiVerifyKernelStateIdle(void);

#endif /* PROSKRNL_KERNEL_INIT_VERIFY_H */
