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

#include "abi/ntdef.h" /* ULONG */

/* Completed sweeps since boot; every one either passed or panicked. */
extern uint64_t KiSweepCount;

/* Set by process teardown (kernel/ps/process.c PspDeleteProcess): the next
 * idle iteration sweeps immediately instead of waiting out the throttle, so
 * every exited process — each smss-run test — still gets a prompt audit. */
extern BOOLEAN KiSweepRequested;

/* Run one full sweep (takes the dispatcher lock). Callable from any thread
 * context at a blocking-point boundary — never from interrupt context. A
 * violated invariant is fatal through the ASSERT path. */
void KiVerifyKernelState(void);

/* The idle-loop cadence: run a sweep at most once per interval. Called by
 * KiIdleLoop with interrupts already disabled. */
void KiVerifyKernelStateIdle(void);

/* The kernel-mode deadlock detector's walk (GUI-5): how many threads are in
 * the wait-for cycle `start` sits on, or 0 when its chain terminates. The
 * sweep runs it over every thread and treats a nonzero answer as fatal;
 * exposed so tests/kmt can convict the walk on a cycle built by hand. */
struct KTHREAD;
ULONG KiFindWaitCycle(struct KTHREAD *start);

#endif /* PROSKRNL_KERNEL_INIT_VERIFY_H */
