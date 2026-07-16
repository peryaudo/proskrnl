/* kernel/ke/sema.c — counting semaphores (M2).
 *
 * signalState IS the count; a satisfied wait decrements it (wait.c). NT
 * raises STATUS_SEMAPHORE_LIMIT_EXCEEDED on over-release; kernel callers are
 * in-tree, so ours panics — same contract, louder. Signatures per Wine's
 * ntoskrnl exports.
 */
#include "kernel/ke/ke.h"
#include "kernel/init/panic.h"

void KeInitializeSemaphore(PRKSEMAPHORE semaphore, LONG count, LONG limit)
{
    if (count < 0 || limit < 1 || count > limit)
    {
        KiPanic("KeInitializeSemaphore: invalid count/limit");
    }
    KiInitializeDispatcherHeader(&semaphore->header, KI_OBJECT_SEMAPHORE, count);
    semaphore->limit = limit;
}

LONG KeReleaseSemaphore(PRKSEMAPHORE semaphore, KPRIORITY increment, LONG count, BOOLEAN wait)
{
    uint64_t flags = KiAcquireDispatcherLock();
    LONG previous = semaphore->header.signalState;
    if (count < 1 || previous + count > semaphore->limit || previous + count < previous)
    {
        KiPanic("KeReleaseSemaphore: limit exceeded (STATUS_SEMAPHORE_LIMIT_EXCEEDED)");
    }
    semaphore->header.signalState = previous + count;
    KiWaitTest(&semaphore->header);
    KiReleaseDispatcherLock(flags);
    return previous;
}
