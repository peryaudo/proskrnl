/* kernel/ke/mutex.c — kernel mutexes (KMUTANT) (M2).
 *
 * NT mutex semantics: signalState 1 = free, 0 = held, negative = recursively
 * held by the owner. Acquisition happens in wait satisfaction (wait.c), which
 * also handles owner recursion and abandonment reporting. Signatures per
 * Wine's ntoskrnl exports.
 */
#include "kernel/ke/ke.h"

void KeInitializeMutex(PRKMUTEX mutex, ULONG level)
{
    /* `level` ordered the retired mutex-levels deadlock checker; NT ignores
     * it and so do we. */
    KiInitializeDispatcherHeader(&mutex->header, KI_OBJECT_MUTANT, 1);
    mutex->ownerThread = 0;
    mutex->abandoned = FALSE;
    mutex->apcDisable = 1; /* KeInitializeMutex-created mutexes are APC-safe */
}

LONG KeReleaseMutex(PRKMUTEX mutex, BOOLEAN wait)
{
    uint64_t flags = KiAcquireDispatcherLock();
    LONG previous = KiReleaseMutant(mutex, FALSE);
    KiReleaseDispatcherLock(flags);
    return previous;
}
