/*
 * sem_mm/stack_growth.c — guard-page stack growth (M5, docs/02): a thread's
 * stack region grows automatically as deeper frames are touched; the process
 * survives recursion well past the initially committed stack, and
 * NT_TIB.StackLimit always bounds the deepest touched frame from below.
 *
 * The observable contract is deliberately the portable core: Wine commits its
 * stacks up front (its StackLimit never moves during ordinary recursion),
 * real Windows and proskrnl grow the stack a guard page at a time — so the
 * test pins survival and the StackBase/StackLimit bracketing, not the growth
 * mechanism itself. Green on the oracle first (Art. 5); on proskrnl this is
 * exactly the "guard-page stack growth" milestone artifact — without growth
 * the recursion faults and the run dies.
 */
#include "util.h"

#if defined(NTAPI_ORACLE)
#include <windows.h> /* NT_TIB, NtCurrentTeb */
#elif defined(NTAPI_PROSKRNL)
#include "abi/ntpsapi.h" /* NT_TIB (generated; offsets pinned by asserts) */
#endif

/* volatile: on a growing kernel (proskrnl, Windows) StackLimit is rewritten
 * behind this code's back; without it the compiler may fold the loads. */
static volatile NT_TIB *get_tib(void)
{
#if defined(NTAPI_ORACLE)
    return (volatile NT_TIB *)NtCurrentTeb();
#else
    /* The TEB begins with the NT_TIB and gs points at it in user mode;
     * NT_TIB.Self (gs:0x30) is the TEB's linear address. */
    void *self;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(self));
    return (volatile NT_TIB *)self;
#endif
}

/* Each frame occupies ~half a page and touches its buffer TOP-DOWN, the
 * direction stacks grow, so every page between two frames is touched in
 * order (the guard page is never skipped over — the same discipline a
 * compiler's stack probes enforce for large frames). */
#define FRAME_BYTES 2048
#define DEPTH       192 /* ~384 KiB of stack, far past any initial commit */

__attribute__((noinline)) static char *recurse(int depth, char *deepest)
{
    volatile char buffer[FRAME_BYTES];
    int i;

    for (i = FRAME_BYTES - 64; i >= 0; i -= 64)
        buffer[i] = (char)depth;
    if ((char *)buffer < deepest)
        deepest = (char *)buffer;
    if (depth > 0)
        deepest = recurse(depth - 1, deepest);
    /* Read a value back after the descent so the frames cannot be elided. */
    if (buffer[0] != (char)depth)
        return NULL;
    return deepest;
}

START_TEST(stack_growth)
{
    volatile NT_TIB *tib = get_tib();
    char *limit_before, *limit_after, *deepest;
    char probe;

    ok(tib != NULL, "no TIB");
    limit_before = (char *)tib->StackLimit;
    ok(tib->StackBase != NULL && limit_before != NULL, "TIB stack fields unset");
    ok(limit_before < (char *)&probe && (char *)&probe < (char *)tib->StackBase,
       "local %p outside stack [%p, %p)", (void *)&probe, (void *)limit_before, tib->StackBase);

    /* Survival IS the contract: on proskrnl the recursion runs far past the
     * initially committed stack, so without guard-page growth it dies as an
     * access violation and the whole test FAILs. (How far the initial commit
     * reaches is not asserted — Wine commits its stacks up front.) */
    deepest = recurse(DEPTH, (char *)&probe);
    ok(deepest != NULL, "recursion corrupted a frame");

    /* The stack grew to cover the deepest frame: StackLimit still bounds it
     * (on growers it moved down; on Wine's fully-committed stacks it already
     * did), and it never rises. */
    limit_after = (char *)tib->StackLimit;
    ok(limit_after <= deepest, "StackLimit %p above deepest touched frame %p", (void *)limit_after,
       (void *)deepest);
    ok(limit_after <= limit_before, "StackLimit rose from %p to %p", (void *)limit_before,
       (void *)limit_after);
}
