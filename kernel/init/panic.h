/* kernel/init/panic.h — fatal-error path + last-syscall slot (M1, Art. 9).
 *
 * NB: this is KiPanic, not KeBugCheck. Real NT KeBugCheck is KeBugCheck(ULONG
 * BugCheckCode) (see third_party/wine/.../ntoskrnl.c) — a different signature —
 * so we do not reuse that name for a string message (docs/15). */
#ifndef PROSKRNL_KERNEL_INIT_PANIC_H
#define PROSKRNL_KERNEL_INIT_PANIC_H

#include <stdint.h>

/* Last syscall number seen at the boundary; shown in the fatal dump. The
 * syscall entry path (M4) updates it. -1 until then. */
extern uint64_t KiLastSystemCall;

/* Nonzero once a fatal dump has started (the recursion latch). KASAN checks
 * it to stay quiet mid-dump — the dump's best-effort reads (an overflowed
 * stack's RBP chain) may legitimately cross poisoned pool bytes. */
extern int KiPanicInProgress;

/* Nonzero on a boot whose human reads the SCREEN, not serial (the
 * interactive desktop boot: kernel/init/main.c KiConfigurePanicOnScreen).
 * A fatal dump there takes the framebuffer back from the GUI and draws itself
 * on the boot console, ends with a recap of its headline (the thread dump
 * scrolls the top of it off the screen), and the machine then stops in a
 * halt loop instead of exiting QEMU — an exit would close the window the dump
 * was drawn in. Serial carries every line either way. Zero (the default, and
 * every scripted boot) keeps the isa-debug-exit stop the harness waits on. */
extern int KiPanicOnScreen;

__attribute__((noreturn)) void KiPanic(const char *message);
__attribute__((noreturn)) void KiAssertFail(const char *expression, const char *file, int line);

/* ASSERT — a checked kernel invariant; failure is fatal (invariant asserts are
 * the highest-value verification tool, docs/08). Always compiled in: there is
 * no free build, and under Art. 9 the resulting dump is the debugger. The
 * failure line carries the machine-greppable [ASSERT] file:line prefix.
 * (NT's checked-build ASSERT shape; ours never continues.) */
#define ASSERT(exp)                                                                                \
    do                                                                                             \
    {                                                                                              \
        if (!(exp))                                                                                \
        {                                                                                          \
            KiAssertFail(#exp, __FILE__, __LINE__);                                                \
        }                                                                                          \
    } while (0)

#endif /* PROSKRNL_KERNEL_INIT_PANIC_H */
