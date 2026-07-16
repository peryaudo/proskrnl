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

__attribute__((noreturn)) void KiPanic(const char *message);

#endif /* PROSKRNL_KERNEL_INIT_PANIC_H */
