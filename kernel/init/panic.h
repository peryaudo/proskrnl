/* kernel/init/panic.h — panic + last-syscall slot (M1, Constitution Art. 9). */
#ifndef PROSKRNL_KERNEL_INIT_PANIC_H
#define PROSKRNL_KERNEL_INIT_PANIC_H

#include <stdint.h>

/* Last syscall number seen at the boundary; shown in the panic dump. The
 * syscall entry path (M4) updates it. -1 until then. */
extern uint64_t g_last_syscall;

__attribute__((noreturn)) void panic(const char *msg);

#endif /* PROSKRNL_KERNEL_INIT_PANIC_H */
