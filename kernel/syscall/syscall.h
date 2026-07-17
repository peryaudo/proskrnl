/* kernel/syscall/syscall.h — the syscall boundary (M4, docs/05 "shape only"):
 * a plain function table (SSDT-equivalent) behind a syscall/sysret stub.
 * Numbers and the stub<->table agreement are generated (tools/gen_syscalls.py). */
#ifndef PROSKRNL_KERNEL_SYSCALL_SYSCALL_H
#define PROSKRNL_KERNEL_SYSCALL_SYSCALL_H

#include <stdint.h>

/* The C half of the entry stub (entry.S): dispatch syscall `number` with the
 * six register arguments in `args` (a seventh comes from the user stack at
 * userRsp + 8). Returns the NTSTATUS, sign-extended for the stub. */
int64_t KiSystemService(uint64_t number, const uint64_t *args, uint64_t userRsp);

/* entry.S: first descent into ring 3 (kernel/ps). KERNEL_GS_BASE must
 * already carry the thread's TEB; the kernel stack is abandoned. */
__attribute__((noreturn)) void KiEnterUserMode(uint64_t rip, uint64_t rsp);

#endif /* PROSKRNL_KERNEL_SYSCALL_SYSCALL_H */
