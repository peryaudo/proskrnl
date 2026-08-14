/* kernel/syscall/syscall.h — the syscall boundary (M4, docs/05 "shape only"):
 * a plain function table (SSDT-equivalent) behind a syscall/sysret stub.
 * Numbers and the stub<->table agreement are generated (tools/gen_syscalls.py).
 *
 * As of M7 the table is indexed by the pinned Wine tree's own 64-bit syscall
 * ids (so the unmodified PE ntdll's thunks land on the right service), and the
 * entry crossing hands the C dispatcher a full KTRAP_FRAME (see entry.S) so
 * the user-mode return protocol (NtContinue / KiUserExceptionDispatcher) can
 * rewrite the outgoing register context. */
#ifndef PROSKRNL_KERNEL_SYSCALL_SYSCALL_H
#define PROSKRNL_KERNEL_SYSCALL_SYSCALL_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "arch/x86_64/trap.h"

/* The C half of the entry stub (entry.S): dispatch the syscall described by
 * `trapFrame` (number in rax; arguments 1-4 in r10/rdx/r8/r9; arguments 5+ on
 * the user stack at frame->rsp + 0x28). The NTSTATUS is written back into
 * frame->rax so the iretq return delivers it in eax. */
void KiSystemServiceTrap(PKTRAP_FRAME trapFrame);

/* Service name for a syscall id ("?" if unknown / unimplemented) — the panic
 * dump prints it next to the raw last-syscall number (Art. 9). */
const char *KiSystemCallName(uint64_t number);

/* Art. 12 dialed to fatal: TRUE when the boot armed it —
 * \Registry\Machine\Hardware\qemu "PanicOnNotImplemented", which every boot
 * that finds a fw_cfg device arms by default (kernel/cm/registry.c
 * CmpQemuBootFlags; read at boot by kernel/init/main.c
 * KiConfigurePanicOnNotImplemented). So booting under QEMU arms it, however
 * that QEMU was launched; tools/qemu.sh PANIC_NOTIMPL=0 disarms it, and no
 * fw_cfg device at all means off. While armed, a ring-3 syscall that answers STATUS_NOT_IMPLEMENTED
 * — a KI_SYSCALL_MISSING id or a partial service's unbuilt case — panics instead of returning, so a
 * run convicts the exact first unbuilt service it needed rather than limping past it. No refusal is
 * exempt: the status means "unbuilt", and the oracle answering it too makes the oracle unbuilt as
 * well — never a contract worth reproducing (Art. 12). */
extern BOOLEAN KiPanicOnNotImplemented;

/* entry.S: first descent into ring 3 (kernel/ps). KERNEL_GS_BASE must already
 * carry the thread's TEB; the kernel stack is abandoned. arg1/arg2 seed the
 * user rcx/rdx (a native client's entry argument; the M7 Wine path passes
 * &CONTEXT to LdrInitializeThunk). */
__attribute__((noreturn)) void KiEnterUserMode(uint64_t rip, uint64_t rsp, uint64_t arg1,
                                               uint64_t arg2);

/* entry.S: the shared ring-3 return path (restore every GP register from the
 * current KTRAP_FRAME and iretq). The exception/APC dispatch code returns
 * into this after re-pointing the frame at a user dispatcher. */
__attribute__((noreturn)) void KiReturnToUser(void);

#endif /* PROSKRNL_KERNEL_SYSCALL_SYSCALL_H */
