/* kernel/syscall/uaccess.h — user-pointer validation (M4, docs/05).
 *
 * The observable contract is that a bad user pointer surfaces as
 * STATUS_ACCESS_VIOLATION, never as a kernel fault. Under Art. 3 the probe
 * CAN be a page-table walk instead of a fault-trapping copy: commit maps
 * pages immediately (no demand paging, no COW) and the kernel never blocks
 * between a probe and the access it guards, so present <=> accessible and
 * nothing can change in between. (A second user thread unmapping memory
 * mid-syscall would reopen this — revisit when M7 brings multi-threaded
 * processes.)
 *
 * The probes are previous-mode aware: for a KernelMode caller (kmt tests,
 * in-kernel Nt* use) they are no-ops, exactly like NT's ProbeFor* under
 * KernelMode.
 */
#ifndef PROSKRNL_KERNEL_SYSCALL_UACCESS_H
#define PROSKRNL_KERNEL_SYSCALL_UACCESS_H

#include <stdint.h>

#include "abi/ntdef.h"

/* Highest user address + 1 (Wine's x86_64 user_space_limit shape: the
 * canonical low half minus the 64 KiB no-man's-land under the kernel).
 * Cross-check: third_party/wine dlls/ntdll/unix/virtual.c,
 * `user_space_limit = (void *)0x7fffffff0000`. */
#define KI_USER_SPACE_LIMIT 0x00007FFFFFFF0000ULL

/* ExGetPreviousMode — real NT export (wine/include/ddk/wdm.h): the mode the
 * current thread entered the kernel from. */
KPROCESSOR_MODE ExGetPreviousMode(void);

/* Does [base, base+size) lie wholly below KI_USER_SPACE_LIMIT? Bounds only —
 * no page walk — and, unlike the probes below, INDEPENDENT of the previous
 * mode. This is the one authority for the question (Art. 11): the probes
 * layer page presence on top of it, and the ring-3 frame writers in
 * kernel/ps/usermode.c call it directly.
 *
 * They must, because a probe cannot serve them: the exception and user-APC
 * dispatch paths run with previousMode == KernelMode (the syscall path
 * restores it before delivering an APC, and a trap never sets it), so
 * KiProbeForWrite short-circuits to success there — while the address they
 * are about to write is computed from a ring-3-controlled RSP. A page walk
 * would not catch it either: MiCreateUserPml4 shares the upper 256 PML4
 * slots with the kernel, so a kernel address reads back present-and-writable
 * in a user address space. A zero-length range is vacuously in bounds. */
BOOLEAN KiIsUserRange(uint64_t base, uint64_t size);

/* Validate a user range for the current process: bounds, alignment, and
 * page presence (write probes also require the write bit). Returns
 * STATUS_SUCCESS, STATUS_ACCESS_VIOLATION, or (misaligned, as NT's
 * ProbeFor* raise) STATUS_DATATYPE_MISALIGNMENT; no-op success for
 * KernelMode callers. The alignment check also keeps user-controlled
 * pointers from tripping the kernel's UBSan alignment traps. */
NTSTATUS KiProbeForRead(const void *address, uint64_t length, uint64_t alignment);
NTSTATUS KiProbeForWrite(void *address, uint64_t length, uint64_t alignment);

/* Probe-then-copy against the current process (an 8-byte fetch for stack
 * syscall arguments, structure captures). KernelMode callers just copy. */
NTSTATUS KiCopyFromUser(void *destination, const void *userSource, uint64_t length);

#endif /* PROSKRNL_KERNEL_SYSCALL_UACCESS_H */
