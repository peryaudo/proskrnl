/* kernel/syscall/uaccess.h — user-pointer validation (M4, docs/05).
 *
 * The observable contract is that a bad user pointer surfaces as
 * STATUS_ACCESS_VIOLATION, never as a kernel fault. Under Art. 3 the probe
 * CAN be a page-table walk instead of a fault-trapping copy: commit maps
 * pages immediately (no demand paging, no COW), so present <=> accessible at
 * the moment of the walk.
 *
 * That "at the moment of the walk" is the whole caveat, and since M7 brought
 * multi-threaded processes it is a live one: a service that probes, blocks
 * (npfs, condrv), and then copies is relying on a stale validation, because a
 * sibling thread can unmap the buffer while it is parked. The probe alone can
 * no longer carry the contract, so it does not have to — the recovery frame
 * declared at the bottom of this header catches exactly that case and turns
 * it into the same STATUS_ACCESS_VIOLATION the probe would have returned.
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

/* --- the ring-0 fault recovery frame (kernel/syscall/recover.S) ----------
 *
 * The probes above are the FIRST line: they turn a bad user pointer into
 * STATUS_ACCESS_VIOLATION at the call site. This is the second — the one
 * that holds when a probe is missing, or was invalidated after the fact by a
 * sibling thread unmapping the buffer while the service blocked. The system
 * service dispatcher arms a frame around every ring-3-originated service;
 * KiDispatchTrap unwinds to it when a ring-0 fault lands on a user address,
 * and the service returns STATUS_ACCESS_VIOLATION.
 *
 * This mirrors NT: KiSystemServiceHandler makes the dispatcher the outermost
 * exception frame of every service, and a user-address access violation
 * inside a service becomes that service's return status. As there, a service
 * unwound this way does not run its own cleanup — an unwind is a bug report,
 * not a supported exit — so it is a backstop for the probes, never a
 * substitute for them.
 *
 * Layout is welded into recover.S: rip, rsp, the SysV callee-saved set,
 * then rflags — captured at arm time and restored by the unwind. The trap
 * that starts an unwind entered through an interrupt gate (IF clear), and a
 * jump-based unwind never executes an iretq, so without the explicit
 * restore the unwound thread would keep running with interrupts masked —
 * survivable for a ring-3 service (sysret reloads user RFLAGS) but
 * permanent for a kernel-mode caller, whose masked clock the CUI-8 drain
 * points then starve (found by tests/kmt/cui8_async.c's poll loop; pinned
 * by the IF assertion in tests/kmt/m4_usermode.c). */
typedef struct
{
    uint64_t rip;
    uint64_t rsp;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
} KI_FAULT_RECOVERY, *PKI_FAULT_RECOVERY;

/* 0 on the direct call; the (nonzero) status on an unwind. */
ULONG KiSetFaultRecovery(PKI_FAULT_RECOVERY frame);
__attribute__((noreturn)) void KiJumpFaultRecovery(PKI_FAULT_RECOVERY frame, ULONG value);

/* Called from KiDispatchTrap for a ring-0 fault. Unwinds to the current
 * thread's armed recovery frame and never returns, IF one is armed and the
 * faulting address is a user address. Returns (so the caller panics) for a
 * genuine kernel-address fault, which is a kernel bug and must stay loud. */
void KiRecoverFromKernelFault(uint64_t faultAddress, uint64_t vector);

#endif /* PROSKRNL_KERNEL_SYSCALL_UACCESS_H */
