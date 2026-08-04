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

/* --- probe tokens (issue #96 C) -------------------------------------------
 *
 * Every stale-probe defect the CUI-8 sweeps convicted — the create path, the
 * scatter/gather segment array, the query-direction fills, PspMakeProcessSystem
 * — is one bug wearing four hats: A PROBE RESULT USED ACROSS A PARK. The rule
 * was stated in prose in docs/20 R3 and §9, applied by hand, and missed by
 * hand each time, because nothing in a `memcpy(userBuffer, ...)` says which
 * probe is supposed to be backing it.
 *
 * A token says so. The probe mints one stamped with the thread's park
 * generation; the copy takes the token and asserts the stamp still matches.
 * "Probed, then blocked, then copied" is then a fatal assert AT THE COPY SITE
 * on any execution that reaches it, with no reviewer in the loop — and the
 * token in the signature documents the rule to the next writer, which is the
 * half review kept failing at.
 *
 * The generation advances in KiSwapToNext, the kernel's single context-switch
 * site, and only when a switch really happens: a wait satisfied without
 * yielding the CPU gave no sibling a chance to unmap anything, and must not
 * cost a re-probe.
 *
 * A token is a stack value with the lifetime of the copy it guards. It is not
 * a capability and it is not stored: nothing outlives the frame that probed. */
typedef struct
{
    void *base;
    uint64_t length;
    uint64_t generation;
} KI_PROBE_TOKEN, *PKI_PROBE_TOKEN;

/* The probes, minting a token. Same statuses as the untokened forms; the
 * token is only meaningful on STATUS_SUCCESS. */
NTSTATUS KiProbeForReadToken(const void *address, uint64_t length, uint64_t alignment,
                             PKI_PROBE_TOKEN token);
NTSTATUS KiProbeForWriteToken(void *address, uint64_t length, uint64_t alignment,
                              PKI_PROBE_TOKEN token);

/* A token over memory that cannot go stale because it is not the caller's:
 * kernel buffers, and the page-cache paths' internal fills. Named rather than
 * implicit so `git grep KiKernelToken` enumerates every copy that opted out. */
KI_PROBE_TOKEN KiKernelToken(void *base, uint64_t length);

/* Assert the token still backs [address, address+length): same generation (no
 * park since the probe) and inside the probed range. Fatal — a stale token is
 * a latent ring-0 fault on a user address, i.e. a leak or a wedge, and Art. 12
 * says an unbuilt guarantee refuses loudly rather than proceeding. */
void KiAssertProbeToken(const KI_PROBE_TOKEN *token, const void *address, uint64_t length);

/* The guarded copies. Direction is named from the KERNEL's point of view, as
 * everywhere else: KiWriteUser fills the caller's buffer, KiReadUser consumes
 * it. Both assert the token first, then copy. */
void KiWriteUser(const KI_PROBE_TOKEN *token, void *destination, const void *source,
                 uint64_t length);
void KiReadUser(const KI_PROBE_TOKEN *token, void *destination, const void *source,
                uint64_t length);

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

/* Arm/disarm the calling thread's frame. Call AFTER KiSetFaultRecovery has
 * returned 0 — the capture must be live before the frame is reachable.
 * `name` names the blamed service (the dispatcher passes the descriptor's);
 * `expected` is TRUE only where an unwind is the thing under test, which is
 * what tells the [UACCESS] accounting below that this one is not a defect.
 * One authority for the arming (Art. 11): nothing else writes the KTHREAD
 * fields, so `git grep KiArmFaultRecovery` is the complete list of arming
 * sites and of who claims an unwind is expected.
 *
 * `name` is BORROWED and must outlive the frame — every caller passes a
 * string literal or the service table's own static name, and an unwind reads
 * it after every non-callee-saved local is already indeterminate. */
void KiArmFaultRecovery(PKI_FAULT_RECOVERY frame, const char *name, BOOLEAN expected);
void KiDisarmFaultRecovery(void);

/* --- the unwind ledger (issue #32 A3) -------------------------------------
 *
 * COUNTING the unwinds, not just surviving them. The recovery frame above is
 * correct and load-bearing, and it also destroyed the signal for the class it
 * backstops: before it existed, a missing probe was a [PANIC] with a stack
 * trace — impossible to miss. After it, the same missing probe is a silent
 * STATUS_ACCESS_VIOLATION that reads exactly like a caller passing a bad
 * pointer, i.e. like ordinary operation. A backstop that is also camouflage
 * costs more than it saves.
 *
 * So every unwind names itself on serial:
 *
 *     [UACCESS] <name> va=<addr> rip=<addr> count=<n>
 *     [UACCESS] expected <name> va=<addr> rip=<addr> count=<n>
 *
 * and tests/run/uacheck.sh fails any leg carrying an untagged line (wired
 * into `make test` and into every tests/run/run.sh leg). The rip is what
 * names the missing probe; tools/symbolize.py resolves it in the .sym.log
 * sidecar every leg already writes.
 *
 * The counters are here for the panic dump and for in-kernel assertions
 * (tests/kmt/m4_usermode.c convicts the counting itself). */
extern uint64_t KiUserFaultRecoveryCount;      /* unwinds, all of them */
extern uint64_t KiUserFaultRecoveryUnexpected; /* the ones nobody claimed */

/* Called from KiDispatchTrap for a ring-0 fault. Unwinds to the current
 * thread's armed recovery frame and never returns, IF one is armed and the
 * faulting address is a user address. Returns (so the caller panics) for a
 * genuine kernel-address fault, which is a kernel bug and must stay loud.
 * `rip` is the faulting instruction, reported but never interpreted. */
void KiRecoverFromKernelFault(uint64_t faultAddress, uint64_t vector, uint64_t rip);

#endif /* PROSKRNL_KERNEL_SYSCALL_UACCESS_H */
