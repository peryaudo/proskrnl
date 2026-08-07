/* kernel/syscall/table.c — the system service table + dispatcher (M4; the
 * Wine-id-indexed table + full-frame entry at M7).
 *
 * A plain array of {handler, argument count, name} indexed by syscall id —
 * NT's SSDT concept without KiSystemService's acrobatics (docs/05). As of M7
 * the ids ARE the pinned Wine tree's own 64-bit syscall numbers
 * (tools/gen_syscalls.py reads them from dlls/ntdll/ntsyscalls.h), so the
 * kernel can never disagree with the unmodified PE ntdll about which service
 * a thunk's `syscall` reaches. The table spans the whole id space; ids
 * proskrnl does not implement yet get a KI_SYSCALL_MISSING row that logs its
 * name and returns STATUS_NOT_IMPLEMENTED — the M7 bring-up loop (which Nt*
 * did ntdll want next?) reads that line straight off serial.
 *
 * previousMode: the dispatcher stamps UserMode on the current thread for the
 * duration of the service so that uaccess probes are live exactly when the
 * arguments came from ring 3 (kmt/kernel callers keep KernelMode and
 * probe-free semantics, as NT kernel callers do).
 */
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h" /* CUI-4: KiProcessPendingUserSignals */
#include "kernel/ob/ob.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/lib/dbgprint.h"

#include "abi/ntobapi.h"
#include "abi/ntmmapi.h"
#include "abi/ntioapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntregapi.h"
#include "abi/ntseapi.h"
#include "abi/syscall_numbers.h"

typedef NTSTATUS (*KI_SERVICE_ROUTINE)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                       uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                       uint64_t, uint64_t);

/* The widest service: the 14-argument NtCreateNamedPipeFile (M9); before it
 * the 11-argument NtCreateFile / NtQueryDirectoryFile (M6) and
 * NtCreateUserProcess / NtCreateThreadEx (M7). */
#define KI_MAX_SYSCALL_ARGUMENTS 14

typedef struct
{
    KI_SERVICE_ROUTINE service; /* 0 for a not-yet-implemented id */
    int argumentCount;
    const char *name; /* for the panic dump's last-syscall line */
} KI_SERVICE_DESCRIPTOR;

/* NOLINTBEGIN(bugprone-casting-through-void) — the uniform uint64 signature
 * is the SSDT idiom; each Nt* consumes only its declared arguments and the
 * x86-64 SysV ABI passes all seven in the same slots either way. */
#define KI_SYSCALL(id, name, argc)         [id] = {(KI_SERVICE_ROUTINE)(void (*)(void))(name), argc, #name},
#define KI_SYSCALL_MISSING(id, name, argc) [id] = {0, argc, #name},
static const KI_SERVICE_DESCRIPTOR KiServiceTable[NTSYS_SYSCALL_LIMIT] = {
#include "kernel/syscall/table.inc"
};
#undef KI_SYSCALL
#undef KI_SYSCALL_MISSING
/* NOLINTEND(bugprone-casting-through-void) */

/* Art. 12 dialed to fatal (see syscall.h): armed at boot from
 * C:\panic_not_implemented.flag by kernel/init/main.c. */
BOOLEAN KiPanicOnNotImplemented = FALSE;

const char *KiSystemCallName(uint64_t number)
{
    if (number >= NTSYS_SYSCALL_LIMIT || KiServiceTable[number].name == 0)
    {
        return "?";
    }
    return KiServiceTable[number].name;
}

/* The NT x64 syscall convention (M7, matching Wine's PE ntdll thunks): the
 * user stack at frame->rsp holds a return address + four 8-byte home/shadow
 * slots, so argument 5 sits at rsp + 0x28. */
#define KI_SYSCALL_STACK_ARGUMENT_OFFSET 0x28

/* Call the service with a ring-0 fault recovery frame armed (uaccess.h): a
 * fault on a user address anywhere inside it returns STATUS_ACCESS_VIOLATION
 * instead of halting the machine, which is what NT's KiSystemServiceHandler
 * does for the same case.
 *
 * Its own frame is the unwind target, so it holds nothing across the call
 * that it needs afterwards: on the recovery path every local is indeterminate
 * except the recovery frame itself, and the current thread is re-derived
 * rather than remembered. Kept separate from KiSystemServiceTrap for exactly
 * that reason — the dispatcher's own state (trapFrame, previousFrame) must
 * survive an unwind, and it does because this returns normally either way.
 *
 * The indirect call crosses function types by design (see the table); keep
 * UBSan's function-type check out of this one call site. */
__attribute__((no_sanitize("function"), noinline)) static NTSTATUS
KiCallServiceGuarded(const KI_SERVICE_DESCRIPTOR *descriptor, const uint64_t *arguments)
{
    KI_FAULT_RECOVERY recovery;
    ULONG unwound = KiSetFaultRecovery(&recovery);
    if (unwound != 0)
    {
        /* KiRecoverFromKernelFault disarmed before jumping; this is the
         * belt-and-braces disarm for a hypothetical unwind from elsewhere. */
        KiDisarmFaultRecovery();
        /* THE assertion this ledger exists for (issue #96 B). The comment in
         * uaccess.h has always said an unwind runs no cleanup; that made a
         * ring-0 fault under the volume gate a permanent, silent, machine-wide
         * wedge (docs/20 §10.2's highest-severity row — every later file op on
         * the volume parks forever, with nothing on serial). Here it is a
         * panic with a stack trace naming the gate, the first time any
         * execution faults across a held obligation. */
        KiAssertNoObligations("fault-recovery unwind");
        return (NTSTATUS)unwound;
    }

    /* The service's own name is what an [UACCESS] line blames (issue #32 A3):
     * an unwind here means this service reached a user address without a live
     * probe behind it, and the name plus the reported rip is the whole
     * suspect. Never `expected` — no service is allowed to fault by design. */
    KiArmFaultRecovery(&recovery, descriptor->name, FALSE);
    NTSTATUS status =
        descriptor->service(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4],
                            arguments[5], arguments[6], arguments[7], arguments[8], arguments[9],
                            arguments[10], arguments[11], arguments[12], arguments[13]);
    KiDisarmFaultRecovery();
    /* The ordinary exit: a service that returns holding a gate is the same
     * defect reached the boring way. */
    KiAssertNoObligations("service return");
    return status;
}

void KiSystemServiceTrap(PKTRAP_FRAME trapFrame)
{
    uint64_t number = trapFrame->rax;
    PKTHREAD thread = KeGetCurrentThread();

    /* Publish the frame so the user-mode return protocol (NtContinue,
     * NtRaiseException, NtGetContextThread) can reach the outgoing context. */
    PKTRAP_FRAME previousFrame = thread->trapFrame;
    thread->trapFrame = trapFrame;

    KiLastSystemCall = number;
    KiTraceEvent(KiTraceSyscall, number, trapFrame->r10, trapFrame->rdx);

    NTSTATUS status;
    const KI_SERVICE_DESCRIPTOR *descriptor =
        (number < NTSYS_SYSCALL_LIMIT) ? &KiServiceTable[number] : 0;
    if (descriptor == 0)
    {
        status = STATUS_INVALID_SYSTEM_SERVICE;
    }
    else if (descriptor->service == 0)
    {
        /* A known Wine id with no proskrnl service yet: name it on serial so
         * the bring-up loop knows exactly what to implement next. */
        DbgPrint("[KTEST] syscall MISSING %#lx %s\n", (unsigned long)number, descriptor->name);
        if (KiPanicOnNotImplemented)
        {
            KiPanic("syscall MISSING (panic_not_implemented.flag armed)");
        }
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        ASSERT(thread->previousMode == KernelMode); /* syscalls never nest */
        thread->previousMode = UserMode;

        /* Arguments 1-4 came in registers (r10/rdx/r8/r9); 5.. come from the
         * user stack. A service that terminates the caller never returns. */
        uint64_t arguments[KI_MAX_SYSCALL_ARGUMENTS] = {trapFrame->r10, trapFrame->rdx,
                                                        trapFrame->r8, trapFrame->r9};
        status = STATUS_SUCCESS;
        if (descriptor->argumentCount > 4)
        {
            ASSERT(descriptor->argumentCount <= KI_MAX_SYSCALL_ARGUMENTS);
            status = KiCopyFromUser(
                &arguments[4], (const void *)(trapFrame->rsp + KI_SYSCALL_STACK_ARGUMENT_OFFSET),
                (uint64_t)(descriptor->argumentCount - 4) * sizeof(uint64_t));
        }
        if (NT_SUCCESS(status))
        {
            /* TEMPORARY PROFILER — not for commit. Per-syscall cumulative
             * cycles + call counts, dumped as a top-12 table every 200k
             * calls. The cui9 spawn loop is ~150x slower on this branch than
             * on its base and three guessed mechanisms were each wrong, so
             * this measures instead. */
            {
                extern volatile uint64_t KiWatchdogSyscallCount;
                KiWatchdogSyscallCount++;
                static uint64_t profileCycles[NTSYS_SYSCALL_LIMIT];
                static uint64_t profileCalls[NTSYS_SYSCALL_LIMIT];
                static uint64_t profileTotal;
                static uint64_t profileWindowStart;
                static uint64_t profileInsideWindow;
                uint64_t started = __builtin_ia32_rdtsc();
                status = KiCallServiceGuarded(descriptor, arguments);
                uint64_t ended = __builtin_ia32_rdtsc();
                profileCycles[number] += ended - started;
                profileInsideWindow += ended - started;
                profileCalls[number]++;
                if (profileWindowStart == 0)
                {
                    profileWindowStart = started;
                }
                /* Dump on a WALL-CLOCK window, not a call count: the whole
                 * question is whether the missing time is inside syscalls at
                 * all, and a call-count trigger cannot fire if the machine is
                 * slow while making few calls. 5e9 cycles is a couple of
                 * seconds. `inside` vs `wall` partitions the time. */
                ++profileTotal;
                if (ended - profileWindowStart >= 5000000000ULL)
                {
                    uint64_t wall = ended - profileWindowStart;
                    DbgPrint("[PROF] window wall=%luM inside=%luM (%lu%%) calls=%lu\n",
                             (unsigned long)(wall / 1000000),
                             (unsigned long)(profileInsideWindow / 1000000),
                             (unsigned long)(profileInsideWindow * 100 / wall),
                             (unsigned long)profileTotal);
                    profileWindowStart = ended;
                    profileInsideWindow = 0;
                    for (int rank = 0; rank < 12; rank++)
                    {
                        uint64_t best = 0;
                        int bestIndex = -1;
                        for (int i = 0; i < NTSYS_SYSCALL_LIMIT; i++)
                        {
                            if (profileCycles[i] > best)
                            {
                                best = profileCycles[i];
                                bestIndex = i;
                            }
                        }
                        if (bestIndex < 0)
                        {
                            break;
                        }
                        DbgPrint("[PROF] %s calls=%lu Mcycles=%lu\n",
                                 KiServiceTable[bestIndex].name,
                                 (unsigned long)profileCalls[bestIndex],
                                 (unsigned long)(profileCycles[bestIndex] / 1000000));
                        profileCycles[bestIndex] = 0; /* consumed for this dump */
                    }
                }
            }
        }

        /* A partial service's unbuilt case (an info class, an ioctl verb, a
         * flag) refusing loudly per Art. 12: name it like the MISSING row
         * does. No case is exempt — STATUS_NOT_IMPLEMENTED means "unbuilt",
         * and matching an oracle that is itself unbuilt is not a contract
         * worth reproducing, so there is nothing here to spare. */
        if (status == STATUS_NOT_IMPLEMENTED)
        {
            /* arg1/arg2 name the refused case (the info class / verb usually
             * rides in one of them) — the bring-up loop needs the exact
             * suspect, not just the service. */
            DbgPrint("[KTEST] syscall PARTIAL %#lx %s a0=%#lx a1=%#lx\n", (unsigned long)number,
                     descriptor->name, (unsigned long)trapFrame->r10,
                     (unsigned long)trapFrame->rdx);
            if (KiPanicOnNotImplemented)
            {
                KiPanic("syscall returned STATUS_NOT_IMPLEMENTED "
                        "(panic_not_implemented.flag armed)");
            }
        }

        thread->previousMode = KernelMode;
    }

    /* Deliver the NTSTATUS in eax on the iretq return — unless a service that
     * manages its own return register (NtContinue, NtRaiseException) already
     * rewrote the frame's rax. */
    if (!thread->userContextReplaced)
    {
        trapFrame->rax = (uint64_t)(int64_t)status;
    }
    thread->userContextReplaced = FALSE;

    /* On the way back to ring 3, deliver a pending user APC (alertable-wait
     * completion or NtTestAlert queued one). This re-points the frame at
     * KiUserApcDispatcher; the dispatcher's NtContinue resumes the syscall
     * return. Only at a genuine ring-3 return, never for kernel callers. */
    if ((trapFrame->segCs & 3) == 3 && KiUserApcPending(thread))
    {
        KiDeliverUserApc(thread, trapFrame);
    }

    /* CUI-4: the suspend/terminate choke point on the way back to ring 3 —
     * a foreign terminate reaps here, a closed suspend gate parks here. */
    if ((trapFrame->segCs & 3) == 3)
    {
        KiProcessPendingUserSignals(thread);
    }

    thread->trapFrame = previousFrame;
}
