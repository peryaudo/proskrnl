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
#include "kernel/ob/ob.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"
#include "kernel/lib/dbgprint.h"

#include "abi/ntobapi.h"
#include "abi/ntmmapi.h"
#include "abi/ntioapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntregapi.h"
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
#define KI_SYSCALL(id, name, argc)         [id] = {(KI_SERVICE_ROUTINE)(void (*)(void))name, argc, #name},
#define KI_SYSCALL_MISSING(id, name, argc) [id] = {0, argc, #name},
static const KI_SERVICE_DESCRIPTOR KiServiceTable[NTSYS_SYSCALL_LIMIT] = {
#include "kernel/syscall/table.inc"
};
#undef KI_SYSCALL
#undef KI_SYSCALL_MISSING
/* NOLINTEND(bugprone-casting-through-void) */

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

/* The indirect call crosses function types by design (see the table); keep
 * UBSan's function-type check out of this one call site. */
__attribute__((no_sanitize("function"))) void KiSystemServiceTrap(PKTRAP_FRAME trapFrame)
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
        status = STATUS_NOT_IMPLEMENTED;
    }
    else
    {
        ASSERT(thread->previousMode == KernelMode); /* syscalls never nest */
        thread->previousMode = UserMode;

        uint64_t stackArguments[KI_MAX_SYSCALL_ARGUMENTS - 4] = {0};
        status = STATUS_SUCCESS;
        if (descriptor->argumentCount > 4)
        {
            ASSERT(descriptor->argumentCount <= KI_MAX_SYSCALL_ARGUMENTS);
            status = KiCopyFromUser(
                stackArguments, (const void *)(trapFrame->rsp + KI_SYSCALL_STACK_ARGUMENT_OFFSET),
                (uint64_t)(descriptor->argumentCount - 4) * sizeof(uint64_t));
        }
        if (NT_SUCCESS(status))
        {
            /* Arguments 1-4 came in registers (r10/rdx/r8/r9); 5.. from the
             * user stack captured above. A service that terminates the caller
             * never returns here. */
            status = descriptor->service(trapFrame->r10, trapFrame->rdx, trapFrame->r8,
                                         trapFrame->r9, stackArguments[0], stackArguments[1],
                                         stackArguments[2], stackArguments[3], stackArguments[4],
                                         stackArguments[5], stackArguments[6], stackArguments[7],
                                         stackArguments[8], stackArguments[9]);
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

    thread->trapFrame = previousFrame;
}
