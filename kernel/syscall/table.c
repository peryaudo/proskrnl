/* kernel/syscall/table.c — the system service table + dispatcher (M4).
 *
 * A plain array of {handler, argument count} in syscall-number order — NT's
 * SSDT concept without KiSystemService's acrobatics (docs/05). The table
 * rows come from the generated table.inc so the kernel can never disagree
 * with the user-mode stubs about numbers (tools/gen_syscalls.py); the
 * handler signatures themselves are the generated abi/ prototypes.
 *
 * previousMode: the dispatcher stamps UserMode on the current thread for
 * the duration of the service so that uaccess probes are live exactly when
 * the arguments came from ring 3 (kmt/kernel callers keep KernelMode and
 * probe-free semantics, as NT kernel callers do).
 */
#include "kernel/syscall/syscall.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/init/panic.h"
#include "kernel/init/trace.h"

#include "abi/ntobapi.h"
#include "abi/ntmmapi.h"
#include "abi/ntioapi.h"
#include "abi/ntpsapi.h"
#include "abi/syscall_numbers.h"

typedef NTSTATUS (*KI_SERVICE_ROUTINE)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                       uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* The widest service so far: NtCreateFile's / NtQueryDirectoryFile's 11
 * arguments (M6). */
#define KI_MAX_SYSCALL_ARGUMENTS 11

typedef struct
{
    KI_SERVICE_ROUTINE service;
    int argumentCount;
    const char *name; /* for the panic dump's last-syscall line */
} KI_SERVICE_DESCRIPTOR;

/* NOLINTBEGIN(bugprone-casting-through-void) — the uniform uint64 signature
 * is the SSDT idiom; each Nt* consumes only its declared arguments and the
 * x86-64 SysV ABI passes all seven in the same slots either way. */
#define KI_SYSCALL(name, argc) {(KI_SERVICE_ROUTINE)(void (*)(void))name, argc, #name},
static const KI_SERVICE_DESCRIPTOR KiServiceTable[] = {
#include "kernel/syscall/table.inc"
};
#undef KI_SYSCALL
/* NOLINTEND(bugprone-casting-through-void) */

_Static_assert(sizeof(KiServiceTable) / sizeof(KiServiceTable[0]) == NTSYS_SYSCALL_COUNT,
               "table.inc and syscall_numbers.h must come from the same generation");

const char *KiSystemCallName(uint64_t number)
{
    if (number >= NTSYS_SYSCALL_COUNT)
    {
        return "?";
    }
    return KiServiceTable[number].name;
}

/* The indirect call crosses function types by design (see the table); keep
 * UBSan's function-type check out of this one call site. */
__attribute__((no_sanitize("function"))) int64_t KiSystemService(uint64_t number,
                                                                 const uint64_t *args,
                                                                 uint64_t userRsp)
{
    KiLastSystemCall = number;
    KiTraceEvent(KiTraceSyscall, number, args[0], args[1]);
    if (number >= NTSYS_SYSCALL_COUNT)
    {
        return (int64_t)STATUS_INVALID_SYSTEM_SERVICE;
    }
    const KI_SERVICE_DESCRIPTOR *descriptor = &KiServiceTable[number];

    PKTHREAD thread = KeGetCurrentThread();
    ASSERT(thread->previousMode == KernelMode); /* syscalls never nest */
    thread->previousMode = UserMode;

    NTSTATUS status;
    uint64_t stackArguments[KI_MAX_SYSCALL_ARGUMENTS - 6] = {0};
    if (descriptor->argumentCount > 6)
    {
        /* Arguments 7..10 sit above the stub's return address on the user
         * stack, exactly where a SysV caller placed them. */
        ASSERT(descriptor->argumentCount <= KI_MAX_SYSCALL_ARGUMENTS);
        status = KiCopyFromUser(stackArguments, (const void *)(userRsp + 8),
                                (uint64_t)(descriptor->argumentCount - 6) * sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            thread->previousMode = KernelMode;
            return (int64_t)status;
        }
    }

    status = descriptor->service(args[0], args[1], args[2], args[3], args[4], args[5],
                                 stackArguments[0], stackArguments[1], stackArguments[2],
                                 stackArguments[3], stackArguments[4]);

    /* A service that terminated the calling thread never returns here. */
    thread->previousMode = KernelMode;
    return (int64_t)status;
}
