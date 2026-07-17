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

#include "abi/ntobapi.h"
#include "abi/ntmmapi.h"
#include "abi/ntpsapi.h"
#include "abi/syscall_numbers.h"

typedef NTSTATUS (*KI_SERVICE_ROUTINE)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                       uint64_t);

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

/* The indirect call crosses function types by design (see the table); keep
 * UBSan's function-type check out of this one call site. */
__attribute__((no_sanitize("function"))) int64_t KiSystemService(uint64_t number,
                                                                 const uint64_t *args,
                                                                 uint64_t userRsp)
{
    KiLastSystemCall = number;
    if (number >= NTSYS_SYSCALL_COUNT)
    {
        return (int64_t)STATUS_INVALID_SYSTEM_SERVICE;
    }
    const KI_SERVICE_DESCRIPTOR *descriptor = &KiServiceTable[number];

    PKTHREAD thread = KeGetCurrentThread();
    ASSERT(thread->previousMode == KernelMode); /* syscalls never nest */
    thread->previousMode = UserMode;

    NTSTATUS status;
    uint64_t argument7 = 0;
    if (descriptor->argumentCount > 6)
    {
        /* Argument 7 sits above the stub's return address on the user
         * stack, exactly where a SysV caller placed it. */
        status = KiCopyFromUser(&argument7, (const void *)(userRsp + 8), sizeof(argument7));
        if (!NT_SUCCESS(status))
        {
            thread->previousMode = KernelMode;
            return (int64_t)status;
        }
    }

    status = descriptor->service(args[0], args[1], args[2], args[3], args[4], args[5], argument7);

    /* A service that terminated the calling thread never returns here. */
    thread->previousMode = KernelMode;
    return (int64_t)status;
}
