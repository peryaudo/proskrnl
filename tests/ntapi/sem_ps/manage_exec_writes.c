/*
 * sem_ps/manage_exec_writes.c — ProcessManageWritesToExecutableMemory and
 * ThreadManageWritesToExecutableMemory are a HOST-ARCHITECTURE probe, and on
 * x86_64 the answer is STATUS_NOT_SUPPORTED.
 *
 * docs/21 W5/W6. `dlls/ntdll/tests/virtual.c` test_exec_memory_writes opens
 * by SETTING the process class and reads the status as "am I on an ARM64EC
 * host?":
 *
 *     status = NtSetInformationProcess( GetCurrentProcess(),
 *                                       ProcessManageWritesToExecutableMemory,
 *                                       &mem, sizeof(mem) );
 *     if (!status) { ... ok( info.ProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64,
 *                            "succeeded on non-ARM64\n" ); skip(...); return; }
 *     ok( status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_SUPPORTED, ... );
 *
 * So a SUCCESS here is not a harmless no-op: it is a wrong answer to a
 * capability question, and the caller then believes it is running on
 * ARM64EC. That is the same defect shape as the dropped
 * MEM_EXTENDED_PARAMETER_EC_CODE attribute (docs/21 W6) — an input accepted
 * and discarded, turning a probe into a lie — and it is what a blanket
 * accept-as-a-no-op arm in NtSetInformationProcess produces by
 * construction.
 *
 * The pinned oracle states both classes in one shape
 * (dlls/ntdll/unix/process.c `case ProcessManageWritesToExecutableMemory`,
 * dlls/ntdll/unix/thread.c `case ThreadManageWritesToExecutableMemory`):
 * the whole body is `#ifdef __aarch64__ ... #else return STATUS_NOT_SUPPORTED;
 * #endif`. Two consequences this file pins, because an implementation can
 * plausibly get either wrong:
 *
 *   - the refusal is about the MACHINE, not about the arguments, so it
 *     precedes every argument check the aarch64 arm makes. A wrong length,
 *     a wrong Version, the mutually-exclusive flag, a NULL buffer and a
 *     junk handle all answer STATUS_NOT_SUPPORTED — never the
 *     STATUS_INFO_LENGTH_MISMATCH / STATUS_REVISION_MISMATCH /
 *     STATUS_INVALID_PARAMETER the ARM64EC path gives for exactly those
 *     inputs (virtual.c:3527-:3554 asserts that other half, reachable only
 *     when the probe above succeeds).
 *
 *   - NOT_SUPPORTED, not STATUS_INVALID_INFO_CLASS. The winetest accepts
 *     either, but the oracle is the spec (Art. 6) and the class DOES exist
 *     on this build — it is the hardware that does not.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle: the pinned Wine answers
 * every case below on x86_64.
 */
#include "util.h"

/* The thread pseudo-handle, as wine/include/winternl.h defines it (mingw's
 * omits it) — the same spelling sem_ps/proc_classes.c uses. */
#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif

/* Neither class is in mingw's winternl.h; spelled as the pinned tree spells
 * them (third_party/wine/include/winternl.h, the _PROCESSINFOCLASS and
 * _THREADINFOCLASS enums). A wrong number would answer
 * STATUS_INVALID_INFO_CLASS on the oracle, so the oracle leg validates
 * them. */
#define PS_ProcessManageWritesToExecutableMemory ((PROCESSINFOCLASS)83)
#define PS_ThreadManageWritesToExecutableMemory  ((THREADINFOCLASS)48)
/* The neighbour the last case below asks, same source, same convention. */
#define PS_ProcessPriorityClass ((PROCESSINFOCLASS)18)

/* MANAGE_WRITES_TO_EXECUTABLE_MEMORY, as wine/include/winternl.h declares
 * it (mingw's winternl.h omits it). The bitfield order is the contract:
 * virtual.c initialises `{ .Version = 2 }` and then sets the two flag bits
 * by name. */
typedef struct
{
    ULONG version : 8;
    ULONG process_enable_write_exceptions : 1;
    ULONG thread_allow_writes : 1;
    ULONG spare : 22;
    PVOID kernel_write_to_executable_signal;
} ps_manage_writes;

/* One (class, value) pair asked of both syscalls; every one of them is
 * STATUS_NOT_SUPPORTED on an x86_64 host whatever else is wrong with it. */
static void expect_not_supported(const char *what, HANDLE processHandle, HANDLE threadHandle,
                                 ps_manage_writes *mem, ULONG length)
{
    NTSTATUS status = NtSetInformationProcess(
        processHandle, PS_ProcessManageWritesToExecutableMemory, mem, length);
    ok(status == STATUS_NOT_SUPPORTED, "process %s -> %08lx", what, (unsigned long)status);

    status =
        NtSetInformationThread(threadHandle, PS_ThreadManageWritesToExecutableMemory, mem, length);
    ok(status == STATUS_NOT_SUPPORTED, "thread %s -> %08lx", what, (unsigned long)status);
}

START_TEST(manage_exec_writes)
{
    ps_manage_writes mem;

    /* The length arguments below only mean what the oracle means by them if
     * the struct is the pinned tree's struct: 4 bytes of bitfields, 4 of
     * padding, an 8-byte pointer. */
    ok(sizeof(mem) == 16, "MANAGE_WRITES_TO_EXECUTABLE_MEMORY is %llu bytes",
       (unsigned long long)sizeof(mem));

    /* --- the probe itself, exactly as virtual.c makes it ------------------ */
    memset(&mem, 0, sizeof(mem));
    mem.version = 2;
    expect_not_supported("Version 2, exact size", NtCurrentProcess(), NtCurrentThread(), &mem,
                         sizeof(mem));

    /* --- and every argument the ARM64EC path would have complained about -- */

    /* Short and long: STATUS_INFO_LENGTH_MISMATCH there, not here. */
    expect_not_supported("size - 1", NtCurrentProcess(), NtCurrentThread(), &mem, sizeof(mem) - 1);
    expect_not_supported("size + 1", NtCurrentProcess(), NtCurrentThread(), &mem, sizeof(mem) + 1);

    /* An unknown Version: STATUS_REVISION_MISMATCH there, not here. */
    memset(&mem, 0, sizeof(mem));
    mem.version = 3;
    expect_not_supported("Version 3", NtCurrentProcess(), NtCurrentThread(), &mem, sizeof(mem));

    /* Each syscall's forbidden flag — the process class refuses
     * ThreadAllowWrites and the thread class refuses
     * ProcessEnableWriteExceptions with STATUS_INVALID_PARAMETER there.
     * Both bits are set at once so the one call covers both refusals. */
    memset(&mem, 0, sizeof(mem));
    mem.version = 2;
    mem.process_enable_write_exceptions = 1;
    mem.thread_allow_writes = 1;
    expect_not_supported("both flags set", NtCurrentProcess(), NtCurrentThread(), &mem,
                         sizeof(mem));

    /* No buffer at all. The refusal is decided before anything reads or
     * probes the caller's memory, so this is NOT_SUPPORTED and not an
     * access violation — which is also what makes it safe to answer with no
     * capture at all. */
    expect_not_supported("NULL buffer, zero length", NtCurrentProcess(), NtCurrentThread(), NULL,
                         0);

    /* And a handle that resolves to nothing. The oracle's switch runs
     * before any handle is looked up, so the class answers for the machine
     * without ever asking who was being addressed. */
    memset(&mem, 0, sizeof(mem));
    mem.version = 2;
    expect_not_supported("junk handle", (HANDLE)(ULONG_PTR)0xdeadbeef,
                         (HANDLE)(ULONG_PTR)0xdeadbeef, &mem, sizeof(mem));

    /* --- the neighbouring class number is untouched by all this ----------
     * A refusal that swallowed its neighbours would pass everything above.
     * ProcessPriorityClass (18) still answers its own way, and the pinned
     * oracle's set arm gives STATUS_INVALID_PARAMETER for a wrong size
     * (dlls/ntdll/unix/process.c) rather than the NOT_SUPPORTED above. */
    ULONG bogus = 0;
    NTSTATUS status =
        NtSetInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &bogus, sizeof(bogus));
    ok(status == STATUS_INVALID_PARAMETER, "ProcessPriorityClass, 4 bytes -> %08lx",
       (unsigned long)status);
}
