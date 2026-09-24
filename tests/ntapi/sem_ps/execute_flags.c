/*
 * sem_ps/execute_flags.c — setting ProcessExecuteFlags on a native 64-bit
 * process is refused with STATUS_INVALID_PARAMETER, whatever is asked.
 *
 * This is the one class the PE loader sets at startup
 * (third_party/wine dlls/ntdll/loader.c alloc_module: an image without
 * IMAGE_DLLCHARACTERISTICS_NX_COMPAT makes it ask for
 * MEM_EXECUTE_OPTION_ENABLE), and kernel32's SetProcessDEPPolicy is the
 * other caller (dlls/kernel32/process.c). Both used to land in
 * NtSetInformationProcess's accept-as-a-no-op default arm and read back a
 * STATUS_SUCCESS nothing had earned — the Art. 12 shape that arm existed in.
 *
 * The pinned oracle's arm opens with
 *
 *     if ((is_win64 && !is_wow64()) || size != sizeof(ULONG))
 *         return STATUS_INVALID_PARAMETER;
 *
 * (dlls/ntdll/unix/process.c, case ProcessExecuteFlags): DEP is not a
 * per-process choice for 64-bit code, so the refusal is about the PROCESS,
 * and it precedes every argument check the WOW64 path makes. That ordering
 * is what this file pins — a valid ENABLE, a valid DISABLE, the invalid
 * both-bits and no-bits values, a wrong length, a NULL buffer and a junk
 * handle all answer the same status, and none of them is an access
 * violation or a handle complaint.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle.
 */
#include "util.h"

/* Neither the class nor the MEM_EXECUTE_OPTION_* bits are in mingw's
 * headers; spelled as the pinned tree spells them
 * (third_party/wine/include/winternl.h, the _PROCESSINFOCLASS enum and the
 * MEM_EXECUTE_OPTION_* defines). A wrong class number would not answer
 * STATUS_INVALID_PARAMETER on the oracle, so the oracle leg validates it. */
#define PS_ProcessExecuteFlags          ((PROCESSINFOCLASS)34)
#define PS_MEM_EXECUTE_OPTION_DISABLE   0x01
#define PS_MEM_EXECUTE_OPTION_ENABLE    0x02
#define PS_MEM_EXECUTE_OPTION_PERMANENT 0x08

static void expect_refused(const char *what, HANDLE processHandle, void *buffer, ULONG length)
{
    NTSTATUS status =
        NtSetInformationProcess(processHandle, PS_ProcessExecuteFlags, buffer, length);
    /* Red on proskrnl until the kernel stops accepting this class as a
     * no-op; the next commit deletes the tag. */
    todo_proskrnl
    {
        ok(status == STATUS_INVALID_PARAMETER, "%s -> %08lx", what, (unsigned long)status);
    }
}

START_TEST(execute_flags)
{
    ULONG flags;

    /* --- the loader's own request, exactly as alloc_module makes it ------- */
    flags = PS_MEM_EXECUTE_OPTION_ENABLE;
    expect_refused("ENABLE", NtCurrentProcess(), &flags, sizeof(flags));

    /* --- SetProcessDEPPolicy(PROCESS_DEP_ENABLE) -------------------------- */
    flags = PS_MEM_EXECUTE_OPTION_DISABLE | PS_MEM_EXECUTE_OPTION_PERMANENT;
    expect_refused("DISABLE|PERMANENT", NtCurrentProcess(), &flags, sizeof(flags));

    /* --- values the WOW64 path would itself reject ------------------------ */
    flags = PS_MEM_EXECUTE_OPTION_ENABLE | PS_MEM_EXECUTE_OPTION_DISABLE;
    expect_refused("ENABLE|DISABLE", NtCurrentProcess(), &flags, sizeof(flags));
    flags = 0;
    expect_refused("no bits", NtCurrentProcess(), &flags, sizeof(flags));

    /* --- a wrong length, and no buffer at all ----------------------------- */
    flags = PS_MEM_EXECUTE_OPTION_ENABLE;
    expect_refused("length + 1", NtCurrentProcess(), &flags, sizeof(flags) + 1);
    expect_refused("NULL buffer, zero length", NtCurrentProcess(), NULL, 0);

    /* --- a handle that resolves to nothing: the refusal is decided before
     * any handle is looked up, so this is not STATUS_INVALID_HANDLE. */
    expect_refused("junk handle", (HANDLE)(ULONG_PTR)0xdeadbeef, &flags, sizeof(flags));

    /* --- and the refusal left nothing behind: a second valid request gets
     * the same answer rather than STATUS_ACCESS_DENIED (the oracle's answer
     * once a PERMANENT setting HAS taken). */
    flags = PS_MEM_EXECUTE_OPTION_ENABLE;
    expect_refused("ENABLE after DISABLE|PERMANENT", NtCurrentProcess(), &flags, sizeof(flags));
}
