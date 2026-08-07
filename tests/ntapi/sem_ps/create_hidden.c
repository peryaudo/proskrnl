/*
 * sem_ps/create_hidden.c — THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER at
 * CREATE time, and the entry point that refuses it.
 *
 * ThreadHideFromDebugger is already a real stored flag on this kernel, set
 * through NtSetInformationThread. What was missing is that a thread can be
 * born with it: NtCreateThreadEx takes the flag in its `flags` word and the
 * server stores it straight into the new thread —
 *
 *     thread->dbg_hidden = !!(req->flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
 *     (third_party/wine server/thread.c, create_thread)
 *
 * — so NtQueryInformationThread(ThreadHideFromDebugger) reads 1 back out of
 * a thread that has not run a single instruction. A kernel that accepts the
 * flag and drops it answers 0, which is a plausible value for a real
 * question and therefore exactly the shape G12 forbids.
 *
 * The second half is the asymmetry, and it is the reason this is one file
 * rather than two. The SAME flag bit is INVALID on NtCreateUserProcess:
 *
 *     if (thread_flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
 *     { WARN( "Invalid thread flags %#x.\n", thread_flags );
 *       return STATUS_INVALID_PARAMETER; }
 *     (third_party/wine dlls/ntdll/unix/process.c)
 *
 * A kernel that implements the flag by simply passing `flags` down to a
 * shared thread-creation path gets the first half right and the second half
 * wrong, and ntdll:thread asserts them thirty lines apart (thread.c:122 and
 * thread.c:153).
 *
 * ONLY the first half is pinned here. The second needs a real image, real
 * RTL_USER_PROCESS_PARAMETERS and a PS_ATTRIBUTE_IMAGE_NAME to be
 * discriminating at all — otherwise STATUS_INVALID_PARAMETER proves nothing,
 * since a malformed call earns it anyway — and ntdll:thread already makes
 * exactly that comparison, running the same call twice with and without the
 * bit. That subtest is itself an oracle-pinned differential test (docs/03,
 * the winetest G5 policy), so duplicating it here would add a second, weaker
 * copy of a pin that exists.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* wine/include/winternl.h. THREADINFOCLASS in mingw's headers stops short of
 * this class, so it is spelled here with the value the oracle run validates
 * (a wrong one would answer STATUS_INVALID_INFO_CLASS there). */
#define PS_ThreadHideFromDebugger ((THREADINFOCLASS)17)

/* wine/include/winnt.h; mingw may omit them. */
#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#endif
#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#endif

static DWORD WINAPI do_nothing(LPVOID unused)
{
    (void)unused;
    return 0;
}

/* Create one thread with `flags`, read its ThreadHideFromDebugger back, let
 * it run, and reap it. `wanted` is the value the query must report. */
static void check_created_thread(ps_create_thread_ex createThreadEx, ULONG flags, UCHAR wanted,
                                 const char *what)
{
    HANDLE thread = NULL;
    NTSTATUS status;
    /* ONE BYTE. ThreadHideFromDebugger's buffer is a BOOLEAN, not a ULONG,
     * and the class refuses any other length with
     * STATUS_INFO_LENGTH_MISMATCH — measured on the oracle, and the reason
     * ntdll:thread declares its own `BOOLEAN dbg_hidden` (thread.c:91). */
    BOOLEAN hidden = 0xcc;
    ULONG previous = 0;

    status =
        createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PVOID)do_nothing,
                       NULL, flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0, 0, NULL);
    ok(status == STATUS_SUCCESS, "NtCreateThreadEx %s -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* Read it before the thread ever runs: the flag is part of the thread's
     * birth state, not something its own code sets. */
    status =
        NtQueryInformationThread(thread, PS_ThreadHideFromDebugger, &hidden, sizeof(hidden), NULL);
    ok(status == STATUS_SUCCESS, "query ThreadHideFromDebugger %s -> %08lx", what,
       (unsigned long)status);
    ok(hidden == wanted, "%s: ThreadHideFromDebugger is %#x, wanted %#x", what,
       (unsigned)hidden, (unsigned)wanted);

    status = NtResumeThread(thread, &previous);
    ok(status == STATUS_SUCCESS, "resume %s -> %08lx", what, (unsigned long)status);
    WaitForSingleObject(thread, 5000);
    NtClose(thread);
}

START_TEST(create_hidden)
{
    ps_create_thread_ex createThreadEx;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    ok(ntdll != NULL, "GetModuleHandleA(ntdll) -> %lu", (unsigned long)GetLastError());
    if (ntdll == NULL)
    {
        return;
    }
    createThreadEx = (ps_create_thread_ex)(void *)GetProcAddress(ntdll, "NtCreateThreadEx");
    ok(createThreadEx != NULL, "NtCreateThreadEx is exported");
    if (createThreadEx == NULL)
    {
        return;
    }

    /* Without the flag: 0. With it: 1. The pair is the point — a kernel
     * that hardwired either answer passes one line and fails the other. */
    check_created_thread(createThreadEx, 0, 0, "without HIDE_FROM_DEBUGGER");
    check_created_thread(createThreadEx, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 1,
                         "with HIDE_FROM_DEBUGGER");
}
