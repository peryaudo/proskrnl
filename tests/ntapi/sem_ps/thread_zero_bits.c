/*
 * sem_ps/thread_zero_bits.c — NtCreateThreadEx's ZeroBits is the PLACEMENT
 * CEILING of the new thread's stack, and its invalid band is NOT
 * NtAllocateVirtualMemory's.
 *
 * docs/21 W5 (the ntdll:virtual thread-stack cluster; the 35 assertions at
 * virtual.c:1411/:1431 that remain after the TEB and class-41 items). The
 * argument is the eighth parameter of the syscall and `RtlCreateUserThread`
 * hands it straight down (third_party/wine dlls/ntdll/thread.c), so the
 * winetest's `test_stack_size` sweep asks for all 32 counts and 27 masks and
 * reads back one status each.
 *
 * A kernel that ACCEPTS the argument and drops it answers STATUS_SUCCESS to
 * every one of those, which is docs/21 W5's accepted-and-dropped-input shape:
 * no stub, no fabricated struct, a correct-looking status, and a stack placed
 * wherever the allocator felt like. It is only visible by asking for a
 * ceiling that cannot be met.
 *
 * TWO LADDERS, NOT ONE — and this is the part an implementation gets wrong by
 * being tidy. The pinned oracle's NtCreateThreadEx validates
 * (dlls/ntdll/unix/thread.c, immediately above the remote-process branch):
 *
 *     if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;
 *     #ifndef _WIN64
 *     if (!is_old_wow64() && zero_bits >= 32) return STATUS_INVALID_PARAMETER_3;
 *     #endif
 *
 * — so on x86-64 there is exactly ONE invalid band. `NtAllocateVirtualMemory`
 * has a SECOND one (`zero_bits > 32 && zero_bits < granularity_mask`,
 * dlls/ntdll/unix/virtual.c), which this entry point does not have. So
 * ZeroBits 33 is STATUS_INVALID_PARAMETER_3 through
 * NtSetInformationProcess(ProcessThreadStackAllocation) — pinned next door in
 * sem_ps/thread_stack_alloc.c, because that class really is implemented by
 * calling NtAllocateVirtualMemory — and here it is a legal MASK naming a
 * 63-byte ceiling, i.e. STATUS_NO_MEMORY. An implementation that reused the
 * allocation path's ladder passes every other case in this file.
 *
 * THE VALIDATION PRECEDES THE PROCESS HANDLE, which is a position rather than
 * a value and therefore invisible in a status table: the two lines above sit
 * before `if (process != NtCurrentProcess())`, so a bad ZeroBits is reported
 * for a handle that names nothing at all.
 *
 * WHAT CONVICTS HERE IS THE REFUSALS, and it is worth saying why the
 * successful placements do not. A ceiling only proves it was applied if the
 * allocator would otherwise have chosen an address ABOVE it, and neither
 * runner promises that: the oracle's unconstrained thread stacks land high
 * (docs/21 W5 measured 0x7ffffe8c0000) while proskrnl's land low, so a 2^28
 * ceiling is a real constraint on one runner and a no-op on the other. The
 * success cases therefore assert the EXTENT rule (last byte at or below the
 * ceiling, which is what the count means) and print the address; the cases
 * that cannot be met are the ones a dropped argument cannot survive.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle.
 */
#include "util.h"

#include <windows.h> /* NtCurrentTeb */

NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* TEB.DeallocationStack, reached by offset because mingw's winternl.h stops
 * at four Reserved[] arrays. 0x1478 is the x64 offset the pinned tree's own
 * header states (third_party/wine include/winternl.h, `PVOID
 * DeallocationStack; /​* e0c/1478 *​/`), which is where abi/ntpebteb.h's
 * generated static_assert comes from too. G8: re-verify there. Proved live on
 * the oracle by the unconstrained thread below before anything is concluded
 * from it. Same constant, same reason, as sem_ps/teb_stack.c. */
#define PS_TEB_DEALLOCATION_STACK_OFFSET 0x1478

/* NT's own minimum stack reserve, so no floor or rounding on either runner
 * can change it, and the extent this file reasons about is a property of the
 * request. */
#define PS_THREAD_RESERVE 0x100000
#define PS_THREAD_COMMIT  0x10000

/* A handle value no creation can return, so "left alone" is distinguishable
 * from "written with something odd". */
#define PS_HANDLE_POISON ((HANDLE)(ULONG_PTR)0xdeadbeef)

static ps_create_thread_ex createThreadEx;

/* The child's own view of its stack, written by the child and read by the
 * creator after it has exited. A child that asserted for itself would make a
 * wrong kernel cost the leg a wedge instead of a failure (docs/21 W10). */
static PVOID childDealloc;

static DWORD WINAPI child(LPVOID unused)
{
    (void)unused;
    childDealloc = *(PVOID *volatile)((char *)NtCurrentTeb() + PS_TEB_DEALLOCATION_STACK_OFFSET);
    return 0;
}

/* One create, run to completion. `deallocOut` is written only on success;
 * `handleOut` always gets whatever the syscall left in the caller's slot,
 * which the two refusal arms below disagree about. */
static NTSTATUS create_thread(ULONG_PTR zeroBits, PVOID *deallocOut, HANDLE *handleOut,
                              const char *what)
{
    HANDLE thread = PS_HANDLE_POISON;
    NTSTATUS status;

    childDealloc = NULL;
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)child,
                            NULL, 0, zeroBits, PS_THREAD_COMMIT, PS_THREAD_RESERVE, NULL);
    if (handleOut != NULL)
    {
        *handleOut = thread;
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "%s: the child did not exit", what);
    NtClose(thread);
    if (deallocOut != NULL)
    {
        *deallocOut = childDealloc;
    }
    return status;
}

/* An ARGUMENT refusal: nothing was created, so the caller's handle slot is
 * untouched. */
static void expect_param_refusal(ULONG_PTR zeroBits, NTSTATUS wanted, const char *what)
{
    HANDLE thread = PS_HANDLE_POISON;
    NTSTATUS status = create_thread(zeroBits, NULL, &thread, what);

    ok(status == wanted, "%s: zero_bits %llx -> %08lx, wanted %08lx", what,
       (unsigned long long)zeroBits, (unsigned long)status, (unsigned long)wanted);
    ok(thread == PS_HANDLE_POISON, "%s: refused before creating anything, yet wrote a handle (%p)",
       what, thread);
}

/* A PLACEMENT refusal: the ceiling is legal and cannot be met.
 *
 * Nothing is asserted about the handle slot here, and the reason is measured
 * rather than conceded. The oracle creates the thread object first and only
 * then reserves the stack (dlls/ntdll/unix/thread.c: `create_server_thread`,
 * then `init_thread_stack`, then `done: if (status) { NtClose( *handle ); … }`),
 * so it CLOSES the handle and leaves its stale value in the caller's slot —
 * this file's first draft asserted the slot was untouched and the oracle
 * refuted it with a live-looking 0x34. A closed handle value is not something
 * a caller can use or ought to depend on, so it is stated here and not
 * pinned; what IS pinned is the argument arm above, where the difference is
 * an ordering the caller can observe. */
static void expect_placement_refusal(ULONG_PTR zeroBits, NTSTATUS wanted, const char *what)
{
    NTSTATUS status = create_thread(zeroBits, NULL, NULL, what);

    ok(status == wanted, "%s: zero_bits %llx -> %08lx, wanted %08lx", what,
       (unsigned long long)zeroBits, (unsigned long)status, (unsigned long)wanted);
}

/* A ceiling that CAN be met: the reservation's last byte is at or below it.
 * The ceiling is on the whole extent, not on the base. */
static void expect_placement(ULONG_PTR zeroBits, ULONG_PTR ceiling, const char *what)
{
    PVOID dealloc = NULL;
    NTSTATUS status = create_thread(zeroBits, &dealloc, NULL, what);

    ok(status == STATUS_SUCCESS, "%s: zero_bits %llx -> %08lx", what, (unsigned long long)zeroBits,
       (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ok(dealloc != NULL, "%s: the child reported no DeallocationStack", what);
    if (dealloc == NULL)
    {
        return;
    }
    ok((ULONG_PTR)dealloc + PS_THREAD_RESERVE - 1 <= ceiling,
       "%s: stack [%llx, %llx] is not under the %llx ceiling", what,
       (unsigned long long)(ULONG_PTR)dealloc,
       (unsigned long long)((ULONG_PTR)dealloc + PS_THREAD_RESERVE - 1),
       (unsigned long long)ceiling);
}

START_TEST(thread_zero_bits)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HANDLE thread = PS_HANDLE_POISON;
    PVOID unconstrained = NULL;
    NTSTATUS status;

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

    /* --- the control: no ceiling at all ---------------------------------- */
    status = create_thread(0, &unconstrained, NULL, "zero_bits 0");
    ok(status == STATUS_SUCCESS, "zero_bits 0 -> %08lx", (unsigned long)status);
    /* Also the proof that PS_TEB_DEALLOCATION_STACK_OFFSET names a live field
     * on the ORACLE, before any placement assertion below leans on it. */
    ok(unconstrained != NULL, "TEB+%#x is not the DeallocationStack",
       PS_TEB_DEALLOCATION_STACK_OFFSET);
    ntapi_printf("thread_zero_bits: unconstrained stack at %llx\n",
                 (unsigned long long)(ULONG_PTR)unconstrained);

    /* --- the ONE invalid band, and both of its edges ---------------------- */
    expect_param_refusal(22, STATUS_INVALID_PARAMETER_3, "band low edge");
    expect_param_refusal(25, STATUS_INVALID_PARAMETER_3, "band middle");
    expect_param_refusal(31, STATUS_INVALID_PARAMETER_3, "band high edge");

    /* 21 is the last COUNT, and it is not refused — it names a 2 KiB ceiling
     * that no 1 MiB stack fits under, so running out of room is the answer.
     * The pair (21, 22) is what separates "this value is malformed" from
     * "this value cannot be served", and a kernel that widened the band by
     * one fails here rather than anywhere the winetest looks. */
    expect_placement_refusal(21, STATUS_NO_MEMORY, "count 21");
    /* The winetest's own i == 12: a 1 MiB ceiling for a 1 MiB stack, which
     * would need the reservation to start at address 0. */
    expect_placement_refusal(12, STATUS_NO_MEMORY, "count 12");

    /* --- >= 32 is a MASK here, where the allocation path has a second band  */

    /* 32: highest set bit 5, so a 63-byte ceiling. */
    expect_placement_refusal(32, STATUS_NO_MEMORY, "mask 32");
    /* 33 and 0xfffe are both inside NtAllocateVirtualMemory's second invalid
     * band (`> 32 && < granularity_mask`), which is why they are
     * STATUS_INVALID_PARAMETER_3 through ProcessThreadStackAllocation
     * (sem_ps/thread_stack_alloc.c) and merely unsatisfiable ceilings here.
     * This is the pair that convicts a shared ladder. */
    expect_placement_refusal(33, STATUS_NO_MEMORY, "mask 33");
    expect_placement_refusal(0xfffe, STATUS_NO_MEMORY, "mask 0xfffe");

    /* --- ceilings that can be met ---------------------------------------- */

    /* A count of 4 means "no bits set at or above 2^28". */
    expect_placement(4, ((ULONG_PTR)1 << 28) - 1, "count 4");
    /* The winetest's mask for i == 0. Every bit of a 32-bit address is
     * acceptable, i.e. a 4 GiB ceiling — the mask arm's answer for a value
     * the count arm would have called "no constraint". */
    expect_placement(0xffffffff, ((ULONG_PTR)1 << 32) - 1, "mask 0xffffffff");

    /* --- ZeroBits is answered BEFORE the process handle ------------------- */
    thread = PS_HANDLE_POISON;
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, PS_HANDLE_POISON, (PVOID)child, NULL,
                            0, 25, PS_THREAD_COMMIT, PS_THREAD_RESERVE, NULL);
    ok(status == STATUS_INVALID_PARAMETER_3, "bad handle + bad zero_bits -> %08lx",
       (unsigned long)status);
    ok(thread == PS_HANDLE_POISON, "bad handle + bad zero_bits wrote a handle (%p)", thread);

    /* The negative control: the same handle with a legal ZeroBits really is
     * refused for being a bad handle, so the assertion above is about ORDER
     * and not about the handle being fine. */
    thread = PS_HANDLE_POISON;
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, PS_HANDLE_POISON, (PVOID)child, NULL,
                            0, 0, PS_THREAD_COMMIT, PS_THREAD_RESERVE, NULL);
    ok(status == STATUS_INVALID_HANDLE, "bad handle + good zero_bits -> %08lx",
       (unsigned long)status);
    ok(thread == PS_HANDLE_POISON, "bad handle + good zero_bits wrote a handle (%p)", thread);
}
