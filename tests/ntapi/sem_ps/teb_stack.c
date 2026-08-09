/*
 * sem_ps/teb_stack.c — TEB.DeallocationStack is the BASE OF THE STACK'S
 * RESERVATION, and every thread has one.
 *
 * docs/21 W5 (the ntdll:virtual thread-stack cluster). NT_TIB.StackBase and
 * NT_TIB.StackLimit bracket the COMMITTED part of a stack and both move as it
 * grows; DeallocationStack is the third, fixed corner — the address the whole
 * region was reserved at, and therefore the only one of the three from which
 * the stack's RESERVE (`StackBase - DeallocationStack`) can be computed.
 *
 * A kernel that fills the first two and leaves the third zero publishes a
 * self-consistent TEB in which every stack looks like it reaches address 0.
 * That is Art. 12's plausible answer with no stub in it, and what makes it
 * expensive is who reads the field: it is not decoration for a debugger.
 *
 *   - `GetCurrentThreadStackLimits` returns it verbatim as the low bound
 *     (dlls/kernelbase/thread.c);
 *   - `SetThreadStackGuarantee` sizes its guarantee against
 *     `StackBase - DeallocationStack` (same file), so a zero makes every
 *     guarantee look satisfiable;
 *   - kernel32's stack-overflow filter re-arms the guard page at
 *     `DeallocationStack + page_size` (dlls/kernel32/virtual.c
 *     badptr_handler), i.e. at page one of a NULL region;
 *   - and the fiber implementation SWAPS it on every switch
 *     (dlls/kernelbase/thread.c SwitchToFiber), so a thread converted to a
 *     fiber and back cannot recover a bound it never had.
 *
 * WHAT THIS FILE CAN ASSERT IS THE PORTABLE CORE, and the reason is in
 * `virtual_alloc_thread_stack` (third_party/wine dlls/ntdll/unix/virtual.c):
 * the oracle commits the WHOLE reservation up front and puts its guard page
 * at page one, while proskrnl commits a slice at the top behind a guard band
 * that walks down (docs/02 "guard-page stack growth", pinned by
 * sem_mm/stack_growth.c). So the SHAPE of the middle differs by design and is
 * not pinned here. What both runners state identically — and what the whole
 * cluster in ntdll:virtual's test_stack_size_thread is built on — is:
 *
 *   - page zero of the region is reserved-not-committed on both (the oracle
 *     explicitly un-commits it: `set_page_vprot( view->base, host_page_size,
 *     0 )`), so a query at DeallocationStack describes a MEM_RESERVE run
 *     whose AllocationBase is DeallocationStack itself;
 *   - the committed part at StackLimit belongs to the SAME allocation, which
 *     is the assertion that catches a DeallocationStack pointing at some
 *     other region rather than at nothing;
 *   - and `StackBase - DeallocationStack` is exactly the reserve the thread
 *     was created with, once NT's own 1 MiB floor and granularity rounding
 *     are applied (`size = max( reserve, commit ); if (size < 1024 * 1024)
 *     size = 1024 * 1024;` — the same floor RtlCreateUserStack applies).
 *
 * Oracle-first (G5). Nothing here is beyond_oracle.
 */
#include "util.h"

#include <windows.h> /* NT_TIB, NtCurrentTeb */

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, LPCVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* MemoryBasicInformation, as sem_mm/util.h spells it. */
#define PS_MEMORY_BASIC_INFO_CLASS 0

/* The reserve/commit this test asks NtCreateThreadEx for. The reserve is
 * NT's own minimum, so no floor or rounding can change it and the expected
 * answer is a property of the request rather than of either runner. */
#define PS_THREAD_RESERVE 0x100000
#define PS_THREAD_COMMIT  0x10000

/* mingw's winternl.h declares the TEB as four Reserved[] arrays and stops,
 * so this field has to be reached by offset. 0x1478 is the x64 offset the
 * pinned tree's own header states in its offset-comment column
 * (third_party/wine include/winternl.h, `PVOID DeallocationStack; /​* e0c/1478 *​/`
 * — the same comment abi/ntpebteb.h's generated
 * `offsetof(TEB, DeallocationStack) == 0x1478` static_assert is derived
 * from). G8: re-verify there, not from memory. The first assertion in the
 * body proves the offset names a live field on the ORACLE before anything
 * is concluded from it here. */
#define PS_TEB_DEALLOCATION_STACK_OFFSET 0x1478

static PVOID read_deallocation_stack(void)
{
    return *(PVOID *volatile)((char *)NtCurrentTeb() + PS_TEB_DEALLOCATION_STACK_OFFSET);
}

/* What a thread says about its own stack, filled by the thread and read by
 * the creator after it has exited. A thread that asserted for itself would
 * make a wrong kernel cost the leg a wedge instead of a failure
 * (docs/21 W10 lesson 2). */
struct stack_facts
{
    PVOID base;
    PVOID limit;
    PVOID dealloc;
    /* The address of one of the recording thread's own locals, kept as an
     * INTEGER: it is only ever compared, never dereferenced, and the thread
     * whose frame it names has exited by the time the creator reads it. */
    ULONG_PTR local;
};

static struct stack_facts childFacts;

static void record_facts(struct stack_facts *facts)
{
    volatile char probe = 0;
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();

    facts->base = tib->StackBase;
    facts->limit = tib->StackLimit;
    facts->dealloc = read_deallocation_stack();
    facts->local = (ULONG_PTR)&probe;
}

static DWORD WINAPI child(LPVOID unused)
{
    (void)unused;
    record_facts(&childFacts);
    return 0;
}

/* The three corners and the two queries, for one thread's stack. */
static void check_stack(const struct stack_facts *facts, const char *what)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T retlen = 0;
    NTSTATUS status;

    ok(facts->dealloc != NULL, "%s: DeallocationStack is NULL", what);
    if (facts->dealloc == NULL)
    {
        return;
    }
    ok((char *)facts->dealloc < (char *)facts->limit,
       "%s: DeallocationStack %p not below StackLimit %p", what, facts->dealloc, facts->limit);
    ok((ULONG_PTR)facts->limit <= facts->local && facts->local < (ULONG_PTR)facts->base,
       "%s: a local at %llx is outside [%p, %p)", what, (unsigned long long)facts->local,
       facts->limit, facts->base);

    /* Page zero of the reservation: uncommitted on both runners, and the
     * base of its own allocation — which is the whole claim the field
     * makes. */
    memset(&mbi, 0xcc, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), facts->dealloc, PS_MEMORY_BASIC_INFO_CLASS,
                                  &mbi, sizeof(mbi), &retlen);
    ok(status == STATUS_SUCCESS, "%s: query DeallocationStack -> %08lx", what,
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(mbi.AllocationBase == facts->dealloc, "%s: AllocationBase %p, wanted %p", what,
           mbi.AllocationBase, facts->dealloc);
        ok(mbi.BaseAddress == facts->dealloc, "%s: BaseAddress %p, wanted %p", what,
           mbi.BaseAddress, facts->dealloc);
        ok(mbi.State == MEM_RESERVE, "%s: State %lx", what, (unsigned long)mbi.State);
        ok(mbi.Protect == 0, "%s: Protect %lx", what, (unsigned long)mbi.Protect);
        ok(mbi.AllocationProtect == PAGE_READWRITE, "%s: AllocationProtect %lx", what,
           (unsigned long)mbi.AllocationProtect);
        ok(mbi.Type == MEM_PRIVATE, "%s: Type %lx", what, (unsigned long)mbi.Type);
    }

    /* The committed part is the SAME allocation. A DeallocationStack that
     * merely pointed at some other reserved region would pass everything
     * above and fail this. */
    memset(&mbi, 0xcc, sizeof(mbi));
    status = NtQueryVirtualMemory(NtCurrentProcess(), facts->limit, PS_MEMORY_BASIC_INFO_CLASS,
                                  &mbi, sizeof(mbi), &retlen);
    ok(status == STATUS_SUCCESS, "%s: query StackLimit -> %08lx", what, (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(mbi.AllocationBase == facts->dealloc,
           "%s: committed part's AllocationBase %p, wanted %p", what, mbi.AllocationBase,
           facts->dealloc);
        ok(mbi.BaseAddress == facts->limit, "%s: committed BaseAddress %p, wanted %p", what,
           mbi.BaseAddress, facts->limit);
        ok(mbi.State == MEM_COMMIT, "%s: committed State %lx", what, (unsigned long)mbi.State);
        ok(mbi.Protect == PAGE_READWRITE, "%s: committed Protect %lx", what,
           (unsigned long)mbi.Protect);
        ok(mbi.Type == MEM_PRIVATE, "%s: committed Type %lx", what, (unsigned long)mbi.Type);
    }
}

START_TEST(teb_stack)
{
    struct stack_facts mainFacts;
    ps_create_thread_ex createThreadEx;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HANDLE thread = NULL;
    NTSTATUS status;

    /* The offset above is a hand-typed layout constant (G8): prove it names
     * the right field before anything is concluded from it. A wrong offset
     * would read some neighbouring TEB pointer, which would fail here on the
     * ORACLE — where the field is known to be correct — rather than convict
     * a kernel. */
    ok(read_deallocation_stack() != NULL, "TEB+%#x is not the DeallocationStack",
       PS_TEB_DEALLOCATION_STACK_OFFSET);

    record_facts(&mainFacts);
    check_stack(&mainFacts, "main thread");

    /* --- a created thread, whose reserve the CALLER chose ---------------- */
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

    memset(&childFacts, 0, sizeof(childFacts));
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)child,
                            NULL, 0, 0, PS_THREAD_COMMIT, PS_THREAD_RESERVE, NULL);
    ok(status == STATUS_SUCCESS, "NtCreateThreadEx -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "the child did not exit");
    NtClose(thread);

    check_stack(&childFacts, "created thread");
    /* The reserve the caller named, reported by the only pair of TEB fields
     * that can express it. This is ntdll:virtual:1050 — the assertion the
     * whole test_stack_size sweep repeats for each of its 61 threads. */
    ok((char *)childFacts.base - (char *)childFacts.dealloc == PS_THREAD_RESERVE,
       "created thread: reserve %llx, wanted %llx",
       (unsigned long long)((char *)childFacts.base - (char *)childFacts.dealloc),
       (unsigned long long)PS_THREAD_RESERVE);
}
