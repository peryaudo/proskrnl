/*
 * sem_mm/protect_old_prot.c — a FAILED NtProtectVirtualMemory still writes
 * the caller's *old_prot, and what it writes is PAGE_NOACCESS.
 *
 * docs/21 W5's tail: `ntdll:virtual:2679` and `:2686` are the last two
 * assertions of that pair outside the cross-process image-map cluster. Both
 * ask the same thing — the call failed, so what is in the slot? — and
 * proskrnl left it holding whatever the caller had put there, because
 * kernel/mm/virtual.c writes the slot only on success.
 *
 * The rule is the pinned oracle's last statement (third_party/wine
 * dlls/ntdll/unix/virtual.c, NtProtectVirtualMemory):
 *
 *     if (status == STATUS_SUCCESS)
 *     {
 *         *addr_ptr = base;
 *         *size_ptr = size;
 *         *old_prot = old;
 *     }
 *     else *old_prot = PAGE_NOACCESS;
 *
 * Read as "on failure, write PAGE_NOACCESS" it is one line. Four things
 * around it are not in that line, and each is a way an implementation
 * reaching for the obvious `else` answers wrongly:
 *
 *   - the slot is written for EVERY failure of the operation — an
 *     unserviceable protection, an uncommitted range, a free address — not
 *     merely for the "found the pages, could not change them" case. None of
 *     the three HAS a previous protection to report, which is the point;
 *   - `*addr_ptr` and `*size_ptr` are NOT written alongside it. The oracle
 *     rounds them into LOCALS and copies them back only on success, so a
 *     failed call leaves the caller's own (unrounded) values where they
 *     were. An implementation that reports its rounding unconditionally
 *     satisfies every old_prot assertion here and still diverges;
 *   - it does NOT cover a failure to reach the operation at all. A process
 *     handle that cannot be resolved returns before the write — on the
 *     oracle because `server_queue_process_apc` fails and returns `status`
 *     directly, above the `else`. So an implementation that writes
 *     PAGE_NOACCESS at every non-success return of the syscall is wrong in
 *     exactly the two cases this pin measures (a junk handle, and a real
 *     handle without PROCESS_VM_OPERATION), and right everywhere else;
 *   - and it holds through the REMOTE arm, which on the oracle is a second,
 *     textually separate `else *old_prot = PAGE_NOACCESS;` reached by an APC
 *     rather than by the inline path. A real handle to our own process takes
 *     that arm (`process != NtCurrentProcess()`; the server answers
 *     `reply->self` and ntdll runs the APC inline, server.c
 *     server_queue_process_apc), so the second site is measurable without a
 *     child process. On proskrnl both arms are one syscall body — but "they
 *     must agree" is an argument, not a measurement (docs/21 §4 trap 4).
 *
 * The STATUS of the free-address case is pinned here too, and it is worth
 * saying why rather than treating it as obvious: upstream's own comment at
 * virtual.c:2677 records that Wine and Windows DISAGREE about it —
 * "STATUS_INVALID_PARAMETER in wine, STATUS_CONFLICTING_ADDRESSES in win64" —
 * and the winetest therefore asserts only that the call fails. proskrnl used
 * to answer a third thing, STATUS_INVALID_ADDRESS, and that one is not a
 * shade of the same refusal: Wine's PE-side RtlNtStatusToDosError maps
 * c0000141 to ERROR_UNEXP_NET_ERR (59) (dlls/ntdll/error.h:686), so
 * VirtualProtect over a free address reported an "unexpected network error"
 * where both authorities report an address or parameter problem. Where two
 * authorities disagree the pinned oracle is this project's arbiter (Art. 6),
 * so this pins the oracle's answer — which is also the same status the
 * oracle's find_view gives for the other way to miss, a range that runs off
 * the end of one view.
 *
 * And the ORDER those refusals are decided in is pinned, because it is not
 * the obvious one. The oracle asks view -> committed -> protection —
 * `find_view`, then `get_committed_size`, then `set_protection`, which is
 * where `get_vprot_flags` refuses an unserviceable protection. So a bad
 * protection over a free address reports the ADDRESS and over a reserved
 * range reports the COMMIT; only over a range it could otherwise have
 * protected does it report itself. Validating the protection on the way in
 * is the shape every implementation reaches for first (proskrnl did), it
 * differs from the oracle in exactly those two cases, and no winetest
 * assertion reaches either.
 *
 * Oracle-first (G5): every case here is measured on the pinned Wine.
 */
#include "util.h"

/* The sentinel every "was the slot written?" assertion is measured against.
 * It is not a legal PAGE_* value, so nothing can produce it by accident. */
#define OLD_PROT_SENTINEL 0xdeadbeefu

/* The one call under test, with the caller's slots always pre-poisoned so
 * "untouched" and "written" are distinguishable. */
static NTSTATUS protect(HANDLE process, PVOID *addr, SIZE_T *size, ULONG newProtect,
                        ULONG *oldProtect)
{
    *oldProtect = OLD_PROT_SENTINEL;
    return NtProtectVirtualMemory(process, addr, size, newProtect, oldProtect);
}

/* Both failing arms of the same call, over a handle the caller chooses: the
 * pseudo-handle takes the oracle's inline path and a real handle takes its
 * APC path, and the rule is the same on both. */
static void test_failures_through(HANDLE process, const char *arm, PVOID committed,
                                  ULONG committedProtect, PVOID reserved, PVOID freed)
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG oldProtect;
    NTSTATUS status;
    PVOID addr;
    SIZE_T size;

    /* `freed` is asserted on twice, with an OpenProcess and a good deal of
     * ntdll activity in between, so state that it is still free rather than
     * assuming it. If something reserved it the cases below would measure a
     * different shape entirely, and this says so instead. */
    status = NtQueryVirtualMemory(NtCurrentProcess(), freed, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(NT_SUCCESS(status) && mbi.State == MEM_FREE, "%s: the free address was reused (%08lx/%lx)",
       arm, (unsigned long)status, (unsigned long)mbi.State);

    /* A ZERO-SIZE request is not a fourth rung above the ladder — it walks
     * the same one. The oracle has no size guard at all: ROUND_SIZE(addr, 0)
     * is 0 for an aligned address, find_view still answers the containing
     * view, and set_protection walks no pages. So all four of these are the
     * ordinary answers of the three questions, measured, and an
     * implementation that refuses `size == 0` on the way in (proskrnl did,
     * with STATUS_INVALID_PARAMETER) gets every one of them wrong. */
    addr = committed;
    size = 0;
    status = protect(process, &addr, &size, PAGE_READONLY, &oldProtect);
    ok(status == STATUS_SUCCESS, "%s: size 0 -> %08lx", arm, (unsigned long)status);
    ok(oldProtect == committedProtect, "%s: size 0 old_prot %lx, expected %lx", arm,
       (unsigned long)oldProtect, (unsigned long)committedProtect);
    ok(addr == committed, "%s: size 0 addr %p, expected %p", arm, addr, committed);
    ok(size == 0, "%s: size 0 size %llx", arm, (unsigned long long)size);

    addr = reserved;
    size = 0;
    status = protect(process, &addr, &size, PAGE_READONLY, &oldProtect);
    ok(status == STATUS_NOT_COMMITTED, "%s: size 0 on a reserved range -> %08lx", arm,
       (unsigned long)status);

    addr = freed;
    size = 0;
    status = protect(process, &addr, &size, PAGE_READONLY, &oldProtect);
    ok(status == STATUS_INVALID_PARAMETER, "%s: size 0 on a free address -> %08lx", arm,
       (unsigned long)status);

    addr = committed;
    size = 0;
    status = protect(process, &addr, &size, 0, &oldProtect);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "%s: size 0 with protect 0 -> %08lx", arm,
       (unsigned long)status);

    /* An unserviceable PROTECTION over a committed range. */
    addr = committed;
    size = 0x1000;
    status = protect(process, &addr, &size, 0, &oldProtect);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "%s: protect 0 -> %08lx", arm,
       (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: protect 0 old_prot %lx", arm, (unsigned long)oldProtect);

    /* The SAME unserviceable protection over a range the call never gets to
     * protect. The oracle asks view -> committed -> protection in that order
     * (find_view, get_committed_size, then set_protection's get_vprot_flags),
     * so the ADDRESS wins over the protection and the COMMIT wins over it
     * too. An implementation that validates the protection on the way in —
     * the obvious shape, and what proskrnl did — answers
     * STATUS_INVALID_PAGE_PROTECTION for both of these and is otherwise
     * indistinguishable. No winetest assertion reaches this. */
    addr = freed;
    size = 0x1000;
    status = protect(process, &addr, &size, 0, &oldProtect);
    ok(status == STATUS_INVALID_PARAMETER, "%s: protect 0 on a free address -> %08lx", arm,
       (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: protect 0 on a free address old_prot %lx", arm,
       (unsigned long)oldProtect);

    addr = reserved;
    size = 0x1000;
    status = protect(process, &addr, &size, 0, &oldProtect);
    ok(status == STATUS_NOT_COMMITTED, "%s: protect 0 on a reserved range -> %08lx", arm,
       (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: protect 0 on a reserved range old_prot %lx", arm,
       (unsigned long)oldProtect);

    /* A RESERVED-but-uncommitted range. */
    addr = reserved;
    size = 0x1000;
    status = protect(process, &addr, &size, PAGE_READWRITE, &oldProtect);
    ok(status == STATUS_NOT_COMMITTED, "%s: uncommitted -> %08lx", arm, (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: uncommitted old_prot %lx", arm, (unsigned long)oldProtect);

    /* A FREE address (see the header for why the status is the oracle's). */
    addr = freed;
    size = 0x1000;
    status = protect(process, &addr, &size, PAGE_READWRITE, &oldProtect);
    ok(status == STATUS_INVALID_PARAMETER, "%s: free address -> %08lx", arm, (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: free address old_prot %lx", arm,
       (unsigned long)oldProtect);

    /* The OTHER way to miss: a range that starts inside a view and runs off
     * its end. The oracle's find_view answers NULL for both, so both are one
     * status — an implementation that only handles "no view at all" answers
     * something else here and passes every case above. */
    addr = committed;
    size = 0x8000; /* the committed region is 0x4000 */
    status = protect(process, &addr, &size, PAGE_READWRITE, &oldProtect);
    ok(status == STATUS_INVALID_PARAMETER, "%s: range past the view -> %08lx", arm,
       (unsigned long)status);
    ok(oldProtect == PAGE_NOACCESS, "%s: range past the view old_prot %lx", arm,
       (unsigned long)oldProtect);
}

START_TEST(protect_old_prot)
{
    ULONG oldProtect;
    NTSTATUS status;
    PVOID base, addr, reserved, freed;
    SIZE_T size;
    HANDLE self;

    /* Four pages, committed PAGE_READONLY: the success control and the
     * "unserviceable protection" case both live here. */
    base = NULL;
    size = 0x4000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "commit 4 pages -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* A separate RESERVE-only region for the uncommitted case. Reserving it
     * inside the committed one is not the same test: NT decides "committed"
     * per page within one VAD, and a caller cannot tell the two shapes
     * apart, but the region has to be reserved by somebody or the address is
     * merely free. */
    reserved = NULL;
    size = 0x4000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &reserved, 0, &size, MEM_RESERVE,
                                     PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "reserve 4 pages -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* And a third region, released again, to name an address that is FREE
     * rather than merely unmapped-inside-something. */
    freed = NULL;
    size = 0x4000;
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &freed, 0, &size, MEM_RESERVE, PAGE_NOACCESS);
    ok(status == STATUS_SUCCESS, "reserve-to-free -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    addr = freed;
    size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    ok(status == STATUS_SUCCESS, "release -> %08lx", (unsigned long)status);

    /* --- the SUCCESS control ------------------------------------------------
     * Without it every PAGE_NOACCESS assertion below would also pass on a
     * kernel that wrote PAGE_NOACCESS unconditionally. */
    addr = base;
    size = 0x1000;
    status = protect(NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &oldProtect);
    ok(status == STATUS_SUCCESS, "protect RW -> %08lx", (unsigned long)status);
    ok(oldProtect == PAGE_READONLY, "protect RW old_prot %lx", (unsigned long)oldProtect);
    ok(addr == base, "protect RW addr %p, expected %p", addr, base);
    ok(size == 0x1000, "protect RW size %llx", (unsigned long long)size);

    /* --- the failing arms, through the pseudo-handle ------------------------ */
    test_failures_through(NtCurrentProcess(), "self", base, PAGE_READWRITE, reserved, freed);

    /* --- addr and size survive a failure ------------------------------------
     * Deliberately UNALIGNED and undersized, so a kernel that copies its own
     * rounding back unconditionally is visible: the oracle rounds into
     * locals and writes the caller's slots on success only. */
    addr = (char *)base + 0x123;
    size = 1;
    status = protect(NtCurrentProcess(), &addr, &size, 0, &oldProtect);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "unaligned + protect 0 -> %08lx",
       (unsigned long)status);
    ok(addr == (PVOID)((char *)base + 0x123), "failed protect moved addr to %p", addr);
    ok(size == 1, "failed protect rewrote size to %llx", (unsigned long long)size);

    /* --- a NULL old_prot is STATUS_ACCESS_VIOLATION -------------------------
     * The oracle refuses it before anything else, so there is no slot to
     * write and no operation to perform. */
    addr = base;
    size = 0x1000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &size, PAGE_READWRITE, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL old_prot -> %08lx", (unsigned long)status);

    /* --- a handle that cannot be resolved leaves the slot ALONE -------------
     * Above the `else` on the oracle: server_queue_process_apc fails and the
     * status returns directly. This is the case that separates "the
     * OPERATION failed" from "the call never got that far". */
    addr = base;
    size = 0x1000;
    status = protect((HANDLE)(ULONG_PTR)0xdeadu, &addr, &size, PAGE_READWRITE, &oldProtect);
    ok(status == STATUS_INVALID_HANDLE, "junk handle -> %08lx", (unsigned long)status);
    ok(oldProtect == OLD_PROT_SENTINEL, "junk handle wrote old_prot %lx",
       (unsigned long)oldProtect);

    /* Same statement, reached by the ACCESS check rather than by the handle
     * lookup: a real process handle without PROCESS_VM_OPERATION. */
    self = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    ok(self != NULL, "OpenProcess(QUERY_INFORMATION) -> %lu", (unsigned long)GetLastError());
    if (self)
    {
        addr = base;
        size = 0x1000;
        status = protect(self, &addr, &size, PAGE_READWRITE, &oldProtect);
        ok(status == STATUS_ACCESS_DENIED, "unentitled handle -> %08lx", (unsigned long)status);
        ok(oldProtect == OLD_PROT_SENTINEL, "unentitled handle wrote old_prot %lx",
           (unsigned long)oldProtect);
        NtClose(self);
    }

    /* --- the REMOTE arm, over a real handle to ourselves --------------------
     * `process != NtCurrentProcess()` is what selects it, not the target
     * being a different process (see the header). */
    self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    ok(self != NULL, "OpenProcess(ALL_ACCESS) -> %lu", (unsigned long)GetLastError());
    if (self)
    {
        addr = base;
        size = 0x1000;
        status = protect(self, &addr, &size, PAGE_READONLY, &oldProtect);
        ok(status == STATUS_SUCCESS, "remote arm protect RO -> %08lx", (unsigned long)status);
        ok(oldProtect == PAGE_READWRITE, "remote arm old_prot %lx", (unsigned long)oldProtect);

        test_failures_through(self, "remote", base, PAGE_READONLY, reserved, freed);
        NtClose(self);
    }

    addr = base;
    size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    addr = reserved;
    size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
}
