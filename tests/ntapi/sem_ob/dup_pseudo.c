/*
 * sem_ob/dup_pseudo.c — a MAGIC PSEUDO-HANDLE as the duplication SOURCE.
 *
 * DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), ...) is the
 * documented idiom for turning the current-process pseudo-handle into a real,
 * inheritable, duplicable one, and kernel32:virtual's test_ReadProcessMemory
 * opens with it. The source handle in that call is not in any handle table,
 * so a duplication that only knows how to look one up refuses it.
 *
 * Operative spec is wineserver's duplicate_handle (third_party/wine
 * server/handle.c) reached through dlls/ntdll/unix/server.c:
 *
 *   - the object comes from get_handle_obj, which tries get_magic_handle
 *     FIRST and only then the source process's table;
 *   - a pseudo source has no entry, so its access is
 *     `obj->ops->map_access( obj, GENERIC_ALL )` — the comment there reads
 *     "pseudo-handle, give it full access" — and its attributes are none;
 *   - that full access is the SAME_ACCESS value only. A duplication naming
 *     specific rights still gets exactly those, because the access it asks
 *     for is mapped independently and only compared against the source's.
 *
 * sem_ob/dup_cross_process.c pins the other half of this subject: WHICH
 * process a pseudo source names when the two ends differ.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCompareObjects(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* OBJ_HANDLE_FLAG_INFORMATION, class 4 (wine/include/winternl.h
 * ObjectHandleFlagInformation), as sem_ob/handle_flags.c spells it. */
#define OB_HANDLE_FLAG_INFO 4
typedef struct
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OB_HANDLE_FLAGS;

/* The magic values, as wineserver's get_magic_handle switches on them
 * (third_party/wine server/handle.c). -3 is deliberately NOT one of them. */
#define PSEUDO_PROCESS       ((HANDLE)(LONG_PTR) - 1)
#define PSEUDO_THREAD        ((HANDLE)(LONG_PTR) - 2)
#define PSEUDO_NOTHING       ((HANDLE)(LONG_PTR) - 3)
#define PSEUDO_PROCESS_TOKEN ((HANDLE)(LONG_PTR) - 4)
#define PSEUDO_THREAD_TOKEN  ((HANDLE)(LONG_PTR) - 5)

static ACCESS_MASK granted_access(HANDLE handle)
{
    OBJECT_BASIC_INFORMATION obi;
    NTSTATUS status;
    memset(&obi, 0, sizeof(obi));
    status = NtQueryObject(handle, ObjectBasicInformation, &obi, sizeof(obi), NULL);
    ok(status == STATUS_SUCCESS, "ObjectBasicInformation -> %08lx", (unsigned long)status);
    return obi.GrantedAccess;
}

START_TEST(dup_pseudo)
{
    NTSTATUS status;
    HANDLE dup = NULL;
    ACCESS_MASK granted;

    /* --- the documented idiom, and what it must be worth ------------------- */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_PROCESS, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate the process pseudo-handle -> %08lx",
       (unsigned long)status);
    ok(dup != NULL && dup != PSEUDO_PROCESS, "got a REAL handle (%p)", dup);
    ok(NtCompareObjects(dup, PSEUDO_PROCESS) == STATUS_SUCCESS, "it names this process");
    granted = granted_access(dup);
    ok(granted == PROCESS_ALL_ACCESS, "full access, not the caller's zero (%08lx)",
       (unsigned long)granted);
    NtClose(dup);
    dup = NULL;

    /* The thread pseudo-handle takes the same arm. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_THREAD, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate the thread pseudo-handle -> %08lx",
       (unsigned long)status);
    ok(NtCompareObjects(dup, PSEUDO_THREAD) == STATUS_SUCCESS, "it names this thread");
    granted = granted_access(dup);
    ok(granted == THREAD_ALL_ACCESS, "full thread access (%08lx)", (unsigned long)granted);
    NtClose(dup);
    dup = NULL;

    /* So does the current-process TOKEN, which is the one magic handle whose
     * object is not the caller itself. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_PROCESS_TOKEN, NtCurrentProcess(), &dup,
                               0, 0, DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "duplicate the process-token pseudo-handle -> %08lx",
       (unsigned long)status);
    ok(NtCompareObjects(dup, PSEUDO_PROCESS_TOKEN) == STATUS_SUCCESS, "it names this token");
    NtClose(dup);
    dup = NULL;

    /* --- full access is the SAME_ACCESS value, not the arm's answer -------- */
    /* PROCESS_VM_READ carries no implication in either runner's mapping, so a
     * duplicate asking for it alone must come back holding exactly it. An
     * implementation that stamped the pseudo source's full mask onto every
     * duplicate would over-grant here and pass every case above. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_PROCESS, NtCurrentProcess(), &dup,
                               PROCESS_VM_READ, 0, 0);
    ok(status == STATUS_SUCCESS, "duplicate asking for one right -> %08lx", (unsigned long)status);
    granted = granted_access(dup);
    ok(granted == PROCESS_VM_READ, "exactly the right asked for (%08lx)", (unsigned long)granted);
    NtClose(dup);
    dup = NULL;

    /* --- a pseudo source carries NO attributes ---------------------------- */
    /* DUPLICATE_SAME_ATTRIBUTES has no entry to copy them from: the server
     * takes them out of the mapped access mask, whose reserved bits are all
     * clear. The inherit flag must therefore be CLEAR even though nothing
     * asked for it either way. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_PROCESS, NtCurrentProcess(), &dup, 0,
                               OBJ_INHERIT, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
    ok(status == STATUS_SUCCESS, "duplicate with SAME_ATTRIBUTES -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        OB_HANDLE_FLAGS flags;
        memset(&flags, 0xff, sizeof(flags));
        status = NtQueryObject(dup, (OBJECT_INFORMATION_CLASS)OB_HANDLE_FLAG_INFO, &flags,
                               sizeof(flags), NULL);
        ok(status == STATUS_SUCCESS, "query handle flags -> %08lx", (unsigned long)status);
        ok(!flags.Inherit, "SAME_ATTRIBUTES off a pseudo source does not inherit");
        NtClose(dup);
        dup = NULL;
    }

    /* --- DUPLICATE_CLOSE_SOURCE has nothing to close ---------------------- */
    /* The server closes the source unconditionally and DISCARDS the error
     * (server/handle.c dup_handle: "close the handle no matter what
     * happened", with close_handle's return value dropped), which is also
     * what MSDN promises for a pseudo handle — "calling the CloseHandle
     * function with a pseudo handle has no effect"
     * (learn.microsoft.com, GetCurrentProcess). So the duplication succeeds
     * and the pseudo-handle keeps working afterwards. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_PROCESS, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
    ok(status == STATUS_SUCCESS, "duplicate with CLOSE_SOURCE -> %08lx", (unsigned long)status);
    ok(NtCompareObjects(PSEUDO_PROCESS, dup) == STATUS_SUCCESS,
       "the pseudo-handle still names this process");
    NtClose(dup);
    dup = NULL;

    /* --- what is NOT magic ------------------------------------------------ */
    /* -3 sits inside the pseudo-handle range and names nothing: no arm of
     * get_magic_handle claims it and no table holds it. */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_NOTHING, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_INVALID_HANDLE, "-3 duplicates nothing -> %08lx", (unsigned long)status);

    /* The thread token exists only while impersonating, and without one there
     * is nothing for -5 to name. (The two runners reach that by different
     * routes — the server's magic arm returns NULL and the table lookup behind
     * it then misses — but the answer is the same status, which is what a
     * boundary test may assert.) */
    status = NtDuplicateObject(NtCurrentProcess(), PSEUDO_THREAD_TOKEN, NtCurrentProcess(), &dup, 0,
                               0, DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_INVALID_HANDLE, "-5 without impersonation -> %08lx", (unsigned long)status);
}
