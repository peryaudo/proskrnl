/*
 * sem_ob/handle_flags.c — NtSetInformationObject / NtQueryObject
 * ObjectHandleFlagInformation and protect-from-close (CUI-6).
 *
 * The Get/SetHandleInformation idiom (kernelbase routes both straight
 * here): per-handle inherit and protect-from-close bits. Oracle behaviour
 * pinned from the pinned tree: both directions demand the full struct
 * (STATUS_INVALID_BUFFER_SIZE below sizeof — dlls/ntdll/unix/file.c
 * NtSetInformationObject/NtQueryObject); the set always writes BOTH flags
 * (mask is INHERIT|PROTECT_FROM_CLOSE, never partial); magic pseudo-handles
 * answer flags 0 on query but STATUS_ACCESS_DENIED on set (server/handle.c
 * set_handle_flags); a protected handle refuses NtClose with
 * STATUS_HANDLE_NOT_CLOSABLE and stays live (server/handle.c close_handle);
 * DUPLICATE_SAME_ATTRIBUTES carries the flags to the new handle
 * (server/handle.c duplicate_handle); OBJ_INHERIT at duplicate time sets
 * the inherit bit.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtSetInformationObject(HANDLE, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* wine/include/winternl.h OBJECT_INFORMATION_CLASS: ObjectHandleFlagInformation
 * = 4 (mingw's enum stops earlier on some toolchains; the oracle run
 * validates the value — a wrong one would answer STATUS_INVALID_INFO_CLASS
 * there). */
#define OB_HANDLE_FLAG_INFO 4

typedef struct
{
    BOOLEAN inherit;
    BOOLEAN protect_from_close;
} ob_handle_flags;

static NTSTATUS query_flags(HANDLE handle, ob_handle_flags *flags, ULONG *retlen)
{
    return NtQueryObject(handle, (OBJECT_INFORMATION_CLASS)OB_HANDLE_FLAG_INFO, flags,
                         sizeof(*flags), retlen);
}

static NTSTATUS set_flags(HANDLE handle, BOOLEAN inherit, BOOLEAN protect)
{
    ob_handle_flags flags;
    flags.inherit = inherit;
    flags.protect_from_close = protect;
    return NtSetInformationObject(handle, OB_HANDLE_FLAG_INFO, &flags, sizeof(flags));
}

START_TEST(handle_flags)
{
    NTSTATUS status;
    HANDLE event = NULL, dup = NULL;
    ob_handle_flags flags;
    ULONG retlen;

    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);

    /* --- fresh handle: both flags clear ---------------------------------- */
    memset(&flags, 0xcc, sizeof(flags));
    retlen = 0xdead;
    status = query_flags(event, &flags, &retlen);
    ok(status == STATUS_SUCCESS, "query fresh -> %08lx", (unsigned long)status);
    ok(!flags.inherit && !flags.protect_from_close, "fresh flags %u/%u", flags.inherit,
       flags.protect_from_close);
    ok(retlen == sizeof(flags), "query retlen %lu", (unsigned long)retlen);

    /* --- both directions demand the full struct -------------------------- */
    status = NtQueryObject(event, (OBJECT_INFORMATION_CLASS)OB_HANDLE_FLAG_INFO, &flags,
                           sizeof(flags) - 1, NULL);
    ok(status == STATUS_INVALID_BUFFER_SIZE, "short query -> %08lx", (unsigned long)status);
    status = NtSetInformationObject(event, OB_HANDLE_FLAG_INFO, &flags, sizeof(flags) - 1);
    ok(status == STATUS_INVALID_BUFFER_SIZE, "short set -> %08lx", (unsigned long)status);

    /* --- set inherit, read it back --------------------------------------- */
    status = set_flags(event, TRUE, FALSE);
    ok(status == STATUS_SUCCESS, "set inherit -> %08lx", (unsigned long)status);
    memset(&flags, 0xcc, sizeof(flags));
    status = query_flags(event, &flags, NULL);
    ok(status == STATUS_SUCCESS, "query inherit -> %08lx", (unsigned long)status);
    ok(flags.inherit && !flags.protect_from_close, "inherit set %u/%u", flags.inherit,
       flags.protect_from_close);

    /* The set writes BOTH flags: setting protect alone clears inherit. */
    status = set_flags(event, FALSE, TRUE);
    ok(status == STATUS_SUCCESS, "set protect -> %08lx", (unsigned long)status);
    memset(&flags, 0xcc, sizeof(flags));
    status = query_flags(event, &flags, NULL);
    ok(status == STATUS_SUCCESS, "query protect -> %08lx", (unsigned long)status);
    ok(!flags.inherit && flags.protect_from_close, "protect set, inherit cleared %u/%u",
       flags.inherit, flags.protect_from_close);

    /* --- protect-from-close enforced at NtClose -------------------------- */
    status = NtClose(event);
    ok(status == STATUS_HANDLE_NOT_CLOSABLE, "close protected -> %08lx", (unsigned long)status);
    /* ...and the handle is still live. */
    status = query_flags(event, &flags, NULL);
    ok(status == STATUS_SUCCESS, "protected handle survives close -> %08lx", (unsigned long)status);

    /* --- DUPLICATE_SAME_ATTRIBUTES carries the flags --------------------- */
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, 0,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
    ok(status == STATUS_SUCCESS, "dup same-attributes -> %08lx", (unsigned long)status);
    memset(&flags, 0xcc, sizeof(flags));
    status = query_flags(dup, &flags, NULL);
    ok(status == STATUS_SUCCESS, "query dup -> %08lx", (unsigned long)status);
    ok(!flags.inherit && flags.protect_from_close, "dup carries protect %u/%u", flags.inherit,
       flags.protect_from_close);
    status = set_flags(dup, FALSE, FALSE);
    ok(status == STATUS_SUCCESS, "unprotect dup -> %08lx", (unsigned long)status);
    status = NtClose(dup);
    ok(status == STATUS_SUCCESS, "close unprotected dup -> %08lx", (unsigned long)status);

    /* --- OBJ_INHERIT at duplicate time sets the inherit bit --------------- */
    dup = NULL;
    status = NtDuplicateObject(NtCurrentProcess(), event, NtCurrentProcess(), &dup, 0, OBJ_INHERIT,
                               DUPLICATE_SAME_ACCESS);
    ok(status == STATUS_SUCCESS, "dup inherit -> %08lx", (unsigned long)status);
    memset(&flags, 0xcc, sizeof(flags));
    status = query_flags(dup, &flags, NULL);
    ok(status == STATUS_SUCCESS, "query inherit dup -> %08lx", (unsigned long)status);
    ok(flags.inherit && !flags.protect_from_close, "dup inherit bit %u/%u", flags.inherit,
       flags.protect_from_close);
    status = NtClose(dup);
    ok(status == STATUS_SUCCESS, "close inherit dup -> %08lx", (unsigned long)status);

    /* --- unprotect and close the original -------------------------------- */
    status = set_flags(event, FALSE, FALSE);
    ok(status == STATUS_SUCCESS, "unprotect -> %08lx", (unsigned long)status);
    status = NtClose(event);
    ok(status == STATUS_SUCCESS, "close unprotected -> %08lx", (unsigned long)status);

    /* --- magic pseudo-handles: query yes (flags 0), set no ---------------- */
    memset(&flags, 0xcc, sizeof(flags));
    status = query_flags(NtCurrentProcess(), &flags, NULL);
    ok(status == STATUS_SUCCESS, "query magic -> %08lx", (unsigned long)status);
    ok(!flags.inherit && !flags.protect_from_close, "magic flags %u/%u", flags.inherit,
       flags.protect_from_close);
    status = set_flags(NtCurrentProcess(), TRUE, FALSE);
    ok(status == STATUS_ACCESS_DENIED, "set magic -> %08lx", (unsigned long)status);

    /* --- invalid handle -------------------------------------------------- */
    status = query_flags((HANDLE)(ULONG_PTR)0xdead0, &flags, NULL);
    ok(status == STATUS_INVALID_HANDLE, "query bad handle -> %08lx", (unsigned long)status);
    status = set_flags((HANDLE)(ULONG_PTR)0xdead0, FALSE, FALSE);
    ok(status == STATUS_INVALID_HANDLE, "set bad handle -> %08lx", (unsigned long)status);
}
