/*
 * syscall/ptr_torture.c — the pointer-torture matrix: every implemented
 * service, every pointer argument, every hostile address (issue #32 A1).
 *
 * WHAT THIS IS FOR, AND WHY IT LOOKS NOTHING LIKE THE TESTS NEXT DOOR.
 * Every other case under tests/ntapi/ asks the differential question — the
 * oracle says what a well-formed call means, and the kernel must agree. That
 * question has no answer for the largest defect class a kernel actually has:
 * Wine is not a kernel, has no ring boundary, and cannot be asked what
 * NtQueryEvent should do when handed a kernel address. The oracle is silent,
 * so the verdict rule changes:
 *
 *     the machine survives, the service returns, and the status is an
 *     ANSWER — never STATUS_NOT_IMPLEMENTED (Art. 12: unbuilt).
 *
 * It is a liveness property, not a semantics one, which is exactly why it
 * needs no oracle and why it is the quadrant the differential harness
 * structurally cannot reach. The three graders are:
 *
 *   this test  the call returned, and did not answer "unbuilt";
 *   uacheck.sh a service that touched a user address with no live probe
 *              behind it named itself on serial ([UACCESS], issue #32 A3) —
 *              which is the missing-probe defect itself, caught in the act;
 *   the boot   a panic or a park takes the leg down with it.
 *
 * The last two are the ones that convict. A missing probe does not change
 * this file's verdict — the recovery frame turns it into
 * STATUS_ACCESS_VIOLATION, which reads exactly like a correct refusal — it
 * changes uacheck's. So the two halves of issue #32's class A are one
 * instrument: A1 generates the hostile calls, A3 grades them.
 *
 * WHY IT IS GENERATED. The finding this answers was "exactly one site
 * probes" out of ~25 — a policy nobody wrote down, applied wherever someone
 * remembered. A hand-written suite is written by the same memory that missed
 * the probes, and would have the same holes in the same places. So the
 * enumeration comes from the machine: tools/gen_syscalls.py reads the pinned
 * Wine's own prototypes for every service in IMPLEMENTED and emits
 * torture_matrix.inc, one row of argument KINDS per service. Coverage is a
 * property of code generation, the way abi/ makes constant correctness one
 * (G4) — and a service added tomorrow is swept the day it lands, with nobody
 * remembering anything.
 *
 * WHAT IS NOT SWEPT, AND WHY THAT IS PRINTED. Ten services would end the
 * sweep rather than answer it (they terminate the caller, transfer control,
 * or power the machine off) and eight more park forever once a handle
 * argument is live. The generator carries both lists WITH REASONS and this
 * test prints every one as a skip: a sweep that quietly covers 90% of the
 * surface and reports "PASS" is the fabricated-plausible-answer shape Art. 12
 * forbids in the kernel, and it is no better in the instrument that judges it.
 *
 * ORACLE DISPOSITION. Skipped there, deliberately and in full. Not because
 * Wine would disagree — because it is not being asked a question: the leg
 * measures a usermode library's behaviour on garbage, which is neither a
 * contract this project owes nor evidence about the kernel. (G5's ordering
 * is untouched: no boundary SEMANTICS is pinned here. Nothing in this file
 * asserts what a status IS, only that one came back and that it is not the
 * unbuilt sentinel.)
 */
#include "../ntapi.h"

/* winternl.h omits these; declared as wine/include/winternl.h has them. */
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE, LONG *);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0)
#endif

/* The widest implemented service takes 14 arguments (NtCreateNamedPipeFile),
 * and on x64 there is one calling convention with a caller-cleaned stack, so
 * one 14-argument pointer type calls all of them. */
#define TORTURE_MAX_ARGS 14
typedef NTSTATUS(WINAPI *torture_fn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
                                     ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
                                     ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

struct torture_entry
{
    const char *name;
    unsigned argc;
    const char *kinds;  /* space-separated tokens; see torture_matrix.inc */
    int liveHandlePass; /* 0: invalid-handle pass only (it would park) */
};

static const struct torture_entry tortureEntries[] = {
#define KI_TORTURE(name, argc, kinds, live) {#name, (argc), (kinds), (live)},
#define KI_TORTURE_EXCLUDED(name, reason)
#define KI_TORTURE_NO_LIVE(name, reason)
#define KI_TORTURE_PARKED(name, reason)
#include "torture_matrix.inc"
#undef KI_TORTURE
#undef KI_TORTURE_EXCLUDED
#undef KI_TORTURE_NO_LIVE
#undef KI_TORTURE_PARKED
};

struct torture_note
{
    const char *name;
    const char *reason;
};

/* The two omission lists, printed rather than kept quiet (see the header). */
static const struct torture_note tortureExcluded[] = {
#define KI_TORTURE(name, argc, kinds, live)
#define KI_TORTURE_EXCLUDED(name, reason) {#name, (reason)},
#define KI_TORTURE_NO_LIVE(name, reason)
#define KI_TORTURE_PARKED(name, reason)
#include "torture_matrix.inc"
#undef KI_TORTURE
#undef KI_TORTURE_EXCLUDED
#undef KI_TORTURE_NO_LIVE
#undef KI_TORTURE_PARKED
};

static const struct torture_note tortureNoLive[] = {
#define KI_TORTURE(name, argc, kinds, live)
#define KI_TORTURE_EXCLUDED(name, reason)
#define KI_TORTURE_NO_LIVE(name, reason) {#name, (reason)},
#define KI_TORTURE_PARKED(name, reason)
#include "torture_matrix.inc"
#undef KI_TORTURE
#undef KI_TORTURE_EXCLUDED
#undef KI_TORTURE_NO_LIVE
#undef KI_TORTURE_PARKED
};

/* The ledger (see the generator's TORTURE_PARKED): services whose ORDINARY
 * arguments already reach unbuilt code, so the sweep cannot get as far as a
 * hostile one. Printed by every run — this is the backlog the matrix found,
 * and a debt nobody prints is a debt nobody pays. */
static const struct torture_note tortureParked[] = {
#define KI_TORTURE(name, argc, kinds, live)
#define KI_TORTURE_EXCLUDED(name, reason)
#define KI_TORTURE_NO_LIVE(name, reason)
#define KI_TORTURE_PARKED(name, reason) {#name, (reason)},
#include "torture_matrix.inc"
#undef KI_TORTURE
#undef KI_TORTURE_EXCLUDED
#undef KI_TORTURE_NO_LIVE
#undef KI_TORTURE_PARKED
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* ---- the hostile address set ------------------------------------------- */

/* Four consecutive pages, each a different way for a dereference to be wrong,
 * placed next to each other on purpose: the straddle case is only a straddle
 * because the page after the scratch one refuses. */
static char *torturePages;   /* [0] RW scratch  [1] NOACCESS
                                [2] READONLY    [3] reserved, uncommitted */
static char *tortureScratch; /* one committed RW page per argument slot */

/* A kernel address, a non-canonical one, and the first address at the top of
 * the user half.
 *
 * The first two are fixed by x86-64's 48-bit linear addressing (Intel SDM
 * Vol. 1 §3.3.7.1): an address is canonical when bits 63:48 copy bit 47, so
 * an all-ones top half is a KERNEL-half address and bit 47 set with 63:48
 * clear is the LOWEST non-canonical one — the same value and the same
 * citation as tests/ntapi/sem_ps/continue_bad_rip.c and
 * kernel/init/panic.c. Re-verify there. If either silently stopped being
 * what it claims, its axis would decay into an ordinary user address and
 * this sweep would report green while testing nothing.
 *
 * Cross-check for the third: third_party/wine dlls/ntdll/unix/virtual.c,
 * `user_space_limit = (void *)0x7fffffff0000` — the same limit
 * kernel/syscall/uaccess.h pins as KI_USER_SPACE_LIMIT. */
#define TORTURE_KERNEL_ADDRESS   ((ULONG_PTR)0xFFFFF80000000000ULL)
#define TORTURE_NONCANONICAL     ((ULONG_PTR)0x0000800000000000ULL)
#define TORTURE_USER_SPACE_LIMIT ((ULONG_PTR)0x00007FFFFFFF0000ULL)

#define TORTURE_PAGE 4096

struct torture_address
{
    const char *what;
    ULONG_PTR value;
};

static struct torture_address tortureAddresses[] = {
    {"null", 0},
    {"one", 1}, /* mapped by nothing, and misaligned for everything */
    {"kernel", TORTURE_KERNEL_ADDRESS},
    {"noncanonical", TORTURE_NONCANONICAL},
    {"reserved", 0}, /* filled in by torture_setup */
    {"noaccess", 0},
    {"readonly", 0},
    {"straddle", 0}, /* last 8 bytes of a page whose successor refuses */
    {"abovelimit", TORTURE_USER_SPACE_LIMIT - 4},
};
#define TORTURE_ADDRESS_COUNT ARRAY_SIZE(tortureAddresses)

/* The counted-string and object-attribute interiors: a WELL-FORMED descriptor
 * pointing somewhere hostile. This is the shape a service that probes its
 * argument and then trusts what it finds inside walks straight into, and it
 * is invisible to a sweep that only ever passes bad top-level pointers. */
static UNICODE_STRING tortureName;      /* valid, empty */
static UNICODE_STRING tortureBadString; /* rewritten per case */
static OBJECT_ATTRIBUTES tortureAttributes;
static OBJECT_ATTRIBUTES tortureBadAttributes;
static WCHAR tortureNameBuffer[8];

/* Handles: the invalid-handle pass hands every H argument a value that names
 * nothing, and the live pass hands it a SIGNALLED notification event — an
 * object whose wait returns immediately, so a service that reaches its wait
 * still returns to the sweep. NULL is never a handle argument here: for
 * NtTerminateProcess and friends it means "the current one", and a matrix
 * that shoots its own runner reports nothing about anything. */
#define TORTURE_DEAD_HANDLE ((HANDLE)(ULONG_PTR)0x1234)
static HANDLE tortureLiveHandle;

static unsigned long tortureCalls;
static unsigned long tortureNotImplemented;

static NTSTATUS torture_alloc(void **base, SIZE_T size, ULONG type, ULONG protect)
{
    *base = NULL;
    return NtAllocateVirtualMemory(NtCurrentProcess(), base, 0, &size, type, protect);
}

static int torture_setup(void)
{
    void *block = NULL;
    void *committed = NULL;
    SIZE_T size = 4 * TORTURE_PAGE;
    NTSTATUS status;

    /* One reservation, so the four pages are neighbours; the first three are
     * then committed with the protection each case needs and the fourth is
     * left reserved — an address that is legal and maps nothing. */
    status =
        NtAllocateVirtualMemory(NtCurrentProcess(), &block, 0, &size, MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || block == NULL)
        return 0;
    torturePages = block;

    committed = torturePages;
    size = TORTURE_PAGE;
    if (NtAllocateVirtualMemory(NtCurrentProcess(), &committed, 0, &size, MEM_COMMIT,
                                PAGE_READWRITE) != STATUS_SUCCESS)
        return 0;
    committed = torturePages + TORTURE_PAGE;
    size = TORTURE_PAGE;
    if (NtAllocateVirtualMemory(NtCurrentProcess(), &committed, 0, &size, MEM_COMMIT,
                                PAGE_NOACCESS) != STATUS_SUCCESS)
        return 0;
    committed = torturePages + 2 * TORTURE_PAGE;
    size = TORTURE_PAGE;
    if (NtAllocateVirtualMemory(NtCurrentProcess(), &committed, 0, &size, MEM_COMMIT,
                                PAGE_READONLY) != STATUS_SUCCESS)
        return 0;

    if (torture_alloc((void **)&tortureScratch, (SIZE_T)TORTURE_MAX_ARGS * TORTURE_PAGE,
                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != STATUS_SUCCESS)
        return 0;

    tortureAddresses[4].value = (ULONG_PTR)(torturePages + 3 * TORTURE_PAGE);
    tortureAddresses[5].value = (ULONG_PTR)(torturePages + TORTURE_PAGE);
    tortureAddresses[6].value = (ULONG_PTR)(torturePages + 2 * TORTURE_PAGE);
    tortureAddresses[7].value = (ULONG_PTR)(torturePages + TORTURE_PAGE - 8);

    tortureNameBuffer[0] = 0;
    tortureName.Length = 0;
    tortureName.MaximumLength = sizeof(tortureNameBuffer);
    tortureName.Buffer = tortureNameBuffer;

    /* The baseline block is the most ORDINARY one there is: anonymous. A
     * name in it would be a second variable in every call that is not about
     * names, and the name paths lose nothing — the O-kind interiors below
     * put a hostile ObjectName in this same block, and every explicit
     * PUNICODE_STRING argument is swept in its own right. */
    tortureAttributes.Length = sizeof(tortureAttributes);
    tortureAttributes.RootDirectory = NULL;
    tortureAttributes.ObjectName = NULL;
    tortureAttributes.Attributes = 0;
    tortureAttributes.SecurityDescriptor = NULL;
    tortureAttributes.SecurityQualityOfService = NULL;
    return 1;
}

/* The live handle is re-minted before every service, because the sweep hands
 * it to NtClose among others and a stale one would silently demote the rest
 * of the live pass to a second invalid-handle pass. */
static void torture_refresh_live_handle(void)
{
    LONG previous = 0;

    if (tortureLiveHandle != NULL && NtSetEvent(tortureLiveHandle, &previous) == STATUS_SUCCESS)
        return;
    tortureLiveHandle = NULL;
    if (NtCreateEvent(&tortureLiveHandle, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */,
                      TRUE) != STATUS_SUCCESS)
        tortureLiveHandle = NULL;
}

/* ---- one call ----------------------------------------------------------- */

/* The service currently under the sweep, with its kinds token string parsed
 * out: one kind letter per argument, plus the pinned value of a class
 * argument. One service runs at a time, so this is the whole state. */
static char tortureKind[TORTURE_MAX_ARGS];
static ULONG_PTR tortureClass[TORTURE_MAX_ARGS];
/* How much of an argument's axis the ledger left standing. A lowercase token
 * parks it (the argument still takes its baseline); a lowercase token with a
 * '+' parks only the DESCRIPTOR INTERIORS, which is the narrowest park there
 * is — the hostile-address sweep, the part this whole matrix is for, still
 * runs over that argument. */
#define TORTURE_SWEEP_NONE      0
#define TORTURE_SWEEP_ADDRESSES 1
#define TORTURE_SWEEP_FULL      2
static int tortureSweep[TORTURE_MAX_ARGS];

/* "H P P S C4" -> kinds {H,P,P,S,C} with class[4] = 4. A token the generator
 * cannot produce is a generator/driver disagreement, so it is reported rather
 * than defaulted into something plausible. */
static int torture_parse_kinds(const struct torture_entry *entry)
{
    const char *cursor = entry->kinds;
    unsigned i;

    for (i = 0; i < entry->argc; i++)
    {
        while (*cursor == ' ')
            cursor++;
        if (*cursor == 0)
            return 0;
        tortureKind[i] = *cursor++;
        tortureSweep[i] = tortureKind[i] >= 'A' && tortureKind[i] <= 'Z'
                              ? TORTURE_SWEEP_FULL
                              : TORTURE_SWEEP_NONE;
        if (tortureSweep[i] == TORTURE_SWEEP_NONE)
            tortureKind[i] = (char)(tortureKind[i] - 'a' + 'A');
        tortureClass[i] = 0;
        while (*cursor >= '0' && *cursor <= '9')
            tortureClass[i] = tortureClass[i] * 10 + (ULONG_PTR)(*cursor++ - '0');
        if (*cursor == '+')
        {
            cursor++;
            tortureSweep[i] = TORTURE_SWEEP_ADDRESSES;
        }
        switch (tortureKind[i])
        {
        case 'S':
        case 'H':
        case 'P':
        case 'U':
        case 'O':
        case 'F':
        case 'C':
            break;
        default:
            return 0;
        }
    }
    while (*cursor == ' ')
        cursor++;
    return *cursor == 0;
}

/* The baseline every argument gets when it is not the one under torture:
 * something well-formed, so the service runs far enough to reach the argument
 * that is not. */
static ULONG_PTR torture_baseline(unsigned index, HANDLE handle)
{
    switch (tortureKind[index])
    {
    case 'H':
        return (ULONG_PTR)handle;
    case 'P':
        return (ULONG_PTR)(tortureScratch + (SIZE_T)index * TORTURE_PAGE);
    case 'U':
        return (ULONG_PTR)&tortureName;
    case 'O':
        return (ULONG_PTR)&tortureAttributes;
    case 'C': /* a class the kernel builds, held still — see CLASS_TYPES */
        return tortureClass[index];
    case 'F': /* a ring-3 routine: NULL is the ordinary value and the safe one */
    case 'S':
    default:
        return 0;
    }
}

static NTSTATUS torture_call(torture_fn fn, const struct torture_entry *entry, HANDLE handle,
                             unsigned victim, ULONG_PTR value)
{
    ULONG_PTR args[TORTURE_MAX_ARGS];
    unsigned i;

    for (i = 0; i < TORTURE_MAX_ARGS; i++)
        args[i] = i < entry->argc ? torture_baseline(i, handle) : 0;
    args[victim] = value;

    /* The out-parameter scratch is wiped per call: a service that writes into
     * the previous call's buffer must not find its own leftovers there. */
    for (i = 0; i < entry->argc; i++)
        if (tortureKind[i] == 'P' && i != victim)
            memset(tortureScratch + (SIZE_T)i * TORTURE_PAGE, 0, TORTURE_PAGE);

    tortureCalls++;
    return fn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
              args[9], args[10], args[11], args[12], args[13]);
}

static void torture_grade(const struct torture_entry *entry, unsigned victim, const char *what,
                          NTSTATUS status)
{
    if (status != STATUS_NOT_IMPLEMENTED)
        return;
    /* Art. 12: unbuilt is not an answer a ring-3 caller may be given, and a
     * hostile argument is the one input every service must have an answer
     * for. Reported per case — the argument and the address are the repro. */
    tortureNotImplemented++;
    ok(0, "%s arg %u %s: STATUS_NOT_IMPLEMENTED", entry->name, victim, what);
}

/* Every hostile ADDRESS, in the argument slot named by `victim`. */
static void torture_addresses(torture_fn fn, const struct torture_entry *entry, HANDLE handle,
                              unsigned victim)
{
    unsigned i;

    for (i = 0; i < TORTURE_ADDRESS_COUNT; i++)
        torture_grade(entry, victim, tortureAddresses[i].what,
                      torture_call(fn, entry, handle, victim, tortureAddresses[i].value));
}

/* A well-formed UNICODE_STRING whose INTERIOR is hostile: the buffer points
 * somewhere it must not be read from, or the counts describe more memory than
 * exists (the straddle buffer makes an over-long Length fault on the second
 * page rather than reading 64 KiB of somebody's heap). */
static void torture_string_interiors(torture_fn fn, const struct torture_entry *entry,
                                     HANDLE handle, unsigned victim)
{
    ULONG_PTR value = (ULONG_PTR)&tortureBadString;
    unsigned i;

    for (i = 0; i < TORTURE_ADDRESS_COUNT; i++)
    {
        tortureBadString.Length = 8;
        tortureBadString.MaximumLength = 8;
        tortureBadString.Buffer = (WCHAR *)(ULONG_PTR)tortureAddresses[i].value;
        torture_grade(entry, victim, tortureAddresses[i].what,
                      torture_call(fn, entry, handle, victim, value));
    }

    tortureBadString.Length = 0xFFFE;
    tortureBadString.MaximumLength = 0xFFFE;
    tortureBadString.Buffer = (WCHAR *)(ULONG_PTR)tortureAddresses[7].value;
    torture_grade(entry, victim, "string:lyinglength",
                  torture_call(fn, entry, handle, victim, value));

    tortureBadString.Length = 1; /* odd: never a whole number of WCHARs */
    tortureBadString.MaximumLength = 2;
    tortureBadString.Buffer = tortureNameBuffer;
    torture_grade(entry, victim, "string:oddlength",
                  torture_call(fn, entry, handle, victim, value));

    tortureBadString.Length = 8; /* Length past MaximumLength */
    tortureBadString.MaximumLength = 4;
    tortureBadString.Buffer = tortureNameBuffer;
    torture_grade(entry, victim, "string:overmax", torture_call(fn, entry, handle, victim, value));
}

/* The same idea one level further in: OBJECT_ATTRIBUTES is a descriptor whose
 * every member is a second thing to trust. */
static void torture_attribute_interiors(torture_fn fn, const struct torture_entry *entry,
                                        HANDLE handle, unsigned victim)
{
    ULONG_PTR value = (ULONG_PTR)&tortureBadAttributes;
    unsigned i;

    for (i = 0; i < TORTURE_ADDRESS_COUNT; i++)
    {
        tortureBadAttributes = tortureAttributes;
        tortureBadAttributes.ObjectName = (UNICODE_STRING *)(ULONG_PTR)tortureAddresses[i].value;
        torture_grade(entry, victim, tortureAddresses[i].what,
                      torture_call(fn, entry, handle, victim, value));

        tortureBadAttributes = tortureAttributes;
        tortureBadAttributes.SecurityDescriptor = (void *)(ULONG_PTR)tortureAddresses[i].value;
        torture_grade(entry, victim, tortureAddresses[i].what,
                      torture_call(fn, entry, handle, victim, value));

        tortureBadAttributes = tortureAttributes;
        tortureBadAttributes.SecurityQualityOfService =
            (void *)(ULONG_PTR)tortureAddresses[i].value;
        torture_grade(entry, victim, tortureAddresses[i].what,
                      torture_call(fn, entry, handle, victim, value));
    }

    tortureBadAttributes = tortureAttributes;
    tortureBadString.Length = 0xFFFE;
    tortureBadString.MaximumLength = 0xFFFE;
    tortureBadString.Buffer = (WCHAR *)(ULONG_PTR)tortureAddresses[7].value;
    tortureBadAttributes.ObjectName = &tortureBadString;
    torture_grade(entry, victim, "objattr:lyingname",
                  torture_call(fn, entry, handle, victim, value));

    tortureBadAttributes = tortureAttributes;
    tortureBadAttributes.Length = 0;
    torture_grade(entry, victim, "objattr:zerolength",
                  torture_call(fn, entry, handle, victim, value));

    tortureBadAttributes = tortureAttributes;
    tortureBadAttributes.Length = 0xFFFFFFFF;
    torture_grade(entry, victim, "objattr:hugelength",
                  torture_call(fn, entry, handle, victim, value));

    tortureBadAttributes = tortureAttributes;
    tortureBadAttributes.RootDirectory = TORTURE_DEAD_HANDLE;
    torture_grade(entry, victim, "objattr:deadroot",
                  torture_call(fn, entry, handle, victim, value));
}

/* Saturated scalars. A length argument is a scalar, and the pointer it
 * describes is well-formed in these cases — so "0xFFFFFFFF bytes into a
 * 4 KiB buffer" is a question about whether the LENGTH was probed, which no
 * bad address can ask. */
static void torture_scalars(torture_fn fn, const struct torture_entry *entry, HANDLE handle,
                            unsigned victim)
{
    torture_grade(entry, victim, "scalar:0xffffffff",
                  torture_call(fn, entry, handle, victim, (ULONG_PTR)0xFFFFFFFFUL));
    torture_grade(entry, victim, "scalar:saturated",
                  torture_call(fn, entry, handle, victim, ~(ULONG_PTR)0));
}

static void torture_service(torture_fn fn, const struct torture_entry *entry, HANDLE handle)
{
    unsigned victim;

    for (victim = 0; victim < entry->argc; victim++)
    {
        if (tortureSweep[victim] == TORTURE_SWEEP_NONE)
        {
            continue; /* parked axis — the baseline is all this argument gets */
        }
        int interiors = tortureSweep[victim] == TORTURE_SWEEP_FULL;
        switch (tortureKind[victim])
        {
        case 'P':
            torture_addresses(fn, entry, handle, victim);
            break;
        case 'U':
            torture_addresses(fn, entry, handle, victim);
            if (interiors)
                torture_string_interiors(fn, entry, handle, victim);
            break;
        case 'O':
            torture_addresses(fn, entry, handle, victim);
            if (interiors)
                torture_attribute_interiors(fn, entry, handle, victim);
            break;
        case 'S':
            if (interiors) /* a scalar has no interior; a park is a park */
                torture_scalars(fn, entry, handle, victim);
            break;
        case 'H': /* baselines only — see TORTURE_DEAD_HANDLE */
        case 'C': /* held still — see the generator's CLASS_TYPES */
        case 'F': /* never dereferenced by the kernel; NULL is the whole story */
        default:
            break;
        }
    }
}

START_TEST(ptr_torture)
{
    HMODULE ntdll;
    unsigned i;
    unsigned swept = 0;
    unsigned unresolved = 0;

    if (!ntapi_ctx.on_proskrnl)
    {
        /* See the header: the oracle is not being asked a question here. */
        skip("pointer torture is a proskrnl liveness sweep; the oracle has no "
             "ring boundary and nothing to say about a kernel address");
        return;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    ok(ntdll != NULL, "ntdll.dll module handle");
    if (ntdll == NULL)
        return;

    ok(torture_setup() != 0, "hostile address set built");
    if (torturePages == NULL || tortureScratch == NULL)
        return;

    for (i = 0; i < ARRAY_SIZE(tortureExcluded); i++)
        skip("%s not swept: %s", tortureExcluded[i].name, tortureExcluded[i].reason);
    for (i = 0; i < ARRAY_SIZE(tortureNoLive); i++)
        skip("%s swept with invalid handles only: %s", tortureNoLive[i].name,
             tortureNoLive[i].reason);
    for (i = 0; i < ARRAY_SIZE(tortureParked); i++)
        skip("%s parked (owed): %s", tortureParked[i].name, tortureParked[i].reason);

    for (i = 0; i < ARRAY_SIZE(tortureEntries); i++)
    {
        const struct torture_entry *entry = &tortureEntries[i];
        torture_fn fn = (torture_fn)(void *)GetProcAddress(ntdll, entry->name);
        LARGE_INTEGER now;

        /* A service the matrix names but ntdll does not export cannot be
         * swept, and must not pass for having been: it is counted and
         * asserted on at the end. */
        if (fn == NULL)
        {
            unresolved++;
            ok(0, "%s: no ntdll export to call", entry->name);
            continue;
        }
        if (entry->argc == 0)
        {
            continue; /* nothing to torture (NtTestAlert, NtYieldExecution) */
        }
        if (entry->argc > TORTURE_MAX_ARGS)
        {
            ok(0, "%s: %u arguments exceeds the dispatch maximum", entry->name, entry->argc);
            continue;
        }
        if (!torture_parse_kinds(entry))
        {
            ok(0, "%s: unparseable kinds '%s'", entry->name, entry->kinds);
            continue;
        }

        torture_service(fn, entry, TORTURE_DEAD_HANDLE);
        if (entry->liveHandlePass)
        {
            torture_refresh_live_handle();
            if (tortureLiveHandle != NULL)
                torture_service(fn, entry, tortureLiveHandle);
        }
        swept++;

        /* The machine is still answering. A service that wedged the kernel
         * short of a panic would otherwise be indistinguishable from one that
         * refused politely, and the next service's results would be noise. */
        now.QuadPart = 0;
        ok(NtQuerySystemTime(&now) == STATUS_SUCCESS && now.QuadPart != 0,
           "system time still answers after %s", entry->name);
    }

    ok(unresolved == 0, "every swept service resolved in ntdll (%u did not)", unresolved);
    ok(tortureNotImplemented == 0, "no service answered STATUS_NOT_IMPLEMENTED (%lu did)",
       tortureNotImplemented);
    ntapi_printf(
        "ptr_torture: %u services, %lu hostile calls, %u excluded, %u invalid-handle only, "
        "%u parked\n",
        swept, tortureCalls, (unsigned)ARRAY_SIZE(tortureExcluded),
        (unsigned)ARRAY_SIZE(tortureNoLive), (unsigned)ARRAY_SIZE(tortureParked));
    /* A sweep that made no calls is a harness failure wearing a green shirt. */
    ok(tortureCalls > 1000, "the sweep actually ran (%lu calls)", tortureCalls);
}
