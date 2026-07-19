/*
 * interp.c — the differential-fuzzer interpreter (docs/08 "Differential
 * fuzzing"; tests/fuzz/README.md).
 *
 * One source, two build modes — exactly like every ntapi test (docs/14):
 *   NTAPI_ORACLE    a Windows PE .exe; Nt* from the host ntdll (run under the
 *                   pinned third_party/wine); contract headers = the oracle's.
 *   NTAPI_PROSKRNL  a freestanding flat binary; Nt* from tests/ntapi/syscall/;
 *                   contract headers = generated abi/.
 *
 * It decodes a compact program blob (built into the binary as fuzz_programs[]
 * by tests/fuzz/fuzz.py) and runs each program's Nt* call sequence, printing
 * ONE normalized [FUZZ] trace line per call. The line carries only
 * cross-implementation-stable data: never a raw handle or address (those
 * differ by ASLR / VA layout), only slot-occupancy flags and the contract
 * payload (statuses, previous-states, counts, info-class fields, lengths).
 * fuzz.py diffs the two sides' [FUZZ] streams verbatim; a difference is a bug.
 *
 * The decode is table-driven from tests/fuzz/gen/fuzz_model.h (generated with
 * the same tools/gen_syscalls.py that emits the syscall table), so this
 * interpreter and the Python generator cannot drift. Only the per-op EXECUTE
 * switch below is hand-written.
 *
 * Determinism: single-threaded, every wait is zero-timeout (never blocks), no
 * NtDisplayString / NtTerminateProcess opcodes (the harness owns output+exit).
 */
#include "ntapi.h"
#include "sem_ob/util.h" /* Nt* prototypes (oracle), abi (proskrnl), init_ustr/init_attr, ob_* structs */
#if defined(NTAPI_PROSKRNL)
#include "abi/ntioapi.h" /* the M6 file surface (must precede fuzz_model.h) */
#include "abi/ntmmapi.h" /* PAGE_* for the protect op (must precede fuzz_model.h) */
#include "abi/ntpsapi.h" /* NtQueryInformationProcess + PROCESS_BASIC_INFORMATION */
#endif
#include "tests/fuzz/gen/fuzz_model.h" /* FzOpcode, fz_ops[], choice tables */

#if defined(NTAPI_ORACLE)
/* Prototypes winternl.h omits (as wine/include/winternl.h declares them). */
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, PULONG);
#endif

/* The program blob, emitted by fuzz.py as build/tests/fuzz/fuzz_programs.c and
 * linked in. Format (little-endian): "PFZ1", u32 program_count, then per
 * program { u32 id, u16 call_count, calls }, each call { u8 opcode, u8 per
 * operand } per fz_ops[opcode]. */
extern const unsigned char fuzz_programs[];
extern const unsigned int fuzz_programs_len;

/* Object names the interpreter can pass; index 0 = anonymous (no name). Order
 * and tags MUST match FUZZ_NAMES in tools/gen_syscalls.py (the static_assert on
 * the count is the tripwire if they drift). These are test object names, not an
 * ABI contract, so they live here as u"" (char16_t) literals — 2 bytes/unit in
 * both build modes, as the sem_ob tests spell them. */
static const void *fz_names[FZ_NAME_COUNT] = {
    NULL,                                /* none / anonymous              */
    W("\\BaseNamedObjects\\fz0"),        /* valid                         */
    W("\\BaseNamedObjects\\fz1"),        /* valid                         */
    W("\\BaseNamedObjects\\fz2"),        /* valid                         */
    W("\\BaseNamedObjects\\fz3"),        /* valid                         */
    W("\\BaseNamedObjects\\fzsub"),      /* subdir (create as directory)  */
    W("\\BaseNamedObjects\\fzsub\\fz4"), /* item under the subdir         */
    W("fz_relative"),                    /* bad: no leading backslash     */
    W(""),                               /* bad: empty                    */
    W("\\BaseNamedObjects\\fznodir\\x"), /* bad: missing directory        */
    W("\\"),                             /* the namespace root            */
    W("\\BaseNamedObjects"),             /* an existing directory itself  */
};
_Static_assert(sizeof(fz_names) / sizeof(fz_names[0]) == FZ_NAME_COUNT,
               "fz_names must match FUZZ_NAMES in tools/gen_syscalls.py");

/* M6 file paths; order/tags MUST match FUZZ_FILE_NAMES in tools/gen_syscalls.py. */
static const void *fz_fnames[FZ_FNAME_COUNT] = {
    W("\\??\\C:\\fuzz\\fa.dat"),
    W("\\??\\C:\\fuzz\\fb.dat"),
    W("\\??\\C:\\fuzz\\Fuzz Long Name.Dat"),
    W("\\??\\C:\\fuzz\\nodir\\x.dat"),
};

#if defined(NTAPI_ORACLE)
/* File-surface prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
#endif

/* iolen / iooff shape indices (semantic tables; see FUZZ_CHOICES). */
enum
{
    FZ_IOLEN_ZERO = 0,
    FZ_IOLEN_ONE,
    FZ_IOLEN_MID,
    FZ_IOLEN_BIG
};
enum
{
    FZ_IOOFF_ZERO = 0,
    FZ_IOOFF_ONE,
    FZ_IOOFF_SECTOR,
    FZ_IOOFF_FAR
};

static ULONG fz_iolen(unsigned shape)
{
    switch (shape)
    {
    case FZ_IOLEN_ONE:
        return 1;
    case FZ_IOLEN_MID:
        return 100;
    case FZ_IOLEN_BIG:
        return 5000;
    default:
        return 0;
    }
}

static unsigned long long fz_iooff(unsigned shape)
{
    switch (shape)
    {
    case FZ_IOOFF_ONE:
        return 1;
    case FZ_IOOFF_SECTOR:
        return 512;
    case FZ_IOOFF_FAR:
        return 8192;
    default:
        return 0;
    }
}

/* Length-shape indices for ch_len (semantic table; see FUZZ_CHOICES["len"]). */
enum
{
    FZ_LEN_EXACT = 0,
    FZ_LEN_ZERO,
    FZ_LEN_SHORT,
    FZ_LEN_LONG
};

/* ---- interpreter state -------------------------------------------------- */

static HANDLE fz_slots[FZ_SLOT_COUNT];

static void fz_bzero(void *p, unsigned long n)
{
    unsigned char *b = (unsigned char *)p;
    for (unsigned long i = 0; i < n; i++)
        b[i] = 0;
}

/* Close every open slot between programs so named objects do not survive into
 * the next program — keeps programs independent and the trace deterministic. */
static void fz_reset_slots(void)
{
    for (int i = 0; i < FZ_SLOT_COUNT; i++)
    {
        if (fz_slots[i] != NULL)
        {
            NtClose(fz_slots[i]);
            fz_slots[i] = NULL;
        }
    }
}

/* Forward decls: reset/setup for the M6 fuzz files (defined below) and the
 * success predicate they use. */
static int fz_ok(NTSTATUS st);
static void fz_reset_files(void);
static void fz_setup_files(void);

/* Scrub the fuzz files between programs (files, unlike handles, persist) and
 * make sure \??\C:\fuzz exists before the first program. Uses only the
 * file surface both sides implement. */
static void fz_setup_files(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = NULL;
    init_ustr(&name, W("\\??\\C:\\fuzz"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    NTSTATUS st =
        NtCreateFile(&dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, NULL,
                     FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                     FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (fz_ok(st))
        NtClose(dir);
}

static void fz_reset_files(void)
{
    for (int i = 0; i < FZ_FNAME_COUNT; i++)
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        IO_STATUS_BLOCK iosb;
        HANDLE handle = NULL;
        init_ustr(&name, fz_fnames[i]);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        NTSTATUS st = NtCreateFile(
            &handle, DELETE | SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (fz_ok(st))
            NtClose(handle);
    }
}

/* A committed private scratch region for the M7 NtProtectVirtualMemory op: one
 * VAD, fully committed, allocated once and reset to PAGE_READWRITE at each
 * program start so protection state does not leak between programs. Its base
 * differs across implementations (ASLR) and is never traced — only the status
 * and the reported previous protection are contract. */
#define FZ_PROTECT_REGION_SIZE 0x4000
static void *fz_protect_base;

static void fz_setup_protect(void)
{
    SIZE_T size = FZ_PROTECT_REGION_SIZE;
    fz_protect_base = NULL;
    NtAllocateVirtualMemory(NtCurrentProcess(), &fz_protect_base, 0, &size,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

static void fz_reset_protect(void)
{
    if (fz_protect_base != NULL)
    {
        void *base = fz_protect_base;
        SIZE_T size = FZ_PROTECT_REGION_SIZE;
        ULONG oldProtect = 0;
        NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_READWRITE, &oldProtect);
    }
}

/* Fill OBJECT_ATTRIBUTES for a name index; index 0 → anonymous (NULL name). */
static POBJECT_ATTRIBUTES fz_build_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *ustr,
                                        unsigned nameIndex, ULONG objFlags)
{
    if (nameIndex == 0 || fz_names[nameIndex] == NULL)
    {
        init_attr(attr, NULL, NULL, objFlags);
        return attr;
    }
    init_ustr(ustr, fz_names[nameIndex]);
    init_attr(attr, NULL, ustr, objFlags);
    return attr;
}

/* Resolve one operand byte to its value: slot/name kinds → an index, choice
 * kinds → the symbolic constant from the generated table (or, for ch_len, the
 * shape index). The value space per kind is fixed by the model. */
static unsigned long long fz_resolve(FzOperandKind kind, unsigned char b)
{
    switch (kind)
    {
    case FZ_OPND_SLOT_IN:
    case FZ_OPND_SLOT_OUT:
        return b % FZ_SLOT_COUNT;
    case FZ_OPND_NAME:
        return b % FZ_NAME_COUNT;
    case FZ_OPND_CH_ACCESS_EVENT:
        return fz_ch_access_event[b % FZ_CH_ACCESS_EVENT_COUNT];
    case FZ_OPND_CH_ACCESS_MUTANT:
        return fz_ch_access_mutant[b % FZ_CH_ACCESS_MUTANT_COUNT];
    case FZ_OPND_CH_ACCESS_SEMAPHORE:
        return fz_ch_access_semaphore[b % FZ_CH_ACCESS_SEMAPHORE_COUNT];
    case FZ_OPND_CH_ACCESS_DIRECTORY:
        return fz_ch_access_directory[b % FZ_CH_ACCESS_DIRECTORY_COUNT];
    case FZ_OPND_CH_ACCESS_SYMLINK:
        return fz_ch_access_symlink[b % FZ_CH_ACCESS_SYMLINK_COUNT];
    case FZ_OPND_CH_OBJFLAGS:
        return fz_ch_objflags[b % FZ_CH_OBJFLAGS_COUNT];
    case FZ_OPND_CH_EVENT_TYPE:
        return fz_ch_event_type[b % FZ_CH_EVENT_TYPE_COUNT];
    case FZ_OPND_CH_BOOL:
        return fz_ch_bool[b % FZ_CH_BOOL_COUNT];
    case FZ_OPND_CH_LONG:
        return (unsigned long long)(long long)fz_ch_long[b % FZ_CH_LONG_COUNT];
    case FZ_OPND_CH_ULONG:
        return fz_ch_ulong[b % FZ_CH_ULONG_COUNT];
    case FZ_OPND_CH_WAIT_TYPE:
        return fz_ch_wait_type[b % FZ_CH_WAIT_TYPE_COUNT];
    case FZ_OPND_CH_DUP_OPTIONS:
        return fz_ch_dup_options[b % FZ_CH_DUP_OPTIONS_COUNT];
    case FZ_OPND_CH_LEN:
        return b % FZ_CH_LEN_COUNT;
    case FZ_OPND_FNAME:
        return b % FZ_FNAME_COUNT;
    case FZ_OPND_CH_ACCESS_FILE:
        return fz_ch_access_file[b % FZ_CH_ACCESS_FILE_COUNT];
    case FZ_OPND_CH_SHARE_FILE:
        return fz_ch_share_file[b % FZ_CH_SHARE_FILE_COUNT];
    case FZ_OPND_CH_DISPOSITION_FILE:
        return fz_ch_disposition_file[b % FZ_CH_DISPOSITION_FILE_COUNT];
    case FZ_OPND_CH_IOLEN:
        return b % FZ_CH_IOLEN_COUNT;
    case FZ_OPND_CH_IOOFF:
        return b % FZ_CH_IOOFF_COUNT;
    case FZ_OPND_CH_PROTECT_PAGE:
        return fz_ch_protect_page[b % FZ_CH_PROTECT_PAGE_COUNT];
    }
    return 0;
}

/* NtQuery* buffer length for a shape, given the natural struct size. */
static ULONG fz_query_len(unsigned shape, ULONG structSize)
{
    switch (shape)
    {
    case FZ_LEN_ZERO:
        return 0;
    case FZ_LEN_SHORT:
        return structSize > 0 ? structSize - 1 : 0;
    case FZ_LEN_LONG:
        return structSize + 16;
    case FZ_LEN_EXACT:
    default:
        return structSize;
    }
}

/* NT_SUCCESS: a success or informational status (high bit clear). NT writes a
 * call's output parameters ONLY on such a status; on an error the outputs are
 * indeterminate and are NOT part of the contract — so the trace must print them
 * only when fz_ok() holds, else two implementations' incidental error-path
 * writes (e.g. Wine touching PreviousCount on STATUS_INVALID_HANDLE) would read
 * as false divergences. Below the status line, only success carries payload. */
static int fz_ok(NTSTATUS st)
{
    return st >= 0;
}

/* A handle-yielding create/open: on success print slot occupancy (never the
 * handle value — that differs by implementation); on failure, status only. */
static void fz_trace_handle(unsigned prog, unsigned call, const char *nt, NTSTATUS st,
                            unsigned slot, HANDLE h)
{
    if (fz_ok(st))
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x h%u=%d\n", prog, call, nt, (unsigned)st, slot,
                     h != NULL ? 1 : 0);
    else
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
}

/* A previous-state op (set/reset/pulse event, release mutant/semaphore): the
 * previous count is contract only on success. */
static void fz_trace_prev(unsigned prog, unsigned call, const char *nt, NTSTATUS st, LONG prev)
{
    if (fz_ok(st))
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x prev=%d\n", prog, call, nt, (unsigned)st,
                     (int)prev);
    else
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
}

/* ---- execute one call --------------------------------------------------- */

static void fz_exec(unsigned prog, unsigned call, int op, const unsigned long long *a)
{
    const char *nt = fz_ops[op].nt_name;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING ustr;
    NTSTATUS st;
    HANDLE h;

    switch (op)
    {
    case FZ_OP_CREATE_EVENT:
        h = NULL;
        st = NtCreateEvent(&h, (ACCESS_MASK)a[1],
                           fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]),
                           (EVENT_TYPE)a[4], (BOOLEAN)a[5]);
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_OPEN_EVENT:
        h = NULL;
        st = NtOpenEvent(&h, (ACCESS_MASK)a[1],
                         fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_SET_EVENT:
    {
        LONG prev = 0;
        st = NtSetEvent(fz_slots[a[0]], &prev);
        fz_trace_prev(prog, call, nt, st, prev);
        break;
    }
    case FZ_OP_RESET_EVENT:
    {
        LONG prev = 0;
        st = NtResetEvent(fz_slots[a[0]], &prev);
        fz_trace_prev(prog, call, nt, st, prev);
        break;
    }
    case FZ_OP_PULSE_EVENT:
    {
        LONG prev = 0;
        st = NtPulseEvent(fz_slots[a[0]], &prev);
        fz_trace_prev(prog, call, nt, st, prev);
        break;
    }
    case FZ_OP_CLEAR_EVENT:
        st = NtClearEvent(fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_QUERY_EVENT:
    {
        unsigned char buf[64];
        ULONG retLen = 0;
        fz_bzero(buf, sizeof buf);
        st =
            NtQueryEvent(fz_slots[a[0]], EVENT_BASIC_INFO_CLASS, buf,
                         fz_query_len((unsigned)a[1], (ULONG)sizeof(ob_event_basic_info)), &retLen);
        if (fz_ok(st))
        {
            const ob_event_basic_info *info = (const ob_event_basic_info *)buf;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u type=%d state=%d\n", prog, call, nt,
                         (unsigned)st, (unsigned)retLen, (int)info->event_type,
                         (int)info->event_state);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CREATE_MUTANT:
        h = NULL;
        st =
            NtCreateMutant(&h, (ACCESS_MASK)a[1],
                           fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]), (BOOLEAN)a[4]);
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_OPEN_MUTANT:
        h = NULL;
        st = NtOpenMutant(&h, (ACCESS_MASK)a[1],
                          fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_RELEASE_MUTANT:
    {
        LONG prev = 0;
        st = NtReleaseMutant(fz_slots[a[0]], &prev);
        fz_trace_prev(prog, call, nt, st, prev);
        break;
    }
    case FZ_OP_QUERY_MUTANT:
    {
        unsigned char buf[64];
        ULONG retLen = 0;
        fz_bzero(buf, sizeof buf);
        st = NtQueryMutant(fz_slots[a[0]], MUTANT_BASIC_INFO_CLASS, buf,
                           fz_query_len((unsigned)a[1], (ULONG)sizeof(ob_mutant_basic_info)),
                           &retLen);
        if (fz_ok(st))
        {
            const ob_mutant_basic_info *info = (const ob_mutant_basic_info *)buf;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u count=%d owned=%d abandoned=%d\n", prog,
                         call, nt, (unsigned)st, (unsigned)retLen, (int)info->current_count,
                         (int)info->owned_by_caller, (int)info->abandoned_state);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CREATE_SEMAPHORE:
        h = NULL;
        st = NtCreateSemaphore(&h, (ACCESS_MASK)a[1],
                               fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]), (LONG)a[4],
                               (LONG)a[5]);
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_OPEN_SEMAPHORE:
        h = NULL;
        st = NtOpenSemaphore(&h, (ACCESS_MASK)a[1],
                             fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_RELEASE_SEMAPHORE:
    {
        LONG prev = 0;
        st = NtReleaseSemaphore(fz_slots[a[0]], (ULONG)a[1], (PULONG)&prev);
        fz_trace_prev(prog, call, nt, st, prev);
        break;
    }
    case FZ_OP_QUERY_SEMAPHORE:
    {
        unsigned char buf[64];
        ULONG retLen = 0;
        fz_bzero(buf, sizeof buf);
        st = NtQuerySemaphore(fz_slots[a[0]], SEMAPHORE_BASIC_INFO_CLASS, buf,
                              fz_query_len((unsigned)a[1], (ULONG)sizeof(ob_semaphore_basic_info)),
                              &retLen);
        if (fz_ok(st))
        {
            const ob_semaphore_basic_info *info = (const ob_semaphore_basic_info *)buf;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u count=%u max=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)retLen, (unsigned)info->current_count,
                         (unsigned)info->maximum_count);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_WAIT_SINGLE:
        st = wait_now(fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_WAIT_MULTIPLE:
    {
        HANDLE hs[2];
        LARGE_INTEGER zero;
        zero.QuadPart = 0;
        hs[0] = fz_slots[a[0]];
        hs[1] = fz_slots[a[1]];
        st = NtWaitForMultipleObjects(2, hs, (WAIT_TYPE)a[2], FALSE, &zero);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CLOSE:
        st = NtClose(fz_slots[a[0]]);
        if (fz_ok(st))
            fz_slots[a[0]] = NULL;
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_DUPLICATE:
        h = NULL;
        st = NtDuplicateObject(NtCurrentProcess(), fz_slots[a[0]], NtCurrentProcess(), &h,
                               (ACCESS_MASK)a[2], 0, (ULONG)a[3]);
        if (fz_ok(st))
            fz_slots[a[1]] = h;
        /* DUPLICATE_CLOSE_SOURCE invalidates the source handle: drop the slot so
         * a later op cannot alias a reused handle value (nondeterminism guard). */
        if (fz_ok(st) && ((ULONG)a[3] & DUPLICATE_CLOSE_SOURCE))
            fz_slots[a[0]] = NULL;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[1], h);
        break;
    case FZ_OP_MAKE_TEMPORARY:
        st = NtMakeTemporaryObject(fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_CREATE_DIRECTORY:
        h = NULL;
        st = NtCreateDirectoryObject(&h, (ACCESS_MASK)a[1],
                                     fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_OPEN_DIRECTORY:
        h = NULL;
        st = NtOpenDirectoryObject(&h, (ACCESS_MASK)a[1],
                                   fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_CREATE_SYMLINK:
    {
        UNICODE_STRING target;
        /* Operand a[4] is the link target name; anonymous index → empty target. */
        const void *tstr = fz_names[a[4]] ? fz_names[a[4]] : W("");
        init_ustr(&target, tstr);
        h = NULL;
        st = NtCreateSymbolicLinkObject(&h, (ACCESS_MASK)a[1],
                                        fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]),
                                        &target);
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    }
    case FZ_OP_OPEN_SYMLINK:
        h = NULL;
        st = NtOpenSymbolicLinkObject(&h, (ACCESS_MASK)a[1],
                                      fz_build_attr(&attr, &ustr, (unsigned)a[2], (ULONG)a[3]));
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_QUERY_SYMLINK:
    {
        WCHAR tbuf[128];
        UNICODE_STRING target;
        ULONG retLen = 0;
        fz_bzero(tbuf, sizeof tbuf);
        target.Length = 0;
        /* Shape drives the caller's MaximumLength (zero shape → too small). */
        target.MaximumLength = (a[1] == FZ_LEN_ZERO) ? 0 : (USHORT)sizeof(tbuf);
        target.Buffer = tbuf;
        st = NtQuerySymbolicLinkObject(fz_slots[a[0]], &target, &retLen);
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u tlen=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)retLen, (unsigned)target.Length);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CREATE_FILE:
    {
        OBJECT_ATTRIBUTES attr;
        UNICODE_STRING ustr;
        IO_STATUS_BLOCK iosb;
        HANDLE handle = NULL;
        init_ustr(&ustr, fz_fnames[a[2]]);
        init_attr(&attr, NULL, &ustr, OBJ_CASE_INSENSITIVE);
        iosb.Information = 0;
        st = NtCreateFile(&handle, (ACCESS_MASK)a[1], &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          (ULONG)a[3], (ULONG)a[4],
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
        if (fz_ok(st))
        {
            fz_slots[a[0]] = handle;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x info=%u slot=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)iosb.Information, (unsigned)a[0]);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_READ_FILE:
    {
        static char io_buffer[8192];
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER off;
        ULONG len = fz_iolen((unsigned)a[1]);
        if (len > sizeof(io_buffer))
            len = sizeof(io_buffer);
        off.QuadPart = (LONGLONG)fz_iooff((unsigned)a[2]);
        fz_bzero(io_buffer, sizeof(io_buffer));
        iosb.Information = 0;
        st = NtReadFile(fz_slots[a[0]], NULL, NULL, NULL, &iosb, io_buffer, len, &off, NULL);
        if (fz_ok(st))
        {
            unsigned sum = 0;
            for (ULONG i = 0; i < (ULONG)iosb.Information && i < sizeof(io_buffer); i++)
                sum = (sum + (unsigned char)io_buffer[i]) & 0xFFFF;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x n=%u sum=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)iosb.Information, sum);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_WRITE_FILE:
    {
        static char io_buffer[8192];
        IO_STATUS_BLOCK iosb;
        LARGE_INTEGER off;
        ULONG len = fz_iolen((unsigned)a[1]);
        if (len > sizeof(io_buffer))
            len = sizeof(io_buffer);
        off.QuadPart = (LONGLONG)fz_iooff((unsigned)a[2]);
        /* Deterministic pattern: a function of (offset, index, length). */
        for (ULONG i = 0; i < len; i++)
            io_buffer[i] = (char)((unsigned)off.QuadPart + i * 13u + len);
        iosb.Information = 0;
        st = NtWriteFile(fz_slots[a[0]], NULL, NULL, NULL, &iosb, io_buffer, len, &off, NULL);
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x n=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)iosb.Information);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_SET_EOF_FILE:
    {
        IO_STATUS_BLOCK iosb;
        FILE_END_OF_FILE_INFORMATION eof;
        eof.EndOfFile.QuadPart = (LONGLONG)fz_iooff((unsigned)a[1]);
        st = NtSetInformationFile(fz_slots[a[0]], &iosb, &eof, sizeof(eof),
                                  FileEndOfFileInformation);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_STANDARD_FILE:
    {
        IO_STATUS_BLOCK iosb;
        FILE_STANDARD_INFORMATION std;
        fz_bzero(&std, sizeof(std));
        st = NtQueryInformationFile(fz_slots[a[0]], &iosb, &std, sizeof(std),
                                    FileStandardInformation);
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x eof=%u links=%u dir=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)std.EndOfFile.QuadPart,
                         (unsigned)std.NumberOfLinks, (unsigned)std.Directory);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_PROCESS_BASIC:
    {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen = 0;
        fz_bzero(&pbi, sizeof(pbi));
        st = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi,
                                       fz_query_len((unsigned)a[0], (ULONG)sizeof(pbi)), &retLen);
        /* rlen is contract; the PEB pointer / process id are not (they differ
         * by VA layout and by pid source — a flat proskrnl process has no PEB,
         * a Wine process does), so they are deliberately not traced. */
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_SYSTEM_BASIC:
    {
        SYSTEM_BASIC_INFORMATION sbi;
        ULONG retLen = 0;
        fz_bzero(&sbi, sizeof(sbi));
        st = NtQuerySystemInformation(SystemBasicInformation, &sbi,
                                      fz_query_len((unsigned)a[0], (ULONG)sizeof(sbi)), &retLen);
        /* Only status + rlen: NumberOfProcessors and the physical-page counts
         * legitimately differ between the oracle host and proskrnl. */
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_PROTECT_MEMORY:
    {
        if (fz_protect_base == NULL)
        {
            ntapi_printf("[FUZZ] p%u c%u %s skip\n", prog, call, nt);
            break;
        }
        void *base = fz_protect_base;
        SIZE_T size = FZ_PROTECT_REGION_SIZE;
        ULONG oldProtect = 0;
        st = NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, (ULONG)a[0], &oldProtect);
        /* status + the reported previous protection are contract (the base is
         * not — ASLR); the region is one fully-committed VAD on both sides. */
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x old=%08x\n", prog, call, nt, (unsigned)st,
                         (unsigned)oldProtect);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    default:
        ntapi_printf("[FUZZ] p%u c%u ??? op=%d\n", prog, call, op);
        break;
    }
}

/* ---- blob decode + driver loop ------------------------------------------ */

static unsigned rd_u16(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned rd_u32(const unsigned char *p)
{
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

START_TEST(fuzz_interp)
{
    const unsigned char *p = fuzz_programs;
    const unsigned char *end = fuzz_programs + fuzz_programs_len;

    if (fuzz_programs_len < 8 || p[0] != 'P' || p[1] != 'F' || p[2] != 'Z' || p[3] != '1')
    {
        ok(0, "fuzz_programs blob missing or bad magic (len=%u)", fuzz_programs_len);
        return;
    }
    unsigned programCount = rd_u32(p + 4);
    p += 8;

    fz_setup_files();
    fz_setup_protect();

    for (unsigned pi = 0; pi < programCount && p < end; pi++)
    {
        if (p + 6 > end)
        {
            ok(0, "truncated program header at program %u", pi);
            return;
        }
        unsigned id = rd_u32(p);
        unsigned callCount = rd_u16(p + 4);
        p += 6;

        fz_reset_slots();
        fz_reset_files();
        fz_reset_protect();
        ntapi_printf("[FUZZ] p%u begin id=%u calls=%u\n", pi, id, callCount);

        for (unsigned ci = 0; ci < callCount; ci++)
        {
            if (p >= end)
            {
                ok(0, "truncated call stream at program %u call %u", pi, ci);
                return;
            }
            int op = *p++;
            if (op < 0 || op >= FZ_OP_COUNT)
            {
                ok(0, "bad opcode %d at program %u call %u", op, pi, ci);
                return;
            }
            int nOperands = fz_ops[op].count;
            if (p + nOperands > end)
            {
                ok(0, "truncated operands at program %u call %u", pi, ci);
                return;
            }
            unsigned long long operands[8];
            for (int k = 0; k < nOperands; k++)
                operands[k] = fz_resolve(fz_ops[op].kinds[k], p[k]);
            p += nOperands;

            fz_exec(pi, ci, op, operands);
        }

        ntapi_printf("[FUZZ] p%u end\n", pi);
    }

    fz_reset_slots();
    ntapi_printf("[FUZZ] batch end n=%u\n", programCount);
    /* No ok() failures unless the blob was malformed: the verdict is the diff
     * of the [FUZZ] lines, computed host-side by fuzz.py. */
}
