/*
 * interp.c — the differential-fuzzer interpreter (docs/08 "Differential
 * fuzzing"; tests/fuzz/README.md).
 *
 * One binary, both sides — exactly like every ntapi test (docs/14): a
 * CRT-less mingw PE .exe against the system NT headers, run under the pinned
 * third_party/wine (the oracle) and baked under C:\ntapi on the proskrnl
 * image (the kernel's ntapi runner sweeps it like any test).
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
/* Prototypes winternl.h omits (as wine/include/winternl.h declares them). */
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtInitializeNlsFiles(void **, LCID *, LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtGetNlsSectionPtr(ULONG, ULONG, void *, void **, SIZE_T *);
/* CUI-3 ops. */
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
/* CUI-8 ops. */
NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCreateJobObject(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtSetInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
/* CUI-4 */
NTSYSAPI NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG,
                                                    PULONG);
NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCompareObjects(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtSetInformationObject(HANDLE, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFlushProcessWriteBuffers(void);
NTSYSAPI ULONG NTAPI NtGetCurrentProcessorNumber(void);
NTSYSAPI NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *,
                                      const CLIENT_ID *);
NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, const void *, void *, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);
NTSYSAPI NTSTATUS NTAPI NtRenameKey(HANDLE, UNICODE_STRING *);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemoryEx(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, PVOID,
                                                  ULONG);
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtLockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtUnlockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSYSAPI NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE, LPCVOID *, SIZE_T *, PVOID);
NTSYSAPI NTSTATUS NTAPI NtGetWriteWatch(HANDLE, ULONG, PVOID, SIZE_T, PVOID *, ULONG_PTR *,
                                        ULONG *);
NTSYSAPI NTSTATUS NTAPI NtResetWriteWatch(HANDLE, PVOID, SIZE_T);
NTSYSAPI NTSTATUS NTAPI NtSetInformationVirtualMemory(HANDLE, ULONG, ULONG_PTR, PVOID, PVOID,
                                                      ULONG);
/* NtGetNlsSectionPtr's section types, as wine/dlls/ntdll/locale_private.h
 * defines them (winternl.h omits the enum; NORM_FORM comes via windows.h).
 * Before fuzz_model.h: its nls choice tables name these. */
enum nls_section_type
{
    NLS_SECTION_SORTKEYS = 9,
    NLS_SECTION_CASEMAP = 10,
    NLS_SECTION_CODEPAGE = 11,
    NLS_SECTION_NORMALIZE = 12
};
#include "tests/fuzz/gen/fuzz_model.h" /* FzOpcode, fz_ops[], choice tables */

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

/* M8 registry paths; order/tags MUST match FUZZ_KEY_NAMES in tools/gen_syscalls.py. */
static const void *fz_knames[FZ_KNAME_COUNT] = {
    W("\\Registry\\Machine\\Software\\fz_reg"),
    W("\\Registry\\Machine\\Software\\fz_reg\\ka"),
    W("\\Registry\\Machine\\Software\\fz_reg\\kb"),
    W("\\Registry\\Machine\\Software\\fz_reg\\ka\\Sub Key"),
    W("\\Registry\\Machine\\Software\\fz_reg\\nokey\\x"),
};

/* Registry prototypes mingw's winternl.h omits (as wine/include/winternl.h;
 * enum-typed class parameters as ULONG, like sem_reg/util.h). */
NTSYSAPI NTSTATUS NTAPI NtCreateKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG,
                                    const UNICODE_STRING *, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtDeleteKey(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtDeleteValueKey(HANDLE, const UNICODE_STRING *);
NTSYSAPI NTSTATUS NTAPI NtSetValueKey(HANDLE, const UNICODE_STRING *, ULONG, ULONG, const void *,
                                      ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryValueKey(HANDLE, const UNICODE_STRING *, ULONG, void *, ULONG,
                                        ULONG *);
NTSYSAPI NTSTATUS NTAPI NtEnumerateKey(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtEnumerateValueKey(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtQueryKey(HANDLE, ULONG, void *, ULONG, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtFlushKey(HANDLE);
/* Info-class values as wine/include/winternl.h orders the enums. */
#define FZ_KEY_BASIC_CLASS  0 /* KeyBasicInformation */
#define FZ_KEY_NODE_CLASS   1 /* KeyNodeInformation */
#define FZ_KEY_FULL_CLASS   2 /* KeyFullInformation */
#define FZ_KV_BASIC_CLASS   0 /* KeyValueBasicInformation */
#define FZ_KV_FULL_CLASS    1 /* KeyValueFullInformation */
#define FZ_KV_PARTIAL_CLASS 2 /* KeyValuePartialInformation */

/* Semantic-table indices for the M8 registry ops (FUZZ_CHOICES vname/vdata/
 * key_info/kv_info); meanings live here. */
enum
{
    FZ_VNAME_DEFAULT = 0, /* the unnamed (default) value */
    FZ_VNAME_A,
    FZ_VNAME_B,
    FZ_VNAME_MISSING
};
enum
{
    FZ_VDATA_EMPTY = 0, /* 0 bytes */
    FZ_VDATA_DWORD,     /* 4 bytes */
    FZ_VDATA_ODD,       /* 7 bytes (exercises the hive's parity pad) */
    FZ_VDATA_MID        /* 33 bytes */
};
enum
{
    FZ_KINFO_BASIC = 0,
    FZ_KINFO_NODE,
    FZ_KINFO_FULL
};
enum
{
    FZ_KVINFO_BASIC = 0,
    FZ_KVINFO_FULL,
    FZ_KVINFO_PARTIAL
};

static const void *fz_vnames[3] = {W(""), W("va"), W("vb")}; /* MISSING handled apart */
static const void *fz_vname_missing = W("fz_no_such_value");

static ULONG fz_key_class(unsigned shape)
{
    switch (shape)
    {
    case FZ_KINFO_NODE:
        return FZ_KEY_NODE_CLASS;
    case FZ_KINFO_FULL:
        return FZ_KEY_FULL_CLASS;
    default:
        return FZ_KEY_BASIC_CLASS;
    }
}

static ULONG fz_kv_class(unsigned shape)
{
    switch (shape)
    {
    case FZ_KVINFO_FULL:
        return FZ_KV_FULL_CLASS;
    case FZ_KVINFO_PARTIAL:
        return FZ_KV_PARTIAL_CLASS;
    default:
        return FZ_KV_BASIC_CLASS;
    }
}

static void fz_init_vname(UNICODE_STRING *name, unsigned shape)
{
    if (shape == FZ_VNAME_MISSING)
        init_ustr(name, fz_vname_missing);
    else
        init_ustr(name, fz_vnames[shape % 3]);
}

/* Deterministic value payload for a vdata shape. */
static ULONG fz_vdata_bytes(unsigned shape, unsigned char *buf, ULONG cap)
{
    ULONG len;
    switch (shape)
    {
    case FZ_VDATA_DWORD:
        len = 4;
        break;
    case FZ_VDATA_ODD:
        len = 7;
        break;
    case FZ_VDATA_MID:
        len = 33;
        break;
    default:
        return 0;
    }
    if (len > cap)
        len = cap;
    for (ULONG i = 0; i < len; i++)
        buf[i] = (unsigned char)(0x40 + i * 3);
    return len;
}

/* File-surface prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);

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

/* CUI-8: the shared completion event read_file_async issues with — lazily
 * created, reused across calls and programs, never traced (handles must not
 * leak into the trace). Its state is a deterministic function of the op
 * history on both runners: a data-path submit resets it, an inline
 * completion sets it. */
static HANDLE fz_async_event;

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

/* Scrub the fuzz registry keys between programs (registry state, like files,
 * persists) and make sure the fz_reg root exists. Children first (a key with
 * subkeys cannot be deleted), then the root's own values; the root itself
 * stays. Uses only the M8 surface both sides implement. */
static void fz_setup_keys(void)
{
    /* NtCreateKey creates only the LAST component, and a fresh proskrnl
     * registry has no Machine\Software yet — build the chain. */
    static const void *chain[2] = {W("\\Registry\\Machine\\Software"), NULL};
    for (int i = 0; i < 2; i++)
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE key = NULL;
        init_ustr(&name, chain[i] != NULL ? chain[i] : fz_knames[0]);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        if (fz_ok(NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL)))
            NtClose(key);
    }
}

static void fz_reset_keys(void)
{
    /* Deepest-first over the known key space: ka\Sub Key, then ka, kb. */
    static const int scrub_order[3] = {3, 1, 2};
    for (int i = 0; i < 3; i++)
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE key = NULL;
        init_ustr(&name, fz_knames[scrub_order[i]]);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        if (fz_ok(NtOpenKey(&key, KEY_ALL_ACCESS, &attr)))
        {
            NtDeleteKey(key);
            NtClose(key);
        }
    }
    /* The root's values (set_value on an open root-key slot). */
    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE key = NULL;
        init_ustr(&name, fz_knames[0]);
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        if (fz_ok(NtOpenKey(&key, KEY_ALL_ACCESS, &attr)))
        {
            UNICODE_STRING vname;
            for (unsigned v = 0; v < 3; v++)
            {
                init_ustr(&vname, fz_vnames[v]);
                NtDeleteValueKey(key, &vname);
            }
            NtClose(key);
        }
    }
    fz_setup_keys(); /* recreate the root if a program deleted it */
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

/* --- M7 user-APC delivery (queue_apc / read_file_apc / test_alert) --------
 * Single-threaded and drained only at the explicit test_alert op, so
 * delivery is deterministic FIFO on both sides. The routines fold what they
 * observed into per-program counters; test_alert's ONE trace line prints
 * them (fuzz.py keys lines by (program, call) — one line per call). */
NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(HANDLE, void *, ULONG_PTR, ULONG_PTR, ULONG_PTR);
NTSYSAPI NTSTATUS NTAPI NtTestAlert(void);
#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif

static unsigned fz_apc_delivered; /* APCs run so far this program */
static unsigned fz_apc_sum;       /* order-sensitive fold of their payloads */

static void fz_apc_fold(unsigned value)
{
    fz_apc_delivered++;
    fz_apc_sum = (fz_apc_sum * 31u + value) & 0xFFFFu;
}

static void NTAPI fz_user_apc(ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3)
{
    (void)arg2;
    (void)arg3;
    fz_apc_fold((unsigned)arg1 * 13u + 1u);
}

static void NTAPI fz_io_apc(PVOID context, IO_STATUS_BLOCK *iosb, ULONG reserved)
{
    (void)reserved;
    fz_apc_fold((unsigned)iosb->Status + (unsigned)iosb->Information * 7u +
                (unsigned)(ULONG_PTR)context * 13u);
}

static void fz_reset_apc(void)
{
    fz_apc_delivered = 0;
    fz_apc_sum = 0;
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
    case FZ_OPND_CH_NLS_TYPE:
        return fz_ch_nls_type[b % FZ_CH_NLS_TYPE_COUNT];
    case FZ_OPND_CH_NLS_ID:
        return fz_ch_nls_id[b % FZ_CH_NLS_ID_COUNT];
    case FZ_OPND_KNAME:
        return b % FZ_KNAME_COUNT;
    case FZ_OPND_CH_ACCESS_KEY:
        return fz_ch_access_key[b % FZ_CH_ACCESS_KEY_COUNT];
    case FZ_OPND_CH_REG_TYPE:
        return fz_ch_reg_type[b % FZ_CH_REG_TYPE_COUNT];
    case FZ_OPND_CH_REG_OPTIONS:
        return fz_ch_reg_options[b % FZ_CH_REG_OPTIONS_COUNT];
    case FZ_OPND_CH_VNAME:
        return b % FZ_CH_VNAME_COUNT;
    case FZ_OPND_CH_VDATA:
        return b % FZ_CH_VDATA_COUNT;
    case FZ_OPND_CH_KEY_INFO:
        return b % FZ_CH_KEY_INFO_COUNT;
    case FZ_OPND_CH_KV_INFO:
        return b % FZ_CH_KV_INFO_COUNT;
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
    case FZ_OP_QUEUE_APC:
    {
        st = NtQueueApcThread(NtCurrentThread(), (void *)fz_user_apc, (ULONG_PTR)a[0], 0, 0);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_READ_FILE_APC:
    {
        static char io_buffer[8192];
        /* static: the completion APC receives this very IOSB at the next
         * test_alert — it must outlive the call (one shared block; the IOSB
         * is written synchronously at completion on both sides, so its
         * contents at delivery are deterministic). */
        static IO_STATUS_BLOCK iosb;
        LARGE_INTEGER off;
        ULONG len = fz_iolen((unsigned)a[1]);
        if (len > sizeof(io_buffer))
            len = sizeof(io_buffer);
        off.QuadPart = (LONGLONG)fz_iooff((unsigned)a[2]);
        fz_bzero(io_buffer, sizeof(io_buffer));
        iosb.Information = 0;
        st = NtReadFile(fz_slots[a[0]], NULL, fz_io_apc, (PVOID)(ULONG_PTR)0x51u, &iosb, io_buffer,
                        len, &off, NULL);
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
    case FZ_OP_TEST_ALERT:
    {
        st = NtTestAlert();
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x apcs=%u sum=%u\n", prog, call, nt, (unsigned)st,
                     fz_apc_delivered, fz_apc_sum);
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
    case FZ_OP_RENAME_FILE:
    {
        /* CUI-5: FileRenameInformation to one of the fixed fuzz paths —
         * renames stay inside the per-program-scrubbed \??\C:\fuzz set, so
         * the replay is deterministic on both runners. Built as kernelbase
         * builds it: offsetof(FileName)+FileNameLength bytes. */
        IO_STATUS_BLOCK iosb;
        unsigned char buffer[sizeof(FILE_RENAME_INFORMATION) + 64 * sizeof(WCHAR)];
        FILE_RENAME_INFORMATION *info = (FILE_RENAME_INFORMATION *)buffer;
        UNICODE_STRING target;
        init_ustr(&target, fz_fnames[a[1]]);
        fz_bzero(buffer, sizeof(buffer));
        info->ReplaceIfExists = (BOOLEAN)a[2];
        info->RootDirectory = NULL;
        info->FileNameLength = target.Length;
        memcpy(info->FileName, target.Buffer, target.Length);
        st = NtSetInformationFile(
            fz_slots[a[0]], &iosb, info,
            (ULONG)(offsetof(FILE_RENAME_INFORMATION, FileName) + target.Length),
            FileRenameInformation);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_FLUSH_EX_FILE:
    {
        IO_STATUS_BLOCK iosb;
        st = NtFlushBuffersFileEx(fz_slots[a[0]], 0, NULL, 0, &iosb);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_EA_FILE:
    {
        IO_STATUS_BLOCK iosb;
        unsigned char ea[128];
        st = NtQueryEaFile(fz_slots[a[0]], &iosb, ea, fz_query_len((unsigned)a[1], sizeof(ea)),
                           TRUE, NULL, 0, NULL, TRUE);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_SET_EA_FILE:
    {
        IO_STATUS_BLOCK iosb;
        unsigned char ea[32];
        fz_bzero(ea, sizeof(ea));
        st = NtSetEaFile(fz_slots[a[0]], &iosb, ea, sizeof(ea));
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
    case FZ_OP_INIT_NLS:
    {
        void *base = NULL;
        LCID lcid = 0;
        LARGE_INTEGER nlsSize;
        nlsSize.QuadPart = 0;
        st = NtInitializeNlsFiles(&base, &lcid, &nlsSize);
        /* base is ASLR and the lcid follows the oracle host's locale; only
         * the status and the mapped size (the same pinned locale.nls on both
         * sides) are contract. */
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x size=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)nlsSize.QuadPart);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_GET_NLS_SECTION:
    {
        void *ptr = NULL;
        SIZE_T nlsSize = 0;
        st = NtGetNlsSectionPtr((ULONG)a[0], (ULONG)a[1], NULL, &ptr, &nlsSize);
        /* status + size only (the pointer is ASLR). */
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x size=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)nlsSize);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    /* ---- M8 Cm registry ops ---------------------------------------------- */
    case FZ_OP_CREATE_KEY:
    {
        ULONG disposition = 0;
        h = NULL;
        init_ustr(&ustr, fz_knames[a[2]]);
        init_attr(&attr, NULL, &ustr, OBJ_CASE_INSENSITIVE);
        st = NtCreateKey(&h, (ACCESS_MASK)a[1], &attr, 0, NULL, (ULONG)a[3], &disposition);
        if (fz_ok(st))
        {
            fz_slots[a[0]] = h;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x disp=%u slot=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)disposition, (unsigned)a[0]);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_OPEN_KEY:
        h = NULL;
        init_ustr(&ustr, fz_knames[a[2]]);
        init_attr(&attr, NULL, &ustr, OBJ_CASE_INSENSITIVE);
        st = NtOpenKey(&h, (ACCESS_MASK)a[1], &attr);
        if (fz_ok(st))
            fz_slots[a[0]] = h;
        fz_trace_handle(prog, call, nt, st, (unsigned)a[0], h);
        break;
    case FZ_OP_DELETE_KEY:
        st = NtDeleteKey(fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_SET_VALUE_KEY:
    {
        UNICODE_STRING vname;
        unsigned char data[64];
        ULONG bytes = fz_vdata_bytes((unsigned)a[3], data, sizeof(data));
        fz_init_vname(&vname, (unsigned)a[1]);
        st = NtSetValueKey(fz_slots[a[0]], &vname, 0, (ULONG)a[2], bytes ? data : NULL, bytes);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_DELETE_VALUE_KEY:
    {
        UNICODE_STRING vname;
        fz_init_vname(&vname, (unsigned)a[1]);
        st = NtDeleteValueKey(fz_slots[a[0]], &vname);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_VALUE_KEY:
    {
        UNICODE_STRING vname;
        unsigned char info[256];
        ULONG retLen = 0;
        fz_init_vname(&vname, (unsigned)a[1]);
        fz_bzero(info, sizeof(info));
        st = NtQueryValueKey(fz_slots[a[0]], &vname, fz_kv_class((unsigned)a[2]), info,
                             fz_query_len((unsigned)a[3], 64), &retLen);
        /* Status + required length; both are contract on every outcome the
         * buffer protocol defines (rlen is set on TOO_SMALL/OVERFLOW too). */
        if (fz_ok(st) || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_ENUM_VALUE_KEY:
    {
        unsigned char info[256];
        ULONG retLen = 0;
        fz_bzero(info, sizeof(info));
        st = NtEnumerateValueKey(fz_slots[a[0]], (ULONG)a[1], fz_kv_class((unsigned)a[2]), info,
                                 fz_query_len((unsigned)a[3], 64), &retLen);
        if (fz_ok(st) || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_ENUMERATE_KEY:
    {
        unsigned char info[256];
        ULONG retLen = 0;
        fz_bzero(info, sizeof(info));
        st = NtEnumerateKey(fz_slots[a[0]], (ULONG)a[1], fz_key_class((unsigned)a[2]), info,
                            fz_query_len((unsigned)a[3], 64), &retLen);
        if (fz_ok(st) || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_KEY:
    {
        unsigned char info[256];
        ULONG retLen = 0;
        fz_bzero(info, sizeof(info));
        st = NtQueryKey(fz_slots[a[0]], fz_key_class((unsigned)a[1]), info,
                        fz_query_len((unsigned)a[2], 64), &retLen);
        if (fz_ok(st) || st == STATUS_BUFFER_TOO_SMALL || st == STATUS_BUFFER_OVERFLOW)
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_FLUSH_KEY:
        st = NtFlushKey(fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    /* ---- CUI-3 SCM surface ---------------------------------------------- */
    case FZ_OP_CANCEL_IO:
    {
        IO_STATUS_BLOCK iosb;
        iosb.Information = 0;
        st = NtCancelIoFile(fz_slots[a[0]], &iosb);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CANCEL_IO_EX:
    {
        IO_STATUS_BLOCK iosb;
        iosb.Information = 0;
        st = NtCancelIoFileEx(fz_slots[a[0]], NULL, &iosb);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_CREATE_FILE_ASYNC:
    {
        /* The CUI-8 asynchronous handle: same shape as create_file MINUS
         * the FILE_SYNCHRONOUS_IO_* option, so the §7-pinned pending-shape
         * answers become reachable from the op stream. */
        OBJECT_ATTRIBUTES attr;
        UNICODE_STRING ustr;
        IO_STATUS_BLOCK iosb;
        HANDLE handle = NULL;
        init_ustr(&ustr, fz_fnames[a[2]]);
        init_attr(&attr, NULL, &ustr, OBJ_CASE_INSENSITIVE);
        iosb.Information = 0;
        st = NtCreateFile(&handle, (ACCESS_MASK)a[1], &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                          (ULONG)a[3], (ULONG)a[4], FILE_NON_DIRECTORY_FILE, NULL, 0);
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
    case FZ_OP_READ_FILE_ASYNC:
    {
        /* Issue with an event and COLLECT AT THE CALL with a zero-timeout
         * wait. Deterministic on both runners precisely because both
         * complete data transfers inline under the CUI-8 §7 pin
         * (sem_file/async_inline.c): the call answers the pending shape
         * with the IOSB already final and the event already set. A kernel
         * that regresses to genuine ring-3 pending diverges RIGHT HERE —
         * wait= flips, ios= goes stale — which is what makes a
         * pended-completion divergence minimizable (docs/19 §8.3.3). */
        static char io_buffer[8192];
        /* static, like FZ_OP_READ_FILE_APC's: the op collects at the call
         * under the §7 pin, but if a genuinely-pending handle type ever
         * enters the slot universe a stack IOSB would be a dangling write
         * at completion time — the divergence should be the trace line
         * flipping, never corrupted interp state. */
        static IO_STATUS_BLOCK iosb;
        LARGE_INTEGER off, zero;
        if (fz_async_event == NULL)
            NtCreateEvent(&fz_async_event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        ULONG len = fz_iolen((unsigned)a[1]);
        if (len > sizeof(io_buffer))
            len = sizeof(io_buffer);
        off.QuadPart = (LONGLONG)fz_iooff((unsigned)a[2]);
        fz_bzero(io_buffer, sizeof(io_buffer));
        iosb.Status = (NTSTATUS)0x0BADF00D; /* poison: did the call write it? */
        iosb.Information = 0;
        st = NtReadFile(fz_slots[a[0]], fz_async_event, NULL, NULL, &iosb, io_buffer, len, &off,
                        NULL);
        zero.QuadPart = 0;
        NTSTATUS waitSt = fz_async_event != NULL
                              ? NtWaitForSingleObject(fz_async_event, FALSE, &zero)
                              : (NTSTATUS)0xEEEEEEEE;
        unsigned sum = 0;
        for (ULONG i = 0; i < (ULONG)iosb.Information && i < sizeof(io_buffer); i++)
            sum = (sum + (unsigned char)io_buffer[i]) & 0xFFFF;
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x wait=%08x ios=%08x n=%u sum=%u\n", prog, call, nt,
                     (unsigned)st, (unsigned)waitSt, (unsigned)iosb.Status,
                     (unsigned)iosb.Information, sum);
        break;
    }
    case FZ_OP_CANCEL_SYNC_SELF:
    {
        /* The interp is never inside synchronous I/O when it runs an op, so
         * NOT_FOUND with the result IOSB written {status, 0} — continuously
         * pinning the CUI-8-widened verb's idle answer on both sides. */
        IO_STATUS_BLOCK iosb;
        iosb.Status = (NTSTATUS)0x0BADF00D;
        iosb.Information = 0x77;
        st = NtCancelSynchronousIoFile(NtCurrentThread(), NULL, &iosb);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x ios=%08x info=%u\n", prog, call, nt, (unsigned)st,
                     (unsigned)iosb.Status, (unsigned)iosb.Information);
        break;
    }
    case FZ_OP_CREATE_JOB:
    {
        HANDLE handle = NULL;
        st = NtCreateJobObject(&handle, (ACCESS_MASK)a[1], NULL);
        if (fz_ok(st))
        {
            fz_slots[a[0]] = handle;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x slot=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)a[0]);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_SET_JOB_LIMITS:
    {
        /* The job_scenario semantic table (tools/gen_syscalls.py): the
         * argument gates NtSetInformationJobObject validates before
         * storing — classes, exact sizes, per-class flag masks. */
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext;
        fz_bzero(&ext, sizeof(ext));
        JOBOBJECTINFOCLASS cls = JobObjectBasicLimitInformation;
        ULONG len = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
        switch (a[1])
        {
        case 0: /* FZ_JOB_BASIC_VALID */
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_WORKINGSET;
            break;
        case 1: /* FZ_JOB_BASIC_BADFLAGS: breakaway is extended-only */
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            break;
        case 2: /* FZ_JOB_BASIC_BADSIZE */
            len -= 1;
            break;
        case 3: /* FZ_JOB_EXT_VALID: the services.exe startup shape */
            cls = JobObjectExtendedLimitInformation;
            len = sizeof(ext);
            ext.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
            break;
        case 4: /* FZ_JOB_EXT_BADSIZE */
            cls = JobObjectExtendedLimitInformation;
            len = sizeof(ext) - 1;
            break;
        default: /* FZ_JOB_CLASS_CEILING */
            cls = (JOBOBJECTINFOCLASS)1000;
            len = sizeof(ext);
            break;
        }
        st = NtSetInformationJobObject(fz_slots[a[0]], cls, &ext, len);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_OPEN_PROCESS:
    {
        /* The process_cid semantic table: our own pid resolves, an id that
         * was never handed out is STATUS_INVALID_CID on both sides. The
         * HANDLE VALUE is never traced (allocation differs); only the status
         * and, on success, the slot it landed in. */
        OBJECT_ATTRIBUTES attr;
        CLIENT_ID cid;
        HANDLE handle = NULL;
        InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
        fz_bzero(&cid, sizeof(cid));
        switch (a[1])
        {
        case 0: /* FZ_CID_SELF */
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
            break;
        case 1: /* FZ_CID_NEVER_ALLOCATED: 4-aligned but absurdly high */
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)0xfffffffcUL;
            break;
        default: /* FZ_CID_ZERO: no process and no thread named */
            break;
        }
        st = NtOpenProcess(&handle, PROCESS_QUERY_INFORMATION, &attr, &cid);
        if (fz_ok(st))
        {
            fz_slots[a[0]] = handle;
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x slot=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)a[0]);
        }
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_SYSTEM_PROCESSES:
    {
        /* Length gating only: the process list's CONTENTS (how many processes
         * exist, their names and ids) legitimately differ between the oracle
         * host and proskrnl, so the trace carries the status and whether a
         * needed size came back — never the bytes or the size itself. */
        static unsigned char buffer[8192];
        ULONG retLen = 0;
        st = NtQuerySystemInformation(SystemProcessInformation, buffer,
                                      fz_query_len((unsigned)a[0], (ULONG)sizeof(buffer)), &retLen);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x sized=%u\n", prog, call, nt, (unsigned)st,
                     (unsigned)(retLen != 0));
        break;
    }
    case FZ_OP_READ_OWN_MEMORY:
    case FZ_OP_WRITE_OWN_MEMORY:
    {
        /* The vm_scenario table over the interp's OWN memory: a whole buffer,
         * a zero-length move, and an address unmapped on both sides (the
         * STATUS_PARTIAL_COPY path). Self-directed, so the bytes moved are
         * fully determined by the program. */
        static unsigned char vmSource[64];
        static unsigned char vmSink[64];
        for (unsigned i = 0; i < sizeof(vmSource); i++)
            vmSource[i] = (unsigned char)(i * 3 + 1);
        const void *from = vmSource;
        void *to = vmSink;
        SIZE_T length = sizeof(vmSource);
        SIZE_T moved = 0;
        switch (a[0])
        {
        case 0: /* FZ_VM_WHOLE */
            break;
        case 1: /* FZ_VM_ZERO_LENGTH */
            length = 0;
            break;
        default: /* FZ_VM_UNMAPPED */
            from = (const void *)(ULONG_PTR)0x1000;
            to = (void *)(ULONG_PTR)0x1000;
            break;
        }
        if (op == FZ_OP_READ_OWN_MEMORY)
            st = NtReadVirtualMemory(NtCurrentProcess(), from, vmSink, length, &moved);
        else
            st = NtWriteVirtualMemory(NtCurrentProcess(), to, vmSource, length, &moved);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x moved=%u\n", prog, call, nt, (unsigned)st,
                     (unsigned)moved);
        break;
    }
    case FZ_OP_IS_PROCESS_IN_JOB:
    {
        /* Self against whatever the slot holds: a job handle answers
         * NOT_IN_JOB (the interp never assigns itself — assignment is
         * irreversible state, deliberately outside the model), a non-job
         * handle is the type mismatch, an empty slot the invalid handle. */
        st = NtIsProcessInJob(NtCurrentProcess(), fz_slots[a[0]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_JOB_INFO:
    {
        /* The job_query semantic table. Every answer is deterministic for an
         * empty interp-created job: zero counts, zero ids, the limit flags
         * set_job_limits stored. */
        unsigned char buffer[256];
        ULONG retLen = 0;
        JOBOBJECTINFOCLASS cls;
        ULONG len;
        fz_bzero(buffer, sizeof(buffer));
        switch (a[1])
        {
        case 0: /* FZ_JOBQ_ACCOUNTING */
            cls = JobObjectBasicAccountingInformation;
            len = sizeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION);
            break;
        case 1: /* FZ_JOBQ_PID_LIST */
            cls = JobObjectBasicProcessIdList;
            len = sizeof(buffer);
            break;
        case 2: /* FZ_JOBQ_BASIC_LIMITS */
            cls = JobObjectBasicLimitInformation;
            len = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
            break;
        default: /* FZ_JOBQ_CLASS_CEILING */
            cls = (JOBOBJECTINFOCLASS)1000;
            len = sizeof(buffer);
            break;
        }
        st = NtQueryInformationJobObject(fz_slots[a[0]], cls, buffer, len, &retLen);
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u\n", prog, call, nt, (unsigned)st,
                         (unsigned)retLen);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_COMPARE_OBJECTS:
        st = NtCompareObjects(fz_slots[a[0]], fz_slots[a[1]]);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_SET_HANDLE_INFO:
    {
        struct
        {
            unsigned char inherit;
            unsigned char protect;
        } flags;
        flags.inherit = (unsigned char)(a[1] & 1);
        flags.protect = (unsigned char)(a[2] & 1);
        st = NtSetInformationObject(fz_slots[a[0]], 4 /* ObjectHandleFlagInformation */, &flags,
                                    sizeof(flags));
        /* Clear protect-from-close again so the slot can be closed at reset. */
        if (fz_ok(st) && flags.protect)
        {
            flags.protect = 0;
            NtSetInformationObject(fz_slots[a[0]], 4, &flags, sizeof(flags));
        }
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_QUERY_HANDLE_FLAGS:
    {
        unsigned char buffer[8];
        ULONG retLen = 0;
        fz_bzero(buffer, sizeof(buffer));
        st = NtQueryObject(fz_slots[a[0]], (OBJECT_INFORMATION_CLASS)4, buffer,
                           fz_query_len((unsigned)a[1], 2), &retLen);
        if (fz_ok(st))
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x rlen=%u inh=%u prot=%u\n", prog, call, nt,
                         (unsigned)st, (unsigned)retLen, buffer[0], buffer[1]);
        else
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_FLUSH_WRITE_BUFFERS:
        st = NtFlushProcessWriteBuffers();
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    case FZ_OP_CURRENT_PROCESSOR:
    {
        ULONG cpu = NtGetCurrentProcessorNumber();
        /* The value differs by host CPU count on the oracle; trace only that
         * it returned (the call cannot fail). */
        ntapi_printf("[FUZZ] p%u c%u %s ran cpu_lt_max=%u\n", prog, call, nt, cpu < 0x10000u);
        break;
    }
    case FZ_OP_RENAME_KEY:
    {
        /* The ren_name shapes over whatever the slot holds: a key renames
         * (or collides deterministically), a non-key is the type mismatch,
         * an empty slot the invalid handle. Renamed keys stay under the
         * scrubbed fz_reg prefix. */
        static const WCHAR renA[] = {'f', 'z', 'r', 'e', 'n', '_', 'a', 0};
        static const WCHAR renB[] = {'f', 'z', 'r', 'e', 'n', '_', 'b', 0};
        static const WCHAR renPath[] = {'a', '\\', 'b', 0};
        UNICODE_STRING name;
        switch (a[1])
        {
        case 0: /* FZ_REN_PLAIN */
            init_ustr(&name, renA);
            break;
        case 1: /* FZ_REN_OTHER */
            init_ustr(&name, renB);
            break;
        case 2: /* FZ_REN_PATH */
            init_ustr(&name, renPath);
            break;
        default: /* FZ_REN_EMPTY */
            init_ustr(&name, renA);
            name.Length = 0;
            break;
        }
        st = NtRenameKey(fz_slots[a[0]], &name);
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_ALLOC_EX:
    {
        /* Each scenario allocates, exercises and frees inside this one
         * call; the placement window (0x30000000..0x3fffffff) is free on
         * both sides (the interp image and its DLLs sit far above it). */
        struct
        {
            ULONGLONG type_bits;
            union
            {
                ULONGLONG u64;
                PVOID pointer;
            } u;
        } params[2];
        struct
        {
            PVOID lowest;
            PVOID highest;
            SIZE_T alignment;
        } req;
        PVOID base = NULL;
        SIZE_T size = 0x10000;
        ULONG type = MEM_RESERVE | MEM_COMMIT;
        PVOID paramPtr = params;
        ULONG count = 1;
        fz_bzero(params, sizeof(params));
        fz_bzero(&req, sizeof(req));
        params[0].type_bits = 1; /* MemExtendedParameterAddressRequirements */
        params[0].u.pointer = &req;
        switch (a[0])
        {
        case 0: /* FZ_AX_CONSTRAINED */
            req.lowest = (PVOID)(ULONG_PTR)0x30000000;
            req.highest = (PVOID)(ULONG_PTR)0x3fffffff;
            req.alignment = 0x20000;
            break;
        case 1: /* FZ_AX_DUP_TYPE */
            params[1] = params[0];
            count = 2;
            break;
        case 2: /* FZ_AX_BAD_ALIGN */
            req.alignment = 0x8000;
            break;
        case 3: /* FZ_AX_TYPE32 */
            params[0].type_bits = 32;
            break;
        case 4: /* FZ_AX_ZERO_SIZE */
            size = 0;
            count = 0;
            paramPtr = NULL;
            break;
        default: /* FZ_AX_BASE_WITH_LIMITS */
            base = (PVOID)(ULONG_PTR)0x30000000;
            req.lowest = (PVOID)(ULONG_PTR)0x30000000;
            req.highest = (PVOID)(ULONG_PTR)0x3fffffff;
            break;
        }
        st = NtAllocateVirtualMemoryEx(NtCurrentProcess(), &base, &size, type, PAGE_READWRITE,
                                       paramPtr, count);
        unsigned inWindow = 0;
        if (fz_ok(st))
        {
            inWindow = (ULONG_PTR)base >= 0x30000000 && (ULONG_PTR)base < 0x40000000;
            SIZE_T freeSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &base, &freeSize, MEM_RELEASE);
        }
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x in_window=%u\n", prog, call, nt, (unsigned)st,
                     inWindow);
        break;
    }
    case FZ_OP_LOCK_VIRTUAL:
    case FZ_OP_UNLOCK_VIRTUAL:
    {
        /* Build the state, exercise, tear down — all inside the call. */
        PVOID region = NULL;
        SIZE_T regionSize = 0x1000;
        ULONG type = a[0] == 1 ? MEM_RESERVE : (MEM_RESERVE | MEM_COMMIT);
        PVOID addr;
        SIZE_T len = 0x1000;
        if (a[0] != 2) /* not FZ_LK_UNMAPPED */
        {
            if (!fz_ok(NtAllocateVirtualMemory(NtCurrentProcess(), &region, 0, &regionSize, type,
                                               PAGE_READWRITE)))
            {
                ntapi_printf("[FUZZ] p%u c%u %s setup-failed\n", prog, call, nt);
                break;
            }
            addr = region;
        }
        else
        {
            addr = (PVOID)(ULONG_PTR)0x1000;
        }
        if (op == FZ_OP_LOCK_VIRTUAL)
            st = NtLockVirtualMemory(NtCurrentProcess(), &addr, &len, 1);
        else
            st = NtUnlockVirtualMemory(NtCurrentProcess(), &addr, &len, 1);
        if (region != NULL)
        {
            SIZE_T freeSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &region, &freeSize, MEM_RELEASE);
        }
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        break;
    }
    case FZ_OP_FLUSH_VIRTUAL:
    {
        PVOID region = NULL;
        SIZE_T regionSize = 3 * 0x1000;
        LPCVOID addr;
        SIZE_T len;
        if (a[0] != 2) /* not FZ_FL_UNMAPPED */
        {
            if (!fz_ok(NtAllocateVirtualMemory(NtCurrentProcess(), &region, 0, &regionSize,
                                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
            {
                ntapi_printf("[FUZZ] p%u c%u %s setup-failed\n", prog, call, nt);
                break;
            }
        }
        if (a[0] == 0) /* FZ_FL_ANON_WHOLE */
        {
            addr = region;
            len = 0;
        }
        else if (a[0] == 1) /* FZ_FL_PARTIAL */
        {
            addr = (const unsigned char *)region + 0x1000;
            len = 0x1000;
        }
        else
        {
            addr = (LPCVOID)(ULONG_PTR)0x1000;
            len = 0x1000;
        }
        st = NtFlushVirtualMemory(NtCurrentProcess(), &addr, &len, NULL);
        unsigned wholeLen = fz_ok(st) && len == regionSize;
        if (region != NULL)
        {
            SIZE_T freeSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &region, &freeSize, MEM_RELEASE);
        }
        ntapi_printf("[FUZZ] p%u c%u %s st=%08x whole=%u\n", prog, call, nt, (unsigned)st,
                     wholeLen);
        break;
    }
    case FZ_OP_GET_WRITE_WATCH:
    case FZ_OP_RESET_WRITE_WATCH:
    {
        /* A fresh two-page watch region per call: clean, dirtied, the flag
         * refusal, and the non-watch refusal. */
        PVOID region = NULL;
        SIZE_T regionSize = 2 * 0x1000;
        ULONG type =
            a[0] == 3 ? (MEM_RESERVE | MEM_COMMIT) : (MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH);
        if (!fz_ok(NtAllocateVirtualMemory(NtCurrentProcess(), &region, 0, &regionSize, type,
                                           PAGE_READWRITE)))
        {
            ntapi_printf("[FUZZ] p%u c%u %s setup-failed\n", prog, call, nt);
            break;
        }
        if (a[0] == 1) /* FZ_WW_DIRTY */
            *(volatile unsigned char *)region = 1;
        if (op == FZ_OP_GET_WRITE_WATCH)
        {
            PVOID addresses[2];
            ULONG_PTR count = 2;
            ULONG granularity = 0;
            ULONG flags = a[0] == 2 ? 4 : 0; /* FZ_WW_BAD_FLAGS */
            st = NtGetWriteWatch(NtCurrentProcess(), flags, region, regionSize, addresses, &count,
                                 &granularity);
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x n=%u g=%u\n", prog, call, nt, (unsigned)st,
                         fz_ok(st) ? (unsigned)count : 0, fz_ok(st) ? (unsigned)granularity : 0);
        }
        else
        {
            SIZE_T resetSize = a[0] == 2 ? 0 : regionSize; /* the zero-size arm */
            st = NtResetWriteWatch(NtCurrentProcess(), region, resetSize);
            ntapi_printf("[FUZZ] p%u c%u %s st=%08x\n", prog, call, nt, (unsigned)st);
        }
        {
            SIZE_T freeSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &region, &freeSize, MEM_RELEASE);
        }
        break;
    }
    case FZ_OP_PREFETCH_VM:
    {
        struct
        {
            PVOID virtual_address;
            SIZE_T number_of_bytes;
        } ranges[2];
        static unsigned char prefetchTarget[0x100];
        ULONG flags = 0;
        PVOID flagsPtr = &flags;
        ULONG flagsSize = sizeof(flags);
        ULONG_PTR count = 2;
        ranges[0].virtual_address = prefetchTarget;
        ranges[0].number_of_bytes = sizeof(prefetchTarget);
        ranges[1].virtual_address = (PVOID)(ULONG_PTR)0x30000000; /* unmapped: fine */
        ranges[1].number_of_bytes = 0x1000;
        switch (a[0])
        {
        case 0: /* FZ_PF_VALID */
            break;
        case 1: /* FZ_PF_NULL_FLAGS */
            flagsPtr = NULL;
            break;
        case 2: /* FZ_PF_BAD_SIZE */
            flagsSize = 2;
            break;
        case 3: /* FZ_PF_ZERO_COUNT */
            count = 0;
            break;
        default: /* FZ_PF_EMPTY_RANGE */
            ranges[1].number_of_bytes = 0;
            break;
        }
        st = NtSetInformationVirtualMemory(NtCurrentProcess(), 0 /* VmPrefetchInformation */, count,
                                           ranges, flagsPtr, flagsSize);
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
    fz_setup_keys();
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
        fz_reset_keys();
        fz_reset_protect();
        fz_reset_apc();
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
