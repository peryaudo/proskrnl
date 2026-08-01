#!/usr/bin/env python3
"""gen_syscalls.py - generate the syscall number space and its consumers.

M7 pins the syscall NUMBERS to the pinned Wine tree's own 64-bit syscall id
table (third_party/wine/dlls/ntdll/ntsyscalls.h, ALL_SYSCALLS under _WIN64):
Wine's PE ntdll's Nt* exports are thunks that place that id in eax and
execute a raw `syscall` instruction (include/wine/asm.h __ASM_SYSCALL_FUNC),
so a kernel that speaks the same numbers runs the UNMODIFIED PE ntdll — the
whole point of the boundary. The ids are extracted, never retyped (Art. 4),
and change only with a Wine pin bump (which regenerates everything below).

Argument counts also come from that table (its per-entry stack-byte count /
8 on x64), cross-checkable against the winternl.h prototypes abi/ carries.

The IMPLEMENTED list below selects which ids get a real kernel handler and a
user-mode test stub; every other Wine syscall id gets a logging
STATUS_NOT_IMPLEMENTED row so an unimplemented syscall names itself on
serial (the M7 debug loop: "which Nt* did ntdll want next").

Generated files (never edit by hand; `make gen-abi` runs this):

    abi/syscall_numbers.h            NTSYS_* id macros (kernel + user)
    kernel/syscall/table.inc         X-macro feeding kernel/syscall/table.c
    tests/ntapi/syscall/syscall_stubs.S  user-mode Nt* stubs (SysV in,
                                         NT-x64-convention syscall out)
"""

import re
import sys
from pathlib import Path

# The Nt* the kernel implements, grouped by the milestone that added them.
# Ids and argument counts come from Wine's table; this list only SELECTS.
IMPLEMENTED = [
    # M3 Ob surface, reachable from user mode as of M4
    "NtClose",
    "NtDuplicateObject",
    "NtQueryObject",
    "NtMakeTemporaryObject",
    "NtCreateEvent",
    "NtOpenEvent",
    "NtSetEvent",
    "NtSetEventBoostPriority",
    "NtResetEvent",
    "NtClearEvent",
    "NtPulseEvent",
    "NtQueryEvent",
    "NtCreateMutant",
    "NtOpenMutant",
    "NtReleaseMutant",
    "NtQueryMutant",
    "NtCreateSemaphore",
    "NtOpenSemaphore",
    "NtReleaseSemaphore",
    "NtQuerySemaphore",
    "NtWaitForSingleObject",
    "NtWaitForMultipleObjects",
    "NtCreateDirectoryObject",
    "NtOpenDirectoryObject",
    "NtCreateSymbolicLinkObject",
    "NtOpenSymbolicLinkObject",
    "NtQuerySymbolicLinkObject",
    # M4 Mm + Ps surface
    "NtAllocateVirtualMemory",
    "NtFreeVirtualMemory",
    "NtQueryVirtualMemory",
    "NtTerminateProcess",
    "NtDisplayString",
    # M5 section surface
    "NtCreateSection",
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtQuerySection",
    # M6 Io surface
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtQueryInformationFile",
    "NtSetInformationFile",
    "NtQueryDirectoryFile",
    "NtQueryAttributesFile",
    "NtFlushBuffersFile",
    "NtLockFile",
    "NtUnlockFile",
    # M7 Ps/Ke surface: threads, the user dispatcher return protocol, the
    # queries Wine's ntdll issues at startup
    "NtCreateUserProcess",
    "NtCreateThreadEx",
    "NtOpenThread",
    "NtResumeThread",
    "NtSuspendThread",
    "NtTerminateThread",
    "NtAlertThread",
    "NtTestAlert",
    "NtYieldExecution",
    "NtDelayExecution",
    "NtQueueApcThread",
    "NtContinue",
    "NtRaiseException",
    "NtQueryInformationProcess",
    "NtSetInformationProcess",
    "NtQueryInformationThread",
    "NtSetInformationThread",
    "NtQueryPerformanceCounter",
    "NtQueryTimerResolution",
    "NtAddAtom",
    "NtAlertMultipleThreadByThreadId",
    "NtCreateKeyedEvent",
    "NtOpenKeyedEvent",
    "NtWaitForKeyedEvent",
    "NtReleaseKeyedEvent",
    "NtDeleteAtom",
    "NtFindAtom",
    "NtQueryInformationAtom",
    "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter",
    "NtQuerySystemInformation",
    "NtQuerySystemInformationEx",  # CUI-1: wineboot's supported-machines gate
    "NtPowerInformation",  # CUI-1: wineboot's ~MHz registry source
    "NtGetNextThread",  # M10: ntdll's TLS walk for runtime-loaded DLLs
    "NtQueryDefaultLocale",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtProtectVirtualMemory",
    "NtFlushInstructionCache",
    "NtAreMappedFilesTheSame",  # the loader's find_existing_module probe
    "NtContinueEx",
    "NtCallbackReturn",
    "NtWaitForAlertByThreadId",
    "NtAlertThreadByThreadId",
    # M7: ntdll startup services (NLS data, the volume query
    # RtlSetCurrentDirectory_U issues)
    "NtInitializeNlsFiles",
    "NtGetNlsSectionPtr",
    "NtQueryVolumeInformationFile",
    # M8 Cm surface (NtOpenKey/NtQueryValueKey were M7 graceful-failure
    # stubs; Cm makes them real)
    "NtCreateKey",
    "NtOpenKey",
    "NtOpenKeyEx",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtSetValueKey",
    "NtQueryValueKey",
    "NtEnumerateKey",
    "NtEnumerateValueKey",
    "NtQueryKey",
    "NtFlushKey",
    # M9 npfs + condrv surface: the ioctl/fsctl services and the named-pipe
    # create (14 arguments — the new dispatch maximum)
    "NtDeviceIoControlFile",
    "NtFsControlFile",
    "NtCreateNamedPipeFile",
    # M10 CUI userland surface
    "NtQuerySystemTime",
    "NtSetTimerResolution",
    "NtQueryFullAttributesFile",
    "NtCreateIoCompletion",
    "NtSetIoCompletion",
    "NtRemoveIoCompletion",
    "NtRemoveIoCompletionEx",
    "NtQueryIoCompletion",
    "NtCreateTimer",
    "NtSetTimer",
    "NtCancelTimer",
    "NtQueryTimer",
    # CUI-2 Se surface (kernel/se/): the token syscalls the already-baked
    # DLLs (kernelbase/security.c, ntdll/sec.c, advapi32) issue
    "NtOpenProcessToken",
    "NtOpenProcessTokenEx",
    "NtOpenThreadToken",
    "NtOpenThreadTokenEx",
    "NtQueryInformationToken",
    "NtAdjustPrivilegesToken",
    "NtDuplicateToken",
    "NtPrivilegeCheck",
    "NtAccessCheck",
    "NtAllocateLocallyUniqueId",
    "NtQuerySecurityObject",
    "NtSetSecurityObject",
    # CUI-3 SCM surface: cancel for pending pipe listens (services.exe's
    # CancelIo-on-timeout path against a stack OVERLAPPED)
    "NtCancelIoFile",
    "NtCancelIoFileEx",
    # CUI-3 SCM surface: the job objects services.exe's process monitor
    # drives (kernel/ps/job.c)
    "NtCreateJobObject",
    "NtAssignProcessToJobObject",
    "NtSetInformationJobObject",
    # CUI-4 the process ecosystem (tasklist/taskkill, job-driving build
    # tools); each row's kernel service lands in its own commit.
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtGetNextProcess",
    "NtSuspendProcess",
    "NtResumeProcess",
    "NtQueryInformationJobObject",
    "NtTerminateJobObject",
    "NtOpenJobObject",
    "NtIsProcessInJob",
    # CUI-5 Io completion: the file surface's last mile (docs/02); each
    # row's kernel service lands in its own commit.
    "NtDeleteFile",
    "NtReadFileScatter",
    "NtWriteFileGather",
    "NtFlushBuffersFileEx",
    "NtQueryEaFile",
    "NtSetEaFile",
    "NtSetVolumeInformationFile",
    "NtOpenIoCompletion",
    "NtSetIoCompletionEx",
    "NtQueryDirectoryObject",
    "NtCancelSynchronousIoFile",
    "NtNotifyChangeDirectoryFile",
    # CUI-6 handles/identity/query surface (docs/02); each row's kernel
    # service lands in its own commit.
    "NtFlushProcessWriteBuffers",
    "NtGetCurrentProcessorNumber",
    "NtSetThreadExecutionState",
    "NtSetInformationObject",
    "NtCompareObjects",
    "NtMakePermanentObject",
    "NtOpenTimer",
    "NtSignalAndWaitForSingleObject",
    "NtQueueApcThreadEx2",
    "NtAlertResumeThread",
    "NtSetInformationToken",
    "NtFilterToken",
    "NtAdjustGroupsToken",
    "NtImpersonateAnonymousToken",
    # CUI-7 Cm-2/Mm-2/system furniture (docs/02); each row's kernel service
    # lands in its own commit.
    "NtRenameKey",
    "NtNotifyChangeKey",
    "NtNotifyChangeMultipleKeys",
    "NtSaveKey",
    "NtLoadKey",
    "NtLoadKey2",
    "NtLoadKeyEx",
    "NtUnloadKey",
    "NtRestoreKey",
    "NtReplaceKey",
    "NtSetInformationKey",
    "NtQueryMultipleValueKey",
    "NtAllocateVirtualMemoryEx",
    "NtCreateSectionEx",
    "NtMapViewOfSectionEx",
    "NtUnmapViewOfSectionEx",
    "NtGetWriteWatch",
    "NtResetWriteWatch",
    "NtFlushVirtualMemory",
    "NtLockVirtualMemory",
    "NtUnlockVirtualMemory",
    "NtSetInformationVirtualMemory",
    "NtSetDefaultLocale",
    "NtQueryDefaultUILanguage",
    "NtSetDefaultUILanguage",
    "NtQueryInstallUILanguage",
    "NtSetSystemTime",
    "NtSetSystemInformation",
    "NtShutdownSystem",
]


def parse_wine_syscalls(root: Path):
    """The 64-bit id table from the pinned Wine: [(id, name, argc)] in id
    order, argc = stack bytes / 8 (x64: every argument is one slot)."""
    src = (root / "third_party/wine/dlls/ntdll/ntsyscalls.h").read_text()
    match = re.search(r"#ifdef _WIN64\n#define ALL_SYSCALLS \\\n(.*?)\n#else", src, re.S)
    if not match:
        sys.exit("gen_syscalls: ALL_SYSCALLS (_WIN64) not found in wine ntsyscalls.h")
    entries = []
    for sid, name, argbytes in re.findall(
        r"SYSCALL_ENTRY\w*\(\s*(0x[0-9a-fA-F]+),\s*(\w+),\s*(\d+)\s*\)", match.group(1)
    ):
        entries.append((int(sid, 16), name, int(argbytes) // 8))
    if len(entries) < 200:
        sys.exit(f"gen_syscalls: extraction looks wrong ({len(entries)} entries)")
    entries.sort()
    if [e[0] for e in entries] != list(range(len(entries))):
        sys.exit("gen_syscalls: wine 64-bit syscall ids are not dense")
    return entries

BANNER = """\
/* {name} - GENERATED by tools/gen_syscalls.py.
 * DO NOT EDIT BY HAND. The syscall list lives in tools/gen_syscalls.py;
 * regenerate with:
 *     python3 tools/gen_syscalls.py
 */
"""

# ---------------------------------------------------------------------------
# Differential-fuzzer op model (docs/08 "Differential fuzzing", tests/fuzz/).
#
# One model, two generated consumers — tests/fuzz/gen/fuzz_model.h (the C
# interpreter's decode tables) and tests/fuzz/gen/fuzz_model.py (the Python
# generator's view of the same shapes) — so the program encoder and decoder
# cannot drift, exactly like SYSCALLS above.
#
# G4 note: the Python side never sees a numeric ABI value. Choice-table
# entries are SYMBOLIC C expressions resolved per build mode by the same
# header switch every ntapi test uses (oracle: winternl.h et al.; proskrnl:
# generated abi/). Python only ever handles table sizes and indices.
#
# An entry marked avoid=True is excluded from default generation (it hits a
# documented docs/03 deviation); fuzz.py --allow-avoid includes it, which is
# also how the fuzzer's own detection path is exercised (tests/fuzz/README).

FUZZ_SLOT_COUNT = 16  # handle slots in the interpreter

# Object names the interpreter can pass (index 0 = anonymous / no name).
# Tags drive generation policy only; the strings become u"" literals in the
# interpreter. Deliberately includes syntactically bad and missing paths.
FUZZ_NAMES = [
    ("none", None),
    ("valid", "\\\\BaseNamedObjects\\\\fz0"),
    ("valid", "\\\\BaseNamedObjects\\\\fz1"),
    ("valid", "\\\\BaseNamedObjects\\\\fz2"),
    ("valid", "\\\\BaseNamedObjects\\\\fz3"),
    ("subdir", "\\\\BaseNamedObjects\\\\fzsub"),
    ("subitem", "\\\\BaseNamedObjects\\\\fzsub\\\\fz4"),
    ("bad", "fz_relative"),
    ("bad", ""),
    ("bad", "\\\\BaseNamedObjects\\\\fznodir\\\\x"),
    ("root", "\\\\"),
    ("basedir", "\\\\BaseNamedObjects"),
]

# File paths the M6 file ops use (index space only; the strings live in
# interp.c). Tag "valid" = creatable under \??\C:\fuzz; "badpath" = missing
# intermediate directory.
FUZZ_FILE_NAMES = [
    ("valid", "\\??\\C:\\fuzz\\fa.dat"),
    ("valid", "\\??\\C:\\fuzz\\fb.dat"),
    ("valid", "\\??\\C:\\fuzz\\Fuzz Long Name.Dat"),
    ("badpath", "\\??\\C:\\fuzz\\nodir\\x.dat"),
]

# M8 registry paths (index space only; strings in interp.c). All under the
# per-program-scrubbed \Registry\Machine\Software\fz_reg; "badpath" = missing
# intermediate key (NtCreateKey creates only the last component).
FUZZ_KEY_NAMES = [
    ("root", "\\Registry\\Machine\\Software\\fz_reg"),
    ("valid", "\\Registry\\Machine\\Software\\fz_reg\\ka"),
    ("valid", "\\Registry\\Machine\\Software\\fz_reg\\kb"),
    ("subitem", "\\Registry\\Machine\\Software\\fz_reg\\ka\\Sub Key"),
    ("badpath", "\\Registry\\Machine\\Software\\fz_reg\\nokey\\x"),
]

# Choice tables: name -> (c_type, [(c_expr, avoid), ...]). c_type None marks a
# semantic table: no C array is emitted, only the index space (the interpreter
# defines the meaning of each index itself, e.g. buffer-length shapes).
FUZZ_CHOICES = {
    "access_event": ("ACCESS_MASK", [
        ("EVENT_ALL_ACCESS", False),
        ("EVENT_MODIFY_STATE|SYNCHRONIZE", False),
        ("EVENT_MODIFY_STATE", False),
        ("EVENT_QUERY_STATE", False),
        ("SYNCHRONIZE", False),
        ("0", False),
        # docs/03 "Generic access mapping": proskrnl over-grants generic bits.
        ("GENERIC_READ", True),
        ("GENERIC_ALL", True),
    ]),
    "access_mutant": ("ACCESS_MASK", [
        ("MUTANT_ALL_ACCESS", False),
        ("MUTANT_QUERY_STATE|SYNCHRONIZE", False),
        ("MUTANT_QUERY_STATE", False),
        ("SYNCHRONIZE", False),
        ("0", False),
        ("GENERIC_READ", True),
    ]),
    "access_semaphore": ("ACCESS_MASK", [
        ("SEMAPHORE_ALL_ACCESS", False),
        ("SEMAPHORE_MODIFY_STATE|SYNCHRONIZE", False),
        ("SEMAPHORE_MODIFY_STATE", False),
        ("SEMAPHORE_QUERY_STATE", False),
        ("SYNCHRONIZE", False),
        ("0", False),
        ("GENERIC_READ", True),
    ]),
    "access_directory": ("ACCESS_MASK", [
        ("DIRECTORY_ALL_ACCESS", False),
        ("DIRECTORY_QUERY", False),
        ("DIRECTORY_QUERY|DIRECTORY_TRAVERSE", False),
        ("DIRECTORY_CREATE_OBJECT", False),
        ("0", False),
    ]),
    "access_symlink": ("ACCESS_MASK", [
        ("SYMBOLIC_LINK_ALL_ACCESS", False),
        ("SYMBOLIC_LINK_QUERY", False),
        ("0", False),
    ]),
    "objflags": ("ULONG", [
        ("OBJ_CASE_INSENSITIVE", False),
        ("0", False),
        ("OBJ_CASE_INSENSITIVE|OBJ_OPENIF", False),
    ]),
    "event_type": ("EVENT_TYPE", [
        ("NotificationEvent", False),
        ("SynchronizationEvent", False),
    ]),
    "bool": ("BOOLEAN", [("0", False), ("1", False)]),
    # Boundary-biased plain integers (not ABI constants).
    "long": ("LONG", [
        ("0", False), ("1", False), ("2", False), ("5", False),
        ("0x7fffffff", False), ("-1", False),
    ]),
    "ulong": ("ULONG", [
        ("1", False), ("2", False), ("0", False), ("0x7fffffff", False),
    ]),
    "wait_type": ("WAIT_TYPE", [("WaitAny", False), ("WaitAll", False)]),
    "dup_options": ("ULONG", [
        ("DUPLICATE_SAME_ACCESS", False),
        ("0", False),
        ("DUPLICATE_SAME_ATTRIBUTES", False),
        ("DUPLICATE_CLOSE_SOURCE", False),
    ]),
    # M6 file ops. Access/share/disposition kept to combinations whose
    # statuses the sem_file suite pins; GENERIC_* stays out (the docs/03
    # generic-mapping deviation would diverge).
    "access_file": ("ACCESS_MASK", [
        ("FILE_GENERIC_READ | FILE_GENERIC_WRITE", False),
        ("FILE_GENERIC_READ", False),
        ("FILE_READ_ATTRIBUTES | SYNCHRONIZE", False),
        ("FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE", False),
    ]),
    "share_file": ("ULONG", [
        ("0", False),
        ("FILE_SHARE_READ", False),
        ("FILE_SHARE_READ | FILE_SHARE_WRITE", False),
        ("FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE", False),
    ]),
    "disposition_file": ("ULONG", [
        ("FILE_OPEN", False),
        ("FILE_CREATE", False),
        ("FILE_OPEN_IF", False),
        ("FILE_OVERWRITE_IF", False),
    ]),
    # Semantic: transfer size / offset shapes; meanings live in interp.c.
    "iolen": (None, [
        ("FZ_IOLEN_ZERO", False),
        ("FZ_IOLEN_ONE", False),
        ("FZ_IOLEN_MID", False),
        ("FZ_IOLEN_BIG", False),
    ]),
    "iooff": (None, [
        ("FZ_IOOFF_ZERO", False),
        ("FZ_IOOFF_ONE", False),
        ("FZ_IOOFF_SECTOR", False),
        ("FZ_IOOFF_FAR", False),
    ]),
    # Semantic: buffer-length shape for NtQuery* (exact / zero / one short /
    # oversized). Meaning lives in interp.c. No NULL/wild buffer in v1 — an
    # asymmetric unprobed deref would crash the harness process and lose the
    # rest of the batch (plan: no wild pointers in v1).
    "len": (None, [
        ("FZ_LEN_EXACT", False),
        ("FZ_LEN_ZERO", False),
        ("FZ_LEN_SHORT", False),
        ("FZ_LEN_LONG", False),
    ]),
    # M7 Wine bring-up: NtGetNlsSectionPtr's type/id space. Types are the
    # generated NLS_SECTION_* (abi/ntpsapi.h; oracle mode declares them as
    # wine/dlls/ntdll/locale_private.h does); 1 is an unknown type
    # (parameter validation). Ids mix the shipped tables (case table id 0,
    # codepages 437/1252, NormalizationC, the IDNA table id 13 Wine
    # hard-codes) with misses (no c_000/c_9999 file).
    "nls_type": ("ULONG", [
        ("NLS_SECTION_CASEMAP", False),
        ("NLS_SECTION_CODEPAGE", False),
        ("NLS_SECTION_SORTKEYS", False),
        ("NLS_SECTION_NORMALIZE", False),
        ("1", False),
    ]),
    "nls_id": ("ULONG", [
        ("0", False),
        ("437", False),
        ("1252", False),
        ("NormalizationC", False),
        ("13", False),
        ("9999", False),
    ]),
    # M7: page protections for NtProtectVirtualMemory. The WRITECOPY flavours
    # need a backing file (rejected for private memory on both sides) and stay
    # out; these five are the private-memory-valid set the reprotect accepts.
    "protect_page": ("ULONG", [
        ("PAGE_NOACCESS", False),
        ("PAGE_READONLY", False),
        ("PAGE_READWRITE", False),
        ("PAGE_EXECUTE_READ", False),
        ("PAGE_EXECUTE_READWRITE", False),
    ]),
    # M8 Cm ops. Access masks/types are ABI symbols; the value-name, value-
    # data, and info-class spaces are semantic tables interp.c interprets
    # (the oracle's winternl.h doesn't declare the info-class enums on every
    # toolchain, so interp.c maps indices per build mode).
    "access_key": ("ACCESS_MASK", [
        ("KEY_ALL_ACCESS", False),
        ("KEY_READ", False),
        ("KEY_QUERY_VALUE", False),
        ("KEY_QUERY_VALUE|KEY_SET_VALUE", False),
        ("KEY_ENUMERATE_SUB_KEYS", False),
        ("0", False),
    ]),
    "reg_type": ("ULONG", [
        ("REG_SZ", False),
        ("REG_DWORD", False),
        ("REG_BINARY", False),
        ("REG_MULTI_SZ", False),
        ("REG_NONE", False),
    ]),
    "reg_options": ("ULONG", [
        ("0", False),
        ("REG_OPTION_VOLATILE", False),
    ]),
    "vname": (None, [
        ("FZ_VNAME_DEFAULT", False),
        ("FZ_VNAME_A", False),
        ("FZ_VNAME_B", False),
        ("FZ_VNAME_MISSING", False),
    ]),
    "vdata": (None, [
        ("FZ_VDATA_EMPTY", False),
        ("FZ_VDATA_DWORD", False),
        ("FZ_VDATA_ODD", False),
        ("FZ_VDATA_MID", False),
    ]),
    "key_info": (None, [
        ("FZ_KINFO_BASIC", False),
        ("FZ_KINFO_NODE", False),
        ("FZ_KINFO_FULL", False),
    ]),
    "kv_info": (None, [
        ("FZ_KVINFO_BASIC", False),
        ("FZ_KVINFO_FULL", False),
        ("FZ_KVINFO_PARTIAL", False),
    ]),
    # CUI-3: job-object creation access + the NtSetInformationJobObject
    # argument-gate scenarios (semantic indices interp.c interprets: valid
    # and invalid limit classes/sizes/flag masks — validated + stored,
    # never enforced, so statuses are deterministic on both sides).
    "access_job": ("ACCESS_MASK", [
        ("JOB_OBJECT_ALL_ACCESS", False),
        ("SYNCHRONIZE", False),
        ("0", False),
    ]),
    "job_scenario": (None, [
        ("FZ_JOB_BASIC_VALID", False),
        ("FZ_JOB_BASIC_BADFLAGS", False),
        ("FZ_JOB_BASIC_BADSIZE", False),
        ("FZ_JOB_EXT_VALID", False),
        ("FZ_JOB_EXT_BADSIZE", False),
        ("FZ_JOB_CLASS_CEILING", False),
    ]),
    # CUI-4: the CLIENT_ID shapes NtOpenProcess resolves deterministically —
    # the interp's own pid, and ids that can never name a live process.
    "process_cid": (None, [
        ("FZ_CID_SELF", False),
        ("FZ_CID_NEVER_ALLOCATED", False),
        ("FZ_CID_ZERO", False),
    ]),
    # The NtRead/WriteVirtualMemory cases over the interp's OWN memory: a
    # whole buffer, a zero-length move, and an address that is never mapped
    # on either side (the STATUS_PARTIAL_COPY path).
    "vm_scenario": (None, [
        ("FZ_VM_WHOLE", False),
        ("FZ_VM_ZERO_LENGTH", False),
        ("FZ_VM_UNMAPPED", False),
    ]),
    # The job query classes whose answers are deterministic for an EMPTY,
    # interp-created job (counts are 0/0; the limit read-back mirrors what
    # set_job_limits stored).
    "job_query": (None, [
        ("FZ_JOBQ_ACCOUNTING", False),
        ("FZ_JOBQ_PID_LIST", False),
        ("FZ_JOBQ_BASIC_LIMITS", False),
        ("FZ_JOBQ_CLASS_CEILING", False),
    ]),
}

# Operand kinds: slot_in / slot_out / name / ch_<table>. The encoded program
# carries one byte per operand; the kind fixes its valid range.
FUZZ_OPS = [
    # (op name, Nt* it drives, [operand kinds])
    ("create_event", "NtCreateEvent",
     ["slot_out", "ch_access_event", "name", "ch_objflags", "ch_event_type", "ch_bool"]),
    ("open_event", "NtOpenEvent", ["slot_out", "ch_access_event", "name", "ch_objflags"]),
    ("set_event", "NtSetEvent", ["slot_in", "ch_bool"]),
    ("reset_event", "NtResetEvent", ["slot_in", "ch_bool"]),
    ("clear_event", "NtClearEvent", ["slot_in"]),
    ("pulse_event", "NtPulseEvent", ["slot_in", "ch_bool"]),
    ("query_event", "NtQueryEvent", ["slot_in", "ch_len"]),
    ("create_mutant", "NtCreateMutant",
     ["slot_out", "ch_access_mutant", "name", "ch_objflags", "ch_bool"]),
    ("open_mutant", "NtOpenMutant", ["slot_out", "ch_access_mutant", "name", "ch_objflags"]),
    ("release_mutant", "NtReleaseMutant", ["slot_in", "ch_bool"]),
    ("query_mutant", "NtQueryMutant", ["slot_in", "ch_len"]),
    ("create_semaphore", "NtCreateSemaphore",
     ["slot_out", "ch_access_semaphore", "name", "ch_objflags", "ch_long", "ch_long"]),
    ("open_semaphore", "NtOpenSemaphore",
     ["slot_out", "ch_access_semaphore", "name", "ch_objflags"]),
    ("release_semaphore", "NtReleaseSemaphore", ["slot_in", "ch_ulong", "ch_bool"]),
    ("query_semaphore", "NtQuerySemaphore", ["slot_in", "ch_len"]),
    ("wait_single", "NtWaitForSingleObject", ["slot_in"]),
    ("wait_multiple", "NtWaitForMultipleObjects", ["slot_in", "slot_in", "ch_wait_type"]),
    ("close", "NtClose", ["slot_in"]),
    ("duplicate", "NtDuplicateObject",
     ["slot_in", "slot_out", "ch_access_event", "ch_dup_options"]),
    ("make_temporary", "NtMakeTemporaryObject", ["slot_in"]),
    ("create_directory", "NtCreateDirectoryObject",
     ["slot_out", "ch_access_directory", "name", "ch_objflags"]),
    ("open_directory", "NtOpenDirectoryObject",
     ["slot_out", "ch_access_directory", "name", "ch_objflags"]),
    ("create_symlink", "NtCreateSymbolicLinkObject",
     ["slot_out", "ch_access_symlink", "name", "ch_objflags", "name"]),
    ("open_symlink", "NtOpenSymbolicLinkObject",
     ["slot_out", "ch_access_symlink", "name", "ch_objflags"]),
    ("query_symlink", "NtQuerySymbolicLinkObject", ["slot_in", "ch_len"]),
    # M6 file surface (paths under \??\C:\fuzz; per-program scrub in interp.c)
    ("create_file", "NtCreateFile",
     ["slot_out", "ch_access_file", "fname", "ch_share_file", "ch_disposition_file"]),
    ("read_file", "NtReadFile", ["slot_in", "ch_iolen", "ch_iooff"]),
    ("write_file", "NtWriteFile", ["slot_in", "ch_iolen", "ch_iooff"]),
    ("set_eof_file", "NtSetInformationFile", ["slot_in", "ch_iooff"]),
    ("query_standard_file", "NtQueryInformationFile", ["slot_in"]),
    # CUI-5: FileRenameInformation between the fixed fuzz paths (the interp's
    # per-program scrub keeps the replay deterministic)
    ("rename_file", "NtSetInformationFile", ["slot_in", "fname", "ch_bool"]),
    # CUI-5: the flush/EA trio (stateless against any slot)
    ("flush_ex_file", "NtFlushBuffersFileEx", ["slot_in"]),
    ("query_ea_file", "NtQueryEaFile", ["slot_in", "ch_len"]),
    ("set_ea_file", "NtSetEaFile", ["slot_in"]),
    # M7 mechanical Ps/Mm surface — process/system information
    # length-checking and the in-place reprotect.
    ("query_process_basic", "NtQueryInformationProcess", ["ch_len"]),
    ("query_system_basic", "NtQuerySystemInformation", ["ch_len"]),
    ("protect_memory", "NtProtectVirtualMemory", ["ch_protect_page"]),
    # M7 user-APC delivery. Possible since the interp became a real ntdll
    # client on both sides (the single-binary harness, docs/14) — the old
    # flat proskrnl binary could not export KiUserApcDispatcher. Single
    # thread + draining only at the explicit test_alert op keeps delivery
    # deterministic (FIFO) and the trace canonical; the APC routines fold
    # what they saw into counters that test_alert's one trace line prints.
    # Threads stay out for a LIVE reason: scheduling nondeterminism would
    # diff the traces themselves.
    ("queue_apc", "NtQueueApcThread", ["ch_ulong"]),
    ("read_file_apc", "NtReadFile", ["slot_in", "ch_iolen", "ch_iooff"]),
    ("test_alert", "NtTestAlert", []),
    # M7 Wine bring-up: the NLS data services ntdll's locale_init issues.
    ("init_nls", "NtInitializeNlsFiles", []),
    ("get_nls_section", "NtGetNlsSectionPtr", ["ch_nls_type", "ch_nls_id"]),
    # M8 Cm surface (paths under \Registry\Machine\Software\fz_reg;
    # per-program scrub in interp.c).
    ("create_key", "NtCreateKey", ["slot_out", "ch_access_key", "kname", "ch_reg_options"]),
    ("open_key", "NtOpenKey", ["slot_out", "ch_access_key", "kname"]),
    ("delete_key", "NtDeleteKey", ["slot_in"]),
    ("set_value_key", "NtSetValueKey", ["slot_in", "ch_vname", "ch_reg_type", "ch_vdata"]),
    ("delete_value_key", "NtDeleteValueKey", ["slot_in", "ch_vname"]),
    ("query_value_key", "NtQueryValueKey", ["slot_in", "ch_vname", "ch_kv_info", "ch_len"]),
    ("enum_value_key", "NtEnumerateValueKey", ["slot_in", "ch_ulong", "ch_kv_info", "ch_len"]),
    ("enumerate_key", "NtEnumerateKey", ["slot_in", "ch_ulong", "ch_key_info", "ch_len"]),
    ("query_key", "NtQueryKey", ["slot_in", "ch_key_info", "ch_len"]),
    ("flush_key", "NtFlushKey", ["slot_in"]),
    # CUI-3 SCM surface. Cancel is deterministic on any slot: the
    # single-threaded interp never has an operation pending, so the
    # thread-scoped verb succeeds and the Ex form answers NOT_FOUND on any
    # resolvable handle (wineserver's cancel_async takes ANY object).
    # Jobs stay anonymous and are only argument-gated (limits are validated
    # + stored, never enforced — docs/03 "CUI-3 SCM notes"), so every
    # scenario's status is deterministic on both sides. Assignment stays
    # out: assigning the interp to a job is irreversible state, and
    # re-assignment answers differ (nesting is unbuilt, docs/03).
    ("cancel_io", "NtCancelIoFile", ["slot_in"]),
    ("cancel_io_ex", "NtCancelIoFileEx", ["slot_in"]),
    ("create_job", "NtCreateJobObject", ["slot_out", "ch_access_job"]),
    ("set_job_limits", "NtSetInformationJobObject", ["slot_in", "ch_job_scenario"]),
    # CUI-4 process-ecosystem ops. Only the DETERMINISTIC slice: opening a
    # process by a CLIENT_ID the interp itself supplies (self, or an id that
    # was never a process), the length gating of the process-list query (its
    # CONTENTS are inherently host-specific — trace status + whether a size
    # came back, never the bytes), and reads/writes of the interp's OWN
    # memory. Foreign-process ops stay out: another process's liveness is not
    # reproducible across the two sides. Suspend/terminate of self are
    # irreversible, so they stay out too (the cancel_io precedent).
    ("open_process", "NtOpenProcess", ["slot_out", "ch_process_cid"]),
    ("query_system_processes", "NtQuerySystemInformation", ["ch_len"]),
    ("read_own_memory", "NtReadVirtualMemory", ["ch_vm_scenario"]),
    ("write_own_memory", "NtWriteVirtualMemory", ["ch_vm_scenario"]),
    ("is_process_in_job", "NtIsProcessInJob", ["slot_in"]),
    ("query_job_info", "NtQueryInformationJobObject", ["slot_in", "ch_job_query"]),
    # CUI-6 handles/identity ops. Only the DETERMINISTIC, side-effect-bounded
    # slice: comparing two interp slots, the handle-flag get/set idiom on a
    # slot, and the two no-argument no-power ids (flush is always SUCCESS, the
    # processor number is 0 on the uniprocessor). Foreign-thread context,
    # make-permanent (irreversible named-object state) and signal-and-wait
    # (may block) stay out, the cancel_io/suspend precedent.
    ("compare_objects", "NtCompareObjects", ["slot_in", "slot_in"]),
    ("set_handle_info", "NtSetInformationObject", ["slot_in", "ch_bool", "ch_bool"]),
    ("query_handle_flags", "NtQueryObject", ["slot_in", "ch_len"]),
    ("flush_write_buffers", "NtFlushProcessWriteBuffers", []),
    ("current_processor", "NtGetCurrentProcessorNumber", []),
]


def gen_numbers(wine_syscalls) -> str:
    by_name = {name: (sid, argc) for sid, name, argc in wine_syscalls}
    missing = [n for n in IMPLEMENTED if n not in by_name]
    if missing:
        sys.exit(f"gen_syscalls: not in wine's 64-bit table: {missing}")
    lines = [f"#define NTSYS_{name} {by_name[name][0]:#06x}" for name in IMPLEMENTED]
    return (
        BANNER.format(name="abi/syscall_numbers.h")
        + "#ifndef PROSKRNL_ABI_SYSCALL_NUMBERS_H\n"
        + "#define PROSKRNL_ABI_SYSCALL_NUMBERS_H\n\n"
        + "/* Ids are the pinned Wine tree's 64-bit syscall numbers\n"
        + " * (third_party/wine/dlls/ntdll/ntsyscalls.h) - the values its PE\n"
        + " * ntdll's thunks place in eax. Only implemented services are listed;\n"
        + " * the kernel table covers the full id space (unimplemented ids log\n"
        + " * and fail with STATUS_NOT_IMPLEMENTED). */\n"
        + "\n".join(lines)
        + f"\n\n/* One past the highest Wine 64-bit syscall id. */\n"
        + f"#define NTSYS_SYSCALL_LIMIT {len(wine_syscalls):#06x}\n"
        + "\n#endif /* PROSKRNL_ABI_SYSCALL_NUMBERS_H */\n"
    )


def gen_table_inc(wine_syscalls) -> str:
    implemented = set(IMPLEMENTED)
    lines = []
    for sid, name, argc in wine_syscalls:
        if name in implemented:
            lines.append(f"KI_SYSCALL({sid:#06x}, {name}, {argc})")
        else:
            lines.append(f"KI_SYSCALL_MISSING({sid:#06x}, {name}, {argc})")
    return (
        BANNER.format(name="kernel/syscall/table.inc")
        + "/* X-macros in Wine-64-bit-syscall-id order (ids dense from 0):\n"
        + " *   KI_SYSCALL(id, name, argumentCount)          implemented service\n"
        + " *   KI_SYSCALL_MISSING(id, name, argumentCount)  known id, no kernel\n"
        + " *                                                service yet\n"
        + " * kernel/syscall/table.c defines both and includes this file. */\n"
        + "\n".join(lines)
        + "\n"
    )


def stub_frame_size(wine_syscalls) -> int:
    """One uniform stub frame sized for the widest IMPLEMENTED service: the
    NT-convention slots reach [rsp + 0x28 + 8*(argc-5)], and the frame keeps
    the incoming SysV 16-byte alignment (rsp ≡ 8 mod 16 at entry, so the
    frame size must be ≡ 8 mod 16)."""
    by_name = {name: argc for _sid, name, argc in wine_syscalls}
    max_argc = max(by_name[name] for name in IMPLEMENTED)
    frame = 0x28 + 8 * max(max_argc - 4, 0)
    if frame % 16 != 8:
        frame += 8
    return frame


def gen_stubs(wine_syscalls) -> str:
    by_name = {name: (sid, argc) for sid, name, argc in wine_syscalls}
    frame = stub_frame_size(wine_syscalls)
    stubs = []
    for name in IMPLEMENTED:
        sid, argc = by_name[name]
        body = [f"    .global {name}", f"{name}:"]
        if argc <= 4:
            # Register-only: permute SysV rdi/rsi/rdx/rcx into NT r10/rdx/r8/r9.
            body += [
                "    mov %rcx, %r9",
                "    mov %rdx, %r8",
                "    mov %rsi, %rdx",
                "    mov %rdi, %r10",
                f"    mov ${sid:#x}, %eax",
                "    syscall",
                "    ret",
            ]
        else:
            # Build an NT-shaped stack: args 5+ live at [rsp+0x28+8n] at the
            # syscall instruction. The frame covers the widest implemented
            # service (stub_frame_size); SysV stack args moved down shift by
            # the same frame.
            body.append(f"    sub ${frame:#x}, %rsp")
            body.append("    mov %r8, 0x28(%rsp)")   # NT arg5 = SysV r8
            if argc >= 6:
                body.append("    mov %r9, 0x30(%rsp)")  # NT arg6 = SysV r9
            for extra in range(argc - 6):  # NT arg7+ = SysV stack args
                body.append(f"    mov {frame + 8 + 8 * extra:#x}(%rsp), %rax")
                body.append(f"    mov %rax, {0x38 + 8 * extra:#x}(%rsp)")
            body += [
                "    mov %rcx, %r9",
                "    mov %rdx, %r8",
                "    mov %rsi, %rdx",
                "    mov %rdi, %r10",
                f"    mov ${sid:#x}, %eax",
                "    syscall",
                f"    add ${frame:#x}, %rsp",
                "    ret",
            ]
        stubs.append("\n".join(body) + "\n")
    return (
        BANNER.format(name="tests/ntapi/syscall/syscall_stubs.S")
        + "/* User-mode Nt* stubs for the proskrnl ntapi target and the M4+ user\n"
        + " * clients (docs/14). The kernel speaks the NT x64 syscall convention\n"
        + " * (M7) - the one Wine's PE ntdll thunks emit (include/wine/asm.h\n"
        + " * __ASM_SYSCALL_FUNC): id in eax, arguments 1-4 in r10/rdx/r8/r9,\n"
        + " * arguments 5+ on the user stack at [rsp+0x28+8n] (the Windows-ABI\n"
        + " * caller frame: return address + 4 shadow slots), NTSTATUS in eax.\n"
        + " * These stubs adapt a SysV caller (our freestanding clang tests /\n"
        + " * -mabi=sysv PE clients) to that convention by permuting registers\n"
        + " * and, for >4 arguments, building the NT-shaped stack area.\n"
        + " * The M5 PE clients assemble this same file with a COFF-targeting\n"
        + " * gas, which has no .note.GNU-stack - hence the __ELF__ guard. */\n"
        + "    .section .text\n"
        + "\n".join(stubs)
        + "\n#ifdef __ELF__\n"
        + '    .section .note.GNU-stack, "", @progbits\n'
        + "#endif\n"
    )


def _operand_kinds():
    """Ordered unique operand-kind names across FUZZ_OPS, for a C enum."""
    seen = []
    for _op, _nt, kinds in FUZZ_OPS:
        for k in kinds:
            if k not in seen:
                seen.append(k)
    return seen


def gen_fuzz_model_h() -> str:
    lines = [BANNER.format(name="tests/fuzz/gen/fuzz_model.h")]
    lines.append("#ifndef PROSKRNL_FUZZ_MODEL_H")
    lines.append("#define PROSKRNL_FUZZ_MODEL_H\n")
    lines.append("/* Decode tables for tests/fuzz/interp.c. The choice arrays below hold")
    lines.append(" * SYMBOLIC constants resolved by the system NT headers the single-binary")
    lines.append(" * ntapi build compiles against (docs/14) — no numeric ABI value")
    lines.append(" * appears here or in the Python generator (G4). */\n")

    lines.append(f"#define FZ_SLOT_COUNT {FUZZ_SLOT_COUNT}")
    lines.append(f"#define FZ_NAME_COUNT {len(FUZZ_NAMES)}")
    lines.append(f"#define FZ_FNAME_COUNT {len(FUZZ_FILE_NAMES)}")
    lines.append(f"#define FZ_KNAME_COUNT {len(FUZZ_KEY_NAMES)}\n")

    # Operand-kind enum.
    lines.append("typedef enum {")
    for k in _operand_kinds():
        lines.append(f"    FZ_OPND_{k.upper()},")
    lines.append("} FzOperandKind;\n")

    # Opcode enum.
    lines.append("typedef enum {")
    for op, _nt, _k in FUZZ_OPS:
        lines.append(f"    FZ_OP_{op.upper()},")
    lines.append(f"    FZ_OP_COUNT")
    lines.append("} FzOpcode;\n")

    # Per-op operand-kind arrays + count, for the generic decode loop.
    lines.append("typedef struct { const FzOperandKind *kinds; int count; "
                 "const char *nt_name; } FzOpDesc;")
    for op, _nt, kinds in FUZZ_OPS:
        if kinds:
            arr = ", ".join(f"FZ_OPND_{k.upper()}" for k in kinds)
            lines.append(f"static const FzOperandKind fz_kinds_{op}[] = {{ {arr} }};")
        else:
            lines.append(f"static const FzOperandKind fz_kinds_{op}[1];")
    lines.append("static const FzOpDesc fz_ops[FZ_OP_COUNT] = {")
    for op, nt, kinds in FUZZ_OPS:
        lines.append(f"    [FZ_OP_{op.upper()}] = {{ fz_kinds_{op}, {len(kinds)}, \"{nt}\" }},")
    lines.append("};\n")

    # Choice tables (symbolic). Semantic tables (c_type None) get only a size.
    for name, (ctype, entries) in FUZZ_CHOICES.items():
        lines.append(f"#define FZ_CH_{name.upper()}_COUNT {len(entries)}")
        if ctype is not None:
            arr = ", ".join(f"({ctype})({expr})" for expr, _avoid in entries)
            lines.append(f"static const {ctype} fz_ch_{name}[] = {{ {arr} }};")
    lines.append("")

    # Name table: the strings themselves (u"" literals) live in interp.c so it
    # controls the char16_t typing; here we only fix the count (above).
    lines.append("#endif /* PROSKRNL_FUZZ_MODEL_H */")
    return "\n".join(lines) + "\n"


def gen_fuzz_model_py() -> str:
    out = ['"""fuzz_model.py - GENERATED by tools/gen_syscalls.py. DO NOT EDIT.',
           "",
           "The Python generator's view of the fuzz op model. Mirrors",
           "tests/fuzz/gen/fuzz_model.h so encoder and decoder cannot drift.",
           "Only shapes (kinds, counts, indices) live here — never ABI values.",
           '"""',
           "",
           f"SLOT_COUNT = {FUZZ_SLOT_COUNT}",
           ""]
    # Name tags (for generation policy) — not the strings.
    out.append("# (index, tag) for each object name; index 0 = anonymous.")
    out.append("NAME_TAGS = [")
    for i, (tag, _s) in enumerate(FUZZ_NAMES):
        out.append(f"    ({i}, {tag!r}),")
    out.append("]")
    out.append("")
    out.append("# (index, tag) for each M6 file path.")
    out.append("FNAME_TAGS = [")
    for i, (tag, _s) in enumerate(FUZZ_FILE_NAMES):
        out.append(f"    ({i}, {tag!r}),")
    out.append("]")
    out.append("")
    out.append("# (index, tag) for each M8 registry path.")
    out.append("KNAME_TAGS = [")
    for i, (tag, _s) in enumerate(FUZZ_KEY_NAMES):
        out.append(f"    ({i}, {tag!r}),")
    out.append("]")
    out.append("")
    # Choice sizes + which indices are 'avoid'.
    out.append("# table name -> (count, [avoid indices])")
    out.append("CHOICES = {")
    for name, (_ctype, entries) in FUZZ_CHOICES.items():
        avoid = [i for i, (_e, a) in enumerate(entries) if a]
        out.append(f"    {name!r}: ({len(entries)}, {avoid!r}),")
    out.append("}")
    out.append("")
    # Ops: name -> (opcode index, [operand kinds]).
    out.append("# op name -> (opcode, [operand kind strings])")
    out.append("OPS = [")
    for i, (op, nt, kinds) in enumerate(FUZZ_OPS):
        out.append(f"    ({op!r}, {i}, {nt!r}, {kinds!r}),")
    out.append("]")
    out.append("")
    return "\n".join(out)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    wine_syscalls = parse_wine_syscalls(root)
    for path, text in [
        (root / "abi/syscall_numbers.h", gen_numbers(wine_syscalls)),
        (root / "kernel/syscall/table.inc", gen_table_inc(wine_syscalls)),
        (root / "tests/ntapi/syscall/syscall_stubs.S", gen_stubs(wine_syscalls)),
        (root / "tests/fuzz/gen/fuzz_model.h", gen_fuzz_model_h()),
        (root / "tests/fuzz/gen/fuzz_model.py", gen_fuzz_model_py()),
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"gen_syscalls: wrote {path.relative_to(root)}")


if __name__ == "__main__":
    main()
