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

import argparse
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
    # The CUI winetest frontier (docs/21 W12): ntdll:reg's named license
    # lookup, answered out of the seeded key (kernel/cm/registry.c).
    "NtQueryLicenseValue",
    # WOW64 (docs/02): the per-process LDT (kernel/ps/ldt.c) and the
    # debugger-ATTACH corner ADR 0011's WOW64 amendment re-opened —
    # DebugActiveProcess/Stop and nothing else (kernel/ps/debug.c; the rest
    # of the debug-object family keeps its loud refusal).
    "NtSetLdtEntries",
    "NtCreateDebugObject",
    "NtDebugActiveProcess",
    "NtRemoveProcessDebug",
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
# The pointer-torture matrix (issue #32 A1, tests/ntapi/syscall/ptr_torture.c).
#
# The argument SHAPE of every implemented service, extracted from the pinned
# Wine tree's own prototypes, so a hostile-pointer sweep over the whole
# syscall surface is complete BY CONSTRUCTION rather than by whoever
# remembered to write a case. The defect it hunts is the one the differential
# harness structurally cannot reach: the oracle answers "what is the right
# semantics for a well-formed call", and has nothing whatever to say about a
# service handed a kernel address — Wine is not a kernel and has no ring
# boundary. So the verdict changes from MATCHES to SURVIVES AND REFUSES
# LOUDLY, and the enumeration has to come from somewhere other than a test
# author's memory. It comes from here.
#
# Same reasoning as G4 for constants: the shape is EXTRACTED, never retyped,
# and the extraction is the reason a service added tomorrow is swept the day
# it lands. `IMPLEMENTED` above is the enrolment list; nothing else opts in.
#
# The classification is by TYPE SPELLING, and every spelling is listed
# explicitly below: a prototype carrying a spelling this file has never seen
# makes the generator REFUSE, naming the type. Guessing from a leading `P`
# would misfile PROCESSINFOCLASS and POWER_INFORMATION_LEVEL as pointers, and
# a matrix that silently tortures the wrong argument is worse than one that
# stops and asks (Art. 4's rule applied to shapes instead of numbers).

# Kind letters, as the generated table spells them. The driver
# (tests/ntapi/syscall/ptr_torture.c) defines what each one is fed.
#   S  scalar          - a value; tortured with saturated lengths
#   H  handle          - tortured only by the pass baseline (invalid / live),
#                        never with a hostile POINTER, so a NULL that means
#                        "the current process" cannot make the sweep shoot
#                        the runner it is running in
#   P  pointer         - the main event: every hostile address in turn
#   U  PUNICODE_STRING - a pointer, plus the counted-string interior
#                        (hostile Buffer behind a well-formed descriptor)
#   O  POBJECT_ATTRIBUTES - a pointer, plus the interior (hostile ObjectName,
#                        lying Length)
#   F  callback        - a ring-3 routine the kernel stores and never
#                        dereferences; always NULL, so the sweep cannot end up
#                        asking a thread to jump into a hostile address
SCALAR_TYPES = {
    "ACCESS_MASK", "BOOL", "BOOLEAN", "DWORD", "EVENT_TYPE", "EXECUTION_STATE",
    "LANGID", "LCID", "LONG", "NTSTATUS", "RTL_ATOM", "SECTION_INHERIT",
    "SECURITY_INFORMATION", "SHUTDOWN_ACTION", "SIZE_T", "TIMER_TYPE",
    "TOKEN_TYPE", "ULONG", "ULONG_PTR", "WAIT_TYPE", "int",
}

# An INFORMATION CLASS is a scalar the sweep holds STILL, and this is the one
# place the matrix deliberately looks away.
#
# A class selects WHICH of a service's bodies runs, so saturating it does not
# ask a harder question about the same code — it asks for a body that does not
# exist, and the answer to that is STATUS_NOT_IMPLEMENTED, which a ring-3
# caller turns into a panic (Art. 12 / G12, kernel/syscall/table.c). The
# machine halts on the first unbuilt class in the first enum and the remaining
# ~190 services are never swept at all. The class space IS a real backlog and
# deserves a real instrument — but a different one: it enumerates a CONTRACT
# (what each class must answer, against the oracle), which is issue #32's 2.1,
# not a liveness sweep that has to survive in order to finish.
#
# So a class argument is pinned to a value the kernel builds and the sweep
# tortures the POINTERS around it — which is what reaches the copy paths at
# all. Each value is that class's basic/first case; the comment names the
# enumerator so the number is checkable against the pinned Wine headers rather
# than taken on faith (G4's habit, even though a test input is not a contract
# constant). A value the kernel does NOT build announces itself immediately —
# the sweep panics on that service — so these cannot rot silently.
CLASS_TYPES = {
    "ATOM_INFORMATION_CLASS": (0, "AtomBasicInformation"),
    "EVENT_INFORMATION_CLASS": (0, "EventBasicInformation"),
    "FILE_INFORMATION_CLASS": (4, "FileBasicInformation"),
    "FS_INFORMATION_CLASS": (1, "FileFsVolumeInformation"),
    "IO_COMPLETION_INFORMATION_CLASS": (0, "IoCompletionBasicInformation"),
    "JOBOBJECTINFOCLASS": (1, "JobObjectBasicAccountingInformation"),
    "KEY_INFORMATION_CLASS": (0, "KeyBasicInformation"),
    "KEY_VALUE_INFORMATION_CLASS": (0, "KeyValueBasicInformation"),
    "MEMORY_INFORMATION_CLASS": (0, "MemoryBasicInformation"),
    "MUTANT_INFORMATION_CLASS": (0, "MutantBasicInformation"),
    "OBJECT_INFORMATION_CLASS": (0, "ObjectBasicInformation"),
    "POWER_INFORMATION_LEVEL": (11, "ProcessorInformation"),
    "PROCESSINFOCLASS": (0, "ProcessBasicInformation"),
    "SECTION_INFORMATION_CLASS": (0, "SectionBasicInformation"),
    "SEMAPHORE_INFORMATION_CLASS": (0, "SemaphoreBasicInformation"),
    "SYSTEM_INFORMATION_CLASS": (0, "SystemBasicInformation"),
    "THREADINFOCLASS": (0, "ThreadBasicInformation"),
    "TIMER_INFORMATION_CLASS": (0, "TimerBasicInformation"),
    "TOKEN_INFORMATION_CLASS": (1, "TokenUser"),
    "VIRTUAL_MEMORY_INFORMATION_CLASS": (0, "VmPrefetchInformation"),
}

# Pointer typedefs that hide their pointer-ness behind a P/LP prefix (a
# spelling ending in `*` needs no table).
POINTER_TYPES = {
    "LPCVOID", "PBOOLEAN", "PCONTEXT", "PDIRECTORY_BASIC_INFORMATION",
    "PDWORD", "PGENERIC_MAPPING", "PHANDLE", "PIO_STATUS_BLOCK",
    "PKEY_MULTIPLE_VALUE_INFORMATION", "PLARGE_INTEGER", "PLONG", "PLUID",
    "PMEMORY_RANGE_ENTRY", "PPRIVILEGE_SET", "PSECURITY_DESCRIPTOR",
    "PTOKEN_GROUPS", "PTOKEN_PRIVILEGES", "PULONG", "PULONG_PTR", "PVOID",
}
STRING_TYPES = {"PUNICODE_STRING", "UNICODE_STRING"}
OBJATTR_TYPES = {"POBJECT_ATTRIBUTES", "OBJECT_ATTRIBUTES"}
CALLBACK_TYPES = {
    "PIO_APC_ROUTINE", "PNTAPCFUNC", "PRTL_THREAD_START_ROUTINE",
    "PTIMER_APC_ROUTINE",
}

# Services the sweep must NOT call at all, each with the reason it is out.
# This is the ONLY judgment in the matrix, and it is deliberately about the
# sweep's own survival, never about whether a service is likely to be buggy:
# a sweep that terminates itself, or parks forever, reports nothing about the
# 200 services it never reached. Enrolment is the default — a service added
# to IMPLEMENTED tomorrow is swept tomorrow — so this list can only shrink a
# run that has already been reasoned about, and the generated table names
# every exclusion so a reader of the test output sees what was not asked.
TORTURE_EXCLUDE = {
    "NtContinue": "transfers control to a caller-supplied context; never returns",
    "NtContinueEx": "transfers control to a caller-supplied context; never returns",
    "NtCallbackReturn": "unwinds a user callback frame the sweep is not inside",
    "NtRaiseException": "raises into the sweep's own thread; never returns normally",
    "NtTerminateProcess": "a NULL handle means the CURRENT process — it would kill the sweep",
    "NtTerminateThread": "a NULL handle means the CURRENT thread — it would kill the sweep",
    "NtShutdownSystem": "powers the machine off, taking every later case with it",
    "NtSetSystemTime": "moves the wall clock under every test that runs after this one",
    "NtSetSystemInformation": "writes machine-global state the rest of the leg reads",
    "NtWaitForAlertByThreadId": "a NULL timeout parks forever and nothing here alerts",
}

# Services swept only with the INVALID-handle baseline: the second pass hands
# every handle argument a live, signalled event, and for these that is the
# difference between a call that returns and a leg that hangs. Reaching the
# pointer paths behind the handle check is exactly what pass 2 is for, so an
# entry here is a coverage loss, not a free choice — the reason has to be
# "this parks", never "this looked risky".
TORTURE_NO_LIVE_HANDLE = {
    "NtWaitForSingleObject": "a live non-signalled handle + NULL timeout parks forever",
    "NtWaitForMultipleObjects": "a live non-signalled handle + NULL timeout parks forever",
    "NtSignalAndWaitForSingleObject": "the wait half parks forever on a NULL timeout",
    "NtWaitForKeyedEvent": "parks until a matching release that never comes",
    "NtReleaseKeyedEvent": "parks until a matching wait that never comes",
    "NtRemoveIoCompletion": "an empty port + NULL timeout parks forever",
    "NtRemoveIoCompletionEx": "an empty port + NULL timeout parks forever",
    "NtLockFile": "a conflicting lock without FailImmediately parks forever",
}

# The LEDGER: services the sweep cannot reach today because an ORDINARY,
# well-formed argument already lands in an unbuilt case — a
# STATUS_NOT_IMPLEMENTED, which for a ring-3 caller is a panic (Art. 12), so
# the sweep would take the machine down before it ever got to a hostile
# pointer. Each entry is a REAL DEFECT this matrix found and did not fix, in
# the class issue #32 calls latent: a hole no consumer has walked into yet.
#
# It is a ledger and not an exclusion list, and the difference is the point.
# An exclusion says "not this one, ever"; a ledger entry says "this is owed",
# names what is unbuilt, and is printed by every run of the test so the debt
# cannot go quiet. Removing an entry is what "fixed" looks like — and if the
# fix is wrong, the sweep panics the moment the entry comes off.
#
# Nothing may be parked here to make a run green. The only admissible reason
# is the one above: a well-formed call reaches unbuilt code, and building it
# is a milestone's work rather than this instrument's.
# name -> (axis, reason). The axis is how much of the sweep the debt costs:
# "*" drops the service entirely; otherwise it names KIND LETTERS whose
# arguments keep their baseline instead of being tortured ("S" = the
# saturated-scalar axis, "O" = the OBJECT_ATTRIBUTES argument, ...), and a
# letter followed by "+" parks only that descriptor's INTERIORS while the
# hostile-ADDRESS sweep over it still runs.
#
# Always take the NARROWEST axis that clears the panic. Parking a service
# outright to dodge one saturated flag word throws away every pointer
# argument it has, and parking a descriptor outright to dodge its interiors
# stops the matrix checking that argument for the very defect it exists to
# find.
TORTURE_PARKED = {
    "NtLockFile": (
        "*",
        "a non-NULL IoStatusBlock, ApcRoutine or Key is unbuilt "
        "(kernel/io/lock.c), and every real caller passes an IOSB",
    ),
    "NtUnlockFile": (
        "*",
        "the keyed form (a non-NULL Key) is unbuilt (kernel/io/lock.c)",
    ),
    "NtCreateUserProcess": (
        "S",
        "a process-creation flag outside the three built ones is unbuilt "
        "(kernel/ps/process.c), so a saturated flag word refuses as unbuilt",
    ),
    "NtQueueApcThreadEx2": (
        "*",
        "a non-NULL ApcReserve handle is unbuilt (kernel/ps/thread.c), and "
        "the sweep has no NULL handle to offer - NULL names the caller itself "
        "for other services",
    ),
    "NtOpenProcess": (
        "O+",
        "a named open - any non-NULL ObjectName - is unbuilt "
        "(kernel/ps/process.c); only the attribute INTERIORS are parked, the "
        "block pointer itself is still swept",
    ),
}

# (service, argument index) -> (value, enumerator). CLASS_TYPES picks one
# value per class TYPE, and one type can serve two services that build
# different halves of it: THREADINFOCLASS's basic class is queryable but not
# settable, so NtSetInformationThread needs its own. Only a service the sweep
# convicted belongs here — the panic IS the evidence.
CLASS_OVERRIDE = {
    ("NtSetInformationThread", 1): (2, "ThreadPriority"),
    ("NtSetInformationObject", 1): (4, "ObjectHandleFlagInformation"),
    ("NtSetInformationJobObject", 1): (2, "JobObjectBasicLimitInformation"),
    ("NtSetInformationToken", 1): (6, "TokenDefaultDacl"),
}


def parse_wine_prototypes(root: Path):
    """{name: [type spelling, ...]} for every Nt* prototype in the pinned
    Wine's winternl.h — the same header abi/ is generated from."""
    src = (root / "third_party/wine/include/winternl.h").read_text()
    protos = {}
    for match in re.finditer(
        r"^NTSYSAPI\s+[A-Za-z_0-9 ]+?\s+WINAPI\s+(Nt\w+)\s*\(([^;]*)\);", src, re.M
    ):
        args = [a.strip() for a in match.group(2).split(",")]
        if len(args) == 1 and args[0].lower() in ("void", ""):
            args = []
        protos[match.group(1)] = args
    if len(protos) < 200:
        sys.exit(f"gen_syscalls: winternl.h prototype extraction looks wrong ({len(protos)})")
    return protos


def argument_kind(name: str, index: int, spelling: str) -> str:
    """One kind TOKEN for one prototype argument, by type spelling only: a
    kind letter, and for a class argument the baseline value after it."""
    # Wine spells a few arguments with a parameter NAME ("HANDLE ThreadHandle");
    # drop it, and the const/whitespace noise with it.
    text = re.sub(r"\s+", " ", spelling.replace("const", " ")).strip()
    text = re.sub(r"\s*\*", "*", text)
    if " " in text and not text.endswith("*"):
        text = text.split(" ")[0]
    base = text.rstrip("*")
    pointer = text.endswith("*")
    if base in STRING_TYPES:
        return "U" if pointer or base == "PUNICODE_STRING" else "S"
    if base in OBJATTR_TYPES:
        return "O" if pointer or base == "POBJECT_ATTRIBUTES" else "S"
    if base in CALLBACK_TYPES:
        return "F"
    if pointer or base in POINTER_TYPES or base in ("void", "VOID"):
        return "P"
    if base == "HANDLE":
        return "H"
    if base in CLASS_TYPES:
        value = CLASS_OVERRIDE.get((name, index), CLASS_TYPES[base])[0]
        return f"C{value}"
    if base in SCALAR_TYPES:
        return "S"
    sys.exit(
        f"gen_syscalls: {name} argument {index} has an unclassified type "
        f"'{spelling}'. Add the spelling to one of the *_TYPES sets in "
        f"tools/gen_syscalls.py (never guess from the prefix — see the "
        f"pointer-torture comment there)."
    )


def gen_torture_matrix(wine_syscalls) -> str:
    argc_by_name = {name: argc for _sid, name, argc in wine_syscalls}
    protos = parse_wine_prototypes(Path(__file__).resolve().parent.parent)
    rows, excluded, parked = [], [], []
    for name in IMPLEMENTED:
        if name not in protos:
            sys.exit(f"gen_syscalls: no winternl.h prototype for {name}")
        args = protos[name]
        # The two extractions are independent (the syscall id table's stack
        # byte count vs. the header's prototype), so their disagreement is a
        # pin bump that moved one and not the other — and the matrix would
        # then torture an argument the service does not have.
        if len(args) != argc_by_name[name]:
            sys.exit(
                f"gen_syscalls: {name} has {len(args)} prototype arguments but "
                f"{argc_by_name[name]} syscall-table slots"
            )
        if name in TORTURE_EXCLUDE:
            excluded.append((name, TORTURE_EXCLUDE[name]))
            continue
        if name in TORTURE_PARKED and TORTURE_PARKED[name][0] == "*":
            parked.append((name, TORTURE_PARKED[name][1]))
            continue
        kinds = " ".join(argument_kind(name, i, a) for i, a in enumerate(args))
        if name in TORTURE_PARKED:  # a narrower axis: keep the rest of the sweep
            axis, reason = TORTURE_PARKED[name]
            parked.append((name, reason))
            for letter in axis.replace("+", ""):
                kinds = kinds.replace(letter, letter.lower())
            if "+" in axis:  # interiors only: the address sweep survives
                kinds = kinds.replace(axis[axis.index("+") - 1].lower(),
                                      axis[axis.index("+") - 1].lower() + "+")
        live = "0" if name in TORTURE_NO_LIVE_HANDLE else "1"
        rows.append(f'KI_TORTURE({name}, {len(args)}, "{kinds}", {live})')
    stale = sorted(
        (set(TORTURE_EXCLUDE) | set(TORTURE_NO_LIVE_HANDLE) | set(TORTURE_PARKED))
        - set(IMPLEMENTED)
    )
    if stale:
        sys.exit(f"gen_syscalls: torture exclusions name unimplemented services: {stale}")
    noLive = [(n, r) for n, r in sorted(TORTURE_NO_LIVE_HANDLE.items())]
    return (
        BANNER.format(name="tests/ntapi/syscall/torture_matrix.inc")
        + "/* The argument SHAPE of every implemented service, for the\n"
        + " * pointer-torture sweep (issue #32 A1, ptr_torture.c). X-macros:\n"
        + " *\n"
        + " *   KI_TORTURE(name, argc, kinds, liveHandlePass)\n"
        + " *   KI_TORTURE_EXCLUDED(name, reason)      not called at all\n"
        + " *   KI_TORTURE_NO_LIVE(name, reason)       invalid-handle pass only\n"
        + " *   KI_TORTURE_PARKED(name, reason)        owed: an ordinary call\n"
        + " *                                          already reaches unbuilt code\n"
        + " *\n"
        + " * kinds is one space-separated token per argument, in order:\n"
        + " *   S scalar   H handle   P pointer   U PUNICODE_STRING\n"
        + " *   O POBJECT_ATTRIBUTES  F ring-3 callback\n"
        + " *   C<n> information class, held at <n> (never tortured; the\n"
        + " *        generator's CLASS_TYPES says why)\n"
        + " *   a LOWERCASE letter is that kind with its torture axis PARKED\n"
        + " *   (the argument still takes its baseline); a trailing + parks\n"
        + " *   only the descriptor INTERIORS, keeping the address sweep\n"
        + " *\n"
        + " * Extracted from the pinned Wine's winternl.h prototypes and\n"
        + " * cross-checked against the syscall table's own argument counts. */\n"
        + "\n".join(rows)
        + "\n\n/* Swept by nobody: calling these would end the sweep. */\n"
        + "\n".join(f'KI_TORTURE_EXCLUDED({name}, "{reason}")' for name, reason in excluded)
        + "\n\n/* Invalid-handle pass only (a live handle parks them). */\n"
        + "\n".join(f'KI_TORTURE_NO_LIVE({name}, "{reason}")' for name, reason in noLive)
        + "\n\n/* The ledger: found by this matrix, not yet built. */\n"
        + "\n".join(f'KI_TORTURE_PARKED({name}, "{reason}")' for name, reason in parked)
        + "\n"
    )

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
    # CUI-7: the NtRenameKey new-name shapes (deterministic per program:
    # plain components, a path, the empty name).
    "ren_name": (None, [
        ("FZ_REN_PLAIN", False),
        ("FZ_REN_OTHER", False),
        ("FZ_REN_PATH", False),
        ("FZ_REN_EMPTY", False),
    ]),
    # CUI-7: NtAllocateVirtualMemoryEx extended-parameter scenarios over
    # interp-owned allocations (allocate + free inside one call).
    "allocex_scenario": (None, [
        ("FZ_AX_CONSTRAINED", False),
        ("FZ_AX_DUP_TYPE", False),
        ("FZ_AX_BAD_ALIGN", False),
        ("FZ_AX_TYPE32", False),
        ("FZ_AX_ZERO_SIZE", False),
        ("FZ_AX_BASE_WITH_LIMITS", False),
    ]),
    # CUI-7: lock/unlock coverage states, each built and torn down inside
    # the call.
    "lock_scenario": (None, [
        ("FZ_LK_COMMITTED", False),
        ("FZ_LK_RESERVED", False),
        ("FZ_LK_UNMAPPED", False),
    ]),
    # CUI-7: flush shapes (whole anonymous region, a partial range, an
    # unmapped address).
    "flush_scenario": (None, [
        ("FZ_FL_ANON_WHOLE", False),
        ("FZ_FL_PARTIAL", False),
        ("FZ_FL_UNMAPPED", False),
    ]),
    # CUI-7: write-watch scan/reset states over a per-call watch region.
    "watch_scenario": (None, [
        ("FZ_WW_CLEAN", False),
        ("FZ_WW_DIRTY", False),
        ("FZ_WW_BAD_FLAGS", False),
        ("FZ_WW_NON_WATCH", False),
    ]),
    # CUI-7: the VmPrefetchInformation argument ladder.
    "prefetch_scenario": (None, [
        ("FZ_PF_VALID", False),
        ("FZ_PF_NULL_FLAGS", False),
        ("FZ_PF_BAD_SIZE", False),
        ("FZ_PF_ZERO_COUNT", False),
        ("FZ_PF_EMPTY_RANGE", False),
    ]),
    # CUI-9: which page of the mapped SEC_IMAGE view an op targets — the
    # header (read-only), the first read-only data segment, and two distinct
    # pages of the first writable (writecopy) segment, so the
    # not-yet-copied vs copied state distinction is drivable per page.
    "image_page": (None, [
        ("FZ_IMG_HEADER", False),
        ("FZ_IMG_RODATA", False),
        ("FZ_IMG_WRITECOPY", False),
        ("FZ_IMG_WRITECOPY2", False),
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
    # CUI-3 SCM surface. Cancel is deterministic on any slot — since CUI-8
    # the reason is the §7 pin rather than an accident of the machine: a
    # data transfer answers the PENDING SHAPE with the IOSB already final
    # (sem_file/async_inline.c), so nothing is ever cancellably pending at
    # ring 3 here — the thread-scoped verb succeeds and the Ex form answers
    # NOT_FOUND on any resolvable handle (wineserver's cancel_async takes
    # ANY object). The interp's own in-flight window has no oracle
    # counterpart; the kmt CUI-8 suite and the cui8 stress leg convict it.
    # Jobs stay anonymous and are only argument-gated (limits are validated
    # + stored, never enforced — docs/03 "CUI-3 SCM notes"), so every
    # scenario's status is deterministic on both sides. Assignment stays
    # out: assigning the interp to a job is irreversible state, and
    # re-assignment answers differ (nesting is unbuilt, docs/03).
    ("cancel_io", "NtCancelIoFile", ["slot_in"]),
    ("cancel_io_ex", "NtCancelIoFileEx", ["slot_in"]),
    # CUI-8 (docs/19 §8.3.3): the asynchronous-handle surface the §7 pins
    # fixed. create_file_async opens without FILE_SYNCHRONOUS_IO_*;
    # read_file_async issues with an event and collects AT THE CALL with a
    # zero-timeout wait — legal and deterministic on both runners precisely
    # because both complete data transfers inline under the pin (the call
    # answers STATUS_PENDING with the IOSB final and the event set), so a
    # kernel that regresses to genuine ring-3 pending diverges on the very
    # line that issued. cancel_sync_self pins the idle-thread NOT_FOUND
    # continuously.
    ("create_file_async", "NtCreateFile",
     ["slot_out", "ch_access_file", "fname", "ch_share_file", "ch_disposition_file"]),
    ("read_file_async", "NtReadFile", ["slot_in", "ch_iolen", "ch_iooff"]),
    ("cancel_sync_self", "NtCancelSynchronousIoFile", []),
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
    # CUI-9: the writecopy page-state machine (docs/17 §8 "the fuzzer" — a
    # mapped image view has a state the op model could not express:
    # not-yet-copied vs copied). One SEC_IMAGE view of the pinned
    # C:\windows\system32\ntdll.dll — identical bytes on both sides, so
    # segment geometry and every status/protection answer are contract;
    # the base is ASLR and never traced. write_image drives the copy
    # through NtWriteVirtualMemory (the hazard-A kernel-write shape);
    # query_image_protect observes Protect/RegionSize, pinned to the
    # oracle's no-transition shape (docs/03 "CUI-9 COW notes"); the
    # interp's per-program scrub unmaps so state never leaks.
    ("map_image_view", "NtMapViewOfSection", []),
    ("write_image", "NtWriteVirtualMemory", ["ch_image_page"]),
    ("query_image_protect", "NtQueryVirtualMemory", ["ch_image_page"]),
    ("unmap_image_view", "NtUnmapViewOfSection", []),
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
    # CUI-7 Cm-2/Mm-2 ops. Only the DETERMINISTIC, side-effect-bounded
    # slice: renaming interp-owned fz_reg keys (collisions, paths and the
    # empty name are all deterministic statuses; renamed keys stay under
    # the scrubbed prefix), and memory scenarios that allocate, exercise
    # and free inside one call. Hive save/load/unload (file I/O + the
    # privilege global), notify (event-slot interplay), restore/replace,
    # and the locale/time/shutdown setters (irreversible or global state)
    # stay out — the cancel_io/suspend precedent.
    ("rename_key", "NtRenameKey", ["slot_in", "ch_ren_name"]),
    ("alloc_ex", "NtAllocateVirtualMemoryEx", ["ch_allocex_scenario"]),
    ("lock_virtual", "NtLockVirtualMemory", ["ch_lock_scenario"]),
    ("unlock_virtual", "NtUnlockVirtualMemory", ["ch_lock_scenario"]),
    ("flush_virtual", "NtFlushVirtualMemory", ["ch_flush_scenario"]),
    ("get_write_watch", "NtGetWriteWatch", ["ch_watch_scenario"]),
    ("reset_write_watch", "NtResetWriteWatch", ["ch_watch_scenario"]),
    ("prefetch_vm", "NtSetInformationVirtualMemory", ["ch_prefetch_scenario"]),
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
    parser = argparse.ArgumentParser(description=__doc__)
    # Same contract as gen_abi.py's --check, for the same reason: every file
    # below is checked in, so nothing in a build notices one of them being
    # hand-edited or left behind by a Wine pin bump. --check writes nothing
    # and names every file that differs.
    parser.add_argument("--check", action="store_true", help="fail if the output is stale")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    wine_syscalls = parse_wine_syscalls(root)
    stale = []
    for path, text in [
        (root / "abi/syscall_numbers.h", gen_numbers(wine_syscalls)),
        (root / "kernel/syscall/table.inc", gen_table_inc(wine_syscalls)),
        (root / "tests/ntapi/syscall/syscall_stubs.S", gen_stubs(wine_syscalls)),
        (root / "tests/ntapi/syscall/torture_matrix.inc", gen_torture_matrix(wine_syscalls)),
        (root / "tests/fuzz/gen/fuzz_model.h", gen_fuzz_model_h()),
        (root / "tests/fuzz/gen/fuzz_model.py", gen_fuzz_model_py()),
    ]:
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"gen_syscalls: wrote {path.relative_to(root)}")

    if args.check:
        if stale:
            sys.exit(
                "gen_syscalls: stale (run: python3 tools/gen_syscalls.py)\n"
                + "\n".join(f"  {p.relative_to(root)}" for p in stale)
            )
        print("gen_syscalls: the syscall number space is up to date with the pin")


if __name__ == "__main__":
    main()
