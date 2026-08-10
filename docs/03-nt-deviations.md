# 03 — Deviations from Real NT

This document is the reference for **what we keep, what we drop, and what we fake**,
relative to a real Windows NT kernel. The organizing principle:

> **Keep the explicit entities user mode can see. Drop the explicit entities only drivers
> can see. Fake the rest with the correct shape.**

NT's defining habit is to turn Unix's *implicit conventions* into *explicit entities*.
That is a genuine design virtue — but an explicit entity leaks across the ABI and becomes
a contract that can no longer be redesigned. Our deviations are chosen so that the
contracts we inherit are exactly the ones observable (and testable) from an `.exe`.

## Kept exactly (the boundary)

| Entity | Why it cannot change |
|---|---|
| `Nt*` syscall semantics (the Wine-used subset) | Wine's PE DLLs depend on exact behaviour |
| `PEB`, `TEB`, `RTL_USER_PROCESS_PARAMETERS` | read field-by-field by Wine DLLs; byte-exact |
| `KUSER_SHARED_DATA` @ 0x7FFE0000 | read directly for time/version |
| Handles + inheritance + duplication | the universal reference mechanism |
| Dispatcher objects + `NtWaitForMultipleObjects` (wait-all/any, alertable) | NT's best invention; Wine relies on it |
| APC delivery (kernel + user), alertable-wait semantics | I/O completion depends on it |
| Section objects (anonymous / file / image, guard pages) | process startup *is* image sections |
| NT file semantics (share modes, case rules, delete-on-close, byte-range locks, info classes) | the part Wine can't fully reproduce on Unix; our reason to exist |
| Async I/O completion protocol (IOSB timing, APC/event/port) | observable and depended-upon |
| User-mode return protocol (`KiUserExceptionDispatcher`, `KiUserApcDispatcher`) | SEH breaks without it |
| Object namespace (`\Device`, `\??`, symlinks) | `NtCreateFile("\Device\...")` must resolve |

## Dropped entirely (driver-only, unobservable)

| Dropped | What it was | Replaced by |
|---|---|---|
| **IRQL** | a number unifying interrupt-mask + preempt-disable + "no sleep in interrupt context", exported as a contract to drivers | ordinary interrupt disable + one lock; no external contract |
| **DPC** | deferred bottom-half, contractual for drivers | internal top/bottom-half, our choice |
| **IRP + IO_STACK_LOCATION** | I/O request as a heap object passed down a driver stack | a VFS-style completion record; no stack, no layering |
| **MDL** | physical-page list for a virtual buffer | direct handling in our async path |
| **WDM / PnP / power** | the driver authoring model + device enumeration state machines | drivers are statically linked in-tree modules |
| **HAL as a swappable module** | platform-difference abstraction | absorbed into `arch/x86_64/`; single platform |
| **Paged vs. NonPaged pool split** | two heaps because paged memory can fault | one pool (nothing is paged out) |
| **Cc as a separate component** | file cache, re-entrant with Mm and FS (the "triangle") | unified page cache inside Mm |
| **Pageout / working set / balance-set** | eviction machinery | nothing is evicted; commit-failure → out-of-memory |
| **ALPC** | kernel-mediated fast IPC | not needed for CUI; GUI uses shared-section transport |
| **SSDT as a patchable table** | the syscall table (historically hooked by AV/rootkits) | a plain function table; nothing to hook |

**Why dropping IRQL matters most:** IRQL is the load-bearing reason HAL exists, and the
reason ReactOS still cannot ship SMP after 30 years — its scheduler internals could not be
redesigned because IRQL/spinlock semantics were promised to third-party drivers. With no
third-party drivers, we owe that contract to no one, and SMP becomes ordinary future work.

## Faked (correct shape, hollow inside)

| Faked | Shape preserved | Inside |
|---|---|---|
| **Se (security)** | CUI-2: a real Ob token object with the full query/adjust/duplicate/access-check surface (`kernel/se/`, pinned by `tests/ntapi/sem_se/` — see "CUI-2 Se notes"). **CUI-6 retired always-allow**: an object carrying a security descriptor now gets the real DACL check at open (`SeCheckObjectAccess`, wineserver `check_object_access`) | ONE fixed admin identity (wineserver's `token_create_admin`, byte-identical); a create-time `OBJECT_ATTRIBUTES.SecurityDescriptor` is captured and enforced, but an object with **no** SD stays permissive (as wineserver's null-SD path does) |
| **Cm hive format** | `NtCreateKey`/value semantics | our own on-disk format; no MS hive binary compat |
| **EPROCESS/ETHREAD** | exist as internal structs | layout entirely ours; nobody reads it (no drivers) |
| **DPC/IRQL surface** | absent, not stubbed | callers don't exist (no drivers) |
| **Generic access mapping** (M3 → CUI-6) | `GENERIC_*`/`MAXIMUM_ALLOWED` accepted everywhere a `DesiredAccess` goes | **CUI-6** gave the named object types their real per-type `GENERIC_MAPPING` (wineserver's, cited per type in `kernel/ob/sync.c`/`namespace.c`); the types without an explicit one (process/thread/job/section/completion/device) still over-grant a generic wish to `validAccess` (no baked caller opens them by generic bit — Art. 1). Handle-granted access is still enforced per use (`EVENT_MODIFY_STATE` etc., pinned by `tests/ntapi/sem_ob/`) |
| **`SystemProcessorIdleCycleTimeInformation`** (W2b) | one `ULONG64` per processor, monotonic, non-decreasing | the value is the kernel's **idle TIME** (`KiIdleTime100ns`, the same counter `SystemPerformanceInformation` reports) rather than an idle CYCLE count. proskrnl keeps no per-CPU cycle counter, and synthesizing one from an assumed frequency would be a fabricated number where a real measure exists. Callers use this class to watch idle *grow*, which this satisfies |
| **Name case folding** (M3 → the winetest frontier) | **no longer faked: the fold is the ORACLE'S OWN TABLE.** `RtlUpcaseUnicodeChar` reads the NLS upcase trie generated from the pinned tree's `nls/l_intl.nls` (`kernel/lib/upcase.h`, `tools/gen_upcase.py`), which is the same data both halves of the oracle fold through — Wine's PE ntdll maps it in `dlls/ntdll/unix/env.c` `init_environment`, wineserver reads the lowercase half for `memicmp_strW` in `server/unicode.c`. Total over the BMP, per 16-bit code unit. Pinned by `tests/ntapi/sem_reg/key_name_fold.c` and `sem_file/name_case_fold.c` | what is left is narrow and named: **upcase only** (no `RtlDowncaseUnicodeChar`, no consumer) and **no OEM code page**, which is why `RtlIsNameLegalDOS8Dot3` still refuses every non-ASCII name. **The history is the lesson and is kept deliberately.** This row twice recorded a hand-written RULE as "unobservable", and user mode reached past it twice: ASCII was widened to Latin-1 when `ntdll:directory` required U+00E9 and U+00C9 to sort as one letter (`directory.c:324`), and Latin-1 was widened to the table when `ntdll:reg` created a key named U+00F6 U+00F3 U+014D U+0371 U+D801 U+DC00 and re-opened it upper-cased (`reg.c:346-:355`). A rule is a claim about what user mode will never write; the table makes no claim. Note also what the table is NOT: Unicode's simple uppercase mapping (U+03C2 folds to itself where U+03C3 folds to U+03A3; U+0131 folds to itself), and it is not per code POINT — `reg.c:350` requires the surrogate halves U+DC00 and U+DC28 to stay different names |
| **Adversarial namespace error classification** (M3) | the ordinary namespace contract (`tests/ntapi/sem_ob/namespace{,_errors}`): missing leaf / missing intermediate / collision / type mismatch / empty-and-root names / symbolic-link resolution and loops all match Wine exactly | the *exact* `NTSTATUS` among the several "namespace is malformed or conflicting" codes for deliberately pathological inputs — a graph of symbolic links pointing at each other or at wrong-typed objects, the *same* name created under several incompatible object types — can still differ from Wine. Wine's PE stack only ever uses well-formed, type-stable namespace paths (`\BaseNamedObjects\Name`, `\??\C:`), so these sequences (the differential fuzzer's `--names named`/`malformed` modes construct them; they do not minimize below ~13 calls) are unobservable in practice. Fixing them byte-exact is deferred object-manager work, not a boundary Wine depends on |

## M6 file-surface notes (Io + FAT32)

The file boundary is pinned test-first against the pinned Wine (Art. 5/6:
`tests/ntapi/sem_file/`). Three kinds of notes fall out:

**Wine-pinned choices that differ from real NT** (Wine is the operative oracle — these are
correct by definition here, listed so nobody "fixes" them against Windows folklore):

| Behaviour | Pinned Wine value (proskrnl matches) |
|---|---|
| Unsupported `FILE_INFORMATION_CLASS` in `NtQuery/SetInformationFile` | `STATUS_NOT_IMPLEMENTED` (real NT: `STATUS_INVALID_INFO_CLASS`) |
| `NtLockFile` with non-NULL `ApcRoutine`/`IoStatusBlock`/`Key`; `NtUnlockFile` with non-NULL `Key` | `STATUS_NOT_IMPLEMENTED` — only the bare form is implemented; Wine's own PE stack never passes them |
| Byte-range lock conflict under FailImmediately | `STATUS_FILE_LOCK_CONFLICT` |
| `FileEndOfFileInformation` through a handle without `FILE_WRITE_DATA` | shrink → `STATUS_INVALID_PARAMETER`, grow → `STATUS_INVALID_HANDLE` (fuzzer-found; artifacts of Wine's unix backend, pinned by `sem_file/info_classes`) |
| `NtQueryDirectoryFile` mask binding | the mask binds to the handle; a NULL mask on a later call reuses the stored one; a first-scan empty result is `STATUS_NO_SUCH_FILE`, later ones `STATUS_NO_MORE_FILES` |
| `FILE_BOTH_DIR_INFORMATION.ShortName` | left empty (Wine's unix backend reports none; not pinned by tests either way) |

**NT behaviours the pinned Wine cannot express** (its unix backend under-implements them;
proskrnl implements the NT form — unobservable by Wine's PE stack, which never relies on
them, and excluded from the differential fuzzer's op model):

- `FILE_STANDARD_INFORMATION.DeletePending` reports TRUE once a delete disposition is set
  (Wine reports FALSE).
- A new open while a delete disposition is pending fails with `STATUS_DELETE_PENDING`
  (Wine lets it succeed and defers the unlink).

**Internal simplifications** (unobservable, Art. 3):

- **RTC (retired in CUI-1):** file timestamps derive from the system clock, which is
  seeded once at boot from the CMOS RTC (`arch/x86_64/rtc.c`; QEMU supplies host UTC) —
  real wall time. Before CUI-1 they were a fixed base date plus uptime. If the CMOS
  content is implausible the fixed-date fallback still applies, so tests may rely on
  presence/ordering/monotonicity unconditionally and on wall-truth only where the RTC
  boot line (`[KTEST] rtc PASS`) is part of the run's contract.
- **Windows' `DIR_NTRes` lower-case hints are not used:** any name that is not already an
  exact upper-case 8.3 name gets an LFN run (spec-conformant; preserves case exactly).
- **FSInfo free-count is not maintained** (the FAT spec marks it advisory and requires
  validation anyway).
- **Mapped-view dirty pages** are written back on `NtFlushBuffersFile`, on
  `NtFlushVirtualMemory` over the view's covered file range (CUI-7), and at file close —
  not per-store (unobservable without a reboot mid-test; `NtWriteFile` itself writes
  through immediately).

### Byte-range locks are tracked but not enforced against I/O

`NtLockFile`/`NtUnlockFile` maintain the lock list and arbitrate lock-vs-lock
conflicts, but `NtReadFile`/`NtWriteFile` never consult it, and the
lock-bypass `key` argument is accepted and ignored. NT enforces byte-range
locks against I/O; the pinned oracle does not, because wineserver's locks are
Unix advisory locks that do not block the process holding them. Art. 6 makes
the oracle the spec here, so the agreement is deliberate and
`sem_file/byte_locks` pins it on both legs — including the two cases that
would change if the oracle ever started enforcing (a foreign handle reading
and writing across an exclusive lock, both of which succeed). Building
enforcement means changing that test first.

### A create-time security descriptor on a file or directory is ignored — the volume says so

`OBJECT_ATTRIBUTES.SecurityDescriptor` is captured and enforced for **Ob**
objects ("CUI-2 Se notes"), but the file path drops it: `IopCreateFile`
(`kernel/io/file.c`) never reads it, and the FAT32 backend neither stores one
nor checks one at open. That is NT's own answer on a FAT volume rather than a
gap — a security descriptor is an NTFS construct, FASTFAT has nowhere on disk
to put one, and MS documents the boundary at both ends: `CreateDirectory`'s
`lpSecurityAttributes` ACLs apply on NTFS, and `GetVolumeInformation`'s
`FILE_PERSISTENT_ACLS` is defined as "the volume preserves and enforces ACLs
— NTFS does, FAT does not".

It is not a silent fabrication either (G12), because the volume ANSWERS the
question: `fs/fat32/fat.c`'s `FileFsAttributeInformation` reports
`FILE_CASE_PRESERVED_NAMES` alone and **not** `FILE_PERSISTENT_ACLS`. A
caller that asks gets told, and the create then behaves the way the answer
promises.

The observable consequence, measured: `kernel32:profile`'s
`test_profile_directory_readonly` (profile.c:536) creates a directory whose
DACL grants Everyone read+execute only and requires the three
`WritePrivateProfileString*` calls into it to FAIL (profile.c:559/:562/:565).
On proskrnl they succeed, and `RemoveDirectoryA` then fails 145
(`ERROR_DIR_NOT_EMPTY`, :568) on the file they left. The ORACLE passes only
because Wine maps the DACL onto unix permission bits — which is why the same
FOUR failures disappeared when the oracle stopped running as root ("M10
winetest notes", the eight host-parked pairs: `kernel32:profile` "from 4 to
0"). That earlier run recorded the count and not the line numbers, so the
identity of the two sets is an inference from count plus mechanism rather
than a second measurement; it is the whole of this subtest's failing
assertions either way. This cluster is about a volume that enforces ACLs, and
re-opens only if the backend changes.

## M7 process/return-protocol notes (Ps + the user boundary)

The M7 boundary is the byte-exact PEB/TEB/`RTL_USER_PROCESS_PARAMETERS`/KUSER_SHARED_DATA
and the ring-3 return protocol (`KiUser{Exception,Apc}Dispatcher` + `NtContinue`), pinned
against the pinned Wine tree. Notes that fall out:

**Boundary choices matched to the pinned Wine tree (correct by definition here):**

- Syscall numbers ARE the pinned Wine tree's own 64-bit ids
  (`third_party/wine/dlls/ntdll/ntsyscalls.h`, `ALL_SYSCALLS` under `_WIN64`), not any
  Windows build's — Wine renumbers its SSDT freely and its PE thunks hardcode the id, so
  matching Wine's table is what lets the unmodified PE ntdll run. Regenerated on a pin bump.
- KUSER_SHARED_DATA is mapped read-only at NT's fixed `0x7ffe0000` with `SystemCall == 0`,
  so Wine's x86_64 thunks (`include/wine/asm.h`) always take the raw `syscall` path; the
  `0x7ffe1000` dispatcher-pointer detour (a host-Wine-on-Linux need) is never mapped.
- The exception frame layout (`CONTEXT` at the base, `EXCEPTION_RECORD` at `+0x4f0`) matches
  Wine's `exc_stack_layout` (`dlls/ntdll/unix/signal_x86_64.c`).

**Internal simplifications under no-preemption (Art. 3 — unobservable by the M7 clients):**

- `NtGetContextThread`/`NtSetContextThread` and `NtRaiseException`/`NtContinue` operate on
  the *calling* thread only. Capturing or setting a *running foreign* thread's context would
  require stopping it mid-instruction, which the single-CPU no-preemption model cannot do.
  (Foreign-thread `NtTerminateThread`/`NtTerminateProcess` are **served since CUI-4** — see
  the process-ecosystem note below — because a *terminate* only needs the target to reach a
  ring-3 edge, not to be frozen at an arbitrary instruction.)
- The `PEB->Ldr`, `ProcessHeap`, `FastPebLock`, and TLS bitmaps are left null by the kernel:
  ntdll's `loader_init` builds them itself (the NT contract — the kernel must *not*
  pre-populate them). Only the fields ntdll reads before that point (`ImageBaseAddress`,
  `ProcessParameters`, the version fields, the `NT_TIB`) are seeded.
- The registry slice (`NtOpenKey`, `NtQueryValueKey`) returns graceful failures until Cm
  (M8) exists; ntdll's `load_global_options`/`version_init` tolerate that (degraded,
  non-crashing) by design.

### M7 Wine bring-up notes (the unmodified PE ntdll running hello.exe)

What the kernel had to provide — beyond the return protocol above — for Wine's own
`ntdll.dll` (+ the `kernel32`/`kernelbase` its `loader_init` hard-loads) to run a process
end to end. Each is behaviour the PE side *observably depends on*, cross-checked against
the pinned tree:

- **The initial-thread protocol is the NT CONTEXT shape**: the kernel builds a `CONTEXT`
  (Rip = `RtlUserThreadStart`, Rcx = entry, Rdx = PEB, Rsp = `StackBase - 0x28`) on the
  user stack and enters `LdrInitializeThunk` with `rcx = &CONTEXT`, `rsp = &CONTEXT - 8` —
  the exact frame Wine's unix `init_syscall_frame` hands over. Both dispatcher frames now
  carry the machine frame their `.seh_pushframe` unwind info reads (`exc_stack_layout`
  at `+0x590`, `apc_stack_layout` at `+0x530`), and APC delivery uses the full
  `apc_stack_layout` (routine + args in `P1Home..P4Home`, `KCONTINUE_ARGUMENT` at
  `+0x4f0`).
- **TEB and PEB live in 4-page blocks** (`dlls/ntdll/unix/virtual.c virtual_alloc_teb` /
  `virtual_alloc_first_teb`): the PE side keeps per-thread state *behind* the TEB proper
  (`debug_info` at `teb+0x2000+sizeof(TEB32)`) and reads relative to the PEB. The TEB also
  seeds `ActivationContextStackPointer`, the `StaticUnicodeString` buffer, the x64
  no-exception-list marker, and `Tib.FiberData`'s `0x1e00`, as Wine's `init_teb` does —
  `actctx.c` dereferences the first two without checking, and `kernel32:fiber` asserts
  the last on a thread that is not a fiber (`fiber.c:203`). `DeallocationStack` is
  seeded too, from the stack's reservation base rather than from `init_teb`: it is the
  stack's third, fixed corner, and `StackBase - DeallocationStack` is the only way user
  mode can state the RESERVE (`GetCurrentThreadStackLimits`, `SetThreadStackGuarantee`,
  `badptr_handler`'s guard re-arm and `SwitchToFiber` all read it). Pinned by
  `sem_ps/teb_stack.c` and `sem_ps/teb_fiber_data.c`.
- **Every stack's commit is at least 64 KiB** regardless of the PE header's
  `SizeOfStackCommit` or the caller's `stackSize`: `signal_start_thread` zeroes `0xf000`
  bytes below the initial CONTEXT before `NtContinue`, deeper than a minimal 1-page
  commit, and this kernel grows a stack one page at a time off a single guard page — a
  frame larger than the gap steps clean over the guard (the 4 KiB commit ntdll's
  threadpool asks for, convicted by `sem_port/ports`). The RESERVE deviates from nothing:
  an unnamed reserve is the image's `SizeOfStackReserve`, floored at NT's 1 MiB, for the
  main thread and for every `NtCreateThreadEx` thread alike — one rule, one function
  (`PspResolveStackGeometry`, `kernel/ps/process.c`), transcribed from
  `virtual_alloc_thread_stack` and pinned by `sem_ps/thread_stack_default.c`. The commit
  is not part of any pinned contract (the winetest's commit assertions are `todo_wine` on
  both runners); the reserve is, through the TEB's `DeallocationStack`.
- **NLS data is real**: `NtInitializeNlsFiles` maps `locale.nls` and reports the fixed
  en-US system LCID `0x409` (the fallback Wine's `init_locale` reports with no configuring
  host locale); its size argument is left **untouched** (Wine never writes it — pinned by
  `sem_ps/nls_files`). `NtGetNlsSectionPtr` maps `l_intl.nls` / `c_%03u.nls` /
  `sortdefault.nls` / `norm*.nls` from `C:\windows\system32` (`kernelbase` parses the
  sortkey table unconditionally at attach). All of it is baked onto the boot volume from
  the pinned tree's `nls/` by the build (Makefile `WINFILES`).
- **User threads carry their x87/SSE state**: Wine's PE dlls are compiled with SSE, so
  CR4.OSFXSR is on and `KiSwapContext` FXSAVEs/FXRSTORs per thread; exception/APC CONTEXTs
  capture the live `FltSave` and `NtContinue`/`NtSetContextThread` restore it.

### M7 fuzzer notes (pre-existing wrinkles the widened op mix surfaced)

- **Set-EOF rides any write-ish access bit**, and overwrite dispositions carry an implicit
  one: Wine's server grants `FILE_OVERWRITE`/`FILE_OVERWRITE_IF` handles
  `FILE_WRITE_ATTRIBUTES` (`server/file.c create_file`) and gates `set_fd_eof` only on the
  unix fd being writable (`FILE_UNIX_WRITE_ACCESS`). Pinned in `sem_file/info_classes`;
  the kernel mirrors both.
- **A delete-on-close unlink waits for the truly-last open**, data access or not: Wine
  unlinks when the inode's fd list empties, so an attributes-only open (which imposes no
  share constraints) still defers the unlink, and the intent survives the deleting
  handle's own close. The FAT FCB now latches `unlinkPending` and applies it at the last
  open's cleanup.
- **`NtDuplicateObject` grants specific access bits verbatim** — generic bits are mapped,
  but nothing is filtered by the type's valid mask (`server/handle.c duplicate_handle`);
  pinned in `sem_ob/handle_life`.
- **Waits on non-dispatcher objects** stay NT-shaped, diverging from wineserver: wineserver
  parks *any* object on a wait queue (a directory just never signals), so a multi-wait
  scans past it to report a later bad handle; proskrnl keeps `STATUS_OBJECT_TYPE_MISMATCH`
  for the non-waitable object itself. Baselined in `tests/fuzz/known_divergences.txt`,
  kept visible by a `todo_proskrnl` in `sem_ob/handle_life`.

## M8 Cm notes (the registry + the initial process chain)

The `Nt*Key*` boundary is pinned test-first against the pinned Wine (`tests/ntapi/sem_reg/`,
green on both sides), and the load-bearing semantics — always-open-if create with the
disposition, only-last-component creation, always-case-insensitive lookup, sorted
subkey/value enumeration order, `STATUS_ACCESS_DENIED` for delete-with-subkeys,
success-no-op re-delete, the `STATUS_KEY_DELETED` stale-handle limbo, the per-info-class
`TOO_SMALL`/`OVERFLOW` buffer protocol with truncated-header writes, the 256-char component
and 16383-char value-name limits — are each cross-checked against
`wine dlls/ntdll/unix/registry.c` + `server/registry.c` (cited at the implementation,
`kernel/cm/registry.c`).

**Inside (all free under the semantic shadow):**

- **The hive is our own format, "proskrnl hive v1"** (`kernel/cm/hive.c` is its normative
  spec): one file, `\??\C:\windows\system32\config\SYSTEM` (NT's path shape), holding a
  length-prefixed preorder dump of the whole tree — no cells, no bins, no free lists, no
  incremental updates. Every successful mutating syscall rewrites the entire file through
  the ordinary `NtCreateFile`/`NtWriteFile` path onto write-through FAT32, so mutations
  are durable at syscall return and **`NtFlushKey` is a success no-op** (strictly stronger
  than NT's lazy flusher; unobservable from a running program).
- **No recovery logging** (NT's `.LOG1`/`.LOG2` dirty-page journals are shed, docs/05): the
  file's magic is written only after the body, so a torn rewrite parses as *no* hive and
  the next boot starts with an empty registry — deterministic loss, never a garbage parse.
  A kernel crash between a mutation and its rewrite completing can lose that mutation.
- **One hive** backs the whole tree (NT splits SYSTEM/SOFTWARE/SAM/... and mounts user
  hives): `\Registry\Machine` and `\Registry\User` are plain keys persisted in the same
  file. Unobservable until something enumerates hive *mount points* as such.
- **The hive file is not locked**: the kernel opens it transiently per rewrite, so a user
  program can open (even corrupt) it, where NT holds its hives open exclusively. A
  corrupted file is rejected structurally at the next boot (bounds-checked parse, empty
  registry on failure).
- **Key classes and change notification are unbuilt**: the class argument is accepted
  and dropped, the notify APIs are refused loudly (`STATUS_NOT_IMPLEMENTED`), matching
  what the CUI Wine stack never uses. `LastWriteTime` ticks on the boot-relative
  interrupt clock, not wall time.
- **Registry symlinks (`REG_OPTION_CREATE_LINK`) are built** (GUI-2: win32u's
  display-device commit creates them), pinned by `sem_reg/symlink`. Two deviations from
  the oracle, both outside what any pinned caller does: a resolution follows at most 32
  links (NT's reparse limit; wineserver would recurse forever on a cycle), and a
  destination outside `\Registry` refuses as `STATUS_OBJECT_NAME_NOT_FOUND` where the
  oracle would resolve the foreign object and fail its type check.
- **`\Registry\Machine`/`\Registry\User` are undeletable** (parent-of-root protection);
  wine would allow an empty hive root's deletion but never exercises it.
- **Key-tree depth is capped at 96 levels**, where NT documents 512 ("Registry element
  size limits"). `NtCreateKey` past the cap refuses with `STATUS_INVALID_PARAMETER`;
  `CMP_HIVE_MAX_DEPTH` (`kernel/cm/cm.h`) is the single number the create path, the hive
  serializer and the hive parser all use. The reason is the serializer: `CmpMeasureKey`,
  `CmpEmitKey` and `CmpFreeSubtree` recurse once per level on a 16 KiB pool-allocated
  kernel stack with no guard page, and 512 levels does not fit. Before this cap the three
  numbers disagreed — create was unlimited, the parser stopped at 96, and a parse failure
  discards the whole hive — so a 100-deep path saved successfully, reported durability,
  and threw the ENTIRE registry away at the next boot. One number makes anything that
  saves also load. Pinned by `sem_reg/deep_keys`, whose "all 200 levels creatable"
  assertion is `todo_proskrnl`: the oracle manages it and proskrnl refuses. Lifting the
  cap to NT's 512 means making the three walks iterative, not raising the constant.

**The initial process chain** (`kernel → smss.exe → hello.exe`): `NtCreateUserProcess`
implements the common single-image spawn — `PS_ATTRIBUTE_IMAGE_NAME` (+ optional
`PS_ATTRIBUTE_CLIENT_ID` write-back), real process/thread handles, `PsCreateSuccess` info.
Caller-supplied `RTL_USER_PROCESS_PARAMETERS` are **not yet threaded through** (the PEB's
parameters are kernel-built from the image path — M10's `CreateProcess` work), and
suspended creation + the pre-success `PS_CREATE_INFO` states are refused loudly. The DOS
device letters (`\??\C:`) remain kernel-created at volume mount, where NT's smss creates
them from `Session Manager\DOS Devices`; our smss-equivalent instead proves the registry
from ring 3 and drives the spawn + wait + exit-code propagation
(`ProcessBasicInformation.ExitStatus` reports the real code once the process object
signals). Persistence acceptance is the boot-twice harness `tests/run/run.sh persist`
(seed on boot 1, byte-verify + volatile-key-absence on boot 2).

### "Always case-insensitive" needed the OTHER half of the name too

The row above has said "always-case-insensitive lookup" since M8, and it was half
true. A registry path is resolved by **two** engines: `\Registry` is an
object-manager name that `ObpLookupName` resolves, honouring
`OBJ_CASE_INSENSITIVE` like any other Ob name, and everything after it is a Cm
subkey that `CmpFindSubkey` compares case-insensitively *unconditionally*. So a
caller passing `Attributes = 0` was asking for a case-sensitive match on exactly
the one component of the path that Cm never compares — and got it:
`\REGISTRY\Machine\...` answered `STATUS_OBJECT_PATH_NOT_FOUND` while
`\Registry\Machine\...` succeeded.

The oracle folds it, and **where** it folds is the whole point:
`dlls/ntdll/unix/registry.c` ORs `OBJ_CASE_INSENSITIVE` into the attributes of
`NtCreateKey`, `NtOpenKeyEx` and `NtLoadKeyEx` before the request leaves user
mode. That file is ntdll's **unix** half — precisely the half proskrnl replaces
at the unixlib seam (Art. 10 / G9). The comment in `kernel/cm/registry.c` had
even cited it correctly ("ntdll forces OBJ_CASE_INSENSITIVE") as the reason the
kernel needed no code for it; the citation was accurate and the conclusion was
wrong, because on proskrnl that code does not run.

`CmpResolvePath` forces the bit now, through a new `extraAttributes` argument on
`ObpLookupParseObject` rather than a second walk (Art. 11) — the caller's
`OBJECT_ATTRIBUTES` is user memory that cannot be edited in place, and a
kernel-stack copy would fail the probe. **Not a deviation**: it is the oracle's
answer, and it is also Windows 10 1607+'s (`ntdll:reg` `reg.c:541-:558` accepts
either answer for the mixed-case spelling and requires success for
`\REGISTRY\MACHINE\SOFTWARE\CLASSES` on every version). Pinned by
`tests/ntapi/sem_reg/root_case.c`.

**The generalisable rule, and it is worth a sweep:** *replacing a layer means
inheriting what that layer did.* Every behaviour the pinned Wine implements in
`dlls/ntdll/unix/` is a behaviour proskrnl owes, and a code comment citing that
directory as the reason something needs no kernel implementation is
self-refuting. This is the second time the same shape has bitten: `docs/21` W1's
`STATUS_NOT_IMPLEMENTED` split is the same seam read the other way round.

### A key handle has a name, and a deleted key has none

`NtQueryObject(ObjectNameInformation)` answered **success with an empty
`UNICODE_STRING`** for every key handle, because a key is a `CMP_KEY_NODE` in
Cm's tree and Ob's generic name walk only ever sees the one namespace object
(`\Registry`). A named object reported as nameless is the fabricated-plausible
answer Art. 12 forbids — no caller can tell two keys apart through it — and the
only assertion in the suite that could see it was the *deleted* case, which
wanted `STATUS_KEY_DELETED` and got success.

`OBJECT_TYPE` grew an optional `queryName` hook (`kernel/ob/ob.h`), which is the
oracle's own shape: `key_ops.get_full_name = key_get_full_name`, whose entire
body is a `KEY_DELETED` guard in front of the generic walk
(`server/registry.c`). `CmpQueryKeyObjectName` answers from `CmpBuildFullPath`
— the same walk `KeyNameInformation` uses, so the two spellings of "what is this
key called" cannot drift — and refuses a deleted node **before** the
buffer-size protocol, since a key that is nowhere has no path however big the
buffer is. `ObjectBasicInformation` and `ObjectTypeInformation` keep answering:
they need the handle and the type, neither of which the delete destroyed.
Pinned by `tests/ntapi/sem_reg/key_object_name.c`.

### A registry link loop is an invalid REQUEST, not a missing name

`CmpFollowLink`'s expansion cap was right and the status it refused with was
not. `STATUS_OBJECT_NAME_NOT_FOUND` says the name is absent; a loop's names are
all present, and it is the *request* that cannot be served. The oracle answers
`STATUS_INVALID_PARAMETER`, from the bound on the same quantity with the same
value: the registry's symlink arm resolves each destination by re-entering the
generic name walk, and that walk gives up at `if (recursion_count > 32)`
(`server/object.c` `lookup_named_object`; `server/registry.c`
`key_lookup_name`). `ntdll:reg` measures it at `reg.c:1312`.

Pinned in `sem_reg/symlink.c` over **both** loop shapes, which is the part worth
carrying: a link whose target runs through itself makes the path grow one
component per follow, so a bound on path LENGTH would also stop it; a
two-link cycle alternates between two names of constant length and only a bound
on the number of FOLLOWS stops that one. Testing the first alone would pass an
implementation that hangs on the second.

## M9 npfs/condrv notes (pipes + the console)

What the M9 bring-up pinned, deviated on, or left unbuilt:

- **Pipe DATA transfers are synchronous-only** (Art. 3): every
  `NtReadFile`/`NtWriteFile` on a pipe completes (or blocks the caller)
  before the syscall returns — `STATUS_PENDING` is never produced for data.
  *Narrowed by CUI-3:* `FSCTL_PIPE_LISTEN` on an **asynchronous** handle
  genuinely pends (`kernel/io/async.c`; pinned `sem_pipe/async_listen.c`) —
  rpcrt4's ncacn_np server loop deadlocks on a blocking listen, see the
  "CUI-3 SCM notes". On synchronous handles the original blocking behaviour
  is unchanged.
- **`FSCTL_PIPE_TRANSCEIVE` / `FSCTL_PIPE_IMPERSONATE` are unbuilt** —
  refused loudly (`STATUS_NOT_SUPPORTED` + a serial line), never faked.
  `FSCTL_PIPE_PEEK` is implemented (state, available bytes, message count,
  preview). *`FSCTL_PIPE_WAIT` is built by CUI-3* (served on the device-root
  open, with `NtCreateNamedPipeFile`'s timeout parameter finally stored as
  the unspecified-timeout default; pinned `sem_pipe/pipe_wait.c`) — one
  unpinned edge: a pipe deleted MID-wait answers
  `STATUS_OBJECT_NAME_NOT_FOUND` on the next wake, where wineserver would
  run the timeout out (waiters park on one global listeners-changed event
  and re-look the pipe up, sidestepping per-pipe waiter lifetime).
- **Byte-mode writes chunk under quota; message-mode writes are framed
  whole**, with one documented allowance: a message larger than the quota is
  admitted once the queue is fully drained (the reader then consumes it
  across several reads). Observable behaviour (partial-read
  `STATUS_BUFFER_OVERFLOW`, zero-byte messages, coalescing) is pinned by
  `tests/ntapi/sem_pipe/` on the oracle.
- **The kernel⇄conhost server protocol is proskrnl-internal**
  (`drivers/condrvproto.h`, mirrored by the fork's
  `programs/conhost/proskrnl.h`): real NT's condrv⇄conhost wire is
  undocumented and Wine pumps conhost through wineserver requests instead.
  The kernel mirrors wineserver's `get_next_console_request` semantics
  (busy verbs vs. parked blocking reads completed by `read=1`) so conhost
  runs uncopied straight from the pinned tree — its wineserver call sites
  carry a runtime-dormant proskrnl leg as a fork commit on
  `proskrnl-target` (Art. 10); the CLIENT surface — `IOCTL_CONDRV_*` and
  its structs — stays fully generated (`abi/ntcondrv.h`, G4).
- **One global console.** `IOCTL_CONDRV_BIND_PID` is answered kernel-side;
  every Connection/Reference/Input/Output open names the same console, and
  `hStdOutput`/`hStdError` share one Output open (the shape kernelbase's own
  std-handle setup produces). Per-console isolation arrives when something
  needs a second console.
- **The console transport is the COM1 serial wire, both directions**
  (HACK-004, docs/10): conhost's tty is `\Device\Serial0`, RX polled — see
  the ledger entry for scope and retirement.
- **The proskrnl conhost build's keyboard knowledge is the ASCII slice** of the
  US-layout `VkKeyScanW` mapping (user/wine/programs/conhost/proskrnl_glue.c): enough for
  the tty line discipline (Enter/Backspace/Tab/Escape/^A-^Z by virtual
  key); a real layout arrives with user32 (M10+).
- **conhost's wire output is a screen diff**, not an echo of written bytes:
  its renderer emits cursor-movement/erase sequences against its screen
  model. Tests assert cooked results (the client's own verdict), never
  literal output bytes (`tests/run/console_expect.py`).

## M10 CUI-userland notes (CreateProcess + the DLL set + cmd.exe)

The full `NtCreateUserProcess` contract (params passthrough, inheritance,
suspended creation) plus the time/port/timer surface, pinned by
`tests/ntapi/sem_ps/{time,suspend_resume,create_process,inherit,dll_load}`,
`sem_wait/alert_by_tid`, `sem_port/{ports,timers}`,
`sem_file/full_attributes`, `sem_pipe/device_type` — all green on the oracle
first (Art. 5). Wrinkles worth remembering:

- **`PS_CREATE_INFO` reports `PsCreateSuccess` on success.** Real NT writes
  the success state; the pinned Wine's unix implementation never writes
  `*info` on its ordinary success path — but kernelbase never reads it
  either, so the divergence is unobservable through the PE stack (and
  `user/smss` relies on the NT shape).
- **Console/std fixups mirror `server/process.c` `new_process`:** a real
  (positive) `ConsoleHandle` in the child's params is re-duplicated to a
  fresh child handle; the `CONSOLE_HANDLE_ALLOC*` sentinels and 0 pass
  through untouched — under the single-global-console model (M9 note) the
  sentinels still mean "no console bound". Without
  `PROCESS_CREATE_FLAGS_INHERIT_HANDLES` the three std handles are
  duplicated with invalid values tolerated. `bInheritHandles=FALSE` +
  `STARTF_USESTDHANDLES` is deliberately unpinned: on the oracle the
  console-less parent's `CONSOLE_HANDLE_ALLOC` headless console allocation
  displaces the duplicated handles, and nothing on the CUI path uses it
  (cmd always redirects with inherit).
- **condrv's seeded std handles are born `OBJ_INHERIT`** (NT console
  handles are inheritable); the console *reference* handle is not — the
  create-time duplication covers it, as on wineserver.
- **Suspend takes effect at the target's next return to user mode**
  (CUI-4 — *retires the M10 "suspend of a run thread is unbuilt"
  deviation*). There is still no kernel preemption, so a foreign thread is
  not parked mid-instruction; instead each `KTHREAD` carries a suspend gate
  (a notification event, `PspSuspend/ResumeTcb` the one truth for the
  thread- and process-level `Nt*`) that `KiProcessPendingUserSignals`
  consults at every ring-3 edge — the syscall-return, the interrupt-return
  (so even a syscall-free busy loop parks at the next timer tick), and the
  first descent. A thread blocked in a kernel wait is *not* pulled out of
  the wait: it finishes it and parks on return, which is exactly NT's
  "suspend applies on the way back to user mode" (server/process.c over the
  unix-signal suspend). `sem_ps/suspend_resume.c` (running-thread counts)
  and `sem_ps/suspend_process.c` (a child frozen mid-loop) pin it on both
  sides.
- **Foreign process/thread termination is served (CUI-4)** — *retires the
  "abandons blocked siblings" and the M7 "foreign terminate is
  `STATUS_NOT_IMPLEMENTED`" notes*. Nothing is torn down from the killer's
  context (Art. 3): `PspFlagThreadTermination` marks each target thread,
  drops its suspend holds and opens its gate, and aborts any wait
  (`KiAbortThreadWait` → `STATUS_THREAD_IS_TERMINATING`); the target reaps
  itself at its next ring-3 edge through the ordinary `PspExitCurrentThread`
  path. Exiting the process now terminates its siblings too, so a process
  actually dies when one thread calls `ExitProcess` (the Ctrl+C case). Every
  indefinite kernel wait a *user* thread can park in propagates the abort and
  releases its stack-local state — audited: `kernel/ob/wait.c`,
  `kernel/ob/sync.c` (keyed park), `kernel/io/completion.c`,
  `kernel/io/lock.c`, `fs/npfs/pipe.c`, and **`drivers/condrv.c`
  `CondrvForward`**, whose request lives on the dying thread's stack and is
  unlinked from the console queue on abort (a vanished console read completes
  as `STATUS_INVALID_HANDLE`, which conhost tolerates). `KiAbortThreadWait`
  asserts a non-kernel thread, so kernel-internal waits (cm hive mutex, the
  `PsRunUserImageEx` joins, the reaper) are never targets. **Any future
  indefinite user-thread wait must join this audit.** Pinned by
  `sem_ps/terminate_process.c`.
- **Thread-id alerts are process-local** — *retired by the winetest gate*:
  ids now come from the shared Ps id source (globally unique, NT's CID
  shape), an unknown id is `STATUS_INVALID_CID`, and a once-allocated id
  of an exited thread aliases the oracle's still-allocated table slot as
  an accepted no-op (`ntdll:sync` test_tid_alert; see "M10 winetest
  notes").
- **Timer APCs (`NtSetTimer` with an APC routine) are refused loudly**;
  nothing on the CUI path arms one (kernelbase and the ntdll threadpool
  wait on the object).
- **`NtRemoveIoCompletionEx` waits once**, then drains without waiting up
  to the caller's count — a partial batch is a success.
- **KUSER_SHARED_DATA time**: `SystemTime` = CMOS-RTC-seeded boot base +
  uptime (CUI-1 retired the fixed 2026-01-01 base; that date remains only as
  the fallback for implausible CMOS content), `TickCount` in milliseconds
  with `TickCountMultiplier = 1 << 24`, exactly the pinned Wine's constants;
  `NtQuerySystemTime` serves the same clock.
- **Sub-tick system time (the winetest frontier, docs/21 W13's residue).**
  The clock a *query* answers is the 1 ms tick plus a TSC-measured fraction
  of the tick in progress (`kernel/ke/timer.c` `KiTickFraction`), calibrated
  on the same PIT gate that sets the LAPIC timer's period
  (`arch/x86_64/lapic.c`). Without it `GetSystemTimePreciseAsFileTime` — which
  is `RtlGetSystemTimePrecise`, which on this kernel is `NtQuerySystemTime`
  (the fork's arm in `dlls/ntdll/time.c`) — moved in whole 1 ms steps, and
  Windows documents it as precise to under a microsecond. Pinned by
  `tests/ntapi/sem_ps/precise_time.c`; it is what took `kernel32:time` green.
  - **The divergence this creates, stated plainly: on NT `NtQuerySystemTime`
    IS the shared page, and here it runs up to one tick AHEAD of it.** The
    page stays tick-granular — a mirror published once per tick cannot be
    refreshed by writing an interpolated value into it — so the two readings
    no longer coincide, and `GetSystemTimeAsFileTime`, the *coarse* getter on
    Windows, is sub-tick here because Wine routes it to the same syscall
    (`dlls/kernelbase/file.c`). What makes the trade acceptable is that the
    gap has a bound (one tick) and a direction (query ≥ page), and every
    ordering the boundary asserts wants that direction: `sem_ps/time.c`, and
    `ntdll:time`'s `time.c:460`. The one assertion pointing the OTHER way is
    `ntdll:time`'s `time.c:458` — `NtQuerySystemTime <= USD SystemTime` —
    which upstream already wraps in
    `todo_wine_if(t1 > t2 && t1 - t2 < 50 * TICKSPERMSEC)` because Wine
    diverges the same way for the same reason. **Measured on that pair's
    proskrnl leg rather than argued** (it is parked for an oracle-side host
    flake, so `WTEST_NO_ORACLE=1`): 10657 tests executed and 0 failures both
    before and after, with the todo count going 1 → 2 — the second todo IS
    that assertion moving into its tolerance arm, which is the whole
    divergence, visible and bounded. Closing the gap properly means the
    Windows arrangement —
    a page carrying the QPC baseline so user mode interpolates for itself —
    and that is a KUSER_SHARED_DATA layout item, not this one.
  - **Only the clamp is load-bearing, not the TSC's quality.** The fraction is
    capped one unit short of a whole tick, so a reading can never reach the
    value the next tick will publish however fast or drifty the counter is,
    and each tick re-bases it — the worst case is the accuracy the clock had
    before interpolation. No invariant-TSC test is made, and none is needed.
  - **`NtQueryPerformanceCounter` inherits the resolution** (it is interrupt
    time, `kernel/ps/query.c`), which is what its 10 MHz reported frequency
    had been claiming all along.
- **`FileFsDeviceInformation.DeviceType` for a mounted volume is
  `FILE_DEVICE_DISK_FILE_SYSTEM` (0x8)**, the pinned oracle's value for
  regular files — not bare `FILE_DEVICE_DISK` (real NT's volume answer);
  `GetFileType` maps both to `FILE_TYPE_DISK`.
- **The volume classes (`FileFsVolume/Size/AttributeInformation`) answer in
  the pinned Wine's shapes**, not real NT's: `VolumeCreationTime` is 0,
  `SupportsObjects` is FALSE for FAT32 (TRUE only for NTFS), the FAT32
  attribute answer is `FILE_CASE_PRESERVED_NAMES` alone (real NT adds
  `FILE_UNICODE_ON_DISK`), and the volume label is read from the boot
  sector's `BS_VolLab` — the field Wine's mountmgr reads — not the root
  directory's `ATTR_VOLUME_ID` entry real NT's fastfat prefers (the two
  agree on any consistently-written volume; `FileFsLabelInformation` set
  is unimplemented on both sides). Pinned by
  `tests/ntapi/sem_file/volume_info.c`; consumer: cmd.exe's `dir`/`vol`
  via `GetVolumeInformationW` / `GetDiskFreeSpaceExW`.
- **A failing `NtQueryVolumeInformationFile` leaves the IOSB untouched on
  every handle** (success writes it; a bad handle writes `Status` alone).
  The pinned Wine is split on this: a drive-root handle is a mountmgr
  DEVICE file served through the wineserver, whose synchronous `NT_ERROR`
  completions never fill the caller's IOSB (`server/async.c`
  `async_terminate` — "the client should not fill the IOSB"), while a
  plain file handle takes the unix-fd path that fills it on failure
  (`dlls/ntdll/unix/file.c` preamble/epilogue). proskrnl has one path and
  follows the server-path shape uniformly — it is also real NT's — so the
  file-handle failure IOSB diverges from the oracle; only the drive-root
  shape is pinned (`tests/ntapi/sem_file/volume_info.c`), and no Wine PE
  consumer reads the IOSB after a failed volume query
  (`dlls/kernelbase/volume.c` checks the return status alone).
- **A relocated `SEC_IMAGE` copy's mapped header claims the ACTUAL base**
  (`OptionalHeader.ImageBase` stamped after the kernel-side fixups), which
  is what keeps ntdll's own `perform_relocations` from applying the delta
  twice — the same convention as Wine's mapper
  (`dlls/ntdll/unix/virtual.c map_image_into_view`).
- **cmd.exe ships as a standalone PE** built from the pinned tree's own
  cmd objects + `user/wine/programs/cmd/proskrnl_glue.c` (the five user32 / four shell32
  imports stood in over ntdll/kernelbase; shell verbs fail loudly).
  user32/shell32 themselves stay off the image until GUI-2 (Art. 7).
- **services.exe is deferred** (milestone text lists it): nothing in the
  M10 acceptance — cmd prompting, pipes/redirection, a third-party CUI
  app — touches the SCM. rpcrt4/advapi32 load and their client surface
  works (`sem_ps/dll_load`); the SCM waits for its first consumer.
- **Ctrl+C / console control events are out of scope**: no signal-delivery
  path from conhost exists yet; the acceptance never sends `^C`.

## M10 winetest notes (the CUI subset of Wine's own test suite)

The M10 stretch line (docs/02 "Ideal regression") is live as **the winetest
gate**: `tests/run/run.sh winetest` runs a manifest of
`<test_exe>:<subtest>` pairs (`tests/winetest/manifest.txt`) that must exit 0
— winetest's own failure count — under the pinned oracle AND on proskrnl.
The binaries are standalone links of the pinned tree's own unmodified test
objects (Makefile `wtests`, the cmd.exe recipe; entry is the msvcrt/ucrtbase
implib's own `mainCRTStartup`, winegcc's choice, with the `.CRT$X??`
boundary symbols winebuild would have emitted supplied by
`tests/winetest/glue/crt_sections.c`). Decisions and wrinkles:

- **The manifest is COVERAGE, not curation — amended.** It listed only
  pairs already green on both runners, which made the leg report the part
  of the surface already crossed and kept the rest invisible. It now lists
  **every** subtest of ntdll, kernel32, msvcrt, ucrtbase and programs/cmd —
  the whole non-GUI sweep, 83 pairs — so the leg's failure count IS the
  distance to the frontier. Two modules stay out, each because another leg
  owns it: **advapi32** (the security/registry service surface — CUI-2's
  `console` leg, CUI-3's `scm` leg, and `tests/ntapi`) and **user32** (the
  GUI trophy, its own `manifest-gui.txt` + `guiwtest` leg). The bullets
  below that say a pair "stays off the manifest" record its CAUSE, not its
  absence: the pair is now listed and red until the cause is fixed.
- **The helper-DLL subtests are reachable now.** `ntdll:thread`,
  `kernel32:actctx` and `ucrtbase:thread` do not IMPORT their helper module
  (`testdll`/`dummy`/`threaddll`); they `extract_resource()` it out of the
  test exe's own `TESTDLL` resource into `%TEMP%` and load it from there.
  The pinned tree's makedep already builds that resource as
  `<name>.dll.res`; the Makefile links it in, which is the whole of what
  those subtests need from the `.spec` SOURCES the exe still excludes.
- **One binary, two runners (docs/14) — so user32 is stood in at link
  time.** The ntdll/kernel32 test objects declare `IMPORTS = user32`;
  user32 is the GUI-2 path, off the image per Art. 7.
  `tests/winetest/glue/user32_stubs.c` supplies the referenced imports (honest
  `ERROR_CALL_NOT_IMPLEMENTED` failures for GUI entities; real
  implementations only where ntdll/msvcrt already carry the semantics).
  A subtest whose assertions need a real window/winstation fails
  IDENTICALLY on both runners and stays off the manifest (`ntdll:om` is
  the canonical casualty: its `\Sessions\...\WindowStations` half needs
  real winstation objects).
- **`ntdll:time` was off the manifest as an oracle-HOST flake, not a
  proskrnl divergence — it is listed again now that the manifest is
  coverage rather than curation, and a host flake is a finding to re-measure
  like any other.** Its `test_user_shared_data_time` check (`USD
  SystemTime / NtQuerySystemTime are out of order`, time.c:460 in the
  pinned tree) races Wine's own user-shared-data updater thread against
  the syscall's direct clock read; on shared CI runners (GitHub Actions
  ubuntu-24.04) the USD page lands ~0.7 ms AHEAD and the check trips
  near-deterministically (2/2 runs), while the same pair is green on
  developer hardware and green on proskrnl's own leg. A pair that can go
  red with zero proskrnl involvement cannot sit in a merge-blocking gate;
  it rejoins when upstream marks the check flaky or the oracle leg moves
  to hardware where it holds.
- **Both runners read as `winetest_platform == "wine"`** — the framework's
  probe is `GetProcAddress(ntdll, "wine_server_call") != NULL`, true for
  the fork's PE ntdll on proskrnl too — so `todo_wine` marks apply
  identically on both legs, and `win_skip` counts as a failure on both.
  That keeps the gate strictly differential.
- **G5 policy for winetest-driven kernel work**: the winetest subtest IS
  the oracle-pinned differential test — green on the oracle first, then a
  permanent regression gate on both runners via the manifest. A separate
  `tests/ntapi` pin is added only when the subtest's coverage of the new
  surface is incidental, or when a proskrnl-vs-oracle deviation needs a
  `todo_proskrnl`-style pin.
- **The sweep runs each pair on the console** (`user/smss/session.c`
  flow_wtest): winetest prints through msvcrt stdout → condrv →
  conhost → serial, so the serial log carries the per-check diagnostics;
  the exit code is the verdict. A pair that exceeds the per-pair budget
  (300 s — TCG runs the million-ok() subtests ~10x slower than native)
  cannot be reaped (no foreign terminate, above) and owns the single
  global console, so the sweep ABORTS on timeout rather than running more
  pairs against a wedged console.
- **The wtest image provisions instead of managing**: the FULL nls set is
  baked (a missing `c_932.nls` reads as a mass CRT/codepage divergence),
  and the leg boots with 1 GiB of guest RAM — no eviction (Art. 3) means
  the page cache holds every MB-scale test binary's pages for the whole
  sweep. A per-process page leak was ruled out empirically (one
  child-spawning pair run ten times in one boot).
- **`PEB->NtGlobalFlag` is stamped by the KERNEL** (`kernel/ps/peb.c`):
  Session Manager `GlobalFlag` default, image-basename "Image File
  Execution Options" override, `PROCESS_PARAMS_IMAGE_KEY_MISSING` mirrored
  — real NT's MmCreatePeb does exactly this; Wine does it unixlib-side
  (`dlls/ntdll/unix/env.c load_global_options`), a seam proskrnl doesn't
  have. Consumer: `kernel32:heap` test_debug_heap children.
- **`Machine\System\CurrentControlSet\Control\Session Manager` is seeded
  Cm furniture** — real NT always has it; the heap test's
  read-Session-Manager child probes it directly.
- **`HKLM\Software\Wine\LicenseInformation` is seeded from the pinned
  `wine.inf`, WHOLE and GENERATED** (`kernel/cm/license.h`,
  `tools/gen_license.py`, applied by `CmInitialize`). It is the key
  `NtQueryLicenseValue` names literally (`dlls/ntdll/unix/registry.c`), and
  on the oracle it is prefix furniture that `loader/wine.inf`'s
  `[LicenseInformation]` writes at `wineboot --init`; the hermetic images
  carry no `wineboot.exe`, so the kernel seeds it — the Session Manager
  precedent, one layer down from `win.ini` (`tools/gen_sysini.py`, docs/21
  W14). What the generator buys over transcription is the failure it
  already prevented once: the seed was hand-written and carried only
  `Kernel-MUI-Language-Allowed`, so the `REG_DWORD` value beside it
  answered `STATUS_OBJECT_NAME_NOT_FOUND` and `ntdll:reg` lost 12
  assertions to a payload nobody had noticed was a subset (docs/21 W12).
  A hand-copied subset is a claim about which lines matter, and the claim
  goes stale silently; the whole section is checkable. The Makefile's
  `--check` rule is what notices a pin bump editing that section.
- **`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time Zones` is seeded
  the same way** (`kernel/cm/timezones.h`, `tools/gen_timezones.py`,
  `CmInitialize`): 139 zone keys and their 92 `Dynamic DST` subkeys, 2576
  values, generated out of the pinned kernelbase's own WINE_REGISTRY resource
  (`dlls/kernelbase/kernelbase.rgs`, applied to the oracle's prefix by
  `dlls/setupapi/fakedll.c` at `wineboot --init`). It is byte-identical to what
  that prefix carries, checked row by row when it was written. The key had
  carried exactly one hand-copied row before this — UTC, because that is the
  row `GetDynamicTimeZoneInformation` needs to boot — and `kernel32:time`
  measured the cost of that subset at fourteen assertions, the license values'
  lesson a second time in the same file (docs/21 W13). Pinned by
  `tests/ntapi/sem_reg/timezone_keys.c`.
  - **The zone proskrnl REPORTS is still UTC alone** (`kernel/ps/query.c`
    answers `SystemDynamicTimeZoneInformation` with `TimeZoneKeyName` `L"UTC"`,
    the no-RTC-offset rule above). The table is what a caller may ASK about —
    `GetTimeZoneInformationForYear` takes a zone key name from its caller — so
    the two are different questions and the table is not a claim that the
    machine is in 139 places.
  - **The seeded rows are ordinary persisted keys**, so they join the hive
    image `CmpSaveHive` rewrites on every mutating registry call. Measured cost
    on the winetest and CUI legs: none visible. They are not volatile because
    the seed path has one never-stomp rule for all furniture (`CmpSeedValue`)
    and a volatile parent would additionally refuse a non-volatile child —
    observable, where the growth is not. The never-stomp rule does make the
    seed ONE-WAY on a surviving disk: a pin bump that brings new tzdata is
    caught in the header by the Makefile's `--check`, but a hive already
    holding the old rows keeps them, because the seed only fills what is
    absent. Every test image is baked fresh, so nothing measures it; a
    long-lived install would need its hive re-seeded rather than merely
    re-booted.
  - **`tzres.dll` is baked onto the winetest image** (`tests/run/run.sh`,
    the `win.ini` precedent). The `MUI_Std`/`MUI_Dlt` values are
    `@tzres.dll,-N` indirections, and `GetDynamicTimeZoneInformation` and
    `GetTimeZoneInformationForYear` resolve them through the same
    `RegLoadMUIStringW` but DISAGREE about its failure — the first ignores the
    error and keeps the raw `@tzres.dll,-22000`, the second falls back to the
    zone's plain `Std`. With the file absent the two APIs therefore answer
    different strings for the same zone, which is `kernel32:time` :990-:1008
    and is made entirely of a file the oracle's prefix has.
- **GlobalMemoryStatusEx's three sources answer for real** (`kernel/ps/
  query.c`): `MmNumberOfPhysicalPages`, the new
  `SystemPerformanceInformation` class, and
  `NtQueryInformationProcess(ProcessVmCounters)` over a VAD walk — no
  paging means committed IS the working set, and with no pagefile the
  commit limit IS physical memory. (Before this, the heap test's own
  `/ (ullTotalPhys / 100)` was a guest divide-by-zero.)
- **`FILE_OBJECT` carries the caller's RAW desired access, not just the
  granted mask** (`kernel/io/io.h` `FILE_OBJECT.desiredAccess`, set at the
  one create site in `kernel/io/file.c` and by
  `NtCreateNamedPipeFile`; docs/21 W11, pinned
  `tests/ntapi/sem_pipe/create_refusals.c`). npfs needs it: a pipe's share
  mask bounds what the CLIENT may ask for, and the rule is about a client
  that EXPLICITLY names a direction the pipe does not offer. After
  `ObpMapDesiredAccess` that distinction is gone — `GENERIC_READ`,
  `GENERIC_ALL` and `MAXIMUM_ALLOWED` all land on masks carrying
  `FILE_READ_DATA`, so a mapped-mask check refuses a `MAXIMUM_ALLOWED`
  client open of an OUTBOUND pipe, which is a routine `CreateFile` pattern
  and which the oracle admits (measured; `server/named_pipe.c`
  `named_pipe_open_file` tests the `GENERIC_*` bits before wineserver's own
  mapping). **Not an NT-absent addition**: NT hands its FSDs exactly this
  word as
  `IO_STACK_LOCATION.Parameters.Create.SecurityContext->DesiredAccess`, and
  proskrnl's vfs `Create` op has no IRP to carry it, so the file object
  does. The first cut of this check read `grantedAccess` and was caught by
  gate-check, not by a test — the twelve-case matrix in the pin uses only
  `GENERIC_*` masks, where the two formulations agree.
- **The gate already convicted and fixed real kernel bugs** (Art. 6 in
  action): the absolute-timeout translation (`KiComputeDueTime` treated a
  positive since-1601 deadline as an interrupt-time due — every absolute
  `RtlWaitOnAddress`/wait timeout parked ~forever), per-process thread-id
  collisions (ids now come from the shared CID-shaped source), the missing
  keyed-event rendezvous, and a divide-by-zero feeding
  `GlobalMemoryStatusEx` zeros into `kernel32:heap`'s own arithmetic.
- **Commented out of the manifest, with cause** (`tests/winetest/
  manifest.txt` carries each reason inline). The bar is deliberately high:
  being UNIMPLEMENTED is not a reason — an unbuilt syscall makes the pair
  FAIL, which is the signal the sweep exists to produce. Only two things
  disqualify a pair:
  - *(a) proskrnl will never implement the surface*, by a decision recorded
    elsewhere. `ntdll:alpc` (the LPC/ALPC surface stays unbuilt because the
    local-RPC transport is npfs — "CUI-3 SCM notes" above) and
    `kernel32:debugger` (debug objects, ADR 0011). Both are GREEN on the
    oracle and both panic on proskrnl's first missing syscall, which is the
    armed-panic contract working rather than a defect to chase. Leaving
    them in would make the gate permanently red on purpose.
    `ntdll:wow64` joins them as the milestone case: WOW64 is planned but
    later (docs/02), and the oracle is red on it anyway (4 failures).
  - *(b) the ORACLE cannot serve as the spec.* `ntdll:om` (the oracle
    CRASHES — om.c:1893 wants `\Sessions\1\Windows\WindowStations\WinSta0`,
    the user32 half of the namespace that Art. 7 keeps off this image);
    `kernel32:console` (1) and `kernel32:process` (48), which need a real
    console the redirected oracle has not got — a pty does hand wine one,
    measured, but it then dies on "Unable to open HKCU\Console, error 2";
    `kernel32:loader` (dies on the oracle too, driving 32-bit children
    through the debug loop); `kernel32:module` (asserts the TEST BINARY'S
    OWN import list, which the standalone link deliberately changes — it
    measures the harness, not the boundary); and `cmd.exe_test:batch` (one
    residual oracle failure, batch.c:390, the pinned cmd.exe against the
    pinned expected file with proskrnl nowhere in it).

- **Eight pairs were parked on the HOST, not on proskrnl — corrected.**
  This section used to record `kernel32:file` (7 failures) and
  `cmd.exe_test:batch` (3) as "upstream suite-vs-Wine drift" and
  `ucrtbase:file` as needing a locale "the oracle environment lacks". All
  three were the runner's own environment, and so were five more. Measured
  on the pinned tree, changing nothing but the host:
  - a UTF-8 locale (`LC_ALL`, now pinned by tests/run/run.sh) takes
    `ntdll:directory` from 82 failures to 0, `ucrtbase:file` from an
    outright death to 0, and `ntdll:change` from 1 to 0;
  - running as an ORDINARY USER instead of root (now refused by
    tests/run/run.sh) takes `ntdll:file` from 6 to 0, `kernel32:profile`
    from 4 to 0, `kernel32:version` from 36 to 0, `kernel32:comm` from 3
    to 0 and `kernel32:file` from 7 to 0.
  Wine maps NT's access checks onto unix permission bits and derives its
  unix codepage from the host locale, so root and C/POSIX each corrupt the
  spec in the one direction nothing downstream can detect. The lesson is
  procedural and worth more than the eight pairs: **do not park a pair on
  an oracle failure without re-measuring it unprivileged under UTF-8.**

- **Still red, and genuinely proskrnl's** (the sweep's actual backlog, one
  boot per pair so no wedge can hide another): most are unbuilt surface
  reached under the armed panic — `ntdll:{directory,info,pipe,thread,
  threadpool,virtual}` and `kernel32:{file,mailslot,pipe,power,process,
  sync,thread,time,virtual}` all stop at a `STATUS_NOT_IMPLEMENTED`. Two
  are memory-safety defects the sweep surfaced and nothing else had:
  `kernel32:timer` panics `KASAN: use after free`, and `ntdll:reg` takes a
  `#UD invalid opcode`. Those two are bugs, not gaps.

## The set-basic access check (`FileBasicInformation`, set direction)

`NtSetInformationFile(FileBasicInformation)` requires **no access** on
proskrnl. Documented NT wants `FILE_WRITE_ATTRIBUTES`, and the kernel asked
for it until the winetest sweep convicted it — because the caller that
matters does not hold it:

```c
/* dlls/kernelbase/file.c SetFileAttributesW */
status = NtOpenFile( &handle, SYNCHRONIZE, &attr, &io, 0,
                     FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT );
...
status = NtSetInformationFile( handle, &io, &info, sizeof(info), FileBasicInformation );
```

`SYNCHRONIZE` and nothing else. Every `SetFileAttributes` in the Wine
userland goes through that one handle, so a kernel that enforces the
documented bit refuses all of them — silently, since the CRT layers above
discard the status. It surfaced as `msvcrt:file`: `test__creat` leaves a
read-only `_creat.tst`, clears the bit, deletes it and recreates it, and
with the clear refused the read-only file outlived its own cleanup and
failed the three blocks after it (file.c:2921, 2934, 2952) with errors that
named `_creat` and `_lseek` rather than the attribute set that actually
broke.

The pinned oracle grants it, so the boundary's answer is "granted" (Art. 1:
the `Nt*` semantics Wine uses, not the documented ones it does not).
Pinned by `tests/ntapi/sem_file/readonly_attr.c` step 5 — a
`SYNCHRONIZE`-only handle clearing `FILE_ATTRIBUTE_READONLY` — on both
runners, so a re-tightening cannot land silently.

The read-only rules the same test pins around it were already right and are
unchanged: creation reports the bit, a delete of a read-only file is
`STATUS_CANNOT_DELETE`, and once set the file refuses `FILE_OVERWRITE_IF`,
an open for write data and an open for `DELETE` with `STATUS_ACCESS_DENIED`
while still granting an open for read.

## CUI-1 firstboot notes (wineboot + the machine-state registry)

First boot runs `wineboot --init` (a session-manager stage: `user/smss/firstboot.c`),
which applies `wine.inf`'s machine-state payload through
`rundll32 setupapi,InstallHinfSection` children. Deviations and scoping:

- **The baked `wine.inf` is filtered, not the oracle's** (`tools/filter_inf.py`,
  run at image-bake time). Dropped directive families: `WineFakeDlls`
  (setupapi's fake-dll machinery truncates a "Wine builtin DLL"-signed
  destination *before* reading the absent source — deletes the baked
  system32), `CopyFiles`/`DelFiles`/`RenFiles` (the file queue fails on absent
  source media and aborts `SetupInstallFromInfSectionW` before its AddReg
  pass), `RegisterDlls` (self-registration loads GUI DLLs not baked),
  `UpdateInis` (`SPINST_INIFILES` runs *before* `SPINST_REGISTRY`;
  `BaseInstall` opens with `UpdateInis=SystemIni`, and a failure there returns
  FALSE before its ~500-line AddReg ever runs), and `ProfileItems` (Start Menu
  shortcuts via shell32). All `AddReg`/`DelReg` and the `.Services` sections
  are kept. The INF is input data staged by the image builder — no Wine
  PE-side change.
- **The registry differential** (`tests/run/run.sh firstboot`, the milestone's
  Art. 6 conviction gate) boots a virgin image, pulls the SYSTEM hive off the
  FAT volume, and compares it against a fresh oracle prefix initialized with
  the SAME filtered INF, staged over the pinned tree's `loader/wine.inf` for
  that one prefix init (restored after; `--keep WineFakeDlls`, because fake
  dlls write no registry but a prefix without them cannot launch any
  non-bootstrap process, and on the host their sources exist). The compared
  scope is derived FROM the filtered INF itself (`tests/run/regdiff.py`
  parses the reachable AddReg sections): every payload key/value must match
  exactly on both sides, and the hive must contain nothing beyond payload +
  documented writers. Oracle-only state outside the payload (each fake
  dll's embedded REGINST registration resource, wineserver furniture) stays
  out of scope by construction; every other exclusion is written down in
  `regdiff.py` and here.
- **The baked PE dlls are debug-stripped copies** (Makefile `winestrip`).
  Not an optimization: with no COW and no eviction (Art. 3) every mapped
  image is copied whole per process, and toolchains that emit large DWARF
  sections (Linux mingw-gcc) tripled the set — firstboot's rundll32
  fan-out then died in `STATUS_INSUFFICIENT_RESOURCES` *import* failures,
  which wineboot warn-and-continues into a silent no-payload "PASS" the
  differential was built to convict. The pinned tree keeps full symbols for
  the oracle legs.
- **Two runtime-dormant setupapi seam commits** on the fork's
  `proskrnl-target` branch (Art. 10): `SetupInstallFromInfSectionW` resolves
  `CoInitialize`/`CoUninitialize` (ole32) lazily and `get_csidl_dir` resolves
  `SHGetSpecialFolderPathW` (shell32) lazily, each degrading gracefully when
  the DLL is absent. Both are *unconditional* delay-import calls setupapi
  makes that no INF filtering can suppress (the ole32 one fires under
  `SPINST_REGSVR` even with zero `RegisterDlls`; the shell32 one fires
  whenever an AddReg value references a CSIDL dirid). Under regular
  Wine/Windows both DLLs always load and the calls run unchanged.
- **`HKLM\Software\Wow6432Node` mirror keys fail and are excluded from the
  differential** (~52 `could not create key` on `Software\...\Wow6432Node\...`).
  These are the WOW64 32-bit registry view; WOW64 is a far-future milestone.
  setupapi warn-and-continues on each.
- **HKCU is not populated (deferred to CUI-2).** `RtlFormatCurrentUserKeyPath`
  needs `NtQueryInformationToken` (still `MISSING`), so wineboot's per-user
  legs fail gracefully; the differential is scoped to `HKLM`.
- **`REG_OPTION_CREATE_LINK` was unimplemented at CUI-1** and the `Time Zones`
  REG_LINK symlink `wine.inf` writes failed. GUI-2 built registry symlinks
  (see the M8 notes), so the link now lands on proskrnl too; the
  differential still excludes `SymbolicLinkValue` values on both sides
  (`tests/run/regdiff.py`), because both dumps resolve links rather than
  reporting them.
- **`ws2_32.dll` is baked as dormant data** — it cannot load (`DllMain`
  returns failure with no unixlib below); wineboot's `gethostname`/
  `getaddrinfo` are glue stand-ins. A loadable seam is Net-1's (sockets).
- wineboot's remaining legs warn-and-continue as stock: missing
  `__wine_user_shared_data` section, absent `services.exe`, the root PnP
  device installs, and the `winedbg` auto-start on a child fault.

## CUI-2 Se notes (the minimal-but-real security model)

`kernel/se/` implements the token surface the already-baked DLLs read
(kernelbase/security.c, ntdll/sec.c, advapi32): `NtOpenProcessToken(Ex)`,
`NtOpenThreadToken(Ex)`, `NtQueryInformationToken`,
`NtAdjustPrivilegesToken`, `NtDuplicateToken`, `NtPrivilegeCheck`,
`NtAccessCheck`, `NtQuery/SetSecurityObject`, `NtAllocateLocallyUniqueId` —
pinned by `tests/ntapi/sem_se/` (oracle-green first, Art. 5). The behaviour
reproduced is the ORACLE COMBINATION of Wine's unix layer
(`dlls/ntdll/unix/security.c`) and wineserver (`server/token.c`,
`server/handle.c`, `server/object.c`); where that pair disagrees with
real-NT folklore, the oracle wins (Art. 6). Scoping and deviations:

- **One fixed identity, byte-identical to wineserver's
  `token_create_admin`**: user `S-1-5-21-0-0-0-1000`, owner/primary group
  Domain Users (`-513`), 8 groups, 21 privileges (4 enabled by default),
  the 2-ACE default DACL, session 1, `TokenElevationTypeLimited`. Identical
  bytes are what let sem_se pin exact SIDs differentially, and make
  `RtlFormatCurrentUserKeyPath` (HKCU) agree on both sides. Every process
  token is a primary *duplicate* of its creator's (wineserver's child
  rule): adjustments never leak across processes; TokenIds are per-process.
- **No impersonation attach** (CUI-3, the SCM needs it): threads carry no
  token; `NtOpenThreadToken(Ex)` validates the thread handle and answers
  `STATUS_NO_TOKEN`, exactly what the oracle says for a fresh thread.
  `NtDuplicateToken` still mints impersonation *objects* — all
  `AccessCheck`/`CheckTokenMembership` need.
- **Still MISSING** (no baked caller; each returns
  `STATUS_NOT_IMPLEMENTED` through the generic dispatcher):
  `NtSetInformationToken`, `NtFilterToken`, `NtCompareTokens`,
  `NtCreateToken`, `NtImpersonateAnonymousToken`, the audit/alarm
  `NtAccessCheck*AndAuditAlarm` family. `TokenLinkedToken` likewise stays
  unanswered (the oracle would mint a Full-elevation linked token) until a
  UAC-probing caller convicts it.
- **Object access: always-allow retired for SD-bearing objects (CUI-6)**:
  a create-time `OBJECT_ATTRIBUTES.SecurityDescriptor` is now captured
  (`SeCaptureObjectSecurity`) and enforced at open through
  `SeCheckObjectAccess` — wineserver's `check_object_access`: the effective
  token (thread impersonation else process primary) walks the object's DACL,
  a denied right is `STATUS_ACCESS_DENIED`, `MAXIMUM_ALLOWED` resolves to the
  granted subset. An object with **no** SD stays permissive, exactly as the
  server's null-SD path does. Create does not ACE-check its own new SD (the
  creator gets the requested access; the DACL bites at open), and a partial
  create-time SD is stored as given — token-defaulting of missing parts is
  `NtSetSecurityObject`'s job (no baked create passes a partial SD).
  `NtAccessCheck` remains the caller-supplied-SD service it always was.
- **`NtQuery/SetSecurityObject` scope**: pinned on named events (kernel
  objects generally); FILE SDs are out — the oracle's come from host
  `stat()` shapes. Mandatory-label SACL surgery
  (`LABEL_SECURITY_INFORMATION` extraction/replacement,
  `token_assign_label`) is not reproduced; no baked caller reads labels.
- **Oracle oddities kept, not "fixed"**: the retlen pre-writes (`*retlen =
  info_len[class]` before any validation, `*handle = 0` before any open);
  `TokenSource` = `BUFFER_TOO_SMALL` short but `NOT_IMPLEMENTED` adequate;
  the semi-stub classes (`TokenVirtualizationEnabled`, `TokenUIAccess`,
  `TokenIntegrityLevel`, `TokenIsAppContainer`, `TokenAppContainerSid`)
  answered without touching the handle at all; adjust's silent
  previous-state truncation; `NtClose` succeeding on every pseudo handle in
  `[~5, ~0]`. One divergence: the oracle reads `info_len[]` out of bounds
  for classes 41..50 (garbage lengths) — proskrnl answers 0/`NOT_IMPLEMENTED`;
  unpinnable either way.
- **winetest**: no parked pair was blocked on the token surface (the
  parked causes are Mm/path/thread breadth — "M10 winetest notes" above);
  the manifest is unchanged by CUI-2.
- **Acceptance**: Wine's unmodified `whoami.exe` (+ `secur32.dll`) is baked
  onto the console image; `tests/run/run.sh console` runs `whoami /logonid`
  under cmd.exe and greps the logon SID `S-1-5-5-0-0` — a real tool's
  startup `OpenProcessToken`/`GetTokenInformation` path, machine-checked.
  (`whoami /user` additionally needs `GetComputerNameW`, whose
  `ActiveComputerName` seeding rides wineboot's unixlib `gethostname` —
  absent here, so the SAM-name flavor stays out of the gate.)
  `GetUserNameW` is an environment read on Wine (`advapi32/advapi.c`), so
  the default environment grows `WINEUSERNAME=wine`.

## CUI-3 SCM notes (services.exe + rpcss over npfs)

What the SCM bring-up pinned, deviated on, or left unbuilt:

- **The transport is M9's npfs, exactly as planned** (`docs/02`): Wine's
  local RPC is named pipes (`ncacn_np:[\pipe\svcctl]`,
  `\pipe\net\NtControlPipe%u`), so the whole LPC/ALPC syscall surface stays
  permanently unimplemented. Zero Wine fork commits: services.exe, rpcss.exe,
  sc.exe, and userenv.dll are pure-PE, prebuilt in the pinned tree, baked
  unmodified (the whoami precedent) — the hack meter is untouched.
- **Async narrows to exactly one verb** (amended M9 note above):
  `FSCTL_PIPE_LISTEN` on an asynchronous handle pends
  (`kernel/io/async.c`); data transfers stay synchronous. One divergence
  this leaves: services.exe's 10-second I/O timeouts on service control
  pipes (`service_send_command`) cannot fire MID-transfer — a blocking
  read against a hung service parks until the peer acts, where NT would
  time out and orphan it. A hung *service* is the only victim; the pinned
  suite and the baked services never hit it.
- **One pending listen per pipe instance**: a second concurrent listen on
  the same instance is refused loudly (`STATUS_NOT_IMPLEMENTED` + serial);
  wineserver queues them. rpcrt4 issues one listen per connection object,
  so no baked caller stacks two. Two adjacent narrownesses, both
  unreachable for baked callers: a pending listen is NOT cancelled at its
  issuer THREAD's exit (NT sweeps a dying thread's pending I/O; here only
  handle cleanup/cancel/completion retire it — rpcrt4's listener thread is
  process-lifetime), and the cancel verbs' thread scoping compares the
  recorded issuer pointer without holding the thread (a compared-only
  field; a recycled thread allocation could in principle mis-scope a
  cancel on the same handle — no baked caller cancels from a thread other
  than the issuer). `NtWriteFile`'s `-2` FILE_USE_FILE_POINTER_POSITION
  sentinel is refused (`STATUS_INVALID_PARAMETER`), not honoured —
  unpinned, no baked caller; `-1` (write-to-end) is pinned and served
  (`sem_file/append.c`).
- **Impersonation attach is RE-deferred with evidence** (correcting the
  CUI-2 prediction above that "the SCM needs it"): Wine's services.exe
  performs no token-based access checks — `programs/services/` contains no
  `RpcImpersonateClient`/`RevertToSelf` call at all
  (`svcctl_OpenSCManagerW` only maps access masks). `NtOpenThreadToken`
  keeps answering `STATUS_NO_TOKEN`; `FSCTL_PIPE_IMPERSONATE` stays
  loud-unbuilt. What the SCM actually needed instead: job objects,
  `ProcessWineMakeProcessSystem`, `NtCancelIoFile(Ex)`, `FSCTL_PIPE_WAIT`,
  async listen, and a `GetComputerNameA` that answers.
- **Job limits are validated and stored, mostly never enforced**
  (`kernel/ps/job.c`): services.exe sets only the breakaway bits, which
  gate behaviour proskrnl does not have. The one exception is
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, **enforced since CUI-4** through the
  type's close procedure (last handle closed → every live member is
  terminated) — the contract a job-driving build tool cleans up with.
  `NtQueryInformationJobObject` (accounting, pid list, limit read-back),
  `NtTerminateJobObject`, `NtOpenJobObject` and `NtIsProcessInJob` are
  served as of CUI-4 too, pinned by `sem_ps/job_query.c`. **CUI-6 finished
  the surface** (`sem_ps/job_nest.c`): job nesting (assigning a process
  already in one job to a fresh job makes it a child — wineserver's
  parent/child chain, with counts and the pid list recursing the subtree and
  `NtIsProcessInJob` recursive), create-time membership with silent/explicit
  breakaway (`PROCESS_CREATE_FLAGS_BREAKAWAY`), and **real per-job CPU-time
  accounting** (the subtree's exited totals plus live members' tick counters
  — pinned `beyond_oracle`, since the oracle zero-fills the same field).
  Still validated-and-stored-not-enforced: the working-set/time/memory limit
  flags — the oracle reads `limit_flags` nowhere but the breakaway and
  kill-on-close bits, so inventing enforcement would exceed the boundary
  (Art. 1). IO counters stay **zero** — no per-process IO accounting exists
  (Art. 12), never a fabricated number. Exit packets always say
  `JOB_OBJECT_MSG_EXIT_PROCESS`; the ABNORMAL_EXIT flavor is unbuilt (no
  consumer distinguishes them).
- **`ProcessWineMakeProcessSystem` is real** (`kernel/ps/query.c`): the
  global shutdown event exists and its user-process count is maintained,
  but on-target it realistically never signals (conhost and cmd live for
  the whole session). The remaining `NtSetInformationProcess` classes stay
  accepted no-ops — now NAMED on serial per call (Art. 12 hygiene; this
  class was the planted-bug shape that rule exists for). **One class has
  since left that group for the opposite reason**:
  `ProcessManageWritesToExecutableMemory` (83) and its thread twin
  `ThreadManageWritesToExecutableMemory` (48) answer
  `STATUS_NOT_SUPPORTED`, because the status IS the value — a caller sets
  the class to ask "am I on an ARM64EC host?", so a no-op success answered
  yes on x86_64 (`dlls/ntdll/tests/virtual.c` `test_exec_memory_writes`
  then asserts the processor architecture is ARM64 and skips its body).
  The refusal is the pinned oracle's own off-ARM64 arm and it precedes
  every argument check, so a wrong length, a wrong `Version` and a junk
  handle all get it too; pinned by `sem_ps/manage_exec_writes.c`. The
  ARM64EC contract behind the class — write exceptions on executable
  pages, `VmPageDirtyStateInformation` — is unbuilt and unreachable on an
  x86_64 host.
- **The hostname is configuration**: the wineboot glue's `gethostname`
  answers the fixed name `proskrnl` (there is no hostname source below the
  boundary); wineboot's stock `create_computer_name_keys` seeds
  `ComputerName`/`ActiveComputerName`, which `rpcrt4_ncacn_np_handoff`
  hard-requires. The firstboot differential already excludes those
  subtrees as host-derived.
- **wine.inf's `AddService` payload now installs through the real SCM**:
  wineboot starts services.exe (`start_services_process`, every boot —
  firstboot always runs `--init`) BEFORE the INF pass, so setupapi's
  service installer round-trips `CreateService` over `\pipe\svcctl` at
  first boot — the Cm+SCM integration exercise. Auto-start services whose
  binaries are not baked (svchost/winedevice) fail fast at
  `CreateProcessW` and are tolerated (`services.c` autostart loop).
- **A resident SCM raises the memory floor**: every process maps full
  private copies of its DLLs (no COW, no eviction — Art. 3), and
  services.exe + its service processes now stay resident for the whole
  session. 256 MB no longer covers an interactive console boot (kernel32
  load fails `STATUS_NO_MEMORY` mid-session); `make run` and the
  console/scm legs provision 1 GB — the winetest leg's long-standing
  answer to the same bill.
- **winetest**: the manifest is unchanged. The natural pair
  (`advapi32:service`) cannot run — the pinned tree builds no advapi32-test
  PE objects. The three adjacent candidates were EVALUATED (oracle-green
  all three) and park on proskrnl with these observed causes:
  `ntdll:pipe` — wants the async DATA path (`STATUS_PENDING` reads/writes),
  `NtSetInformationFile(FilePipeInformation)` validation, pipe-object
  signal-state semantics, and wrong-end verb mapping
  (`STATUS_ILLEGAL_FUNCTION`); runs past the deadline on an unfulfilled
  wait. `kernel32:pipe` — the same overlapped data-path breadth through
  the Win32 surface. `ntdll:info` — unbuilt query classes
  (`SystemProcessorFeaturesBitMapInformation` et al.); also over-deadline.
  All are M9-breadth surface the SCM demonstrably does not need.
- **Acceptance** (`tests/run/run.sh scm`, boot-twice): boot 1 drives
  `sc query RpcSs` (STOPPED over the pipe), `sc start RpcSs` (a real
  service process spawns and reports RUNNING), `sc create SvcDemo` +
  `sc start SvcDemo` (`tests/cui/svcdemo.c`, a plain-mingw third-party
  service binary that appends a proof line to `C:\svcdemo.log`); boot 2
  asserts the SCM AUTO-started SvcDemo from the persisted registry before
  cmd prompted, and the proof file grew to two lines.

## CUI-4 process-ecosystem notes (tasklist/taskkill, Ctrl+C, job tools)

The milestone's own deviations; the retirements it earns are recorded at the
notes they replace (the M7 foreign-terminate note, the M10 suspend and
abandoned-siblings notes, the CUI-3 job note).

- **One preemption point exists now** (`KiPreemptAtUserReturn`,
  `kernel/ke/sched.c`, called from the timer interrupt's ring-3 return in
  `kernel/init/panic.c`). This is *not* kernel preemption — Art. 3 still
  holds inside the kernel — but the switch AT a user-mode return the
  constitution sanctions. It is **required**, not an optimization: a ring-3
  loop that issues no syscall never yields, so before this a killer could
  never regain the CPU and `taskkill` / Ctrl+C could not work at all (the
  proskrnl sweep hung the first time foreign terminate was tried without
  it). Round-robin only when an equal-or-higher-priority thread is ready.
- **Ctrl+C is detected on the serial RX path, not by conhost**
  (`drivers/condrv.c CondrvSerialRead`). Under HACK-004 the UART receive
  path *is* this milestone's keyboard driver (docs/02 M9), so it is also the
  line discipline: like a Unix tty's `ISIG`, `0x03` is consumed there and
  becomes a console control event rather than a keystroke. The kernel-side
  `IOCTL_CONDRV_CTRL_EVENT` handler is nevertheless implemented for both the
  server handle (conhost's own fanout) and the client handle
  (`GenerateConsoleCtrlEvent`), so the real Wine path works the moment
  conhost can drive it. **Cost:** `ENABLE_PROCESSED_INPUT` is not consulted —
  a program that turns it off still gets a control event instead of a `0x03`
  input record. Retired with HACK-004 when a real keyboard arrives (GUI-1).
  *Why the transport and not conhost:* the pinned conhost kills its own tty
  input thread on a raw `0x03` when it is not in `--unix` mode
  (`programs/conhost/conhost.c`), and `--unix` cannot be used here because it
  switches decoding to `CP_UNIXCP`, a codepage proskrnl has no table for.
  Fixing conhost is a `proskrnl-target` fork commit (G9) and is the right
  long-term shape; it is out of this change's repository scope.
- **Delivery is a new thread at ntdll's `__wine_ctrl_routine`**
  (`PsPropagateConsoleCtrlEvent`, `kernel/ps/process.c`) — the exact contract
  wineserver's `propagate_console_signal` + ntdll's `int_handler` implement,
  so kernelbase's `CtrlRoutine` and every handler above it work unmodified.
  An APC could not serve: a user APC only runs at an alertable wait, so it
  could never interrupt a busy loop. Console attachment is
  `consoleHandle != 0` (one global console, docs/03 M9); `EPROCESS`
  gains `processGroupId`, inherited from the creator or the process's own id,
  which is what `GenerateConsoleCtrlEvent`'s group filter selects on. A
  process whose ntdll export did not resolve is skipped, never faked.
- **`SystemProcessInformation`'s time/IO/memory fields are zero**
  (`kernel/ps/query.c`): proskrnl keeps no per-process CPU or IO accounting,
  and the counts that ARE real (thread count, ids, handle count, session,
  base priority, the base-name `ProcessName`) are what `CreateToolhelp32
  Snapshot` and tasklist read. `ParentProcessId` is a new `EPROCESS` field.
- **tasklist/taskkill are standalone PEs** built from the pinned tree's own
  unmodified program objects plus `user/{tasklist,taskkill}/proskrnl_glue.c`
  (the cmd.exe precedent). taskkill's *graceful* path needs windows, which do
  not exist before GUI-2, so `EnumWindows`/`GetWindowThreadProcessId`/
  `PostMessageW` fail honestly (Art. 12) and `/f` — `OpenProcess` +
  `TerminateProcess` — is the working path.
- **Acceptance** (`tests/run/run.sh procs`): one interactive console boot in
  which `looper.exe` (a busy loop with a console control handler) is
  interrupted by an injected `^C` and reports the handler's own marker and
  exit code; `tasklist` lists the live processes; `taskkill /f /im` kills a
  background looper and then reports there is nothing left to kill; and
  `jobtool.exe` assigns children to a `KILL_ON_JOB_CLOSE` job, reads the live
  member count back through the job's accounting, and closes the handle to
  reap them.

## CUI-5 Io-completion notes (rename and the file surface's last mile)

The milestone's own deviations (docs/02 CUI-5; the pins live in
`tests/ntapi/sem_file/rename.c` and its siblings).

- **Rename is not atomic on disk** (`fs/fat32/dir.c FatRenameEntry`): the
  new directory entry run is written before the old run is freed (and before
  a target being replaced is deleted, the target's entry goes first), so a
  crash inside the window leaves either the replaced target already gone
  with the source still under its old name, or the file reachable under
  *both* names — never under neither. NTFS journals this; FAT under Art. 3
  (write-through, no journal) cannot, and the fatstress/tornwrite legs'
  fsck oracle bounds the damage to exactly these shapes. Order chosen so
  the file's data chain is never unreachable.
- **The NT FileId changes across a rename** (`fs/fat32/fat.h FatFileId`):
  the id *is* the (directory cluster, SFN slot) identity key, and the entry
  moves. Real Windows on FAT behaves the same way (the id is the entry
  location; only NTFS has stable file ids); the oracle's ext4 backing store
  keeps its inode number instead, so nothing pins id stability either way
  and `sem_file/rename.c` deliberately does not assert it. The live FCB is
  rewritten in place, so one-FCB-per-file, share state, and open handles
  all survive the move.
- **Rename checks no handle access** (`kernel/io/query.c`
  `IopSetRenameInformation`): the pinned Wine's server takes the rename
  handle with zero required access (`server/fd.c set_fd_name_info:
  get_handle_fd_obj(..., 0)`), so a read-only handle can rename. Real NT
  wants DELETE; the oracle is the spec (Art. 6), and every real caller
  (kernelbase `MoveFileWithProgressW`) opens DELETE anyway.
- **`FileLinkInformation` refuses with `STATUS_INVALID_DEVICE_REQUEST`**
  (`kernel/io/query.c`): FAT has no hard links (MS "Hard Links and
  Junctions" — NTFS only; kernelbase surfaces `ERROR_INVALID_FUNCTION`).
  The oracle's ext4 *can* link, so the refusal is pinned `beyond_oracle`
  — the suite's first use of the tag.
- ~~**Directory-change watches deliver one record and do not buffer between
  watches**~~ — **RETIRED by the winetest frontier's W4b** (`docs/21`;
  the pair that convicted it is `kernel32:change`). It was a CUI-5 deviation and
  it is now the oracle's own shape: changes queue on the ARMED HANDLE with or
  without a watch parked, a later arm that finds the queue non-empty completes
  at once, and a completion drains the WHOLE queue into one chained buffer.
  With it went the last of the "assign it once" state (`kernel/io/notify.c`,
  `FILE_OBJECT.notify*`): the subtree flag and "did the first arm pass a
  buffer" are fixed by the first arm exactly as the filter always was.
  Pinned by `sem_file/notify_queue.c`; `kernel32:change` went from 14 failures
  to green on it. Two things the escalation note did not predict:
  - **The queue is what makes a rename reportable at all.** NT owes an
    in-place rename TWO records, `FILE_ACTION_RENAMED_OLD_NAME` chained to
    `FILE_ACTION_RENAMED_NEW_NAME`, in ONE completion. `fs/fat32` reported
    both all along; the one-shot watch consumed the first and dropped the
    second, and a bare OLD_NAME is indistinguishable from a delete. So
    reporting and delivering had to become separate calls, with the batch
    delivered at the end of the VFS operation (`FatReleaseVolumeGate`).
  - **A handle whose FIRST arm passed no buffer can never report data
    again.** The server queues no record at all when `want_data` is clear
    (`server/change.c inotify_do_change_notify`), so every later completion
    is `STATUS_NOTIFY_ENUM_DIR` with Information 0 however large a buffer the
    re-arm supplies. That is the `FindFirstChangeNotification` handle for
    life.
- **`NtCancelSynchronousIoFile` cancels npfs parks only**
  (`kernel/io/async.c IoWaitCancellable`): the Io layer marks every
  potentially-blocking device op, but only npfs's waits (blocking
  read/write/listen, `FSCTL_PIPE_WAIT`) park on the cancellable event.
  The other blocking reads — condrv/serial input, `\Device\Input*` — keep
  their own uncancellable waits; a canceller still finds the op (SUCCESS,
  the mark is set) but the thread wakes only when its device does. Wine
  cancels any server-side async; the gap is unpinned (no baked caller
  cancels a console read) and closes if a consumer ever convicts it.
- **`FileCompletionInformation` (port-to-file association) stays unbuilt**:
  docs/02 widens async I/O only "where a consumer convicts it", and no
  baked CUI binary associates a completion port with a file handle (the
  threadpool drives ports directly via `NtSetIoCompletion`;
  `BindIoCompletionCallback`'s consumers are not baked). The class refuses
  loudly like any other unbuilt `NtSetInformationFile` arm; the day a
  consumer arrives, the packet engine (`IopPostCompletionPacket`) is
  already the single posting authority to hook (Art. 11).

## CUI-6 handles/identity notes (the query surface and Se-2)

The milestone's own deviations (docs/02 CUI-6; the pins live in
`tests/ntapi/sem_ps/times.c` and its siblings).

- **Impersonation attach is real** (`kernel/ps/thread.c`, `kernel/se/token.c`,
  `kernel/ob/handle.c`): a thread carries an impersonation token
  (`ETHREAD.impersonationToken`), attached through
  `NtSetInformationThread(ThreadImpersonationToken)`, preferred by
  `SeCurrentToken` and the `~4`/`~5` magic pseudo-handles, and read back by a
  now-real `NtOpenThreadToken(Ex)`. Retires the CUI-2 "no impersonation
  anywhere" deviation (`sem_se/se_impersonate`).
- **`NtAdjustGroupsToken` and `NtImpersonateAnonymousToken` are built against
  the NT contract, `beyond_oracle`** (the pinned Wine stubs both,
  `dlls/ntdll/unix/security.c`): AdjustGroups refuses to disable an
  `SE_GROUP_MANDATORY` group and resets to default (the fixed identity's
  groups are all mandatory-and-enabled, so no adjust changes state and the
  previous-state buffer truthfully reports zero groups — not a fabrication);
  ImpersonateAnonymous mints an S-1-5-7 impersonation token onto the thread
  slot. `sem_se/se_adjgroups` pins both against MS documentation.
- **`NtSetInformationToken` serves `TokenDefaultDacl` via a side allocation**
  (`kernel/se/token.c`, `kernel/se/se.h`): the one documented exception to the
  token blob's shrink-only rule — a replacement DACL that does not fit the
  inline slot is a separate pool allocation, preferred by the single default-
  DACL accessor and freed by the token delete procedure. `TokenSessionId`/
  `TokenIntegrityLevel` are accepted no-ops, the oracle's own pinned answer.

- **CPU time is whole-tick sampling at 1 ms granularity**
  (`kernel/ke/timer.c KiUpdateClock`): the clock interrupt charges
  `KI_100NS_PER_TICK` to the interrupted thread, kernel or user by the
  interrupted CS — exactly NT's clock-interrupt accounting shape, at the
  1 ms tick instead of NT's ~15.6 ms default. A thread that always yields
  before the tick accrues nothing, as on real NT. `sem_ps/times` asserts
  growth under wall-clock burns, never exact quanta.
- **Foreign `NtGet/SetContextThread` reads a suspended, parked target only**
  (`kernel/ps/usermode.c KiResolveContextTarget`): the sanctioned
  `SuspendThread`+`GetThreadContext` profiler/GC pattern. A target that has
  descended to ring 3 and is off-CPU carries a published trap frame across
  the park (`kernel/init/panic.c` publishes the interrupted ring-3 frame for
  the whole off-CPU window, the way the syscall edge does — a syscall-free
  spinner is otherwise invisible) and its SSE state in `KTHREAD.fxArea`
  (spilled by `KiSwapContext`); those are what the foreign path reads and
  writes. A never-descended or currently-running target has no frame and
  refuses `STATUS_NOT_IMPLEMENTED` (Art. 12) — the debugger consumer that
  would read a running thread is gone with debug objects, and every baked
  caller suspends first. `sem_ps/context_foreign` pins the read-back, the Rip
  redirect and the XMM round-trip.

## CUI-7 Cm-2/Mm-2/system notes (hive attach, write-watch, the furniture)

The milestone's own deviations (docs/02 CUI-7; the pins live in
`tests/ntapi/sem_reg/{rename,notify,save_load,restore_setinfo}.c`,
`sem_mm/{alloc_ex,map_ex,write_watch,flush_lock}.c` and
`sem_ps/{locale,set_time,shutdown}.c`). The buildable id surface is complete:
202/264, every remaining `KI_SYSCALL_MISSING` row an out-of-scope decision
(`docs/16`).

- **`NtSaveKey` writes a PHV1 subtree image** (`kernel/cm/hive.c`
  `CmpSerializeSubtree` — the M8 "our own on-disk format" deviation extended to
  explicit saves; wineserver writes its text format there). Round-trips are pinned
  semantically (save → load → query equality), never by file bytes; `tests/run/regdump.py`
  parses both formats.
- **A loaded hive is a volatile graft** (`NtLoadKey{,2,Ex}`): the mount never persists —
  NT's own contract for loaded hives, and `CmpSaveHive`'s skip-volatile rule prunes it —
  while the parsed CONTENT keys are ordinary, so an explicit `NtSaveKey` of the loaded
  root round-trips. Observable cost: a non-volatile subkey created directly under a
  loaded root answers `STATUS_CHILD_MUST_BE_VOLATILE` where the oracle (whose loaded
  keys are ordinary keys) allows it — the arm is deliberately not exercised.
- **The load family reproduces the server's dropped destination attributes**: loading
  onto an existing key is `STATUS_OBJECT_NAME_COLLISION` (the ntdll-forced `OBJ_OPENIF`
  never reaches wineserver's `create_key`) and a failed parse leaves the just-created
  destination behind, empty — both pinned. Destinations are only exercised
  RootDirectory-relative (the one shape kernelbase issues; the oracle's absolute form
  falls over its own case-sensitive root lookup, a server quirk left unpinned — proskrnl
  resolves absolute destinations through the one `CmpResolvePath` authority and simply
  works, an unexercised superset). The `NtLoadKeyEx` extras
  (flags/trustkey/event/access/roothandle/iostatus) are accepted-and-ignored, the pinned
  oracle FIXME shape.
- **Notify records are keyed by the arming OPEN** (`kernel/cm/notify.c`: one
  `CM_KEY_BODY` per open ≈ wineserver's (process, hkey) key). A `NtDuplicateHandle`d key
  handle shares its body and therefore its record — the record dies at the LAST close of
  that body's handles where wineserver's dies per handle; untested, unobserved by any
  consumer. The `count`/`attr`/`apc`/`buffer` arguments are accepted-and-ignored and the
  IOSB is never written (the pinned oracle shape); the sync form blocks kernel-side on an
  internal event where ntdll emulates it PE-side — observably identical.
- **`NtRestoreKey` refuses open handles anywhere below the target** with
  `STATUS_CANNOT_DELETE` (the MS docs are silent; wineserver's unload shape is the
  model), and nonzero flags with `STATUS_INVALID_PARAMETER` (`REG_FORCE_RESTORE` etc.
  stay unbuilt). **`NtReplaceKey`'s refusal is total**: after the `SeRestorePrivilege`
  gate every key answers the documented not-a-hive-root `STATUS_INVALID_PARAMETER` —
  proskrnl has no replaceable file-backed hive roots (one SYSTEM image + volatile
  grafts). `KEY_SET_INFORMATION_CLASS` is hand-typed in `kernel/cm/registry.c` with its
  wdm.h citation (the pinned Wine tree has no trace of it); only
  `KeyWriteTimeInformation` is served.
- **Placeholders are built on the ALLOCATION surface and still unbuilt on the SECTION
  one.** `NtAllocateVirtualMemoryEx`'s `MEM_RESERVE_PLACEHOLDER`/`MEM_REPLACE_PLACEHOLDER`
  and `NtFreeVirtualMemory`'s `MEM_PRESERVE_PLACEHOLDER`/`MEM_COALESCE_PLACEHOLDERS`
  are implemented and pinned (`tests/ntapi/sem_mm/placeholder.c`; `docs/21` W5). A VAD
  carries the oracle's own two bits — `MI_VAD_PLACEHOLDER` says the range is in the
  protocol, `MI_VAD_FREE_PLACEHOLDER` says it is an empty placeholder right now — and
  nothing else can tell a placeholder from a `PAGE_NOACCESS` reservation, because they
  report identically through `MEMORY_BASIC_INFORMATION`. `MEM_REPLACE_PLACEHOLDER` in
  `NtMapViewOfSectionEx` and `MEM_PRESERVE_PLACEHOLDER` in `NtUnmapViewOfSectionEx`
  still refuse loudly with `STATUS_NOT_IMPLEMENTED` (Art. 12; the `SEC_RESERVE`
  precedent): mapping a section INTO a placeholder is a second, larger contract and no
  baked consumer reaches it. `NtCreateSectionEx`'s parameter array is
  accepted-and-ignored (the pinned oracle FIXME shape).
- **`MemoryImageInformation` reports signing level ZERO where the oracle reports 12**
  (`kernel/mm/virtual.c` `MiQueryVirtualMemoryImage`, `docs/21` W5; pinned
  `tests/ntapi/sem_mm/image_info.c`). The pinned Wine writes
  `info->ImageSigningLevel = 12` for every image view unconditionally
  (`dlls/ntdll/unix/virtual.c` `get_memory_image_info`); proskrnl leaves the field at 0
  because nothing on this system validates an image signature, and 12 would be a claim
  about a check that never ran (Art. 12 — the same rule that forbids a plausible status
  from a stub). This is not a divergence from the BOUNDARY: the winetest accepts either
  value at every one of its five image queries
  (`ok( info.ImageSigningLevel == 0 || info.ImageSigningLevel == 12, ...)`,
  `dlls/ntdll/tests/virtual.c` `test_query_image_information`), so NT itself reports 0
  for an image it has not checked. The pin therefore asserts the pair rather than one
  value, and says so.
  Two more of the class's rules are the oracle's and are easy to get backwards, so they
  are recorded here as well as in the code: a MAPPED-but-not-image address (a private
  allocation, a data view, a pagefile view) is a **SUCCESS with an all-zero struct**
  rather than a refusal; and the struct is **zeroed before the lookup**, so the caller's
  buffer comes back zeroed even on the `STATUS_INVALID_ADDRESS` refusal — the exact
  opposite of `MemoryRegionInformation`, which leaves the buffer untouched on its.
  `ImagePartialMap` stays clear because `MipMapImageView` maps the whole
  `SizeOfImage` whatever view size was asked for, so no view this kernel can produce is
  partial. Be precise about WHY that is not itself a dropped input: the image path
  accepting and ignoring the requested view size is a real gap, it is **shared with the
  pinned oracle** (the winetest wraps both the `size == 0x4000` and the
  `ImagePartialMap` assertions in `todo_wine`), and it is unbuilt on both sides rather
  than impossible. So `ImagePartialMap` = 0 is an accurate report of the views that
  exist, not a bit nobody computed — and when partial image views are built, this bit is
  part of that item.
- **`MEM_EXTENDED_PARAMETER_EC_CODE` is the one attribute bit that refuses, and the
  refusal belongs to the ALLOCATION engine.** Every other bit of the
  `MemExtendedParameterAttributeFlags` word is accepted and dropped;
  `MEM_EXTENDED_PARAMETER_EC_CODE` asks for ARM64EC code memory and answers
  `STATUS_INVALID_PARAMETER`, which is the oracle's guard with its left half
  permanently true on an x86_64-only kernel (`if (!arm64ec_view && (attributes &
  MEM_EXTENDED_PARAMETER_EC_CODE))`, `dlls/ntdll/unix/virtual.c`
  `allocate_virtual_memory`; `docs/adr/0006-x64-only.md`). It sits in
  `MiAllocateVirtualMemoryEx` below the working-set and type-flag tests — NOT in the
  shared `MiCaptureExtendedParams` parser — because `NtMapViewOfSectionEx` takes the
  same word and ignores it; both halves and the ordering are pinned
  (`sem_mm/alloc_ex.c`, `sem_mm/map_ex.c`). **The bit is a probe, not a preference**:
  `ntdll:unwind`'s `test_virtual_unwind_arm64` calls this to ask whether it is on an
  ARM64EC host and, on a "yes", runs ARM64 unwind opcodes over the x86_64 buffer it
  just received. Accepting and dropping the bit therefore did not return a wrong
  answer — it killed the process with an unhandled `0xc0000005` (`docs/21` W6).
- **`MemExtendedParameterImageMachine` belongs to the mapping engine's IMAGE arm, and
  it is the mirror image of the bullet above.** A non-zero value that the PE header does
  not declare is `STATUS_NOT_SUPPORTED` (the oracle's **`map_image_into_view`**,
  `dlls/ntdll/unix/virtual.c`: `if (machine && machine != nt->FileHeader.Machine)` — a
  different function from the `map_image_view` cited below for the image arm's floor);
  zero is "no constraint", not "the machine must be zero". `MiCaptureExtendedParams`
  carries the word out and `MipMapImageView` acts on it — NOT the parser, because a
  **data** view takes the same word and ignores it, so a guard one level up would refuse
  a mapping the oracle admits. Its POSITION is pinned as well as its status:
  `virtual_map_image` places the view with `map_image_view` and only then calls
  `map_image_into_view`, whose machine check is its last act before the relocation — so a
  view that cannot be **placed** under the requested limits reports the placement failure
  and never reaches the machine comparison, i.e. an impossible ceiling plus a wrong
  machine is `STATUS_NO_MEMORY`, not `STATUS_NOT_SUPPORTED`. It holds for a **remote**
  target too, which is the configuration the winetest uses and which on the oracle sends
  the word to the target as an APC (`call.map_view_ex.machine`). All of it pinned by
  `tests/ntapi/sem_mm/map_image_machine.c`; `docs/21` W5 has the item.
- **`zero_bits` binds `NtMapViewOfSection` differently from
  `NtAllocateVirtualMemory`, in three ways, and only the first is the obvious one**
  (`kernel/mm/section.c`, `docs/21` W5; pinned `tests/ntapi/sem_mm/map_zero_bits.c`).
  Both syscalls read the argument through the oracle's one definition
  (`get_zero_bits_limit`, `dlls/ntdll/unix/unix_private.h`) and proskrnl through one
  `MiZeroBitsLimit`, and the resulting ceiling rides the same `limitHigh` the
  `MEM_ADDRESS_REQUIREMENTS` path already uses — one bounded-placement mechanism, not
  two (Art. 11). What differs:
  (1) the invalid band here is **22..31 only**, so `33` is a legal mask whose ceiling
  is 63 bytes and the answer is `STATUS_NO_MEMORY`, where the allocation path refuses
  `33` outright with `STATUS_INVALID_PARAMETER_3`;
  (2) the refusal names argument **four**, not three;
  (3) a **named base does not drop the constraint**. `NtAllocateVirtualMemory` drops
  it (`if (!*ret) limit = get_zero_bits_limit( zero_bits ); else limit = 0;`);
  `NtMapViewOfSection` passes it down unconditionally
  (`virtual_map_section( handle, addr_ptr, 0, get_zero_bits_limit( zero_bits ), … )`),
  so `map_view` tests the view's whole EXTENT against it and a view based under the
  ceiling but ending above it is `STATUS_CONFLICTING_ADDRESSES`. That extent test is
  `is_beyond_limit( base, size, limit_high )` — `base + size > limit_high` — while the
  free-range SEARCH beside it treats the same `limit_high` as inclusive
  (`end = limit_high + 1`), so a named view whose last byte is exactly the ceiling is
  one byte too long. `MiRangeWithinLimits` transcribes that asymmetry rather than
  tidying it; the pin measures it, because either convention is defensible and only the
  measurement says which one NT picked.
  The limits reach the IMAGE path too (`MipMapImageView` takes them: the preferred
  base is only taken when it fits, everything else is the bounded search) — before
  this they were dropped there, which also silently dropped
  `NtMapViewOfSectionEx`'s `MEM_ADDRESS_REQUIREMENTS` for an image section. **The
  image arm answers one case differently from the data arm**, and it is measured, not
  a simplification: `map_image_view` raises `limit_low` to `address_space_start`
  ("make sure the DOS area remains free") before anything else, and `map_view` then
  refuses `limit_low >= limit_high` outright — so a ceiling below 64 KiB is
  `STATUS_INVALID_PARAMETER` for an image view where the data arm, which passes
  `limit_low` 0, lets the same ceiling reach its search and answers
  `STATUS_NO_MEMORY`. (The floor is the image arm's; the refusal that follows from it
  is `map_view`'s, i.e. shared, so it is stated once in `MiMapViewOfSectionEx` above
  the arm split.) One thing the oracle does that proskrnl does not, recorded so nobody
  reads the code as a transcription of it: the oracle's image path **ignores a
  caller-supplied address entirely** (`virtual_map_section` hands `addr_ptr` to it as
  an out-parameter only), while proskrnl honours one. That predates this change, and
  the limits are now applied to that arm as well — for consistency with the data
  path's named base, since no oracle run can measure an arm the oracle does not have.
- **Splitting a VAD carries its write-watch record.** One split serves both
  `MEM_RELEASE` and `MEM_PRESERVE_PLACEHOLDER` (`MiCarveVad`, Art. 11). The release
  path's own earlier copy of it rebuilt the surviving pieces without `watchDirty`, so a
  `MEM_WRITE_WATCH` reservation that was partially released stopped being watched —
  unobserved by any suite, and fixed rather than reproduced when the second caller made
  the duplication visible.
- **Write-watch is fault-driven with the dirty array authoritative**
  (`kernel/mm/virtual.c` `MI_VAD.watchDirty`; the PTE writable bit is only the trap —
  `docs/17` §6.B's rule applied). Kernel writes mark through the same
  `MiResolveWriteWatchFault` authority at the probe chokepoint (`KiProbeForWrite`) and
  the cross-process checked copy — which means a service that probes a watched buffer
  for write and then fails before writing has still marked it (the oracle marks only on
  the actual store; unobserved by the pinned suites, recorded here).
  `NtGetWriteWatch`/`NtResetWriteWatch` operate on the CALLER's address space whatever
  the process handle says, as the oracle's implementations do.
- **`NtLock/UnlockVirtualMemory` validate and do nothing**: everything is resident
  (Art. 3 — no eviction), so a committed, accessible range answers `STATUS_SUCCESS` with
  the oracle's rounding echo and reserved-only/unmapped ranges answer
  `STATUS_ACCESS_DENIED` (the oracle's mlock cannot populate `PROT_NONE`).
  `VmPrefetchInformation` likewise validates its ladder and succeeds without work.
- **The locale slots are kernel state seeded from the registry** (`kernel/ps/nls.c`:
  HKLM `...\Control\Nls\Language` "Default", HKCU `Control Panel\International`
  "Locale", 0x0409 fallback) where the oracle seeds from the host locale; the setters
  are in-memory only on both sides (nothing writes back to the registry).
- **A privileged `NtSetSystemTime` does not re-evaluate armed absolute timers**: their
  due points were fixed against the interrupt clock at arm time (`KiComputeDueTime`) and
  stand; NT re-signals absolute timers on a clock change. No baked consumer observes it;
  the NT-faithful exit is an absolute flag on KTIMER plus a re-insert walk, deliberately
  unbuilt (`docs/12` names ke/wait as a danger zone). The set writes the CMOS back
  (`arch/x86_64/rtc.c` `KiWriteRtcTime`), so it survives a reboot.
- **`NtSetSystemInformation` refuses unknown classes with
  `STATUS_INVALID_INFO_CLASS`** where the oracle FIXME-succeeds for every class (G12: a
  blanket success is a fabricated answer); the one served class
  (`SystemTimeAdjustmentInformation`) stores its pair, and the query side reflects the
  STORED state after a set where the oracle's answer is fixed — pinned pre-set, where
  the two coincide. `NtShutdownSystem`'s live arms ride the existing `KiQemuExit`
  convention and the 8042 reset pulse; the refusal arms are the ntapi pins, the live
  arms the `tests/run/run.sh cui7` leg.

## CUI-8 async notes

- **Asynchronous disk handles answer the pending shape over an inline completion**
  (`kernel/io/rw.c` `IopAsyncReturnShape`) — a pin, not a deviation, recorded here
  because the §7 decision run reversed the plan's guess: the oracle returns
  `STATUS_PENDING` with the IOSB already final, the event already set and the APC
  queued (wine `dlls/ntdll/unix/file.c`; reads convert `SUCCESS` and `END_OF_FILE`,
  writes only `SUCCESS`; refusals that never wrote the IOSB stay inline). Pinned by
  `sem_file/async_inline.c` hot and cold, and continuously by the fuzzer's
  `read_file_async` collect-at-call op, whose trace diverges on the issuing line if
  either side ever genuinely pends.
- **Cancellation scope after the §9.9 widening** (`kernel/io/async.c`,
  `fs/fat32/file.c`, `kernel/io/rw.c`): `NtCancelSynchronousIoFile` now reaches the
  fat32 data park — the fill and the extension's zero-fill stop issuing on a landed
  cancel, await what is out (docs/20 R4), and answer `STATUS_CANCELLED` with the
  IOSB untouched (a cancelled extension is unwound, so the volume is exactly as it
  was). A write's cancel point is BEFORE its cache mutation: from `MiCacheWrite` on,
  the cache write and its writeback are one too-late-to-cancel durability unit —
  honoring a cancel there left the cache and the disk permanently disagreeing, with
  no dirty tracking to reconcile them (PR #95 review). Still outside the verb:
  `NtFlushBuffersFile` and the section-writeback path (`IoWritebackSectionRange`) run
  unmarked — no baked caller cancels a flush — and condrv/serial/`\Device\Input*`
  keep their CUI-5 uncancellable waits. Escalation: mark the flush spans when a
  consumer convicts them.
- **Cross-thread device overlap on the one volume serializes at the FS** (the
  `FAT_VOLUME` gate, docs/20 R1): two threads' file operations never interleave
  inside the volume's structures — the depth the `[KTEST]` verdict measures comes
  from one gated operation's batched pages (up to `VIO_BLK_MAX_INFLIGHT` in flight),
  while the other thread overlaps as computation or parks. Machine-internal (latency
  only, no boundary edge); escalation is `docs/18`'s locking split, whose first
  consumer would be a second volume or Net-1's independent device.
- **The synchronous-handle file-object lock covers the seekable data leg only**
  (`kernel/io/rw.c` `syncIoLock`): NT's `IopLockFileObject` serializes ALL I/O on a
  synchronous handle, pipes and devices included; here the stream-device path
  (npfs/condrv/serial, the `ops->Read`/`ops->Write` branch) takes no lock, so two
  threads' blocking reads on one synchronous pipe handle can interleave where NT
  would run them one at a time. Deliberate scoping (PR #95 review round 2, F6): the
  lock exists for the observable offset races `sem_file/shared_handle_offset.c`
  pins, streams have no offset, and no baked caller multi-threads one synchronous
  pipe handle. Escalation: widen the lock to the stream branch when a consumer (or
  an oracle pin on pipe-read atomicity) convicts the interleaving.

- **A pended IOCTL/FSCTL posts its completion packet, unconditionally**
  (`kernel/io/async.c` `IopCompletePendingRequest` through `kernel/io/rw.c`
  `IopPostRequestPacket`) — a pin, not a deviation, recorded because the rule
  reads backwards from the flag's name. The oracle's guards are
  `req->async || !(comp_flags & SKIP…)` (wine `server/fd.c` `add_fd_completion`)
  and `async->pending || !NT_ERROR(status)` (`server/async.c`
  `async_set_result`), so pendedness alone satisfies both: neither
  `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` nor a failing status withholds the
  packet, and a CANCELLED listen posts its cancel. A caller holding
  `ERROR_IO_PENDING` has nothing else to wait on, so either omission hangs
  `GetQueuedCompletionStatus` forever. Pinned by
  `sem_pipe/pending_packet.c`; the inline half is `sem_pipe/completion_packet.c`.
  The port is read off the FILE_OBJECT at completion rather than captured at
  issue, because the oracle re-reads (`add_async_completion`'s
  `if (async->fd && !async->completion)`) — measured: binding a port AFTER an
  async listen has pended still posts. That is why `IOP_PENDING_REQUEST` holds a
  REFERENCED file object, which also makes "a parked request cannot outlive its
  file object" structural rather than a per-filesystem convention.
  **Scoped to that tail, deliberately:** the OTHER thing that pends here,
  `NtNotifyChangeDirectoryFile`, still posts no packet — `IopCompleteDirWatch`
  (`kernel/io/notify.c`) writes the buffer and IOSB, signals, queues the APC
  and stops, and `IOP_DIR_WATCH` carries no `ApcContext` to post as a value.
  So `ReadDirectoryChangesW` on a port-bound directory handle hangs
  `GetQueuedCompletionStatus` for exactly the reason above. Neither
  `ntdll:change` nor `kernel32:change` convicts it (both green), so it is an
  unpinned gap rather than a measured divergence — issue #135, and the fix is
  the same one-line route through `IopPostRequestPacket` once a pin has
  measured what an ERROR or CANCELLED watch completion owes.
- **npfs data reads and writes never pend: on an asynchronous handle they
  BLOCK the caller** (`fs/npfs/pipe.c` `NpfsRead`/`NpfsWrite`, which park in
  `NpfsWait` whenever the queue cannot serve them). NT and the oracle answer
  `STATUS_PENDING` with the IOSB untouched and complete the request later.
  Measured on both runners with the same binary: an `NtReadFile` on an empty
  pipe through an overlapped handle returns `0x103` immediately on the oracle
  and does not return at all on proskrnl. Only `FSCTL_PIPE_LISTEN` pends here
  (`kernel/io/async.c`), which is why this went unrecorded for so long — the
  listen was the one verb a baked caller drove asynchronously.
  **Consequence, measured:** it is what wedges `ntdll:pipe`. `pipe.c:1578`
  issues the overlapped read and then satisfies it from the SAME thread at
  `:1583`, so the thread parks inside the read and the write it is waiting for
  is never issued. Escalation: grow the pending-request engine with the
  buffer/length legs `kernel/io/io.h` already anticipates and give the stream
  devices a pended data path (`docs/19`; `docs/21` W4c).
- **The differential fuzzer convicts the contract, not the in-flight window**
  (docs/19 §8.3.3, recorded honestly): proskrnl's internal in-flight state has no
  oracle counterpart under the inline pin, so the traces cannot see it — the kmt
  `CUI8` suite (deterministic via the await-spin knob), `file_coherence_mt`, and the
  `cui8` leg's park-on-every-await stress boot are its conviction instead. The
  npfs async listen remains the one surface where issue-now/collect-later pends on
  both runners, and `sem_pipe/async_listen.c` guards it.

## CUI-9 COW notes (shared image masters)

### The Article 3 amendment: "no COW", lifted for SEC_IMAGE only

Article 3's "no copy-on-write" mandate is lifted for **image sections only**, on the
measurement docs/09 "Lifting a mandate" requires (docs/17 §2; numbers recorded in
docs/17 §1): at the pinned `MEM=512M` `cui9` boot, eager per-process image copies cost
**≈ 5.9 MB per resident process** — the mapped private copies *plus* each section's
raw-byte pool snapshot — and the machine **refuses at 70 resident processes**. The
refusal ring 3 observes is the spawned child dying mid-load with
`STATUS_DLL_NOT_FOUND` (0xC0000135), the loader's dressing of the image-map
`STATUS_NO_MEMORY`. A ceiling a user program can observe is a semantic, not a
performance concern — the only justification Article 3 accepts. Process-creation
latency (a full memcpy + relocation pass of every DLL per spawn) is the secondary
effect, deliberately not the argument.

**Landed, and the ceiling moved** (docs/02's "done when": the §2 measurement re-run):
70 → 143 with the masters alone, → 302 with the raw-snapshot release, → **319** with the
lazy COW arm (per-process cost 5965 → 1500 KB), the refusal now the plain
`ERROR_NOT_ENOUGH_MEMORY` dressing of `STATUS_NO_MEMORY`. The `cui9` leg ratchets a
committed floor of 250 (`tests/cui/mmceiling_floor.txt`).

What the amendment admits, in docs/17 §4's two instalments:

1. **A shared, already-relocated master per file** — `MI_IMAGE_MASTER` in
   `kernel/mm/section.c`, keyed on the `IO_FCB` (boot modules: the ramdisk file),
   holding relocated frames that every view of that image maps. The read-only bulk
   of a DLL (`.text`, `.rdata`, headers) shares outright; relocation happens **once
   per file**, into the master. (It was once per `(file, base)`; see "An image
   section is relocated once" below for why the base left the key.)
2. **The COW arm** on the one write-fault authority (`MiResolveWriteFault` — the CUI-7
   write-watch resolver, extended, never forked): writable PE sections map the
   master's frames hardware-read-only, and the first store — a ring-3 fault,
   `NtWriteVirtualMemory`, or a syscall out-buffer probe — allocates a private frame,
   copies, and repoints that page.

**Scope.** Lazy COW is image-only. File-backed data `PAGE_WRITECOPY` views keep their
M5 shape — an eager private full copy at map time, pinned oracle-green by
`sem_mm/section_protect` — because data sections map the file's cache, where
mapped-view/`ReadFile` coherence lives (docs/17 §5; that section's earlier "refuses
loudly" wording described a world the tree never shipped — the eager copy is a legal,
pinned implementation of writecopy's observable contract, not a stub). Anonymous
sections need no COW: there is no fork, so no second mapper to diverge from. Either
implementation — eager copy or master + COW — satisfies the same observable contract,
pinned by `sem_mm/writecopy_image` and `sem_mm/writecopy_query`.

### Hazard D, decided: there is no observable transition

Real NT reports a written writecopy page as `PAGE_(EXECUTE_)READWRITE` afterwards and
splits the region around it. **The pinned oracle does not**: Wine realizes writecopy
silently through `MAP_PRIVATE` + `PROT_WRITE` (`dlls/ntdll/unix/virtual.c`), so the
store never reaches it and `NtQueryVirtualMemory` / `NtProtectVirtualMemory` keep
answering the WRITECOPY flavour. Diverging toward NT would turn a green pair red
(Art. 6), so proskrnl pins the oracle's no-transition shape
(`sem_mm/writecopy_query`): the kernel's COW copy leaves the recorded per-page
protection untouched — the shared/private state lives in the VAD's per-page frame
ownership record, never in the reported protection. Two adjacent shapes pinned with
it: `NtProtectVirtualMemory` accepts the WRITECOPY flavours on mapped views and
refuses them on private memory (the oracle's `set_protection` rule), and on an image
view `PAGE_READWRITE` canonicalizes to `PAGE_WRITECOPY` (the oracle's
`get_vprot_flags` with image=TRUE), which a following query reports. A third shape, pinned by `sem_mm/protect_shared_view`
(written after the PR-108 review raised it, and it reversed the intended fix): on a
*shared* view — `ownsFrames` FALSE, PTEs aimed straight at the section's / file
cache's frames, no master and no per-page copy record — the oracle **grants** the
WRITECOPY flavours and realizes them as a plain writable shared mapping. It
`mprotect`s the existing `MAP_SHARED` region rather than remapping it `MAP_PRIVATE`,
so no copy ever happens: the store is visible through every other view of the section
and reaches the backing **file**. Real NT would privatize the page. proskrnl pins the
oracle's shape for the same Art. 6 reason hazard D is pinned — and it is the answer
this kernel already gives, since a shared view's stores land in the file's page cache
under immediate writeback. Refusing writecopy there (the review's suggested fix, and
this PR's first attempt at it) is a divergence from the spec wearing a fix's clothes.

What the oracle *does* refuse on that same view is the **plain-writable** flavours
when the backing handle lacks write access, with `STATUS_INVALID_PAGE_PROTECTION` —
so `MiProtectVirtualMemory` applies the map-time `backingWritable` gate at protect
time too. That closes the one genuine hole in the report: map `PAGE_READONLY` over a
read-only handle, protect `PAGE_READWRITE`, and you wrote a file you could not open
for writing. The asymmetry (writecopy granted on that same read-only-handle view,
read-write refused) is the oracle's own, pinned as case D. One unpinned addition,
recorded here: a body-less shared VAD — the kernel-owned `KUSER_SHARED_DATA` frame —
refuses the writable protections too, since the oracle has no equivalent object and
ring 3 making a kernel-shared frame writable is not a boundary behavior worth
reproducing.

### Hazard F, decided: the share-mode gate, and its recorded residual

The file changing under a live master is closed on the share-mode side, as docs/17
§6F prescribes: while any image section or view of a file is alive, an open asking
write access answers `STATUS_SHARING_VIOLATION` (pinned oracle-green by
`sem_mm/image_deny_write`; the oracle's mapping fd enforces the same). Residual,
recorded honestly: a *pre-existing* writable handle can still `NtWriteFile` the file
while a master lives — real NT refuses that write through `MmFlushImageSection`, the
oracle permits it, and no baked consumer does it. **The gate's scope has since been
measured rather than reasoned about, and it moved in both directions** — see "What a
live SECTION holds against a later OPEN" below, which is now the statement of record:
the write bit is `FILE_WRITE_DATA` *alone* (this paragraph used to say
`FILE_WRITE_DATA | FILE_APPEND_DATA`, and the oracle refuted it), while the delete
side — which this paragraph recorded as a visible gap — is closed for the
`FILE_DELETE_ON_CLOSE` spelling. What survives of the gap is narrower: a plain
`DELETE`-access open of a live image, later followed by a disposition set, is
permitted here exactly as the pinned oracle permits it. The same staleness already exists
per-section today: the raw-byte snapshot is taken at `NtCreateSection`, so a write
between create and map is invisible to the view. Masters widen the window across
sections without changing its class; the gate closes the only path a real caller
takes.

### An image section is relocated once, and every view shares that copy

**docs/17 §6F said to put the mapped base in the master's key** — "a different base
means different relocation fixups… omitting it lets a process at base X read pages
relocated for base Y, a silent, non-local corruption, the worst bug available in this
design". Measured against the pinned oracle, the premise is wrong, and Art. 6
arbitrates: **the oracle relocates an image ONCE per mapping and hands every view the
same bytes**, whatever address the view lands at. The delta it uses is the mapping's
own dynamic base and not the view's placement (`dlls/ntdll/unix/virtual.c`
`map_image_into_view`: `delta = image_info->map_addr - image_info->base`), and the
server states the same thing when it decides at-base-ness (`server/mapping.c`
`DECL_HANDLER(map_image_view)`: `view->base != (map_addr ? map_addr : base) +
offset`). `sem_mm/map_image_offset.c` memcmps two views of one section, in-process and
in a child, and they are byte-identical on the oracle.

What §6F got right is one step over, and it is what makes the arrangement safe: **the
copy's stamped `ImageBase` must name the base the copy was relocated for.** ntdll's
PE-side loader keys `perform_relocations` off exactly that field
(`dlls/ntdll/loader.c`: `if (module == base) return STATUS_SUCCESS;`), so a view that
does *not* sit at the copy's base has its residual fixed up privately, through the COW
arm, by the layer that owns loading. A stamp disagreeing with the relocation base is
the corruption §6F named; the base being absent from the key is not. `MI_IMAGE_MASTER`
keeps `base` as *what the copy was relocated for* rather than as key material.
`tests/kmt/m5_section.c` `test_image_relocation` convicts the stamp, and it has to
hold the preferred base to do it: a copy built AT the preferred base is relocated by
zero, so the file already holds the right value and the assertion cannot fail. Every
other stamp assertion in the tree (`cui9_cow.c`, `abi_probe.c`) is that vacuous case
and is there for the frames-shared half instead.

**`STATUS_IMAGE_NOT_AT_BASE` moved with it, and the two dynamic bases are not the
same quantity.** "At base" is now measured against the image's dynamic base — the
copy's base once one exists, else the PE's preferred base, since proskrnl assigns no
other — which is the *shape* of the server's test (`server/mapping.c`
`DECL_HANDLER(map_image_view)`), not the same value. The server's `map_addr` is per
MAPPING OBJECT and is assigned **only** for a `SEC_IMAGE` mapping whose image carries
`IMAGE_FLAGS_ImageDynamicallyRelocated` (`server/mapping.c`
`DECL_HANDLER(get_image_map_address)`); proskrnl's is per FCB and exists for any image
whose first view was rebased. So an image *without* that flag — an ordinary EXE — can
separate them: rebase its first view, then map it again somewhere its first base is
free, and proskrnl answers `STATUS_SUCCESS` where the oracle measures against the PE's
preferred base and answers `STATUS_IMAGE_NOT_AT_BASE`. Recorded, not pinned: nothing
in the baked stack or the winetest gate maps an EXE section twice, and closing it is a
change to which images get a dynamic base — an item of its own, not a line here.

Two consequences worth stating:

- **A second view at a different base is now free** rather than a whole second copy —
  the sharing the amendment exists for, extended to the case that previously defeated
  it.
- **`ntdll:virtual:2244` was a false skip.** The pair's `test_syscall_patching` maps
  the running module afresh and `memcmp`s the first page against the loaded copy; with
  a per-base master the two headers differed, so it `skip`ped its whole body. The body
  passes (five assertions, 2200 → 2205 executed), and the test then calls
  `perform_relocations( ptr, delta )` itself — user mode fixing up exactly the residual
  described above, which is the shape confirmed rather than assumed.

### Page tables are CHARGED, because committing a page cannot fail

`MiMapUserPage` is infallible by contract — a committed page always gets its PTE —
and the intermediate page TABLES were the one allocation inside that promise which
could fail. `MiEnsureTable` panicked on it, so a ring-3 program that simply ran the
machine out of memory could bring the kernel down instead of getting
`STATUS_NO_MEMORY`. The commit sites that *can* refuse now charge the tables first
(`MiChargeUserTables`, `arch/x86_64/mmu.c`; called by `MiCreateMappedVad` for a view
and `MiCommitPages` for private memory), which is also what makes the remaining panic
honest: past the charge, an absent table is a bug and not a shortage. Tables created
before a failed charge stay — they are empty, cost one page each, and
`MiDeleteUserPml4` frees the whole user tree at teardown.

**It was the shared-copy change above that made this reachable, and the way it did is
the part worth keeping.** Sharing one relocated copy across bases lowered the
per-process cost slightly, so the `cui9` ceiling rose 317 → **319** — and the create
that then failed lost its race at a page table rather than at a frame allocation the
loader reports. Same shortage, different site, kernel panic instead of
`ERROR_NOT_ENOUGH_MEMORY`. **Which allocation loses at the ceiling was never something
to rely on**: the graceful refusal was one arbitrary ordering away from a panic for as
long as any commit path could fail unreportably.

### `NtMapViewOfSection`'s offset maps an image's TAIL

A non-zero offset into a `SEC_IMAGE` section used to answer
`STATUS_INVALID_PARAMETER` (`image subrange views: not M5`). It is now the oracle's
rule: the view is `base + offset` with size `SizeOfImage - offset`, and the trimmed
head is **free**, not a reserved stub. The oracle reaches that by mapping the whole
image and then removing the front of the view (`virtual_map_image`: `if (offset) {
free_pages( view, view->base, offset ); size -= offset; }`); `MipMapImageView` creates
the VAD over the tail directly, which is the same extent without mapping pages only to
unmap them. Three things around it, all pinned by `sem_mm/map_image_offset.c`:

- **`offset >= SizeOfImage` is `STATUS_INVALID_PARAMETER`**, and it is the *first*
  thing the oracle's image path does — above the fd, above placement. The highest
  legal offset is therefore the last 64K granule strictly inside the image, which
  still maps.
- **The whole image is what gets PLACED**, and the view is the tail of it. So a
  ceiling, a `zero_bits` limit or a caller-named base bounds `SizeOfImage`, not
  `SizeOfImage - offset`.
- **The trim does not make the view a different image.** The master's frames are
  indexed by image RVA and the VAD's pages by view offset; `MipVadMasterIndex`
  (`kernel/mm/virtual.c`) is the one place the two are related, so the COW arm and
  docs/17 §8's shared-PTE sweep read the same frame the commit path mapped.

### Hazard I (KASAN): vacuous by scope

The tree's KASAN is pool-only (`kernel/mm/kasan.h`); COW's fresh frames are whole
pages written through the HHDM, outside the shadow. Recorded so docs/17 §6's
checklist item is visibly discharged rather than silently dropped.

## Debug objects are out of scope (permanent; ADR 0011)

The `NtCreateDebugObject` family — `NtDebugActiveProcess`, `NtDebugContinue`,
`NtRemoveProcessDebug`, `NtWaitForDebugEvent`, `NtSetInformationDebugObject` — was
CUI-4's stretch goal; it was not taken, and it is now ruled **permanently out of
scope** rather than deferred (the fixed decision: `docs/adr/0011-no-debug-objects.md`;
this entry is its expanded reasoning):

- **No baked consumer (Art. 1).** The entire family sits behind ntdll's on-demand
  `DbgUi*` entry points (`dlls/ntdll/process.c`) and the
  `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS` flags in kernelbase's `CreateProcess`
  path — nothing in the baked CUI stack reaches them at startup or on any normal
  path. A debugger is a development tool, not an app the boundary exists to run.
- **Symbol-toolchain impedance mismatch.** proskrnl's own toolchain is
  clang/LLD/DWARF end-to-end (`tools/symbolize.py`, the panic-path stack traces);
  the native Windows debugging ecosystem a debug-object surface would invite
  (windbg et al.) expects PDB symbol flow that nothing here produces. Supporting
  the syscalls without the toolchain they exist to serve would be surface without
  a consumer.
- **What is lost, concretely:** `DebugActiveProcess`/`WaitForDebugEvent`-style
  debugger attach, and `CreateProcess` with `DEBUG_PROCESS`. Both fail loudly
  (`KI_SYSCALL_MISSING` on serial + `STATUS_NOT_IMPLEMENTED`, Art. 12) — never
  silently. Debugging *of* proskrnl user processes remains what it is today:
  the panic dump, serial tracing, and the differential suites (Art. 6/9).
- **Also out with them:** the kernel-debug control pair
  (`NtSystemDebugControl`, `NtSetDebugFilterState`). Foreign-thread
  `NtGet/SetContextThread` is NOT out — it stays on the CUI-6 plan for the
  `SuspendThread`+`GetThreadContext` profiler pattern (`docs/02`).
- If a future milestone ever revisits this (e.g. a DWARF-native debugger as its
  own consumer), it re-enters through the front door: an oracle-green `tests/ntapi`
  pin first (Art. 5), and this entry is amended — not silently contradicted.

The full accounting of which missing syscalls are out of scope vs. planned is
`docs/16-syscall-status.md`.

## Panic-on-STATUS_NOT_IMPLEMENTED boot (Art. 12 dialed to fatal)

- **Every image carries `C:\panic_not_implemented.flag` by default**
  (`tools/mkimage.sh`; `PANIC_NOTIMPL=0` omits it). While the marker is
  present (`kernel/init/main.c KiConfigurePanicOnNotImplemented`), a ring-3
  syscall that answers `STATUS_NOT_IMPLEMENTED` — a `KI_SYSCALL_MISSING` id
  or a partial service's unbuilt case — panics at the dispatcher
  (`kernel/syscall/table.c`) after naming the service (and its first two
  arguments) on serial. Art. 12's loud refusal becomes an immediate,
  attributable stop instead of a status a caller may limp past.
- **No refusal is exempt.** There is no "pinned refusal" category and no
  `KiPinnedNotImplemented()` escape hatch (removed): the status means
  *unbuilt*, and an oracle that answers it is unbuilt for that case too,
  never authoritative — so matching it is not a contract worth reproducing
  and **no `tests/ntapi/` case may assert it** (Art. 12, gate G12). Where the
  pinned Wine refuses, the test skips the case with a comment saying why:
  the unsupported token classes (`sem_se/se_query`), the unsupported file
  info classes (`sem_file/info_classes`), and the decorated byte-lock forms
  (`sem_file/byte_locks`). Those kernel paths still answer
  `STATUS_NOT_IMPLEMENTED`, and reaching one from ring 3 now stops the
  machine — which is the point: it converts a frozen hole into a work item.
  A skipped case is **not** a decision to leave it unbuilt: a gap in Wine is
  a gap in the oracle, not in NT, so any of those cases may be built against
  NT's own documented contract and moved from a skip to a `beyond_oracle`
  block (Art. 5) whenever a real caller wants it.
  A refusal a real caller *depends* on is a different status entirely (the
  specific NT failure for the case), implemented and pinned like any other
  behaviour.
- **The two classes the tightening forced to be built.** Making unbuilt
  fatal is only honest if "unbuilt" is then *fixed* rather than re-exempted,
  and two refusals sat directly on the boot path. Both are now implemented
  and their `sem_ps/process_query` pins carry no `todo_proskrnl`:
  `SystemFirmwareTableInformation` (76) and `SystemWineVersionInformation`
  (1000), below.

## `SystemFirmwareTableInformation` (76) — the RSMB provider

Not a deviation so much as ordinary OS work that had been mistaken for a
host dependency. The oracle *synthesizes* its SMBIOS blob from the host's
DMI files (`dlls/ntdll/unix/system.c create_smbios_data`) because
Wine-on-unix has no firmware of its own to read. proskrnl does: Limine
reports the SMBIOS entry point (physically, under base revision 3), and
`arch/x86_64/smbios.c` parses it — the 64-bit `_SM3_` form preferred, the
32-bit `_SM_` form otherwise, anchors and checksum verified, the 3.x table
length recovered by walking to the type-127 end-of-table marker because that
entry point reports only a maximum size (DMTF DSP0134 §5.2). Under QEMU this
finds SMBIOS 2.8, ~400 bytes.

`kernel/ps/query.c` shapes the answer: the `RawSMBIOSData` prologue followed
by the raw structure table, `Enumerate` reporting the single table id 0, and
`*returnLength` carrying the full requirement even on
`STATUS_BUFFER_TOO_SMALL` — which is what kernelbase's sizing call depends on
(`dlls/kernelbase/memory.c get_firmware_table` allocates only the fixed part
and subtracts it from `*returnLength`). Providers other than RSMB, and
actions other than the two, stay unbuilt and refuse loudly.

**Only the shape is pinned, never the bytes** — those name the machine, and
the two runners run on different ones. wineboot's `create_bios_key` now finds
real tables on proskrnl instead of nothing; the firstboot registry
differential stays at 0 divergences (its scope already excludes the
host-derived keys).

## Processor features: the array says what ring 3 may execute, not what the silicon has

`KUSER_SHARED_DATA.ProcessorFeatures` is filled at boot from CPUID
(`arch/x86_64/cpu.c` `KiInitializeProcessorFeatures`), transcribing the
oracle's `init_shared_data_cpuinfo` (`dlls/ntdll/unix/system.c`) leaf for leaf
and bit for bit. It is the ONE statement of the machine's capabilities: Wine's
PE ntdll implements `RtlIsProcessorFeaturePresent` as a plain load from the
array (`dlls/ntdll/signal_x86_64.c`), and the two `Nt*` classes that report a
feature word — `SystemCpuInformation` (1) and
`SystemProcessorFeaturesInformation` (154) — compose it from the array through
one function rather than re-reading CPUID, exactly as the oracle's
`get_cpu_features` reads the same page (Art. 11). Pinned by
`tests/ntapi/sem_ps/shared_machine.c`, which checks every optional entry
against CPUID as the TEST executes it, so the pin measures the rule and not
this developer box's feature set.

**The one divergence from the oracle's derivation, and it is a difference in
the machine rather than in the rule: the AVX family reports FALSE here.**
`PF_AVX_INSTRUCTIONS_AVAILABLE`, `PF_AVX2_*` and `PF_AVX512F_*` are gated on
`PF_XSAVE_ENABLED`, which is CPUID.1:ECX.27 (OSXSAVE) and therefore a
statement about the running kernel — and this kernel never sets CR4.OSXSAVE,
because a thread's FPU state is an FXSAVE image (`arch/x86_64/ctxswitch.S`).
A VEX-encoded instruction raises #UD while OSXSAVE is clear, so reporting AVX
available would hand a believing caller a fault; that is the
fabricated-plausible-answer failure of Art. 12 expressed as a bit rather than
as a status. The oracle does not need the gate because the Linux it runs on
always enables XSAVE, and it already applies the same shape to the one flag
where its host might not — `PF_RDWRFSGSBASE_AVAILABLE` is ANDed with the host
kernel's `AT_HWCAP2` bit, i.e. with CR4.FSGSBASE. Here that question is
answered by reading CR4, because here we are that kernel; `KiReadCr4()` is
where the FSGSBASE half lives.

Two consequences worth stating so nobody re-derives them:

- **user mode agrees with the array by its own measurement.** A library that
  checks CPUID for itself sees OSXSAVE clear and reaches the same conclusion,
  so the report is not merely safe, it is consistent with what a caller that
  ignores the flag would find.
- **`XState.EnabledFeatures` stays zero for the same reason**, so
  `RtlGetEnabledExtendedFeatures` reports nothing enabled and
  `ntdll:virtual`'s `test_user_shared_data` skips its xstate block rather than
  measuring a configuration no `CONTEXT` record here carries. When XSAVE is
  enabled — which is a context-switch change, not a reporting one — the AVX
  gate must become the XCR0 state test, not simply be deleted: CR4.OSXSAVE
  says the kernel *can* save extended state, not *which* states it does.

`NumberOfPhysicalPages`, `ActiveProcessorCount` and `ActiveGroupCount` are
filled from the same boot site, each from the one place its quantity is stated
(`MiGetTotalPageCount`, `KE_NUMBER_PROCESSORS`, and one group), so the page
cannot disagree with `SystemBasicInformation` about the same number — which is
what the winetest compares. `SystemProcessorFeaturesBitMapInformation` (250)
stays two zero words and that is a full answer, not an unfilled field: it
carries the flags numbered at or above `PROCESSOR_FEATURE_MAX`, which is an
aarch64-only set on both runners.

## `SystemWineVersionInformation` (1000) — implemented as HACK-005

NT has no class 1000; it is a Wine extension, and adding it puts an NT-absent
entity **inside the `Nt*` surface** — which Article 2 names first, and which
the GUI carve-out (a new device or process at the boundary's *outside*) does
not cover. It is taken deliberately and logged as **HACK-005**
(`docs/10-hacks-ledger.md`), because the alternative is worse: ntdll's
`version_init` calls the class at every process start
(`dlls/ntdll/version.c`) and ignores the status, so once Art. 12 made an
unbuilt answer fatal, refusing it meant the first user process panicked the
machine.

The reply is the oracle's layout — `version\0build\0sysname\0release` — with
values that are facts about this image rather than an imitation of a host:
`version`/`build` name the Wine the PE stack is built from (hand-typed
against `third_party/wine/VERSION` and re-verified on a pin bump, G8);
`sysname` is `proskrnl`, which is exactly what `wine_get_host_version` exists
to report; and `release` is **empty**, because proskrnl has no release
versioning and inventing a number would be the plausible-answer stub Art. 12
forbids. `sem_ps/process_query` pins the shape — a non-empty version and the
four-string walk — never the text.

## `ZeroBits`: the rule is exact, the reachable set is the address space's

`NtCreateThreadEx`, `NtAllocateVirtualMemory`, `NtMapViewOfSection` and
`NtSetInformationProcess(ProcessThreadStackAllocation)` all resolve `ZeroBits` through the
one authority (`MiZeroBitsLimit`, `kernel/mm/virtual.c`, byte-for-byte the oracle's
`get_zero_bits_limit`), and each states its own invalid band because the oracle's bands
genuinely differ per entry point — `NtCreateThreadEx` has **one** on x86-64 where the
allocation path has **two** (`docs/21` W5; pinned by `tests/ntapi/sem_ps/thread_zero_bits.c`
and `sem_ps/thread_stack_alloc.c`). Nothing here deviates.

What differs is which ceilings can be **met**, and it is worth writing down because it is
user-observable and it is not a bug. A ceiling is satisfiable only if a free hole of the
requested size lies under it, so the answer depends on where the address space starts being
free. proskrnl's lowest free hole in a *fresh* test process is `0x7c0000` (printed by
`sem_ps/thread_zero_bits.c`); the pinned oracle's is lower. So a 1 MiB thread stack under
the tightest few `ZeroBits` values — 9, 10 and 11 when the sweep starts at that hole — is
`STATUS_SUCCESS` on the oracle and `STATUS_NO_MEMORY` here, the same difference two Windows
machines with different loader layouts would show, and `ntdll:virtual`'s `test_stack_size`
accepts `STATUS_NO_MEMORY` at every one of those values for exactly that reason. **Which
values, exactly, is not a constant**: the hole a sweep actually sees is the fresh one minus
whatever the threads before it reserved, so the refused set widens by one as soon as those
threads get bigger (below).

The consequence to expect when reading a winetest count: proskrnl runs **16** of
`test_stack_size_thread`'s bodies where the oracle runs 24, because the sweep's tighter
ceilings correctly refuse here. That is coverage the pair cannot reach on this kernel, not
a failure, and it is why the pair's *executed* count sits below the oracle's while its
*failure* count matches on that cluster. No promise is made about where an allocation
lands; if this kernel's low reserved region ever shrinks, the reachable set grows and
nothing above needs changing.

**This paragraph said 18 and the number was arithmetic, not a count.** It was derived from
the two runners' lowest free holes (9 counts + 9 masks); counted per line in the serial
log, the pair ran **17** bodies then — 15 from the sweep plus the two
`test_stack_growth_thread` creates ahead of it — and runs **16** now. The one it lost is a
sweep create that flipped to `STATUS_NO_MEMORY` when the two threads ahead of it started
reserving the image's 2 MiB instead of a hardwired 1 MiB, because **this kernel never
releases a dead thread's stack** (`PspDeleteThread` frees the name, the token and the
KTHREAD, and nothing frees the reservation until the process dies), so each thread's
reserve is subtracted from the low address space permanently. That mechanism is read off
the code and is consistent with the arithmetic; which sweep index moved was not measured.
The leak itself is issue #152 — a real defect, not a property of the `ZeroBits` rule.

## What a FAILED `NtProtectVirtualMemory` answers

`NtProtectVirtualMemory` writes `PAGE_NOACCESS` into the caller's `*old_prot` on **every**
failure of the operation, and leaves `*base`/`*size` alone — the oracle's closing
`else *old_prot = PAGE_NOACCESS;` (`dlls/ntdll/unix/virtual.c`), mirrored in its remote-APC
arm. Nothing deviates; it is implemented and pinned by
`tests/ntapi/sem_mm/protect_old_prot.c` (`docs/21` W5), and it is what
`ntdll:virtual:2679`/`:2686` wanted. Three edges of that rule are pinned with it, because
none of them is in the line: the slot is written even for failures that never had a previous
protection to report (an unserviceable protection, an uncommitted range, a free address);
`*base` and `*size` are *not* written with it, since the oracle rounds them into locals and
copies back on success only; and the two returns *above* the `else` stay silent — a probe
failure has no writable slot, and a process handle that cannot be resolved (junk, or lacking
`PROCESS_VM_OPERATION`) means the operation never ran.

**The ORDER the refusals are decided in is the oracle's too, and it was not.** The oracle
asks view → committed → protection: `find_view`, then `get_committed_size`, then
`set_protection`, which is where `get_vprot_flags` refuses an unserviceable protection. So a
bad protection over a free address reports `STATUS_INVALID_PARAMETER` and over a reserved
range reports `STATUS_NOT_COMMITTED`; only over a range it could otherwise have protected
does it report itself. `MiProtectVirtualMemory` validated the protection on the way in — the
shape every implementation reaches for — and so answered `STATUS_INVALID_PAGE_PROTECTION` for
all three. No winetest assertion reaches the two that differ; the pin does.

**A zero-size request walks the same ladder** rather than being refused above it. The oracle
has no size guard: `ROUND_SIZE(addr, 0, mask)` is 0 for an aligned address, `find_view` still
answers the containing view, and `set_protection` walks no pages. Measured on both runners:
zero-size over a committed page succeeds and reports that page's protection with `*base`
rounded and `*size` 0; over a reserved range it is `STATUS_NOT_COMMITTED`; over a free address
`STATUS_INVALID_PARAMETER`; with an unserviceable protection `STATUS_INVALID_PAGE_PROTECTION`.
`MiProtectVirtualMemory` refused all four with `STATUS_INVALID_PARAMETER` from an
`end <= base` guard, which is now `end < base` — the overflow the oracle's `find_view`
refuses in the same words. The named page is therefore checked for commit, and read for the
previous protection, outside the range loop, because a zero-size range has no pages in it.

**The status for a range no single view covers was a third answer, and it is now the
oracle's.** Both ways to miss — a free address, and a range that starts inside a view and
runs off its end — are the oracle's `find_view` returning NULL, whose one caller answers
`STATUS_INVALID_PARAMETER`. `MiProtectVirtualMemory` used to answer `STATUS_INVALID_ADDRESS`
for both, and that is not a different shade of the same refusal at the boundary Win32 sees:

| | status | `RtlNtStatusToDosError` |
|---|---|---|
| pinned oracle | `STATUS_INVALID_PARAMETER` (`c000000d`) | `ERROR_INVALID_PARAMETER` (87) |
| Windows x64 | `STATUS_CONFLICTING_ADDRESSES` (`c0000018`) | `ERROR_INVALID_ADDRESS` (487) |
| proskrnl, before | `STATUS_INVALID_ADDRESS` (`c0000141`) | **`ERROR_UNEXP_NET_ERR` (59)** |

So `VirtualProtect` over a free address used to report an "unexpected network error"
(`dlls/ntdll/error.h:686`, against `:389`). Wine and Windows genuinely disagree here —
upstream says so itself at `dlls/ntdll/tests/virtual.c:2677`, which is why `ntdll:virtual`
asserts only that the call fails and no winetest assertion convicts any of the three — and
where two authorities disagree the pinned oracle is this project's arbiter (Art. 6). Pinned
both ways by the same file. If a real caller is ever found to branch on
`ERROR_INVALID_ADDRESS` there, that caller is evidence for Windows' answer and the change is
its own commit with its own pin.

## The page-protection modifier bits, and where the mask stops

A Win32 page protection is a base protection in its **low byte** plus modifier flags above
it, and how much of the word a syscall reads is *not* uniform across the boundary. Getting
that wrong is what broke `WriteProcessMemory` outright: kernelbase makes a non-writable range
writable for the duration of the copy with
`PAGE_EXECUTE_READWRITE | PAGE_TARGETS_NO_UPDATE | PAGE_ENCLAVE_NO_CHANGE`
(`dlls/kernelbase/memory.c`), `MiCheckPageProtect` refused the whole word, and
`STATUS_INVALID_PAGE_PROTECTION` reaches the caller as `ERROR_INVALID_PARAMETER` — so every
`WriteProcessMemory` into a read-only or executable range failed (`kernel32:virtual:236`).
Nothing deviates now; the three masks are the oracle's and they are pinned by
`tests/ntapi/sem_mm/protect_modifier_bits.c`:

| entry point | what it reads | a modifier bit is |
|---|---|---|
| `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` (`get_vprot_flags`) | `protect & 0xff`, plus `PAGE_GUARD` | accepted, dropped |
| `NtCreateSection` (`dlls/ntdll/unix/sync.c`) | `protect & 0xff` | accepted |
| `NtMapViewOfSection` (`virtual_map_section`) | `switch (protect)`, no mask at all | `STATUS_INVALID_PAGE_PROTECTION` |

The last row is why this is a table rather than one function: "mask the modifier bits off
wherever a protection is captured" is the tidy rule, it passes every winetest assertion, and
it admits a view the oracle refuses — including one asking for `PAGE_GUARD`, which the
private path keeps. `MiStoredPageProtect` is therefore applied at exactly the two places the
oracle calls `get_vprot_flags` (`MiAllocateVirtualMemoryEx` and `MiProtectVirtualMemory`) and
nowhere near `mm/section.c`.

**Dropping the bits is not enough on its own: they must not be STORED.**
`MEMORY_BASIC_INFORMATION.Protect` is read back out of the recorded per-page protection,
while the oracle rebuilds it from the kept flags alone (`get_win32_prot`:
`VIRTUAL_Win32Flags[vprot & 0x0f]`, plus `PAGE_GUARD`). An implementation that only widens
its *validation* answers every status correctly and then reports a protection value no NT
ever produces.

**`PAGE_NOCACHE` is the exception, and it belongs to the RESERVATION rather than to the
page.** The oracle records it in the *view's* own protect word, once, in the reserve arm —
`if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;`, inside `allocate_virtual_memory`'s
`(type & MEM_RESERVE) || !base` branch — and reads it back from there on every query
(`get_win32_prot`'s `if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;`). So it is sticky and
write-once in three directions a per-page implementation reproduces in none: a later
`NtProtectVirtualMemory` can neither remove it nor add it, and neither can a `MEM_COMMIT`
into an existing reservation, which takes the other branch. proskrnl now keeps it on the VAD
(`MI_VAD.noCache`) and re-applies it at every report site. The first draft of the pin
asserted the obvious thing — that `PAGE_NOCACHE` was dropped like the others — and **the
oracle refuted it** (Art. 6).

That one bit was five of `kernel32:virtual`'s failures, and only two of them look like
protections: `:517`'s "wrong size 1000" is the same cause one step out, because a
re-protected page then differed from its neighbour by the `PAGE_NOCACHE` bit alone and split
the reported region run in half.

**What is still unbuilt is the SECTION half of the same bit, and it is a deviation.** A
section created with `SEC_NOCACHE` keeps the flag on the oracle (`server/mapping.c` preserves
it into `sec_flags`, which becomes the view's protect word), so every view of it reports
`PAGE_NOCACHE`. `MiCreateSection`'s attribute switch never looks at `SEC_NOCACHE`, so
proskrnl's views report the protection without it. Nothing in the baked stack or the winetest
manifest reaches it; it is recorded here rather than fixed because the fix is the same
one-field shape on the *section*, and it should land with a pin of its own (`docs/21` W5).

## What a live SECTION holds against a later OPEN

NT models a section as a **pseudo-open of the file**, and the pinned oracle says so
literally: `create_mapping` (`third_party/wine` `server/mapping.c`) keeps the file's
fd with a magic access word — `FILE_MAPPING_ACCESS` always, `FILE_MAPPING_IMAGE`
under `SEC_IMAGE`, `FILE_MAPPING_WRITE` when the section's own file access carried
`FILE_WRITE_DATA` (`server/file.h:303-305`) — and sharing
`FILE_SHARE_READ|WRITE|DELETE`. `check_sharing` (`server/fd.c`) reads those three
bits back as four rules. proskrnl carries them as three counters on the `IO_FCB`
(`sectionCount` / `imageSectionCount` / `writableSectionCount`), applied in
`IoCheckShareAccess`; pinned by `tests/ntapi/sem_mm/section_file_hold.c`.

| A live section that is… | refuses a later open that… | with |
|---|---|---|
| non-image, file access included `FILE_WRITE_DATA` (i.e. `PAGE_READWRITE` / `PAGE_EXECUTE_READWRITE`) | does not share `FILE_SHARE_WRITE` | `STATUS_SHARING_VIOLATION` |
| `SEC_IMAGE` | asks for `FILE_WRITE_DATA` | `STATUS_SHARING_VIOLATION` |
| `SEC_IMAGE` | passes `FILE_DELETE_ON_CLOSE` | `STATUS_CANNOT_DELETE` |
| anything | names a truncating disposition | `STATUS_USER_MAPPED_FILE` |

Five things are not guessable from that table and each is a way an implementation
reaching for the tidy version diverges:

- **The mapping rules sit ABOVE `check_sharing`'s own "no data access → sharing is
  ignored" escape**, so an opener asking for nothing but `FILE_READ_ATTRIBUTES` —
  exempt from every ordinary share mode — is still refused by the write rule. That is
  the entire `a2 == 0` column of `kernel32:file`'s `test_file_sharing` mapping loop.
- **A section demands nothing of the opener's *sharing* except through the write
  rule**, because the magic bits carry no read/write/delete bit of their own and the
  mapping fd shares everything. An image section refuses a writer and admits an
  unshared reader.
- **The image rule is `FILE_WRITE_DATA` alone.** Every other share-mode rule in NT
  groups `FILE_WRITE_DATA | FILE_APPEND_DATA`; this one does not, and an
  append-only open of a running image succeeds. Sixteen `kernel32:file` assertions
  are exactly that cell.
- **`PAGE_WRITECOPY` is not writable here.** The discriminator is the section's
  *required file access*, not the word "write" in the protection's name, which is
  why `IopSectionFileAccess` (`kernel/io/file.c`) is one function answering both
  "what must the creating handle grant" and "does this section take the write hold".
- **The ORDER between the four is observable**: write beats truncate, delete beats
  truncate, and the pair of section rules sits *between* `check_sharing`'s two
  share-mode directions rather than before or after both. An image section opened
  `GENERIC_WRITE` with `FILE_OVERWRITE_IF` reports the sharing violation; drop the
  write and the same call reports `STATUS_USER_MAPPED_FILE`.

The truncating dispositions are the oracle's three `O_TRUNC` ones —
`FILE_SUPERSEDE`, `FILE_OVERWRITE`, `FILE_OVERWRITE_IF` (`server/file.c`
`create_file`'s switch). This is what makes `CopyFile` onto a mapped destination and
`DeleteFile` of a mapped image answer `ERROR_USER_MAPPED_FILE` and
`ERROR_ACCESS_DENIED`: both are Win32 spellings of an open, not separate rules.

## Deliberate simplifications under the "stupidly correct" mandate (T4)

These are deviations from NT's *implementation*, never from its *observable semantics*:

- **COW: image sections only (amended at CUI-9)** — the "no COW" mandate was lifted for
  `SEC_IMAGE` on the measured ceiling (see "CUI-9 COW notes": ≈5.9 MB/process, refusal at
  70 processes at the pinned 512M boot). Private memory and data-section `PAGE_WRITECOPY`
  mappings still copy fully on map; anonymous sections still share their frames outright.
- **No eviction, immediate writeback** — makes mapped-view/`ReadFile` consistency trivial.
- **One dispatcher lock, uniprocessor** — turns every race into a plain state machine.
  Retiring "uniprocessor" is designed in `docs/18-smp-strategy.md` (giant lock, four entry
  conditions); the other two clauses survive that design unchanged.
- **No kernel preemption** — context switches only at explicit waits and user-mode return
  (plus the CUI-4 preemption point at return to ring 3).

**Not on this list, and not a simplification:** I/O completing inside the syscall. That is a
legal point inside the NT asynchronous contract — `STATUS_PENDING` is permitted, never
required — and `docs/19-io-strategy.md` §1 states the contract that inline completion
satisfies, §3 the gaps that remain.

Every simplification above is unobservable from user mode, so none is a contract. See
`docs/09-constitution.md` "Lifting a mandate", which makes these *rules* with named exits,
not options.

## Console/GUI-era additions that are NOT in NT (tracked as HACKs)

These are the only places we add something NT lacks. Each lives strictly at the boundary's
*outside* (a new device or a new process), never inside the existing `Nt*` or Wine PE code,
and each is logged in `docs/10-hacks-ledger.md`:

- **serial-backed console** (HACK-004, M9) — condrv's transport is the COM1 UART in both
  directions; real NT feeds conhost from win32k's raw input path and draws its output into
  a window. Retired when the GUI-1+ input/display path exists.
- **`\Device\Fb0`** (HACK-001, GUI-1, **built**) — map the framebuffer to user mode; NT would
  own this via a display driver behind win32k. See "GUI-1 notes" below.
- **`\Device\Input0`** (HACK-002, GUI-1, **built**) — raw input stream to user mode; NT routes
  this through win32k/csrss. See "GUI-1 notes" below.
- **wineserver-lite as a desktop server** — a user-mode server holding desktop state. Not
  a hack against NT so much as a return to NT 3.1's actual architecture (see `docs/07`).

## GUI-1 notes (`\Device\Fb0`)

**A section over a device handle.** `\Device\Fb0` is mappable because it implements the
internal `GetCache` vfs op (`kernel/io/vfs.h`) and returns a page cache whose frames are the
scanout's physical pages; `NtCreateSection(SEC_COMMIT, PAGE_READWRITE, fbHandle)` +
`NtMapViewOfSection` then work through the same `IopBuildSectionBacking` / `MiMapViewOfSection`
path a file uses, and `kernel/mm` gains nothing. Real NT does not expose a display device this
way at all — VRAM is mapped below win32k by the display driver — so this is an extension of our
internal seam, not an imitation of an NT one. The client-visible shape is deliberately the
boring one (`MapViewOfFile(CreateFileMapping(hDevice))` at the Win32 level), because that is
what winefb.drv will use at GUI-2. `NtReadFile`/`NtWriteFile` on the handle fall out of the same
seam and genuinely read and write scanout bytes.

**Writeback is a no-op, honestly.** The device's `WritebackRange` returns success because the
"cache" *is* the scanout: there is no farther copy of those bytes. This is an implementation of
the op, not a stub — the op's contract is "these bytes are durable at the next level down", and
they are.

**Cacheability.** The view is plain `PAGE_READWRITE`, mapped write-back through the HHDM like
every other page; there is no WC/PAT support and no `MiMapPage` cacheability argument. Under the
QEMU target the "VRAM" is host RAM (pinned tree `hw/display/vga.c` backs it with a RAM memory
region), so write-combining would buy nothing observable. On real hardware this would be a
performance deviation to revisit — never a correctness one (Art. 3).

**The mode is the bootloader's.** There is no mode-set path. `IOCTL_PRSFB_GET_MODE`
(`drivers/fbproto.h`) reports width/height/pitch/bpp and the RGB mask sizes and shifts exactly as
Limine reported them, so a client composes pixels from the masks rather than assuming BGRA. A
framebuffer that is absent, not RGB, or not 32bpp means the device is **not published** and an
open fails `STATUS_OBJECT_NAME_NOT_FOUND` — the honest refusal, never a fabricated mode
(Art. 12). Any ioctl other than the mode query names itself on serial and refuses with
`STATUS_NOT_IMPLEMENTED`, which the dispatcher's armed panic turns into a stop.

**`FileFsDeviceInformation` answers `FILE_DEVICE_VIDEO`**, generated from the pinned Wine
`winioctl.h` like every other device type (Art. 4) rather than recalled — it is `0x23`, not the
`0x22` a plausible guess produces.

**The G5 adaptation.** Oracle-first is inapplicable to a HACK device: Wine has no `\Device\Fb0`,
so no `tests/ntapi` case can be green on it before the kernel implements it. What replaces the
oracle is a differential against an implementation the kernel does not control — the guest paints
a rectangle and reports on serial what it painted and where, and `tests/run/run.sh gui` pulls the
scanout back through QEMU's own device model (`screendump` → PPM) and checks the pixels against
that report (Art. 6: a sanitizer-quiet kernel convicts nothing; an independent reader does). The
contract itself is pinned in `drivers/fbproto.h` and in this section, which is the same shape
HACK-004's console leg uses. No golden image at GUI-1 — a byte-compared PPM would break on any
QEMU rendering change without saying anything about the kernel.

### `\Device\Input0`

**Events are the wire format, untranslated.** A read returns whole `virtio_input_event` records
(`drivers/hidproto.h`) — Linux evdev type/code/value, exactly as the device produced them. There
is deliberately no scancode-to-character mapping in the driver: that mapping is a keyboard
layout, and a layout belongs in user32 above the boundary. (Contrast the M9 conhost glue, which
knows the ASCII slice of US-layout `VkKeyScanW` only because HACK-004 gave it no alternative.)

**Blocking-only, whole events, one reader.** A read blocks until at least one event is available;
there is no peek/poll mode and no ioctl, because nothing has needed one — GUI-3's unified waiting
lives in user mode (`docs/07`). A buffer smaller than one event returns
`STATUS_INVALID_PARAMETER` rather than a silent zero-length read the caller would spin on. The
device opens exclusively (`STATUS_SHARING_VIOLATION` on a second open), enforced through the
existing `IoCheckShareAccess`/`IoSetShareAccess` engine rather than a private flag (G10/Art. 11),
so the Io layer's ordinary close path releases it.

**Polled, not interrupt-driven.** `kernel/ke/irq.c` routes no device vectors, and this driver
does not add any: the read drains the eventq and, finding nothing, naps a millisecond — the shape
`CondrvSerialRead` already uses for the serial console. Buffering is the device's: QEMU's eventq
holds 64 single-event buffers and drops whole new reports when full (pinned tree
`hw/input/virtio-input.c` `virtio_input_send`), so there is no second ring inside the kernel to
size, and the driver's only obligation is to re-post each buffer as it consumes it.

**No output path.** virtio-input's statusq (§5.8.2) carries LED and force-feedback output *to*
the device; it is left unconfigured and says so on serial, and `\Device\Input0` correspondingly
has no `Write` or `DeviceControl` op, so the Io layer refuses those verbs outright (Art. 12).

**`FileFsDeviceInformation` answers `FILE_DEVICE_KEYBOARD`**, generated like every other device
type (Art. 4).

**The G5 adaptation** is the framebuffer's, applied to input: no oracle can have `\Device\Input0`,
so the conviction is that a key injected by QEMU's own input layer (QMP `send-key`) comes back out
of the read path as `EV_KEY`/`KEY_A` press-then-release.

### `\Device\Input1` (GUI-4)

**The pointer stream — QEMU's `virtio-tablet-pci` — under the same contract.** Everything the
Input0 section pins holds per stream: verbatim `virtio_input_event` records, blocking whole-event
reads, one exclusive reader, polled, no output path. The tablet was chosen over a relative mouse
because its coordinates are absolute: a QMP-injected position arrives verbatim (the pinned QEMU's
`qmp_input_send_event` does not scale abs values), so a dropped event cannot skew every later
position the way a lost relative delta would — the difference between a convictable test (Art. 6)
and a flaky one.

**Which function is the pointer is the device's own claim.** The instance whose `EV_BITS` config
advertises `EV_ABS` is the pointer (virtio 1.2 cs01 §5.8.5.1: an unsupported select/subsel pair
reads back size 0, which the pinned QEMU implements as a memset). PCI enumeration order decides
nothing, so identity survives a reordered command line.

**One ioctl, `IOCTL_PRSHID_GET_ABS_INFO`** (`drivers/hidproto.h`), reporting the ABS_X/ABS_Y
min/max the device published — verbatim, cached at init, the `IOCTL_PRSFB_GET_MODE` precedent.
Events are still untranslated and unscaled: scaling to screen pixels is user mode's, exactly as
scancode translation is. The keyboard keeps no `DeviceControl` op at all, so the Io layer's own
refusal shape for it never shifts. **`FileFsDeviceInformation` answers `FILE_DEVICE_MOUSE`**, generated (Art. 4).

**The G5 adaptation, restated for the pointer:** no oracle can have `\Device\Input1`, so the
conviction is that QMP-injected `input-send-event` abs moves and button presses come back out of
the read path as `EV_ABS`/`BTN_LEFT` with the injected values, and downstream that the gui4 leg's
click/drag verdicts and screendumps hold (`tests/run/run.sh gui4`).

## GUI-2 notes (win32u in-process)

GUI-2 runs win32u's implementation and the pinned wineserver's GUI object model inside the
GUI process (`user/wine/`, docs/07 route (a)). Three shortcuts that arrangement makes are
deliberate, and each is a delta to re-examine at GUI-3, when wineserver-lite becomes a
process again.

**The arrangement itself — RETIRED after GUI-5.** GUI-3 made wineserver-lite a process but
did not remove the in-process mode, because the gui2 test image kept selecting it: the mode
was probed from whether `wineserver-lite.exe` was on the boot volume, and that one image
shipped without it. So a superseded arrangement stayed alive — and stayed *mandatory*, since
every GUI change had to be correct in both modes — because a test pinned it. The gui2 image
now carries the server like every other win32u image; `wine_server_call` has one path; and
win32u.dll no longer links the object model at all (it linked ~186 KB of it, dormant, into
every GUI process — a second copy of the desktop state machine, which is the parallel
authority Art. 11 is about). The notes below stay as the record of what GUI-2 was.

**One window-station directory — RETIRED at GUI-3.** `NtUserCreateWindowStation` names
"WinSta0" relative to a handle on `\Sessions\<id>\Windows\WindowStations`, and that handle
comes from the KERNEL namespace (`NtOpenDirectoryObject`), which the in-process server had
no view of. GUI-2's `get_directory_obj` therefore probed the handle for validity and
answered with the one window-station directory it owned — correct while there was one
process, one session and one station, and wrong the moment there were two of any of them.

The server now keeps **one station directory per session**, made on demand, and answers with
the directory for the *calling client's* session. The session comes from the kernel
(`NtQueryInformationProcess(ProcessSessionInformation)` on the client's process handle, taken
when the client attaches), not from an assumption about how many exist. The handle itself is
still checked rather than trusted: it is duplicated out of the client with a cross-process
`NtDuplicateObject` (`sem_ob/dup_cross_process`) and its type queried, so a handle that is
not a live directory over there is refused. What remains a deviation is narrower and worth
stating: proskrnl's `NtQueryObject(ObjectNameInformation)` returns an object's **leaf** name
rather than NT's full path, so the server cannot read the session number out of the handle's
own name and takes it from the owning process instead. That is the same answer for every
case the boundary can distinguish, since a process's window stations live in its session's
directory; making the name query answer full paths is NT-correct and unbuilt.

**Security is the kernel's, not a second engine's.** The in-process server's
`check_object_access` succeeds, `sd_is_valid` checks only that a descriptor is big enough to
be one, and the token queries answer "no token". proskrnl's Se department already decides
access at the `Nt*` boundary (M8); running a second, parallel check over descriptors nobody
sets would be exactly the drift Art. 11 warns about — two authorities that agree today and
diverge later. The GUI objects are reachable only from this process, so there is nothing for
the second check to protect.

**One process, so any process handle names it — RETIRED at GUI-3.** GUI-2's
`get_process_from_handle` returned the one process record for any handle a GUI request
carried, `get_process_from_id` accepted only that process's id, and `enum_processes` visited
the one. The server now keeps a list of clients — it mints its own record at bringup so the
list is never empty, and every transport client joins it through the same constructor — and
`get_process_from_id`/`enum_processes` answer from it truthfully.

`get_process_from_handle` is the exception, and it now **refuses loudly** instead of
answering. Resolving it would mean reading a handle table the server does not own, and the
GUI-2 answer ("the process I know about") becomes a fabricated one as soon as there are two
(Art. 12). Nothing on the GUI path calls it: the only caller among the linked server files is
`req_dup_handle` (`server/handle.c`), which is not a request win32u makes.

**Thread records are not reclaimed — RETIRED at GUI-3 (with a named residual).** GUI-2 minted
a `struct thread` on a Win32 thread's first server request and never freed it: Wine's server
learns of thread death from the socket closing, and there is no socket here. The server
process now has two authorities for it, neither a socket. A thread that detaches normally
sends `PRSK_OP_DETACH` from win32u's `DLL_THREAD_DETACH` and is reaped in wineserver's own
order (`cleanup_clipboard_thread` → `destroy_thread_windows` → `free_msg_queue` →
`release_thread_desktop`); a client PROCESS that exits is noticed by its process handle going
signalled in the server's own wait, and everything it still owns is reaped then.

The residual, stated because it is real: a thread killed with `NtTerminateThread` while its
process lives on delivers no `DLL_THREAD_DETACH`, so its records wait for process exit. That
is the same root cause as before — no per-thread death signal — but bounded by a process
lifetime rather than unbounded, and it is the case GUI-4's input routing will care about
first.

**Desktop inheritance: threads inherit, connecting processes self-create — RESOLVED at
GUI-3 (what stopped the milestone was elsewhere).** What was diagnosed here as "the missing
connect step" — `create_desktop` on a desktop-less first thread returns
`STATUS_INVALID_HANDLE` **beside the handle it allocated** (its body's
`get_thread_desktop( current, 0 )` fails while inheriting the `DF_WINE_*_DESKTOP` flags, and
only the already-existed branch clears the error) — turned out to be the *oracle's own
behaviour*, not a divergence. The first process ever to connect to a real wineserver hits the
same reply: its parent has no window station either, `connect_process_winstation`
(`server/winstation.c`) bails through `clear_error()`, win32u's `winstation_init` creates
`WinSta0`/`Default` itself, `NtUserCreateDesktopEx` deliberately takes `reply->handle`
without looking at the error, and the following `set_thread_desktop` request repairs the
process default desktop. Every wineserver-lite client is such a parentless first process, so
the create-and-ignore-the-error dance *is* the pinned behaviour — and no session bootstrap
in the server is needed or wanted.

The actual stopper was a transport infidelity: `slot_call`
(`user/wine/wineserver-lite/client/call.c`) copied the reply back **only on success**, where Wine's wire contract delivers the full
reply and its data unconditionally and returns the error beside it (`send_reply`,
`server/request.c`; `wait_reply`, `dlls/ntdll/unix/server.c`) — and the in-process dispatch
already did the same, so the two modes had drifted (Art. 11) in exactly the way this file
exists to prevent. With the reply delivered, win32u recovers exactly as it does on the
oracle. The one piece of inheritance wineserver-lite *did* owe is the per-thread half, and
it is built: a new thread record starts on its process's default desktop — the same block
wineserver's `create_thread` runs (`server/thread.c`) — which is what a client's second and
later threads inherit. The residual deviation is narrow: a process spawned *by a connected
GUI process* would, on the oracle, inherit its parent's window station and desktop handles
at connect time; here it self-creates and `OBJ_OPENIF` lands it on the same `WinSta0`/
`Default`, so the objects agree and only the connect-time handles differ. That case first
matters when a GUI process launches another (explorer, GUI-6).

**The desktop is always forced, and its user entries look foreign.** On Wine the desktop
and `HWND_MESSAGE` windows belong to explorer: `get_desktop_window` without `force` waits
for it, and every app process sees the windows' user entries carry a foreign pid, which is
what routes win32u onto its `WND_DESKTOP` special cases. There is one GUI process here and
explorer is GUI-6, so the shim sets `force` on every `get_desktop_window` (the same server
path the forcing caller takes — win32u never tries to launch an explorer.exe the image does
not carry) and then clears the owner ids on the two entries so they read as foreign
(`shim.c detach_user_entry`; the server side is already detached,
`server/window.c detach_window_thread`). Without that second half the entries kept our own
pid, win32u went looking for a client-side WND that was never made, `GetWindowLong` on the
desktop answered style 0, and the first `ShowWindow` took the invisible-parent shortcut —
the window turned visible without ever being exposed, and nothing painted. The desktop
window's rects, which explorer would size, come from winefb.drv's `pSetDesktopWindow`
sizing it to the scanout — the same repair `X11DRV_SetDesktopWindow` makes when it finds
them uninitialized.

**`HKU\<sid>` exists from boot.** win32u's `font_init` opens
`\Registry\User\S-1-5-21-0-0-0-1000` (the fixed Se identity) and loads no fonts at all when
it is absent; the oracle's wineserver creates `HKU\<sid>` at prefix init. `CmInitialize`
seeds the empty root (the ComputerName precedent); HKCU *population* stays deferred
(CUI-1 notes).

**Case folding comes from ntdll, not from the server's own table.** `server/unicode.c` reads
a lowercase table out of `l_intl.nls` with `pread()` on a unix descriptor; that file is a
unix-fd reader rather than a state machine, so it is not compiled here, and `hash_strW` /
`memicmp_strW` go through `RtlDowncaseUnicodeChar` instead. It is the same table — ntdll maps
the same `l_intl.nls` the image bakes — reached a different way.

Everything else the GUI path asks for that is not linked in refuses by name and returns
`STATUS_NOT_IMPLEMENTED`; the dispatch table is generated from the pinned tree's own request
list (`tools/gen_server_table.py`), so the refusals are a measured set (188 of 308) rather
than an assumption.

**FreeType was on for the proskrnl build only** — GUI-2's state, retired at GUI-3. It is
recorded here because the reasoning is the reusable part.

At GUI-2 the pinned Wine stayed `--without-freetype` while `user/wine/include/config.h` set
the two defines for the proskrnl build alone, so the two builds did not share a font
backend and there was no oracle for font *metrics* at all. That was the right default —
turning fonts on in the oracle to make a proskrnl build *easier* would be fixing the oracle
instead of the kernel (Art. 6) — but it left docs/07's "same FreeType + fonts as
Wine-on-Linux ⇒ same numbers" a plan rather than a fact, and docs/02 scheduled the decision
here.

**Taken at GUI-3: the oracle gets the same font backend, from the same source tree.**
`tools/setup_linux.sh` now configures the pin `--with-freetype --without-fontconfig` with
`FREETYPE_CFLAGS`/`FREETYPE_LIBS` pointed at `third_party/freetype` — the *pinned* FreeType,
built native by `tools/build_freetype.sh` from the same file list as the PE static library
`win32u.dll` links. Both sides therefore agree on three things that have to agree before a
metric can be differentially tested at all:

- **backend** — FreeType on both, no fontconfig on either;
- **version** — the pin (2.13.3) on both, rather than the pin on one side and whatever the
  distro ships (Ubuntu 24.04: 2.13.2) on the other;
- **font set** — with fontconfig off, win32u never loads host fonts, so the oracle's fonts
  are the pinned tree's own `fonts/` and the target's are the same files baked at
  `C:\windows\fonts` (Makefile `WINE_FONTS`).

This is not Art. 6 oracle-fixing: nothing was changed to make a proskrnl divergence pass —
no font test existed to fail. The spec was *extended* to cover a surface it did not cover,
before the milestone that judges dialog layout (GUI-5) needs it. The configure change is
deliberately a visible `tools/setup_linux.sh` event, as docs/02 required, and forces one
rebuild through the cache-prefix bump (tp-v3 → tp-v4) plus a staleness check on
`SONAME_LIBFREETYPE` in the generated `config.h`.

What is still *not* pinned: an actual metric differential. `tests/gdi/fontsmoke.c` proves
the oracle's backend loads and answers (the failure mode it guards is real — win32u
`dlopen`s its backend and falls back to *no fonts* rather than failing loudly), but
comparing numbers between oracle and target is GUI-5 work, as docs/02 has it.



## GUI-4 notes (the compositor, the pointer, the cursor)

**winefb.drv is the native windowing system, and that sentence has two halves.** The pinned
server deliberately neither clips top-level siblings out of a window's surface region
(`server/window.c get_visible_region`: "that's up to the native windowing system") nor exposes
them when a top-level moves away (`expose_window` skips children of the desktop). Under
winex11/winewayland the host compositor owns both; here both are the driver's:

- **occlusion**: every surface flush intersects its dirty rect with win32u's own surface clip
  (delivered through `window_surface_set_clip` and previously dropped) and subtracts the rects
  of every visible top-level *above* it, queried fresh from the server per flush
  (`get_window_list` — the same topmost-first walk the server's own hit-testing does — plus
  `get_window_rectangles`), with the region algebra done by win32u's own `NtGdi` engine;
- **exposure**: the *mover* repairs the world from `pWindowPosChanged`/surface destroy — other
  top-levels touching the vacated area are invalidated cross-process (`NtUserRedrawWindow` →
  server `redraw_window` wakes their queues), the desktop-owned remainder is filled directly,
  and the moved window's own surface is re-blitted whole (a pure move dirties nothing:
  the surface is reused and `move_window_bits` is an identity no-op; a raise generates no
  exposure at all).

Queried fresh rather than cached, on purpose: a cache would need exactly the cross-process
invalidation protocol this design avoids. Staleness is bounded by one flush — clip and repair
derive from the same server rectangles, so the picture converges on the next flush of either
side.

**The desktop background is the driver's too.** The desktop window is forced and foreign
(the GUI-2 notes above): no process runs its WndProc, so nothing would ever paint the
desktop. winefb paints it — once, in the first process, the moment that sizes the desktop
window, and again wherever the uncover repair reaches desktop-owned pixels. The same
authority split as an X root window. The color is reported on serial
(`[KTEST] gui2 desktop … bg=…`) and the checkers sample against the report, never assume.

**Input0's reader placement was a live bug, fixed here.** The GUI-2 start hook —
`pUpdateDisplayDevices` — is never called once the display cache is warm in the registry, so
the app under test had *no* reader at all (the gui3 logs proved it: `input READY` only in an
early firstboot-era process). `winefb_start_input` is now idempotent and also fires at the
first window surface; every GUI process attempts the exclusive opens, one wins, losers exit
quietly on `STATUS_SHARING_VIOLATION`. Residual: if the winning process dies, input is
orphaned until a process that has not yet attempted creates its first surface.

**Pointer injection is the winewayland shape, per event.** The tablet's absolute axes scale
to scanout pixels in the reader (range from `IOCTL_PRSHID_GET_ABS_INFO`, screen from the
mode — no QEMU constant on either side) and inject as
`MOUSEEVENTF_MOVE|ABSOLUTE|MOVE_NOCOALESCE` with hwnd 0: the reader serves the desktop, and
the unmodified server routes by capture and coordinate (`find_hardware_message_window`).
`MOVE_NOCOALESCE` bypasses win32u's motion accumulator — QEMU already coalesced.

**The cursor is a software arrow, composited by every writer.** No hardware cursor plane
exists — and acquiring one is not the cheap fix it sounds like: `-vga std` (QEMU's
bochs-display) has no cursor plane at all, the only QEMU device that does is virtio-gpu's
cursor queue, and a hardware cursor is a *host-side overlay* that `qmp screendump` does not
composite into the PPM (`ui/ui-qmp-cmds.c qmp_screendump` dumps the `DisplaySurface` alone),
so no pixel test could ever convict it (Art. 5/6). The cursor is therefore pixels this
driver draws, and the rule is one line: **the cursor is above everything, so every writer
that touches the scanout draws it back on top of what it just painted.** The surface flush
and the background fill both end with `winefb_cursor_present`, in every process, and the
position comes from `desktop_shm->cursor` — the server's own state, read through the seqlock
`NtUserGetCursorPos` uses, which takes no user lock and is therefore legal inside the
surface lock (the compose.c rule).

There is deliberately **no save-under**, and that is the correctness argument rather than a
simplification: a save-under is a per-process cache of pixels several processes write, so
its snapshot goes stale the moment another process flushes over it and restoring it deposits
a cursor-sized patch of pixels captured somewhere else. GUI-4 shipped that (with the
artifact documented, and both gui4 clients repainting themselves to hide it); GUI-5 replaced
it. When the pointer moves, the vacated rect is repainted **from whoever owns those
pixels** — `winefb_repaint_rect`, the same authority the mover uses (Art. 11: the mover and
the cursor vacate screen rects for different reasons, but there is one walk that repairs
one). Whether a process draws a cursor at all is decided by whether a pointer *device*
exists, which every process already learns from `\Device\Input1`'s exclusive open: the
winner and every loser (`STATUS_SHARING_VIOLATION`) both know, and a keyboard-only image
draws nothing.

**No arrow before the pointer has reported a position**, and the test for that is the
position itself: `(0,0)` is the desktop's initial cursor value (`server/winstation.c`) and
so cannot be told apart from "never moved". `cursor.last_change` is the field that *looks*
like the has-it-ever-moved flag and is not one — the server stamps it through the ordinary
motion path every time it resyncs the cursor, which a visible window changing rect does
(`server/window.c set_window_pos` → `update_cursor_pos`) as does releasing capture, both of
which happen during startup on any tablet-equipped image. Gating on it painted an arrow in
the top-left corner of every such image before the mouse moved, which the gui4 dumps caught
— they check that corner for the background. The same arrow is a standing hazard for
gui5con, which *locates* its console window as the bounding box of everything that is not
background: a corner arrow would stretch that box to the screen edge for any window not
already touching the origin (gui5con's own window sits at the origin, so it happened not to
show there). The cost of the position test is that a pointer parked at exactly `(0,0)` draws no
arrow until it moves again — bounded, cosmetic, self-correcting, and it fails to *no*
cursor rather than to a cursor where the pointer has never been.

The SHAPE is still not the per-window `HCURSOR`: `WM_WINE_SETCURSOR` is delivered to the
process owning the window under the cursor, and honoring shapes would mean tracking that
cross-process for zero milestone value.

Residual, named: the vacated rect over a *window* is repainted by that window's own thread
(rect-scoped invalidation — a whole-window repaint per mouse motion would be a repaint storm
on anything console-sized), so a wedged window keeps the trail until it pumps again. Over
the desktop background — the common case — the repair is immediate and local. Same latency
class the mover already accepts for an uncovered window, and it degrades to briefly-stale
rather than permanently-wrong.

**Known residuals, named:**

- **lowering** a window (`HWND_BOTTOM`) exposes the sibling that rises above it with no
  notification anywhere; the newly-uncovered window shows through only on its own next
  flush. Not on the milestone path; the gui4 scenario avoids it.
- the thread-record residual from GUI-3 (a violently-killed thread's `thread_input` — focus,
  capture — survives to process exit) is now load-bearing for input routing; still bounded by
  process lifetime, still waiting for a case that hits it.
- **the pinned server's focus-stealing rule is real** and convicted the gui3 leg's latent
  race: a non-foreground process whose input is older may not retake foreground once its
  window has been foreground before (`set_foreground_window`, `queue->input->user_time`).
  Show-order determinism (B created after A) is now pinned in gui3b/gui4b; click-driven
  activation (the gui4 way) is exempt because a click *is* fresh user input.

## GUI-5 notes

What "GUI finishing" (docs/02) actually landed, and the shortcuts/residuals it created or
retired. The clipboard/hook/AttachThreadInput machinery itself needed **nothing built** —
every server half has been compiled and dispatchable since GUI-2, and the gui5 leg's whole
job was to exercise it cross-process for the first time (it passed on first bring-up, which
is the strongest statement about route (a)'s "compile the pinned server unmodified" bet the
project has).

- **Clipboard payload ceiling.** Cross-process clipboard is live within the transport slot
  (`PRSK_SLOT_DATA`, 64 KiB — `user/wine/wineserver-lite/common/transport.h`); a larger
  `set_clipboard_data` refuses loudly by request name rather than truncating (Art. 12). Named residual,
  grow-on-demand: msg.c and a windowed conhost's copy-paste are the plausible consumers, and
  neither has needed it yet.
- **Cross-process non-LL global hooks are unexercised.** A global `WH_CBT`-class hook needs
  hook-module injection into the hooked process (`ERROR_HOOK_NEEDS_HMOD`, the module loaded
  by name over there) — freestanding no-CRT test clients cannot host that. `WH_KEYBOARD_LL`
  is the pinned cross-process hook coverage (moduleless by design, delivered through the
  server's `MSG_HOOK_LL` posting); msg.c's hook tests are the eventual real consumer.
- **The GUI-4 residuals gui5 deliberately sidesteps**: no tablet on the gui5 image (no
  pointer *device*, so no process draws a cursor at all); no `HWND_BOTTOM`; both attached threads outlive
  the AttachThreadInput phase (though attach makes the violently-killed-thread
  `thread_input` residual *more* load-bearing should a client ever die attached — same
  bound, process lifetime).

### The windowed conhost (dual-mode; the serial console is permanent)

`CONHOST_GUI` compiles the pinned tree's `window.c` and `conhost.rc` **unmodified** and
links the real user32/gdi32/advapi32 — zero fork commits, hack meter unchanged. Decisions
and their reasons:

- **The baked binary decides the mode, not a runtime probe.** headless_stubs.c /
  window_glue.c define a link-time capability flag the shared entry branches on. A disk
  probe of the server image was rejected: gui3/gui4/guiwtest images carry wineserver-lite
  *and* need the headless conhost (their verdicts ride serial). The windowed binary still
  probes `PRSK_SRV_IMAGE`, but only as a refusal — a windowed conhost on a serverless image
  has no desktop to draw on, and would otherwise discover that as a win32u bringup failure
  during Ldr init; it exits loudly by name instead (G12). (Before the in-process dispatch
  mode was deleted the same probe prevented something worse: conhost would have become the
  desktop's OWNER, the split-brain `user/wine/wineserver-lite/client/call.c` used to name.)
- **comctl32 is a manual delay-load** (`user/wine/programs/conhost/window_glue.c`),
  mirroring upstream's DELAYIMPORT: reachable only from the config dialog, resolved by LoadLibrary on first
  call, refusing with the API's real failure shapes if absent. No load-time import of a
  DllMain path no boot has exercised (the GUI-2 imm32 delay-import abort is the precedent).
- **Start order**: wineserver-lite now starts BEFORE conhost (`kernel/init/main.c`) — a
  GUI-linked conhost is a win32u client during Ldr init, before its entry point runs. On
  serverless images the swap is a probe/skip no-op. The condrv attach window widened
  10 s → 30 s for the same prologue.
- **^C**: in window mode the whole CUI-4 deviation ("Ctrl+C is detected on the serial RX
  path; `ENABLE_PROCESSED_INPUT` is not consulted") does not apply — conhost's own
  `map_to_ctrlevent` runs from `WM_KEYDOWN`/`ToUnicode`, honours `ENABLE_PROCESSED_INPUT`,
  and reaches the kernel through `IOCTL_CONDRV_CTRL_EVENT` like real NT. The gui5con leg
  convicts that path end to end (looper interrupted with the serial intercept never
  involved). The CUI-4 cost paragraph is now CUI-image-only.
- **conhost is the input-reader host** on its images (first surface-creating GUI process,
  the GUI-4 rule) — and being a permanent process, the "orphaned input if the winner dies"
  residual attaches to something that cannot die early. An improvement, recorded.
- **The serial-backed console is PERMANENT** (decision, GUI-5 planning): HACK-004's
  retirement condition was met and explicitly not taken. A console that works while the
  whole GUI stack is broken is a debugging capability we keep, and the CUI test surface
  rides it. The hack's scope shrank (GUI images now run the windowed conhost); the entry
  stays. See docs/10.

### Deadlock detection, both sides of the boundary (GUI-5)

The consistency sweep (`KiVerifyKernelState`, docs/08) gained two detectors, because the
msg.c hunt cost a 40-minute harness timeout to learn one fact a sweep already had in hand.
Art. 3 is what makes both sound *and* cheap: the sweep holds the one dispatcher lock and
every non-running thread is parked at a blocking point, so what it walks is an atomic
snapshot of the whole executive, not a sample of a moving target.

- **Kernel-mode — a wait-for cycle, and it is fatal.** Edges come from objects whose owner
  the kernel records: a mutant held by another thread, a thread object being joined. Only
  *necessary* edges are drawn — a `WaitAny` over several objects draws none (any one may
  release the waiter), and timed and alertable waits are excluded (they wake themselves, or
  an APC breaks them). What survives is a proof, so it ASSERTs. Convicted by
  `tests/kmt` `test_deadlock_walk`, which builds the graph by hand (a real deadlock would
  panic the boot before a test could report) and checks every exclusion, because a false
  positive here would panic a healthy boot.
- **User-mode — a wedge, and it is a loud diagnostic.** The kernel cannot name a cycle whose
  locks live in user memory, but it can prove the *process* is dead: when every thread sits
  in an untimed wait on its own tid-alert latch, only `NtAlertThreadByThreadId` can wake it,
  and ntdll's futex protocol only alerts same-process tids. After the picture stands across
  consecutive sweeps the wedge dump fires once. Not an ASSERT: a cross-process alert is
  theoretically expressible, so this one reports and lets the boot run to its timeout.

### GUI-5 winetest notes (user32:msg — the budget ratchet)

The trophy gate (`tests/run/run.sh guiwtest`) runs the pinned tree's own
`user32_test.exe msg` — 21.5 kloc, ~85 test functions — over the full GUI stack, swept by
the same kernel wtest runner as the CUI manifest (`tests/winetest/manifest-gui.txt`, with
the manifest's new optional per-pair timeout field).

- **There is no oracle leg, by measurement.** The pinned oracle is `--without-x` (GUI-3
  made it the *font* oracle, deliberately nothing more). Under its null display driver
  user32 refuses every window ("The graphics driver is missing", `nodrv_CreateWindow`),
  msg.c fails its first `CreateWindow` and then hangs forever in
  `test_SendMessage_other_thread` (an INFINITE wait on a thread whose window never
  existed). The recorded oracle baseline is therefore *cannot run*, not a failure count.
  The spec authority for this gate is msg.c's own `ok()`/`todo_wine` assertions — winetest
  is third-party, Windows-verified spec (docs/08), and `todo_wine` evaluates on proskrnl
  exactly as on Wine (the M10 finding: `winetest_platform_is_wine` is TRUE here).
  Building an X/Xvfb oracle was considered and rejected: an X11-driver-driven message
  environment is no more "the spec" for a winefb target than nulldrv is, and it would
  drag X into a tree that deliberately has none.
- **The verdict is a budget ratchet** (`tests/winetest/msg-budget.txt`): the leg reads the
  kernel's own verdict line off serial (winetest's text reaches the console through an
  80-column screen diff that mangles it; the NT exit status carries the full failure count)
  and fails on any count above the budget. The budget only ever decreases, in the same
  commit as the fix that earned it (G13: the number is that commit's test expectation). An
  exit outside a sane count range is a CRASH and fails the leg by name regardless of budget.
  The end state is 0 — msg.c green with only its own `todo_wine` marks.
- **In CI the leg is advisory on pull requests and blocking on main**
  (`.github/workflows/test.yml`: the `msg` shard, and the `all-green` job that decides which
  shards stop a merge). The budget is a ceiling over a machine-speed-dependent band — up to
  twelve of the counted assertions are settled by how much guest time passes inside a block,
  not by semantics (below) — and a hosted runner's speed is not a constant: legs on the same
  suite have run ~2× apart between two runs of the same commit. A run that overshoots the
  band is reporting the runner, and that must not block a merge. It must still be *visible*,
  so the shard goes honestly red rather than being wrapped in `continue-on-error`; nothing is
  suppressed, only de-blocked, and only on PRs. On main the same red blocks the branch: a
  real regression has to stop it, and main's history is where the ratchet's numbers live.
  This is a CI-policy carve-out, not a budget change — the leg's verdict rule is unchanged,
  and a crash exit fails it under either policy.
- **The per-assertion text is recovered, not read by eye** (`tools/unscreen.py`, run by the
  leg into `build/tests/guiwtest-msg.log`). HACK-004's console is a screen, so a test's
  output reaches serial as a diff: cursor moves, erases and changed cells. Replaying `CSI n
  C` as n spaces and dropping the rest turns the fragments back into
  `msg.c:20062: Test failed: ...`. Nothing machine-read depends on it — the verdict is
  still the kernel's own `[KTEST]` line — but a budget above zero is a list of named
  divergences, and this is where the names come from.

**What the campaign convicted** — every one of these was found by the gate and is now
fixed, pinned, or convicted by a green leg:

1. *The named-event hole.* `test_WaitForInputIdle`'s ~20 child processes all failed at
   `CreateEventA`: `\Sessions\1\BaseNamedObjects` did not exist (`sem_ob/session_bno` pins
   it, `ob` creates it).
2. *The only refused server request.* `get_process_idle_event` lives in `server/process.c`,
   which this build does not compile; the shim implements it, and `get_msg_queue_handle`
   now hands out the idle event so win32u's client-side idle signalling works.
3. *A real lock-order inversion of ours.* `winefb_surface_flush` called
   `NtUserGetWindowLongW` (which takes win32u's user lock) while holding the surface mutex,
   inverting every `user lock -> surface mutex` path in win32u; `DestroyWindow` against a
   concurrent flush deadlocked the suite for the whole harness timeout. The flush path's
   clip query is now raw server requests and takes no win32u lock. **This one was ours, not
   Wine's** — the value the trophy gate returned before it could even finish a run.
4. *An unbuilt file info class, refusing exactly as designed.* The run died `0xC0000005`
   in the combobox area for as long as the module could not get past it; the fault was a
   red herring of an earlier build. What actually stopped a complete run was
   `NtQueryInformationFile(FileEndOfFileInformation)` — ntdll's `actctx.c` asks it of every
   manifest file it maps, msg.c's activation-context tests build one, and the class was
   unbuilt, so the armed dispatcher panicked the boot (Art. 12 working as intended). Built,
   pinned by `sem_file/info_classes` on the oracle first.
5. *The process idle event is a GUI-process thing.* wineserver creates it only when the
   image subsystem is not `IMAGE_SUBSYSTEM_WINDOWS_CUI`; this build created one for every
   client, on the assumption that every client is a GUI process. `user32_test.exe` is a
   console binary that loads user32, so `WaitForInputIdle` waited on an event nobody would
   signal instead of failing the way Wine and Windows both fail it. −3 failures.
6. *The forced desktop window re-homed the whole process.* GUI-2's fixture answers every
   `get_desktop_window` with `force`, so the ASKING app creates the desktop window — and
   `server/window.c` hands whoever creates a desktop's top window that desktop as its
   process default, a line that on Wine only explorer reaches. One `run_in_temp_desktop`
   later the process default was a throwaway desktop: `CloseDesktop` refused it as busy,
   every later thread inherited it, child windows whose parent lived on the real desktop
   were refused `ACCESS_DENIED`, and a thread-wide winevent hook landed on the wrong hook
   table. The fixture now restores the default it displaced. −10 failures.
7. *A third state the console's terminate unwind did not have.* The leg stopped answering
   at all — no failure count, a panic 90 s in: `[ASSERT] kernel/lib/list.h:56` (a
   double-remove) under `CondrvForward`, in `test_WaitForInputIdle`, whose parent
   `TerminateProcess`es each of its ~21 children while the child's console read is in
   flight. A parked client verb lives on the client's kernel stack, so the CUI-4 unwind
   has to disown it — and it knew two states, `current` or still-linked. There is a third:
   `KiAbortThreadWait` readies the client *without touching the console queues* and on the
   uniprocessor the client does not run until conhost parks, so conhost can fetch **and
   complete** the request in that window, leaving it neither `current` nor linked. The
   unwind now recognizes a completed request (`done` signalled) and unlinks nothing;
   `tests/kmt/condrv_unwind.c` drives all three states deterministically over the real
   server transport, which the cooperative scheduler makes reachable by construction
   rather than by luck. **This one was ours, not Wine's**, and it is why the leg's ratchet
   is a ceiling on a *count*: a crash has no count, and `run.sh guiwtest` fails it by name.

**What is left, and why** (the budget is a ceiling — `msg-budget.txt` explains the
difference from the measured count):

- *Two assertions wait on GUI-6.* `SetFocus(GetDesktopWindow())` and
  `SetForegroundWindow(GetDesktopWindow())` both go through
  `check_queue_input_window`/`get_window_thread` on the desktop window, and here that
  window has **no owning thread** — GUI-2's forced-foreign fixture again. Wine answers
  `ERROR_ACCESS_DENIED` because the desktop belongs to explorer, a different input queue;
  we answer `ERROR_INVALID_HANDLE` because it belongs to nobody. Explorer owning the
  desktop is precisely what GUI-6 builds (docs/02 says the fixture retires there), so this
  is the one divergence deliberately left for that milestone rather than papered over.
- *Up to twelve assertions are decided by emulated-machine speed, not by semantics,* and
  they are the reason the budget is a ceiling rather than a measurement.
  `test_PeekMessage3` sets a 100 ms timer, never kills it, and then asserts **seven** times
  that the queue is empty — true where the intervening block runs in microseconds, false
  where 100 ms of guest time passes first (Wine's own `restart_timer` makes a late timer
  due immediately). Measured runs have put **1 and 4** of those seven on the failing side,
  which is the whole observed movement between two otherwise identical runs.
  `test_WM_COPYDATA` contributes a further **five**: it polls `FindWindow` for one second
  for a child process's window, and a process start on this stack costs more than that
  under TCG — but they fail as a block, so they cost the budget no headroom. Neither family
  says anything about NT semantics; both would pass on a fast machine.
- *Two message-sequence divergences in `test_interthread_messages`* — **still open**, and
  the hunt is recorded because two fixes came out of it and neither closed it. "destroy
  child on thread exit" expects `WM_PAINT` then `WM_ERASEBKGND` and gets `WM_NCPAINT` and
  `WM_GETTEXT` in between: the parent's non-client area is dirty when it paints, so
  `BeginPaint` sends `WM_NCPAINT` and `DefWindowProc`'s caption paint asks for the title.
  The uncover repair was the suspect twice over — it invalidated whole windows, and a
  request trace showed a `RDW_FRAME` `redraw_window` reaching a top-level from another
  thread. Both are real defects and `winefb_repaint_rect`/`invalidate_covered` now handle
  both (rect-scoped in client coords when the covered area lies inside the client rect,
  whole-window only when it reaches the frame) — which matters because
  `server/window.c redraw_window` sets `PAINT_NONCLIENT` **unconditionally** on seeing
  `RDW_FRAME` rather than reading it as a description of the region handed with it. But
  **neither moved this count**, measured before and after: the compositor is not this
  divergence's cause. The reason is now known and is the useful residue of the hunt —
  win32u never gives a child window a surface (`window.c`: `is_child` ⇒
  `needs_surface = FALSE`), so a child's destruction never reaches the repair path at all.
  The frame must therefore be dirtied by one of the other two `PAINT_NONCLIENT` setters,
  `init_window_info` or `set_window_info(GWL_STYLE)`; logging both in the shim is how the
  first trace was got, and that is the thread to pull next.
- *Two are `todo_wine` tags that are stale on proskrnl* — winetest counts a test that
  *succeeds* inside a todo block as a failure (`winetest_failures + winetest_todo_failures`
  is the exit status), so these are cases where **we are right and Wine is not**:
  `ShowWindow(SW_SHOWMAXIMIZED)` on an overlapped window produces the message sequence
  Windows produces (msg.c:5730 marks the whole sequence todo), and a 500 ms wait for a
  window proc completes here where Wine times out (msg.c:18349). Neither is fixable in this
  tree: the fix is upstream in Wine, and editing msg.c to make the number smaller would be
  fixing the oracle instead of the kernel (G9).

Running 32-bit apps via WOW64 is **NT's real mechanism**, so it adds nothing to the hacks
ledger. Kernel cost is a few hundred lines (GDT compat descriptors, an
`IMAGE_FILE_MACHINE_I386` branch in process creation, low-4GB address-space restriction,
compat-mode exception delivery, `ProcessWow64Information`). No `Nt*` semantics change. The
32→64 transition ("Heaven's Gate") is entirely user-mode; the kernel never sees a 32-bit
syscall. See `docs/02` §WOW64.

## WOW64 notes — what "purely additive" turned out to mean (Art. 7)

The plan called WOW64 "purely additive" and `docs/02` still calls it removable. That is
true of the *feature*, and NOT true of the diff, so the difference is written down here
rather than left to be discovered.

**Removable, as claimed.** `kernel/ps/wow64.c` is the whole WOW64 construction —
PEB32/TEB32, the 32-bit parameter block, `WOW64INFO`, the second ntdll and its
`SYSTEM_DLL_INIT_BLOCK`, the guest stack, the `WOW64_CPURESERVED` area. Every core call
site into it is one guarded line, and deleting the file plus those lines removes the
feature. `kernel/ps/ldt.c` and `kernel/ps/debug.c` are likewise self-contained.

**NOT removable, and deliberately so.** Three core changes stand on their own and would
NOT be reverted if WOW64 were dropped:

- **The GDT selector re-layout** (`arch/x86_64/gdt.h`: kernel CS/DS `0x08/0x10 →
  0x10/0x18`, ring-3 `0x23/0x1b → 0x33/0x2b`, `KI_GDT_ENTRIES 8 → 13`). proskrnl's old
  values were divergent from both NT and Linux, and `0x23` — proskrnl's *64-bit* user CS
  until now — is NT's *32-bit* one. Every `CONTEXT` leaks these to ring 3. Fixing that is
  a correctness change that WOW64 forced but does not own; `tests/boot/abi_probe.c`
  `check_selectors` now pins it independently of any 32-bit code.
- **The ring-3 return path loading its data segments** (`kernel/syscall/entry.S`
  `KI_LOAD_USER_SEGMENTS`). `iretq` nullifies the kernel's DPL-0 data selectors, so user
  `%ds`/`%es` read back as 0 without this — a real divergence from NT for a 64-bit
  process too, and one `RtlCaptureContext` exposes. Also pinned by `abi_probe`.
- **`MI_ADDRESS_SPACE.machine` and the PE32 arm in `mm/pecoff.c` / `mm/section.c`.** A
  32-bit image mapped into a 64-bit process must report
  `STATUS_IMAGE_MACHINE_TYPE_MISMATCH` (success-class — the view IS created) whether or
  not WOW64 exists. Answering plain `STATUS_SUCCESS` satisfied every `NT_SUCCESS()` check
  and was simply wrong.

So: the WOW64 *milestone* is subtractable; the *bug fixes it forced* are not, and should
not be. Art. 7 asks that the GUI/WOW64 layers not entangle the CUI core — it does not ask
that a core defect stay unfixed because a later milestone is what surfaced it.

## WOW64 GUI notes — the defects a 32-bit window found

`make rungui` gained the 32-bit half of the GUI shelf: a 32-bit `.exe`, typed at the
windowed console, paints a window on the desktop the 64-bit applets share
(`tests/run/run.sh wow64gui` is the acceptance). No `Nt*`
semantics moved for it, and nothing new was minted: the guest's own `user32`/`gdi32`
import the pinned tree's STOCK i386 `win32u.dll`, which is nothing but syscall thunks —
`wow64cpu` catches those syscalls, `wow64.dll` routes service table 1 to `wow64win.dll`,
and `wow64win` calls the SAME 64-bit `win32u.dll` this build already ships, by name, for
all 483 entry points it imports. One desktop authority (Art. 11), reached through one
more door.

What it cost was a handful of defects, all of them older than the feature and none of
them 32-bit in nature — a WOW64 GUI process is simply the first caller that exercises
them:

- **`NtQueryDirectoryFile` assumed an 8-byte-aligned output buffer.** Entries are laid out
  on 8-byte boundaries *relative to the buffer*; the buffer's own alignment is the
  caller's business. i386 gives the pinned tree's own SxS lookup (`actctx.c`
  `lookup_manifest_file`) a 4-aligned `char buffer[8192]`, and every `LARGE_INTEGER` field
  the kernel stored through a struct pointer then landed misaligned — legal on the
  hardware, undefined in C, and a UBSan `#UD` in this build. The fields are now staged in
  an aligned local and copied out as bytes. Pinned by
  `tests/ntapi/sem_file/dir_unaligned_buffer.c` (buffer+1/+2/+4 answer exactly like
  buffer+0, measured on the oracle first).
- **The interrupt return path did not reload the ring-3 data selectors.** The WOW64
  milestone fixed this for the *syscall* path (`KI_LOAD_USER_SEGMENTS`) and `trap.S`'s
  `iretq` kept nullifying them, so whether a guest survived depended on WHERE the timer
  tick landed: the CUI leg's short-lived guest never noticed, and a windowed one died
  within a second on its next `mov %fs:0x18, %eax`. The macro now lives in
  `arch/x86_64/kipcr.inc` and both paths run it. Like its syscall half, this is a
  correctness fix that outlives WOW64.
- **A WOW64 process's SECOND thread got no 32-bit furniture.** `NtCreateUserProcess` built
  the TEB32, the guest stack and the CPU area; `NtCreateThreadEx` built none of it, so the
  first thread a 32-bit GUI app created ran with `fs:[0x18]` reading zero. Both thread
  builders now go through one `PspBuildThreadFurniture` — which is also the answer to why
  there were two paths to drift apart (Art. 11).
- **`THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` was accepted and dropped.** In a WOW64 process
  every thread is a guest thread unless its creator says otherwise (the diversion is in
  `loader_init`, which this flag makes return before it), so the flag is how the two
  64-bit reader threads `winefb.drv` starts stay 64-bit. Silently discarding it is the
  Art. 12 shape exactly: success, a handle, and a thread that jumps to its own start
  routine truncated to 32 bits. Now recorded in `SameTebFlags` (and mirrored into the
  TEB32, as the oracle mirrors it); pinned by `tests/ntapi/sem_ps/thread_skip_flags.c`.
  The mirror is written *after* `PspWow64BuildTeb32`, never before — that call writes the
  whole 32-bit TEB, so the order is load-bearing, and it is the oracle's order for the
  same reason. The 64-bit half is what an ntapi test can reach; the guest half is checked
  by `tests/cui/hello32.c`, the one client that runs the same binary on both runtimes.

One user-mode addition, in `user/wine/dlls/win32u/glue.c` rather than the kernel: **the
64-bit ntdll of a WOW64 process never runs `locale_init`.** `loader_init` calls
`init_wow64`, which hands control to `Wow64LdrpInitialize` and never returns, so
`nls_info.UpperCaseTable` stays NULL and `RtlUpcaseUnicodeChar` faults. Upstream that is
harmless — the only 64-bit code in such a process is the `wow64*` thunk set, which never
folds case. proskrnl puts one more 64-bit DLL there, so `win32u` installs the case tables
itself when nobody else has (idempotent; a no-op in a 64-bit process, where the PEB field
it publishes is already set).
