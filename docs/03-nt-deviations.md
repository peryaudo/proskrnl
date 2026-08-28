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
| `FILE_BOTH_DIR_INFORMATION.ShortName` | reported, and matched as a second leg by the mask — the *value* differs between the runners by construction (see "The 8.3 alias's leading run" below). This row used to say "left empty"; that was true before `IopFillShortName` and `sem_file/short_names.c`. |

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
  `NtFlushVirtualMemory` over the view's covered file range (CUI-7), and **when the view
  itself goes away** — `MiWritebackMappedView`, called from `MiUnlinkAndFreeVad`, which
  every path that destroys a VAD comes through (an explicit unmap, and an exiting
  process's address-space teardown). Not per-store, and the residual deferral (store →
  unmap) stays **unobservable**, which is what Art. 3 asks of an entry here: while any
  view exists the section holds a reference to the `FILE_OBJECT`
  (`kernel/mm/section.c` `IopBuildSectionBacking`), which keeps the FCB and its page
  cache alive, so a concurrent open of the same file reads the *same frames* and sees
  every store already. `NtWriteFile` writes through immediately, so only a mapped store
  can ever be behind.

  **This line used to say "and at file close", and nothing did it.** That was not a
  harmless overclaim: the page cache hangs off the FCB and the FCB dies with the file's
  last handle (`fs/fat32/fat.c FatDereferenceFcb`), so a shared writable view's stores
  were dropped and a LATER open of the same file read the pre-view bytes back off the
  disk. Every assertion *inside one open* still agreed, which is why
  `sem_mm/file_coherence.c` — which never closes the file — was green throughout. It cost
  `kernel32:resource` 41 assertions and `kernel32:actctx` 34, both through
  `EndUpdateResource`, which writes a module's new `.rsrc` section through a
  `PAGE_READWRITE` view and copies the file back (`dlls/kernel32/resource.c`
  `write_raw_resources`). Pinned by `tests/ntapi/sem_mm/view_close_reopen.c`, whose cases
  4 and 5 pin the two inverses that matter: a **WRITECOPY** view's stores must stay
  private, and a read-only view must change nothing. On a SHARED view the writecopy
  flavours are themselves writable (the oracle grants `PAGE_WRITECOPY` on one and
  realizes it as a writable shared mapping — `MiProtectVirtualMemory`'s shared-view
  gate), so the writeback predicate is `MiProtectToPteBits`'s `writable`, not
  `PAGE_READWRITE`.

### The 8.3 alias's leading run: dots are stripped, a space is not

A name that is not already a legal 8.3 name gets a generated alias
(`FatGenerateShortName`, `fs/fat32/dir.c`). The FAT specification (§7.4)
licenses any unique legal 8.3 name, so the *string* is ours to pick and the
two runners pick differently — the oracle hashes the long name into an
eight-character base, FAT uses a numeric tail. **One bit of the value is
nevertheless shared, and it is observable: whether the alias carries an
EXTENSION.** A mask ending in DOS_STAR (`<`) can never match an alias that
has a dot, and `<` is exactly what kernelbase's `fixup_mask` emits for the
DOS glob `*.`, so this bit decides which files a "list the extensionless
names" call returns.

The rule both runners implement:

- a **leading run of dots** is stripped before the last dot is looked for, so
  `.a`, `..a` and `.aaa` alias to a base with **no** extension even though
  their long names all carry a dot. This is the only reason `<` reaches them;
- a **leading space is not part of that run**. ` .a` keeps its `.a`, aliases
  *with* the extension `A`, and is invisible to the same mask. Spaces are
  still dropped from the base as illegal 8.3 characters — what a leading
  space does not do is make the dot after it a leading dot.

The asymmetry is measured, not reasoned: the oracle's `hash_short_file_name`
(`dlls/ntdll/unix/file.c`) advances its leading-run loop over `'.'` only, and
`tests/ntapi/sem_file/short_names.c` §7-8 asserts the same split on both
runners. Stripping dots *and* spaces — which proskrnl did until this item —
answers every other cell of `kernel32:file`'s wildcard table correctly and
gets ` .a` wrong in sixteen of them.

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

- **The hive is our own format, "proskrnl hive v2"** (`kernel/cm/hive.c` is its normative
  spec): one file, `\??\C:\windows\system32\config\SYSTEM` (NT's path shape), holding a
  **flat log of records** — no cells, no bins, no free lists. Each record carries its own
  length, a CRC-32, an op (create key / delete key / set values / delete value / rename
  key) and the **full path** of the key it acts on, relative to the image's top key; the
  tree is the fold of the log in order. v1 stored the tree AS a tree, a nested preorder
  dump in which a key's parent was its lexical position — which left exactly one way to
  change a key three levels down, rewriting the whole file, and that is what made every
  mutating syscall O(hive). Structure is a field now rather than a position. Writes still
  go through the ordinary `NtCreateFile`/`NtWriteFile` path onto write-through FAT32, so
  mutations are durable at syscall return and **`NtFlushKey` is a success no-op**
  (strictly stronger than NT's lazy flusher; unobservable from a running program).
- **A mutation APPENDS one record; it does not rewrite the file.** That is the whole
  point, and it is what makes a mutation O(change) instead of O(hive). Durability is
  unchanged — the record is on write-through FAT32 before the syscall returns, so nothing
  is buffered and `NtFlushKey` stays an honest no-op. The file is opened and closed per
  append rather than held open for the boot, because FAT32 refuses to rename over a file
  with an open handle (`fs/fat32/file.c` `FatVfsRenameLocked`) and compaction below needs
  that rename. Two syscalls do NOT append: `NtUnloadKey` on a non-volatile target and
  `NtRestoreKey` drop a whole subtree, which the log's leaf-only `DELETE_KEY` cannot
  express, so they rewrite from a snapshot instead. Both are cold — nothing in firstboot
  or the baked services reaches either.
- **Compaction runs unconditionally, exactly once per boot**, in `CmInitialize` after the
  replay and after every seed, immediately before the hive goes live. Not threshold
  driven, and the reasons are worth keeping: there is no policy to tune; the file only
  ever accumulates one boot's appends, which is what keeps the 64 MiB cap out of reach;
  and — the one that actually decides it — **the rewrite path then runs on every boot of
  every leg** instead of rotting behind a condition almost nothing meets. Compacting
  *after* the seeds is also what stops the 139-zone time-zone table and the license values
  from being appended a record at a time: they land in the snapshot. The mechanism is
  write-a-temp-file-then-rename-over-it, so a crash during the snapshot leaves the live
  hive untouched, and the only exposed window is the two directory-slot writes inside
  FAT's rename — against PHV1's 237 KiB body write on *every mutation*.
- **The log's growth is loud, because nothing shrinks it until the next boot.** Past a
  16 MiB soft threshold the kernel says so once per boot; at the 64 MiB cap an append
  refuses and names itself every time rather than dropping a mutation quietly (G12).
- **Three replay rules are load bearing**, and the format comment states them: `SET_VALUES`
  MERGES (so absence needs its own `DELETE_VALUE` op — a log whose only value op were
  "set" would replay a deletion away); a record's PARENT MUST ALREADY EXIST (ancestors are
  always logged first, so a missing one means corruption, and replay refuses rather than
  conjuring intermediates — the same rule as `NtCreateKey` creating only the last
  component); and NO RECORD EVER DELETES A NON-EMPTY KEY (`NtDeleteKey` refuses a key with
  subkeys, and the two syscalls that do drop a subtree — `NtUnloadKey` on a non-volatile
  target, and `NtRestoreKey` — rewrite the log from a fresh snapshot instead of appending).
- **No recovery logging** (NT's `.LOG1`/`.LOG2` dirty-page journals are shed, docs/05): the
  per-record length + CRC are what a reader recovers with instead. It validates each
  record and **stops at the first one that fails, keeping everything before it**, so a
  torn write costs the last record rather than the file. That is strictly better than v1,
  whose magic was written last so that an unfinished body left no valid file at all and
  the next boot started with an *empty registry*. The two readers outside the kernel —
  `tests/run/regdump.py` (the firstboot differential) and `tests/run/tornreplay.py` (the
  torn-write leg) — implement the same stop-at-first-bad-record rule, because a reader
  that did not would report a legitimately torn hive as a whole-file divergence.
  A kernel crash between a mutation and its write completing can still lose that mutation.
- **A ring-3 image gets a verdict, the boot hive gets its prefix.** One replay function
  with one flag: `NtLoadKey`/`NtRestoreKey` were handed a file by a caller, so anything
  malformed unwinds and answers `STATUS_NOT_REGISTRY_FILE` (what v1 did, and what the
  oracle does); the boot hive is the kernel's own append log, where a torn tail is an
  expected ending rather than corruption. Pinned by `sem_reg/save_load.c`'s junk-file case.
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
- **`FSCTL_PIPE_IMPERSONATE` is unbuilt on a pipe END** — refused loudly
  (`STATUS_NOT_SUPPORTED` + a serial line), never faked. *Both statements
  below were overtaken by the winetest frontier and are corrected here rather
  than left to read as current:* `FSCTL_PIPE_TRANSCEIVE` is built (see "What
  `FSCTL_PIPE_TRANSCEIVE` writes, and what it refuses"), and on the DEVICE
  ROOT `FSCTL_PIPE_IMPERSONATE` is not unbuilt either — it is
  `STATUS_ILLEGAL_FUNCTION`, an implemented refusal (see "What the named-pipe
  DEVICE ROOT answers to each pipe FSCTL"). `FSCTL_PIPE_PEEK` is implemented
  (state, available bytes, message count, preview). *`FSCTL_PIPE_WAIT` is
  built by CUI-3* (served on the device-root
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
- **Consoles are per-client, on demand** (M11 — *retires the M9 "one
  global console" deviation*). The object model is wineserver's
  (`server/console.c`), pinned by `tests/ntapi/sem_console/`: every
  `\Device\ConDrv\Server` open mints a console server; `"Reference"`
  relative to it mints THE console, once; `"Connection"` relative to the
  console binds the opening process (`EPROCESS.console`, wineserver's
  field of the same name); Input/Output opens and their I/O resolve the
  CALLER's binding at every call, never a captured pointer; closing a
  connection handle unbinds the closing process; `IOCTL_CONDRV_BIND_PID`
  adopts a target's console with wineserver's exact refusals. Kernel-side
  wrinkles vs. wineserver, all inside the same observable behavior:
  - a ScreenBuffer open holds a counted console pointer (wineserver's
    `screen_buffer->input` is uncounted) so its `CLOSE_OUTPUT` reaches the
    right conhost even after the opener unbinds;
  - the connection unbind runs at the connection FILE_OBJECT's Cleanup in
    the closing process's context (wineserver has a per-process
    close-handle hook; proskrnl's Io has Cleanup), with a process-delete
    fallback for a connection handle duplicated across processes;
  - conhost learns its console's last client is gone by its next Server
    read answering `STATUS_INVALID_HANDLE` (wineserver's
    `get_next_console_request` on a console-less server) — the boot
    console never hits this because smss holds its Reference forever;
  - a serial-wire `^C` (HACK-004) routes to the console whose conhost is
    doing the tty read (the reading thread's process names it); a `^C`
    with no such conhost is dropped loudly;
  - the Server open's granted access implicitly includes
    `FILE_READ_DATA | FILE_WRITE_DATA`: the request pump is
    `NtReadFile`/`NtWriteFile` here (the fork transport,
    `drivers/condrvproto.h`) where wineserver serves a
    `get_next_console_request` server call with no file-access dimension —
    so kernelbase opens the handle properties-only
    (`create_console_server`), and the data access the pump needs is the
    device's to grant.
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
- **Every boot brings the desktop stack up, including a serial CUI one.** One
  image serves every leg, so there is one conhost and it links the real
  `user32`/`gdi32` (the CUI stand-ins are gone). Whether it puts up a WINDOW is
  a boot decision — `\Registry\Machine\Hardware\qemu` "Gui", HACK-006 — but
  whether it LOADS the stack is not: an import table is resolved at load. So
  `win32u`, `winefb.drv` and `wineserver-lite` come up, and a desktop is
  created, on a boot whose only console is the serial wire.

  This is resident cost, and with no eviction (Art. 3) it never comes back:
  **132 MB**, measured at the `cui9` leg's pinned 512M console boot (466 MB
  free before, 334 MB after — docs/17 §1, which carries the table). Nothing
  observable at the boundary changes; what changes is how much machine is left
  for the thing the boot was started to do, which is why `tools/qemu.sh`'s
  default guest memory went from 256M to 384M in the same change.

  Reclaiming it means conhost not IMPORTING what a serial boot will not call —
  delay-loading `user32`/`gdi32` (95 functions across the two) or splitting
  `window.c` into a module loaded when "Gui" says so. Both are Wine-fork
  surface (Art. 10) rather than kernel work, and neither is a boundary
  question, so neither is done here. Restoring the CUI-only stand-ins is not
  the answer: two builds of one program drift, which is the failure this whole
  change was made to end.

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
- **Console/std fixups mirror `server/process.c` `new_process` plus
  ntdll's `create_startup_info` subsystem gate** (M11): the console (and,
  without `PROCESS_CREATE_FLAGS_INHERIT_HANDLES`, the std handles) reach
  the child ONLY when the child image is `IMAGE_SUBSYSTEM_WINDOWS_CUI`
  (`dlls/ntdll/unix/env.c` 2164-2175, pinned by
  `sem_console/subsystem_gate`) — a GUI child gets no console even from a
  console-attached parent, which is what keeps GUI apps from ever
  spawning a conhost. Within that gate: a real (positive) `ConsoleHandle`
  is re-duplicated to a fresh child handle (the child is NOT bound here —
  it binds itself through its Connection open, the one binding
  authority); the `CONSOLE_HANDLE_ALLOC*` sentinels and 0 pass through
  untouched and now reach stock kernelbase's `alloc_console`; without an
  inherit, the three std handles are duplicated (invalid values
  tolerated) only for a CUI child not steered by `STARTF_USESTDHANDLES`.
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
    IS the shared page, and here it runs AHEAD of it — by up to one tick
    while the tick is on schedule, by up to the late time while a clock
    interrupt is delayed (capped at `KI_MAX_FRACTION_TICKS` = 40 ms).** The
    page stays tick-granular — a mirror published once per tick cannot be
    refreshed by writing an interpolated value into it — so the two readings
    no longer coincide, and `GetSystemTimeAsFileTime`, the *coarse* getter on
    Windows, is sub-tick here because Wine routes it to the same syscall
    (`dlls/kernelbase/file.c`). What makes the trade acceptable is that the
    gap has a bound and a direction (query ≥ page), and every
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
  - **Only the clamp is load-bearing, not the TSC's quality.** The fraction
    is capped at `KI_MAX_FRACTION_TICKS` (40 ticks), and each tick re-bases
    it by the whole ticks it publishes (`KiTicksElapsed`), so tick + fraction
    is one continuous measurement of one TSC delta — monotone across the
    tick — and a lying counter mis-places a reading by at most 40 ms before
    the next tick corrects it. The cap used to be a single tick, which FROZE
    the query clock whenever a clock interrupt was late (a loaded CI host
    delivers ticks milliseconds late): every query in the window answered
    the same saturated value and the catch-up tick then published the
    backlog as one ≥ 1 ms step — the recurring `kernel32:time` `time.c:843`
    CI flake. Convicted deterministically by `tests/kmt/m2_dispatcher.c`
    `test_query_time_spans_late_ticks`, which holds the tick off and
    requires the query clock to keep moving. 40 and not more because of the
    50 ms `todo_wine_if` ceiling above: the query-ahead-of-page gap must
    stay inside `time.c:458`'s tolerance arm even mid-stall, so the fraction
    stops 10 ms short of it, and a tick later than 40 ms re-enters the
    freeze-then-step regime only past 41 ms of lateness — where the old
    clamp entered it at two. No invariant-TSC test is made, and none is needed.
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
  GUI trophy, its own `manifest-gui.txt` + `winetest-gui` leg). The bullets
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
- **And it is the SAME machine `make run` boots — amended.** The leg's
  image was assembled from its own hand-written list (the run.sh proskrnl
  set: ten DLLs, smss, conhost, cmd) and had drifted into a shorter machine
  than the product's: no `wineboot.exe`, so smss skipped firstboot and the
  sweep ran against a registry that had never seen `wine.inf`'s
  machine-state payload; no SCM (`services`/`rpcss`/`sc`); no
  `setupapi`/`cfgmgr32`/`ws2_32`/`secur32`/`userenv`/`hid` beside test
  binaries that import them. A differential leg can only spend such a
  difference as a divergence — the win.ini finding below is one that was
  chased down to exactly this cause — so the one image the leg boots carries
  the Makefile's own `$(WINFILES)` (one list, one authority, Art. 11; the
  `make print-winfiles` hand-off that let run.sh bake its own image is gone
  with the per-leg images) plus this leg's payload: the wtest binaries and
  manifests, the full nls set, tzres, the .ini furniture, and the WOW64 guest
  set `ntdll:wow64` spawns children out of.
  `[SystemIni]` remains the one part of `wineboot --init` no proskrnl image
  gets — `tools/filter_inf.py` drops `UpdateInis=` (its failure on absent
  source media would abort the AddReg pass behind it) — so
  `tools/gen_sysini.py` still stages `win.ini`/`system.ini` here.
  **Measured** (kernel-side sweep, 52 active pairs): firstboot PASSes on this
  image and 51 pairs are unchanged-green; the one pair the deeper machine
  moves is `kernel32:environ`, and it moved because the sweep can now REACH a
  check it used to skip — `test_Predefined` resolves
  `GetUserProfileDirectoryA` out of `userenv.dll`, which the short list did
  not bake. It failed on machine state no CUI image has (the `ProfileList`
  values wineboot writes through *shell32*, which is off the image by Art. 7)
  — a gap the old image was hiding, not one this change introduced. That state
  is seeded now (the user-profile entry below) and the pair is GREEN and in the
  gate.
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
- **The USER PROFILE is seeded, and it is THREE statements of one fact that
  have to agree.** `HKLM\…\CurrentVersion\ProfileList` gets
  `ProfilesDirectory` = `C:\users` (`REG_EXPAND_SZ`, the type and the value
  shell32's `_SHGetProfilesValue` writes into the oracle's prefix) and, under
  a subkey named by the fixed Se identity's SID, `ProfileImagePath` =
  `C:\users\wine` (`REG_SZ`, wineboot's `update_user_profile`);
  `kernel/ps/peb.c`'s default environment gets `USERPROFILE=C:\users\wine`;
  and `tools/mkimage.sh` bakes the directory. **The three cannot be split**:
  userenv's `GetUserProfileDirectoryW` *composes* its answer as
  `ProfilesDirectory` + `\` + the account name, `kernel32:environ`'s
  `test_Predefined` asserts that answer equals `%USERPROFILE%`, and the
  account name is `WINEUSERNAME` (advapi32's `GetUserNameW` is an environment
  read, and `LookupAccountSidW`'s RID-1000 arm calls it) — which the same
  default environment already fixes at `wine`. Seeding the key alone would
  have moved the pair's failure from "no profile directory" to "the two
  disagree" and changed nothing about the count.
  **`Flags` beside `ProfileImagePath` is deliberately absent** and so are
  `Public`/`ProgramData` beside `ProfilesDirectory`: nothing in the baked
  stack reads them (Art. 5), and on the oracle the last two also mint
  `ALLUSERSPROFILE`/`PUBLIC` environment variables out of the half of ntdll
  proskrnl replaces (`dlls/ntdll/unix/env.c` `add_registry_environment`), so
  seeding them without the directories and the variables would describe
  folders that are not there. Pinned by
  `tests/ntapi/sem_reg/user_profile.c` — which accepts either string type for
  `ProfilesDirectory` on purpose: `GetProfilesDirectoryW` expands whatever it
  finds and no consumer reads the type, so `REG_EXPAND_SZ` above is
  provenance rather than a contract. docs/21 W17.
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
  - *(a) proskrnl does not implement the surface the pair needs*, by a
    decision or a backlog recorded elsewhere. `ntdll:alpc` (the LPC/ALPC
    surface stays unbuilt because the local-RPC transport is npfs — "CUI-3
    SCM notes" above) and `kernel32:debugger` (the debug event queue —
    once ADR 0011's permanent refusal, now backlog since that ADR was
    deprecated, so
    this pair parks as a *pending* consumer, not a disqualified one, and
    un-parks when the queue lands). Both are GREEN on the
    oracle and both panic on proskrnl's first missing syscall, which is the
    armed-panic contract working rather than a defect to chase. Leaving
    them in would make the gate red on purpose.
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
  pass),
  `UpdateInis` (`SPINST_INIFILES` runs *before* `SPINST_REGISTRY`;
  `BaseInstall` opens with `UpdateInis=SystemIni`, and a failure there returns
  FALSE before its ~500-line AddReg ever runs), and `ProfileItems` (Start Menu
  shortcuts via shell32). All `AddReg`/`DelReg` and the `.Services` sections
  are kept. The INF is input data staged by the image builder — no Wine
  PE-side change.

  `RegisterDlls` was a sixth dropped family — self-registration loads DLLs a
  CUI disk did not bake — and is **kept** since one image began carrying every
  leg's payload: shell32's COM classes are what explorer's file window is
  (GUI-6) and mmdevapi's are what `CoCreateInstance` of the MMDeviceEnumerator
  needs (AUD-2), and both are injected into `[RegisterDllsSection]` rather than
  hand-seeded as CLSIDs (Art. 11 / G8). Of the section's 30 entries exactly
  shell32, mmdevapi and dsound resolve on the disk; the rest fail
  `LoadLibrary` and are skipped one by one (`setupapi do_register_dll` — a
  skip, not an abort). There were three baked infs, one per image family; there
  are two, and which one a boot installs is the `Gui` flag rather than the
  media: a boot with a desktop keeps the full payload, and a CUI-only boot
  swaps in the registry-only one (`user/smss/firstboot.c FirstbootInstallInf`),
  because `[RegisterDllsSection]` on a machine with no desktop is ~150
  processes failing their way through `CreateWindow`.
- **The registry differential** (`tests/run/run.sh firstboot`, the milestone's
  Art. 6 conviction gate) boots a virgin image, pulls the SYSTEM hive off the
  FAT volume, and compares it against a fresh oracle prefix initialized with
  the SAME filtered INF, staged over the pinned tree's `loader/wine.inf` for
  that one prefix init (restored after; `--keep WineFakeDlls`, because fake
  dlls write no registry but a prefix without them cannot launch any
  non-bootstrap process, and on the host their sources exist; `RegisterDlls`
  is NOT kept there, and its output is out of the compared scope in
  consequence — see the exclusion note below). The compared
  scope is derived FROM the filtered INF itself (`tests/run/regdiff.py`
  parses the reachable AddReg sections): every payload key/value must match
  exactly on both sides, and the hive must contain nothing beyond payload +
  documented writers. Oracle-only state outside the payload (each fake
  dll's embedded REGINST registration resource, wineserver furniture) stays
  out of scope by construction; every other exclusion is written down in
  `regdiff.py` and here.
- **Self-registration output is out of the compared scope**, and that is
  measured rather than assumed. The guest's firstboot now runs shell32's,
  mmdevapi's and dsound's own `DllRegisterServer` (the kept `RegisterDlls`
  above), which writes ~120 `Explorer\FolderDescriptions` keys plus
  `ProfileList`'s `ProgramData`/`Public` — all absent from the oracle prefix,
  reading as 122 "unexpected key/value" divergences in the extras sweep.
  Keeping the directive on the ORACLE side to make the two payloads identical
  does not work: the prefix has all 30 fake dlls to register instead of the
  three the disk carries, and its `InstallHinfSection` **wedges** (rundll32 at
  0% CPU for 18 minutes, no verdict). So the payload is excluded by name in
  `regdiff.py`, the mirror of the oracle-only REGINST exclusion above. What
  stays in scope is the whole `AddReg` machine-state payload, which is what
  CUI-1 is about — including every CLSID key `wine.inf` writes; only the
  `ShellFolder` child shell32's registrar adds to seven of them is out (as a
  suffix RULE, so a pin that registers an eighth is not a divergence).
  `Software\Microsoft\AudioCompressionManager` goes with them for a
  neighbouring reason: it is msacm32's driver CACHE, built the first time
  anything enumerates the baked `.acm` codecs (`MSACM_ReadCache`, reached
  through the dsound/mmdevapi registration), and the oracle's prefix has
  those modules as fake dlls it never enumerates. With the four families
  excluded the differential is **0 divergences** on a 195-key / 345-value
  scope.
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
`tests/ntapi/sem_reg/{reg_rename,notify,save_load,restore_setinfo}.c`,
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
  still refuse loudly with `STATUS_NOT_IMPLEMENTED` (Art. 12): mapping a section INTO
  a placeholder is a second, larger contract and no baked consumer reaches it. (This
  used to cite `SEC_RESERVE` as its precedent; that one is built — see "A
  `SEC_RESERVE` section's commit ledger" below.) `NtCreateSectionEx`'s parameter array is
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
- **npfs data READS now pend on an asynchronous handle; WRITES still block**
  (`fs/npfs/pipe.c`). The read half is built and is a pin, not a deviation:
  a read an asynchronous handle cannot serve parks an `IOP_PENDING_REQUEST`
  on the END and answers `STATUS_PENDING` with the caller's IOSB and buffer
  untouched; the peer's write, a state change, `NtCancelIoFile` or the
  handle's own cleanup completes it. Pinned by `sem_pipe/pended_read.c`.
  The engine grew the buffer/length legs `kernel/io/io.h` anticipated
  (`docs/19` §5d) rather than a fourth bookkeeping shape: the bounce
  `kernel/io/rw.c` already allocated becomes the request's, and the bytes go
  into the owner's address space through `MiCopyToUserRangeChecked`
  immediately before the IOSB.
  **What it was, and why the shape matters:** parking the CALLING thread was
  a deadlock rather than a latency, because the standard overlapped idiom
  satisfies its own read from the same thread — `ntdll:pipe` issues the read
  at `pipe.c:1578` and writes at `:1583`, and that one line wedged the pair
  for three milestones (`docs/21` W4c). `kernel32:virtual`'s `test_write_watch`
  and `kernel32:pipe`'s overlapped echo server are the same shape.
  **Still blocking, deliberately:** a WRITE over quota on an asynchronous
  handle parks its caller, because no measured consumer convicts it (Art. 5)
  — the pipes the winetest pairs drive have room. Escalation: the same
  treatment on the outgoing queue, keyed on the peer's read freeing quota,
  the day a pair or a baked caller shows it.
- **A pended request leaves the FILE OBJECT unsignalled, and exactly one of
  the event or the object is signalled at completion** (`kernel/io/async.c`
  `IopMarkRequestOutstanding` / `IopSignalRequestCompletion`, one authority
  the directory-watch engine now shares). Transcribed from the oracle:
  `queue_async` does `set_fd_signaled( async->fd, 0 )` for every non-system
  async — whether or not an event was also supplied, which is the part that
  matters here — and `async_set_result` does `if (async->event)
  set_event(...); else if (async->fd) set_fd_signaled( ..., 1 )`. A consequence that reads as a bug
  and is the contract: a read that pended WITH an event leaves the handle
  unsignalled through its own completion. `ntdll:pipe` measures it
  (`pipe.c:1607-:1617`); pinned by `sem_pipe/pended_read.c`.
- **A BLOCKING request owes the same two things** (`kernel/io/async.c`
  `IopBeginBlockingRequest` / `IopEndBlockingRequest`, driven from
  `kernel/io/rw.c`'s device branch and its flush) — a pin, not a deviation;
  the condrv exemption it rests on has its own bullet below.
  The oracle queues a blocking async through exactly the same code and
  `async->blocking = !is_fd_overlapped( fd )` (`create_async`) decides only
  how the CALLER waits, so a synchronous pipe read resets the caller's event
  at issue, takes the handle down for the duration, and puts exactly one of
  the two back up. `NtFlushBuffersFile` is in scope for the same reason and
  can only ever take the file-object arm (it has no event parameter).
  Pinned by `sem_pipe/blocking_signal.c`; `ntdll:pipe`'s `test_blocking` is
  the winetest consumer (`pipe.c:1740`/`:1742`/`:1753`, and the `todo_wine`
  at `:1829` that a kernel which never clears the handle PASSES).

  Two parts of it are not derivable from the rule's statement, and both were
  got wrong in a first draft that no winetest assertion could convict:

  - **What a FAILING request owes depends on whether it was QUEUED.** One
    that parked reaches `async_set_result`'s signal block even though it
    failed (`async->pending || !NT_ERROR( status )`) and takes the same
    event-or-handle arm a success takes — *so a failing read SIGNALS the
    caller's event*, the opposite of the direct-fd path's
    `if (status != STATUS_PENDING && event) NtResetEvent`. One the device
    refused above `queue_async` reaches nothing: the handle keeps whatever
    state it had and the event stays reset. `KTHREAD.syncIoParked`, set by
    `IoWaitCancellable`, is the engine's own answer — set where the park
    happens, so no device has to remember to report it (the argument
    `IO_CONTROL_CONTEXT.pended` already makes below). The WRITE direction
    carries the same rule and reached it through a different tail, whose
    unconditional `IopAbandonRequest` reset the event the engine had just
    set; `eventSettled` (`kernel/io/rw.c`) is what stops that, and
    `blocking_signal.c`'s quota-blocked write is what convicts it.
  - **The event reset and the handle clear are merged at issue**, where the
    oracle has them a frame apart (`create_async` above the device's state
    checks, `queue_async` below them). The split is observable only for the
    refusal case, and `IopRequestRefused` RESTORES the handle to what
    `IopBeginBlockingRequest` found — which is not the same as signalling it:
    a read that completed through an event left the handle DOWN, and a
    refusal that follows must leave it there. Measuring the refusal against a
    fresh (born-signalled) handle cannot tell the two apart, which is why
    `blocking_signal.c` has a case that refuses on a handle already down.
- **condrv's file objects are EXEMPT from the signalled-state rule**
  (`FILE_OBJECT.deviceManagedSignal`, honoured in `kernel/io/async.c`
  `IopFileSignalSuppressed`) — a deviation, and it is the residue of a larger
  one. NT counts no outstanding requests, so ANY completion on a handle puts
  it back up; proskrnl used to skip that for EVERY device, because **condrv
  borrows the file object as its own readiness signal** (`drivers/condrv.c`
  `CondrvSignalServer`; `CondrvServerRead` CLEARS it when the request queue
  empties) and re-signalling on the very read that drained the queue re-arms
  conhost's park and spins its poll loop — measured, at the cost of
  `kernel32:virtual`'s run. Declaring the borrowing on the FILE_OBJECT instead
  narrows the deviation to condrv's own three opens and lets every other
  device have the NT rule; `ntdll:pipe:1678`, the one assertion the old form
  cost, passes. Nothing pins the exemption, because nothing but conhost holds
  a console server handle and the input/output opens' `header` is managed by
  nobody at all (they stay permanently signalled, as before this change).
  **Escalation is unchanged and now smaller**: give condrv an event of its
  own and delete the field.
- **"The device pended" is a FLAG, not a status** (`kernel/io/vfs.h`
  `IO_CONTROL_CONTEXT.pended`, set by `IopPreparePendingRequest` itself) —
  NT's `IoMarkIrpPending`, and for NT's reason. `STATUS_PENDING` as a
  *status* is ambiguous here: `CondrvServerRead` returns it as a FINAL
  answer meaning "nothing deliverable, wait on the handle", IOSB written and
  buffers freed. Keying the read path's early return on the status leaked
  conhost's bounce buffer on every poll of an idle console, and the pool
  exhaustion behind that surfaced as a 3x per-process memory regression in
  the `cui9` ceiling (319 -> 79 processes) — a symptom with no visible
  connection to its cause. The flag is set by the ENGINE at the one place a
  park is created, so no device can park and forget to say so.
- **A pended read whose owner unmapped its buffer completes SUCCESS with the
  byte count and no bytes** (`kernel/io/async.c` `IopCompletePendingRequest`,
  the `MiCopyToUserRangeChecked` leg). Same shape and same reason as the IOSB
  write beside it: the completer is another process's thread, the transfer
  HAS happened by then, and a ring-0 fault on a vanished user page would
  unwind past every cleanup. NT would raise on the caller instead. No baked
  consumer unmaps a buffer under a pended read; recorded so the answer is a
  decision rather than an accident.
- **`FILE_SKIP_SET_EVENT_ON_HANDLE` FREEZES the file object's signalled
  state** (`kernel/io/async.c` `IopFileSignalSuppressed`) — a pin, and it
  supersedes this document's earlier "stored and reported back, unbuilt".
  The oracle puts the guard inside the transition (`server/fd.c`
  `set_fd_signaled`: `if (fd->comp_flags & FILE_SKIP_SET_EVENT_ON_HANDLE)
  return;`) and clears the handle in `set_fd_completion_mode` BEFORE
  recording the bit — so the ORDER is the content: the one clear that ever
  happens is that one, and the handle is unsignalled for the rest of its
  life. Written the other way round the clear is a no-op and the handle
  stays signalled forever, the exact inverse. The caller's own event is
  untouched by any of it. Pinned by `sem_pipe/pended_read.c`;
  `ntdll:pipe` `pipe.c:1680-:1702` is the winetest consumer.
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

## Debug objects: attach is built, the event queue is unbuilt (ADR 0011 deprecated)

**Read this section through its note at the bottom.** The reasoning below is
CUI-4's, and its conclusion — that the family is *permanently* out of scope — no
longer holds: attach was carved out at WOW64, and post-CUI-9 the event queue is
in scope and unbuilt. **ADR 0011 is deprecated**, not a live decision; this
section is where the subject lives now. The original argument is kept in full
rather than rewritten, because how it failed is the useful part.

The `NtCreateDebugObject` family — `NtDebugActiveProcess`, `NtDebugContinue`,
`NtRemoveProcessDebug`, `NtWaitForDebugEvent`, `NtSetInformationDebugObject` — was
CUI-4's stretch goal; it was not taken, and it was ruled **permanently out of
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

**What is actually true now (ADR 0011 deprecated, post-CUI-9).** Attach is
**built** — `NtCreateDebugObject`, `NtDebugActiveProcess`, `NtRemoveProcessDebug`
and the `BeingDebugged` flag they move, pinned by
`tests/ntapi/sem_ps/debug_attach.c` (the WOW64 carve-out). The **event queue** —
`NtWaitForDebugEvent`, `NtDebugContinue`, `NtSetInformationDebugObject`,
`DEBUG_PROCESS` at create — is **unbuilt, in scope**: it still refuses loudly and
is not scheduled, but it is backlog, not exclusion.

Both bullets above failed on measurement rather than on argument, which is why
they are kept. "No baked consumer" was falsified twice — `ntdll:wow64` at WOW64,
then `kernel32_test.exe:debugger`, parked in `tests/winetest/manifest.txt` citing
this entry and green on the oracle. The symbol-toolchain bullet is about a
debugger *ecosystem*, not about whether the three syscalls have an observable
contract at the boundary. And the pinned Wine tree implements all three through
wineserver (`unix/sync.c` `wait_debug_event` / `set_debug_obj_info`,
`unix/process.c` `continue_debug_event`), so an Art. 5 pin is available before
any kernel code (`docs/16`).

**The constraint that survives is G11, not scope** — this is the part of the old
ADR worth keeping, and it lives here now rather than there. The event queue is a
scheduling contract: every debuggee thread blocks until a debugger answers.
Building it must extend the dispatcher's own wait/wake — one stop/continue
authority, never a parallel scheduler — with each new parking point declared in
`tools/blocking_frontier.txt` in the same commit (G14), which re-opens
`docs/20` §8.4's checklist for it. That is a constraint on *how*, not a decision
about *whether*.

Unchanged and still out of scope: the kernel-debug control pair
(`NtSystemDebugControl`, `NtSetDebugFilterState`). Not debug-object surface, no
consumer, and Wine stubs both — one fabricating `STATUS_SUCCESS`, the other a
hardwired `STATUS_DEBUGGER_INACTIVE` — so there is no oracle either way
(`docs/16`). That exclusion never rested on the reasoning above.

The full accounting of which missing syscalls are out of scope vs. planned is
`docs/16-syscall-status.md`.

## Panic-on-STATUS_NOT_IMPLEMENTED boot (Art. 12 dialed to fatal)

- **Every boot under QEMU is armed by default.** The switch is
  `\Registry\Machine\Hardware\qemu` `"PanicOnNotImplemented"`, seeded at
  `CmInitialize` from the fw_cfg item `opt/org.proskrnl/panic_not_implemented`
  and defaulting to **on** when the device is present but the item is absent
  (docs/10 HACK-006). It used to be a marker file baked onto every image, so
  the coverage is unchanged — but it is now a property of running under QEMU
  rather than of the image or of the launcher, so a hand-rolled `qemu` line
  gets the net too. `tools/qemu.sh PANIC_NOTIMPL=0` passes `string=0` to opt
  out; a kernel that finds **no fw_cfg device** defaults it off, that being
  the one case that is not a development VM. While armed
  (`kernel/init/main.c KiConfigurePanicOnNotImplemented`), a ring-3
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

## Which region the guard-page fault path GROWS, and the guarantee it does not honour

A guard-page touch has two answers — GROW (clear the guard, commit a fresh guard one page
down, publish the new `NT_TIB.StackLimit`) or REFUSE (clear the guard, raise
`STATUS_GUARD_PAGE_VIOLATION`) — and which one a page gets turns on a single question: is
this address inside THIS THREAD'S STACK. **The TEB answers it, and nothing else does.**
`is_inside_thread_stack` (`dlls/ntdll/unix/virtual.c`) reads `DeallocationStack` and
`Tib.StackBase` out of the TEB and tests `ptr > start && ptr <= end` against the fault
address rounded down to its page; `MiHandleUserFault` does the same, through
`MipReadUserPointer` on the FAULTING thread's TEB. Pinned by
`tests/ntapi/sem_mm/teb_stack_growth.c` (`docs/21` W20).

Nothing deviates, and the reason it is written down is that the obvious alternative looks
better and is wrong. The kernel knows where it put every stack
(`ETHREAD.stackAllocationBase`/`stackBase`), and answering from that record agrees with the
oracle for every stack the kernel made — while refusing every stack USER MODE made. User
mode makes them: `SwitchToFiber` swaps these three fields on every switch
(`dlls/kernelbase/thread.c`), and `kernel32:virtual`'s `test_stack_commit` reserves 4 MiB,
commits one `PAGE_GUARD` page at the top, points the TEB at it and runs a function there.

**Believing the TEB grants nothing, which is what makes it safe to believe.** The whole
action is committing one page of the caller's own address space and writing the caller's own
TEB — both things the caller can do for itself with `NtAllocateVirtualMemory`. So this is not
the kernel trusting user mode about a privilege; it is the kernel letting a process define
its own stack, which is the only definition NT has.

Two edges come with it, both pinned because an implementation gets them wrong by writing the
tidier half-open range:

- the LOW edge is exclusive — `DeallocationStack`'s own page is *not* inside the stack, so a
  guard there is refused rather than grown (it is also what makes the new guard's placement
  total: `page > start` and both page-aligned means `page - PAGE_SIZE` is never below the
  reservation);
- the HIGH edge is INCLUSIVE — a fault page at `StackBase` itself, one page above the last
  byte the stack can hold, still grows.

**What is deliberately not built is the guaranteed space.** The oracle's `grow_thread_stack`
splits on `page >= start + page_size + max(TEB.GuaranteedStackBytes, 2 * page_size)`: above
that it pushes the next guard, and below it commits the whole guarantee in one go, sets
`StackLimit` to `start + page_size` and returns **`STATUS_STACK_OVERFLOW`**. proskrnl always
takes the first arm: the guard walks all the way down and the reserve then runs out as an
ordinary access violation. Two consequences to expect, since the arm's absence is visible
before the death — the last guard is committed **at `DeallocationStack`'s own page**, where
the oracle leaves page zero `MEM_RESERVE` for good (`sem_ps/teb_stack.c` asserts that state
for a live thread's stack, and no thread has ever grown that far), and the growth into the
guarantee says so on serial rather than diverging quietly (`[USERFAULT] stack growth …
inside the guaranteed space`; the printed bound is the FLOOR of the oracle's split, so a
thread that called `SetThreadStackGuarantee` crosses earlier and silently). This is
measured, not assumed: the pin's first draft used a
region small enough that its touch landed inside the guarantee, and the oracle answered
`STATUS_STACK_OVERFLOW` where the draft expected silent growth. The pin's cases now sit well
clear of that floor and count the code separately so they cannot drift back into it. Nothing
in the CUI frontier convicts the arm (`test_stack_commit` stops four pages above the base,
one page above where the guarantee begins), so it stays unbuilt under Art. 5 rather than
being written blind.

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

**The SECTION half of the same bit is built too, and it is the next section's subject.** A
section created with `SEC_NOCACHE` keeps the flag, and every view of it reports
`PAGE_NOCACHE` — `MiCreateMappedVad` sets the same `MI_VAD.noCache` from the section's
attribute word, so the report site is unchanged and there is one statement of what the bit
means.

## The `SEC_*` modifier flags on a section

`SEC_NOCACHE`, `SEC_WRITECOMBINE` and `SEC_LARGE_PAGES` are not three flags with three
answers. They are read by **one** twenty-line function — `third_party/wine`
`server/mapping.c` `get_mapping_flags` — which decides three separate things at once, and an
implementation can satisfy any two of them while failing the third. Nothing deviates; the
function is transcribed as `MipMappingFlags` (`kernel/mm/section.c`), pinned by
`tests/ntapi/sem_mm/section_sec_flags.c`.

**1 — which combinations refuse.** Neither modifier is uniformly legal or uniformly illegal:

| section kind | `SEC_NOCACHE` | `SEC_WRITECOMBINE` | `SEC_LARGE_PAGES` |
|---|---|---|---|
| anonymous `SEC_COMMIT` | kept | kept | **kept** |
| anonymous `SEC_RESERVE` | kept | kept | `STATUS_INVALID_PARAMETER` |
| file-backed (either kind) | kept | kept | `STATUS_INVALID_PARAMETER` |
| `SEC_IMAGE` | accepted, **dropped** | `STATUS_INVALID_PARAMETER` | `STATUS_INVALID_PARAMETER` |

The anonymous-`SEC_COMMIT` row is the one no winetest asks: it is the single arm that
`return`s *above* the `SEC_LARGE_PAGES` guard, so the same word that succeeds there refuses
the moment a file handle is named. "`SEC_LARGE_PAGES` is unsupported" as one rule passes the
whole of `kernel32:virtual`'s 44-row matrix and diverges exactly there.

**2 — which bits survive, and it differs by arm.** An anonymous section keeps the caller's
word **whole** (the oracle's literal `return flags`, unknown bits included); a file-backed
one reports `SEC_FILE` in place of the kind it was asked for plus
`flags & (SEC_NOCACHE | SEC_WRITECOMBINE)` and nothing else; an image reports
`SEC_FILE | SEC_IMAGE` and keeps neither modifier. `SEC_IMAGE | SEC_NOCACHE` is therefore the
one accepted-and-not-kept combination on the surface, and it is what separates an
implementation that reads the section's **resolved** attributes from one that reads the flags
its caller passed — both answer every other case here.

**3 — where the check sits.** `get_mapping_flags` runs above `create_mapping`'s
`get_file_obj`, so a refused combination is reported for a file handle that names nothing:
`SEC_COMMIT | SEC_LARGE_PAGES` with a junk handle is `STATUS_INVALID_PARAMETER`, while
`SEC_COMMIT` alone with the same handle is `STATUS_INVALID_HANDLE`. `NtCreateSection` calls
`MipMappingFlags` before it resolves the backing for that reason and `MipBuildSection` calls
it again for the answer — the same "validate the arguments *after* resolving the object is
what NT does" shape as `NtProtectVirtualMemory`'s ladder above.

**And exactly one of the kept bits is readable afterwards.** A view's protect word is the
section's resolved flags (`dlls/ntdll/unix/virtual.c` `virtual_map_section`:
`vprot |= sec_flags`), and `get_win32_prot` reads one modifier back out of it —
`if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;`. So `SEC_NOCACHE` decorates every page's
`Protect` and the view's `AllocationProtect`, survives a re-protect that splits the view, and
appears in the `*old_prot` a re-protect reports; `SEC_WRITECOMBINE` is kept by the section
and read by nothing. An implementation that decorates the reported protection with every
modifier it kept fails only the `SEC_WRITECOMBINE` view.

It was 24 of `kernel32:virtual`'s 25 remaining failures — and the 17 assertions behind that
pair's `if (section_info.Attributes & SEC_NOCACHE)` gate (`virtual.c:1017`) had never run,
because the gate reads the value rule 2 was getting wrong. They all pass.

## A partial `NtWriteVirtualMemory` reports the bytes it wrote

`NtWriteVirtualMemory` and `NtReadVirtualMemory` both answer `STATUS_PARTIAL_COPY` when the
range runs into memory they cannot touch, and they report **different** counts. The
asymmetry is upstream's and it is on the PE side (`dlls/ntdll/unix/virtual.c`): the write
keeps the server's count unconditionally (`size = reply->written;`) while the read throws it
away (`if ((status = wine_server_call( req ))) size = 0;`). The server's number is a byte
count off `process_vm_writev`, not a page count (`server/ptrace.c`
`write_process_memory_vm`: `*written = max( len, 0 )`), so a write that starts mid-page and
runs into a read-only page reports the bytes up to that page.

proskrnl reported zero for both, because the syscall wrote the caller's slot only on full
success — `kernel32:virtual:261`/`:275`. `MiCopyToUserRangeChecked` already returned the
byte-accurate count; only the reporting was missing. Nothing deviates; pinned by
`tests/ntapi/sem_ps/virtual_memory.c`, which measures the count through both handle arms and
in both alignments.

## What a REFUSED handle-producing call leaves in the caller's slot

A handle-producing `Nt*` call writes **0 into the caller's out-handle as its first act**,
above every validation, so a refusal leaves `NULL` there rather than whatever the caller
never initialized. The pinned oracle states it once per entry point, as that function's
opening statement (`*handle = 0;`): `dlls/ntdll/unix/sync.c` for the sync objects, the
namespace objects, the section and the completion port; `unix/file.c` for `NtCreateFile` and
`NtCreateNamedPipeFile` (`NtOpenFile` reaches it by tail-calling `NtCreateFile`, and proskrnl
states it at both entry points because its own `NtOpenFile` does not go through
`NtCreateFile`); `unix/registry.c` for `NtCreateKey` / `NtOpenKeyEx`;
`unix/process.c` and `unix/thread.c` for `NtOpenProcess` / `NtOpenThread`; `unix/security.c`
for the token opens and `NtDuplicateToken`; `unix/server.c` for `NtDuplicateObject`, which is
the one that **guards** the store (`if (dest) *dest = 0;`) because its out pointer is
optional.

Nothing deviates. It is recorded here because the rule is neither guessable nor uniform, and
because the cost of missing it is paid a long way from the syscall:

- **The consumer that depends on it is Win32, not the test suite.** `kernelbase`'s
  `CreateFileMappingW` (`dlls/kernelbase/sync.c`) declares `HANDLE ret;` uninitialized,
  passes `&ret` to `NtCreateSection` and `return ret`s on **every** path including the
  failing ones. A kernel that refuses correctly and leaves the slot alone therefore hands
  Win32 a stack-garbage `HANDLE` for a create that did not happen — and the caller then
  closes it, which closes whatever unrelated object that value names. 71 of
  `kernel32:virtual`'s 96 failures were that one omission.
- **It is a per-entry-point obligation, and three of the surface's creates do NOT have it.**
  `NtCreateThreadEx` (`unix/thread.c`) refuses `zero_bits` without touching `*handle`;
  `NtCreateUserProcess` (`unix/process.c`) builds into locals and assigns the caller's two
  slots on the success path only; `NtFilterToken` (`unix/security.c`) opens with its flags
  FIXME. So the clear cannot live in the system service dispatcher, nor in the shared
  create/open engine — an implementation that hoists it passes every positive case and
  diverges on those three.
- **One statement of it (Art. 11).** `ObpClearOutHandle` (`kernel/ob/handle.c`), beside
  `ObpCreateHandle`, which is already the one site that writes a handle out. It also
  subsumes the `if (handle == 0) return STATUS_ACCESS_VIOLATION;` prologue the entry points
  each carried, and the two hand-written copies of the rule that had appeared meanwhile
  (`kernel/cm/registry.c`'s `*keyHandle = 0;` and `kernel/se/token.c`'s `SepPreZeroHandle`).
  The NULL slot is refused inside it rather than left to the probe, because the probe is a
  no-op for a KernelMode caller and the store would then be a ring-0 write to address 0.

Pinned by `tests/ntapi/sem_ob/out_handle.c`, whose last two cases are the entry points that
must **not** clear.

## A magic pseudo-handle as a duplication SOURCE

`DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), …)` is the documented way to
turn the current-process pseudo-handle into a real one, and the source handle in it is in
nobody's handle table. A duplication that only knows how to look a handle up therefore
refuses the one call every consumer makes — `kernel32:virtual`'s `test_ReadProcessMemory`
opens with it, and `ERROR_INVALID_HANDLE` there took three assertions with it.

Nothing deviates. It is recorded because three of its four rules are stated somewhere other
than where they are needed, and each is invisible to a test that only checks the status:

- **The lookup ORDER is the content.** `get_handle_obj` (`third_party/wine`
  `server/handle.c`) tries `get_magic_handle` FIRST and the process's table second, so the
  magic values never reach a table at all. `kernel/ob/handle.c` states the list once
  (`ObpReferencePseudoHandle`) and both `ObReferenceObjectByHandle` and `NtDuplicateObject`
  ask it, because the server has exactly one such site too.
- **Every arm names something of the CALLING thread's, whatever process the caller named.**
  `get_magic_handle` resolves against `current` and takes no process argument, so
  `NtDuplicateObject(childProcess, NtCurrentProcess(), …)` yields a handle to the CALLER's
  process, not the child's. Measured, not inferred (`sem_ob/dup_cross_process`).
- **A pseudo source has no recorded rights, so the server SYNTHESIZES them**:
  `map_access( obj, GENERIC_ALL )`, commented "pseudo-handle, give it full access". That is
  the `DUPLICATE_SAME_ACCESS` value only — a duplication naming specific rights still gets
  exactly those, because the access asked for is mapped independently. Its attributes come
  out of the same mask's reserved bits, i.e. none, which is what `DUPLICATE_SAME_ATTRIBUTES`
  copies when there is no entry to copy from.
- **`DUPLICATE_CLOSE_SOURCE` has nothing to close and must not say so.** The server closes
  unconditionally and DISCARDS the error (`dup_handle`: "close the handle no matter what
  happened", with `close_handle`'s return value dropped), which agrees with what Microsoft
  documents for a pseudo handle — "calling the CloseHandle function with a pseudo handle has
  no effect" (learn.microsoft.com, `GetCurrentProcess`). So the duplication succeeds.

Pinned by `tests/ntapi/sem_ob/dup_pseudo.c` and one case in `sem_ob/dup_cross_process.c`.

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

## Where a PE's section table may live, and what SizeOfHeaders means

`SizeOfHeaders` does **not** bound the section table. A linker rounds it up to
`FileAlignment` so the table always sits inside it and the question never
arises, but a hand-written PE may declare exactly
`sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)` and start its table on
the byte after the header region ends — and NT loads that image. The rule
`MiParseImage` (`kernel/mm/pecoff.c`) implements is the pinned oracle's, in
its order (`third_party/wine server/mapping.c` `get_image_params`, the "load
the section headers" block):

- the table is bounded by the **image** (`SizeOfImage`, page-rounded) and by
  the **file**, and a table past either is `STATUS_INVALID_FILE_FOR_SECTION` —
  not `STATUS_INVALID_IMAGE_FORMAT`, which is what proskrnl used to answer for
  both;
- where the table overruns `SizeOfHeaders`, **the header region grows** to
  cover it (`header_size = pos + size`). Nothing else about the image moves;
  in particular the segments are still required to start at or after the
  page-rounded header region, which is proskrnl's own commit-each-page-once
  structure (Art. 3) and not the oracle's rule.

**The growth is observable, which is why it is a behaviour and not an
implementation detail.** `dlls/ntdll/unix/virtual.c` `map_image_into_view`
zeroes the mapped view from `header_size` to the end of the header page before
mapping the sections over it (`memset( ptr + header_size, 0, header_end - (ptr
+ header_size) )`), so whether the section table is readable *in the view* is
exactly whether the header region grew — the bytes sit inside the first page
either way. proskrnl copies `sizeOfHeaders` bytes into freshly zeroed master
frames (`MipMasterCommitRange`), which is the same statement.

Convicted by the winetest gate: `kernel32:resource`'s `test_mui` builds such an
image by hand (`dlls/kernel32/tests/resource.c`, `dll_image` + `create_test_dll`)
and `GetFileMUIInfo` maps it with `LOAD_LIBRARY_AS_IMAGE_RESOURCE`, which is a
plain `CreateFileMapping(PAGE_READONLY | SEC_IMAGE)`. Refusing it produced
`ERROR_BAD_EXE_FORMAT` and 21 failures plus a fault. Pinned by
`tests/ntapi/sem_mm/image_section_table.c`.

**One residual, unpinned and pre-existing.** The oracle bounds the table by
`round_size(SizeOfImage, max(SectionAlignment - 1, page_mask))`, where
`MiParseImage` rounds `sizeOfImage` to `PAGE_SIZE` only. For an image whose
`SectionAlignment` exceeds a page the two bounds differ, so a table ending
between the 4K- and the `SectionAlignment`-rounded size is accepted by the
oracle and refused here. Nothing on either runner's stack builds such an image
— every module in the baked set uses `SectionAlignment == 0x1000` — so it has
never been reachable; the page rounding is used because it is the extent
proskrnl actually maps, and inventing a second rounding for the bound alone
would put two notions of the image's size in one function.

## A `SEC_RESERVE` section's commit ledger

`SEC_RESERVE` is the one section kind whose views are **not** committed by the map,
and NT keeps the commit record on the SECTION rather than on the view: a
`VirtualAlloc(MEM_COMMIT)` through one view commits those pages for *every* view of
that section, while each view keeps its own page protection. The pinned oracle
splits the two records in two places — `server/mapping.c` `create_mapping` hangs a
`create_ranges()` ledger off the mapping and each view grabs a reference to that one
object, and `dlls/ntdll/unix/virtual.c` `allocate_virtual_memory`'s commit arm calls
`set_protection( view, ... )` (this view only) beside `add_mapping_committed_range`
(shared). proskrnl keeps the same split: an anonymous section's frame array **is**
the ledger (`0` = uncommitted, `kernel/mm/section.h`) and `MI_SECTION.viewListHead`
names every live view, which is what lets one commit reach all of them. Pinned by
`tests/ntapi/sem_mm/reserve_section.c`.

`SEC_RESERVE` is also a property of an ANONYMOUS mapping only: handed a file handle
the oracle drops the flag whole and answers `SEC_FILE` (`get_mapping_flags`, whose
`SEC_COMMIT` case falls *through* into `SEC_RESERVE`), so a file-backed "reserve"
section is an ordinary fully-committed data section. An implementation that routed
the flag rather than the (handle, flag) pair builds a reserve section over a file and
diverges only there; the pin covers it.

Three consequences, none of them guessable from the flag's name:

- **A commit is EAGER in every view, not a promise redeemed at a fault.** Art. 3's
  "no demand paging" is a contract other code reads: a committed page is present, and
  `syscall/uaccess.c`'s page-table-walk probe depends on it. So
  `MiCommitReserveSectionRange` (`kernel/mm/virtual.c`) allocates the frames, writes
  them into the section's ledger, and maps them into every view *before the commit
  returns* — including views in other processes. NT would fault them in one at a
  time; nothing observable at the boundary separates the two, and the physical cost
  is paid earlier.
- **A `PAGE_WRITECOPY` view takes its private copy at commit time** — the same
  whole-copy rule the rest of the mapping surface uses (Art. 3, no COW outside
  `SEC_IMAGE`), applied at the moment the page comes into existence rather than at
  the map.
- **A commit that runs out of frames changes NOTHING** — unlike `MiCommitPages`,
  whose partial commit is NT's own shape for private memory. The difference is whose
  record it is: the ledger belongs to the *section*, and a half-filled ledger would
  have the views that already exist reporting `MEM_RESERVE` for pages a view mapped
  afterwards reports as `MEM_COMMIT` (the map takes its frames from the same array) —
  two views of one section disagreeing about State, which is the exact contract this
  feature implements. So `MiCommitReserveSectionRange` counts what it must create,
  gets all of it, and only then publishes; `STATUS_NO_MEMORY` leaves the section and
  every view as they were.

And one measured disagreement, which is why the pin deliberately asserts **nothing**
about it: **what an access to an uncommitted page of a reserve view does.** NT raises
`STATUS_ACCESS_VIOLATION`, and so does proskrnl — by construction rather than by
measurement, and the construction is the whole path: the page has no PTE, so
`MiHandleUserFault` (`kernel/mm/fault.c`) finds no write-fault to resolve and no
guard page, and returns the AV. The pinned ORACLE lets the read through —
`virtual_map_section` mmaps the whole view accessible under "file mappings must
always be accessible" and only tracks the commit state in software — so the two
authorities disagree and no assertion could be green on both legs (Art. 6). Recorded
here instead: proskrnl follows NT, and a test that pins it would be pinning the
oracle's mmap arrangement.

## What a pipe's `NtFlushBuffersFile` waits for

On a named pipe the flush is not a writeback — there is no cache to push. It is the
promise that **the call does not return until the PEER has consumed everything this
end wrote**, and that promise is what the `FlushFileBuffers`-then-`DisconnectNamedPipe`
idiom rests on: a disconnect DISCARDS whatever the peer has not read, so without the
wait the reply is thrown away before the peer ever sees it. The rule is
`server/named_pipe.c` `pipe_end_flush`, whose whole body is two guards, plus the wake
in `reselect_read_queue`. Implemented as `NpfsFlush` (`fs/npfs/pipe.c`) behind a new
optional `IO_VFS_OPS.Flush` slot; pinned by `tests/ntapi/sem_pipe/flush_buffers.c`.

| the end's situation | answer |
|---|---|
| connected, peer's queue empty | `STATUS_SUCCESS`, at once |
| connected, peer's queue has bytes | parks; `STATUS_SUCCESS` when the last byte is read |
| LISTENING (no peer at all) | `STATUS_SUCCESS`, at once — not `STATUS_PIPE_LISTENING` |
| peer's handle closed (CLOSING), bytes still queued | `STATUS_SUCCESS`, at once |
| this end was DISCONNECTED out from under it (a client) | `STATUS_PIPE_DISCONNECTED` |
| the server's OWN end, after its own disconnect | `STATUS_SUCCESS` |
| already PARKED when the server disconnects | `STATUS_PIPE_DISCONNECTED` |
| already PARKED when the peer closes | `STATUS_PIPE_BROKEN` |

Four things in that table are not derivable from the verb's name, and each is a way
an implementation reaching for the obvious guard diverges:

- **The queue it waits on is the PEER's**, i.e. this end's OUTGOING. A flush never
  waits for data somebody sent *us*.
- **The two ends do not answer alike after one disconnect.** `FSCTL_PIPE_DISCONNECT`
  clears the *client's* pipe pointer (`server->pipe_end.connection->pipe = NULL`)
  and leaves the server's own alone, so the client is `STATUS_PIPE_DISCONNECTED`
  while the server — which merely has no connection any more — is a success. A
  kernel that asks one "is this end disconnected" question answers both the same
  way; proskrnl's `NpfsEndDisconnected` is exactly that question, which is why the
  flush asks `end->pipe == 0` instead.
- **No connection means nothing to wait for, buffered bytes or not.** A listening
  instance and a closed peer are both immediate successes. An implementation that
  waits on the QUEUE alone hangs on the second one forever.
- **A parked flush's status is decided at the TRANSITION that satisfies it, not when
  the parked thread is next scheduled.** The oracle terminates the async inside the
  read that empties the queue; nothing that happens afterwards can change an answer
  already given. This is why `NPFS_QUEUE` carries a `drainSeq` rather than the flush
  re-reading the queue: a disconnect empties the queue too, so "is it empty now" cannot
  tell a drain from a disconnect — and once the peer has CLOSED, the state alone says
  `STATUS_PIPE_BROKEN` about a flush the drain had already completed. That is not a
  corner: `kernel32:pipe`'s echo servers read and close back to back, so all 24 of
  their flushes took the wrong branch of exactly this question.

**The defect this replaced is G12's shape without a stub in it.** `IopFlushBuffers`
answered `STATUS_SUCCESS` for every cache-less device, which is true of a console and
false of a pipe — a plausible no-op that nothing convicts until an ordering somewhere
else falls apart. It cost `kernel32:pipe` both of its synchronous echo servers
(`docs/21` W11).

**And the flush parks inside a synchronous-I/O span (`IopEnterSyncIo`), which is a
correctness requirement rather than bookkeeping.** proskrnl's cancel is a per-THREAD
flag (`KTHREAD.syncIoCancelled` + `syncIoCancelEvent`), and *only* `IopEnterSyncIo`
resets it, while `IoWaitCancellable` reads it unconditionally. So a park outside a
span gets the previous request's cancel — a thread whose blocking pipe read was
cancelled, then flushing, answered `STATUS_CANCELLED` to a caller that had asked for
nothing of the kind — and cannot itself be cancelled, because
`NtCancelSynchronousIoFile` requires `syncIoActive` and answers `STATUS_NOT_FOUND`
without it, leaving the flush parked with no way out. Both halves are observable
(the oracle's flush async is created blocking, `server/fd.c` `DECL_HANDLER(flush)` →
`async_handoff(async, NULL, 1)`, and `cancel_sync` matches every blocking async of the
target thread), both were measured on the kernel before the span was added, and both
are pinned. **The generalisable tell is that a per-thread flag makes every new
blocking point in the Io layer a place the previous request's state can leak into** —
the flush was the first blocking pipe operation whose wrapper had no span, and
nothing in the type system said so.

## The `FilePipeInformation` SET ladder, and where each rung lives

The class is two `ULONG`s — `ReadMode` and `CompletionMode` — and every one of the
twelve assertions `ntdll:pipe`'s `test_filepipeinfo` was failing (`:886-:989`) was a
guard that was missing or in the wrong PLACE. The ladder is split across the two
halves of the oracle, and the split is what decides which mistake gets reported:

| the caller's mistake | answer | decided in |
|---|---|---|
| buffer shorter than the class | `STATUS_INVALID_PARAMETER_3` | ntdll |
| any bit above the low one set in either field | `STATUS_INVALID_PARAMETER` | ntdll |
| handle names no pipe end (the npfs ROOT included) | `STATUS_OBJECT_TYPE_MISMATCH` | server |
| SERVER end, handle without `FILE_WRITE_ATTRIBUTES` | `STATUS_ACCESS_DENIED` | server |
| CLIENT end, handle without `FILE_WRITE_ATTRIBUTES` | **succeeds** | server |
| end a server DISCONNECTED out from under | `STATUS_PIPE_DISCONNECTED` | server |
| message read mode on a BYTE-type pipe | `STATUS_INVALID_PARAMETER` | server |

`dlls/ntdll/unix/file.c` `NtSetInformationFile`'s `case FilePipeInformation` owns the
first two; `server/named_pipe.c` `DECL_HANDLER(set_named_pipe_info)` owns the rest.
Landed in `kernel/io/query.c` (the two argument checks, above the handle) and
`fs/npfs/pipe.c` `NpfsSetPipeInfo` (the three the pipe object decides), pinned by
`tests/ntapi/sem_pipe/pipe_mode_set.c`.

Five things in that table are not derivable from the class's name, and each is a way
an implementation reaching for the tidy rule diverges while passing most of the pair:

- **The first two rungs run above the HANDLE**, because they are in ntdll and the
  handle only exists on the server side. So an out-of-range value passed through a
  handle that names nothing reports the *value*. proskrnl owns both halves at this
  seam (`docs/16`'s "replacing a layer means inheriting what that layer did"), so the
  ordering has to be reproduced rather than inherited.
- **A short buffer is `STATUS_INVALID_PARAMETER_3`, not the `INFO_LENGTH_MISMATCH`
  the QUERY direction gives for the very same class.** The query side is table-driven
  (`info_sizes[]`) and the set side is hand-written per class; the two disagree, and
  proskrnl's shared `needed`/`INFO_LENGTH_MISMATCH` path was the wrong one to be on.
  `FileCompletionInformation` already carried the same exception.
- **The value bound is `(CompletionMode | ReadMode) & ~1`, not "greater than 1".**
  Written as a `> 1` test on a signed field, `0x80000000` is admitted.
- **The SERVER end demands `FILE_WRITE_ATTRIBUTES` and the CLIENT end demands
  NOTHING**, and that asymmetry is nobody's stated rule — it falls out of how the
  handler finds the end. It looks the handle up as a server end *with* the access,
  and only a `STATUS_OBJECT_TYPE_MISMATCH` makes it retry as a client end with an
  access of **0**. `get_handle_obj` tests the type before the access
  (`server/handle.c`), so a client handle leaves the first lookup on the type with
  its access word never examined. This is why the check cannot be the class's
  required access in `kernel/io/query.c`, the way the query direction's
  `FILE_READ_ATTRIBUTES` is: which end this is is not knowable before the file object
  is resolved. npfs therefore learns the end from the file object and then resolves
  the caller's HANDLE a second time asking for the bit, so **Ob's one check site
  decides it** and the refusal is Ob's own. Reading `FILE_OBJECT.grantedAccess`
  instead answers a different question — that word is the access of the original
  OPEN, and `NtDuplicateObject` hands out handles to the same file object carrying
  less — which is why the pin weakens a duplicate as well as opening a weak client.
  The `SetPipeInfo` vfs slot takes the handle for exactly this reason.
- **The disconnect sits above the mode rule**, and it has to: an end with no pipe has
  no pipe TYPE to compare a message read mode against. `!pipe_end->pipe` is this
  end's own `pipe` pointer — the same identification "What a pipe's
  `NtFlushBuffersFile` waits for" already makes for this quantity, and with the same
  consequence that the server's own end is unaffected by its own disconnect.

**The root row is narrower than it reads, and the difference is recorded rather than
closed.** `\??\pipe\` opens as the oracle's `named_pipe_device_file`, matching neither
ops table, so both of the set handler's lookups leave on the type. The SET direction
now answers that; the QUERY direction reaches a different oracle path for the same
handle, is not measured, and still answers `STATUS_INVALID_DEVICE_REQUEST`.

**One thing about the disconnected end that the rungs above depend on**, convicted by
nothing today and left as it is (Art. 5): `NpfsDisconnect` takes the client's pipe in
`CLOSING_STATE` as well as in `CONNECTED_STATE`, where the oracle's
`FILE_PIPE_CLOSING_STATE` arm breaks without clearing `connection->pipe`. In this tree
`clientEnd` is already 0 in that state, so the two agree — but that is an inference, not
a measurement.

(The other thing this list used to carry — a client that outlived its server reading
`FilePipeLocalInformation` as zeros — is built; see "How long a pipe outlives its
NAME".)

**The QUERY direction carries the disconnect rule too, in both pipe classes**, and
`FilePipeLocalInformation` is the one that reads as a judgement call: it *has* a
`NamedPipeState` field, so answering `FILE_PIPE_DISCONNECTED_STATE` in it is the
plausible thing to do, and proskrnl did exactly that. The oracle refuses the whole
query (`pipe_end_get_file_info`, one `if (!pipe)` per arm, below each arm's access and
length guards). Only a query on an orphaned end can see it, and no winetest assertion
does; the pin does.

**Five of the twelve winetest assertions were CONSEQUENCES, and reading them as
findings points at a subsystem with nothing wrong with it.** `:888`, `:896`, `:907`,
`:918` and `:936` are all `Unexpected CompletionMode` out of the test's
`check_pipe_handle_state` helper — i.e. the QUERY direction reporting a wrong value.
The query was correct throughout: a set the kernel should have refused had really
changed the server end's mode, so every later read-back of that end was right about a
state that should never have existed (`docs/21` §4 trap 4).

## `FileAccessInformation` (class 8) asks Ob, and its length check is BELOW the handle

The class is one `ACCESS_MASK` and neither half of it follows from the name.

**The value is the HANDLE ENTRY's access, not the file object's.** The oracle answers
`info.AccessFlags = get_handle_access( current->process, handle )` (`server/fd.c`
`default_fd_get_file_info`), which reads `entry->access` — the word in the caller's own
handle table slot. `NtDuplicateObject` grants specific bits verbatim, so a weakened
duplicate names the same `FILE_OBJECT` through a smaller mask and reports the smaller
mask; a duplicate made with an access of **zero** is a legal handle and reports zero,
and the query still succeeds. `FILE_OBJECT.grantedAccess` is the OPEN's word and would
answer the create's mask for every handle that ever named the file. This is the same
distinction the `FilePipeInformation` SET ladder pays one section above — *"the access"
is ambiguous whenever more than one handle can name one object* — and `docs/21` W11's
own estimate ("the granted access of the handle, which `FILE_OBJECT.grantedAccess`
already holds") got the second clause wrong. `IopReferenceFileByHandle` grew Ob's
optional `OBJECT_HANDLE_INFORMATION` out-parameter for it, so the entry's word comes
from the one resolver rather than from a second lookup.

**The class demands no access at all.** `DECL_HANDLER(get_file_info)` resolves the fd
with a mask of 0, so a `SYNCHRONIZE`-only handle reads its own word back — which is
exactly what `ntdll:pipe`'s `_test_file_access(hClient, SYNCHRONIZE)` asserts, and what
separates this class from the two pipe classes in the same handler (`FILE_READ_ATTRIBUTES`).

**The length check runs BELOW the handle lookup, which is the inverse of every
table-driven class.** `info_sizes[FileAccessInformation]` is 0 (`dlls/ntdll/unix/file.c`
`NtQueryInformationFile`), so ntdll makes no length check and hands the call straight to
`server_get_file_info`; the size guard lives inside the fd op, under the handle. So:

| the caller's mistake | answer |
|---|---|
| handle names an object with no fd (a process, an event) | `STATUS_OBJECT_TYPE_MISMATCH` |
| handle names nothing | `STATUS_INVALID_HANDLE` |
| either of the above **with** a buffer shorter than 4 bytes | still the HANDLE's status |
| valid handle, buffer shorter than 4 bytes | `STATUS_INFO_LENGTH_MISMATCH`, buffer untouched |
| valid handle, buffer longer than 4 bytes | success; `Information` is 4 and the tail is untouched |

`FilePipeInformation` through the same junk handle with the same short buffer reports
the LENGTH, because its `info_sizes[]` entry is non-zero and that check sits in ntdll.
Two classes of one syscall, two orders — an implementation with a single length gate
ahead of a single handle gate cannot answer both. `kernel/io/query.c` gives class 8
`needed = 0` in the size switch for exactly this reason and checks the length after the
reference; pinned by `tests/ntapi/sem_file/access_info.c`.

**One place proskrnl answers where the oracle does not.** `FileAllInformation`'s
`AccessInformation.AccessFlags` is a hardwired 0 with a `FIXME` in the pinned Wine
(`dlls/ntdll/unix/file.c`), as `ModeInformation.Mode` beside it is; proskrnl fills both,
and class 8 and `FileAllInformation` report the **same** word from the same place
(Art. 11). The oracle cannot refute the value, so the agreement is pinned against
Microsoft's own contract instead — `FILE_ACCESS_INFORMATION.AccessFlags` is "the access
rights that are granted for this handle" and `FILE_ALL_INFORMATION.AccessInformation` is
that same structure — in a `beyond_oracle` block of `sem_file/access_info.c` §7, queried
through a WEAKENED DUPLICATE, which is the only handle that can tell one answer from
two.

Two things here are deliberately NOT pinned.

**Whether a FAILING `NtQueryInformationFile` writes the caller's IOSB.** The oracle
writes `io->Status` on nearly every return from the syscall (`return io->Status = ...`,
and `server_get_file_info` assigns both fields unconditionally); proskrnl writes the
block only on success. That is a whole-syscall convention with a dozen classes inside
it, not this class's rule, and adopting it for class 8 alone would make one syscall
answer two ways.

**The RESERVED access bits.** `get_handle_access` returns `entry->access & ~RESERVED_ALL`
and `alloc_handle` strips the same two bits on the way in (`server/handle.c`:
`RESERVED_SHIFT` 26, i.e. bits 26–27), because the oracle *stores its handle flags there*
— `HANDLE_FLAG_INHERIT` and `HANDLE_FLAG_PROTECT_FROM_CLOSE` live inside the access word.
proskrnl keeps handle attributes in their own field, so it has nothing to steal and
nothing to strip: `ObpCreateHandleInTable` stores the granted mask verbatim. A caller
that duplicates a handle asking for `0x0C000000` therefore reads those bits back through
class 8 (and through `NtQueryObject(ObjectBasicInformation)`, which has reported them
since long before this class existed — so the divergence is Ob's and pre-dates it, not
this class's to fix). Filed as issue #199 rather than masked here, because masking
two bits inside class 8 would put a second, narrower statement of "what a handle's access
is" beside `ObpCreateHandleInTable`'s (Art. 11) and would leave `NtQueryObject` still
reporting them.

## `FILE_SYNCHRONOUS_IO_ALERT`: the park is alertable, and an interrupted request completes nothing

`FILE_SYNCHRONOUS_IO_NONALERT` and `FILE_SYNCHRONOUS_IO_ALERT` had been folded together
everywhere below `FileModeInformation`: both meant "this handle blocks its caller", and
`IoWaitCancellable` waited non-alertably for both. The oracle keeps them apart in one
argument, repeated identically in `server_read_file`, `server_write_file` and
`server_ioctl_file` (`dlls/ntdll/unix/file.c:5746/:5781/:5823`):

```c
if (wait_handle) status = wait_async( wait_handle, (options & FILE_SYNCHRONOUS_IO_ALERT) );
```

so a queued user APC breaks the park of every synchronous request on an ALERT handle and
none on a NONALERT one. `NtFlushBuffersFileEx` is the oracle's own exception and passes a
literal `FALSE` (`:6876`), so a flush blocks through a queued APC whatever the handle
says — stated at that service in `kernel/io/rw.c` rather than as a rule about the layer,
which is `docs/21` W4d's lesson about where a one-service exception belongs. `KTHREAD.syncIoAlertable` carries the handle's answer into the
one place the Io layer parks, and `syncIoAlerted` carries the outcome back out
(`kernel/io/async.c`; pinned by `tests/ntapi/sem_pipe/alertable_park.c`).

**What an interrupted request leaves behind is the half that does not follow from "the
wait was alertable", and it is the whole of the deviation risk.** The oracle's async is
still QUEUED in the server — only the *client* stopped waiting — so `async_set_result`
has not run: no IOSB is written, the completion routine does not fire, the caller's event
stays down and the file object stays as the issue left it. The syscall returns the wait's
own `STATUS_USER_APC`. Windows differs here and the difference is deliberate: NT
*cancels* the request and answers `STATUS_CANCELLED`, which `ntdll:pipe`'s
`test_alertable` records as `todo_wine`. Art. 6 makes the pinned oracle the spec, and
matching NT instead would flip that todo to an unexpected pass — i.e. score a failure for
being closer to NT.

**`STATUS_USER_APC` is an `NT_SUCCESS` value, so it is carried as a FLAG and never read
off a device's return.** That is `docs/21` W4c's lesson applied before it could be paid
again: `STATUS_PENDING` was already a final status for one device, and reading it as a
channel leaked conhost's bounce buffer on every idle poll. The engine sets the flag at
the one place a park is created, so no device can be interrupted and forget to say so.

**The divergence that outlives the call, and it is the opposite of the oracle's.** Above
describes the state at the moment the caller returns, where the two agree. They part
afterwards: the oracle's async is still live, so when the thing it was waiting for finally
arrives — a client connects, the peer writes — it completes for real, writing the caller's
IOSB, signalling the event and firing the completion routine *after the call that issued
it has returned*. proskrnl's blocking park is a THREAD park with no queue entry behind it,
so an interrupted request ceases to exist: the IOSB is never written, the routine never
runs, and (for a transfer, which cleared it at issue) the FILE OBJECT stays non-signalled
for good. Windows is on proskrnl's side of this — it cancels rather than leaving the IRP
queued — so the divergence is from the *oracle's* known-imperfect half, which is why
`test_alertable`'s status assertion is `todo_wine` in the first place. The practical
consequence is only visible to a caller that keeps the IOSB alive and re-reads it later;
`tests/ntapi/sem_pipe/alertable_park.c` has to make every IOSB a per-case `static` for
exactly that reason, since on the ORACLE the rescue's connect writes into it.

**A partially-committed stream write reports nothing, and that is unpinned.** `NpfsWrite`
chunks a byte-stream write across quota and re-parks; broken mid-way, it returns the
wait's status with bytes already in the peer's queue and no IOSB to say how many, so a
retrying caller duplicates them. The shape pre-dates this item — the CANCEL path has
always had it — and the alertable park only made it reachable without a canceller. Left
as it is rather than guessed at: what NT reports for an interrupted partial stream write
has not been measured on either runner, and inventing a count is Art. 12's fabricated
answer. Named at the site (`fs/npfs/pipe.c` `NpfsWrite`).

**One thing this did NOT build, deliberate and recorded rather than hidden** (the
file-object half of the ioctl's signalled state, which was the other one, is built — see
"An IOCTL clears the handle at its PARK" below). An ALERT handle whose park is broken
while a *cancel* has also landed reports `STATUS_CANCELLED`: the cancel writes the
caller's IOSB and the alert writes nothing, so reporting the alert would lose a
completion the canceller was promised.

**The find under the find: npfs was a second FILE_OBJECT construction site and it had
already drifted.** `NtCreateNamedPipeFile` says it builds the object "exactly as
`IopCreateFile` does" and set `synchronousIo` alone — so every pipe handle reported a
zero `FileModeInformation` whatever it was opened with, its `syncIoLock` was never
initialised, and `FILE_SYNCHRONOUS_IO_ALERT` was invisible to the park that this item
keys on. Both sites now go through `IopCaptureCreateOptions` (`kernel/io/file.c`).
Art. 11's "parallel paths drift even while currently equivalent" was not a prediction
here; the drift was already shipped, and only a test that needed one of the dropped bits
found it.

## An IOCTL clears the handle at its PARK, where a transfer clears it at issue

`NtDeviceIoControlFile` / `NtFsControlFile` now owe the FILE OBJECT's signalled state the
same two transitions a read does (`docs/03` "What a BLOCKING request owes" is stated in
`kernel/io/io.h` above `IOP_BLOCKING_REQUEST`): down while the request is outstanding,
and back up at the end unless the caller supplied an event, which takes the signal
instead. `ntdll:pipe`'s `test_cancelsynchronousio` is the consumer — `pipe.c:747` spins

```c
while ((ret = WaitForSingleObject(ctx.pipe, 0)) == WAIT_OBJECT_0) Sleep(1);
```

waiting for a blocking `FSCTL_PIPE_LISTEN` to take the pipe handle down, and the pair
wedged there for as long as nothing did. Pinned by `tests/ntapi/sem_pipe/ioctl_signal.c`.

**WHERE the clear happens is the whole content, and the oracle refuted the obvious
transcription.** `rw.c`'s transfers merge the oracle's two issue-time statements —
`create_async`'s event reset and `queue_async`'s `set_fd_signaled( async->fd, 0 )` — into
one call at issue, and restore the handle if the device refuses without parking. That is
correct for a TRANSFER because `pipe_end_read` and `pipe_end_write`
(`third_party/wine` `server/named_pipe.c`) queue every request they SERVE — their state
refusals return above the queue like the ioctl's, but neither has an arm that answers a
caller *without* queueing — so for a served transfer "issued" and "queued" are the same
instant. An IOCTL is not that shape:
`pipe_server_ioctl`'s `FSCTL_PIPE_LISTEN` arm answers `STATUS_PIPE_CONNECTED` /
`_CLOSING` / `_LISTENING` **above** `queue_async( &server->listen_q, async )`, and
`FSCTL_PIPE_PEEK` is answered inline and never queues at all. Two measured consequences,
neither of which a clear-at-issue can produce:

| ioctl | event? | handle before | handle after, on the oracle |
|---|---|---|---|
| `FSCTL_PIPE_PEEK` (inline success) | yes | up | **up** — the event takes the signal and nothing ever cleared the handle |
| `FSCTL_PIPE_PEEK` (inline success) | no | down | **up** — `async_set_result`'s guard is `async->pending \|\| !NT_ERROR( status )`, so a success reaches the signal block whether or not it was queued |
| `FSCTL_PIPE_LISTEN` refused (`STATUS_PIPE_CONNECTED`) | either | either | **unchanged** — the refusal returns above the queue, so the signal block is skipped |
| `FSCTL_PIPE_LISTEN` parked then cancelled | no | down | **up** — it WAS queued, so `async->pending` is 1 and the failure still signals |
| `FSCTL_PIPE_LISTEN` parked then cancelled | yes | down | **stays down**; the event goes up instead |

So the timing is the caller's to state (`IOP_BLOCKING_CLEAR`: `IopClearAtIssue` for the
transfer paths, `IopClearAtPark` for the ioctl), and the clear itself is made by the
ENGINE at the one place a blocking park happens — `IoWaitCancellable`, through
`KTHREAD.syncIoParkFile` — or by `IopPreparePendingRequest` for the arm that pends
instead. No device is told where the boundary is, for the same reason
`IO_CONTROL_CONTEXT.pended` and `KTHREAD.syncIoParked` are engine-set: a device that has
to remember eventually forgets.

**The COMPLETION ROUTINE splits on the same question, and both tails had it wrong.**
`async_set_result` queues `APC_USER`, posts the completion packet and signals the event or
the fd *inside one guard* — `if (async->pending || !NT_ERROR( status ))` — so a request
that was QUEUED and then failed runs its routine, with an IOSB nobody wrote as its only
argument, while one refused above the queue runs nothing. `rw.c`'s device branch and
`ioctl.c` both freed the block on every failure, so a cancelled blocking listen and a
parked read broken by its peer silently dropped a callback the oracle delivers. Stated
once (`IopEndFailedRequestApc`, `kernel/io/async.c`) and measured on both tails
(`sem_pipe/blocking_signal.c` case 6, `sem_pipe/ioctl_signal.c` case 6). **Found by
gate-check reading the new two-armed branch, not by a failing assertion** — the arm that
was already measured was the refusal, and the pin that measured it
(`sem_pipe/listen_apc.c`) reads as coverage of the whole failure path.

**What did NOT change:** `condrv` still owns its own file object's signalled state
(`FILE_OBJECT.deviceManagedSignal`), so conhost's server-fetch ioctls are untouched by
all of this — the suppression is tested inside the one transition every producer goes
through (`IopFileSignalSuppressed`).

## A pipe end's own file information, and the orphan's refusal

`NtQueryInformationFile(FileStandardInformation)` on a named-pipe end reports the pipe's
capacity and this end's readable bytes, not zeros. The oracle answers the class from
`server/named_pipe.c` `pipe_end_get_file_info` — a pipe end has no unix fd (the server
hands it an `alloc_pseudo_fd`), so `server_get_unix_fd` says `STATUS_BAD_DEVICE_TYPE` and
ntdll routes the WHOLE class to the server rather than to its own `fstat`. Pinned by
`tests/ntapi/sem_pipe/pipe_file_info.c`; it takes `ntdll:pipe` from **123** failed
assertions to **99**.

**The two numbers answer different questions, and the winetest asks in the one state
where that shows.** `AllocationSize` is `pipe->outsize + pipe->insize` — the pipe's pair
of quotas, the same at both ends and *unmoved by traffic* — while `EndOfFile` is
`pipe_end_get_avail( pipe_end )`, what THIS end can read right now, so the two ends of one
pipe disagree about it the moment either writes. An implementation that reports "how much
is buffered" for the first passes an empty pipe and fails `pipe.c:2160` in every state
that has data. Both come out of `NpfsGetInfo` through the raw `IO_FILE_INFO` shape
`IopFillStandard` already reads, so the class stays one fill for every backend; the
available-bytes quantity is reached through `NpfsIncomingQueue`, the same helper
`FilePipeLocalInformation`'s `ReadDataAvailable` uses (Art. 11).

**`DeletePending` is 0 and `NumberOfLinks` is 1.** Both carry a `/* FIXME */` in the
oracle and NT is documented to report a pipe's delete as pending (the winetest wraps that
assertion in `todo_wine`), but the oracle is the spec here (Art. 6) and 0 is what it
answers — matching NT would score a failure for being closer to NT, the same shape as
`kernel32:volume:186`.

**The class's FILE_READ_ATTRIBUTES demand could not be stated where the other pipe
classes' is.** The arm's first guard is
`get_handle_access( current->process, handle ) & FILE_READ_ATTRIBUTES`, and no other
backend demands anything for `FileStandardInformation`, because on the oracle every other
backend answers it out of ntdll's `fstat` with no server call at all. So it is not the
CLASS's required access — `kernel/io/query.c` cannot know which device a handle names
before Ob has resolved it — and it is asked the way `NpfsSetPipeInfo` already asks its
own: by resolving the same handle a second time with the bit, which leaves the decision at
Ob's one check site (G10) rather than open-coding a mask test on the entry word the
function already holds, and makes the answer Ob's own `STATUS_ACCESS_DENIED`.

**And the demand is a pipe END's, not the pipe DEVICE's.** The `\Device\NamedPipe` root
opens on the same device ops, and the oracle's root is a `named_pipe_device_file` whose fd
ops are `default_fd_get_file_info` — no access guard anywhere in it — so a root handle
without the bit must answer whatever an entitled one answers. Keyed on "this device has
pipes" the check fires on the root too; it is keyed on `FILE_OBJECT.isDirectory`, the Io
layer's own statement of the split, which `kernel/io/rw.c` already uses to keep
`NtRead`/`NtWriteFile` off that same root. The pin measures the root as an EQUALITY
between an entitled and an unentitled handle rather than by naming a status, because the
oracle refuses the class there and an unbuilt oracle is not authoritative (Art. 12).

**The orphan's refusal is one statement, and it is wider here than the oracle's.**
An end the server DISCONNECTED out from under has `pipe_end->pipe == NULL` (the
`FSCTL_PIPE_DISCONNECT` arm clears the CLIENT's; the disconnecting server keeps its own),
and every arm `pipe_end_get_file_info` IMPLEMENTS carries the same `if (!pipe)` —
`FileStandardInformation`, `FileNameInformation` and the two pipe classes. Stated once in
`NpfsGetInfo`, `FileNameInformation` inherits it (`pipe.c:2181`, `:2447`) with no second
transcription — and so do the classes the oracle's handler does *not* implement
(`FileBasic`/`Position`/`Internal`/`EndOfFile`/`NetworkOpen`/`AttributeTag`/`All`), which
now answer `STATUS_PIPE_DISCONNECTED` for an orphaned end where they used to answer
success with a zeroed struct. **That widening is deliberate and nothing convicts either
answer**: those classes are unbuilt on the oracle for a pipe end whether it is orphaned or
not (`default_fd_get_file_info`'s `default:` arm), so there is no measurement to match, and
a zeroed struct is a description of a pipe that is gone. The ORDER between the two
refusals is observable and IS pinned: an orphaned end held through a handle with no
`FILE_READ_ATTRIBUTES` reports the ACCESS failure for `FileStandardInformation` and the
DISCONNECT for `FileNameInformation`, because only the first arm has an access guard.

**The residual this section used to record is built**, and it is its own rule: a client
that outlives its server keeps the pipe and loses only its NAME. See "How long a pipe
outlives its NAME" below.

## How long a pipe outlives its NAME, and which end owns it

Two lifetimes, and the oracle keeps them apart. The named-pipe OBJECT is referenced by
EVERY end — `server/named_pipe.c` `init_pipe_end`'s
`pipe_end->pipe = (struct named_pipe *)grab_object( pipe )`, released in
`pipe_end_destroy` — while its NAME goes with the last INSTANCE, in
`pipe_server_destroy`'s `if (!--pipe->instances) unlink_named_object( &pipe->obj )`.
proskrnl had ONE lifetime: `NPFS_INSTANCE.pipe` was dropped and the whole `NPFS_PIPE`
freed at the last server end's cleanup, so a client that outlived its server described a
pipe that was no longer there — `NamedPipeType`, `NamedPipeConfiguration`,
`MaximumInstances`, both quotas and `AllocationSize` all zero, and `FSCTL_PIPE_PEEK`
giving a byte pipe's answers because the pipe's TYPE had gone with it.

The pointer now lives on the END (`NPFS_END.pipe`, the oracle's own field) over a
reference count, and the two teardowns are separate: `NpfsUnlinkPipe` when
`instanceCount` reaches 0, `NpfsDereferencePipe` when an end goes.
`ntdll:pipe` **29 → 22**. Pinned by `tests/ntapi/sem_pipe/pipe_lifetime.c`, with the
consequences pinned where they show — `sem_pipe/peek_state.c` §4 (the type) and
`sem_pipe/pipe_file_info.c` §4 (`AllocationSize`), both of which carried a
`todo_proskrnl` for this and no longer do.

**What the unlink takes is the NAME, and that is observable through a handle that keeps
everything else.** `FileNameInformation`'s arm is
`if (!pipe || !(name = get_object_name( &pipe->obj, &name_len )))` →
`STATUS_PIPE_DISCONNECTED`, and `get_object_name` of an unlinked object is NULL. So one
client handle answers `FilePipeLocalInformation` with the pipe's real numbers and refuses
to report its name, in the same instant. `NpfsUnlinkPipe` frees the name buffer for
exactly that reason, which makes `NpfsQueryName`'s guard the oracle's one guard over
three states (no pipe, never named, unlinked) instead of the single disjunct it was.

**TRADE — that one refusal moves proskrnl AWAY from NT, deliberately, and it is the
`DeletePending` trade above a second time.** The oracle carries its own
`/* FIXME: We should be able to return on unlinked pipe */` over that guard, and
`ntdll:pipe:2185` wraps `ok(status == STATUS_SUCCESS)` in a `todo_wine_if` for exactly
this row — i.e. real NT reports the name and Wine knows it. proskrnl reported the name
before this change and reports `STATUS_PIPE_DISCONNECTED` after it, so **the pair's
failure count fell by one for being FARTHER from NT on this line**, and that half of the
`29 → 22` is a trade rather than a fix. It is made the way Art. 6 is applied everywhere
else in this file — where the oracle answers at all it is the spec — and there is a
second, harder reason it cannot go the other way: the "report the name" answer is
**un-pinnable**. G5 wants an oracle-green case; the oracle refuses; and `beyond_oracle`
is barred by its own definition (`tests/ntapi/ntapi.h`) for behaviour Wine DOES
implement, which this arm is — a FIXME is an aspiration, not the `STATUS_NOT_IMPLEMENTED`
that makes an oracle unbuilt. An answer no test may pin is an answer Art. 5 does not let
this kernel build.

**`CurrentInstances` is not a liveness bit and must not be keyed like one.** It is
`pipe->instances`, which really did fall to zero when that server left, so the correct
answer through a surviving client is five real values and a zero — which is what
`ntdll:pipe:2358` (`CurrentInstances == 0` for a closing client) was passing on all along,
for the wrong reason.

**The unlink follows the INSTANCE COUNT, not "a server end closed".** With a second
instance still open the name stays in the namespace: the client of the closed instance
reports `CurrentInstances 1` and its own name, and a further open by that name still
finds it. No winetest assertion reaches this; it is `sem_pipe/pipe_lifetime.c` §3, and an
implementation that unlinked per server end passes every other case.

**A DISCONNECT is still not a close.** `FSCTL_PIPE_DISCONNECT` drops the CLIENT's
reference outright (`release_object( ...connection->pipe ); ...connection->pipe = NULL`),
which is what every `if (!pipe)` in `pipe_end_get_file_info` refuses on — so that end
describes nothing while a merely-orphaned-by-close client describes everything. Because
the pointer moved onto the end, `end->pipe == 0` IS that condition: the `orphaned` bit it
replaces was a second spelling of one fact, which is the shape Art. 11 warns about even
while two statements agree.

## What `FSCTL_PIPE_PEEK` answers, by state and by the PIPE's type

The whole verb is `server/named_pipe.c` `pipe_end_peek`, twenty lines that decide four
things in an order none of them follows from the verb's name. Transcribed into
`fs/npfs/pipe.c` `NpfsPeek` and pinned by `tests/ntapi/sem_pipe/peek_state.c`; it takes
`ntdll:pipe` from **99** failed assertions to **80** (`pipe.c:2055`×6, `:2205` 10→1,
`:1197`/`:1199`×2 each).

| this end | queue | answer |
| --- | --- | --- |
| buffer shorter than `offsetof(FILE_PIPE_PEEK_BUFFER, Data)` | any | `STATUS_INFO_LENGTH_MISMATCH` |
| orphaned (a server disconnected it) | any | `STATUS_PIPE_DISCONNECTED` |
| `FILE_PIPE_LISTENING_STATE` | any | `STATUS_INVALID_PIPE_STATE` |
| `FILE_PIPE_DISCONNECTED_STATE`, not orphaned (the disconnecting SERVER) | any | `STATUS_INVALID_PIPE_STATE` |
| `FILE_PIPE_CLOSING_STATE` | empty | `STATUS_PIPE_BROKEN` |
| `FILE_PIPE_CLOSING_STATE` | has data | the fill below |
| `FILE_PIPE_CONNECTED_STATE` | any | the fill below |

**The LENGTH floor is decided above the state.** A four-byte reply buffer on a listening
pipe reports the length, not the state — the two guards are one `if` apart in the oracle
and an implementation that validates the object before the arguments answers the state.

**`CLOSING` is not `BROKEN` while there is anything left to read.** The oracle's arm is
`if (!list_empty( &pipe_end->message_queue )) break;`, so the QUEUE is the discriminator
and the state word alone is not: one handle answers `STATUS_SUCCESS` and then
`STATUS_PIPE_BROKEN` across the single read that empties it, with nothing else having
moved. `sem_pipe/peek_state.c` §1 measures exactly that pair, because "CLOSING means the
peer is gone" passes every other row of this table.

**A DISCONNECTED end's answer depends on WHICH end it is.** The oracle writes
`pipe_end->pipe ? STATUS_INVALID_PIPE_STATE : STATUS_PIPE_DISCONNECTED`, and
`FSCTL_PIPE_DISCONNECT` drops the pipe reference for the CLIENT only (`pipe_server_ioctl`:
`release_object( ...connection->pipe ); ...connection->pipe = NULL`) — so the server that
did the disconnecting complains about its STATE and its client reports a disconnection.
proskrnl's `end->pipe == 0` is that end (the same identification `NpfsFlush` already
makes, and the same field), and it is asked FIRST rather than folded into the switch,
because proskrnl's state word belongs to the INSTANCE where the oracle's belongs to the
END: a re-listened instance moves back to `FILE_PIPE_CONNECTED_STATE` under an end that
was thrown out of it, and only the per-end fact still says what that end is.

**The fill, and the axis its `STATUS_BUFFER_OVERFLOW` is keyed on.** `ReadDataAvailable`
is every unread byte on this end's incoming queue; `MessageLength` is the FIRST message's
remaining bytes and is written **only for a `FILE_PIPE_TYPE_MESSAGE` pipe**; the payload
is the caller's room bounded by what is queued and, on a message-type pipe, by that first
message; and the status is `message_length > reply_size`. So:

- **the type is the PIPE's, not the end's read mode.** `pipe_end->pipe->message_mode` is
  fixed at create and the end's `FILE_PIPE_*_MODE` does not appear in the function at all,
  so a message-type pipe read through a BYTE-mode end still truncates and still overflows
  — which is what `ntdll:pipe:1197` asks and what keying the rule on the read mode gets
  wrong. A byte-type pipe never overflows however much it leaves behind, which is the
  1-byte `PeekNamedPipe` poll's whole shape (`docs/review-2026-07` §9);
- **the overflow is about the first MESSAGE, not about `avail`.** Two ten-byte messages
  queued and room for both is a `STATUS_SUCCESS` carrying **one** of them; room for none
  of the first is an overflow even though the fixed part fitted. An implementation that
  copies across the queue up to the caller's capacity — right for a byte pipe — reports
  twenty bytes and no overflow.

**`NumberOfMessages` is a literal 0 in every reply.** The oracle hardwires it under a
FIXME of its own, and where the oracle answers at all it is the spec (Art. 6) — the same
trade `FileStandardInformation`'s `DeletePending` records above. Nothing on the boundary
reads it: `PeekNamedPipe` hands back `MessageLength` and drops this field. proskrnl used
to return a real count, which was more NT-correct and unmeasurable by anything in the
baked stack.

**The residual this section recorded is built.** A client whose SERVER handle closed used
to forget the pipe's TYPE and answer a byte pipe's `MessageLength` 0 with no overflow —
`ntdll:pipe`'s `:2205` (`in client state 4`). The end holds its own pipe now; see "How
long a pipe outlives its NAME". `sem_pipe/peek_state.c` §4 is the case, without its
`todo_proskrnl`.

## What `FSCTL_PIPE_TRANSCEIVE` writes, and what it refuses

One message out and one message back, in one verb, on one end — the transaction
`TransactNamedPipe` is. The whole thing is `server/named_pipe.c`
`pipe_end_transceive`, reached through `pipe_end_ioctl` from **both** ends' ioctl
handlers, so unlike `FSCTL_PIPE_LISTEN` and `FSCTL_PIPE_DISCONNECT` it is a verb
a client has too. Transcribed into `fs/npfs/pipe.c` `NpfsTransceive` and pinned
by `tests/ntapi/sem_pipe/transceive.c`; it takes `ntdll:pipe` from **80** failed
assertions to **68** (`pipe.c:2069`×8 in `test_pipe_state`, `:1450`/`:1456`/
`:1457`/`:1458` in `test_transceive`).

| this end | answer |
| --- | --- |
| orphaned (a server disconnected it) | `STATUS_PIPE_DISCONNECTED` |
| `FILE_PIPE_LISTENING_STATE` | `STATUS_INVALID_PIPE_STATE` |
| `FILE_PIPE_DISCONNECTED_STATE`, not orphaned (the disconnecting SERVER) | `STATUS_INVALID_PIPE_STATE` |
| `FILE_PIPE_CLOSING_STATE` (the peer closed) | `STATUS_INVALID_PIPE_STATE` |
| connected, read mode is `FILE_PIPE_BYTE_STREAM_MODE` | `STATUS_INVALID_READ_MODE` |
| connected, message mode, bytes already buffered here | `STATUS_PIPE_BUSY` |
| connected, message mode, nothing buffered | the input is queued to the peer, and the verb waits for the reply |

**The state question is "is there a connection", and its two answers split the
ends.** `if (!pipe_end->connection) set_error( pipe_end->pipe ?
STATUS_INVALID_PIPE_STATE : STATUS_PIPE_DISCONNECTED )` — and `connection` is
NULL in every state but `CONNECTED`, so three different situations collapse onto
the STATE complaint and only the client a server threw out reports the
disconnection. That is `FSCTL_PIPE_PEEK`'s split one table up, asked by the same
`end->pipe == 0` and asked FIRST for the same reason (proskrnl's state word
belongs to the INSTANCE, so a re-listened instance moves back to `CONNECTED`
under an end that was thrown out of it).

**The read-mode refusal is about the END, not the pipe.** The oracle reads
`pipe_end->flags & NAMED_PIPE_MESSAGE_STREAM_READ`, which is what
`FilePipeInformation` writes — so a message-TYPE pipe whose end is SET back to
byte mode refuses, and moves back the moment the mode does. A byte-TYPE pipe can
never carry the flag (`NpfsSetPipeInfo` refuses the combination, as the oracle
does at create and at set), which is why the append can assume a message-type
pipe. The guard sits BELOW the state question and ABOVE the busy one: a listening
byte-mode end reports its state, a connected byte-mode end with data queued
reports its mode.

**`STATUS_PIPE_BUSY` is total: nothing is written.** A reader that already has
buffered bytes cannot transact, and the input is not queued to the peer either.
This is the rung an implementation built as "call the write path, then call the
read path" cannot have, because such an implementation would answer the caller
out of the bytes that were already there.

**The write half NEVER blocks, and that is a difference rather than a note.**
The oracle says so where it does it — *"transaction never blocks on write, so
just queue a message without async"* — so `NpfsTransceive` calls
`NpfsAppendBuffer` directly and not `NpfsWrite`: an ordinary `NtWriteFile` past
the peer's quota parks its caller (and still does), while a transceive of the
same bytes over the same full queue is accepted on the spot and waits only for
its reply.

**The read half is the end's ordinary read machinery, minus exactly one rung.**
Both `pipe_end_read` and `pipe_end_transceive` end in
`queue_async( &pipe_end->read_q, async )`, so the two share one queue and are
served in issue order — a read issued behind a parked transceive cannot take the
first reply. `NpfsAwaitRead` is that shared body (the state ladder, the park, the
pend, the drain), with `honourCompletionMode` as the one parameter, because
`pipe_end_read` opens with a `NAMED_PIPE_NONBLOCKING_MODE` arm that
`pipe_end_transceive` has none of: **a NOWAIT-mode end refuses a read with
`STATUS_PIPE_EMPTY` and PENDS a transceive**, in the same state, back to back.
An implementation that tail-calls its own read path answers `STATUS_PIPE_EMPTY`
there.

What that NOWAIT arm asks about is BUFFERED DATA and not outstanding requests,
and the oracle had to say so: the pin's first draft expected a read issued behind
a parked transceive to pend, and it is refused exactly as it would be with
nothing outstanding (`list_empty( &pipe_end->message_queue )` is the whole test).

**The reply is framed as a MESSAGE**, so a reply longer than the caller's output
buffer completes `STATUS_BUFFER_OVERFLOW` with the tail still queued as the same
message — `NpfsReadDrain`'s existing rule, reached with the ioctl's output buffer
in place of a read's.

**`FSCTL_PIPE_TRANSCEIVE`'s pended arm is what gave `kernel/io/ioctl.c` its data
legs.** An ioctl that parks still owes its caller a reply, so the OUTPUT buffer
and its pool bounce now travel in the `IO_CONTROL_CONTEXT` exactly as a
transfer's do (`kernel/io/rw.c`), with the same ownership rule — the bounce
belongs to the request once `pended` comes back TRUE, and
`IopCompletePendingRequest` is what frees it and what places the bytes in the
owner's address space. The INPUT bounce is never the request's: a verb that pends
has already consumed it.

**Two things deliberately NOT built with it.** The verb's embedded access
(`(code >> 14) & (FILE_READ_DATA | FILE_WRITE_DATA)`, which the oracle demands in
`DECL_HANDLER(ioctl)`) is a rule about the ENGINE owed by every verb including
`FSCTL_PIPE_PEEK`'s `FILE_READ_DATA`, and `kernel/io/ioctl.c` asks Ob for no
access on any of them — so it is one item and not half of this one. And the
`\Device\NamedPipe` ROOT answers this verb `STATUS_PIPE_DISCONNECTED`
(`named_pipe_device_ioctl`), which is a fact about the root rather than about the
verb: the root arm still refuses loudly and `ntdll:pipe`'s `:2751` cluster still
convicts it.

## A completion PORT and a completion APC ROUTINE are mutually exclusive

`NtReadFile` / `NtWriteFile` / `NtDeviceIoControlFile` / `NtFsControlFile` /
`NtNotifyChangeDirectoryFile` refuse `STATUS_INVALID_PARAMETER` when the handle
is bound to an I/O completion port **and** the call carries an `ApcRoutine`. It
is the last statement of the one function every asynchronous request is created
by (`third_party/wine` `server/async.c` `create_async`):

```c
if (event) reset_event( event );

if (async->completion && data->apc)
{
    release_object( async );
    set_error( STATUS_INVALID_PARAMETER );
    return NULL;
}
```

`async->completion` is `fd_get_completion( fd, &async->comp_key )`, i.e. the
port bound to the handle; `data->apc` is the **routine**. Landed as
`IopPortApcConflict` (`kernel/io/io.h`, `kernel/io/async.c`), applied inside
`IopBeginBlockingRequest` for the transfer and ioctl paths and at the watch
arm's own issue point in `kernel/io/notify.c`; pinned by
`tests/ntapi/sem_port/port_apc.c`. It takes `ntdll:pipe` from **68** failed
assertions to **60** (`pipe.c:3094`×8, `test_async_cancel_on_handle_close`).

**Not the ApcCONTEXT.** With a NULL routine the context IS the completion
packet's value, and every overlapped Win32 caller passes one (the `OVERLAPPED`
pointer). An implementation keyed on the context refuses the ordinary case.

**Where it sits is as measurable as what it answers**, and both halves are
pinned:

- **the caller's EVENT is already RESET when the refusal is made** — the reset
  is the statement *above* the guard — so a request that was never issued still
  takes the caller's pre-signalled event down;
- **the FILE OBJECT is not cleared**, because the clear belongs to
  `queue_async` (`set_fd_signaled( async->fd, 0 )`) and the refusal returns
  above it. proskrnl merges those two statements into `IopBeginBlockingRequest`
  (see "An IOCTL clears the handle at its PARK"), which is exactly why the
  refusal is made *inside* that function, between its two halves, and needs no
  `IopEndBlockingRequest` to put anything back;
- **it precedes every verb.** The refusal is made when the request is CREATED,
  so `FSCTL_PIPE_PEEK` — answered inline, never queued — is refused just the
  same;
- **the handle and its access are decided first** (`get_handle_fd_obj( ...,
  FILE_READ_DATA )` in `DECL_HANDLER(read)`, `server/fd.c`), so a read through
  a duplicate that dropped `FILE_READ_DATA` reports `STATUS_ACCESS_DENIED` and
  never reaches this rule.

**Its reach is the requests the SERVER queues, not the syscall's arguments, and
that is the part an implementation reaching for the tidy rule gets wrong.** A
regular disk file's transfer never reaches wineserver at all —
`dlls/ntdll/unix/file.c` `NtReadFile` `pread()`s it locally — so the same
combination is *admitted* on a disk handle, where ntdll resolves the conflict
the other way instead: `cvalue = apc ? 0 : (ULONG_PTR)apc_user`, so the APC runs
and no packet is posted. proskrnl has had that half since CUI-8
(`IopPostRequestPacket`, `kernel/io/rw.c`), so no double report was ever
possible; what was missing is only the refusal. Hoisting it into `NtReadFile`
would refuse a disk read the oracle serves, and passes every pipe case in the
pin — which is why `sem_port/port_apc.c` measures the disk arm too.

**The known EDGE of that argument, stated so it is not rediscovered as a bug.**
`NtFsControlFile` has a second locally-served family: `FSCTL_IS_VOLUME_MOUNTED`,
`FSCTL_LOCK_VOLUME`, `FSCTL_UNLOCK_VOLUME`, `FSCTL_GET_RETRIEVAL_POINTERS`,
`FSCTL_GET_OBJECT_ID` and `FSCTL_SET_SPARSE` are answered inside ntdll and
finished by `file_complete_async`, which runs the APC and posts nothing — so the
oracle admits the pair for those six exactly as it does for a disk read, while
`kernel/io/ioctl.c` refuses uniformly. It is unreachable rather than divergent
today, and doubly so: proskrnl implements none of the six, and an FSCTL on a
disk-file handle answers `STATUS_INVALID_DEVICE_REQUEST` above this refusal
because `fs/fat32` has no `DeviceControl` op at all. The day one of them is
built, its pin owns this row.

Whether NT draws the line in the same place is not established here and nothing
in the tree measures it: the pinned oracle answers both arms, and where the
oracle answers it is the spec (Art. 6). If a consumer ever convicts the disk
arm, it is a new item with its own pin — not a widening of this one on the
strength of symmetry.

## A completion PORT has TWO wait channels, and they are not interchangeable

Waiting on a port HANDLE and calling `NtRemoveIoCompletion` are different
questions, and the pinned server answers them with two different objects
(`third_party/wine` `server/completion.c`). proskrnl mirrors the split in
`kernel/io/completion.c`; pinned by `tests/ntapi/sem_port/port_wait.c`.

- **The HANDLE's signal state is `completion->sync`**, an internal sync created
  MANUAL-reset and clear (`create_internal_sync( 1, 0 )`, `server/event.c`). It
  means *an unclaimed packet is queued*: `add_completion` sets it only for a
  packet that survives the remover fan-out, `remove_completion` clears it when
  the queue empties, `completion_close_handle` sets it on the last handle. So a
  handle wait **wakes every waiter and consumes nothing** — one packet and two
  waiters wakes both, and the packet is still there afterwards for whoever
  removes it.
- **A parked `NtRemoveIoCompletion(Ex)` is a `completion_wait`** on
  `completion->wait_queue`, pushed at the HEAD (`list_add_head`) and served
  head-first by `add_completion`'s forward walk. Two consequences a tidier
  implementation gets wrong: the fan-out is **LIFO**, so the most recently
  parked remover takes the first packet; and a parked remover takes the packet
  **before the handle's signal state ever sees it**, so a handle waiter on the
  same port is not woken at all.
- **Closing the LAST handle** abandons every parked remover with
  `STATUS_ABANDONED_WAIT_0` and then signals the handle's state, so a thread
  waiting on the HANDLE comes back `STATUS_SUCCESS` while a thread parked in a
  remove comes back abandoned. It is NT's `OB_CLOSE_METHOD` moment
  (`IopCloseCompletion`, opening with `if (systemHandleCount != 1) return;`).

**The shape this replaced is worth naming, because it read as correct.** The
port body used to begin with a `KSEMAPHORE` whose count was the queue depth,
with a comment saying "nothing on the CUI path waits on port handles". That is
one channel doing both jobs, and it is wrong in both directions: a handle wait
**consumed** a packet, and one packet woke exactly **one** of two handle
waiters. The comment had been true when written and nothing re-read it once the
winetest gate became a consumer — `ntdll:sync`'s
`test_completion_port_scheduling` parks two threads on the handle and posts one
packet, so the second never woke and the pair burned its whole 300 s timeout
(docs/21 W10).

**The waiter block lives on the parked thread's own kernel stack.** It needs no
allocation and no lifetime rule: the parked syscall holds the port reference
that keeps the object alive around it, and the block is unlinked under the
dispatcher lock before its frame returns. The one case worth stating is a
hand-off that races the deadline — the poster has already dequeued the packet,
so the hand-off beats the wait's own `STATUS_TIMEOUT` and nothing is dropped.

**Deciding and signalling had to be one step**, which is the only thing this
touched outside `io/`. "Does a parked remover take this packet, or does the
port's handle go signalled?" is read from state the dispatcher lock guards, and
`KeSetEvent` acquires that lock itself. `KiSetEventLocked` / `KiClearEventLocked`
(`kernel/ke/event.c`) are the lock-held halves; `KeSetEvent` and `KeResetEvent`
now go through them, so each transition is still stated once (Art. 11).

## What ROOT a named-pipe create and a pipe-relative open accept

`NtCreateNamedPipeFile` and `NtCreateFile` both take an
`OBJECT_ATTRIBUTES.RootDirectory`, and for the pipe device the answer is decided
in two different places in the oracle — which is why the ladder in
`fs/npfs/pipe.c` looks lopsided and why a single "does the root resolve" test
gets it wrong. Pinned by `tests/ntapi/sem_pipe/pipe_root.c`; it takes
`ntdll:pipe` from **60** failed assertions to **37** (`pipe.c:2842`-`:2936`,
`test_empty_name`).

**An EMPTY name is decided in the HANDLER, and the root goes unread.**
`server/named_pipe.c` `DECL_HANDLER(create_named_pipe)`:

```c
if (!name.len)  /* pipes need a root directory even without a name */
{
    if (!objattr->rootdir) { set_error( STATUS_OBJECT_PATH_SYNTAX_BAD ); return; }
    if (!(root = get_handle_obj( current->process, objattr->rootdir, 0, NULL ))) return;
}
```

`get_handle_obj` with a NULL ops table and an access of 0 is *any object, no
rights*, and `server/object.c` `create_named_object`'s empty-name arm then
allocates the pipe with `alloc_object( ops )` and never touches `parent`. So an
**event handle is a legal root for an unnamed pipe**, and the only refusals are
a missing root (`STATUS_OBJECT_PATH_SYNTAX_BAD`) and a handle naming nothing
(`STATUS_INVALID_HANDLE` — the handle's fault, not the name's).

| root, with an empty name | answer |
|---|---|
| none | `STATUS_OBJECT_PATH_SYNTAX_BAD` |
| a closed/bogus handle | `STATUS_INVALID_HANDLE` |
| an event, a pipe end, the pipe device's root directory | an UNNAMED pipe, `FILE_CREATED` |
| any of those, with `FILE_OPEN` | `STATUS_OBJECT_TYPE_MISMATCH` |

The `FILE_OPEN` row is the one that reads as a bug and is not: `open_named_object`
resolves an empty name to the **root itself** (`lookup_named_object`'s
`if (!name_tmp.len) ptr = NULL`, which every `lookup_name` answers with "myself")
and then type-checks it against `named_pipe_ops`, which no root ever is. So
"open the unnamed pipe" is not a request that can exist, and the status is about
the ROOT's type rather than about a missing name.

**A NAMED create is decided in the LINK**, `server/named_pipe.c`
`named_pipe_link_name`:

```c
if (parent->ops == &named_pipe_dir_ops) parent = &((struct named_pipe_device_file *)parent)->device->obj;
if (parent->ops != &named_pipe_device_ops) { set_error( STATUS_OBJECT_NAME_INVALID ); return 0; }
namespace_add( ((struct named_pipe_device *)parent)->pipes, name );
```

The device's root DIRECTORY is folded onto the device and every other parent is
`STATUS_OBJECT_NAME_INVALID`. Two consequences that a status table does not show:

- **the name always lands in the DEVICE's flat namespace, whatever root was
  used** — so a pipe created relative to the root directory is openable by its
  absolute `\??\pipe\<name>` afterwards, and a **component separator in the name
  is a character rather than a path**: `"test3\pipe"` is one key
  (`find_object` hashes the whole remaining name, `named_pipe_device_lookup_name`);
- **a root that is not a File at all gets the NAME error, not a type error.**
  The handler resolves it as any object and the refusal happens one frame later
  in the link, so an event and a FAT directory answer identically. `kernel/io`'s
  `IopReferenceRelativeRoot` reports `STATUS_OBJECT_TYPE_MISMATCH` for the first,
  and npfs maps exactly that one status onto `STATUS_OBJECT_NAME_INVALID`.

**The three refusals are ORDERED, and the order is separable from all three.**
The handle is resolved above everything (`server/request.c`
`get_req_object_attributes`, whose `get_handle_obj` failure returns before
`create_named_object` is called), so a root naming nothing is
`STATUS_INVALID_HANDLE` whatever the name is. Then `lookup_named_object`'s
**first** guard refuses an **absolute** name under *any* root that resolved —
`if (root) { if (name_tmp.len && name_tmp.str[0] == '\\') set_error(
STATUS_OBJECT_PATH_SYNTAX_BAD ); }` — which fires before `lookup_name` and
before `named_pipe_link_name`. Only then does the link ask whether this root
reaches the pipe namespace. A ladder that asks about the ROOT first passes every
row where the root *is* the pipe device and answers `STATUS_OBJECT_NAME_INVALID`
for an absolute name under an event, a disk directory or a pipe end, where the
oracle answers the syntax error; `sem_pipe/pipe_root.c` walks all four roots
with the same absolute name for exactly that reason, and gate-check found the
order wrong on the first draft. The syntax error is also not the
`STATUS_INVALID_PARAMETER` `NtCreateFile` gives for the identical mistake — that
one is ntdll's own check on a path this call never goes through (see "An
ABSOLUTE name under a RootDirectory handle").

**The pipe-relative OPEN is the third root, and it is how an unnamed pipe is
reachable at all.** `pipe_server_lookup_name` refuses a non-empty name
(`STATUS_OBJECT_NAME_INVALID` — an end has no namespace to hold one) and
resolves an empty name to the end itself, whose `pipe_server_open_file` is a
bare tail call onto `named_pipe_open_file` — the same function a by-name client
open reaches. So a second such open answers `STATUS_PIPE_NOT_AVAILABLE` exactly
as a busy pipe's by-name open does, and `NpfsAttachClient` (`fs/npfs/pipe.c`) is
the one transcription both callers use (Art. 11). The CLIENT end is not a root
in turn: `pipe_client_ops` carries `no_lookup_name`, whose two arms give two
statuses — an empty name sets `STATUS_OBJECT_TYPE_MISMATCH` itself, a non-empty
one returns with no error and leaves the name unconsumed, which
`open_named_object` reports as `STATUS_OBJECT_NAME_NOT_FOUND`.

An empty name under the device's root DIRECTORY handle is
`STATUS_OBJECT_TYPE_MISMATCH` too, for a third reason:
`named_pipe_dir_open_file` opens with `if (dir->fd) return no_open_file(...)`,
and the root handle in hand has already been turned into a file object. It does
**not** produce a second root handle.

**An unnamed pipe has no name to report, and says so through the orphan's
status.** `pipe_end_get_file_info`'s `FileNameInformation` arm is
`if (!pipe || !(name = get_object_name( &pipe->obj, &name_len )))
{ set_error( STATUS_PIPE_DISCONNECTED ); return; }` — one guard, two conditions,
so a pipe that never had a name answers what an end whose pipe was taken away
answers. `NpfsQueryName` implements the second disjunct; reporting the bare
`"\"` there would be a fabricated name (Art. 12).

**All of it, and a third state the oracle folds into the same guard.**
`NpfsQueryName` asks `pipe == 0 || pipe->name.Length == 0`, which covers the end a
disconnect threw out, a pipe that never had a name, and a pipe UNLINKED because
its last instance closed — the oracle's `get_object_name` answers NULL for that
one too. See "How long a pipe outlives its NAME"; the guard was one disjunct
short until the pipe's lifetime and its name's were told apart.

**The device and its root directory ARE distinguished** — see "Two spellings of
a device root" below, which is where the fourth root in this ladder is
described. A NAMED create relative to a `\Device\NamedPipe` handle is
`STATUS_OBJECT_NAME_INVALID` because that handle is not one of the two parents
`named_pipe_link_name` accepts; a named OPEN relative to it is
`STATUS_OBJECT_NAME_NOT_FOUND`, the CLIENT end's answer above, and for the same
reason — `no_lookup_name` consumes nothing.

## What the named-pipe DEVICE ROOT answers to each pipe FSCTL

Every pipe verb asked of a handle that is not a pipe END goes through one switch,
`server/named_pipe.c` `named_pipe_device_ioctl`, and its three answers do **not**
collapse into a single "wrong object for this verb". Transcribed into
`fs/npfs/pipe.c` `NpfsDeviceControl`'s root arm and pinned by
`tests/ntapi/sem_pipe/device_ioctl.c`; it takes `ntdll:pipe` from **37** failed
assertions to **29** (`pipe.c:2751`×8, four rows asked through each of the two root
spellings).

| verb | answer | what it is saying |
| --- | --- | --- |
| `FSCTL_PIPE_LISTEN`, `FSCTL_PIPE_IMPERSONATE` | `STATUS_ILLEGAL_FUNCTION` | this object does not HAVE the verb |
| `FSCTL_PIPE_DISCONNECT`, `FSCTL_PIPE_TRANSCEIVE` | `STATUS_PIPE_DISCONNECTED` | a STATE the device is not in |
| `FSCTL_PIPE_QUERY_CLIENT_PROCESS` | `STATUS_INVALID_PARAMETER` | the ARGUMENTS — decided above any look at them |
| `FSCTL_PIPE_WAIT` | the device: `STATUS_ILLEGAL_FUNCTION`; its root DIRECTORY: the name lookup | the one arm where the two objects part; see "Two spellings of a device root" |
| everything else, `FSCTL_PIPE_PEEK` included | `STATUS_NOT_SUPPORTED` | `default_fd_ioctl`'s own default (`server/fd.c`) |

**`FSCTL_PIPE_PEEK` is the discriminating row and it is not in the switch.** It is as
much a per-instance verb as `FSCTL_PIPE_LISTEN` is, so `STATUS_ILLEGAL_FUNCTION` is the
answer a ladder grouped by MEANING gives — and proskrnl gave it. The oracle never names
PEEK here, so it falls through to the unknown-verb default like a verb the device has
never heard of. No winetest assertion convicts that: `pipe.c:2721` asks the same call
and is `todo_wine` (it wants NT's `STATUS_INVALID_PARAMETER`), so the row is pinned
because the oracle answers it, not because anything failed.

**The refusals precede the arguments.** A `FSCTL_PIPE_TRANSCEIVE` carrying a legal
input and output buffer is still `STATUS_PIPE_DISCONNECTED`, and a
`FSCTL_PIPE_QUERY_CLIENT_PROCESS` with room for its reply is still
`STATUS_INVALID_PARAMETER` — the opposite of what that status invites an implementation
to build. Both leave the caller's `IO_STATUS_BLOCK` untouched, the rule
`sem_pipe/ioctl_event.c` pins for an ioctl refused on the spot.

**`FSCTL_PIPE_WAIT` is the one arm the two roots do not share**, and the SHAPE of
the split is what `NpfsDeviceControl` transcribes rather than the statuses: the
directory's ladder is that one arm plus a tail call onto the device's
(`named_pipe_dir_ioctl`), so the device's `STATUS_ILLEGAL_FUNCTION` sits above both
the name lookup and the input-buffer check the directory makes first. A wait for a
pipe that EXISTS and is LISTENING is still `STATUS_ILLEGAL_FUNCTION` through the
device, and so is one whose buffer stops inside the name it claims — the same call
the directory answers `STATUS_INVALID_PARAMETER`. See "Two spellings of a device
root".

**DEVIATION — the four verbs `default_fd_ioctl` answers SPECIALLY are not
transcribed.** `FSCTL_DISMOUNT_VOLUME` is `STATUS_BAD_DEVICE_TYPE` on the oracle
(`get_unix_fd` of the device's pseudo fd) and the three reparse-point verbs are
`STATUS_OBJECT_TYPE_MISMATCH` (no `unix_name`); proskrnl folds all four into the
`STATUS_NOT_SUPPORTED` default, which names itself on serial. Nothing baked reaches
them and no pin asserts them.

## Two spellings of a device root: `\Device\NamedPipe` is not `\Device\NamedPipe\`

A name that ends AT a device and a name that ends with the device's terminating
separator are two different names, and NT resolves them to two different objects:
the DEVICE itself, and the device's root DIRECTORY. The oracle spells the whole
distinction in two lines of `server/named_pipe.c`
`named_pipe_device_lookup_name`:

```c
if (!name) return NULL;                    /* open the device itself */
if (!name->len && name->str) { ... }       /* open the root directory */
```

`name == NULL` is `server/object.c` `lookup_named_object`'s `if (!name_tmp.len)
ptr = NULL` — the walk consumed the whole path — while a name that is PRESENT and
EMPTY is what a trailing separator leaves behind. So the fact is carried by a
pointer, not by a length, and the only place it exists is the parse.

**Ob carries it in the parse remainder's `Buffer`, because a `UNICODE_STRING` has
nowhere else to put it.** `ObpLookupName`'s parse-object handoff (`kernel/ob/
namespace.c`) now yields `Buffer == 0, Length == 0` for `\Device\NamedPipe` and a
live `Buffer` with `Length == 0` for `\Device\NamedPipe\`. It had folded the two,
and *where* it folded them is the lesson: the loop already computed the
difference (`trailingEmpty`, which the symbolic-link arm needs so a reparse can
rebuild `\??\C:\` with its separator intact) and then dropped it on the way out.
Every filesystem sees the distinction through that one parse; a second parser
re-examining the caller's name would be an Art. 11 failure, and this is the same
engine Art. 11 has for names.

**npfs decides it ONCE, at create, and then asks the FILE_OBJECT.** The two roots
get two FCBs (`NpfsRootFcb`, `NpfsDeviceFcb`) — two objects, as on the oracle,
where they are a `named_pipe_device_file` and a `named_pipe_dir` — and
`NpfsIsDeviceFile` is what every later rule asks. Both still carry
`fsContext == 0`, so no "is this a pipe end" test in the file changes. Three
rules follow, all pinned by `tests/ntapi/sem_pipe/device_root.c`, and each is a
different function's refusal:

| through the DEVICE | through the root DIRECTORY | the oracle's site |
| --- | --- | --- |
| `FSCTL_PIPE_WAIT` → `STATUS_ILLEGAL_FUNCTION`, above the lookup AND above the buffer check | the name lookup: absent → `STATUS_OBJECT_NAME_NOT_FOUND`, listening → `STATUS_SUCCESS`, short buffer → `STATUS_INVALID_PARAMETER` | `named_pipe_dir_ioctl` (one arm, then a tail call onto `named_pipe_device_ioctl`) |
| a NAMED create → `STATUS_OBJECT_NAME_INVALID` | the pipe is created in the device's flat namespace | `named_pipe_link_name` (accepts only the device or its directory as parent) |
| a NAMED open → `STATUS_OBJECT_NAME_NOT_FOUND`, **whether or not the pipe exists** | the pipe opens | `no_lookup_name` leaves the name unconsumed; `open_named_object` reports that |
| `ObjectNameInformation` → `\Device\NamedPipe` | → `\Device\NamedPipe\` | `named_pipe_device_file_get_full_name` defers to the device; `named_pipe_dir_get_full_name` appends the separator |

Two things it deliberately does NOT change:

- **the UNNAMED create is blind to which root it is**, and to the root's type
  entirely — `create_named_object`'s empty-name arm allocates an unlinked pipe
  and never reads the parent, so an event handle is still a legal root
  ("What ROOT a named-pipe create and a pipe-relative open accept"). The
  winetest marks that `todo_wine` at `pipe.c:2800`, i.e. NT refuses it and the
  pinned oracle does not; Art. 6 makes the oracle the spec, so this is pinned as
  measured and not "fixed" toward NT;
- **every other pipe FSCTL still answers identically through both handles**
  (`sem_pipe/device_ioctl.c` §4 runs the whole eight-row matrix twice), because
  the directory's ladder is one arm plus a tail call. A split implemented as
  "the device refuses more things" would pass `:2787` and fail that matrix.

**DEVIATION — `fs/fat32` does not read the distinction yet.** `\??\C:` and
`\??\C:\` both still open the volume's root directory, so
`CreateFile("\\\\.\\c:")` is `STATUS_FILE_IS_A_DIRECTORY` (`kernel32:volume:632`).
Nothing is missing in the parse: what is missing is a volume DEVICE object for
the first spelling to open, plus the `IOCTL_VOLUME_*` surface behind it. That is
`docs/21` W7's remaining half and the manifest block has the triage. The parse
change is inert for fat32 — a zero-length remainder is a zero-length remainder
whatever its `Buffer` — which is why this landed with npfs's consumer and no
fat32 change.

## `FileNameInformation`'s length floor is the whole struct

`NtQueryInformationFile(FileNameInformation)` refuses a buffer shorter than
`sizeof(FILE_NAME_INFORMATION)` — **8** bytes, the `ULONG` count plus its
`WCHAR FileName[1]` tail — not shorter than the tail's offset. The floor is ntdll's own
table entry (`dlls/ntdll/unix/file.c` `NtQueryInformationFile`, `info_sizes[]`), which
sits above the handle and therefore above every device: a pipe end and a FAT file answer
the ladder identically. Pinned by `tests/ntapi/sem_file/name_info_length.c`.

The two spellings differ for exactly the buffers 4..7 bytes long, and they differ in
STATUS, not in how much they copy: an `offsetof` floor accepts four bytes, writes the
count into them and reports `STATUS_BUFFER_OVERFLOW` where the oracle reports
`STATUS_INFO_LENGTH_MISMATCH` and leaves the caller's buffer alone. `ntdll:pipe:1987` is
the consumer. At the floor exactly, the class succeeds into an overflow: the count is
reported in full, one `WCHAR` of name fits, and `Information` counts the 8 bytes consumed
rather than the bytes owed.

## What a FILE handle is called in the object namespace

`NtQueryObject(ObjectNameInformation)` answered **success with an empty
`UNICODE_STRING`** for every file handle in the system. A `FILE_OBJECT` is never
linked into the Ob namespace — the **device** is, and everything past it belongs
to that device — so the generic walk (`ObpFullNameLength` / `ObpWriteFullName`)
found no name for any of them and reported every one as nameless. That is
Art. 12's fabricated-plausible answer with no stub in it: a caller told a named
pipe has no name cannot tell two pipes apart, and is not told that it cannot.
It is the same defect `CmpQueryKeyObjectName` removed one type over, and
`ntdll:pipe` `:2849`/`:2881` are the assertions that could see it.

`IoFileObjectType` now carries the `queryName` hook, and the composition lives
in **one** place (`kernel/io/file.c` `IopQueryFileObjectName`): the device
object's own namespace name, plus the volume-relative path the filesystem's
`IO_VFS_OPS.QueryName` already builds for `FileNameInformation`. A filesystem's
only say is whether its files are in a namespace at all
(`IO_VFS_OPS.namedInObjectNamespace`) — so no FS grows a second name source
(Art. 11), and the two spellings of "what is this file called" cannot drift.
That is the oracle's own shape, where the answer is per object type: an end
defers to its pipe and the pipe walks to the device
(`server/named_pipe.c` `pipe_end_get_full_name` → `named_pipe_get_full_name` →
`default_get_full_name`), a disk file reports the name its fd captured
(`server/fd.c` `default_fd_get_full_name`), and a console object has none at all
(`server/object.c` `no_get_full_name`).

Three rules came out of it and none follows from the class name:

- **"No name at all" and "no name for THIS one" are different answers.** A
  device that is not in a namespace answers SUCCESS with an empty string — the
  oracle's `no_get_full_name` reply, which `server/handle.c`
  `DECL_HANDLER(get_object_name)` turns into a zero-length one — while a pipe
  that HAS a namespace and no name in it **refuses**, `STATUS_OBJECT_PATH_INVALID`.
  So proskrnl's condrv, `\Device\Fb0` and the sound devices stay nameless on
  purpose and match the oracle for doing so, and only `fat32` and `npfs` opt in.
  The filesystem spells the same "no name" fact `STATUS_PIPE_DISCONNECTED`
  through `FileNameInformation`, because that is what the oracle's *other* arm
  says (`pipe_end_get_file_info`): one fact, two syscalls, two names for it.
  **Two devices are a KNOWN REMAINING GAP rather than a measured answer**, and
  the distinction matters because the comment beside them will be read as a
  precedent: `\Device\Null` and `\Device\MountPointManager` still report the
  empty name, while the oracle reports the device's own name for them
  (`server/device.c` `device_file_get_full_name`; `dlls/ntdll/tests/om.c` pins
  `\Device\Null` with no `todo_wine`, and `ntdll:om` is parked for an unrelated
  oracle crash so nothing convicts it today). What keeps them out is mechanical
  — their `QueryName` answers the ABSOLUTE device path where the composition
  wants the volume-relative part — so opting them in means moving what
  `FileNameInformation` reports for them, which is its own item with its own pin.
- **The too-short status belongs to the TYPE, not to the query.** Every
  file-ish `get_full_name` in the oracle sets `STATUS_BUFFER_OVERFLOW`
  explicitly where the generic walk leaves `STATUS_INFO_LENGTH_MISMATCH`
  (`default_fd_get_full_name`, `named_pipe_get_full_name`,
  `named_pipe_dir_get_full_name`), so a registry key and a file answer
  *differently* to the same mistake — `OBJECT_TYPE.nameTooShortStatus`. Only a
  buffer between `sizeof(OBJECT_NAME_INFORMATION)` and the full size can see it:
  below the struct the answer is `STATUS_INFO_LENGTH_MISMATCH` on both, forced
  one layer up (`dlls/ntdll/unix/file.c` `NtQueryObject`).
- **A name too long to be REPORTED is `STATUS_NAME_TOO_LONG`, refused below the
  size protocol.** The class reports a `UNICODE_STRING`, whose `Length` and
  `MaximumLength` are `USHORT`s, so a name past `0xfffc` bytes cannot be
  described — and it is reachable, because a pipe's name is the caller's
  `ObjectName` bounded by that same `USHORT`: 32760 characters relative to
  `\Device\NamedPipe` composes to 65556. A **too-small** buffer is still
  answered the ordinary way, `STATUS_BUFFER_OVERFLOW` carrying the whole 65574,
  because that is what the oracle does and it is measurable. Only above it does
  the oracle stop being a spec: it answers SUCCESS reporting `Length` 20 and
  `MaximumLength` 22 — 65556 truncated into the `USHORT` by
  `p->Name.Length = res` (`dlls/ntdll/unix/file.c` `NtQueryObject`) — which
  names a *different* object. Repeating that is Art. 12's fabricated answer;
  answering the length error instead would spin any caller that grows its buffer
  and retries (that same file's `server_get_name_info` is such a loop). The
  refusal is `kernel/ob/handle.c`'s, not the File type's, because it is a
  property of the ANSWER's shape; `object_name.c` §7 pins the short-buffer half
  against the oracle and the refusal in a `beyond_oracle` block.
- **The name goes with the PIPE's name, which goes with the last INSTANCE.**
  A client that outlives its server still reports the pipe's path while a second
  instance is open, and refuses once the last one closes — the same lifetime
  "How long a pipe outlives its NAME" states, asked through a different syscall.

**One thing the two runners are allowed to disagree about, and it is deliberate:
the PREFIX of a disk file's name.** The oracle reports the name its fd captured
at open — `\??\C:\prstest\objname.txt`, the DOS-device spelling the caller used
— because Wine's `C:` is a host directory and the server has nothing else to
report. proskrnl composes its volume device object's name,
`\Device\HarddiskVolume1\prstest\objname.txt`, which is what NT answers; tuning
it to the `\??\` form would be tuning to a Wine artefact. So the pin asserts what
is the same on both — the name ENDS with the file's path, a directory's name is
its file's name minus the last component, and the whole length protocol — and
says so rather than weakening. Pinned by `tests/ntapi/sem_pipe/object_name.c`.

## A create-time security descriptor takes the same merge a set does

`SeCaptureObjectSecurity` stored an `OBJECT_ATTRIBUTES.SecurityDescriptor` RAW.
Its header claimed to be "the ONE create-time SD site (G11)" and said
"token-defaulting of missing parts is `NtSetSecurityObject`'s job (no baked
create passes a partial SD)" in the same breath. The oracle defaults at create
too: `server/object.c` `create_object` and `create_named_object` both end with

```c
if (sd && !default_set_sd( obj, sd, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION ))
```

— i.e. the same `set_sd_defaults_from_token` a `NtSetSecurityObject` runs, with
every info bit on. So a create naming only a DACL comes back with the token's
owner and primary group filled in, and one naming only a group gets the token's
owner and default DACL. proskrnl now runs the same merge (`kernel/se/secobj.c`
`SepApplySecurityDescriptor`, the one writer of a stored descriptor), and
`SeCaptureObjectSecurity` takes the SLOT the blob lives in rather than an object
header — which is what lets an object whose descriptor is NOT on its own header
(a named pipe, below) use the one site instead of growing a second.

The claim about partial SDs was also simply false by the time it was read:
`CreateNamedPipeA(..., &sec_attr)` in `ntdll:pipe`'s `test_security_info`
passes an owner-and-group SD with no DACL. Pinned by
`tests/ntapi/sem_se/se_secobj.c`, whose discriminating case is exactly a
partial one — an SD carrying every part is indistinguishable from a raw copy.

## Whose security descriptor a pipe handle reports

`NtQuerySecurityObject` / `NtSetSecurityObject` read and wrote
`OBJECT_HEADER.securityDescriptor` — the object the HANDLE names. For a named
pipe that object is the `FILE_OBJECT`, one per open, and the descriptor is not
the file object's: **a pipe END has none of its own and defers to its PIPE**,
which every end and every instance of that name shares. The oracle says it in
two lines (`server/named_pipe.c`):

```c
static struct security_descriptor *pipe_end_get_sd( struct object *obj )
{
    struct pipe_end *pipe_end = (struct pipe_end *) obj;
    if (pipe_end->pipe) return default_get_sd( &pipe_end->pipe->obj );
    set_error( STATUS_PIPE_DISCONNECTED );
    return NULL;
}
```

`pipe_end_set_sd` is the same function one verb over. Two consequences, and
both are behaviour a caller can see: a group set through the server end is what
the CLIENT end reports (and a second instance, and a client opened later, and
the surviving end after the one that set it closed), and an end whose pipe is
gone — a client its server disconnected — **refuses** rather than reporting an
empty descriptor. `ntdll:pipe`'s `test_security_info` is ten assertions of the
first and two of the second.

**The mechanism is a REDIRECT, deliberately not a second get/set.**
`OBJECT_TYPE.securityStorage` (`kernel/ob/ob.h`) answers *which slot* an
object's descriptor lives in and never *what it says*, so Se keeps its one
capture / merge / filter path (`kernel/se/secobj.c`) and a type that redirects
gains no reading of an SD (Art. 11). `IO_VFS_OPS.SecurityStorage` is that
question one layer down, so the Io layer does not grow a per-device branch
either: `IoFileObjectType` asks the device, and a device that declines keeps
the file object's own slot, which is what every other device has always had.
npfs points it at the `NPFS_PIPE`, whose `end->pipe` is already the oracle's
`pipe_end->pipe`.

**The refusal sits BELOW the handle's access check**, and that ordering is the
oracle's: `server/handle.c` `DECL_HANDLER(get_security_object)` resolves the
handle with `READ_CONTROL` (plus `ACCESS_SYSTEM_SECURITY` for a SACL) and calls
`get_sd` afterwards. It falls out here because a hook is reached only once
`ObReferenceObjectByHandle` succeeded — and the only thing that can tell the two
statuses apart is an under-privileged query on a disconnected end, which is why
`tests/ntapi/sem_pipe/pipe_security.c` §6 asks exactly that.

**The create-time descriptor goes through the one create-time site**
("A create-time security descriptor takes the same merge a set does", above),
which is what lets a pipe carry one at all without growing a second.

**It binds ONCE, in the arm that MINTS the pipe.** A further instance of an
existing name carries its own `OBJECT_ATTRIBUTES` descriptor along and drops it,
because the oracle's `if (sd) default_set_sd( &pipe->obj, ... )` sits inside
"initialize it if it didn't already exist"
(`DECL_HANDLER(create_named_pipe)`). Applying it per instance passes the
winetest — which never sets a *different* one on a second instance — and lets
any caller that can open the pipe rewrite the security every other instance is
running under.

Pinned by `tests/ntapi/sem_pipe/pipe_security.c` and, for the create-time
defaulting shared with every Ob object, `tests/ntapi/sem_se/se_secobj.c`.

## What CLOSING a handle does to the requests that process left parked

`NtClose` used to do nothing to a parked request unless it was the last handle
in the system, in which case the filesystem's cleanup cancel-completed
everything on the file object. The moment in between had no answer at all: a
process that closed **its own last handle** to a pipe end, while another
process still held a duplicate, left its read parked forever — with the
caller's IOSB never written and, if the handle was bound to a completion port,
`GetQueuedCompletionStatus` waiting on a packet nobody would ever post.

NT cancels there, and so does the oracle. The rule is `async_close_obj_handle`
(`third_party/wine` `server/async.c`), which is the `close_handle` op of both
pipe-end object types (`server/named_pipe.c` `pipe_server_ops` /
`pipe_client_ops`) and of sockets (`server/sock.c`):

```c
if (obj->handle_count == 1 || get_obj_handle_count( process, obj ) != 1) return 1;
LIST_FOR_EACH_ENTRY( async, &process->asyncs, struct async, process_entry )
{
    if (async->terminated || async->canceled || get_fd_user( async->fd ) != obj) continue;
    if (!async->completion || !async->data.apc_context || async->event) continue;
    cancel_async( async );
}
```

Two counts and a three-term predicate. Every one of the five is a way an
implementation that reads only the first sentence diverges, and
`tests/ntapi/sem_pipe/close_cancel.c` measures each:

| the handle being closed | what happens to a parked request |
| --- | --- |
| last in the SYSTEM | nothing here — the FS cleanup answers it (unchanged) |
| last in this PROCESS, another process holds one | swept, if the three terms hold |
| not the last in this process | nothing; the request completes normally later |
| swept: port-bound at ISSUE + ApcContext + no event | `STATUS_CANCELLED`, IOSB written, packet posted |
| no completion port bound at issue | left parked |
| no ApcContext | left parked |
| an event supplied | left parked |

Three of those are worth stating in prose because each reads as a bug:

- **An EVENT disarms the sweep.** The thing a caller is most likely to be
  waiting on is exactly what stops the cancel, so a read issued with an event
  survives its own process's last close and reports nothing to anybody. That is
  the oracle's answer and the winetest's
  (`dlls/ntdll/tests/pipe.c` `test_async_cancel_on_handle_close` runs sixteen
  rows and exactly one reaches the cancel).
- **"Was this request port-bound" is asked of a different INSTANT than "which
  port gets the packet".** The packet's port is re-read at completion, so a bind
  that lands while a request is parked still gets its packet (`docs/21` W4c,
  `sem_pipe/pending_packet.c` §4). This predicate reads the value `create_async`
  captured at ISSUE and never re-reads it, so the same late bind does **not**
  arm the sweep. `IOP_PENDING_REQUEST.portBoundAtIssue` exists for that one
  difference, and `close_cancel.c` §6 is the only thing that separates them.
- **The two counts INCLUDE the handle being closed**, which is also NT's
  convention for `ObjectCloseMethod`'s `ProcessHandleCount` /
  `SystemHandleCount`. `OBJECT_TYPE.closeProcedure` now takes NT's shape and
  fires on EVERY close for that reason; a type that only wants the
  last-handle-in-the-system moment opens with `if (systemHandleCount != 1)
  return;` (`kernel/ob/ob.h`), which is the statement it used to make by being
  called nowhere else.

**Where the rule STOPS is decided by which devices can PARK, not by a branch.**
The sweep goes through `IO_VFS_OPS.CancelPending`, which only a filesystem that
queues requests implements — so npfs is swept and fat32 is not, exactly as the
oracle hangs the op off the pipe-end and socket types. Directory watches are
deliberately **not** swept: `server/change.c` `dir_close_handle` releases a cache
entry and nothing else, so a change-notify parked by a process that closes its
last handle stays parked until the last handle in the system goes.

**One divergence from NT is inherited from the oracle and is visible.** The
cancel writes the caller's IOSB immediately; Windows leaves it untouched until
`NtRemoveIoCompletion` delivers the packet. `ntdll:pipe:3111` wraps that
assertion in `todo_wine_if` for precisely this, so matching NT would score a
failure for being closer to NT — the same trade this file records for
`DeletePending` and `docs/21` records for `STATUS_USER_APC` (Art. 6). Writing it
late is also un-pinnable: the oracle writes it, so no G5 case could be green
asserting otherwise, and `beyond_oracle` is barred for behaviour Wine does
implement.

Pinned by `tests/ntapi/sem_pipe/close_cancel.c`.

## `ProcessIoCounters`: what proskrnl counts as an I/O operation

`NtQueryInformationProcess(ProcessIoCounters)` reports `EPROCESS.ioCounters`, charged by
`PsChargeIoCounters` (`kernel/ps/process.c`) — the single writer, read by both this class
and `SystemProcessInformation`'s `IoCounters` field. taskmgr is the consumer that forced
it: `programs/taskmgr/perfdata.c` calls `GetProcessIoCounters` once per process per refresh,
so an unbuilt class there panicked the boot (Art. 12 dialed to fatal).

The **shape** is the oracle's (`dlls/ntdll/unix/process.c`): short buffer refused, exact
buffer filled, oversized buffer filled *and* `STATUS_INFO_LENGTH_MISMATCH`, `returnLength`
always `sizeof(IO_COUNTERS)`. The **values** are not — the pinned Wine memsets them to zero
behind a `FIXME : real data`, so it is unbuilt for this and has nothing to say (Art. 12);
the contract used instead is Microsoft's own documentation of `IO_COUNTERS` /
`GetProcessIoCounters`, pinned in the `beyond_oracle` block of
`tests/ntapi/sem_file/io_counters.c`.

The deviation worth stating is **which requests are charged**. NT counts every IRP a
process issues: reads, writes, and "other" — which for NT includes device and filesystem
control, but also the query/set-information, flush and lock verbs. proskrnl charges only for
the verbs that carry a data or control payload, at the four sites a charged request can end
— `IopCompleteTransfer` (the inline tail), `IopCompletePendingRequest` (the pended one), and
the two scatter/gather completions in `IopSegmentedTransfer`, which write the IOSB
themselves:

| verb | counter |
|---|---|
| `NtReadFile`, `NtReadFileScatter` | Read |
| `NtWriteFile`, `NtWriteFileGather` | Write |
| `NtDeviceIoControlFile`, `NtFsControlFile` | Other |

Everything else — `NtQueryInformationFile`, `NtSetInformationFile`, `NtQueryDirectoryFile`,
`NtFlushBuffersFile`, `NtLockFile` — completes without charging, so proskrnl's "other"
totals run below NT's for the same workload.

**Which statuses charge** is one predicate, `IopChargesIoCounters` (`kernel/io/io.h`), asked
by all four sites: a request counts once it has COMPLETED with a transfer decided — success,
`STATUS_BUFFER_OVERFLOW`, or `STATUS_END_OF_FILE` (a read that found nothing is still a read
the device performed; it contributes zero bytes). A cancelled park never completed one and
charges nothing. It is a shared predicate rather than a rule spelled at each site because
the two tails did drift: the pended one filtered on `NT_SUCCESS` while the inline one
charged `STATUS_END_OF_FILE`, so an EOF read counted or not depending on which path served
it. Nothing at the boundary pins an absolute
total (no test can: the number is a property of the machine and of every DLL the process
loaded), and the documented meaning of each counter — one operation, its bytes — holds
exactly for the verbs above. A scatter/gather is ONE operation whatever its segment count,
which is what makes it one request rather than one per page. Charging the remaining verbs
is a strictly additive change if a consumer ever needs them.

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
not a live directory over there is refused. The server reads the session number off the
owning **process** rather than out of the handle's own name — the same answer for every case
the boundary can distinguish, since a process's window stations live in its session's
directory.

**The reason this paragraph used to give for that is stale and was left standing for two
milestones.** It said proskrnl's `NtQueryObject(ObjectNameInformation)` "returns an object's
leaf name rather than NT's full path", and that "making the name query answer full paths is
NT-correct and unbuilt". It answers the full path — `ObpFullNameLength` /
`ObpWriteFullName` walk to the root, and `docs/review-2026-07` §9 is where that landed. The
server's choice is a design one and still defensible; the constraint it was written against
no longer exists.

**A fault inside win32u is contained at the boundary Wine has and this build does not.**
On Wine every `NtUser*`/`NtGdi*` call crosses a syscall, and a fault taken past it does not
reach the caller: ntdll's unix half catches it and makes the *call* return the exception code
(`dlls/ntdll/unix/signal_x86_64.c handle_syscall_fault` — `RAX_sig = rec->ExceptionCode;
RIP_sig = __wine_syscall_dispatcher_return`). That containment is observable, not internal:

    GetClassLongPtrW( <a window owned by ANOTHER process>, GCLP_HICONSM )

faults inside win32u **on the pinned oracle too** — the window belongs to a different process,
so `dlls/win32u/class.c get_class_ptr` hands back the `OBJ_OTHER_PROCESS` sentinel and
`get_class_long_size` dereferences it whenever the class carries no small icon — and the
oracle answers the caller `0xc0000005` and keeps running (measured, two processes and one).
In-process, the same fault killed the process. taskmgr found it: its application page asks
every top-level window for a small icon, and conhost registers a plain `WNDCLASSW` with none.

`user/wine/dlls/win32u/glue.c` rebuilds the containment as a vectored handler rather than as a
wrapper around each of the ~483 exports, because the frame to return to is derivable: unwind
from the fault until the return address leaves win32u, and that frame is the one Wine's
dispatcher would have returned to. It is deliberately narrow — an access violation only, whose
faulting instruction is inside win32u itself (a fault in a user-mode callback runs in
user32/the app and is left to the SEH chain that owns it), and it declines if the unwind
cannot land outside win32u, so a containment that cannot name its destination never happens.
Every contained fault is still reported on serial: it is a defect somewhere in win32u, just
not the caller's death. Pinned by `tests/gui/gui3b.c` ("win32u fault contained"), which asks about
**A's** window — another process's by construction. It used to ask about the DESKTOP window,
which faulted only while that window belonged to no process; once conhost linked the real
user32 it became the boot's first desktop client and owned it, so the query returned 0
without ever reaching the dereference and the leg contained zero faults while every gui3
verdict passed. The leg awaits the discriminating form of the marker (the subject's own
`0xc0000005`), because the containment COUNT alone is satisfied by any contained fault on the
boot. The verdict is SURVIVAL and not the value — the value is Wine's bug leaking its exception code,
and it becomes a real handle the day upstream fixes it.

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
later threads inherit. The residual deviation — a process spawned *by a connected GUI
process* self-created where the oracle inherits the parent's window station and desktop
handles at connect time — was retired at GUI-6, where it first stopped being harmless: on
`WinSta0`/`Default` the self-create's `OBJ_OPENIF` converged on the same objects and only
the connect-time handles differed, but a child of explorer must land on explorer's desktop
(`shell`), which no self-create can find. The connect step is now run at attach
(`shim.c create_client`) through the pinned engine itself — `connect_process_winstation`
with an empty desktop path takes exactly its inherit-from-parent branches — with the parent
found by `InheritedFromUniqueProcessId` and required to be a connected client of the same
session (winstations are per-session; the oracle never faces the question because one
wineserver serves one session). One sliver survives: the oracle's call site passes the
spawning *thread* (`server/process.c new_process`), and the engine prefers
`parent_thread->desktop` over the process default; attach happens after the fact, so the
shim passes no thread and a child spawned by a parent thread that had `SetThreadDesktop`'d
off the process default inherits the process default instead of that thread's desktop.
Explorer's process default *is* its desktop, so GUI-6 never sees the difference.

**The desktop is forced on explorerless images, and its user entries look foreign.** On
Wine the desktop and `HWND_MESSAGE` windows belong to explorer: `get_desktop_window`
without `force` returns empty until explorer creates the desktop — win32u answers that by
*launching* `C:\windows\system32\explorer.exe` itself (`dlls/win32u/winstation.c
get_desktop_window`) — and every app process sees the windows' user entries carry a foreign
pid, which is what routes win32u onto its `WND_DESKTOP` special cases. Since GUI-6 that is
the shipping arrangement on any boot that HAS a shell, which `ShellBoot` derives rather
than being asked for by name (HACK-006, `user/smss/smss.c SmssIsShellBoot`): an
INTERACTIVE desktop boot, because a machine a human sits at has a shell, plus the gui6
leg, because GUI-6's subject IS the shell. It was "any image that carries `explorer.exe`"
until one image carried every leg's payload, and then briefly a flag of its own defaulting
OFF, which is how `make rungui` lost the shell it had always had. So: the gui6 leg and
`make rungui` — and those two only. gui5con is subtracted by name (`SmssIsShellBoot`
returns 0 for it: its subject is the console WINDOW, which the shell's explorer would take
the desktop away from), and wow64gui and the flash fixtures are `Serial`=1 boots, which is
the "something off-box is driving this" case a shell has no prompt for. On a shell boot the
clients are
routed onto explorer's desktop by registry (`HKCU\Software\Wine\Explorer
"Desktop"="shell"`, the configuration a Wine user sets for a virtual desktop — written
natively by smss before the first client connects; a GUI-process writer was the first
cut's defect, `user/smss/smss.c SmssShellDesktopConfig`): the fixture sites are all off, explorer creates
and owns the desktop, and the entries are foreign because they are. On a boot without a shell — every scripted GUI gate (gui, gui2..gui5, winetest-gui and the
audio legs), which runs a purpose-built client against the compositor or the message path
and whose golden was measured with no explorer on the desktop, plus every CUI boot, which
has no desktop at all — win32u's launch would fail and its force-fallback re-enter both
convicted failure modes below, so there the GUI-2 fixture stays, keyed on one flag
(`shim.c prsk_no_explorer`, the negation of the derived `ShellBoot`; it used to PROBE for
the explorer path win32u hardcodes — the answer is printed on serial either way):
the shim sets `force` on every `get_desktop_window` (the same server path the forcing
caller takes) and then clears the owner ids on the two entries so they read as foreign
(`shim.c detach_user_entry`; the server side is already detached,
`server/window.c detach_window_thread`). Without that second half the entries kept our own
pid, win32u went looking for a client-side WND that was never made, `GetWindowLong` on the
desktop answered style 0, and the first `ShowWindow` took the invisible-parent shortcut —
the window turned visible without ever being exposed, and nothing painted. (The other
convicted mode is the forced create's `set_process_default_desktop` side effect, restored
across the call — the `defaultDesktop` block in `prsk_server_dispatch`, which cost 10
`msg.c` failures before GUI-5 found it.) The desktop window's rects are sized by
winefb.drv's `pSetDesktopWindow` to the scanout — under explorer that hook runs in
explorer's process exactly as `X11DRV_SetDesktopWindow` does on Wine; under the fixture it
is the same repair X11DRV makes when it finds the rects uninitialized. The two
`user32:msg` assertions this fixture costs (`SetFocus`/`SetForegroundWindow` on the
desktop window: no owning thread ⇒ `ERROR_INVALID_HANDLE` where Wine's explorer-owned
desktop answers `ERROR_ACCESS_DENIED`) remain inside the msg pair's budget in
`tests/winetest/manifest-gui.txt` —
they flip only on a winetest-gui boot that DERIVES `ShellBoot`=1, which the decision above
declined (the payload is on the volume either way now; it is the flag that decides).

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
- **exposure**: the *mover* repairs the world from `pWindowPosChanged` — other top-levels
  touching the vacated area are invalidated cross-process (`NtUserRedrawWindow` → server
  `redraw_window` wakes their queues), the desktop-owned remainder is filled directly, and the
  moved window's own surface is re-blitted whole (a pure move dirties nothing: the surface is
  reused and `move_window_bits` is an identity no-op). The same hook repairs the **hide**
  (`SWP_HIDEWINDOW` arrives with the dummy surface, so the vacated rect comes from the rects
  win32u passes — this is the one repair a closing window gets, since `DestroyWindow` hides
  first), the **resize** (a replaced surface's screen rect rides over on its successor —
  blit.c's `vacated` stash — and is compared against the new rect exactly once), and the
  **z-drop** (an insert-after that can lower asks everything the window's rect touches to
  repaint; a raise needs only the forced re-blit). Deliberately NOT hung off the window
  surface's destroy callback: that fires when the surface's *refcount* dies, not when the
  window leaves the screen, and cached DCs (win32u keeps a released cache DCE bound, dibdrv
  surface reference included, until reuse or purge) pin surfaces so far past `DestroyWindow`
  that across a whole measured session the callback fired exactly **never** — which was the
  winemine close afterimage the compositor unit suite pins (tests/run/run.sh winefbunit,
  tests/winefb/ — the real compose.c/blit.c objects against a mocked seam, one case per
  compositor policy bug; the gui legs stay the end-to-end umbrella);
- **activation raises, silently**: clicking a covered window must bring it to the *front*,
  and neither win32u nor the server reorders top-levels on activation — on Wine the driver's
  `pActivateWindow` hook hands exactly this to the native windowing system (winex11 sets
  `_NET_ACTIVE_WINDOW` and the X window manager restacks). winefb is the native windowing
  system, so its hook restacks itself — but as a **raw `set_window_pos` request**, never a
  client-side `NtUserSetWindowPos`: an X window manager's restack is invisible to Win32 (no
  `WM_WINDOWPOSCHANGING/CHANGED` reaches anyone), and `user32:msg`'s recorded sequences hold
  the driver to exactly that — the message-visible spelling failed 77 of its cases. The
  server half alone restacks (`link_window` owns the topmost band for `previous=0`),
  computes the exposure, and wakes the risen window's queue; the repaint arrives as an
  ordinary `WM_PAINT` for the newly-visible region — the same convergence an X expose event
  drives. The request preserves the stored visible/surface rects and paint flags (built as
  `apply_window_pos` builds it — they are load-bearing: `get_visible_region` and `top_rect`
  derive from them). Without the hook a click moved focus, caption state and input to a
  window whose pixels stayed underneath — never a regression but a hole open since GUI-4,
  masked while windows rarely overlapped.

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

**Input0's reader placement was a live bug twice, and the second fix moved the readers into
the session server.** First shape: the GUI-2 start hook — `pUpdateDisplayDevices` — is never
called once the display cache is warm in the registry, so the app under test had *no* reader
at all. The fix made `winefb_start_input` idempotent and fired it at the first window
surface: every GUI process attempted the exclusive opens, one won, losers exited quietly on
`STATUS_SHARING_VIOLATION` — with a *named* residual: if the winning process died, input was
orphaned until a process that had not yet attempted created its first surface. The residual
then shipped as a user-visible bug: a cold `make rungui`'s firstboot churn hands the claim
to a chain of transients ending in the second explorer, which loses the desktop race and
exits — no mouse, no keyboard, until reboot (three `input READY` claims on one boot; the NMI
dump showed no thread left in `NtReadFile` on either device).

Second fix, the current design: **wineserver-lite hosts the readers** — the RIT's role,
placed where NT 3.x placed it (the user-mode session server; win32k took it later). The pump
(`wineserver-lite/server/rawinput.c`) claims both exclusive opens at bring-up, *before* the
transport is published, so it wins deterministically, and its lifetime is the session's — the
orphan is unreachable, not retried around. Injection is the same engine a client's
`NtUserSendHardwareInput` reaches: a `send_hardware_message` request run through
`prsk_internal_dispatch` (shim.c) under the server lock, with hardware origin, for which the
whole pinned path is `current`-independent; what win32u does client-side before that request
(kbdus scancode→vkey resolution, abs→pixel scaling) the pump mirrors, tables cited. The pump
is also the cursor's mover: one more scanout writer that draws the shared arrow
(`cursorshape.h`) and repairs the vacated rect — overlapped top-levels through
`redraw_window`, the desktop remainder filled directly. The per-process readers are
**deleted, not demoted**: a GUI client never opens `\Device\Input0/1` at all — the devices
belong to the session server the way NT's input hardware belongs to the RIT, and a fallback
electorate beneath it would just be the orphaning bug kept on retainer. The coldinput leg
pins the placement (READY precedes the first client attach) and the acceptance (the
`gui4 ptr` echo on a settled cold boot).

**Pointer injection is the winewayland shape, per event.** The tablet's absolute axes scale
to scanout pixels in the pump (range from `IOCTL_PRSHID_GET_ABS_INFO`, screen from the
mode — no QEMU constant on either side) and inject as
`MOUSEEVENTF_MOVE|ABSOLUTE|MOVE_NOCOALESCE` with hwnd 0: the pump serves the desktop, and
the unmodified server routes by capture and coordinate (`find_hardware_message_window`).
`MOVE_NOCOALESCE` bypasses the motion accumulator win32u would apply — QEMU already
coalesced.

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
pixels** — the mover (the server's pump) invalidates the covered top-levels and fills the
uncovered remainder, the same walk a client's repaint authority does (Art. 11: windows and
the cursor vacate screen rects for different reasons, but one walk repairs both). Whether a
process draws a cursor at all needs no pointer-presence flag: only the pump moves the
cursor, so on a keyboard-only image the published position never leaves the initial `(0,0)`,
which the paragraph below already refuses to draw at.

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

- ~~**lowering** a window (`HWND_BOTTOM`) exposes the sibling that rises above it with no
  notification anywhere~~ — retired: `pWindowPosChanged` now treats a lowering insert-after
  as an exposure and routes the window's rect through the repaint authority (blit.c); the
  risen sibling repaints its overlap cross-process, the same convergence as the mover's.
- **a violently-dead client's windows** are torn out of the tree by the server reap with the
  winefb repair unreachable (it lives in the dead process). The reap now asks the whole
  desktop to repaint — one `redraw_window(desktop, RDW_ALLCHILDREN)` fabricated through the
  same dispatch the transport drives (shim.c) — which converges on every explorer-bearing
  image; on an explorerless image the desktop window has no painter, so desktop-owned pixels
  stay stale until the next mover repairs them (no fixture leg kills a window-owning process
  mid-scene).
- a **flush racing its own window's hide** used to paint unclipped (the z-order query's
  "hwnd not found" fallback subtracted nothing); it now paints nothing — the safe direction,
  since the re-show forces a full flush anyway (compose.c `winefb_windows_above`).
- ~~**window shapes are not composited**~~ — retired for the flush half: a shaped
  (`SetWindowRgn`) or color-keyed layered surface now blits only its shape's set bits
  (blit.c `blit_rect_shaped`; pinned both row orders in tests/winefb/). What REMAINS is the
  occlusion half: `winefb_windows_above` still subtracts a shaped window's full *rect* from
  the windows below, so pixels under its holes go stale when the window beneath repaints —
  bounded by the shaped window's lifetime, repaired by its hide like any vacate. Shape-aware
  occlusion would need every flush to fetch every sibling's shape cross-process; not on the
  milestone path.
- **uniform layered alpha renders opaque**: `SetLayeredWindowAttributes` with `LWA_ALPHA`
  < 255 needs read-modify-write blending against whatever is beneath, which a one-copy
  compositor does not retain; dce.c folds `LWA_COLORKEY` (and per-pixel alpha masks) into
  the shape bitmap, so those DO composite. Nothing on the milestone path fades a window.
- **more than 64 top-level windows** makes the z-order query answer "nothing is visible":
  every flush paints nothing until the count drops — the safe direction (subtracting
  nothing would paint soup) — and the overflow names itself once on serial
  (`[KTEST] gui2 toplevel overflow`, Art. 12; pinned in tests/winefb/). 64 is far beyond
  any milestone's desktop; if that line ever prints, raise `WINEFB_MAX_TOPLEVELS`.
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
  probe of the server image was rejected: gui3/gui4/winetest-gui images carry wineserver-lite
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

The trophy gate (`tests/run/run.sh winetest-gui`) runs the pinned tree's own
`user32_test.exe msg` — 21.5 kloc, ~85 test functions — over the full GUI stack, swept by
the same kernel wtest runner as the CUI manifest (`tests/winetest/manifest-gui.txt`, in the
same `<exe>:<subtest>[:<budget>][:<timeout_s>]` grammar the CUI list uses — docs/14 "A
manifest line").

- **There is an oracle leg since the oracle got a display — and this note used to say the
  opposite.** Through GUI-6 the pinned oracle was `--without-x`, and under its null display
  driver user32 refuses every window ("The graphics driver is missing",
  `nodrv_CreateWindow`): msg.c failed its first `CreateWindow` and then hung forever in
  `test_SendMessage_other_thread` (an INFINITE wait on a thread whose window never
  existed), so the recorded oracle baseline was *cannot run*, not a failure count. This
  entry then rejected building one: "an X11-driver-driven message environment is no more
  'the spec' for a winefb target than nulldrv is, and it would drag X into a tree that
  deliberately has none." **The premise is still true and the conclusion was wrong**, on
  two counts. The X oracle was never going to be the spec and is not being asked to be —
  the spec is still msg.c's own `ok()`/`todo_wine` assertions (winetest is third-party,
  Windows-verified spec, docs/08, and `todo_wine` evaluates on proskrnl exactly as on Wine:
  the M10 finding that `winetest_platform_is_wine` is TRUE here). What it is, is the only
  available SECOND RUN of the same code: the same unmodified user32/gdi32/comctl32 PE
  binaries above the same win32u, with only the display driver and everything under it
  different (winex11.drv on Xvfb vs. winefb.drv on `\Device\Fb0` over our own kernel). A
  divergence between the halves is localized to that seam by construction, and without one
  "17 failures" and "17 failures of ours" were the same sentence. The second count is that
  the cost was mispriced: "drag X into a tree that deliberately has none" describes the
  TARGET, and the oracle is a host program, not the target — and the same argument, made
  one milestone earlier about fonts, is what GUI-3 had to reverse to stop the oracle
  answering metric questions from no font backend at all (docs/06 "One tree, three roles").
- **Only the kernel half is budgeted; the oracle half is demanded green.** The kernel
  half grades against the msg pair's own budget field in `manifest-gui.txt` — a ceiling
  over *our* divergences plus a machine-speed band. The oracle half has no ceiling at all,
  for the reason the CUI leg has never had one: a budget is a ceiling over what is OURS,
  and on unmodified Wine running its own suite nothing is.

  It briefly had one. **Measured, the oracle answered 1** — three consecutive runs,
  byte-identical (32082 tests executed, 234 marked as todo, 3 skipped, 1 failure, ~83 s),
  always `msg.c:5730`, `ShowWindow(SW_SHOWMAXIMIZED)` reporting `marked "todo_wine" but
  succeeds`. That measurement is what the oracle half was added to get, and what it
  established is that the tag is stale in the SUITE rather than a divergence of ours:
  `ok_sequence` only says "succeeds" when the whole sequence matched, and it matched on
  both halves. So the fix went where the tag lives — commits on the fork's
  `proskrnl-target` branch (upstreamable; test source, so no shipped Wine code moves).
  That is not "patching Wine to make a divergence pass" (G9's prohibition), because there
  is no divergence: it is the ordinary retirement of a tag that a stock Wine satisfies.

  **It took two commits, and the second is the argument for demanding green rather than
  budgeting.** Turning the `ok_sequence` call's `todo` argument off silenced its line and
  the oracle still answered **1** — the same site, a different tag: `WmShowMaxOverlappedSeq`
  marks its `EVENT_OBJECT_LOCATIONCHANGE` entry `msg_todo`, and while the SEQUENCE was
  todo, `messages_equal` was told not to report, so the entry's own tag never spoke.
  With both retired the oracle half measures **0** — demanded green, and green. A ceiling
  of one would have absorbed the second tag silently and called it the first one's cost.

  The kernel budget dropped with them, 17 → 16, by derivation (the term leaves the
  ceiling's arithmetic) — and the run that followed **confirms it: 13 measured**, with the
  ShowWindow todo-success absent from proskrnl's side too. `manifest-gui.txt`'s msg block
  carries that measurement and its per-family breakdown.
- **Both halves run the manifest's ACTIVE LIST.** The kernel half always did; the oracle
  half used to run one hardcoded pair, so activating a second GUI pair would have graded it
  on the kernel side with its spec side silently unrun — a differential gate down to one
  side without saying so.
- **The count is read from winetest's summary line, cross-checked against the exit
  status.** msg spawns ~21 children and each prints its own summary; the parent's is the
  last (it waits on them) and its count is also its exit status, so the leg parses the
  last line and fails loudly if the two disagree rather than grading either. That check
  exists because the first draft of the parser matched `failures)` and silently read a
  *child's* zero — the parent's line says "1 failure", singular. A number nobody
  cross-checked is how a gate reports green for a run it never read.
- **The verdict is a budget ratchet** (the msg pair's budget field in
  `tests/winetest/manifest-gui.txt` — a budget is a property of the PAIR, so any pair in
  either manifest may carry one, and this is the only one that does): the leg reads the
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
  leg into `build/tests/winetest-gui-msg.log`). HACK-004's console is a screen, so a test's
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
   is a ceiling on a *count*: a crash has no count, and `run.sh winetest-gui` fails it by name.

**What is left, and why** (the budget is a ceiling — the msg pair's block in
`manifest-gui.txt` explains the difference from the measured count):

- *Two assertions wait on GUI-6.* `SetFocus(GetDesktopWindow())` and
  `SetForegroundWindow(GetDesktopWindow())` both go through
  `check_queue_input_window`/`get_window_thread` on the desktop window, and here that
  window has **no owning thread** — GUI-2's forced-foreign fixture again. Wine answers
  `ERROR_ACCESS_DENIED` because the desktop belongs to explorer, a different input queue;
  we answer `ERROR_INVALID_HANDLE` because it belongs to nobody. GUI-6 built exactly that
  arrangement — on a shell boot the fixture is off and the desktop has a real owner — but
  the winetest-gui boot was kept explorerless by decision (GUI-2 notes above), so the pair
  stays in the bound: it flips the day that leg derives `ShellBoot`=1 (a flag, not a
  payload, since one image), and the divergence is a recorded fixture cost, not a
  papered-over unknown.
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
- *One is a `todo_wine` tag that is stale on proskrnl* — winetest counts a test that
  *succeeds* inside a todo block as a failure (`winetest_failures + winetest_todo_failures`
  is the exit status), so it is a case where **we are right and Wine is not**: a 500 ms
  wait for a window proc completes here where Wine times out (msg.c:18349). It is not
  fixable in this tree, and the line between that and the tag that WAS fixed is the whole
  point. `msg.c:18349` is stale *for us* — unmodified Wine still fails that wait — so
  editing it would be fixing the oracle instead of the kernel (G9). `msg.c:5730` was stale
  for **both**: the oracle half measured stock Wine satisfying it too, which makes it a
  defect in the suite rather than a divergence of ours, and it is retired on the fork's
  `proskrnl-target` branch (upstreamable). A measurement of the oracle is what tells the
  two apart; without one, they look identical.

Running 32-bit apps via WOW64 is **NT's real mechanism**, so it adds nothing to the hacks
ledger. Kernel cost is a few hundred lines (GDT compat descriptors, an
`IMAGE_FILE_MACHINE_I386` branch in process creation, low-4GB address-space restriction,
compat-mode exception delivery, `ProcessWow64Information`). No `Nt*` semantics change. The
32→64 transition ("Heaven's Gate") is entirely user-mode; the kernel never sees a 32-bit
syscall. See `docs/02` §WOW64.

## GUI-6 notes (the desktop's lifetime)

**A desktop of this session is never idle-closed, because `desktop->users` cannot count a
child that has not attached yet.** wineserver closes an idle desktop: one second after the
last user that is not the desktop window's owner leaves, `close_desktop_timeout` unlinks the
desktop and posts `WM_CLOSE` to its top window, which is explorer's cue to leave its message
loop and exit (`server/winstation.c` — `remove_desktop_user` arms it, the timeout fires it).
The decision reads `desktop->users`, and here that count is short by every child a connected
client has already spawned but that has not yet **attached**: the oracle counts a child from
`new_process` — its server *creates* the process, so it is a desktop user before the child
runs an instruction — while wineserver-lite learns of one only when the child's win32u
connects (the attach-time connect above, "the connect step is now run at attach").

GUI-6 is exactly that shape: explorer creates the desktop, spawns the file window with
`CreateProcessW`, and is momentarily its own only user. On a boot where that child needs more
than a second to reach the server — a cold image whose `wineboot --init` just ran, a slow
host — the desktop closed under the live session: explorer took the `WM_CLOSE`, posted itself
a quit, and exited **0**, so the leg's only symptom was that the browser window never flushed
and the golden never matched. Deterministic on a slow box, invisible on a fast one, which is
how it survived CI: the child won the one-second race there every time.

**Neither half of the oracle's arrangement is reachable from this side of the seam.** The
count cannot be repaired: `desktop->users` is raised per *thread* (`add_desktop_thread`), so
minting the child's client record early — which `shim.c` already does for a not-yet-attached
child — would not raise it, and a thread record for a thread that does not exist yet is an
entity NT has no name for (Art. 2). Nor can the decision be corrected where it is made:
`remove_desktop_user` is a static in the pinned tree, and editing it is editing a file the
*oracle* executes, which is exactly what Art. 10 forbids. What is left is to not act on the
answer.

So the decision built on the short count is not made — `shim.c prsk_hold_desktops_open`
cancels an armed close, and says so on serial (every cancel is a moment where this count and
the oracle's disagree; a silent one would be the next invisible symptom, Art. 12). It runs
after a reap (a reap *is* a departure from a desktop) and after any dispatched request
(`set_thread_desktop` moves a thread off one). Those two cover every arm: the reap's lookup
*is* `release_thread_desktop`'s own (`get_desktop_obj` on `thread->desktop`), so a thread whose
desktop does not resolve for the hold did not resolve for the arm either; and `set_thread_desktop`
leaves the caller on a desktop of the same winstation, which the sweep walks. A desktop here
therefore lives as long as the session that created it. Nothing on any image wants the other
behavior: smss owns the session's lifetime, no user can reopen a desktop that closed itself,
and every image's desktop belongs to the leg that created it. The sweep is across the
winstation's desktops rather than one desktop by name, because the arming site is inside the
pinned server and reachable from more than one caller — a sweep cannot miss a caller the way a
per-caller hook can (Art. 11).

One consequence, named rather than discovered later: `close_desktop_timeout` also
`unlink_named_object`s the desktop, so a desktop that would have become unopenable by name
stays openable. Nothing reaches it — the arm needs a top window (`get_top_window_owner`), which
the temp desktops `msg.c`'s `run_in_temp_desktop` creates never have, so those are not even
armed.

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

## WOW64 audit notes — the second pass (the misalignment frontier)

The WOW64 GUI notes above close with three defects that a 32-bit window found; none of
them was 32-bit *in nature*, and that is the point. A WOW64 caller is the tree's only
routine source of an input the 64-bit surface had quietly assumed away, so an audit of the
WOW64 path is largely an audit of that one assumption. It is written down here rather than
left to be re-derived by whoever hits the next instance.

**The assumption — "the caller's output buffer is naturally aligned."** It is not, and the
oracle is explicit about who forwards what: `dlls/wow64/*.c` translates a struct whose
32-bit and 64-bit layouts differ, and passes the pointer STRAIGHT DOWN when they agree.
The pass-through set is a fact of the pinned tree, enumerable with one grep, and every
member of it reaches a 64-bit kernel at i386's 4-byte alignment. Two consequences, and the
tree had both:

- a kernel that stores through a struct pointer into that buffer performs an 8-byte store
  at a 4-mod-8 address — undefined in C and a UBSan `#UD` here (the crash class);
- a kernel that PROBES that buffer for 8-byte alignment answers
  `STATUS_DATATYPE_MISALIGNMENT` where the oracle answers the value, and Wine's PE callers
  do not check the status (the silent-garbage class — this is what stalled
  SAFlashPlayer.exe, `sem_ps/misaligned_out.c`).

So the rule for anything the thunks forward untranslated is now uniform and stated once:
**probe for alignment 1, stage the fill in an aligned local, copy out as bytes.**
Alignment 1 rather than 4 is deliberate and follows `KiCaptureTimeout`'s reasoning: the
pinned Wine checks no alignment at all, so 1 is the only answer this side has evidence
for, and narrowing it needs a measurement on Windows rather than a recollection.

The file surface is the first application. `NtQueryInformationFile` filled every one of
its fixed classes through a struct pointer aimed at the caller's buffer — the same defect
`IopFillDirEntry` and the volume classes already had fixed — and `FileNameInformation`
went further, handing the FS backend the caller's buffer to write `WCHAR`s into directly.
Both now stage: the fixed classes into a union, the name into an aligned local (with a
pool fallback for a path longer than it) copied out as bytes. The npfs pipe classes stage
for the same reason. `NtQueryAttributesFile` / `NtQueryFullAttributesFile` already staged
their fills but probed for 8-byte alignment, which refused the ordinary i386 caller
outright; both probe for 1 now. Pinned by `tests/ntapi/sem_file/info_unaligned_buffer.c`.

The process and system query surfaces are the second application, and there the defect was
only ever the probe: `ProcessTimes`, `ProcessIoCounters`,
`SystemPerformanceInformation`, `SystemProcessorPerformanceInformation` and
`SystemProcessorIdleCycleTimeInformation` all staged their fills already but demanded
8-byte alignment of an output the thunks forward untranslated, refusing the ordinary i386
caller outright. `NtQueryTimer` had the same shape (`TIMER_BASIC_INFORMATION` opens with a
`LARGE_INTEGER`). All six probe for alignment 1 now; pinned by
`tests/ntapi/sem_ps/query_unaligned_out.c`.

Two sites in the same class are not WOW64-reachable and were fixed anyway, because each
one's own probe already admitted the alignment it then violated: `NtQueryKey`'s
`KeyNameInformation` wrote the key path through a `WCHAR *` derived from a buffer probed
for alignment 1 (an odd buffer misaligns every unit of the path), and `NtQueryObject`'s
`ObjectNameInformation` / `ObjectTypeInformation` stored an 8-byte `Buffer` pointer at
offset 8 of a buffer probed for alignment 4. Both stage their headers now; the registry
half is pinned by `tests/ntapi/sem_reg/key_name_unaligned.c`.

### The IOSB's own probe — the operand every Io service shares (M10)

The audit above swept output BUFFERS and stopped there, and the one operand it did not
reach is the one every Io service has: the caller's `IO_STATUS_BLOCK`. All 23 probe sites
demanded `sizeof(void *)` alignment of it. **The block has no alignment requirement**, by
the same evidence the rule above rests on — the pinned Wine assigns the two fields through
the caller's pointer and tests nothing first (`io_status->Status = status;`,
`dlls/ntdll/unix/file.c` `NtCancelSynchronousIoFile`, and the same shape at every other
entry point), so a misaligned but MAPPED block is served and only an inaccessible one
refuses. `IopProbeIosb` / `IopProbeIosbToken` (`kernel/io/io.h`) are now the one statement
of that, and `IopWriteIosb` / `IopWriteIosbStatus` the one statement of the copy-out.
Pinned by `tests/ntapi/sem_file/iosb_probe.c`.

Three things this one adds to the rule above rather than repeating:

- **The alignment term was wrong by ORDERING, not merely superfluous, and a winetest is
  what convicted it.** `KiProbeForWrite` tests alignment before accessibility, so an
  address that is *neither* — `(IO_STATUS_BLOCK *)0xdeadbeef` — reported
  `STATUS_DATATYPE_MISALIGNMENT` where NT reports `STATUS_ACCESS_VIOLATION`.
  `third_party/wine` `dlls/ntdll/tests/pipe.c:725` asserts that unguarded, so it is
  measured Windows behaviour and not merely the oracle's. Note what the *silent-garbage*
  framing above would have missed: this instance is loud, and the caller reads the status.
- **Two fixes make that address answer correctly, and only a mapped-AND-misaligned case
  separates them** — dropping the requirement, or swapping the two tests. The oracle
  serves the misaligned block, so the requirement goes; `iosb_probe.c` §2 is the case that
  says so, and neither the winetest nor any refusal case can.
- **Relaxing the probe without the copy-out is a kernel PANIC, not a divergence.**
  Seventeen sites wrote the block as `iosb->Status = ...`, and the first proskrnl run of
  the pin was a `#UD` inside `NtCancelSynchronousIoFile`, not a failed assertion. The
  probe and the write are one rule and land together.

`IopWriteIosbStatus` exists because a PARTIAL write is part of the contract, not as a
convenience: `NtQueryVolumeInformationFile` writes `Status` and leaves `Information`
untouched for a bad handle (the oracle's early `return io->Status = status;`), and a
single two-field writer would have quietly widened it.

**What this deliberately did NOT change**, so the next reader does not assume it did: the
SET direction's short-buffer status. The oracle answers `STATUS_INVALID_PARAMETER_3` per
class (`dlls/ntdll/unix/file.c:5245` and its neighbours) where `NtSetInformationFile` here
answers `STATUS_INFO_LENGTH_MISMATCH` from the shared `needed` gate that the QUERY
direction correctly uses. Measured while writing the pin above and filed as issue #219;
it is about which status a class owes, not about the block.

Outside the alignment pattern, the audit found the CPU area's reset-state flag being
CLEARED where the oracle raises it. `WOW64_CPURESERVED_FLAG_RESET_STATE` is wow64cpu's only
signal that the guest state it is about to resume was rewritten under it: every syscall
thunk ends in `btrl $0,-4(%r13); jc ...` — read-and-clear, full `iretq` restore when it was
set, a short `Eip`/`SegCs`/`Esp`-only `ljmp` when it was not (`dlls/wow64cpu/cpu.c`).
wow64cpu is therefore the CONSUMER that clears it, and the setter is
`NtSetInformationThread(ThreadWow64Context)` under its `CONTEXT_I386_CONTROL` arm
(`set_thread_wow64_context`, `dlls/ntdll/unix/signal_x86_64.c`). Clearing it instead — on
the plausible reading that a freshly written context has nothing left to reset — left every
guest exception return, APC return and `NtContinue` resuming through the short path,
silently dropping the caller's `EFlags`, `Ecx`, `Edx`, `SegSs` and data selectors.

**The raise is SELF-only, and that qualifier is the oracle's answer rather than a reading
of it — the first version of this fix raised it on any target, and the pin caught it.**
Every pointer in that arm comes from `get_thread_data()`, i.e. the CALLING thread: the CPU
area it writes and the flag it raises are the caller's own, and a non-self target never
reaches the arm at all, because the `if (!self)` gate above it hands the context to the
server and returns. A thread that is not running is not sitting in a wow64cpu thunk return,
so there is no resume for the flag to describe.
`tests/ntapi/sem_ps/wow64_thread_context.c` pins the cross-thread half in BOTH directions —
"untouched" is distinguishable from "written to that value" only by asserting from a set
and an unset starting state — while the self half is what `tests/cui/hello32.c` and the
`wow64gui` leg exercise, by running a real guest through exception and APC returns. The
same arm also stopped rewriting the staged context's `ContextFlags`, which the oracle never
touches on a set.

The last of the audit is a second assumption, symmetrical to the first: **"the 32-bit
mirror can re-derive what the 64-bit block decided."** It cannot, and the oracle never
tries — `build_wow64_parameters` and `init_peb` copy the FINISHED 64-bit block field by
field, so anything the 64-bit builder computed is carried, not recomputed. `PspBuildPeb`
now hands its decisions back in a `PSP_PEB64_FACTS` and `kernel/ps/wow64.c` mirrors them.
What had drifted: `Flags` (the 32-bit block lost `PROCESS_PARAMS_FLAG_NORMALIZED`, which
is what tells the guest's `RtlNormalizeProcessParams` the string `Buffer`s are pointers and
not offsets to re-base), `EnvironmentSize` (re-derived from the same environment, agreeing
only when the rounding happened to be a no-op, while `ntdll:wow64` compares the two fields
directly), and `ProcessGroupId` (dropped entirely — a plausible 0 that is also a real
console group, the Art. 12 shape). Pinned by `sem_ps/wow64_process.c`.

One more of the same kind: **`LdrSystemDllInitBlock.version` was synthesized from
`sizeof()`.** It belongs to the 64-bit ntdll's own static initializer
(`SYSTEM_DLL_INIT_BLOCK LdrSystemDllInitBlock = { 0xf0 };`, `dlls/ntdll/loader.c`), and
`load_ntdll_wow64_functions` only assigns the handle and the entry points on top of it
before memcpying the whole block into the guest's copy. `PspWow64FillInitBlock` starts
from the host block instead of a zeroed local now, so the version the guest reads is the
one the pinned ntdll declares and the kernel never has to know it.

## AUD-2 notes (single-process audio)

**A second process's `IAudioClient::Initialize` answers `AUDCLNT_E_DEVICE_IN_USE`; Windows
shared mode admits N processes.** NT mixes shared-mode render streams in audiodg — a
process; Wine delegates the same mixing to the host sound server. proskrnl has neither,
and virtio-snd advertises exactly one output stream, so the AUD-2 stack opens
`\Device\Snd0` EXCLUSIVELY per process (the Io share engine, no private flag —
`drivers/sndproto.h`), mixes that process's own shared-mode streams in the winevsnd
feeder, and surfaces a competing process's `STATUS_SHARING_VIOLATION` as
`AUDCLNT_E_DEVICE_IN_USE` (`user/wine/dlls/winevsnd.drv/stream.c dev_acquire`). The
status is a real WASAPI status produced in circumstances Windows would not produce it —
exactly the class of divergence this file records.

Justified against consumers, never performance (Art. 3's rule applied to a deviation
that is not even Art. 3's): no baked scenario plays audio from two processes at once —
the render winetest pairs, the audio leg's clients and the GUI images are all
one-audio-process boots. In-process concurrency, which is what Wine's own render tests
exercise, is real (the feeder mixes all of its process's streams).

Two subtler shapes fall out of the same exclusivity and are part of this entry:

- **Endpoint enumeration while another process holds the stream**: the busy node answers
  `STATUS_SHARING_VIOLATION` to the enumeration probe, and with no handle there is no
  `PCM_INFO` to relay, so the endpoint is skipped (named on serial) rather than listed
  under a fabricated direction (Art. 12). Windows would list the endpoint. Same
  convicting consumer, same exit.
- **The device stays STARTed (playing the feeder's silence) from a process's first
  `Start` until its last stream is released** — inaudible on the null/wav backends and
  unobservable through any `Nt*` boundary, noted for the WAV artifact's sake (leading /
  trailing silence, which `tests/audio/check_audio.py` already must not assert).

**AUD-3 extends the same deviation to capture, unchanged in shape**: the capture node
opens exclusively per process too, a competing process's `STATUS_SHARING_VIOLATION`
surfaces as the same `AUDCLNT_E_DEVICE_IN_USE`
(`user/wine/dlls/winevsnd.drv/stream.c cap_acquire`), and Windows shared-mode capture
admits N processes where this stack admits one. Same justification (no baked scenario
captures from two processes at once — the capture pairs and the capture leg's client
are one-audio-process boots), same convicting consumer class, same named exit below.
The enumeration-while-held and stays-STARTed shapes above apply to the capture node
verbatim.

**The named exit is audiodg-lite (HACK-008, reserved in `docs/10`), not a wider share
mask:** a user-mode mixer process owning the device, clients reaching it over shared
sections + kernel events — the GUI-3 transport recipe, and NT's own architecture adopted
rather than invented (the conhost argument, `docs/23` §4d). The convicting consumer is a
baked scenario in which two processes must be audible at once — a shell beep while an
app plays, or a second audio app on a GUI image. When one exists, HACK-008 is built and
this entry retires; until then the deviation stands recorded.

## Net-2 notes (\Device\Afd)

### The unbuilt-verb tail answers the unknown-code shape

The oracle's raw boundary refuses an ioctl `\Device\Afd` does not know INLINE with
`STATUS_NOT_SUPPORTED` and the IOSB untouched (measured — ws2_32's own WSAIoctl never
even forwards an unknown code; its overlapped pend-then-refuse is fabricated PE-side
with `IOCTL_AFD_WINE_COMPLETE_ASYNC`; pinned `sem_net/afd_refusal.c`). proskrnl's
`drivers/afd.c` default arm answers exactly that shape — and it is also the answer for
every verb the oracle implements that Net-2 has not built (`WINE_TRANSMIT`, the
`IP_*`/`IPV6_*` option tail, `MESSAGE_SELECT`, `KEEPALIVE_VALS`, `SIOCATMARK`, …), each
named loudly on serial (`afd: unimplemented ioctl`). That tail is the deviation: where
the oracle serves the verb and proskrnl refuses, the refusal is at least loud, specific
and in the oracle's own refusal shape — never `STATUS_NOT_IMPLEMENTED` (Art. 12: the
armed panic stays the enforcement for a silent stub; this is an implemented refusal,
not a stub). Each verb leaves the tail by the ordinary G5 route: pin first, then build.

### Urgent data (TCP OOB): the loopback sidechannel

lwIP implements no TCP urgent pointer, so wire-peer OOB stays unbuilt
(`SIOCATMARK` rides the unbuilt tail; an OOB send whose peer is remote refuses
`STATUS_INVALID_PARAMETER`). But a LOOPBACK connection's both ends are this
driver's, so the one urgent byte NT semantics carry travels beside the stream:
`WINE_SENDMSG` with `MSG_OOB` finds the peer socket by its port pair and lands
the byte in its OOB slot (or, under `SO_OOBINLINE`, folds it into the stream),
raising the `AFD_POLL_OOB`/`READ` edge; `WINE_RECVMSG` with `MSG_OOB` collects
it. The `IOCTL_AFD_RECV` flavor of OOB receive deliberately keeps the ORACLE's
refusal (its server path is unbuilt too — `ws2_32:afd` carries those delivery
rows as `todo_wine`, and matching the oracle keeps the todo discipline
intact). The flag VALIDATION (exactly one of `AFD_MSG_OOB`/`AFD_MSG_NOT_OOB`)
is pinned + implemented.

### AF_INET6: create/bind/name exist, the data path is staged

The v6 core is compiled into lwIP (dual-stack from day one, docs/24 §5).
`IOCTL_AFD_WINE_CREATE` accepts `AF_INET6` and the bind/getsockname surface
speaks `sockaddr_in6` (28 bytes, `::1` on the loop interface) — `ws2_32:afd`'s
`test_bind` v6 block is the consumer. Everything deeper (v6 connect/data,
`IPV6_*` options, `V6ONLY`) stays staged until its own pins exist;
`ws2_32:sock`'s v6 data rows park in the winetest manifest with this note as
their signature.

### Oracle-parity shapes measured off ws2_32:afd (Art. 6: the Wine answer is the spec)

- A SOCKET handle's `NtQueryObject(ObjectBasicInformation).Attributes` reports
  without `OBJ_INHERIT` (the pinned Wine loses it there and the test carries
  NT's answer as `todo_wine`); the REPORT only — the stored attribute, and
  handle inheritance with it, is intact (`kernel/ob/handle.c`'s one shim).
- Closing a polled socket completes a poll WATCHING it with `AFD_POLL_CLOSE`
  and `STATUS_SUCCESS`; closing a poll's ISSUING handle while it watches
  another socket tears the poll down with the output buffer UNTOUCHED and
  `Information` 0 (`STATUS_HANDLES_CLOSED`, the close-teardown status the
  RECV sweep already carries). Real NT lets such a poll run to its timeout —
  the test's `todo_wine` rows make Wine's early teardown the spec.
- An ACCEPTED socket's re-`connect()` answers `STATUS_SUCCESS` as a no-op
  (only a `connect()`ed socket's re-connect refuses
  `STATUS_CONNECTION_ACTIVE`), and a datagram `connect()` fixes the default
  peer inline with no `CONNECT` edge.
- `AFD_POLL_WRITE` behaves with hysteresis: a filled send window drops it and
  a congested loopback peer (receive ring half-full) keeps it down; a
  send-shutdown or a reset does NOT drop it.

### Close-cancel completes with STATUS_HANDLES_CLOSED (the oracle's own answer)

Not a deviation from the oracle — recorded because it IS one from real NT, inherited
deliberately: NT completes I/O parked on a closing socket handle with
`STATUS_CANCELLED`; the pinned Wine answers `STATUS_HANDLES_CLOSED`
(`ws2_32:afd test_recv` carries the NT value as `todo_wine`, so the Wine answer is
the spec here — Art. 6). Pinned by `sem_net/afd_cancel_close.c`.

## Net-3 notes (resolution, \Device\Nsi, the acceptance scope)

### \Device\Nsi: icmp-echo and change-notification refuse; unbuilt tables refuse by name

The pinned oracle's nsiproxy serves all five `IOCTL_NSIPROXY_WINE_*` codes;
proskrnl's `drivers/nsi.c` builds the three TABLE verbs (enumerate-all,
get-all-parameters, get-parameter) over exactly the tables the pinned
`GetAdaptersAddresses` reads — ndis ifinfo, ip unicast (v4+v6), ip forward
(v4+v6; the forward read is unconditional in
`gateway_and_prefix_addresses_alloc`, the measured conviction docs/24 §4e's
"grows by conviction" clause asks for). The deviations:

- `IOCTL_NSIPROXY_WINE_ICMP_ECHO` and `..._CHANGE_NOTIFICATION` answer
  `STATUS_NOT_SUPPORTED` (the oracle's own unknown-code status, pinned
  `sem_nsi/nsi_refusal.c`), named on serial — docs/24 §5: ping is nobody's
  dependency on the acceptance path, and a change notification on a
  static-address machine would never fire anyway. Never
  `STATUS_NOT_IMPLEMENTED` (Art. 12).
- A REAL nsi table outside the served set (tcp/udp stats and connection
  tables, ip stats/neighbour/compartment, …) answers the oracle's
  unknown-table status `STATUS_INVALID_PARAMETER`, named on serial
  (`nsi: unbuilt table`). Loud, specific, in the oracle's own refusal
  shape; each table leaves the tail by the ordinary G5 route when a
  consumer convicts it.
- The v6 FORWARD table exists and answers zero rows (no v6 route state is
  held — the staged-v6 record above, "Net-2 staged AF_INET6", is the
  signature); v6 unicast answers the honest netif state (`::1`).

Row VALUES no oracle pins (interface alias/description strings, the
loopback MTU where lwIP's loop netif carries none, infinite address
lifetimes) are authored; everything a pinned consumer joins on — luid ↔
if_index ↔ if_guid identity, the 127.0.0.1/prefix-8/origin-Manual/
dad-Preferred unicast row, the 127.0.0.0/8 no-gateway route — is pinned by
`tests/ntapi/sem_nsi/` on both runners. The ethernet row's `if_guid` is
`NetAdapterGuid` — the same MAC-derived value that names the adapter's
`Tcpip\Parameters\Interfaces` key (one identity authority, Art. 11).

### The resolver (wsresolv): authored answers behind the WS_CALL seam

ws2_32's five resolver entries are its own unixlib — never an `Nt*` surface — so
on proskrnl they dispatch through PE `wsresolv.dll` (the fork's one Net-3 seam
commit; `user/wine/dlls/wsresolv/`). The engine's order is numeric literals →
localhost → the machine's registry names → `drivers\etc\hosts` → DNS, and the
authored answers, each loud where it refuses:

- **DNS is UDP-only** (RFC 1035 over ws2_32's own sockets, against the servers
  the Net-1 lease wrote): a truncated (TC) reply answers `WSATRY_AGAIN` and
  names itself on serial rather than retrying over TCP; no search-list
  suffixing. The wire format is convicted by the hermetic `tests/resolv`
  corpus (the run.sh `resolvunit` leg), not by live queries.
- **Wire PTR is unbuilt**: `gethostbyaddr` and `getnameinfo(NI_NAMEREQD)`
  serve hosts-file and local-machine reverse matches and refuse the rest
  `WSAHOST_NOT_FOUND`, named on serial.
- **The local machine's addresses** are the lease values the registry carries
  (`DhcpIPAddress`) plus 127.0.0.1 — the same one lease authority netd wrote;
  no second address database.
- A **missing wsresolv.dll** degrades to per-entry failures
  (`WSAHOST_NOT_FOUND`; `WSAENETDOWN` for gethostname) instead of the old
  rip=0 fault on the NULL unix-call dispatcher.

### Net-3 oracle-parity shapes measured off ws2_32:afd (Art. 6 — the Wine answer is the spec)

The resolver seam un-wedged `ws2_32:afd` past its old crash, and the newly
reached rows convicted four kernel behaviors, each pinned in `tests/ntapi/`
before the fix:

- **Thread exit spares port-bound asyncs**: a parked request with a completion
  port bound, an ApcContext and no event survives its issuer's exit and
  reports only through the port (`IOP_CANCEL_FILTER.exemptPortBoundApcNoEvent`;
  pinned `afd_cancel_close.c`).
- **An accepted socket inherits its listener's synchronicity**: minted from a
  synchronous listener, `NtReadFile` on it blocks — FIONBIO nonblocking
  included, which governs the recv verbs, not the file API (pinned
  `afd_read_write.c`).
- **Byte offsets on sockets are ignored, never validated**: negative offsets
  read/write like NULL (real NT refuses `STATUS_INVALID_PARAMETER`; the suite
  carries that as `todo_wine`, so Wine's accept-anything is the spec; pinned
  `afd_read_write.c`).
- **READ re-latches on a partial consume, and half-close HUP waits for the
  drain**: consuming part of the ring re-raises the READ edge (ws2_32's
  FD_READ re-enable); the peer's send-shutdown raises HUP only once the ring
  is empty — real NT raises it immediately (`todo_wine` again; pinned
  `afd_event_select.c`, `afd_poll.c`; one consume-edge authority,
  `AfdConsumeEdges`).

### The acceptance's TLS scope: bundled TLS, never schannel

The Net-3 acceptance (docs/02; `tests/run/run.sh net3`) uses an app with
BUNDLED TLS — the pinned curl-for-win build, LibreSSL statically linked
(`tools/setup_linux.sh`, sha256-pinned). Windows-native schannel stays out of
scope: its protocol engine is GnuTLS behind secur32's unixlib seam, which is
null-dispatched on proskrnl (the boot's own
`err:secur32:SECUR32_initSchannelSP no schannel support` line is that fact,
loud). Raw bcrypt works as-is — the pinned tree vendors SymCrypt PE-side
(`libs/symcrypt`), and `bcrypt.dll` is baked for LibreSSL's
`BCryptGenRandom` entropy. The certificate chain the acceptance validates is
the tool's own (`--cacert` against the harness's fresh CA, `notBefore` = the
run's wall clock), which is what finally convicts a fake SystemTime — a
frozen base date rejects every newer certificate (docs/22; CUI-1's RTC is
the prerequisite that armed it).

Two loader consequences ride the same image, recorded here because they are
NT-shaped answers rather than hacks: the api-set forwarder DLLs
(`tools/gen_apiset_forwarders.py` — with no `PEB.ApiSetMap` the pinned
loader falls back to literal `api-ms-*` file names, and the generated
forwarders make those names real, every export forwarding to ucrtbase), and
the tool's measured import closure (normaliz, wldap32, bcrypt, ncrypt,
crypt32 — crypt32 loading unixlib-less via the fork's existing commit).
