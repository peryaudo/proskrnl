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
| **Se (security)** | CUI-2: a real Ob token object with the full query/adjust/duplicate/access-check surface (`kernel/se/`, pinned by `tests/ntapi/sem_se/` — see "CUI-2 Se notes") | ONE fixed admin identity (wineserver's `token_create_admin`, byte-identical); object create/open stays "always allow" — `NtAccessCheck` exists as a service, but Ob never consults tokens or SDs when granting handles |
| **Cm hive format** | `NtCreateKey`/value semantics | our own on-disk format; no MS hive binary compat |
| **EPROCESS/ETHREAD** | exist as internal structs | layout entirely ours; nobody reads it (no drivers) |
| **DPC/IRQL surface** | absent, not stubbed | callers don't exist (no drivers) |
| **Generic access mapping** (M3) | `GENERIC_*`/`MAXIMUM_ALLOWED` accepted everywhere a `DesiredAccess` goes | any generic bit grants the type's FULL access mask instead of NT's per-type `GENERIC_MAPPING` — an over-grant, consistent with always-allow Se. Handle-granted access is still enforced per use (`EVENT_MODIFY_STATE` etc., pinned by `tests/ntapi/sem_ob/`) |
| **Name case folding** (M3) | `OBJ_CASE_INSENSITIVE` honoured per lookup | upcasing is ASCII-only; NT carries a full Unicode upcase table. Kernel-created names are ASCII, so this is unobservable until user mode invents non-ASCII object names |
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
- **Mapped-view dirty pages** are written back on `NtFlushBuffersFile` and at file close,
  not per-store (unobservable without a reboot mid-test; `NtWriteFile` itself writes
  through immediately).

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
  require stopping it, which the single-CPU no-preemption model cannot do without the
  suspend machinery; foreign-thread `NtTerminateThread`/`NtTerminateProcess` are
  `STATUS_NOT_IMPLEMENTED` for the same reason. The M7 clients (and ntdll's own startup)
  only ever act on the current thread or join already-exiting ones.
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
  seeds `ActivationContextStackPointer`, the `StaticUnicodeString` buffer, and the x64
  no-exception-list marker, as Wine's `init_teb` does — `actctx.c` dereferences them
  without checking.
- **The initial stack commit is at least 64 KiB** regardless of the PE header's
  `SizeOfStackCommit`: `signal_start_thread` zeroes `0xf000` bytes below the initial
  CONTEXT before `NtContinue`, deeper than a minimal 1-page commit.
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
- **Key classes, registry symlinks (`REG_OPTION_CREATE_LINK`), and change notification**
  are unbuilt: the class argument is accepted and dropped, `CREATE_LINK` and the notify
  APIs are refused loudly (`STATUS_NOT_IMPLEMENTED`), matching what the CUI Wine stack
  never uses. `LastWriteTime` ticks on the boot-relative interrupt clock, not wall time.
- **`\Registry\Machine`/`\Registry\User` are undeletable** (parent-of-root protection);
  wine would allow an empty hive root's deletion but never exercises it.

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

## M9 npfs/condrv notes (pipes + the console)

What the M9 bring-up pinned, deviated on, or left unbuilt:

- **Pipes are synchronous-only** (Art. 3): every `NtReadFile`/`NtWriteFile`/
  `FSCTL_PIPE_LISTEN` on a pipe completes (or blocks the caller) before the
  syscall returns — `STATUS_PENDING` is never produced. The pinned sem_pipe
  suite uses synchronous handles exclusively; an async-handle divergence
  found later gets its own entry here.
- **`FSCTL_PIPE_WAIT` / `FSCTL_PIPE_TRANSCEIVE` are unbuilt** — refused
  loudly (`STATUS_NOT_SUPPORTED` + a serial line), never faked. The
  `NtCreateNamedPipeFile` timeout parameter is accepted and unused until
  WAIT exists. `FSCTL_PIPE_PEEK` is implemented (state, available bytes,
  message count, preview).
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
  US-layout `VkKeyScanW` mapping (user/conhost/proskrnl_glue.c): enough for
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
- **`NtSuspendThread` of a thread that has ever run stays
  `STATUS_NOT_IMPLEMENTED`** (no kernel preemption — no park point; only
  never-run threads carry a suspend count). The oracle behaviour is pinned
  under `todo_proskrnl` in `sem_ps/suspend_resume.c`.
- **`NtTerminateProcess` abandons blocked sibling threads**: they keep
  their waits and exit on their own (their next syscall fails on the
  closed handles). NT terminates them. Unobservable for the CUI clients
  (cmd joins its children; the ntdll threadpool's workers wake on their
  own timeouts).
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
- **`FileFsDeviceInformation.DeviceType` for a mounted volume is
  `FILE_DEVICE_DISK_FILE_SYSTEM` (0x8)**, the pinned oracle's value for
  regular files — not bare `FILE_DEVICE_DISK` (real NT's volume answer);
  `GetFileType` maps both to `FILE_TYPE_DISK`.
- **A relocated `SEC_IMAGE` copy's mapped header claims the ACTUAL base**
  (`OptionalHeader.ImageBase` stamped after the kernel-side fixups), which
  is what keeps ntdll's own `perform_relocations` from applying the delta
  twice — the same convention as Wine's mapper
  (`dlls/ntdll/unix/virtual.c map_image_into_view`).
- **cmd.exe ships as a standalone PE** built from the pinned tree's own
  cmd objects + `user/cmd/proskrnl_glue.c` (the five user32 / four shell32
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
gate**: `tests/run/run.sh winetest` runs a curated manifest of
`<test_exe>:<subtest>` pairs (`tests/winetest/manifest.txt`) that must exit 0
— winetest's own failure count — under the pinned oracle AND on proskrnl.
The binaries are standalone links of the pinned tree's own unmodified test
objects (Makefile `wtests`, the cmd.exe recipe; entry is the msvcrt/ucrtbase
implib's own `mainCRTStartup`, winegcc's choice, with the `.CRT$X??`
boundary symbols winebuild would have emitted supplied by
`user/wtest/crt_sections.c`). Decisions and wrinkles:

- **One binary, two runners (docs/14) — so user32 is stood in at link
  time.** The ntdll/kernel32 test objects declare `IMPORTS = user32`;
  user32 is the GUI-2 path, off the image per Art. 7.
  `user/wtest/user32_stubs.c` supplies the referenced imports (honest
  `ERROR_CALL_NOT_IMPLEMENTED` failures for GUI entities; real
  implementations only where ntdll/msvcrt already carry the semantics).
  A subtest whose assertions need a real window/winstation fails
  IDENTICALLY on both runners and stays off the manifest (`ntdll:om` is
  the canonical casualty: its `\Sessions\...\WindowStations` half needs
  real winstation objects).
- **`ntdll:time` is off the manifest — an oracle-HOST flake, not a
  proskrnl divergence.** Its `test_user_shared_data_time` check (`USD
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
- **The sweep runs each pair on the console** (`kernel/init/main.c`
  KiRunWineTests): winetest prints through msvcrt stdout → condrv →
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
- **GlobalMemoryStatusEx's three sources answer for real** (`kernel/ps/
  query.c`): `MmNumberOfPhysicalPages`, the new
  `SystemPerformanceInformation` class, and
  `NtQueryInformationProcess(ProcessVmCounters)` over a VAD walk — no
  paging means committed IS the working set, and with no pagefile the
  commit limit IS physical memory. (Before this, the heap test's own
  `/ (ullTotalPhys / 100)` was a guest divide-by-zero.)
- **The gate already convicted and fixed real kernel bugs** (Art. 6 in
  action): the absolute-timeout translation (`KiComputeDueTime` treated a
  positive since-1601 deadline as an interrupt-time due — every absolute
  `RtlWaitOnAddress`/wait timeout parked ~forever), per-process thread-id
  collisions (ids now come from the shared CID-shaped source), the missing
  keyed-event rendezvous, and a divide-by-zero feeding
  `GlobalMemoryStatusEx` zeros into `kernel32:heap`'s own arithmetic.
- **Left off the manifest with cause** (candidates re-join as their
  blockers land):
  - oracle-side failures (upstream suite-vs-Wine drift, not proskrnl's):
    `kernel32:file` (7), `cmd.exe_test:batch` (3); `ucrtbase:file` needs a
    host UTF-8 locale the oracle environment lacks.
  - user32-load-bearing: `ntdll:om` (its `\Sessions\...\WindowStations`
    half needs real winstation objects).
  - path-syntax breadth: `ntdll:path` / `kernel32:path` pin the full NT
    open-path table (trailing/doubled slashes, dot components,
    RootDirectory-relative opens) — the Io/FAT walker diverges on ~22
    cases.
  - missing Mm surface: `ntdll:virtual` / `kernel32:virtual` (zero_bits,
    `NtAllocateVirtualMemoryEx`); `ntdll:info` (processor-feature and
    breadth classes, then hangs).
  - process-exit protocol: `ntdll:sync` and `kernel32:sync` complete their
    checks (sync: zero failures) but park at exit — the tests deliberately
    LEAK threads blocked on a closed completion port, which real NT's
    terminate-all-threads kills; proskrnl's no-preemption abandon rule
    (above) leaves the exit path waiting. Needs the foreign-terminate
    story.
  - breadth not yet triaged: `kernel32:{thread,time,pipe}` (107/43/slow),
    `msvcrt:{misc,file,time}`, `ucrtbase:misc`, `cmd.exe_test:directory`
    (6 failures on proskrnl only).

## CUI-1 firstboot notes (wineboot + the machine-state registry)

First boot runs `wineboot --init` (`smss.exe firstboot` → `KiRunFirstBoot`),
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
- **`REG_OPTION_CREATE_LINK` stays unimplemented** (`NtCreateKey` returns
  `STATUS_NOT_IMPLEMENTED`); the `Time Zones` REG_LINK symlink `wine.inf`
  writes fails and is on the differential's exclusion list.
- **`ws2_32.dll` is baked as dormant data** — it cannot load (`DllMain`
  returns failure with no unixlib below); wineboot's `gethostname`/
  `getaddrinfo` are glue stand-ins. A loadable seam is CUI-5's (sockets).
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
- **Object access remains always-allow**: `OBJECT_ATTRIBUTES.
  SecurityDescriptor` at create time is accepted and ignored; Ob's
  create/open/handle paths never evaluate SDs or tokens. `NtAccessCheck`
  is a pure *service* over a caller-supplied SD (the wineserver ACE walk,
  transcribed exactly).
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

## Deliberate simplifications under the "stupidly correct" mandate (T4)

These are deviations from NT's *implementation*, never from its *observable semantics*:

- **No COW initially** — private/image mappings copy fully on map. Costs RAM; unobservable.
- **No eviction, immediate writeback** — makes mapped-view/`ReadFile` consistency trivial.
- **One dispatcher lock, uniprocessor** — turns every race into a plain state machine.
- **No kernel preemption** — context switches only at explicit waits and user-mode return.

Every one of these is unobservable from user mode, so none is a contract. See
`docs/09-constitution.md`, which makes these *rules*, not options.

## Console/GUI-era additions that are NOT in NT (tracked as HACKs)

These are the only places we add something NT lacks. Each lives strictly at the boundary's
*outside* (a new device or a new process), never inside the existing `Nt*` or Wine PE code,
and each is logged in `docs/10-hacks-ledger.md`:

- **serial-backed console** (HACK-004, M9) — condrv's transport is the COM1 UART in both
  directions; real NT feeds conhost from win32k's raw input path and draws its output into
  a window. Retired when the GUI-1+ input/display path exists.
- **`\Device\Fb0`** (HACK-001) — map the framebuffer to user mode; NT would own this via a
  display driver behind win32k.
- **`\Device\Input0`** (HACK-002) — raw input stream to user mode; NT routes this through
  win32k/csrss.
- **wineserver-lite as a desktop server** — a user-mode server holding desktop state. Not
  a hack against NT so much as a return to NT 3.1's actual architecture (see `docs/07`).

## WOW64 (not a deviation)

Running 32-bit apps via WOW64 is **NT's real mechanism**, so it adds nothing to the hacks
ledger. Kernel cost is a few hundred lines (GDT compat descriptors, an
`IMAGE_FILE_MACHINE_I386` branch in process creation, low-4GB address-space restriction,
compat-mode exception delivery, `ProcessWow64Information`). No `Nt*` semantics change. The
32→64 transition ("Heaven's Gate") is entirely user-mode; the kernel never sees a 32-bit
syscall. See `docs/02` §WOW64.
