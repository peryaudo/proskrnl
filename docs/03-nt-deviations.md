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
  `PsRunWineImage` joins, the reaper) are never targets. **Any future
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
    terminate-all-threads kills. **Re-triaged at CUI-4** (which built the
    foreign-terminate story this note used to wait on): both pairs are
    oracle-green, and on proskrnl the run now reaches its own summary line
    — `sync: 0 tests executed (… 0 failures)` on serial — and *then* still
    fails the per-pair budget as `FAIL (timeout)`. So terminating the
    siblings at `ExitProcess` (`PspExitCurrentProcess`) was necessary but
    NOT sufficient: something else keeps the process alive after the last
    check. They stay off the manifest with that sharper cause; the next
    attempt should start from which thread is still counted in
    `activeThreadCount` at that point, not from the wait paths (those now
    abort). Adding them meanwhile is actively harmful: pairs share one
    console, so a wedged pair fails every pair after it (the re-triage run
    showed five otherwise-green `kernel32` pairs cascade).
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
  served as of CUI-4 too, pinned by `sem_ps/job_query.c`. Still loud-unbuilt:
  job nesting (re-assigning a process already in a job), the other limit
  flags, and per-job CPU/IO accounting — the time and IO counters read back
  **zero** rather than a fabricated number (Art. 12); the counts that are
  real (assigned / active / terminated) are what consumers read. Exit
  packets always say `JOB_OBJECT_MSG_EXIT_PROCESS`; the ABNORMAL_EXIT flavor
  is unbuilt (no consumer distinguishes them).
- **`ProcessWineMakeProcessSystem` is real** (`kernel/ps/query.c`): the
  global shutdown event exists and its user-process count is maintained,
  but on-target it realistically never signals (conhost and cmd live for
  the whole session). The remaining `NtSetInformationProcess` classes stay
  accepted no-ops — now NAMED on serial per call (Art. 12 hygiene; this
  class was the planted-bug shape that rule exists for).
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
the one. The server now keeps a list of clients — the in-process build registers itself as
the single one at bringup, so there is one code path rather than two — and
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

The actual stopper was a transport infidelity: `slot_call` (`user/wine/server/call.c`)
copied the reply back **only on success**, where Wine's wire contract delivers the full
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
  (`PRSK_SLOT_DATA`, 64 KiB — `user/wine/server/transport.h`); a larger `set_clipboard_data`
  refuses loudly by request name rather than truncating (Art. 12). Named residual,
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
  probes `PRSK_SRV_IMAGE`, but only as a refusal — windowed conhost on a serverless image
  would make win32u go in-process and conhost the desktop's OWNER (the split-brain
  `user/wine/server/call.c` names); it exits loudly instead (G12).
- **comctl32 is a manual delay-load** (`user/conhost/window_glue.c`), mirroring upstream's
  DELAYIMPORT: reachable only from the config dialog, resolved by LoadLibrary on first
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
- *Twelve assertions are decided by emulated-machine speed, not by semantics.*
  `test_PeekMessage3` sets a 100 ms timer, never kills it, and then asserts seven times
  that the queue is empty — true where the intervening block runs in microseconds, false
  where 100 ms of guest time passes first (Wine's own `restart_timer` makes a late timer
  due immediately). `test_WM_COPYDATA` polls `FindWindow` for one second for a child
  process's window, and a process start on this stack costs more than that under TCG. Both
  families would pass on a fast machine and neither says anything about NT semantics; the
  budget carries the headroom the first can swing by, and names it.
- *Two message-sequence divergences remain in `test_interthread_messages`* ("destroy child
  on thread exit", a missing `WM_ERASEBKGND` in the expected order). These are real and
  unexplained — they were previously masked by item 6, which stopped the child windows
  from being created at all, and are the next honest thread to pull.

Running 32-bit apps via WOW64 is **NT's real mechanism**, so it adds nothing to the hacks
ledger. Kernel cost is a few hundred lines (GDT compat descriptors, an
`IMAGE_FILE_MACHINE_I386` branch in process creation, low-4GB address-space restriction,
compat-mode exception delivery, `ProcessWow64Information`). No `Nt*` semantics change. The
32→64 transition ("Heaven's Gate") is entirely user-mode; the kernel never sees a 32-bit
syscall. See `docs/02` §WOW64.
