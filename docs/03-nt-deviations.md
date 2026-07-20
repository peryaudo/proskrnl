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
| **Se (security)** | token object; `SECURITY_DESCRIPTOR` accepted by every relevant `Nt*`; `NtQueryInformationToken` info classes | "always allow"; a fixed admin token |
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

- **No RTC driver yet:** file timestamps derive from a fixed base date plus uptime —
  present, ordered, monotonic; no test may compare them across hosts.
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
  (`drivers/condrvproto.h`): real NT's condrv⇄conhost wire is undocumented
  and Wine pumps conhost through wineserver requests instead. The kernel
  mirrors wineserver's `get_next_console_request` semantics (busy verbs vs.
  parked blocking reads completed by `read=1`) so conhost's logic ports
  unmodified; the CLIENT surface — `IOCTL_CONDRV_*` and its structs — stays
  fully generated (`abi/ntcondrv.h`, G4).
- **One global console.** `IOCTL_CONDRV_BIND_PID` is answered kernel-side;
  every Connection/Reference/Input/Output open names the same console, and
  `hStdOutput`/`hStdError` share one Output open (the shape kernelbase's own
  std-handle setup produces). Per-console isolation arrives when something
  needs a second console.
- **The console transport is the COM1 serial wire, both directions**
  (HACK-004, docs/10): conhost's tty is `\Device\Serial0`, RX polled — see
  the ledger entry for scope and retirement.
- **The ported conhost's keyboard knowledge is the ASCII slice** of the
  US-layout `VkKeyScanW` mapping (user/conhost/proskrnl_glue.c): enough for
  the tty line discipline (Enter/Backspace/Tab/Escape/^A-^Z by virtual
  key); a real layout arrives with user32 (M10+).
- **conhost's wire output is a screen diff**, not an echo of written bytes:
  its renderer emits cursor-movement/erase sequences against its screen
  model. Tests assert cooked results (the client's own verdict), never
  literal output bytes (`tests/run/console_expect.py`).

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
  a window. Retired when the M11+ input/display path exists.
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
