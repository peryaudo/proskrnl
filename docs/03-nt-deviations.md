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

## Deliberate simplifications under the "stupidly correct" mandate (T4)

These are deviations from NT's *implementation*, never from its *observable semantics*:

- **No COW initially** — private/image mappings copy fully on map. Costs RAM; unobservable.
- **No eviction, immediate writeback** — makes mapped-view/`ReadFile` consistency trivial.
- **One dispatcher lock, uniprocessor** — turns every race into a plain state machine.
- **No kernel preemption** — context switches only at explicit waits and user-mode return.

Every one of these is unobservable from user mode, so none is a contract. See
`docs/09-constitution.md`, which makes these *rules*, not options.

## GUI-era additions that are NOT in NT (tracked as HACKs)

These are the only places we add something NT lacks. Each lives strictly at the boundary's
*outside* (a new device or a new process), never inside the existing `Nt*` or Wine PE code,
and each is logged in `docs/10-hacks-ledger.md`:

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
