# Kernel subsystem code review — 2026-07

Read-only review of every subdirectory under `kernel/`, `drivers/`, `fs/`, and
`arch/`, at commit `74e96a0`. One reviewer per subdirectory, 14 in total,
each reading its directory in full plus the seams it depends on, and
cross-checking against the pinned Wine oracle (`third_party/wine`) and the
relevant vendor specs.

**169 findings.**

**Status.** Every finding this document rates *critical* is fixed, along with
four rated *high* that shared their code paths. Nothing else is. Fixed items
carry a **[FIXED `<commit>`]** mark inline below — read the marks, not the
section headings: sections 1–4 are *themes*, and each still contains unfixed
items alongside the fixed ones.

Fixing section 1a took two passes. The first covered the Ob namespace engine
and assumed that reached every `NtCreate*`/`NtOpen*`; re-checking against the
kernel showed Io and Cm parse `ObjectName` into their own namespaces without
entering the engine, so `NtCreateFile`, `NtCreateKey` and `NtOpenKey` were
still halting the machine. Three further paths in the same section were also
still live. Every fix here was confirmed to convict first: the unfixed kernel
produces `[PANIC] vector=14 (#PF page fault)` under the new tests, so these
are differential results rather than a sanitizer going quiet (Art. 6).

A second audit pass then re-checked every `[FIXED]` mark against the kernel
rather than against the commit messages. It found no wrong marks, but two
fixes that had no *convicting* test — the `peb.c` saturation and the
`SetEndOfFile` guard — and both now have one. Three claims were also verified
negative, i.e. they are **not** second instances of a fixed bug:
`kernel/ps/atom.c:359` already probed its `returnLength` and checked the
result; `kernel/se/token.c:639`'s `reply[512]` is genuinely bounded, because
group and privilege counts are fixed at boot and only copied by
`SepDuplicateToken`, with no path that grows them; and `kernel/io/rw.c:208`
(the read path's `GetCache`) is unreachable today, since every shipped device
has a `Read` or a `GetCache` — it is latent, not live.

| Subdirectory | Findings | Worst |
| --- | --- | --- |
| `kernel/ps` | 16 | critical |
| `kernel/io` | 16 | critical |
| `fs/npfs` | 16 | high |
| `drivers/virtio` | 15 | high |
| `fs/fat32` | 15 | critical |
| `kernel/cm` | 15 | critical |
| `kernel/mm` | 12 | critical |
| `kernel/ob` | 12 | critical |
| `arch/x86_64` | 12 | high |
| `kernel/init` | 10 | high |
| `kernel/ke` | 8 | high |
| `kernel/lib` | 8 | medium |
| `kernel/se` | 7 | critical |
| `kernel/syscall` | 7 | critical |

---

## 1. The headline: one missing layer causes most of the critical findings

The single largest defect class is **user-pointer validation**, and it is not a
scatter of independent oversights — it is one absent architectural layer,
amplified by one design decision.

### 1a. There is no capture layer, and per-call-site probing was applied unevenly

`KiSystemServiceTrap` (`kernel/syscall/table.c:118-140`) does no validation of
register arguments. Validation is therefore each service's own responsibility,
and the coverage is close to random. Confirmed unprobed user dereferences:

- **[FIXED ae98013, c4d0eb3] `kernel/ob/namespace.c:152-248, 387`** — the *entire* Ob create/open engine
  reads `attributes->ObjectName->Length` and walks `Buffer[]` raw. Every
  `NtCreateEvent` / `NtCreateMutant` / `NtCreateSemaphore` / `NtCreateSection` /
  `NtCreateFile` / `NtCreateDirectoryObject` / `NtCreateJobObject` /
  `NtCreateIoCompletion` reaches it with an unvalidated ring-3 pointer. The only
  `OBJECT_ATTRIBUTES` probe in the tree is in `NtOpenProcess`
  (`kernel/ps/process.c:1129`).
- **[FIXED 6b87fc6] `kernel/ps/query.c`, `kernel/ps/job.c`, `kernel/ps/thread.c`** — roughly 25
  `*returnLength = ...` stores with no probe at all
  (`query.c:89,111,133,180,208,239,254,280,314,327,646,790,856,892,914,932,953,984,1030,1048,1068,1176,1196`;
  `job.c:375,407,439,452`; `thread.c:1044,1067`). Exactly one site
  (`query.c:1085`, `SystemInterruptInformation`) probes, which is what shows the
  rest are oversights rather than policy.
- **[FIXED c4d0eb3] `kernel/ob/namespace.c:741-864`** — `NtQueryDirectoryObject` validates
  nothing at all; it reads `*context` before even resolving the handle, then
  writes `buffer[]`, `*context`, and `*returnedSize`.
- **NOT FIXED. `kernel/ob/namespace.c:874-951`** — `NtCreateSymbolicLinkObject` /
  `NtQuerySymbolicLinkObject` read and `memcpy` up to 64 KB through an
  unvalidated `UNICODE_STRING`.
- **[FIXED 7d399f1, c4d0eb3] `kernel/cm/registry.c:852,856,1025,1077,1096,1159,1182`** — `valueName` and
  `attributes` raw in `NtSetValueKey` / `NtQueryValueKey` / `NtDeleteValueKey` /
  `NtCreateKey` / `NtOpenKeyEx`. Cm's `data` parameter *is* probed, one line
  away.
- **[FIXED c4d0eb3 — `NtCreateFile` only] `kernel/io/file.c:309,341`, `kernel/io/query.c:942-950`** —
  `NtCreateFile`'s `OBJECT_ATTRIBUTES`, and `NtQueryDirectoryFile`'s `mask`
  (whose `Buffer` is then `memcpy`'d into the handle's retained `dirMask`).
  The `mask` half is **NOT FIXED**.
- **[FIXED c4d0eb3] `kernel/ke/wait.c:459`, `kernel/ob/wait.c:38,60,83`** — the `timeout`
  pointer and the `handles[]` array of `NtWaitForSingleObject` /
  `NtWaitForMultipleObjects`. `kernel/ps/thread.c:746` probes an identical
  `HANDLE` array, so again the omission is local.
- **[FIXED c4d0eb3] `kernel/ob/handle.c:626-630, 665-669`** — `NtQueryObject` calls
  `KiProbeForWrite` and then **discards the result**, writing regardless. Its
  three success paths do not probe at all.

The mitigating pattern already exists and is used correctly in a handful of
places (`kernel/ps/display.c:20-30`: `KiCopyFromUser` the descriptor, then
probe its interior). It simply was never made mandatory.

Per gate G10, the fix belongs in the engines — `ObpLookupName` /
`ObpCreateObjectWithHandle` should capture and probe `OBJECT_ATTRIBUTES` once,
rather than twenty `Nt*` callers each doing it — not spread across call sites,
which is how the current situation arose.

### 1b. A missing probe is a machine kill, not an access violation

`KiDispatchTrap` (`kernel/init/panic.c:275-335`) contains a fault only when
`segCs & 3 == 3`. A fault taken in ring 0 on a user address has no fixup and
falls through to `KiPanicLatch` / `KiHalt`. So each of the above is not
"returns the wrong status" — it is **any unprivileged process halting the whole
machine with one syscall**. A kernel-mode fault fixup path (or an exception
table on the copy routines) would convert this entire class from fatal to
`STATUS_ACCESS_VIOLATION` in one change, and is worth doing independently of
fixing the individual sites.

### 1c. The probe is a no-op on the two paths that need it most

`KiProbeRange` (`kernel/syscall/uaccess.c:19-22`) returns `STATUS_SUCCESS`
immediately when `ExGetPreviousMode() == KernelMode`. `previousMode` is
`UserMode` only inside the service-call branch and is restored to `KernelMode`
at `table.c:161` — **before** `KiDeliverUserApc` runs at `table.c:179`. The
exception dispatch path (`panic.c:307` → `PspDispatchUserException`) likewise
runs with `KernelMode`.

Consequently the `KiProbeForWrite` guarding both ring-3 dispatch frames —
`kernel/ps/usermode.c:317` (exception, 0x5c0 bytes) and `:442` (APC) —
validates nothing. The only remaining gate, `KiMaterializeUserRange`
(`usermode.c:81-103`), has **no user-space bound check**, and because
`MiCreateUserPml4` shares the upper 256 PML4 slots with the kernel, a walk of a
kernel address in a user PML4 succeeds against pages the kernel maps
`PRESENT|WRITE`.

Net effect: `mov $<kernel address>, %rsp ; ud2` from ring 3 writes ~0x5c0 bytes
of attacker-chosen `CONTEXT` into the kernel image. This is the most serious
single finding in the review. Two independent fixes are needed — probe with
`UserMode` semantics on the dispatch paths, **and** bound
`KiMaterializeUserRange` against `KI_USER_SPACE_LIMIT`.

**[FIXED b775f4e]** via the second of those. `KiIsUserRange` is now the one
authority for the bound, phrased to hold regardless of previous mode, and is
checked first in `KiMaterializeUserRange` — which all three frame writers
(`usermode.c:292`, `:330`, `:455`) pass through before their `memcpy`. The
probes on those paths remain no-ops, which is now harmless rather than
load-bearing; making them mode-aware is still worth doing so the weaker
guarantee is not relied on again.

### 1d. Probe-then-block TOCTOU is now live

`kernel/syscall/uaccess.h:8-10` states the probe is sound because "the kernel
never blocks between a probe and the access it guards", and flags "revisit when
M7 brings multi-threaded processes". M7 and M10 have landed.
`NtReadFile` probes at `kernel/io/rw.c:166`, blocks in `ops->Read` (npfs,
condrv) at `:184`, then `memcpy`s at `:189` on a stale validation. Same in
`NtWriteFile` and `kernel/io/ioctl.c:31,96`. Thread B unmapping the buffer
while thread A is parked gives a ring-0 fault, i.e. (per 1b) a panic.

The same double-fetch shape appears independently in
**`kernel/se/sd.c:100-152, 236-294`**, where the *measure* pass sizes a pool
allocation and the *copy* pass then re-reads the length from user memory and
copies that many bytes. The equality check that would catch it sits at
`:289-294`, after all four copies have run.

---

## 2. `ASSERT` on user-controlled state

`ASSERT` is always compiled in and fatal by design (`kernel/init/panic.h`).
Several sites assert on values ring 3 controls, turning a diagnostic into a
denial-of-service primitive:

- **[FIXED 901cf20] `kernel/se/secobj.c:87-88` (critical)** — `BYTE reply[512]` with
  `ASSERT(needed <= sizeof(reply))`, where `needed` derives from an SD the
  caller stored earlier and `SepCaptureAcl` accepts ACLs up to 65535 bytes. An
  `NtCreateEvent` + `NtSetSecurityObject` (2 KB DACL) + `NtQuerySecurityObject`
  sequence halts the kernel; weaken the assert and it is a 64 KB stack smash.
  The 512 figure was carried over from the token path, where replies really are
  bounded.
- **`kernel/init/verify.c:65-67` (high)** — the state sweep asserts on
  `teb->ClientId.UniqueThread` and `teb->Tib.Self`, which live in a
  `PAGE_READWRITE` user page. Any process writing its own TEB panics the kernel
  at the next sweep.
- **`kernel/mm/section.c:339` (high)** — relocation target VA is
  `base + block.VirtualAddress + offset` with `block.VirtualAddress` read
  straight from a user-supplied PE's `.reloc` and never bounds-checked against
  `sizeOfImage`. Unmapped → `ASSERT(frame != 0)` panic; mapped → silent
  corruption of unrelated memory in that process.
- **`kernel/io/async.c:83`, `kernel/io/notify.c:81,96` (high)** — completing a
  pended request writes through `MiCopyToUserRange`, which asserts on a missing
  frame. The buffer was probed at issue time; the owner may unmap it while the
  request is parked. `NtNotifyChangeDirectoryFile` + `NtFreeVirtualMemory` +
  touch the directory = panic.
- **`kernel/ke/wait.c:56` (high)** — `KiSatisfyObject` asserts
  `signalState > 0`, and nothing de-duplicates objects in a `WaitAll`.
  `NtWaitForMultipleObjects(2, {hSem, hSem}, WaitAll, ...)` on a
  count-1 semaphore satisfies it twice and panics. The oracle does not panic.
- **`kernel/io/file.c:526,581` (latent)** — `ASSERT(NT_SUCCESS(refStatus))` on
  a transient handle that lives in the *caller's* handle table, and is
  therefore user-closable. Safe only under the current no-preemption mandate.

---

## 3. Integer overflow in size arithmetic

- **[FIXED 5ab7738] `kernel/ps/peb.c:141,521` (critical)** — `PspCaptureString` computes
  `MaximumLength = (USHORT)(source->Length + sizeof(WCHAR))`, which wraps to 1
  for `Length == 0xFFFF`. `PspBuildPeb` sizes the scratch region from
  `MaximumLength` (16 bytes reserved) but `memcpy`s `Length` (65535) bytes — a
  fully attacker-controlled kernel pool overflow via `NtCreateUserProcess`.
  `Length == 0xFFFE` wraps to 0 and silently drops the string instead.
- **[FIXED 0db0498] `kernel/mm/virtual.c:311,321` (critical)** — `MiRoundUp(requestedBase + size,
  PAGE_SIZE) - base` wraps to 0 with no guard; the `size == 0` check at `:286`
  runs on the *pre-rounding* value, and the `base + size < base` test does not
  fire when the rounded size is exactly 0. Reaches `MiCreateVad(base, 0, ...)`
  → `MiAllocatePool(0)` → `KiPanic` (`kernel/mm/pool.c:118`). One syscall,
  any process, machine halts. Verified directly against the source.
- **`kernel/mm/virtual.c:406` (medium)** — the same wrap in
  `MiFreeVirtualMemory`, where a rounded size of 0 is the *sentinel* for
  "the whole VAD". `NtFreeVirtualMemory` with a crafted length releases an
  entire reservation and reports success.
- **`kernel/io/lock.c:39` (medium)** — byte-range overlap arithmetic on
  `uint64_t` with lengths taken from user `LARGE_INTEGER`s unvalidated; two
  "exclusive" locks over the same bytes can both be granted.
- **`drivers/virtio/blk.c:132-135`** — `sectorCount * VIO_BLK_SECTOR_SIZE` is a
  32-bit multiply, so `sectorCount = 0x800000` makes the bounding `ASSERT` pass
  with a product of 0. Latent (callers chunk at 8 sectors).
- **`kernel/ps/process.c:178-187`** — `SizeOfStackReserve` from the image is
  rounded without a guard, and `reserve - 2*PAGE_SIZE` then underflows.
- **`kernel/lib/dbgprint.c:165-168`** — `-value` on `INT64_MIN` is signed
  overflow; the kernel builds with `-fsanitize-trap=undefined`, so this is a
  `ud2` **inside the logging path**.

---

## 4. Untrusted external input parsed without validation

- **[FIXED e7a0bd8] `fs/fat32/fat.c:465-477` (critical)** — mount validates neither
  `fatSize != 0`, nor `totalSectors != 0`, nor
  `clusterCount + 2 <= fatSize * bytesPerSector / 4`. The author knew the
  invariant — it appears as an `ASSERT` in `FatQueryVolumeInfo` at `:673` — but
  not at mount, the only place it matters. A crafted BPB with `TotSec32 = 0`
  yields `clusterCount = 0xFFFFFFA0` against a 4096-entry FAT, so every bounds
  `ASSERT` passes for any cluster and `FatSetFatEntry` **writes** far past the
  pool block.
- **`fs/fat32/fat.c:44-53` (high)** — FAT entry values are returned verbatim;
  the bounds check is an `ASSERT` on the *input* cluster, never on the
  *returned* one. A file whose `DIR_FstClus` is `0x0FFFFFF0` panics on first
  read. `FatAllocateCluster` at `:93` indexes with no assert at all.
- **`fs/fat32/dir.c:166-258` (high)** — no cycle detection when walking a
  directory's cluster chain. A cyclic chain hangs the kernel forever
  (uniprocessor, no preemption).
- **`kernel/mm/pecoff.c:250`** — export-name comparison bounds only the *first*
  byte (`nameOffset < rawSize`); a crafted PE whose tail spells a prefix of a
  looked-up name over-reads past the page-cache block.
- **`arch/x86_64/smbios.c:127-136`** — firmware `maxSize` used unvalidated as a
  walk bound (and `cursor + 1` wraps at 4 GiB). The 32-bit entry-point path at
  `:163-174` does no table validation at all, unlike the 64-bit one.
- **`drivers/virtio/pci.c:54,81,61-65,194-196`** — capability-list walk is
  unbounded (a cyclic `cap_next` hangs boot), the device-supplied BAR index is
  unvalidated, and the notify address is computed from device values with no
  bound against the mapped notify window — potentially landing in another
  device's register window.

---

## 5. Fabricated answers (gate G12)

Art. 12's claim that every silent-plausible stub becomes a deferred bug holds
up well here. Live instances:

- **`kernel/ps/thread.c:1077-1094`** — `NtSetInformationThread` returns
  `STATUS_SUCCESS` for **every** class, including `ThreadImpersonationToken`,
  and does not even name the class on serial. A caller that impersonates and
  gets success then makes security decisions on a fabricated answer.
- **`kernel/ps/process.c:1291-1294`** — `NtTerminateProcess(NULL, status)`
  returns success without terminating the sibling threads it is contractually
  required to. This is precisely how `RtlExitUserProcess` drains siblings
  before DLL detach.
- **`fs/npfs/pipe.c:686-716`** — pipe info classes return `STATUS_SUCCESS` with
  an all-zero structure when the pipe is gone; the oracle returns
  `STATUS_PIPE_DISCONNECTED` for both classes.
- **`kernel/cm/registry.c:768-772, 1171-1175`** — `KeyNameInformation`,
  `KeyCachedInformation`, and `KeyValuePartialInformationAlign64` refuse with
  `STATUS_INVALID_PARAMETER`, all three of which the oracle implements. The
  comment credits the refusal to wine's default arm; that arm sits *below* the
  implemented cases. Breaks `RegOpenKeyEx` with `KEY_WOW64_32KEY`.
- **`kernel/ps/query.c:1622-1629`** — `NtCallbackReturn` hardwires
  `STATUS_UNSUCCESSFUL`, which is invisible to the `KiPanicOnNotImplemented`
  net.
- **`kernel/ob/sync.c:501-504, 522-525, 566-570`** — `NtSetTimer` /
  `NtCancelTimer` / `NtQueryTimer` swallow probe failures on optional
  out-parameters and report success — while the timer *is* armed.

Conversely, two `STATUS_NOT_IMPLEMENTED` sites are reachable by ordinary
callers and therefore panic the kernel under the (default-on) arming flag:
**`fs/npfs/pipe.c:524-527`** (a second concurrent async `FSCTL_PIPE_LISTEN`,
which the oracle supports via a queue — this is the standard accept-loop
idiom), and **`kernel/mm/section.c:138`** (`CreateFileMapping` with a size
larger than the file, an everyday Win32 pattern).

---

## 6. Unchecked NULL vfs dispatch (kernel/io)

Two ring-3-reachable calls through NULL function pointers, both critical:

- **[FIXED b236449] `kernel/io/rw.c:315`** — the device branch is entered only when
  `ops->Write != 0`; otherwise control falls through to
  `ops->GetCache(...)` with no check. `HidInputOps` / `HidPointerOps`
  (`drivers/hid.c:202,213`) have `Read` but neither `Write` nor `GetCache`, and
  `HidInputCreate` does not filter `grantedAccess` — so
  `NtCreateFile(L"\\Device\\Input0", GENERIC_WRITE)` + `NtWriteFile` calls
  through NULL in ring 0.
  Note `drivers/hid.c:198` carries a comment asserting that "their absence
  makes the Io layer refuse with its own distinct status". The Io layer does
  not; the comment documents behavior that was never implemented.
- **[FIXED b236449] `kernel/io/rw.c:330,529`** — `ops->SetEndOfFile` is called unchecked on the
  cache path. `FbOps` (`drivers/fb.c:170`) has `GetCache` but no
  `SetEndOfFile`, and `FbCreate` ignores `grantedAccess`. A write at
  `fileSize - 1` of length 2 on `\Device\Fb0` panics.

---

## 7. Half-completed operations and error-path leaks

A recurring shape: state is mutated, then a later step fails, and the caller is
told the whole operation failed.

- **`kernel/ps/thread.c:433-438` (high)** — the comment claims the deref
  "deletes the never-started thread", but `pointerCount` is 2 at that point
  (allocate + running pin), so the ETHREAD survives on `threadListHead` with
  `activeThreadCount` permanently inflated. The process can then **never
  exit** — `remaining` never reaches 0, handles are never closed, `exitStatus`
  is never published, and every wait on that process hangs forever.
- **`kernel/io/file.c:394-401` (high)** — when create succeeds but handle
  creation fails, `closeProcedure` never runs (it fires only on handle
  count 1→0), so `IoRemoveShareAccess`, `IopReleaseAllLocks` and `ops->Cleanup`
  are all skipped. The FCB's share counts are permanently inflated →
  `STATUS_SHARING_VIOLATION` on every later open for the FCB's lifetime.
- **`kernel/io/file.c:187` (high)** — the event handle is resolved *after* the
  I/O has run. A bad event handle on `NtReadFile` consumes 100 bytes from a
  pipe, advances the file pointer, queues the completion APC, and returns
  `STATUS_INVALID_HANDLE`. The data is gone and the caller believes nothing
  happened.
- **`kernel/mm/virtual.c:929-945`** — `MiProtectVirtualMemory` rewrites PTEs
  page by page and only then discovers an uncommitted page, leaving the range
  half-modified while reporting failure. ntdll's loader flips section
  protections through this path.
- **`kernel/mm/pool.c:105`** — a partial `MiExpandPool` failure advances
  `MiPoolEnd` without inserting the block into any free list: the mapped frames
  are permanently unreachable. Combined with a large `MEM_RESERVE` (each VAD
  costs `size/1024` bytes of pool), this can drain all physical memory.
- **`fs/fat32/file.c:466-475`** — a create that fails its *type* checks has
  already written the directory entry; a trailing-backslash path without
  `FILE_DIRECTORY_FILE` leaves a zero-length orphan file behind.
- **`fs/fat32/file.c:568-571` (high)** — a deferred delete-on-close is dropped
  forever when a section is mapped: `sectionCount != 0` returns early, and
  nothing re-enters the FS when the section is later released.
- **`kernel/ps/process.c:1563-1569`** — process handle leaked when the thread
  handle fails; the caller will not close a handle it believes was never made.
- **`kernel/ke/apc.c:18-35`** — queued user APCs are never drained at thread
  exit. Looping `NtQueueApcThread` at an exited thread leaks pool without bound.
- **`drivers/virtio/virtqueue.c:40-46`** — physical frames leaked on partial
  ring-allocation failure.

---

## 8. Architecture and driver correctness

- **`arch/x86_64/idt.c:47` (high, corroborated independently by two reviewers)**
  — every IDT gate is `0x8E`, i.e. DPL 0. A ring-3 `int3` therefore raises
  `#GP`, not `#BP`, and dies as `STATUS_ACCESS_VIOLATION`. Every
  `DbgBreakPoint` / `__debugbreak` / CRT assert in the Wine stack is affected.
  `kernel/init/panic.c:232` has `case 3: return STATUS_BREAKPOINT;` — dead code
  today, which is what shows the intent. Note the fix is two-part: `panic.c:266`
  tests `vector == 3` *before* the ring check, so simply raising the gate DPL
  would let a user `int3` be swallowed as the M1 demo and resumed, giving ring 3
  an unbounded serial-spam primitive.
- **`drivers/virtio/pci.c:38` (high)** — virtio BAR MMIO is mapped write-back
  cacheable via `MiMapPage`, when `MiMapDevicePage` exists for exactly this
  (`arch/x86_64/mmu.c:116-119`, already used by `lapic.c:114`). `volatile`
  constrains the compiler, not the cache. This works today only because
  firmware happens to leave the PCI hole UC in the MTRRs; nothing in the kernel
  establishes or checks that. One word per call site.
- **`drivers/virtio/virtqueue.c:101-123`** — the completion spin loop reads a
  non-`volatile` `used->idx` with no `"memory"` clobber on the `pause` and no
  call in the loop body, so the load is hoistable. Contrast `pci.c:132`, which
  is safe only because `deviceStatus` is `volatile`.
- **`arch/x86_64/trap.S:86`** — no `cld` before calling C. `iretq`-delivered
  exceptions do not clear DF (unlike `syscall`, which the code correctly
  handles via `IA32_FMASK`), so the whole trap path — including a context
  switch into another thread — can run with DF=1. The reviewer compiled
  representative cases with the project's exact flags and confirmed clang emits
  no rep-string instructions today, so this is latent; it is a one-instruction
  fix.
- **`arch/x86_64/lapic.c:151`** — the spurious-interrupt vector 0xFF has no IDT
  gate, so the architecturally-defined "ignore this" event becomes a `#GP` and
  a panic blaming an unrelated RIP.
- **`arch/x86_64/lapic.c:123-130`** — the LAPIC timer is started *after* the
  PIT, so calibration systematically under-measures and the 1 ms clock runs
  fast. Small (<0.1%) but one-directional, and it biases every timeout in the
  system.
- **`arch/x86_64/trap.S:57-58`** — vectors 29 (#VC) and 30 (#SX) are declared
  no-error-code; AMD APM Vol. 2 says both push one, which shifts the whole
  trap frame by 8 bytes (and makes the entry `swapgs` decision read RFLAGS
  instead of CS). Not reachable under the pinned QEMU config.
- **`arch/x86_64/gdt.c:141-147`** — CR4 is inherited from the bootloader;
  SMAP/SMEP are never put into a defined state, although
  `kernel/syscall/uaccess.c` and `panic.c:206` both depend on SMAP being off.
- **`kernel/syscall/entry.S:96`** — `NtContinue` accepts a non-canonical `Rip`;
  `iretq` then `#GP`s with kernel CS → panic. Choosing `iretq` over `sysret`
  correctly avoids the classic non-canonical-RCX hole, but IRET has its own.

---

## 9. Oracle divergences (gate G1) worth pinning

These are correctness bugs against the pinned Wine tree rather than safety
bugs, and each needs a `tests/ntapi/` pin before the fix (G5):

- **`kernel/ps/usermode.c:186-218`** — `KiContextToTrapFrame` ignores
  `CONTEXT.ContextFlags` entirely. The documented NT idiom
  (`ContextFlags = CONTEXT_INTEGER`, get, modify, set) overwrites `rip` and
  `rsp` with 0. Also drops `TF`, so user single-step is impossible, and
  `KiTrapFrameToContext` hard-sets `ContextFlags = CONTEXT_FULL` while leaving
  the segment registers zeroed.
- **`kernel/ke/wait.c:107-112`** — a pending alert is never consumed on the
  wake path, so one `NtAlertThread` satisfies two alertable waits (a `SleepEx`
  loop spins). At `:453-454`, `STATUS_USER_APC` clears `alerted` on both
  branches, silently destroying a pending alert.
- **`kernel/ke/wait.c:163,436`** — `WaitAll` abandonment returns
  `STATUS_ABANDONED_WAIT_0 + index`; the oracle
  (`third_party/wine/server/thread.c:1081-1092`) always returns bare
  `STATUS_ABANDONED_WAIT_0` for a wait-all.
- **`kernel/cm/registry.c:1235`** — `NtEnumerateValueKey` returns
  `STATUS_BUFFER_TOO_SMALL` where the oracle has no such arm and always returns
  `STATUS_BUFFER_OVERFLOW`. Breaks the standard grow-and-retry loop.
- **`kernel/ob/handle.c:619-657`** — `NtQueryObject(ObjectNameInformation)`
  returns the leaf component, not the full path; the oracle walks
  `name->parent` to the root.
- **`kernel/ob/handle.c:416-430`** — `NtDuplicateObject` open-codes a *second*
  generic-access mapping instead of calling `ObpMapDesiredAccess`, and the two
  have already drifted: duplicating a keyed-event handle with `GENERIC_READ`
  grants wake rights the original correctly denied. Textbook G10.
- **`fs/npfs/pipe.c:733,1101`** — message *read* mode is accepted on a byte-type
  pipe (the oracle refuses at both create and set-info), which then fabricates
  message framing at arbitrary quota boundaries.
- **`fs/npfs/pipe.c:628`** — byte-mode peek returns `STATUS_BUFFER_OVERFLOW`
  whenever data remains; the oracle overflows only on *message* truncation, so
  the normal 1-byte `PeekNamedPipe` poll fails.
- **`kernel/io/rw.c` (whole file)** — byte-range locks are taken and tracked but
  **never enforced** on read/write; `IopLockConflicts` is referenced only inside
  `lock.c`, and the lock-bypass `key` argument is `(void)`-cast away. Not in
  `docs/03`.
- **`kernel/io/rw.c:501-515`** — scatter/gather silently ignores negative
  `ByteOffset`, so `NtWriteFileGather` with `FILE_WRITE_TO_END_OF_FILE`
  overwrites the *start* of the file instead of appending.
- **`kernel/se/sd.c:89-92`** — unknown ACE types are accepted with a comment
  saying "as the server's do"; wine's `acl_is_valid` ends with
  `default: return FALSE`. The access check then silently skips the ACE.
- **`kernel/se/sd.c:164-222`** — `SECURITY_DESCRIPTOR.Revision` is never
  checked, though the named oracle function checks it and
  `SECURITY_DESCRIPTOR_REVISION` is already generated in `abi/`.
- **`kernel/lib/rtl.c:93-94`** — `RtlCopyUnicodeString` never NUL-terminates,
  unlike the oracle. Latent (only a test calls it), but this is the shared
  authority other departments will reach for — `kernel/ob/handle.c:647` already
  hand-rolls its own terminator.
- **`kernel/cm/registry.c:1040`** — `NtDeleteValueKey` doesn't round an odd
  name length to whole WCHARs while `NtQueryValueKey` does, so within proskrnl
  query and delete disagree about which names exist.

---

## 10. Information disclosure

- **`kernel/se/token.c:639,677-682,715-736,948-954` (high)** —
  `BYTE reply[...]` is never zeroed, and structure padding pinned by
  `abi/ntseapi.h` is copied out verbatim: 4 bytes from `TOKEN_USER`, 4 + 4 per
  group from `TOKEN_GROUPS` (36 bytes with the boot token's 8 groups), 4 from
  `TOKEN_MANDATORY_LABEL` (which does not even need a valid handle). A
  repeatable kernel-stack oracle. `TokenStatistics` already memsets correctly —
  the pattern just was not applied to the variable-length classes.
- **`kernel/ob/namespace.c:874-885`** — `NtCreateSymbolicLinkObject` copies up
  to 64 KB from an unvalidated `Buffer`; pointing it at kernel memory and
  reading it back with `NtQuerySymbolicLinkObject` is a clean disclosure
  primitive.

---

## 11. Access checks that are missing or too weak

- **`kernel/mm/section.c:526,553` (high)** — the section's creation protection
  is never consulted at map time (`section->pageProtection` is written and read
  nowhere). Open a file `FILE_READ_DATA`, create a `PAGE_READONLY` section,
  map it `PAGE_READWRITE` — and write to the file's page cache, which with
  immediate writeback (Art. 3) is a write to the file. NT returns
  `STATUS_SECTION_PROTECTION`.
- **`kernel/ps/job.c:226,241`** — `NtAssignProcessToJobObject` requires **zero**
  access on both handles, where NT requires `JOB_OBJECT_ASSIGN_PROCESS` and
  `PROCESS_SET_QUOTA | PROCESS_TERMINATE`. Gives termination without
  `PROCESS_TERMINATE` via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The file's own
  comment at `:124-126` records that a fuzzer found this exact class on
  `NtSetInformationJobObject`; the assign path was not fixed.
- **`kernel/ps/thread.c:433,471`** — `NtCreateThreadEx` ignores `desiredAccess`
  and always grants `THREAD_ALL_ACCESS`; also ignores `objectAttributes` (so
  `OBJ_INHERIT` is dropped) and `stackSize` (hardcoded 1 MiB).
- **`kernel/io/ioctl.c:54`, `query.c:134,1077,1330`, `lock.c:141,215`** —
  `IopReferenceFileByHandle(handle, 0, ...)`: a zero-access handle can drive
  every ioctl/FSCTL, `NtLockFile`, and `NtSetVolumeInformationFile` — the last
  mutating the on-disk volume label through a `FILE_READ_ATTRIBUTES` handle.
- **`fs/fat32/file.c:550`** — `FILE_DELETE_ON_CLOSE` bypasses the read-only
  check that `NtSetInformationFile(FileDispositionInformation)` correctly
  applies.
- **`kernel/cm/registry.c:891,967`** — the zero-access refusal tests the
  *unmapped* mask, so `NtOpenKey(&h, KEY_WOW64_64KEY, ...)` returns a
  usable-looking handle granting nothing, where the oracle denies.

---

## 12. Data-integrity issues in fs/fat32

Beyond the mount validation above:

- **`file.c:572` / `fat.h:71-73`** — a deleted file's FCB keeps its
  `(dirCluster, sfnSlot)` identity key while the slot is reusable, so a new file
  landing on that slot aliases the stale FCB (wrong `isDirectory`, wrong name,
  wrong cached size, stale page cache). `FatVfsRename`'s replace path can
  produce two live FCBs with the same key and thus the same `FatFileId`.
- **`dir.c:562-572`** — the exact-8.3 creation path never checks short-name
  uniqueness (`FatBuildExact83` accepts `~` and digits), so creating
  `AAAAAA~1.TXT` alongside an LFN whose generated short name is `AAAAAA~1TXT`
  produces two entries with identical 11-byte short names. `FatLookup` then
  returns whichever comes first — a plain wrong-file open.
- **`fat.c` (whole file)** — FSInfo is never read or written. Free-space
  reports from Windows and mtools are stale after proskrnl writes, and the
  deviation is not in `docs/03`.
- **`dir.c:691-719`** — a directory can be created without its `.`/`..` entries
  if the first-sector RMW fails after the parent entry is already written; the
  result is enumerable, permanently corrupt, and has no FCB.
- **`file.c:189-193,230-234`** — `FatSetFileSize` error paths leave the chain
  and the on-disk metadata disagreeing; a failed shrink silently zero-fills on
  the next read.
- **`file.c:572`, `:515`, `fat.c:113-122`** — return values discarded where the
  failure is user-visible; `FatFreeChain` is `void` and drops every
  `FatSetFatEntry` error.

---

## 13. Registry durability (kernel/cm)

- **`hive.c:94,114` (high)** — `CmpMeasureKey` / `CmpEmitKey` / `CmpFreeSubtree`
  recurse once per tree level on a 16 KiB pool-allocated kernel stack with **no
  guard page**. Nothing caps tree depth at create time. ~400 levels of
  `NtCreateKey` followed by any mutation runs the stack off its block and
  corrupts adjacent pool headers. The *parser* was capped
  (`CMP_HIVE_MAX_DEPTH`); the serializer and the free path were not.
- **`hive.c:60,221` vs `registry.c:904` (high)** — and the asymmetry is worse
  than a crash: create depth is unlimited, load depth caps at 96, and
  `CmpLoadHive` treats any parse failure as "hive invalid" →
  `CmpFreeSubtree(CmpRootNode)`. A 100-deep key path saves successfully,
  reports durability, and **discards the entire registry at next boot**. That
  is not the bounded loss `docs/03` authorizes.

---

## Suggested order of work

Items 1–6 of the original plan are done (see the marks above). What remains,
in the order the findings argue for:

1. **A ring-0 fault fixup path** (§1b). Still the highest-leverage single
   change in the document: it converts every *remaining* missing probe — and
   every one added by future code — from "machine halts" into
   `STATUS_ACCESS_VIOLATION`. The probes added so far fix specific sites; this
   fixes the failure mode.
2. **The rest of §1a** — `NtQueryDirectoryFile`'s `mask`, and the symbolic-link
   pair (which is also a kernel-memory disclosure channel, §10).
3. **§2's remaining `ASSERT`-on-user-state sites** — `verify.c:65` (a process
   writing its own TEB), `mm/section.c:339` (a crafted `.reloc`),
   `io/async.c:83` and `notify.c:81,96` (unmapping a pended buffer), and
   `ke/wait.c:56` (a duplicate handle in a `WaitAll`). Each is an
   unprivileged halt.
4. **§4's remaining untrusted-input paths** — the FAT entry values and the
   cyclic-chain hang in particular, which a mounted image reaches without any
   syscall at all.
5. Everything else, pinning each behaviour in `tests/ntapi/` first (G5).

Themes worth treating as policy rather than as individual fixes; the first is
now partly enforced, the rest are not:

- **Probes belong in the engine, not the service.** Section 1a took two passes
  precisely because "the engine covers it" was assumed rather than checked —
  Io and Cm resolve names outside Ob. `ObProbeObjectAttributes` is now shared
  by all three, but the general lesson stands: when a check moves to one
  authority, enumerate the callers that bypass that authority.
- `ASSERT` must never fire on user-controlled state.
- Size arithmetic on user-supplied lengths must be checked at the point of
  rounding, not after.
- A comment asserting a safety property (`drivers/hid.c:198`,
  `kernel/ps/thread.c:436`, `kernel/mm/pecoff.c:250`, `kernel/se/sd.c:91`) was
  wrong in every case a reviewer checked it. `drivers/hid.c:198` claimed the
  Io layer refused writes it did not implement; that is true only as of
  b236449, and the comment predated it by the whole life of the file.

### Test-harness issues found while fixing

Neither is a kernel bug, both cost real time:

- **`tests/run/run.sh` reports `PASS` when a test fails to compile** — the
  stale `.exe` from the previous build runs instead, so a broken test prints
  green. This happened four times during this work (an undeclared info-class
  constant, a `*/` inside a comment, a wrong enum name, a missing `util.h`
  include). It is the same silent-plausible-answer failure Art. 12 forbids in
  the kernel, in the harness that judges it.
- **`/dev/kvm` present but unusable** (e.g. an ephemeral container) makes
  `qemu.sh` select KVM and every test fail with an empty serial log, which
  reads as a mass kernel regression. `ACCEL=tcg` is the workaround; the
  accelerator probe could check usability rather than existence.
