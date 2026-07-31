# Kernel subsystem code review — 2026-07

Read-only review of every subdirectory under `kernel/`, `drivers/`, `fs/`, and
`arch/`, at commit `74e96a0`. One reviewer per subdirectory, 14 in total,
each reading its directory in full plus the seams it depends on, and
cross-checking against the pinned Wine oracle (`third_party/wine`) and the
relevant vendor specs.

**169 findings.**

**Status: every finding in this document has been dealt with.** Most were
fixed; a handful were checked against the pinned oracle and turned out not to
be proskrnl bugs, and those are recorded as such rather than "fixed". Fixed
items carry a **[FIXED `<commit>`]** mark inline below and items resolved the
other way a **[NOT A BUG `<commit>`]** mark with the reason.

The first round (the `[FIXED]` marks with short hashes from the original pass)
covered everything rated *critical* plus four *high* findings that shared their
code paths. The second round closed the remainder; its commits are on
`claude/kernel-subsystems-review-bugs-0j8jc5`.

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

### What the second round found that the review did not

Four things worth carrying forward, because they changed what "fixed" meant:

- **Four findings were not proskrnl bugs.** `MiFreeVirtualMemory`'s wrapping
  `RegionSize`, the unenforced byte-range locks, the zero-access references in
  `kernel/io` (bar one), and npfs's pipe info classes on a dead pipe all match
  the pinned oracle exactly. Art. 6 makes the oracle the spec, so each is
  pinned as deliberate agreement (and, where it is also a deviation from NT,
  recorded in `docs/03`) rather than "fixed" into a divergence.
- **Two predictions about the oracle were wrong**, and running it settled
  them: section-map protection is gated by the backing FILE HANDLE's access,
  not by the section's creation protection, and answers
  `STATUS_ACCESS_DENIED` rather than `STATUS_SECTION_PROTECTION`; and a bad
  completion-event handle on `NtReadFile` is discarded rather than reported,
  because the transfer has already happened.
- **The oracle cannot answer everything.** Three cases wedge or kill the
  pinned Wine rather than returning a status (a ring-3 `int3` with no
  debugger, a wait-all naming one object twice, an unwritable
  `NtQuerySymbolicLinkObject` buffer). Those are pinned in `beyond_oracle`
  blocks against cited Microsoft contracts, with the calls skipped on the
  oracle leg so it stays runnable — and each block says which.
- **The harness hid results three times, not once.** Beyond the stale-`.exe`
  bug the review found, `run.sh` also booted a STALE KERNEL (it built only
  when `build/proskrnl` was missing) and ignored `make`'s exit status. Both
  produced a false "pass" while convicting fixes in this round.

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
- **[FIXED 54ffe24] `kernel/ob/namespace.c:874-951`** — `NtCreateSymbolicLinkObject` /
  `NtQuerySymbolicLinkObject` read and `memcpy` up to 64 KB through an
  unvalidated `UNICODE_STRING`. `ObProbeUnicodeStringRead` is now the shared
  authority for a counted string that arrives outside an `OBJECT_ATTRIBUTES`.
- **[FIXED 7d399f1, c4d0eb3] `kernel/cm/registry.c:852,856,1025,1077,1096,1159,1182`** — `valueName` and
  `attributes` raw in `NtSetValueKey` / `NtQueryValueKey` / `NtDeleteValueKey` /
  `NtCreateKey` / `NtOpenKeyEx`. Cm's `data` parameter *is* probed, one line
  away.
- **[FIXED c4d0eb3 — `NtCreateFile` only] `kernel/io/file.c:309,341`, `kernel/io/query.c:942-950`** —
  `NtCreateFile`'s `OBJECT_ATTRIBUTES`, and `NtQueryDirectoryFile`'s `mask`
  (whose `Buffer` is then `memcpy`'d into the handle's retained `dirMask`).
  The `mask` half is **[FIXED 54ffe24]**, through the same shared probe.
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

### 1b. A missing probe is a machine kill, not an access violation — **[FIXED 8676fbb]**

`KiDispatchTrap` (`kernel/init/panic.c:275-335`) contains a fault only when
`segCs & 3 == 3`. A fault taken in ring 0 on a user address has no fixup and
falls through to `KiPanicLatch` / `KiHalt`. So each of the above is not
"returns the wrong status" — it is **any unprivileged process halting the whole
machine with one syscall**. A kernel-mode fault fixup path (or an exception
table on the copy routines) would convert this entire class from fatal to
`STATUS_ACCESS_VIOLATION` in one change, and is worth doing independently of
fixing the individual sites.

**[FIXED 8676fbb]** — and it is the highest-leverage change in the series, as
predicted. `KiSystemServiceTrap` arms a recovery frame
(`kernel/syscall/recover.S`) around every ring-3-originated service;
`KiDispatchTrap` unwinds to it when a ring-0 `#PF`/`#SS` lands on a user
address and the service returns `STATUS_ACCESS_VIOLATION`. This is NT's own
arrangement: `KiSystemServiceHandler` makes the dispatcher the outermost
exception frame of every service. A fault on a KERNEL address still panics.
Convicted by `tests/kmt/m4_usermode.c test_kernel_fault_recovery`, which
without the hook takes the machine down with
`[PANIC] vector=14 (#PF page fault)`.

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

**[FIXED 0693a9a]** — by DELETING them rather than strengthening them. A
mode-aware probe there would be worse than useless: it runs BEFORE
materialization and demands present-and-writable, so it would refuse exactly
the guard-paged growing stacks these frames must be written onto.
`KiMaterializeUserRange` is the one gate, and its comment now says so.

### 1d. Probe-then-block TOCTOU is now live — **[FIXED 8676fbb, d4cc2f4]**

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

**[FIXED 8676fbb]** for the read/write shape: the recovery frame of §1b turns
a sibling's mid-syscall unmap into `STATUS_ACCESS_VIOLATION` instead of a
ring-0 fault, which is what the probe alone could never carry.
**[FIXED d4cc2f4]** for the `se/sd.c` double fetch: both capture helpers now
take the capacity the measure pass reserved and refuse a changed length
BEFORE copying, which is the only ordering that helps.

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
- **[FIXED e0d7f7c] `kernel/init/verify.c:65-67` (high)** — the state sweep asserts on
  `teb->ClientId.UniqueThread` and `teb->Tib.Self`, which live in a
  `PAGE_READWRITE` user page. Any process writing its own TEB panics the kernel
  at the next sweep. Now reported on serial and the run continues: a named
  suspect is all an assert on user state was ever worth.
- **[FIXED f696a9a] `kernel/mm/section.c:339` (high)** — relocation target VA is
  `base + block.VirtualAddress + offset` with `block.VirtualAddress` read
  straight from a user-supplied PE's `.reloc` and never bounds-checked against
  `sizeOfImage`. Unmapped → `ASSERT(frame != 0)` panic; mapped → silent
  corruption of unrelated memory in that process. The entry's type now selects
  the fixup width before the bound is applied, so the check is exact; a fixup
  outside the image is `STATUS_INVALID_IMAGE_FORMAT`.
- **[FIXED db7bc7d] `kernel/io/async.c:83`, `kernel/io/notify.c:81,96` (high)** — completing a
  pended request writes through `MiCopyToUserRange`, which asserts on a missing
  frame. The buffer was probed at issue time; the owner may unmap it while the
  request is parked. `NtNotifyChangeDirectoryFile` + `NtFreeVirtualMemory` +
  touch the directory = panic. All three sites use `MiCopyToUserRangeChecked`
  now: a caller that unmaps its own completion buffer gets no completion
  written into it, and there is nobody left to report a status to.
- **[FIXED e232a4f] `kernel/ke/wait.c:56` (high)** — `KiSatisfyObject` asserts
  `signalState > 0`, and nothing de-duplicates objects in a `WaitAll`.
  `NtWaitForMultipleObjects(2, {hSem, hSem}, WaitAll, ...)` on a
  count-1 semaphore satisfies it twice and panics. The oracle does not panic —
  though it does not answer either: wineserver has the identical assertion
  (`server/semaphore.c semaphore_sync_satisfied`) and EXITS on the input. NT's
  documented contract settles it instead: "the array ... may not contain
  multiple copies of the same handle", so a wait-all naming one object twice
  is `STATUS_INVALID_PARAMETER`, refused before anything is consumed. WaitAny
  is untouched — duplicates are legal there.
- **[FIXED 94e5509] `kernel/io/file.c:526,581` (latent)** — `ASSERT(NT_SUCCESS(refStatus))` on
  a transient handle that lives in the *caller's* handle table, and is
  therefore user-closable. Safe only under the current no-preemption mandate —
  which has a named exit (`docs/18` §13), so both sites now return the
  reference's status and close the transient handle.

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
- **[NOT A BUG 09e7d34] `kernel/mm/virtual.c:406` (medium)** — the same wrap in
  `MiFreeVirtualMemory`, where a rounded size of 0 is the *sentinel* for
  "the whole VAD". `NtFreeVirtualMemory` with a crafted length releases an
  entire reservation and reports success. Verified against the pinned oracle
  by running it: Wine wraps identically (`ROUND_SIZE` then
  `case MEM_RELEASE: if (!size) size = view->size`), answers `00000000`,
  frees the whole view and reports the view's size — byte for byte what
  proskrnl answers. Validating it would be the divergence (Art. 6), so
  `sem_mm/reserve_commit` pins the agreement instead.
- **[FIXED 7dea934] `kernel/io/lock.c:39` (medium)** — byte-range overlap arithmetic on
  `uint64_t` with lengths taken from user `LARGE_INTEGER`s unvalidated; two
  "exclusive" locks over the same bytes can both be granted. Fixed to the
  oracle's model rather than by saturating (which was the first attempt, and
  diverges): a wrap to anything other than exactly 0 is refused, and an end of
  exactly 0 is the UNBOUNDED lock.
- **[FIXED 1bf13ac] `drivers/virtio/blk.c:132-135`** — `sectorCount * VIO_BLK_SECTOR_SIZE` is a
  32-bit multiply, so `sectorCount = 0x800000` makes the bounding `ASSERT` pass
  with a product of 0. Latent (callers chunk at 8 sectors).
- **[FIXED 95739f8] `kernel/ps/process.c:178-187`** — `SizeOfStackReserve` from the image is
  rounded without a guard, and `reserve - 2*PAGE_SIZE` then underflows.
- **[FIXED beec8bc] `kernel/lib/dbgprint.c:165-168`** — `-value` on `INT64_MIN` is signed
  overflow; the kernel builds with `-fsanitize-trap=undefined`, so this is a
  `ud2` **inside the logging path**. Negated in the unsigned domain.

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
- **[FIXED 51ec994] `fs/fat32/fat.c:44-53` (high)** — FAT entry values are returned verbatim;
  the bounds check is an `ASSERT` on the *input* cluster, never on the
  *returned* one. A file whose `DIR_FstClus` is `0x0FFFFFF0` panics on first
  read. `FatAllocateCluster` at `:93` indexes with no assert at all.
  `FatIsDataCluster` is now the one authority and filters BOTH ends, and
  `FatMakeFcb` normalises a corrupt `DIR_FstClus` where it is read.
- **[FIXED 51ec994] `fs/fat32/dir.c:166-258` (high)** — no cycle detection when walking a
  directory's cluster chain. A cyclic chain hangs the kernel forever
  (uniprocessor, no preemption). Every chain walk is bounded by the volume's
  cluster count — a chain longer than that has revisited one by definition —
  and `FatChainLength` returns the capped count instead of calling `KiPanic`:
  a cycle is a property of the media, not of the kernel.
- **[FIXED 52777d1] `kernel/mm/pecoff.c:250`** — export-name comparison bounds only the *first*
  byte (`nameOffset < rawSize`); a crafted PE whose tail spells a prefix of a
  looked-up name over-reads past the page-cache block. `KiStringEqualsWithin`
  is the bounded compare, in `kernel/lib` beside the one it replaces.
- **[FIXED 1123446] `arch/x86_64/smbios.c:127-136`** — firmware `maxSize` used unvalidated as a
  walk bound (and `cursor + 1` wraps at 4 GiB). The 32-bit entry-point path at
  `:163-174` does no table validation at all, unlike the 64-bit one. The bound
  is capped at 1 MiB before the walk, the cursor is 64-bit, and the 32-bit
  path walks its table and requires the walk to agree with the stated
  length.
- **[FIXED eb56ea8] `drivers/virtio/pci.c:54,81,61-65,194-196`** — capability-list walk is
  unbounded (a cyclic `cap_next` hangs boot), the device-supplied BAR index is
  unvalidated, and the notify address is computed from device values with no
  bound against the mapped notify window — potentially landing in another
  device's register window. All three bounded; the notify window's length is
  recorded when the capability is resolved.

---

## 5. Fabricated answers (gate G12)

Art. 12's claim that every silent-plausible stub becomes a deferred bug holds
up well here. Live instances:

- **[FIXED acba386] `kernel/ps/thread.c:1077-1094`** — `NtSetInformationThread` returns
  `STATUS_SUCCESS` for **every** class, including `ThreadImpersonationToken`,
  and does not even name the class on serial. A caller that impersonates and
  gets success then makes security decisions on a fabricated answer. Unbuilt
  classes refuse loudly now; the accepted set is spelled out explicitly, so
  adding one is a decision rather than a fall-through.
- **[FIXED 415626e] `kernel/ps/process.c:1291-1294`** — `NtTerminateProcess(NULL, status)`
  returns success without terminating the sibling threads it is contractually
  required to. This is precisely how `RtlExitUserProcess` drains siblings
  before DLL detach. Siblings are flagged and woken, and the caller waits
  (bounded at 5 s) for them to reap themselves at their next ring-3 edge.
- **[NOT A BUG] `fs/npfs/pipe.c:686-716`** — pipe info classes return
  `STATUS_SUCCESS` with an all-zero structure when the pipe is gone; the claim
  was that the oracle returns `STATUS_PIPE_DISCONNECTED` for both classes.
  Verified by running it: with the server end closed, the pinned Wine answers
  `00000000` for BOTH `FilePipeInformation` and `FilePipeLocalInformation` —
  the same status proskrnl gives. No change; Art. 6.
- **[FIXED 730be22] `kernel/cm/registry.c:768-772, 1171-1175`** — `KeyNameInformation`,
  `KeyCachedInformation`, and `KeyValuePartialInformationAlign64` refuse with
  `STATUS_INVALID_PARAMETER`, all three of which the oracle implements. The
  comment credits the refusal to wine's default arm; that arm sits *below* the
  implemented cases. Breaks `RegOpenKeyEx` with `KEY_WOW64_32KEY`. All three
  implemented, with their layouts GENERATED into `abi/` rather than hand-typed
  (G4); `KeyNameInformation` reports the full path, as the oracle's
  `get_full_name` does.
- **[FIXED 37ce57b] `kernel/ps/query.c:1622-1629`** — `NtCallbackReturn` hardwires
  `STATUS_UNSUCCESSFUL`, which is invisible to the `KiPanicOnNotImplemented`
  net. It answers `STATUS_NOT_IMPLEMENTED` now: if it is ever reached, the
  unreachability argument has broken and the caller needs to hear about it.
- **[FIXED 295602e] `kernel/ob/sync.c:501-504, 522-525, 566-570`** — `NtSetTimer` /
  `NtCancelTimer` / `NtQueryTimer` swallow probe failures on optional
  out-parameters and report success — while the timer *is* armed. All three
  probe BEFORE the side effect and return the probe's status; "optional" means
  the pointer may be NULL, not that it may be unwritable.

Conversely, two `STATUS_NOT_IMPLEMENTED` sites are reachable by ordinary
callers and therefore panic the kernel under the (default-on) arming flag:
**[FIXED 7bf5790] `fs/npfs/pipe.c:524-527`** (a second concurrent async
`FSCTL_PIPE_LISTEN`, which the oracle supports via a queue — this is the
standard accept-loop idiom; the instance keeps a queue now, and a client
attach wakes ALL of it, as wineserver does), and
**[FIXED 24166b7] `kernel/mm/section.c:138`** (`CreateFileMapping` with a size
larger than the file, an everyday Win32 pattern; Io extends the file when the
protection allows writing and answers `STATUS_SECTION_TOO_BIG` when it does
not, as Microsoft documents for `CreateFileMappingW`).

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

- **[FIXED 220d686] `kernel/ps/thread.c:433-438` (high)** — the comment claims the deref
  "deletes the never-started thread", but `pointerCount` is 2 at that point
  (allocate + running pin), so the ETHREAD survives on `threadListHead` with
  `activeThreadCount` permanently inflated. The process can then **never
  exit** — `remaining` never reaches 0, handles are never closed, `exitStatus`
  is never published, and every wait on that process hangs forever.
  `PspUnwindUnstartedThread` drops exactly what `PspCreateThreadObject`
  added, in reverse.
- **[FIXED 837a82b] `kernel/io/file.c:394-401` (high)** — when create succeeds but handle
  creation fails, `closeProcedure` never runs (it fires only on handle
  count 1→0), so `IoRemoveShareAccess`, `IopReleaseAllLocks` and `ops->Cleanup`
  are all skipped. The FCB's share counts are permanently inflated →
  `STATUS_SHARING_VIOLATION` on every later open for the FCB's lifetime. The
  cleanup half now runs explicitly on that path.
- **[FIXED 801688c] `kernel/io/file.c:187` (high)** — the event handle is resolved *after* the
  I/O has run. A bad event handle on `NtReadFile` consumes 100 bytes from a
  pipe, advances the file pointer, queues the completion APC, and returns
  `STATUS_INVALID_HANDLE`. The data is gone and the caller believes nothing
  happened. The oracle draws the line in two places and both are reproduced:
  read/write DISCARD an event-signal failure and return the transfer's own
  status (`if (event) NtSetEvent( event, NULL );`, result untested), while the
  ioctl/FSCTL pair rejects the request up front — so `IopValidateEventHandle`
  runs there before the verb does.
- **[FIXED bbc98b1] `kernel/mm/virtual.c:929-945`** — `MiProtectVirtualMemory` rewrites PTEs
  page by page and only then discovers an uncommitted page, leaving the range
  half-modified while reporting failure. ntdll's loader flips section
  protections through this path. The whole range is checked in a pass of its
  own first, so the call applies completely or changes nothing.
- **[FIXED 272f238] `kernel/mm/pool.c:105`** — a partial `MiExpandPool` failure advances
  `MiPoolEnd` without inserting the block into any free list: the mapped frames
  are permanently unreachable. Combined with a large `MEM_RESERVE` (each VAD
  costs `size/1024` bytes of pool), this can drain all physical memory. A
  partial expansion now hands what it got to the free list and still reports
  failure.
- **[FIXED 5da2f01] `fs/fat32/file.c:466-475`** — a create that fails its *type* checks has
  already written the directory entry; a trailing-backslash path without
  `FILE_DIRECTORY_FILE` leaves a zero-length orphan file behind. Every refusal
  after the entry exists now deletes it.
- **[FIXED 5da2f01] `fs/fat32/file.c:568-571` (high)** — a deferred delete-on-close is dropped
  forever when a section is mapped: `sectionCount != 0` returns early, and
  nothing re-enters the FS when the section is later released. The intent is
  latched, and `IO_VFS_OPS` grows a `SectionsReleased` hook — deliberately NOT
  `Cleanup`, since no handle is closing there.
- **[FIXED f85f619] `kernel/ps/process.c:1563-1569`** — process handle leaked when the thread
  handle fails; the caller will not close a handle it believes was never made.
- **[FIXED 75a5256] `kernel/ke/apc.c:18-35`** — queued user APCs are never drained at thread
  exit. Looping `NtQueueApcThread` at an exited thread leaks pool without bound.
  Both halves fixed: the queue is drained at exit, and an APC aimed at an
  already-terminated thread is dropped rather than queued.
- **[FIXED 367c52f] `drivers/virtio/virtqueue.c:40-46`** — physical frames leaked on partial
  ring-allocation failure.

---

## 8. Architecture and driver correctness

- **[FIXED 9122031] `arch/x86_64/idt.c:47` (high, corroborated independently by two reviewers)**
  — every IDT gate is `0x8E`, i.e. DPL 0. A ring-3 `int3` therefore raises
  `#GP`, not `#BP`, and dies as `STATUS_ACCESS_VIOLATION`. Every
  `DbgBreakPoint` / `__debugbreak` / CRT assert in the Wine stack is affected.
  `kernel/init/panic.c:232` has `case 3: return STATUS_BREAKPOINT;` — dead code
  today, which is what shows the intent. Note the fix is two-part: `panic.c:266`
  tests `vector == 3` *before* the ring check, so simply raising the gate DPL
  would let a user `int3` be swallowed as the M1 demo and resumed, giving ring 3
  an unbounded serial-spam primitive. Both halves are in: vectors 3 and 4 (the
  two ring 3 raises deliberately) get DPL-3 gates, and the M1 demo branch is
  ring-0 only.
- **[FIXED eb56ea8] `drivers/virtio/pci.c:38` (high)** — virtio BAR MMIO is mapped write-back
  cacheable via `MiMapPage`, when `MiMapDevicePage` exists for exactly this
  (`arch/x86_64/mmu.c:116-119`, already used by `lapic.c:114`). `volatile`
  constrains the compiler, not the cache. This works today only because
  firmware happens to leave the PCI hole UC in the MTRRs; nothing in the kernel
  establishes or checks that. One word per call site.
- **[FIXED 367c52f] `drivers/virtio/virtqueue.c:101-123`** — the completion spin loop reads a
  non-`volatile` `used->idx` with no `"memory"` clobber on the `pause` and no
  call in the loop body, so the load is hoistable. Contrast `pci.c:132`, which
  is safe only because `deviceStatus` is `volatile`.
- **[FIXED 01a5598] `arch/x86_64/trap.S:86`** — no `cld` before calling C. `iretq`-delivered
  exceptions do not clear DF (unlike `syscall`, which the code correctly
  handles via `IA32_FMASK`), so the whole trap path — including a context
  switch into another thread — can run with DF=1. The reviewer compiled
  representative cases with the project's exact flags and confirmed clang emits
  no rep-string instructions today, so this is latent; it is a one-instruction
  fix.
- **[FIXED 4572271] `arch/x86_64/lapic.c:151`** — the spurious-interrupt vector 0xFF has no IDT
  gate, so the architecturally-defined "ignore this" event becomes a `#GP` and
  a panic blaming an unrelated RIP. It has a handler now, returning without an
  EOI as the SDM requires.
- **[FIXED 4572271] `arch/x86_64/lapic.c:123-130`** — the LAPIC timer is started *after* the
  PIT, so calibration systematically under-measures and the 1 ms clock runs
  fast. Small (<0.1%) but one-directional, and it biases every timeout in the
  system. The PIT loads on its HIGH-byte write, so the low byte goes first,
  the LAPIC's initial count next and the high byte last — one I/O write apart.
- **[FIXED 01a5598] `arch/x86_64/trap.S:57-58`** — vectors 29 (#VC) and 30 (#SX) are declared
  no-error-code; AMD APM Vol. 2 says both push one, which shifts the whole
  trap frame by 8 bytes (and makes the entry `swapgs` decision read RFLAGS
  instead of CS). Not reachable under the pinned QEMU config.
- **[FIXED e6192a4] `arch/x86_64/gdt.c:141-147`** — CR4 is inherited from the bootloader;
  SMAP/SMEP are never put into a defined state, although
  `kernel/syscall/uaccess.c` and `panic.c:206` both depend on SMAP being off.
  Both are now explicitly CLEARED, and that is a decision: the probes, the
  copy routines and the panic dump's user RBP walk all dereference user
  addresses from ring 0, so enabling them belongs with STAC/CLAC annotations —
  a change of its own.
- **[FIXED e59e931] `kernel/syscall/entry.S:96`** — `NtContinue` accepts a non-canonical `Rip`;
  `iretq` then `#GP`s with kernel CS → panic. Choosing `iretq` over `sysret`
  correctly avoids the classic non-canonical-RCX hole, but IRET has its own.
  The answer is not a refusal: the oracle reports `STATUS_ACCESS_VIOLATION` to
  the thread, so `KiContinue` delivers that through the same path a real fault
  takes. Note the pin does NOT convict — the pinned QEMU under TCG models
  Intel's IRET, which does not canonical-check the target RIP on a return to
  CPL 3; AMD's does, so the halt is real on half the hardware this kernel
  targets and unreachable on the emulator available to test it.

---

## 9. Oracle divergences (gate G1) worth pinning

These are correctness bugs against the pinned Wine tree rather than safety
bugs, and each needs a `tests/ntapi/` pin before the fix (G5):

- **[FIXED 82bcc47] `kernel/ps/usermode.c:186-218`** — `KiContextToTrapFrame` ignores
  `CONTEXT.ContextFlags` entirely. The documented NT idiom
  (`ContextFlags = CONTEXT_INTEGER`, get, modify, set) overwrites `rip` and
  `rsp` with 0. Also drops `TF`, so user single-step is impossible, and
  `KiTrapFrameToContext` hard-sets `ContextFlags = CONTEXT_FULL` while leaving
  the segment registers zeroed. All three fixed; TF joins the preserved RFLAGS
  bits. NO boundary pin: for the self handle — the only one proskrnl
  implements — Wine's ntdll answers `NtGetContextThread` in USER mode without
  entering the kernel, so a `tests/ntapi` case measures ntdll on one leg and
  the kernel on the other. A draft was deleted rather than kept green by
  accident.
- **[FIXED 6999cde] `kernel/ke/wait.c:107-112`** — a pending alert is never consumed on the
  wake path, so one `NtAlertThread` satisfies two alertable waits (a `SleepEx`
  loop spins). At `:453-454`, `STATUS_USER_APC` clears `alerted` on both
  branches, silently destroying a pending alert. Both halves fixed: the wake
  IS the delivery (the bit is latched only when there is no wait to wake), and
  the alert is consumed only when `STATUS_ALERTED` is what is returned.
- **[FIXED 4fdcb31] `kernel/ke/wait.c:163,436`** — `WaitAll` abandonment returns
  `STATUS_ABANDONED_WAIT_0 + index`; the oracle
  (`third_party/wine/server/thread.c:1081-1092`) always returns bare
  `STATUS_ABANDONED_WAIT_0` for a wait-all.
- **[FIXED 9ddafd2] `kernel/cm/registry.c:1235`** — `NtEnumerateValueKey` returns
  `STATUS_BUFFER_TOO_SMALL` where the oracle has no such arm and always returns
  `STATUS_BUFFER_OVERFLOW`. Breaks the standard grow-and-retry loop.
- **[FIXED f93f0c9] `kernel/ob/handle.c:619-657`** — `NtQueryObject(ObjectNameInformation)`
  returns the leaf component, not the full path; the oracle walks
  `name->parent` to the root.
- **[FIXED f93f0c9] `kernel/ob/handle.c:416-430`** — `NtDuplicateObject` open-codes a *second*
  generic-access mapping instead of calling `ObpMapDesiredAccess`, and the two
  have already drifted: duplicating a keyed-event handle with `GENERIC_READ`
  grants wake rights the original correctly denied. Textbook G10.
- **[FIXED ecb1411] `fs/npfs/pipe.c:733,1101`** — message *read* mode is accepted on a byte-type
  pipe (the oracle refuses at both create and set-info), which then fabricates
  message framing at arbitrary quota boundaries.
- **[FIXED ecb1411] `fs/npfs/pipe.c:628`** — byte-mode peek returns `STATUS_BUFFER_OVERFLOW`
  whenever data remains; the oracle overflows only on *message* truncation, so
  the normal 1-byte `PeekNamedPipe` poll fails.
- **[NOT A BUG f6f8ebe] `kernel/io/rw.c` (whole file)** — byte-range locks are taken and
  tracked but **never enforced** on read/write; `IopLockConflicts` is
  referenced only inside `lock.c`, and the lock-bypass `key` argument is
  `(void)`-cast away. Not in `docs/03`. Verified against the pinned oracle by
  running it: a second handle reads AND writes straight across another
  handle's exclusive lock, both succeeding — wineserver's locks are Unix
  advisory locks that do not block the process holding them. NT does enforce,
  so this IS a deviation from NT and is now in `docs/03`, with
  `sem_file/byte_locks` pinning the agreement on both legs so a change in the
  oracle shows up before the kernel has to guess.
- **[FIXED 37b0e0e] `kernel/io/rw.c:501-515`** — scatter/gather silently ignores negative
  `ByteOffset`, so `NtWriteFileGather` with `FILE_WRITE_TO_END_OF_FILE`
  overwrites the *start* of the file instead of appending.
- **[FIXED d6fbd32] `kernel/se/sd.c:89-92`** — unknown ACE types are accepted with a comment
  saying "as the server's do"; wine's `acl_is_valid` ends with
  `default: return FALSE`. The access check then silently skips the ACE.
- **[FIXED d6fbd32] `kernel/se/sd.c:164-222`** — `SECURITY_DESCRIPTOR.Revision` is never
  checked, though the named oracle function checks it and
  `SECURITY_DESCRIPTOR_REVISION` is already generated in `abi/`.
- **[FIXED 9c5254a] `kernel/lib/rtl.c:93-94`** — `RtlCopyUnicodeString` never NUL-terminates,
  unlike the oracle. Latent (only a test calls it), but this is the shared
  authority other departments will reach for — `kernel/ob/handle.c:647` already
  hand-rolls its own terminator.
- **[FIXED 9ddafd2] `kernel/cm/registry.c:1040`** — `NtDeleteValueKey` doesn't round an odd
  name length to whole WCHARs while `NtQueryValueKey` does, so within proskrnl
  query and delete disagree about which names exist.

---

## 10. Information disclosure

- **[FIXED 77bac43] `kernel/se/token.c:639,677-682,715-736,948-954` (high)** —
  `BYTE reply[...]` is never zeroed, and structure padding pinned by
  `abi/ntseapi.h` is copied out verbatim: 4 bytes from `TOKEN_USER`, 4 + 4 per
  group from `TOKEN_GROUPS` (36 bytes with the boot token's 8 groups), 4 from
  `TOKEN_MANDATORY_LABEL` (which does not even need a valid handle). A
  repeatable kernel-stack oracle. `TokenStatistics` already memsets correctly —
  the pattern just was not applied to the variable-length classes. The reply
  buffer is zeroed ONCE for every class, so the property holds for classes
  nobody thought about and for ones added later.
- **[FIXED 54ffe24] `kernel/ob/namespace.c:874-885`** — `NtCreateSymbolicLinkObject` copies up
  to 64 KB from an unvalidated `Buffer`; pointing it at kernel memory and
  reading it back with `NtQuerySymbolicLinkObject` is a clean disclosure
  primitive.

---

## 11. Access checks that are missing or too weak

- **[FIXED d6813f2] `kernel/mm/section.c:526,553` (high)** — the section's creation protection
  is never consulted at map time (`section->pageProtection` is written and read
  nowhere). Open a file `FILE_READ_DATA`, create a `PAGE_READONLY` section,
  map it `PAGE_READWRITE` — and write to the file's page cache, which with
  immediate writeback (Art. 3) is a write to the file. NT returns
  `STATUS_SECTION_PROTECTION`. Both predictions are wrong against the
  operative oracle, and running it settled them: the gate is the backing FILE
  HANDLE's access, not the creation protection (Wine maps a `PAGE_READONLY`
  section over a read-WRITE handle as `PAGE_READWRITE` quite happily), and the
  refusal is `STATUS_ACCESS_DENIED`. Fixed to what the oracle does (Art. 6),
  pinned by `sem_mm/section_protect` across all four corners.
- **[FIXED 21d8264] `kernel/ps/job.c:226,241`** — `NtAssignProcessToJobObject` requires **zero**
  access on both handles, where NT requires `JOB_OBJECT_ASSIGN_PROCESS` and
  `PROCESS_SET_QUOTA | PROCESS_TERMINATE`. Gives termination without
  `PROCESS_TERMINATE` via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The file's own
  comment at `:124-126` records that a fuzzer found this exact class on
  `NtSetInformationJobObject`; the assign path was not fixed.
- **[FIXED ea2d4d1] `kernel/ps/thread.c:433,471`** — `NtCreateThreadEx` ignores `desiredAccess`
  and always grants `THREAD_ALL_ACCESS`; also ignores `objectAttributes` (so
  `OBJ_INHERIT` is dropped) and `stackSize` (hardcoded 1 MiB). All three
  honoured; the reserve follows the oracle's own flooring and rounding. The
  COMMIT is taken as a floor only, and the comment says why: this kernel grows
  a stack one page at a time off a single guard page, so a frame larger than
  the gap steps over it — honouring ntdll's own 4 KiB request literally
  crashed its threadpool threads, caught by `sem_port/ports`.
- **[PARTLY FIXED 77bac43] `kernel/io/ioctl.c:54`, `query.c:134,1077,1330`, `lock.c:141,215`** —
  `IopReferenceFileByHandle(handle, 0, ...)`: a zero-access handle can drive
  every ioctl/FSCTL, `NtLockFile`, and `NtSetVolumeInformationFile` — the last
  mutating the on-disk volume label through a `FILE_READ_ATTRIBUTES` handle.
  Only the last is a proskrnl bug, and it is fixed (`FILE_WRITE_DATA`); the
  oracle cannot arbitrate that one, since its `NtSetVolumeInformationFile` is
  a FIXME stub, so the requirement follows NT's rule for
  `IRP_MJ_SET_VOLUME_INFORMATION`. The others match the oracle, which also
  passes 0 (`server/file.c DECL_HANDLER(lock_file)`, the ioctl handler,
  `server_get_unix_fd(handle, 0, ...)` on the query paths), and are left
  alone deliberately.
- **[FIXED 77bac43] `fs/fat32/file.c:550`** — `FILE_DELETE_ON_CLOSE` bypasses the read-only
  check that `NtSetInformationFile(FileDispositionInformation)` correctly
  applies.
- **[FIXED 9e72e58] `kernel/cm/registry.c:891,967`** — the zero-access refusal tests the
  *unmapped* mask, so `NtOpenKey(&h, KEY_WOW64_64KEY, ...)` returns a
  usable-looking handle granting nothing, where the oracle denies.

---

## 12. Data-integrity issues in fs/fat32

Beyond the mount validation above:

- **[FIXED 5da2f01] `file.c:572` / `fat.h:71-73`** — a deleted file's FCB keeps its
  `(dirCluster, sfnSlot)` identity key while the slot is reusable, so a new file
  landing on that slot aliases the stale FCB (wrong `isDirectory`, wrong name,
  wrong cached size, stale page cache). `FatVfsRename`'s replace path can
  produce two live FCBs with the same key and thus the same `FatFileId`.
- **[FIXED 5da2f01] `dir.c:562-572`** — the exact-8.3 creation path never checks short-name
  uniqueness (`FatBuildExact83` accepts `~` and digits), so creating
  `AAAAAA~1.TXT` alongside an LFN whose generated short name is `AAAAAA~1TXT`
  produces two entries with identical 11-byte short names. `FatLookup` then
  returns whichever comes first — a plain wrong-file open.
- **[FIXED 5da2f01] `fat.c` (whole file)** — FSInfo is never read or written. Free-space
  reports from Windows and mtools are stale after proskrnl writes, and the
  deviation is not in `docs/03`. The free count is maintained at
  `FatSetFatEntry` — the single site that changes a FAT entry — and written
  back on allocation and chain release; a rescan per allocation was measurably
  too slow to boot with, which is why the count is incremental.
- **[FIXED 5da2f01] `dir.c:691-719`** — a directory can be created without its `.`/`..` entries
  if the first-sector RMW fails after the parent entry is already written; the
  result is enumerable, permanently corrupt, and has no FCB.
- **[FIXED 5da2f01] `file.c:189-193,230-234`** — `FatSetFileSize` error paths leave the chain
  and the on-disk metadata disagreeing; a failed shrink silently zero-fills on
  the next read.
- **[FIXED 5da2f01] `file.c:572`, `:515`, `fat.c:113-122`** — return values discarded where the
  failure is user-visible; `FatFreeChain` is `void` and drops every
  `FatSetFatEntry` error.

---

## 13. Registry durability (kernel/cm)

- **[FIXED 6043de4] `hive.c:94,114` (high)** — `CmpMeasureKey` / `CmpEmitKey` / `CmpFreeSubtree`
  recurse once per tree level on a 16 KiB pool-allocated kernel stack with **no
  guard page**. Nothing caps tree depth at create time. ~400 levels of
  `NtCreateKey` followed by any mutation runs the stack off its block and
  corrupts adjacent pool headers. The *parser* was capped
  (`CMP_HIVE_MAX_DEPTH`); the serializer and the free path were not.
- **[FIXED 6043de4] `hive.c:60,221` vs `registry.c:904` (high)** — and the asymmetry is worse
  than a crash: create depth is unlimited, load depth caps at 96, and
  `CmpLoadHive` treats any parse failure as "hive invalid" →
  `CmpFreeSubtree(CmpRootNode)`. A 100-deep key path saves successfully,
  reports durability, and **discards the entire registry at next boot**. That
  is not the bounded loss `docs/03` authorizes. `CMP_HIVE_MAX_DEPTH` is now
  the one number the create path, the serializer and the parser all use, so
  anything that saves also loads; `NtCreateKey` past it refuses with
  `STATUS_INVALID_PARAMETER`. The cap (96) is below NT's documented 512
  because the recursive serializer cannot afford 512 on a 16 KiB stack —
  recorded in `docs/03` with the exit named (make the walks iterative, do not
  raise the constant).

---

## What was done, in the order the findings argued for

The plan the review closed with; every item is done.

1. **A ring-0 fault fixup path** (§1b) — `8676fbb`. The highest-leverage
   single change, as predicted: it converts every *remaining* missing probe,
   and every one added by future code, from "machine halts" into
   `STATUS_ACCESS_VIOLATION`.
2. **The rest of §1a** — `54ffe24`: `NtQueryDirectoryFile`'s `mask` and the
   symbolic-link pair, all three through one shared
   `ObProbeUnicodeStringRead`.
3. **§2's remaining `ASSERT`-on-user-state sites** — `e0d7f7c`, `f696a9a`,
   `db7bc7d`, `e232a4f`, `94e5509`.
4. **§4's remaining untrusted-input paths** — `51ec994` (the FAT entry values
   and the cyclic-chain hang), `52777d1`, `1123446`, `eb56ea8`.
5. **Everything else**, each pinned in `tests/ntapi/` first where the oracle
   could answer (G5) — §3, §5, §7, §8, §9, §10, §11, §12, §13.

The themes the review asked to treat as policy:

- **Probes belong in the engine, not the service.** `ObProbeObjectAttributes`
  is layered on `ObProbeUnicodeStringRead`, so the four services that take a
  counted string outside an `OBJECT_ATTRIBUTES` reach the same authority. The
  general lesson held again this round: `ObpMapDesiredAccess`,
  `IopReferenceCompletionEvent`, `FatIsDataCluster`, `CmpKeyDepth`,
  `ObpFullNameLength` and `KiStringEqualsWithin` all exist because a second
  copy of an answer had drifted from the first.
- **`ASSERT` must never fire on user-controlled state.** Every §2 site is
  converted; `verify.c` reports instead of asserting, precisely because the
  TEB is memory ring 3 owns.
- **Size arithmetic on user-supplied lengths must be checked at the point of
  rounding.** Done at every §3 site.
- **A comment asserting a safety property was wrong in every case a reviewer
  checked it**, and that held for the second round too: `kernel/io/file.c`'s
  "close/cleanup run via the type hooks" was half true, `kernel/se/sd.c`'s
  "as the server's do" was the opposite of what the server does, and
  `kernel/ps/thread.c`'s "deletes the never-started thread" did not delete it.

One more, learned this round: **check the oracle before believing the
review**. Four findings were not proskrnl bugs and two predicted the oracle's
answer wrongly. Every one was settled by running the case, not by reading
either codebase.

### Test-harness issues found while fixing

None is a kernel bug; all three cost real time. **[FIXED 6aac2d1, ec19b25,
cefe1e3]**

- **`tests/run/run.sh` reports `PASS` when a test fails to compile** — the
  stale `.exe` from the previous build runs instead, so a broken test prints
  green. This happened four times during this work (an undeclared info-class
  constant, a `*/` inside a comment, a wrong enum name, a missing `util.h`
  include). It is the same silent-plausible-answer failure Art. 12 forbids in
  the kernel, in the harness that judges it.
- **And it did the same with the KERNEL.** The proskrnl legs built the image
  only when `build/proskrnl` was missing, and ignored `make`'s exit status
  besides — so a kernel that failed to compile, or simply was not rebuilt, had
  the previous binary's verdict reported as this one's. Both produced a false
  "pass" while convicting fixes in this round: once a reverted change was
  never compiled in, once a debug print was not.
- **`/dev/kvm` present but unusable** (e.g. an ephemeral container) makes
  `qemu.sh` select KVM and every test fail with an empty serial log, which
  reads as a mass kernel regression. The accelerator probe now ends with QEMU
  itself — start a halted, deviceless guest under kvm and see whether it
  survives — and falls back to tcg when it does not.
