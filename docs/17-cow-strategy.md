# 17 — Copy-on-Write Strategy

**Status: built at CUI-9.** Copy-on-write was *forbidden* by Article 3 ("no
copy-on-write" is a mandate, not a default — `docs/09-constitution.md`, T4 in
`docs/01-tradeoffs.md`) until the CUI-9 amendment (`docs/03` "CUI-9 COW notes"), taken
on the §2 measurement recorded in §1 — exactly the path this document existed to force:
amend on measured grounds, with the hazards enumerated up front rather than discovered
on serial. The document remains the spec and the record; §6's hazard D and F entries
carry their decisions.

It records: what the kernel does today, the only justification for COW that Article 3
accepts, why COW is *safer here than in an ordinary kernel*, why the real work is not
COW at all, the full hazard list, and the test plan — including the one failure mode
that passes every semantic test.

Companion documents: `docs/18-smp-strategy.md` — the two interact in exactly one place
(write-protect becomes a TLB-shootdown site) and both flag it — and
`docs/19-io-strategy.md`, which is independent of this one but shares its §8 failure mode
(a correct-but-inert implementation passes every semantic test).

---

## 1. What the kernel does today (measured, not remembered)

- **Every image view is a full private copy.** `MipMapImageView`
  (`kernel/mm/section.c:398`) is commented "a full private copy of the PE, relocated if
  the base differs", and the mapping loop says so plainly: *"everything is copied — no
  COW, no demand paging"* (`section.c:443`). Every process that maps `ntdll`,
  `kernelbase`, `user32`, `gdi32`, `ole32`, … gets its own byte-for-byte copy of each.
- **Relocations are applied into that private copy.** `MipRelocateImage`
  (`section.c:309`) fixes up the mapped copy after `MipCommitImageRange` has memcpy'd
  the raw bytes in (`section.c:393`). There is no relocated master anywhere.
- **The fault handler already has a write arm, and it is not the guard arm.** CUI-7's
  write-watch changed this: `MiHandleUserFault` (`kernel/mm/fault.c:24`) now takes
  `BOOLEAN writeAccess`, and a store into a present, protection-writable but clean
  watched page is resolved *before* the guard arm (`fault.c:36`). Anything neither arm
  claims is still `STATUS_ACCESS_VIOLATION` — the M4 containment path. There is still no
  demand paging: every committed page has a frame behind it before user mode can touch it.
- **Image sections do not touch the page cache.** `MiCreateSection`
  (`section.c:234`): *"Data sections map the file's cache; image sections read the raw
  module bytes directly and need no cache."* This single fact is what makes a scoped COW
  tractable — see §4.

**Measured (CUI-9 step 1 — the §2 deliverable).** At the `cui9` leg's pinned `MEM=512M`
console boot (`tests/run/run.sh cui9`, driving `tests/cui/mmceiling.c`), one minimal-CRT
resident process costs **≈ 5.9 MB** of physical memory — the mapped private image copies
of its DLL set *plus* each section's raw-byte pool snapshot (`IopBuildSectionBacking`
re-reads the whole file per `NtCreateSection`, a second per-process copy this document
had not counted) — and the machine **refuses at 70 resident processes** (available
memory 411 MB → 9 MB). The refusal ring 3 observes is the spawned child dying mid-load
with `STATUS_DLL_NOT_FOUND` (0xC0000135): the loader's dressing of the underlying
image-map `STATUS_NO_MEMORY`. That is the functional ceiling §2 predicts, measured.

**Re-measured at each CUI-9 instalment (same leg, same 512M — the §8 acceptance):**
masters alone moved the ceiling to **143** (2985 KB/process), releasing the snapshot to
**302** (1575 KB), the lazy COW arm to **319** (1500 KB) — 4.6× the baseline, with the
refusal now surfacing as plain `ERROR_NOT_ENOUGH_MEMORY` from process creation. The
`cui9` leg ratchets a committed floor (`tests/cui/mmceiling_floor.txt`), so a sharing
regression fails as a machine verdict, not a semantic test.

**Re-measured when the CUI boot became a desktop boot (the two-image change).** One image
now serves every leg, so there is one conhost and it links the real `user32`/`gdi32`
rather than CUI stand-ins — which means every boot brings the desktop stack up
(`win32u`, `winefb.drv`, `wineserver-lite`, a 1280x800 desktop surface) before the leg's
own work starts. At the same pinned 512M console boot, measured on the same host:

| | `main` (CUI conhost) | one image (desktop conhost) |
|---|---|---|
| available memory at sweep start | 466 MB | 334 MB |
| ceiling | 318 processes | 232 processes |
| **per resident process** | **1505 KB** | **1480 KB** |

The 132 MB is standing cost, not pressure — with no eviction (Art. 3) nothing works it
off, and it is identical on a virgin image and on one that has already firstbooted (both
334 MB), so it is what the boot LOADS, not residue the boot leaves. Sharing did not
regress: the per-process cost is what image-master sharing decides and it got slightly
better. The ceiling is a product of the two numbers and only reports their product, which
is why the floor alone read a baseline shift as a regression.

So the floor drops to 180 with the same ~78% margin it had, and the property it was
standing in for is pinned directly beside it: `tests/cui/mmceiling_perproc_kb.txt` caps
one resident process at 1600 KiB. A real sharing regression now fails on the number that
means sharing, whatever the baseline does; the floor stays as the functional-ceiling
statement §2 is about. The 132 MB itself is a live cost worth reclaiming — a CUI boot has
no desktop to look at — and the lever is conhost's import table, not the kernel: see
`docs/03-nt-deviations.md`.

## 2. The only justification Article 3 accepts

Article 3 forbids deviations justified by performance. `docs/03-nt-deviations.md`
currently dismisses COW with one line:

> **No COW initially** — private/image mappings copy fully on map. Costs RAM;
> unobservable.

**That claim is true at one process and false at some larger number.** Eager full copies
of the whole baked DLL set, per process, turn RAM into a *functional ceiling*: past some
process count, `NtCreateUserProcess` (or the loader's first section map) fails and the
failure surfaces to ring 3 as `STATUS_NO_MEMORY`. A ceiling a user-mode program can
observe is a semantic, not a performance concern — which is precisely the form Article 3
requires of a deviation.

There is a second cost with the same shape: **process creation time**. Every process pays
a `memcpy` of every DLL it maps (`MipCommitImageRange` → `MiCopyToUserRange`,
`section.c:393`), plus a full relocation pass when it is not at its preferred base. On the
paths that spawn processes in bulk — CUI-1's `rundll32` children, cmd.exe pipelines, a
build tool — that is the dominant cost of `NtCreateUserProcess`. It is weaker as a
constitutional argument (latency, not a ceiling), so lead with the ceiling; record this as
the secondary effect.

**Therefore the first deliverable is a measurement, not code:** how many MB does one
process's image set cost today, and at what process count does the machine refuse? The
CUI-1 firstboot path (a `wineboot` that spawns `rundll32` children) and the GUI legs
(multiple GUI processes since GUI-3) are the natural workloads to measure. With that
number the Article 3 amendment rests on data; without it the amendment is a performance
argument wearing a hat, and G3 rejects it.

This is the same shape as the SMP justification in `docs/18` (a verification argument,
not a speed argument). Neither is available by assertion.

## 3. Why COW is *safer here* than in an ordinary kernel

The other Article 3 mandates — the ones that make this kernel look thin — remove most
of what makes COW dangerous elsewhere:

| Ordinary-kernel hazard | Why it is absent here |
|---|---|
| TLB shootdown races on write-protect | **Uniprocessor.** A local `invlpg` suffices; no IPI, no cross-CPU window. (This changes the day `docs/18` lands — see §11.) |
| The fault path interleaving with an unmap or another fault | **No kernel preemption.** The fault path runs to completion. |
| The shared master being evicted mid-fault | **No eviction, immediate writeback.** Nothing pages out; the master cannot vanish. |
| COW colliding with the file cache and mapped-view coherence | **Image sections bypass the page cache entirely** (`section.c:234`). The one genuinely hard problem in Mm — mapped-view/`ReadFile` coherence, T4's "structurally trivial because everything looks at the same page-cache page" — is *untouched* by an image-only COW. |

The contract COW implements is also **observable from ring 3**, which means Articles 5
and 6 apply normally: write to a `PAGE_WRITECOPY` view, then assert that the file did
not change, that another mapper does not see the write, and that the private page
outlives the other mapper. All of that pins on the Wine oracle. This is the decisive
difference from SMP, where the failure mode is a race that no differential test can
convict (`docs/18` §3).

## 4. The real work is not COW

Because relocations are applied *into the private copy* (§1), naive COW shares nothing:
two processes' copies of `ntdll` differ wherever a fixup landed unless both are mapped
at the same base. `MipMapImageView` already distinguishes this case — `atBase` is true
when `image->preferredBase` was free (`section.c:427`) — and Wine's DLLs normally do get
their preferred base.

So the work decomposes, and the two halves have very different risk:

1. **A shared, already-relocated master, keyed on `(FCB, base)`** — mapped read-only
   into every view that matches the key. **This touches no fault path at all** and
   carries the large majority of the RAM win, because the pages that stay clean
   (`.text`, `.rdata`) are the bulk of a DLL.
2. **The COW fault itself** — a write fault on a master page allocates a private frame,
   copies, repoints the PTE, flushes. Roughly 200–300 lines.

**Land them as separate commits (G13).** Step 1 alone is a legitimate stopping point: until
step 2 exists, any *writable* page is copied eagerly exactly as today, and only
read-only pages share. Risk is bought in two instalments instead of one.

## 5. Scope: image sections only

**In scope:** `SEC_IMAGE` sections — the read-only-shared master plus COW on write.

**Out of scope for lazy COW:** `PAGE_WRITECOPY` on *file-backed data* sections. Data
sections map the file's cache (`section.c:234`), so a lazy copy there lands squarely on
mapped-view/`ReadFile` coherence — the one thing T4 bought outright and the one thing we
must not spend. Those views keep their M5 implementation instead: an **eager private
full copy at map time** (`section.c`, pinned oracle-green by `sem_mm/section_protect`
and `sem_mm/writecopy_query`) — a legal implementation of writecopy's observable
contract, never a silent promotion to shared `PAGE_READWRITE`. (An earlier revision of
this section said the class "refuses loudly"; the tree never shipped that — the eager
copy predates this document and is pinned.)

Anonymous (pagefile-backed) sections need no COW: there is no fork in NT, so there is no
second mapper to diverge from.

## 6. Hazards, worst first

### A. Kernel-side writes bypass the hardware — but the authority now exists

`MiCopyToUserRange` (`kernel/mm/virtual.c:738`), `MiCopyToUserRangeChecked`
(`virtual.c:812`) and `MiTranslateUserPage` walk the page tables and `memcpy` **straight
into the physical frame**. They never let the CPU evaluate the PTE's writable bit, so a
scheme that relies on write faults does not exist from their point of view — and there are
20-plus call sites (IOSB completion, APC delivery, PEB/TEB construction in
`kernel/ps/peb.c`, image mapping itself at `section.c:393`, …).

**CUI-7 already solved this shape**, for write-watch rather than for COW, and solved it the
way Article 11 requires — one authority, consulted by everyone:

```c
/* kernel/mm/virtual.c:872 */
/* Space-parameterized so the kernel's own user-memory writers (probe retry,
 * the cross-process checked copy) resolve through the SAME arm the ring-3
 * fault takes (Art. 11). */
BOOLEAN MiResolveWriteWatchFault(PMI_ADDRESS_SPACE space, uint64_t pageAddress)
```

Its three consumers are already wired:

- the ring-3 fault (`kernel/mm/fault.c:36`);
- `MiCopyToUserRangeChecked` — `NtWriteVirtualMemory`'s engine — which on a non-writable
  page calls the resolver and re-translates instead of reporting a short write
  (`virtual.c:830`);
- `KiProbeRange`, where the comment states the principle exactly: *"the probe IS the
  kernel's write intent, and it is the single chokepoint every service that writes a user
  buffer passes (Art. 11)"* (`kernel/syscall/uaccess.c:63-70`).

**So COW's job here is to add an arm to an existing authority, not to invent one** —
extend, never fork. That is a materially smaller and much better-understood task than this
document originally described, and it removes what was its single most likely omission
(fixing only the fault handler). What remains is genuine but narrow: the resolver's write-watch
arm *marks and opens the gate*, while a COW arm must *copy and re-point*, and the two must
compose on a page that is both watched and writecopy.

### B. The PTE's writable bit is an insufficient record — with precedent for the fix

`PAGE_READONLY` image pages and `PAGE_WRITECOPY` image pages are **both non-writable in
the PTE**. If the COW decision is taken by inspecting hardware state, a write to a
genuinely read-only page silently copies and succeeds — **a real access violation
disappears**, which is a boundary-semantics regression, not an internal one. (Conversely:
never satisfy a writecopy page by just setting the writable bit — that corrupts the shared
master for everyone.)

Again CUI-7 set the pattern: `MiResolveWriteWatchFault` consults `vad->pageProtect[index]`
and derives the hardware bits with `MiProtectToPteBits` (`virtual.c:94`), refusing when the
recorded protection is not writable — *"a real protection violation, or already open"*. The
per-page protection array is the authority; the PTE is a trigger and a cache of it. Follow
that, and hazard B is closed by construction rather than by care.

### C. NX / execute bits must survive the copy

Image pages carry `PAGE_EXECUTE_READ` / `PAGE_EXECUTE_WRITECOPY`. Rebuilding the PTE
after a copy from a generic `PAGE_READWRITE` either sets NX on a page that must execute
(instant, confusing crash) or grants W+X where the section did not. Both are visible
through `NtQueryVirtualMemory`; the first is visible by simply running the process.

### D. `NtQueryVirtualMemory` observes COW — decide, then pin

Real NT reports, for a `MEM_IMAGE` region: `AllocationProtect` =
`PAGE_EXECUTE_WRITECOPY`, and `Protect` = `PAGE_EXECUTE_WRITECOPY` **before** the first
write, `PAGE_EXECUTE_READWRITE` **after**. Because `RegionSize` spans only pages sharing
one protection, **writing a single page splits one region into three**. Wine's own tests
look at this shape.

`NtProtectVirtualMemory`'s returned old-protection value has the same exposure.

This must be a decision recorded in `docs/03`, pinned on the oracle if implemented and
documented as a deviation if not. Discovering it later means a winetest pair convicts us
after the fact.

**Decided at CUI-9 (docs/03 "CUI-9 COW notes"): pin the oracle, which has NO
transition.** The pinned Wine realizes writecopy silently through `MAP_PRIVATE` +
`PROT_WRITE`, so a store never reaches it and it keeps reporting the WRITECOPY flavour;
region splits never happen there. Diverging toward real NT's transition would turn a
green pair red (Art. 6). `sem_mm/writecopy_query` pins the shape; the kernel keeps the
recorded protection untouched across a COW copy — the shared/private state lives in the
VAD's per-page frame-ownership record.

### E. Failure atomicity

A COW fault that cannot allocate a frame must leave **no** intermediate state — in
particular it must never have made the master writable. Note that today's handler
deliberately warns and continues when a guard-page commit fails
(`kernel/mm/fault.c:78`, "Out of frames mid-growth: the touched page itself is usable,
so resume"). **That policy is wrong for COW**: continuing means the write lands in the
master. Decide the status now — NT raises `STATUS_IN_PAGE_ERROR` — and assert the
absence of the half-state.

### F. Master identity and lifetime

- **Key on the FCB, not the file object**: two independent opens of `ntdll.dll` must
  reach the same master.
- ~~**Include the base in the key**: a different base means different relocation fixups.
  Omitting the base lets a process at base X read pages relocated for base Y — a silent,
  non-local corruption, the worst bug available in this design.~~ **Measured and
  reversed.** The oracle relocates an image ONCE per mapping and gives every view the
  same bytes wherever it lands (`map_image_into_view`'s `delta = image_info->map_addr -
  image_info->base`, and the server's at-base test in
  `DECL_HANDLER(map_image_view)`); `sem_mm/map_image_offset.c` memcmps two views of one
  section on the pinned Wine and they are identical. So the key is the identity alone.
  **What survives is the sentence one step over**, and it is what makes that safe: the
  copy's stamped `ImageBase` must name the base it was relocated for, because
  `perform_relocations` (`dlls/ntdll/loader.c`) keys off that field to fix up a view
  that sits elsewhere. Corruption comes from a stamp that disagrees with the copy, not
  from a base that is absent from the key. `docs/03` "An image section is relocated
  once" carries the trade. The stamp is convicted by `tests/kmt/m5_section.c`
  `test_image_relocation`, which holds the preferred base so the copy MUST be
  relocated — at the preferred base the assertion is vacuous, because the file
  already holds the right value there.
- **`MipRelocateImage` is not idempotent.** The second mapper must not re-apply fixups.
- **The image file changing under a live section**: close this on the share-mode side
  (refuse the write) rather than by invalidating masters. The share-mode machinery
  already exists (M6).
- **Answer the G11 ownership audit explicitly**: who holds a reference to the master at
  each point, who frees it when the last matching view unmaps, and what happens if the
  owning process dies at the earliest legal moment (including mid-fault).

### G. Guard pages × writecopy — one more arm, and the order is already established

`MiHandleUserFault` is now a two-armed decision (write-watch, then guard, then access
violation), and CUI-7 already had to reason about the ordering — the write-watch arm is
placed first with the justification that *"the guard arm only ever sees not-present
pages"*. COW adds a third arm and inherits the same obligation: a page can be both
`PAGE_GUARD` and writecopy, NT consumes the guard first, and the *next* write triggers the
copy. Note the resolver already declines guard pages explicitly (`(protect & PAGE_GUARD)
!= 0` → FALSE), so the precedent to copy is right there. Fix the order and `ASSERT` it — a
classification silently collapsing arms is hazard B in another costume.

### H. The missing `invlpg`

Write-protecting a page (step 1's master mapping, and re-protecting after a copy)
requires flushing the stale TLB entry. A missed flush lets a writable cached translation
send the write **into the shared master**, corrupting other processes silently. Under a
uniprocessor kernel this is a local `invlpg` with no shootdown — genuinely easy — which
is exactly why it gets dropped: the code "looks done" once the PTE is rewritten.

**Caveat to verify before relying on the test loop:** QEMU TCG maintains its own softmmu
translation cache, and its tolerance for a missing `invlpg` is not necessarily real
hardware's. A missing flush may pass under QEMU and fail on metal. Treat "the QEMU legs
are green" as insufficient evidence here; assert the flush directly instead (§8).

### I. KASAN shadow

The freshly allocated private frame needs its shadow initialized like any other pool/page
allocation (`kernel/mm/kasan.c`).

### J. Practical: the IAT always dirties

The loader writes import addresses, so `.idata`/`.data` pages go private in essentially
every DLL in every process. Sharing is a `.text`/`.rdata` phenomenon. **Estimate the
expected sharing ratio before measuring**, or a correct implementation reads as a broken
one.

## 7. Interaction with the rest of the system

- **System process**: `MiHandleUserFault` already asserts `process !=
  PsInitialSystemProcess` — kernel pages are never COW. Keep that invariant.
- **Commit accounting**: a view backed by a shared master is still `MEM_COMMIT` with a
  frame behind every page; `NtQueryVirtualMemory`'s `State` must not change. Sharing is
  invisible to the commit model.
- **`\Device\Fb0`** implements `GetCache` and is mapped through the ordinary section path
  (GUI-1). Make sure a device-backed view cannot be classified writecopy.

## 8. Testability

The good news is that most of this is directly testable, at three levels.

| Level | What it convicts |
|---|---|
| In-kernel `[KTEST]` | the fault-classification table (PTE state × access kind → decision); the copy; refcount transitions; **the number of `invlpg` calls** — a counter turns hazard H into a unit test |
| Boundary, oracle-pinned (Art. 5) | `PAGE_WRITECOPY` write leaves the file unchanged; another mapper does not observe it; the private page survives the other mapper's unmap; a write to a `PAGE_READONLY` image page is still an access violation; `NtQueryVirtualMemory`'s Protect transition and region split (hazard D) |
| Existing regression net | `tests/ntapi/sem_mm/` — `section_stress.c`, `image_section.c`, `mapped_same.c`, `guard_pages.c`, `stack_growth.c`, and `file_coherence.c` (the M6 mapped-view/`ReadFile` stress) — plus the SEH test already guard every dangerous neighbour. They are oracle-green today, so a COW regression in any of them is immediately attributable. |

### The hazard-A tests already exist — as write-watch's

The previous revision of this document said no test in the tree had the shape "the kernel
writes into a page the CPU would have write-protected". **CUI-7 added exactly that**, for
write-watch. `tests/ntapi/sem_mm/write_watch.c` states it in its own header:

> *KERNEL-side writes mark too: `NtWriteVirtualMemory` into one's own watched page, and a
> syscall out-buffer (`NtQueryVirtualMemory`) placed [in one].*

So the two cases are already written, oracle-green, and pointed at the same resolver COW
will extend. They are the **template**, not work to invent:

1. `NtWriteVirtualMemory` into a writecopy image page must copy and complete.
2. A syscall whose output buffer lies in a writecopy page must succeed.
3. **The neighbour that write-watch does not have to pin**: both must still *fail* on a
   genuinely `PAGE_READONLY` page. That is hazard B's boundary case and it is the one new
   test of the three — write-watch never faces it, because a watched page's recorded
   protection is writable by definition.

Write them before the resolver arm, not after: they are the specification of what the new
arm must mean.

### Which tests gate which commit

§4 offers step 1 (shared master, no fault path) as a legitimate stopping point, so the plan
has to say what "done" means there or the option is not real:

- **Step 1** is gated by the sharing metric and the sweep below, plus the whole existing
  regression net staying green. No `PAGE_WRITECOPY` behaviour changes, so no new boundary
  pin is due.
- **Step 2** adds the three hazard-A cases (two of them cloned from
  `sem_mm/write_watch.c`), the `NtQueryVirtualMemory` protection transition (hazard D),
  and the `invlpg` counter.
- **Hazard E (failure atomicity) is only reachable by fault injection** — a knob that fails
  the frame allocation inside the COW fault. Without it, "never leaves the master writable
  in the out-of-frames path" is an assertion nobody has executed.

### The one failure mode no semantic test catches

**An implementation that copies everything eagerly — i.e. shares nothing — passes every
test above.** It is exactly today's behaviour, and today's behaviour is green. So the
*win* must be pinned as a machine verdict, not inferred:

- free-frame count (`kernel/mm/phys.c`) after launching N processes, asserted against a
  committed budget;
- and/or a master-hit counter (how many views bound to an existing master vs. built one).

Without this, "COW landed" is unfalsifiable. With it, the RAM argument of §2 stays true
over time instead of being a one-off measurement.

**The acceptance, though, is the ceiling itself.** §2 justifies the amendment on a process
count at which the machine refuses; the milestone is done when **that number moves** — the
same measurement re-run, with process counts that previously failed now completing. The
frame counter is a proxy for it and a good regression guard; the ceiling is the claim.

### Two more things the plan owes

- **The fuzzer.** A writecopy page has a state the op model cannot currently express:
  not-yet-copied versus copied. Under `docs/02`'s rule (widened at CUI-8 to cover new
  *states*, not only new `Nt*`) that is an op-model extension — a mapped image view plus
  writes and protection queries against it.
- **The winetest spine, and here it cuts the other way.** CUI-8 and CUI-10 add no observable
  answer, so their question is only "what unparks". COW *changes* one:
  `NtQueryVirtualMemory`'s `Protect` and `RegionSize` (hazard D). **It is the only one of
  the three that can make a currently-green winetest pair go red**, so the manifest must be
  re-run and the delta recorded either way.

### The highest-value single check

A debug-build sweep asserting: **no writable PTE anywhere points at a frame owned by a
shared master.** That one invariant catches hazard A (kernel-side write that skipped the
resolver), hazard B (writecopy satisfied by flipping the bit), hazard F (base-keying
mistake), and hazard H (stale writable translation, where the sweep is run after a
flush-eliding path). It is worth writing before the feature.

## 9. Guidance for LLM-driven implementation

Article 3 lumps COW together with SMP, eviction and fine-grained locking. That grouping
is defensible for the others and **weakest here**, for two reasons:

1. **The contract is observable**, so Articles 5 and 6 work normally: a COW bug is
   pinnable by a differential test. An SMP bug is not (`docs/18` §3).
2. **The hazards are enumerable** — §6 is a finite checklist, not an invariant that has
   to be invented across 27 kloc. The danger is omission, not conception.
3. **CUI-7 left a worked example of the hardest part.** Write-watch is the same problem in
   miniature: a page whose hardware writability is a lie, resolved through one authority
   that the fault path, the checked copy and the probe all consult, pinned by a test that
   includes the kernel-side writes. Point the task at `MiResolveWriteWatchFault` and
   `sem_mm/write_watch.c` before it writes a line.

The failure mode to plan around is therefore *dropping a listed item*, and the two that
still get dropped are **H** (the flush) and **F** (master ownership / base in the key) —
hazard A's omission is now much less likely, because the authority exists and not using it
is a visible choice rather than an oversight. Require the §8 sweep and counters as
deliverables rather than as follow-up.

`docs/12-llm-workflow.md` marks `mm/` as a dangerous region. That still holds — it argues
for the commit split below, not against the work.

## 10. Build order

This work is milestone **CUI-9** (`docs/02`), after CUI-8 (`docs/19`) and before CUI-10
(`docs/18`). It depends on neither of them; the order is a risk ordering, not a dependency.

1. **Measure** (§2): MB per process today; process count at refusal. No code.
2. **Amend**: an Article 3 / `docs/03` entry justified on the observable ceiling, plus
   the explicit scope of §5 and the `docs/03` decision on hazard D. Its own commit.
3. **Pin on the oracle** (Art. 5, before kernel code): the `PAGE_WRITECOPY` semantics and
   the `NtQueryVirtualMemory` shape from §8.
4. **Shared read-only master** keyed on `(FCB, base)` — no fault-path change — plus the
   sharing metric and the §8 sweep. Most of the win; a legitimate stopping point.
5. **The COW arm on `MiResolveWriteWatchFault`'s authority** (hazard A — extend, never
   fork), the added fault-classification arm and its ordering (G), NX preservation (C),
   failure atomicity (E), `invlpg` + its counter (H), KASAN shadow (I).
6. **Optionally** re-examine file-backed `PAGE_WRITECOPY` — only if a baked consumer
   convicts it, and only with the mapped-view coherence stress test as the gate.

## 11. Interaction with SMP (`docs/18`)

Under a uniprocessor kernel, write-protecting a page is a local `invlpg`. The moment
`docs/18`'s giant-lock SMP lands, **every write-protect in the COW path becomes a
TLB-shootdown site** — the hazard is a hardware cache, so the giant lock does not cover
it (`docs/18` §6b). Whichever feature lands second inherits the join:

- COW first, then SMP → the shootdown work must enumerate the COW protect sites.
- SMP first, then COW → the shootdown primitive already exists and COW calls it.

Neither ordering is wrong; both are cheaper than discovering the interaction from a
corrupted `.data` page.
