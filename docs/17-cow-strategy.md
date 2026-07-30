# 17 — Copy-on-Write Strategy

**Nothing in this document is built.** Copy-on-write is *forbidden* by Article 3 ("no
copy-on-write" is a mandate, not a default — `docs/09-constitution.md`, T4 in
`docs/01-tradeoffs.md`). This document exists so that if we ever amend that mandate we
do it on measured grounds, with the hazards enumerated up front rather than discovered
on serial.

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
  (`kernel/mm/section.c:382`) is commented "a full private copy of the PE, relocated if
  the base differs", and the mapping loop says so plainly: *"everything is copied — no
  COW, no demand paging"* (`section.c:427`). Every process that maps `ntdll`,
  `kernelbase`, `user32`, `gdi32`, `ole32`, … gets its own byte-for-byte copy of each.
- **Relocations are applied into that private copy.** `MipRelocateImage`
  (`section.c:306`) fixes up the mapped copy after `MipCommitImageRange` has memcpy'd
  the raw bytes in. There is no relocated master anywhere.
- **The user fault handler is 82 lines and handles exactly one case.**
  `MiHandleUserFault` (`kernel/mm/fault.c:24`) clears a guard page and grows the
  faulting thread's stack. Anything that is not a guard page returns
  `STATUS_ACCESS_VIOLATION` — the M4 containment path. There is no demand paging: every
  committed page has a frame behind it before user mode can touch it.
- **Image sections do not touch the page cache.** `MiCreateSection`
  (`section.c:231`): *"Data sections map the file's cache; image sections read the raw
  module bytes directly and need no cache."* This single fact is what makes a scoped COW
  tractable — see §4.

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
`section.c:377`), plus a full relocation pass when it is not at its preferred base. On the
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
| COW colliding with the file cache and mapped-view coherence | **Image sections bypass the page cache entirely** (`section.c:231`). The one genuinely hard problem in Mm — mapped-view/`ReadFile` coherence, T4's "structurally trivial because everything looks at the same page-cache page" — is *untouched* by an image-only COW. |

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
when `image->preferredBase` was free (`section.c:411`) — and Wine's DLLs normally do get
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

**Out of scope for the first implementation:** `PAGE_WRITECOPY` on *file-backed data*
sections. Data sections map the file's cache (`section.c:231`), so writecopy there lands
squarely on mapped-view/`ReadFile` coherence — the one thing T4 bought outright and the
one thing we must not spend. Until a baked consumer convicts it, the class **refuses
loudly** per G12: no plausible no-op, no silent promotion to `PAGE_READWRITE`.

Anonymous (pagefile-backed) sections need no COW: there is no fork in NT, so there is no
second mapper to diverge from.

## 6. Hazards, worst first

### A. Kernel-side writes bypass COW entirely — the structural trap

`MiCopyToUserRange` (`kernel/mm/virtual.c:619`), `MiCopyToUserRangeChecked`
(`virtual.c:693`) and `MiTranslateUserPage` walk the page tables and `memcpy` **straight
into the physical frame**. They never let the CPU evaluate the PTE's writable bit.
A COW scheme that relies on write faults therefore **does not exist** from their point of
view, and there are 20-plus call sites (IOSB completion, APC delivery, PEB/TEB
construction in `kernel/ps/peb.c`, image mapping itself at `section.c:377`, …).

Two concrete, checkable breakages:

```c
/* kernel/mm/virtual.c:693 — NtWriteVirtualMemory's engine */
if (frame == 0 || !present || !writable) { break; }   /* a COW page stops the copy */
```
`NtWriteVirtualMemory` into a writecopy page would report a **short write**. Real NT
faults, copies, and completes.

```c
/* kernel/syscall/uaccess.c:44 — KiProbeRange */
if (... || (forWrite && !writable)) { return STATUS_ACCESS_VIOLATION; }
```
A syscall whose **output buffer** lies in a writecopy page would fail with
`STATUS_ACCESS_VIOLATION`. Real NT succeeds.

**Required shape (Article 11, one authority):** exactly one function decides "resolve
this VA for write, performing the copy if the page is COW, and return a writable frame."
The fault path and the `uaccess`/copy paths both go through it. Nothing else may
interpret the writable bit. An implementation that fixes only `MiHandleUserFault` is
wrong, and this is the single most likely thing to be missed.

### B. The PTE's writable bit is an insufficient record

`PAGE_READONLY` image pages and `PAGE_WRITECOPY` image pages are **both non-writable in
the PTE**. If the COW decision is taken by inspecting hardware state, a write to a
genuinely read-only page silently copies and succeeds — **a real access violation
disappears**, which is a boundary-semantics regression, not an internal one. The
writecopy attribute must live in the VAD / section bookkeeping, and the PTE is only a
trigger. (Conversely: never satisfy a writecopy page by just setting the writable bit —
that corrupts the shared master for everyone.)

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

### E. Failure atomicity

A COW fault that cannot allocate a frame must leave **no** intermediate state — in
particular it must never have made the master writable. Note that today's handler
deliberately warns and continues when a guard-page commit fails
(`kernel/mm/fault.c:69`, "Out of frames mid-growth: the touched page itself is usable,
so resume"). **That policy is wrong for COW**: continuing means the write lands in the
master. Decide the status now — NT raises `STATUS_IN_PAGE_ERROR` — and assert the
absence of the half-state.

### F. Master identity and lifetime

- **Key on the FCB, not the file object**: two independent opens of `ntdll.dll` must
  reach the same master.
- **Include the base in the key**: a different base means different relocation fixups.
  Omitting the base lets a process at base X read pages relocated for base Y — a silent,
  non-local corruption, the worst bug available in this design.
- **`MipRelocateImage` is not idempotent.** The second mapper must not re-apply fixups.
- **The image file changing under a live section**: close this on the share-mode side
  (refuse the write) rather than by invalidating masters. The share-mode machinery
  already exists (M6).
- **Answer the G11 ownership audit explicitly**: who holds a reference to the master at
  each point, who frees it when the last matching view unmaps, and what happens if the
  owning process dies at the earliest legal moment (including mid-fault).

### G. Guard pages × writecopy — fault classification becomes three-valued

Today `MiHandleUserFault` is a two-valued decision: guard page, or access violation. A
page can be both `PAGE_GUARD` and writecopy. NT consumes the guard first; the *next*
write then triggers the copy. Fix the order, and `ASSERT` it — a three-way classification
silently collapsing to two is hazard B in another costume.

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

### The one failure mode no semantic test catches

**An implementation that copies everything eagerly — i.e. shares nothing — passes every
test above.** It is exactly today's behaviour, and today's behaviour is green. So the
*win* must be pinned as a machine verdict, not inferred:

- free-frame count (`kernel/mm/phys.c`) after launching N processes, asserted against a
  committed budget;
- and/or a master-hit counter (how many views bound to an existing master vs. built one).

Without this, "COW landed" is unfalsifiable. With it, the RAM argument of §2 stays true
over time instead of being a one-off measurement.

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

The failure mode to plan around is therefore *dropping a listed item*, and the three
that get dropped are: **A** (fixing only the fault handler), **H** (the flush), and **F**
(master ownership / base in the key). Name them in the task, and require the §8 sweep and
counters as deliverables rather than as follow-up.

`docs/12-llm-workflow.md` marks `mm/` as a dangerous region. That still holds — it argues
for the commit split below, not against the work.

## 10. Build order

1. **Measure** (§2): MB per process today; process count at refusal. No code.
2. **Amend**: an Article 3 / `docs/03` entry justified on the observable ceiling, plus
   the explicit scope of §5 and the `docs/03` decision on hazard D. Its own commit.
3. **Pin on the oracle** (Art. 5, before kernel code): the `PAGE_WRITECOPY` semantics and
   the `NtQueryVirtualMemory` shape from §8.
4. **Shared read-only master** keyed on `(FCB, base)` — no fault-path change — plus the
   sharing metric and the §8 sweep. Most of the win; a legitimate stopping point.
5. **The COW fault**: the single write-resolution authority (hazard A), three-valued
   classification (G), NX preservation (C), failure atomicity (E), `invlpg` + its counter
   (H), KASAN shadow (I).
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
