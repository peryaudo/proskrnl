# 08 — Verification

The deepest reason proskrnl is tractable: its boundary is **observable from an
unprivileged `.exe`**, so oracles exist. ReactOS could not do this at the driver boundary
because that boundary is unobservable. Verification strategy follows directly.

## The core asset: oracles

An oracle is anything that tells you the correct answer independently of your
implementation. proskrnl has an unusually good one:

- **Real Windows** — unfixed, high-value, but opaque.
- **Wine** — transparent, and **the operative oracle** (Art. 6): "approximate" only
  relative to real Windows, which is not what proskrnl runs. The boundary consumer is
  Wine's own PE stack, so Wine's observed behaviour *is* the contract — a divergence from
  the pinned `third_party/wine` is a proskrnl bug by definition, never a question to park.
- **proskrnl** — a *third* independent implementation: transparent, instrumentable,
  deterministic.

Any two agreeing pins the third. This is **triangulation**, and it is only possible
because the boundary is observable. Real Windows serves as the extra triangulation point
when Wine's own behaviour is unstable, not as an excuse to second-guess Wine.

## Tests are assets *before* the code exists

Writing the test first is not process purity — it is that the boundary is *observable*, so
the test is the executable spec, and writing it first stops the LLM from encoding what it
*built* instead of what NT *does*. Four things make this concrete.

**A portable harness.** `tests/ntapi/` is a thin, self-checking harness with its own minimal
`ok()`/`START_TEST` shim, deliberately built so the **same source** compiles two ways: as an
ordinary Windows `.exe` (runs on Windows and on Wine-on-Linux — the oracle) and as a
freestanding flat binary against proskrnl's pre-ntdll kernel (the M4 test client). This
portability is the whole reason `ntapi` exists apart from Wine's own tests, which link the
full PE user-mode stack and therefore cannot run on proskrnl until M7. `ntapi` is the only
oracle you can run against the M1–M6 kernel.

**Per-milestone, not up front.** Do not author the whole boundary suite before M1 and watch
it stay red for months — that gives the loop no gradient. For each milestone, write exactly
the cases for the `Nt*` it is about to implement, green them on the oracle first, then
implement until they are green on proskrnl. The buckets grow milestone by milestone:

- `sem_mm/` — reserve/commit behaviour, guard-page stack growth, (later) COW separation.
- `sem_file/` — share modes, info classes, async + APC completion.
- `sem_wait/` — wait-all/any, alertable waits, APC interruption of waits.

**Two run targets, one binary.** Every case runs green on the **oracle** target
(Wine/Windows) from the day it is written — that is the spec being executable ahead of the
code. The **proskrnl** target runs the same binaries on the kernel; a case whose divergence
is known and documented is gated in-source by `todo_proskrnl` (borrow Wine's own
`todo_wine` idea) so it is *tagged out*, never failing. So the proskrnl run is always
**green-or-real-regression**, and a red there always means something broke — the only way
red stays meaningful across a dozen milestones.

The one case that inverts this is a service the pinned Wine does not implement. An oracle
answering `STATUS_NOT_IMPLEMENTED` is unbuilt, not authoritative (Art. 12), and a gap in
Wine is not a gap in NT — so where Microsoft's own documentation fixes the behaviour, the
kernel builds it and the case is tagged `beyond_oracle`: skipped on the oracle, enforced on
proskrnl, with the comment naming the MS contract it is written against (Art. 5). It is the
mirror image of `todo_proskrnl` in every respect, including the discipline that the tag is
wrong wherever the oracle *can* answer.

**Contract-shaped tests first; boring surface can come after.** The bugs that kill this
project are wrong-*contract* bugs (e.g. signalling the event before writing the IOSB) —
memory-safe, no crash, invisible to sanitizers. For those (IOSB/event ordering, wait-all/any
+ APC interruption, share-mode + delete-on-close) the test *must* precede the kernel code, or
the implementation certifies its own mistake. For mechanical surface (info-class
field-filling) a test written just after is acceptable.

This test asset is **the single most important thing an LLM can be asked to produce** — it
is where the model is strongest (broad knowledge of Windows behaviour) and where the
project's life is decided. The harness API, the `todo_proskrnl` convention, and the
runner are specified concretely in **`docs/14-test-harness.md`** (and skeletoned in
`tests/`).

## Wine's test suite is our conformance suite

Wine's tests are a **third-party, Windows-verified, legally-clean** specification of the
boundary. The moment M7 lands Wine's ntdll, that suite becomes proskrnl's conformance
suite. `user32/tests/msg.c` is the GUI trophy — passing it means 30 years of message-order
compatibility hold on our kernel.

Since M10 this is live as **the winetest gate**: `tests/run/run.sh winetest` runs the
manifest (`tests/winetest/manifest.txt`) of every non-GUI `<test_exe>:<subtest>` pair from the
CUI modules (ntdll, kernel32, msvcrt, ucrtbase, programs/cmd) — standalone links of the
pinned tree's own test objects — and every pair must exit 0 under the oracle AND on
proskrnl. Mechanics + wrinkles: `docs/03` "M10 winetest notes".

`tests/ntapi/` is **not** retired at that point — and the differential fuzzer never
replaces it either. The three assets are complementary, permanently:

- **`ntapi`** pins contract-shaped behaviours as small, deterministic, first-class tests
  that run on the bare kernel via raw syscalls. It is also where every confirmed
  divergence — found by the fuzzer or by Wine's suite — gets distilled into a permanent
  regression test (Art. 6: only a differential test convicts, and the pin must outlive the
  fix).
- **The differential fuzzer** (next section, built on the same harness) explores the space
  *between* the hand-written cases; its findings flow back into `ntapi` as pins.
- **Wine's suite** adds third-party breadth through the full PE stack from M7 on.

Each catches what the others structurally cannot; none subsumes another, and all three are
maintained for the life of the project.

## Differential fuzzing (the hidden weapon)

Because the same harness runs on Windows/Wine and on proskrnl, a random `Nt*`-sequence
generator triangulates the two automatically:

```
generate random Nt* call sequence
  ├── run on the oracle (Wine/Windows)  -> normalized [FUZZ] trace
  └── run on proskrnl                   -> normalized [FUZZ] trace
difference == bug
```

This is triangulation, automated — and an ideal LLM task (mechanical oracle, explicit
failure, boring). It works *only* because the boundary is observable — the final dividend of
the boundary choice.

**Implemented at `tests/fuzz/` (a few hundred lines atop the `ntapi` harness); run it with
`tests/run/run.sh fuzz`.** It arrived after M5 — every prerequisite (the one-source/two-mode
harness, the generated syscall list, the deterministic serial-log verdict) exists from M4/M5,
so it need not wait for M7. One interpreter binary (`interp.c`), built in both `ntapi` modes,
executes a compact program blob and prints a *normalized* trace per call: never a raw handle
or address (those differ by ASLR/VA layout), only slot-occupancy flags and the contract
payload (statuses, previous-states, counts, info-class fields, lengths), and only on
`NT_SUCCESS` (output params are undefined on error). The op model is generated from the same
`tools/gen_syscalls.py` list that defines the syscall table, so each milestone's new `Nt*`
becomes fuzzable the day it lands, and generator and interpreter cannot drift. A Python driver
(`fuzz.py`) generates, builds both sides, diffs, and — on a divergence whose signature is not
already in the `known_divergences.txt` baseline — minimizes the program and emits a repro. Per
Art. 6 a new divergence is dispositioned by a `tests/ntapi/` conviction or a cited baseline
entry, never silence.

## The pointer-torture matrix (where the oracle has nothing to say)

Differential fuzzing above triangulates *semantics*, and it can only ask questions the
oracle can answer. Wine is not a kernel: it has no ring boundary, so there is no oracle
for "what should `NtQueryEvent` do when handed a kernel address" — and that quadrant is
where the largest defect class lives. The verdict rule has to change from **matches** to
**survives and refuses loudly**, and once it does, no oracle is needed at all: it is a
liveness property.

**Implemented at `tests/ntapi/syscall/ptr_torture.c`** (issue #32 A1), generated from
`tools/gen_syscalls.py`. The generator reads the pinned Wine's own prototypes for every
service in `IMPLEMENTED`, classifies each argument by *type spelling only* — pointer,
counted string, `OBJECT_ATTRIBUTES`, handle, scalar, information class, ring-3 callback —
and emits `tests/ntapi/syscall/torture_matrix.inc`. The test then calls **every** service
with each pointer argument set in turn to NULL, `0x1`, a kernel address, a non-canonical
address, a reserved-but-uncommitted page, a `PAGE_NOACCESS` page, a read-only page, the
last eight bytes of a page whose successor refuses, and the first address above the user
limit — plus, for the counted-string and attribute kinds, a *well-formed descriptor with
a hostile interior* (the shape a service walks into after validating the outside), and
for scalars the saturated lengths. It runs on proskrnl only; the oracle leg skips it,
because measuring a usermode library's behaviour on garbage is not evidence about the
kernel.

Three graders, and the first is the weakest: the test itself only sees that the call
returned and did not answer `STATUS_NOT_IMPLEMENTED` (Art. 12). **`uacheck.sh` is what
convicts a missing probe** — a service that reaches a user address with no live probe
behind it names itself on serial, and the recovery frame's `STATUS_ACCESS_VIOLATION`
(indistinguishable from a correct refusal) no longer hides it. The boot is the third: a
panic or a park takes the leg down. A1 generates the hostile calls; A3 grades them.

Why generated rather than written: the finding that prompted it was *"exactly one site
probes"* out of ~25 — an unwritten policy applied wherever someone remembered. A
hand-written suite is written by the same memory that missed the probes and has the same
holes in the same places. Table-driven from the syscall list, coverage is a property of
code generation exactly as `abi/` makes constant correctness one (G4), and **a service
added tomorrow is swept the day it lands**. Its first run convicted three ring-3-reachable
machine halts — two missing `OBJECT_ATTRIBUTES` probes (one of them behind a
previousMode elevation that switched every probe below it off) and one `&user->member`
address computation that is undefined before any probe can run, all three of them UBSan
traps, i.e. `#UD`, i.e. exactly the fault the service dispatcher's recovery frame cannot
convert into a status.

Three lists are printed by every run rather than kept quiet: services never called (they
terminate the caller, transfer control, or power the machine off), services swept with
invalid handles only (a live handle parks them), and **the ledger** — services whose
*ordinary* arguments already reach unbuilt code, so the sweep cannot get as far as a
hostile one. A ledger entry is a real latent defect this instrument found and did not fix;
removing one is what "fixed" looks like, and if the fix is wrong the sweep panics the
moment the entry comes off. Nothing may be parked there to make a run green.

Information-class arguments are the one thing the matrix deliberately holds still. A class
selects *which* body runs, so saturating it asks for a body that does not exist — the
answer to which is `STATUS_NOT_IMPLEMENTED`, a panic, on the first unbuilt class of the
first enum, with the remaining ~190 services never swept. The class space is a real
backlog and deserves its own instrument (a contract enumeration, issue #32's 2.1); it is
not a liveness sweep's job.

## The FAT on-disk format has its own oracles

The same triangulation principle applies below the `Nt*` boundary: the FAT32 volume the
kernel writes is an externally specified format with excellent independent implementations,
one of which (mtools) already builds every disk image. The FS test battery therefore never
lets the kernel grade its own homework:

- **`tests/run/fatcheck.sh`** runs after every disk-mutating boot (`make test`, the
  `run.sh` `proskrnl`/`persist`/`firstboot` legs): `fsck.fat -n` (dosfstools) on the
  dd-extracted partition, the invariant sweeper below, and mtools byte-compares — files
  the kernel wrote are extracted with `mcopy` and compared against host-side truth, and
  files the kernel only read (ntdll.dll, the baked test binaries) must come back
  byte-identical, which convicts corrupted *neighbors* no in-kernel readback can see
  (the kernel reads through its own cache and its own FAT code).
- **`tests/run/fatsweep.py`** pins the invariants specific to how `fs/fat32/` writes:
  FAT copies byte-identical (every entry write mirrors), no cross-linked clusters, chain
  length consistent with each dirent's size, no lost clusters, LFN runs
  ordered/complete/checksummed. The FSInfo free count is advisory by deviation
  (docs/03) — a stale count warns, a clobbered signature fails.

GPL tools serve as *test oracles* only; no code flows into the kernel (docs/11).

Three dedicated legs build on those two oracles (each one boot-plus-host-verdict,
the docs/08 QEMU-loop shape):

- **`run.sh fatinterop`** — the bidirectional interop battery, the FAT analog of the
  Wine oracle. The host bakes an adversarial corpus with mtools (LFN unit-boundary
  and 255-char names, 8.3/case classes, SFN-collision families, cluster/page-edge
  sizes, deep nesting, chains fragmented by deterministic host-side FAT surgery);
  the kernel enumerates, reads and checksums it all (`tests/kmt/fat_interop.c`),
  then writes a battery the host extracts and verifies. Every divergence in either
  direction of `dir.c`'s 8.3/LFN logic surfaces here; confirmed wrinkles are pinned
  as permanent corpus classes (Art. 6).
- **`run.sh fatstress`** — fixed-seed random churn against an in-kernel shadow model
  (`tests/kmt/fat_churn.c`, the `section_stress` precedent), across three mkfs
  geometries including page-size clusters and a near-full volume. The shadow
  advances from the PRNG alone, so boot 2 replays it dry and verifies the tree
  through a **cold** cache; the host then re-verifies the extraction by CRC.
- **`run.sh tornwrite`** — exhaustive power-loss testing. Art. 3's synchronous
  immediate-writeback I/O makes the block-write sequence deterministic and short;
  QEMU's blklogwrites driver records it, and `tests/run/tornreplay.py` replays
  every prefix onto a pristine partition, separating fatal corruption
  (cross-links, loops, a valid-magic hive that fails to parse) from the
  deterministic, fsck-repairable states the write orderings legitimately produce.

## Sanitizers: make silent corruption loud, not "find bugs"

Sanitizers do **not** catch the bugs that kill this project — those are *wrong-contract*
bugs (e.g. setting an event before writing the IOSB): memory-safe, no UB, no crash. Their
real value is turning silent corruption into an immediate, correctly-located failure, so
the LLM-driven loop (whose only eyes are the logs) does not chase a lie.

- **UBSan (trap mode)** — day one, one flag: `-fsanitize=undefined
  -fsanitize-trap=undefined`. No runtime lib; a violation traps and the M1 panic handler
  reports the site.
- **KASAN (minimal)** — ~1000 lines (shadow memory + `__asan_load/store` + pool redzones).
  Highest-return sanitizer because handle tables and object refcounts (LLM's favourite
  bug site) are exactly what it catches. Add around M3.
- **KMSAN / KCSAN** — skip. Too heavy; and KCSAN is made moot by T4 (uniprocessor + one
  lock ⇒ no data races to find).

## The strongest tools are not sanitizers

- **Invariant asserts** — highest value per line, and the only tool that catches
  *semantic* invariants a sanitizer cannot express:
  `ASSERT(!(iosb->Status == STATUS_PENDING && event_signaled));` These catch exactly the
  wrong-contract bugs. Have the LLM write many; it is good at this.
  The macro is real: **`ASSERT(exp)` in `kernel/init/panic.h`** — always compiled in
  (there is no free build), fatal through the panic path, printing the machine-greppable
  `[ASSERT] file:line: expr` verdict plus an rbp-chain stack trace (Art. 9: the dump is
  the debugger). **New kernel code states its invariants with `ASSERT` as it is written**
  — lock-held preconditions, state transitions, type tags, count/list agreement (see
  `kernel/ke/` and `kernel/lib/list.h` for the pattern). Per Art. 6, a firing assert
  *names a suspect*; only a differential test convicts.
- **Self-checking stress tests** — the only reliable guard for Mm consistency: N threads
  each write via mmap, read via `ReadFile`, write via `WriteFile`, read via mmap, verifying
  a known pattern every time. Mm consistency bugs surface *only* in this form — and
  reliably do.
- **The standing ABI-conformance probe** — `tests/boot/abi_probe.c`, a native PE run
  on every boot (`[KTEST] ABI`, kernel runner `KiRunAbiProbe`): cheap one-line checks of
  ring-3 *conventions* rather than features — entry `rsp ≡ 8 (mod 16)` and DF clear, the
  FXSAVE seed control words (on the first thread AND a created one), the mapped PE header
  claiming the base it actually got (forced through the relocation path by double-mapping
  ntdll), TEB ids agreeing with the `Nt*Information*` surface, per-thread guard-page
  growth published in that thread's `NT_TIB.StackLimit`, a nonzero stable
  `ProcessCookie`, `KUSER_SHARED_DATA` ticking, past absolute timeouts satisfying
  immediately. The probe's header also keeps the ledger of conventions that are real but
  unobservable today (user-callback dispatch, XSTATE, WOW64 selectors/TEB32, debugger and
  token conventions), each pinned to the milestone that must add its check. Unlike the milestone smoke
  clients it asserts contracts no current consumer may exercise yet: every historical
  convention bug of this class (entry alignment, double relocation, TEB/ETHREAD id
  mismatch, unserved cookie, absolute waits parked as interrupt-time) was cheap to state
  and stayed latent until a later Wine DLL consumed the convention. The probe makes such
  a regression name itself on the boot it happens, not milestones later.

## LLM-specific failure modes to defend against

1. **Plausible constants from memory.** The model emits `STATUS_*` values and info-class
   numbers confidently and *approximately* right — worse than wrong, because it hides.
   Defence: **generate all of `abi/`'s numeric values from Wine headers** (`tools/gen_abi.py`);
   never accept a hand-typed value.
2. **"Silencing" fixes.** Given a sanitizer report, the model often *hides* the symptom
   (adds a bounds check masking a logic error). Defence: **a sanitizer only names a
   suspect; only a passing differential test convicts.** "KASAN went quiet" is never a
   completion criterion; "the differential test is green" is.

## The QEMU loop (same shape from M1 to the desktop)

Everything normalizes to **non-interactive, finite-time, exit-code + log**:

```bash
timeout 60 qemu-system-x86_64 \
    -display none -serial stdio \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -drive file=build/proskrnl-test.hdd,if=virtio,format=raw \
    -no-reboot 2>&1 | tee build/serial.log
echo "exit: $?"
```

- **Limine boot image** — `build/proskrnl-test.hdd` is a FAT32 image with the Limine bootloader
  installed and the kernel (plus any test payload / FS) baked in by `tools/mkimage.sh`.
  Limine hands off in long mode, so there is no `-kernel` direct-load and no 32→64
  trampoline (ADR 0010).
- **ONE image, and the leg is a command-line flag.** There is exactly one test image and
  it carries every leg's payload; which leg a boot runs is `GUEST_LEG` on the QEMU command
  line, and which cases a sweep runs is `GUEST_SUBTESTS` — both published through fw_cfg
  as `HKLM\Hardware\qemu` values (`kernel/cm/registry.c`, HACK-006) and read by the
  session manager (`user/smss/session.c`). Two more flags of the same kind pick the
  arrangement rather than the leg: `GUEST_GUI` (does this boot have a desktop at all --
  `0` is CUI-only, where a user32 call that would create a window fails) and `GUEST_SERIAL`
  (on a boot that has one, keep the console on the serial transport). Whether explorer owns
  the desktop is NOT a flag: smss derives it from those and publishes it as `ShellBoot`,
  because as a flag of its own it was a third thing every caller had to remember.
  It used to be the other way round — a leg ran because its client .exe was baked on the
  volume — and that made *fourteen* images of one userland whose payload lists drifted
  apart, made two legs unable to share a bake, and made a FILTERED run yet another image
  whose file on disk recorded which subset had last been asked for.
- **isa-debug-exit** — the kernel writes a value to port 0xf4; QEMU exits with a derived
  code. In-kernel test verdicts reach the host as a process exit code.
- **timeout + -no-reboot** — hang, panic, and success all become finite-time processes
  with an exit code and a log. (Hangs are routine early; this is the safety net.)
- **structured log prefixes** — `[KTEST] name PASS` / `[PANIC] …` / `[ASSERT] file:line`.
  Keep machine-verdict output separate from human free-text. `tests/run/` greps these.
  A boot's verdict is one `PASS_RE` grep, and one grep names **one line** — so a suite that
  reports *after* the line `PASS_RE` names is reporting into the void. That is not
  hypothetical: `CUI8`, `CONDRV`, `PREVENTIVE` and `SCHED` all print after `M9 PASS`, and
  every `ok()` failure in them short of a panic turned no leg red. `tests/run/kmtcheck.sh`
  (in `make test`) closes it by reading *every* suite's verdict line — each must be present
  **and** PASS, so a suite that silently stopped running fails too, per the same rule the
  `all-green` job states: a verdict nobody reached must never read as one that passed. A new
  kmt suite is listed there in the commit that adds it, or it is ungated.
- **`[UACCESS]` — the unwind ledger** (issue #32 A3). The system service dispatcher's
  ring-0 fault recovery frame (`kernel/syscall/uaccess.h`) is a backstop for a missing or
  stale user-pointer probe, and it is also *camouflage*: before it existed a missing probe
  was a `[PANIC]` with a stack trace, impossible to miss; after it, the same missing probe
  is a silent `STATUS_ACCESS_VIOLATION` indistinguishable from a caller passing a bad
  pointer on purpose — i.e. from ordinary operation. So the kernel **counts** the unwinds
  it recovers from instead of only surviving them, naming each on serial with the service
  and the faulting rip (`tools/symbolize.py` resolves that rip in the `.sym.log` sidecar
  every leg writes). `tests/run/uacheck.sh` fails any leg carrying an unclaimed line; the
  one deliberate provoker tags its own (`KiArmFaultRecovery(..., TRUE)` in
  `tests/kmt/m4_usermode.c`, which also convicts the counting), and
  `git grep 'KiArmFaultRecovery(.*TRUE'` is the complete list of claims. Wired into
  `make test` and into every `tests/run/run.sh` leg at the dispatcher, so a new leg is
  swept without being enrolled. The fix for a red line is a probe at the named rip, never
  a wider recovery frame.
- **the boot console** (`kernel/init/bootvid.c`) — the same log, mirrored onto the Limine
  framebuffer from the second line of boot until `FbInitialize` hands the scanout to the
  GUI. Serial stays the machine channel and is written first, always: the mirror is for a
  human (or a `screendump`) watching a box with no serial wire, and it can never change
  what a verdict grep sees.

At M7+ the same mechanism promotes: user-mode test exes (ntapi / Wine tests) write results
to the console → condrv → its COM1 serial backend (HACK-004, `docs/10`) → host log; the
runner hits the exit device. At M9 the serial chardev becomes a socket/pty so the runner
can also *write* keystrokes into the guest (the 16550 is bidirectional) and grep the echo —
interactive-console tests without a display. For GUI, `screendump` extends the loop to
images. The loop's shape never changes — which is itself evidence the design is coherent.

GDB stub (`-s -S`) is available but *not* for the main loop (it's interactive); it's for a
human chasing a hard bug. Invest instead in the **panic handler** (register dump, stack
trace via forced frame pointers, last syscall) — under LLM-driven development, the panic
dump *is* the debugger.

**Symbols stay out of the kernel.** The dumps print raw hex; `tools/symbolize.py` resolves
them on the host against the build's DWARF (`build/proskrnl`, and each boot module's `.elf`
kept beside its `.bin`), so the kernel carries no symbol table and nothing has to be
looked up from inside the failure being reported. `tools/qemu.sh` writes the annotated copy
as a **sidecar** — `<log>.log` → `<log>.sym.log` — for *every* run, so a leg that discards
qemu.sh's stdout still ships symbols in its CI artifacts; verdict greps stay on the raw log,
and a missing `llvm-symbolizer` degrades to pass-through rather than to a failed run.

That degradation is silent by design, which is why the symbolizer has its own gate:
`tests/run/symcheck.sh` (in `make test`) asserts that the green boot's own dumps — the `#BP`
trap self-test and `crash.bin`'s contained access violation — still resolve to
`Name+0xoff (file:line)`. It convicts the one real coupling of the out-of-kernel design: the
script recognizes addresses by their *printed shape* (field width, kernel link base,
`PSP_IMAGE_BASE`, the `[USERFAULT]` block layout), and nothing else forces those to agree.

## The whole suite, locally: `make fulltest`

CI (`.github/workflows/test.yml`) is 26 legs over seven shards, and the shards exist
because a hosted runner has two cores and no KVM. A dev box has neither limitation, so
`make fulltest` (`tools/fulltest.sh`) runs **the same 26 legs** — same commands, same
environment, nothing lightened — as independent parallel units. The wall clock becomes the
*longest* leg instead of the sum of a shard's, and the question "would CI be green" is
answerable in minutes rather than in a push-and-wait.

One CI shard has no leg here: `style` runs `make format` on a clean checkout and demands
the tree come back byte-identical (docs/15). It cannot be a leg, because a fulltest view is
symlinks onto the working tree and a *fixer* run inside one would edit the real files
mid-run — which is also why `make format` belongs before `make fulltest`, never after. Its
G14 half, `blocking_frontier.py --check`, is a leg (`frontier`); the clang-format and
clang-tidy halves are the part a green fulltest does not answer for.

Everything about that speed-up is scheduling; the interesting part is the isolation it
needs. The legs were written to run one at a time and say so in the tree: each calls
`make -C $ROOT test-img-warm` (two makes in one build directory race over the same
objects, and that target BOOTS QEMU to warm the image), and legs copy the masters while a
neighbour's make may be rewriting them — a corrupt read for whoever is copying at that
moment. (Earlier this said `cui8` and `net` booted the master in place and that three legs
`rm -f`'d it. Both stopped being true when the images were unified: every leg copies, and
**nothing** boots a master — the invariant `test_image_virgin_copy` rests on.) Making every one of
those shared-nothing would be a rewrite of `tests/run/run.sh`, and a rewrite of the harness
is the last thing that should ride along with *making the harness faster*.

So the isolation is in the filesystem instead of in the tests. Each leg gets a **view**:
`build/fulltest/views/<leg>/`, whose entries are symlinks to this tree's (`kernel/`,
`tests/`, `third_party/`, `Makefile`, …) and whose `build/` is a real copy of the build
outputs, minus the disk images (every leg makes the one it boots) and minus the previous
run's logs, screendumps and wineprefixes (a stale artifact must not be reachable from a
fresh verdict; and run.sh's own comment forbids a *copied* wineprefix). A leg's `$ROOT`
resolves to its view, so its makes, images, serial logs and mutated disks are its own, and
`tests/run/run.sh` is untouched by any of it. The view's root is a real directory and only
its entries are links, which is what makes `$ROOT` come out as the view — `make_view()`
asserts that rather than trusting it, because if it ever stopped holding, every leg would
quietly be running in the real tree again.

Two knobs carry judgement rather than taste:

- **`-j` defaults to a quarter of the cores, not all of them.** Each leg is a single-vCPU
  guest, so the box could hold many more — but four legs measure the *machine* rather than
  the boundary (the oracle's `times` case reads the host idle counter; `cui8` asserts a park
  under a throttled disk; `procs` and `gui5con` have choreography with sleeps in it), and a
  box with every core saturated is a different machine. A quarter is where the two terms of
  the wall clock meet: on a 32-core KVM box the 26 legs are ~1089 s of work whose longest
  single leg is 114 s (`guiwtest`), and `-j8` lands the whole suite in **150 s** — no width
  can do better than ~120 s, and buying that last 20% with a saturated box would be paying
  in false reds.
- **`tests/run/run.sh prebuild`** builds the ~165 ntapi test `.exe`s once, fanned out,
  before the legs start. It is a build step and produces no verdict — it exists because the
  `proskrnl` leg builds them one at a time, and at ~1.2 s each that is three minutes on the
  leg's clock, paid again in every sandbox that needs them.

**Do not touch the tree while it runs.** The views symlink the sources, so an edit mid-run
reaches every leg at once — and that includes editing `run.sh` or `fulltest.sh` themselves,
where the shell re-reads a script whose byte offsets just moved underneath it. It is the
same rule a single hand-run leg has always had (a leg bakes its image from the live tree);
the fan-out only makes one careless save cost twenty-six verdicts instead of one.

What CI still has that `fulltest` does not is three things, and only the first is about
speed. **CI is a slower machine** — two cores, TCG, a virgin cache — so the failures it can
see that `fulltest` cannot are the ones settled by machine speed rather than by semantics,
which is exactly why the `msg` leg is advisory on PRs there. **CI tests the committed
tree**, `fulltest` the working one: a required file nobody `git add`ed is green in every leg
and red on CI (this tool's own script was that file, once), so the summary reports when the
tree is dirty. And **CI builds from nothing**, while the views copy this tree's incremental
`build/`, which hides a stale object or a missing Makefile dependency. Everything
*semantic*, `fulltest` has already answered — which is what makes it usable as the gate
before a merge rather than a preview of one.

## Detection loses to prevention

The final point. An implementer who cannot review the hardest code should rely on
prevention, not detection:

| bug class | detected by | erased by (constitution) |
|---|---|---|
| data race | KCSAN (heavy) | **uniprocessor + one lock** |
| COW miss | a clever test | **don't write COW** |
| eviction-race consistency | ~undetectable | **don't evict** |
| writeback window | ~undetectable | **immediate writeback** |

A bug that cannot exist needs no review. The constitution (T4, `docs/09`) is therefore the
most powerful verification tool in the repository.
