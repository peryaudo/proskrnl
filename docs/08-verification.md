# 08 — Verification

The deepest reason proskrnl is tractable: its boundary is **observable from an
unprivileged `.exe`**, so oracles exist. ReactOS could not do this at the driver boundary
because that boundary is unobservable. Verification strategy follows directly.

## The core asset: oracles

An oracle is anything that tells you the correct answer independently of your
implementation. proskrnl has an unusually good one:

- **Real Windows** — unfixed, high-value, but opaque.
- **Wine** — transparent but approximate.
- **proskrnl** — a *third* independent implementation: transparent, instrumentable,
  deterministic.

Any two agreeing pins the third. This is **triangulation**, and it is only possible
because the boundary is observable.

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

**Two run targets, one manifest.** Every case runs green on the **oracle** target
(Wine/Windows) from the day it is written — that is the spec being executable ahead of the
code. The **proskrnl** target runs only the slice implemented so far, gated by a
`todo_proskrnl` manifest (borrow Wine's own `todo_wine` idea): a not-yet-implemented case is
*tagged out*, never failing. So the proskrnl run is always **green-or-real-regression**, and
a red there always means something broke — the only way red stays meaningful across a dozen
milestones.

**Contract-shaped tests first; boring surface can come after.** The bugs that kill this
project are wrong-*contract* bugs (e.g. signalling the event before writing the IOSB) —
memory-safe, no crash, invisible to sanitizers. For those (IOSB/event ordering, wait-all/any
+ APC interruption, share-mode + delete-on-close) the test *must* precede the kernel code, or
the implementation certifies its own mistake. For mechanical surface (info-class
field-filling) a test written just after is acceptable.

This test asset is **the single most important thing an LLM can be asked to produce** — it
is where the model is strongest (broad knowledge of Windows behaviour) and where the
project's life is decided. The harness API, the `todo_proskrnl` convention, the manifest,
and the runner are specified concretely in **`docs/14-test-harness.md`** (and skeletoned in
`tests/`).

## Wine's test suite is our conformance suite

Wine's tests are a **third-party, Windows-verified, legally-clean** specification of the
boundary. The moment M7 lands Wine's ntdll, that suite becomes proskrnl's conformance
suite. `user32/tests/msg.c` is the GUI trophy — passing it means 30 years of message-order
compatibility hold on our kernel.

At that point `tests/ntapi/` has served its purpose as the M1–M6 scaffold: Wine's suite is
the richer oracle, and `ntapi`'s portable harness lives on as the base for the differential
fuzzer below (already built — see the next section), not as a parallel suite to keep
maintaining.

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
    -drive file=build/proskrnl.hdd,if=virtio,format=raw \
    -no-reboot 2>&1 | tee build/serial.log
echo "exit: $?"
```

- **Limine boot image** — `build/proskrnl.hdd` is a FAT32 image with the Limine bootloader
  installed and the kernel (plus any test payload / FS) baked in by `tools/mkimage.sh`.
  Limine hands off in long mode, so there is no `-kernel` direct-load and no 32→64
  trampoline (ADR 0010).
- **isa-debug-exit** — the kernel writes a value to port 0xf4; QEMU exits with a derived
  code. In-kernel test verdicts reach the host as a process exit code.
- **timeout + -no-reboot** — hang, panic, and success all become finite-time processes
  with an exit code and a log. (Hangs are routine early; this is the safety net.)
- **structured log prefixes** — `[KTEST] name PASS` / `[PANIC] …` / `[ASSERT] file:line`.
  Keep machine-verdict output separate from human free-text. `tests/run/` greps these.

At M7+ the same mechanism promotes: user-mode test exes (ntapi / Wine tests) write results
to the console → condrv/virtio-console → host log; the runner hits the exit device. For
GUI, `screendump` extends the loop to images. The loop's shape never changes — which is
itself evidence the design is coherent.

GDB stub (`-s -S`) is available but *not* for the main loop (it's interactive); it's for a
human chasing a hard bug. Invest instead in the **panic handler** (register dump, stack
trace via forced frame pointers, last syscall) — under LLM-driven development, the panic
dump *is* the debugger.

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
