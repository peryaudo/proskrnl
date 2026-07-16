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

## Tests are assets *before* the code exists (M0b)

Write `tests/ntapi/` and make it green on **Linux + Wine (and Windows where possible)**
*before* the kernel implements the corresponding `Nt*`. This makes the specification
executable ahead of the implementation:

- `sem_mm/` — reserve/commit behaviour, guard-page stack growth, (later) COW separation.
- `sem_file/` — share modes, info classes, async + APC completion.
- `sem_wait/` — wait-all/any, alertable waits, APC interruption of waits.

When the kernel later implements these, "done" already has a definition, and triangulation
holds from the first commit. **This is the single most important thing an LLM can be asked
to produce** — it is where the model is strongest (broad knowledge of Windows behaviour)
and where the project's life is decided.

## Wine's test suite is our conformance suite

Wine's tests are a **third-party, Windows-verified, legally-clean** specification of the
boundary. The moment M7 lands Wine's ntdll, that suite becomes proskrnl's conformance
suite. `user32/tests/msg.c` is the GUI trophy — passing it means 30 years of message-order
compatibility hold on our kernel.

## Differential fuzzing (the hidden weapon)

Because the same `tests/ntapi/` binary runs on Windows and on proskrnl, add a random
`Nt*`-sequence generator:

```
generate random Nt* call sequence
  ├── run on real Windows  -> NTSTATUS list + output buffers
  └── run on proskrnl      -> NTSTATUS list + output buffers
difference == bug
```

This is triangulation, automated — and an ideal LLM task (mechanical oracle, explicit
failure, boring). Cost is just the generator (`tests/fuzz/`, a few hundred lines) atop the
existing `ntapi` harness; no syzkaller-scale build required. It works *only* because the
boundary is observable — the final dividend of the boundary choice.

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
    -kernel build/proskrnl \
    -drive file=build/disk.img,if=virtio,format=raw \
    -no-reboot 2>&1 | tee build/serial.log
echo "exit: $?"
```

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
