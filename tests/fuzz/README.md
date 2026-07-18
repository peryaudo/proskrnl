# tests/fuzz — the differential fuzzer

The "hidden weapon" of `docs/08-verification.md`. It generates random `Nt*`
call sequences, runs each on two independent implementations of the same
boundary — the Wine/Windows **oracle** and **proskrnl** — and treats any
divergence in the observable results as a bug:

```
generate random Nt* program (seed)
  ├── oracle   (mingw .exe under third_party/wine)  → [FUZZ] trace
  └── proskrnl (clang flat binary, Limine module)   → [FUZZ] trace
difference (after suppressions) == bug
```

It works only because the NT syscall boundary is observable from an
unprivileged binary (ADR 0002), and it is cheap because it rides the existing
`tests/ntapi` harness (`docs/14`): the interpreter is built in the same two
modes every ntapi test is.

## Why it works with only part of the surface implemented

The oracle implements a strict **superset** of proskrnl. The generator only
ever draws ops from proskrnl's implemented set (the op model is generated from
the same `tools/gen_syscalls.py` list that defines the syscall table), so every
program is valid on both sides — there is never an "oracle lacks this" case.
Each milestone that adds an `Nt*` adds one `FUZZ_OPS` entry in the same commit,
and the new call becomes fuzzable immediately. v1 covers the Ob surface (events,
mutants, semaphores, waits, handle ops, directories, symlinks); Mm and Io follow
as M6+ lands.

## Scope: the name-space levels

Generation has three name-space levels (`--names`):

- **`anon`** (default) — anonymous objects only. A clean, converging baseline
  that makes the fuzzer a green regression gate: the dispatcher-object +
  handle-table + wait/query core plus every anonymous create/close path.
- **`named`** — adds valid names (collisions, reopens, nesting, symbolic links).
- **`malformed`** — adds deliberately-bad names (empty, relative, missing dir,
  the root, a directory used as a leaf).

**Wine is the operative oracle (docs/09 Art. 6): a divergence from Wine is a
proskrnl bug.** The `named`/`malformed` modes were used to find and fix the
object-namespace corners — empty/`"\"` names, symbolic-link collision, reparse
targets, `OBJ_OPENIF` status, zero-access opens, non-directory path components,
link loops — now pinned by `tests/ntapi/sem_ob/namespace_errors`. What those two
modes still surface is the *adversarial* residue: the exact error code for
pathological symbolic-link graphs and the same name reused across incompatible
object types — inputs Wine's PE stack never produces and that do not minimize
below ~13 calls. That residue is a documented, deferred deviation
(`docs/03-nt-deviations.md`, "Adversarial namespace error classification"), not a
green-gate target, which is why the default stays `anon`. Run `--names named`
to explore it; treat its findings against that docs/03 entry.

## Running

```
tests/run/run.sh fuzz                      # default batch (64 programs × ≤32 calls, --names anon)
tests/run/run.sh fuzz --seed 7 --programs 256
tests/run/run.sh fuzz --names named        # exercise the object namespace (docs/03 residue)
tests/run/run.sh fuzz --replay build/tests/fuzz/repro/fuzz_<id>.blob
```

Or call `tests/fuzz/fuzz.py` directly (same options). A green run prints the
known divergences it hit (all baselined) and `0 NEW divergence(s)`, exit 0. A
**new** divergence — one whose `(NtName, oracle_status, proskrnl_status)`
signature is not in `known_divergences.txt` — is printed with context, then the
offending program is minimized by greedy call removal (preserving the signature)
and a re-runnable repro is written under `build/tests/fuzz/repro/`; exit 1.

Requires the full toolchain from `tools/setup_linux.sh` (mingw + pinned
`third_party/wine` for the oracle, clang/lld + pinned `third_party/qemu` for
proskrnl).

## How it stays deterministic and comparable

- **One interpreter, table-driven decode.** `interp.c` executes a compact
  program blob; the decode tables come from `gen/fuzz_model.h`, generated
  alongside `gen/fuzz_model.py` (which the Python generator reads) so encoder
  and decoder cannot drift. Only the per-op *execute* switch is hand-written.
- **No ABI constants in Python (G4).** Programs carry choice *indices*; the
  interpreter maps them to symbolic constants (`EVENT_ALL_ACCESS`, …) resolved
  per build mode by the ntapi header switch. Python only handles shapes.
- **Normalized traces.** A raw handle or address differs by ASLR/VA layout, so
  the trace never prints one — only slot-occupancy flags (`h3=1`) and the
  contract payload (statuses, previous-states, counts, info-class fields,
  `ReturnLength`s). Everything printed is meant to match bit-for-bit.
- **Deterministic execution.** Single-threaded; every wait is zero-timeout (no
  blocking); slots are closed between programs so named objects don't leak; no
  wild pointers in v1 (an asymmetric unprobed deref would kill the batch).

## The known-divergence baseline

`known_divergences.txt` is the set of root-divergence signatures the default
(`anon`) run is allowed to still show. The fuzzer ignores these and fails only
on a **new** signature, so the default is a green regression gate whose baseline
is a *visible, cited* list rather than a silence (docs/09 Art. 6 — a difference
merely hidden is not a difference fixed). Wine is the operative oracle, so every
entry is a proskrnl bug; a baseline line is a scheduling decision ("not fixed
yet"), never a verdict question. Removing a line turns that divergence back into
a hard failure, which is what you do when you fix it.

The `anon` baseline is currently **empty**: the default policy is at full parity
with Wine. (Its history: nine signatures fixed in the first follow-up —
MakeTemporaryObject's DELETE-access check, open-by-null-name status, and
NtReleaseSemaphore ordering — and eight namespace corners fixed in the second,
pinned by `tests/ntapi/sem_ob/namespace_errors`.) The `named`/`malformed` modes
are not baselined; their residual adversarial-namespace divergences are the
deferred deviation documented in `docs/03-nt-deviations.md`.

## Conviction (docs/09 Art. 6)

This tool *names a suspect* and hands over a minimized reproducer. A new
divergence is a proskrnl bug (Wine is the operative oracle): fix it now — pin
the Wine behaviour with a permanent `tests/ntapi/` case first (Art. 5), then
change the kernel — or, only if it cannot be fixed now, add the signature to
`known_divergences.txt` with a note so it stays a visible debt. Only a passing
differential test convicts.

## Verifying the fuzzer itself

Do these after any change to `interp.c`, the trace format, or the model:

1. **Canonical traces:** `tests/fuzz/fuzz.py --self-check` runs the same blob
   through the oracle twice and diffs. ASLR makes any leaked raw handle/address
   show up here immediately. Must be clean.
2. **Detection path:** the docs/03 "Generic access mapping" over-grant is a
   real divergence the fuzzer must catch. `--allow-avoid` includes the
   `GENERIC_*` access masks; a program that creates an object with `GENERIC_READ`
   and then issues a modify op on the handle diverges as
   `NtSetEvent oracle=c0000022 proskrnl=00000000` (Windows maps GENERIC_READ
   without MODIFY_STATE → ACCESS_DENIED; proskrnl over-grants → success). It is
   deliberately *not* in the baseline, so it reports as a NEW divergence. Craft
   it deterministically instead of waiting for it:
   ```
   python3 -c "import importlib.util as u; \
     m=u.module_from_spec(s:=u.spec_from_file_location('f','tests/fuzz/fuzz.py')); s.loader.exec_module(m); \
     open('build/tests/fuzz/detect.blob','wb').write(m.encode([(0,[(0,[0,6,0,0,0,0]),(2,[0,0])])]))"
   tests/run/run.sh fuzz --replay build/tests/fuzz/detect.blob   # -> NEW divergence, exit 1
   ```
3. **Mutation smoke (manual, scratch branch):** invert `NtSetEvent`'s
   previous-state in the kernel; a default batch must catch it and the minimizer
   shrink it to a handful of calls.
