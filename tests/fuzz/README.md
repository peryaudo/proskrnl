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

The dispatcher-object + handle-table + wait/query core is where proskrnl and
Wine already agree. The object *namespace* is not: proskrnl and Wine map
malformed / nested / colliding paths to *different error statuses*
(`OBJECT_NAME_INVALID` vs `INVALID_PARAMETER` vs `PATH_SYNTAX_BAD` vs
`PATH_NOT_FOUND` vs `ACCESS_DENIED`), and which matches real Windows is not yet
verified — docs/08 calls Wine an *approximate* oracle, so that space needs a
real-Windows triage, not a guess. So generation has three levels (`--names`):

- **`anon`** (default) — anonymous objects only. A clean, converging baseline
  that makes the fuzzer a green regression gate today.
- **`named`** — adds valid names (collisions, reopens, nesting).
- **`malformed`** — adds deliberately-bad names (empty, relative, missing dir,
  the root, a directory used as a leaf).

`named` and `malformed` surface the namespace error-status backlog on purpose;
those runs are exploration to triage, not a gate, and are **not** baselined.

## Running

```
tests/run/run.sh fuzz                      # default batch (64 programs × ≤32 calls, --names anon)
tests/run/run.sh fuzz --seed 7 --programs 256
tests/run/run.sh fuzz --names named        # explore the namespace backlog
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

`known_divergences.txt` is the set of root-divergence signatures already known
and documented — proskrnl-vs-Wine differences awaiting disposition. The fuzzer
ignores these and fails only on a **new** signature, so the default run is a
green regression gate whose baseline is a *visible, cited backlog* rather than a
silence (docs/09 Art. 6 — a difference merely hidden is not a difference fixed).
Every line carries a note; removing a line turns that divergence back into a hard
failure, which is what you do once it is fixed or convicted. The `anon` baseline
ships with 9 signatures (MakeTemporaryObject's DELETE-access check, open-by-
null-name status classification, and NtReleaseSemaphore's validation ordering).

## Conviction (docs/09 Art. 6)

This tool *names a suspect* and hands over a minimized reproducer. A new
divergence is dispositioned one of two ways: (a) curate a permanent
`tests/ntapi/` regression test with the oracle-observed values as the expected
side and add it to `tests/ntapi/manifest.txt` — the conviction; or (b) if it is
a proskrnl-vs-Wine difference pending a real-Windows check, add the signature to
`known_divergences.txt` with a note. Only a passing differential test convicts.

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
