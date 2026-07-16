# 14 — The ntapi test harness & the `todo_proskrnl` convention

This makes Article 5 (`docs/09`) and the verification strategy (`docs/08`) concrete. It
specifies the one piece of infrastructure that must exist *before* kernel code: a portable
test that runs on both an oracle and on proskrnl, and the bookkeeping that keeps the
proskrnl run **green-or-regression** while the boundary is still mostly unimplemented.

Nothing here depends on kernel code existing. The oracle side is buildable today; the
proskrnl side has a single clearly-marked seam that lights up at M4.

---

## The two build modes

One source file, two toolchains, selected by exactly one predefined macro:

| Macro | Artifact | `Nt*` come from | Headers (the contract) | Output | Verdict |
|---|---|---|---|---|---|
| `NTAPI_ORACLE` | Windows PE `.exe` | the host ntdll | Windows SDK / Wine (`winternl.h`) | `stdout` | process exit code |
| `NTAPI_PROSKRNL` | freestanding flat binary (M4+) | `tests/ntapi/syscall/` stubs | generated `abi/` | serial console | `isa-debug-exit` port |

The Makefile defines exactly one macro; a build that defines both or neither is an error.

**The header switch is itself a conformance check.** In oracle mode the test includes the
*oracle's* headers (the definition of truth); in proskrnl mode it includes generated `abi/`.
The same test compiling and passing against both means proskrnl's `abi/` layouts and
constants agree with the oracle — for free, at every test. This is why `ntapi` includes the
system headers in oracle mode rather than `abi/`: mixing them would hide exactly the drift
we want to catch.

**Why `ntapi` exists at all**, given Wine already ships `dlls/ntdll/tests/*`: those link the
full PE user-mode stack and cannot run until M7. `ntapi` is the *only* oracle that also runs
on the M1–M6 kernel (a flat binary issuing raw syscalls). At M7 Wine's own suite becomes the
richer conformance oracle (`docs/08`), and `ntapi` retires into the differential-fuzzer base
rather than a second suite to maintain.

---

## Harness API (`tests/ntapi/ntapi.h`)

Deliberately close to Wine's, so distilling `ok()`s out of Wine tests is near-mechanical:

- `START_TEST(name) { ... }` — declares a test binary's entry point.
- `ok(cond, fmt, ...)` — one assertion. Failures are counted and logged with `file:line`.
- `todo_proskrnl { ... }` — an in-source block whose assertions are *expected to fail on
  proskrnl but must pass on the oracle*. Semantics mirror Wine's `todo_wine`:
  - **oracle mode:** transparent — the block must pass like any other.
  - **proskrnl mode:** an `ok()` failure inside is **not** a test failure; an `ok()` that
    unexpectedly *passes* is reported as `todo succeeded` — a signal to delete the tag,
    because the behaviour now works and should be held to it.
- `skip(reason, fmt, ...)` — record and continue; for preconditions unavailable in a mode.

Every run ends by emitting a machine-greppable verdict line (`docs/08`):

```
[KTEST] <name> PASS
[KTEST] <name> FAIL failures=<n> todo_unexpected=<n>
```

and exits non-zero on failure (oracle) / writes the fail code to `isa-debug-exit`
(proskrnl). `tests/run/` greps these lines; nothing parses free-text.

### `todo_proskrnl` vs. the manifest — two granularities, on purpose

- **`todo_proskrnl` (in-source, fine-grained):** for a test that is *otherwise live* on
  proskrnl but has a known-not-yet-correct corner. Keeps the test running so its passing
  assertions guard against regression while the one corner is still red.
- **The manifest (coarse-grained):** selects which whole test binaries the proskrnl target
  even *builds and runs* this milestone. A test for an unimplemented syscall must not be in
  the manifest — otherwise the proskrnl binary would reference a syscall stub that traps (or
  fails to link). The manifest is what actually prevents "a sea of expected reds."

Rule of thumb: **not implemented at all → leave it out of the manifest. Implemented but one
corner wrong → in the manifest, wrap the corner in `todo_proskrnl`.**

---

## The manifest (`tests/ntapi/manifest.txt`)

Plain text, line-oriented, reviewable in a diff. One test path per line; `#` comments;
blank lines ignored. A line lists a test that is **expected to build, run, and pass on the
proskrnl target as of the current milestone** (modulo its `todo_proskrnl` blocks).

```
# tests/ntapi/manifest.txt
# Tests expected GREEN on the proskrnl target right now.
# Everything under tests/ntapi/ not listed here is oracle-only for this milestone.
# Adding a line is the last step of implementing an Nt*: it moves the test from
# "oracle-only spec" to "proskrnl must not regress this".

# --- M2: dispatcher objects (in-kernel; see note) ---
# (M2 tests run in-kernel via tests/kmt, not as ntapi user binaries — no lines yet.)

# --- M4: user mode + first syscalls ---
# sem_wait/notification_event      # NtCreateEvent/NtWaitForSingleObject/NtSetEvent
# sem_mm/reserve_commit            # NtAllocateVirtualMemory reserve then commit

# --- M6: file semantics ---
# sem_file/share_modes             # STATUS_SHARING_VIOLATION on conflicting share
```

The lines are commented out because **nothing is implemented yet** — the file ships with the
milestone map pre-drawn so that "implement `NtCreateEvent`" has an obvious final step:
uncomment `sem_wait/notification_event`. The oracle target ignores the manifest and runs
everything.

---

## The runner (`tests/run/run.sh`)

One entry point, two modes, same shape from M1 to the desktop (`docs/08`):

```
tests/run/run.sh oracle     # build+run every ntapi test on the host ntdll (Wine/Windows)
tests/run/run.sh proskrnl   # build the manifest subset into a disk image, run under QEMU
```

Both collect `[KTEST] … PASS/FAIL` lines and exit non-zero if any test fails or any
`todo_proskrnl` unexpectedly succeeded. `oracle` is the spec gate (must be all-green before
you may implement); `proskrnl` is the regression gate (must stay all-green as you go).

---

## Directory layout

```
tests/
  ntapi/
    ntapi.h              # the portable harness API (this doc)
    ntapi.c              # per-mode output + verdict; the M4 proskrnl seam
    manifest.txt         # which tests must be green on proskrnl now
    syscall/             # (M4) proskrnl-mode syscall stubs; empty until then
    sem_wait/            # dispatcher/wait semantics
    sem_mm/              # virtual memory semantics
    sem_file/            # file semantics
  run/
    run.sh               # oracle | proskrnl runner
```

---

## Workflow, end to end (one Nt*)

1. Find the behaviour in Wine's `dlls/ntdll/tests/*` (or Windows docs). Distil the relevant
   `ok()`s into a `tests/ntapi/<bucket>/<name>.c` using this harness.
2. `tests/run/run.sh oracle` → the new test is **green on the oracle**. It is now the
   executable spec. Commit it *before* kernel code (Article 5).
3. Implement the `Nt*` in the kernel until `tests/run/run.sh proskrnl` passes it. Wrap any
   still-wrong corner in `todo_proskrnl`.
4. Add the test's path to `manifest.txt`. From now on the proskrnl target guards it against
   regression. "Done" = this line is green (`docs/09` Art. 5), not the code compiling.
