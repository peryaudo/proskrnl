# 14 — The ntapi test harness & the `todo_proskrnl` / `beyond_oracle` conventions

This makes Article 5 (`docs/09`) and the verification strategy (`docs/08`) concrete. It
specifies the one piece of infrastructure every boundary behaviour passes through: a test
that runs **as the same binary** on the Wine oracle and on proskrnl, and the bookkeeping
that keeps the proskrnl run green-or-regression.

> History: through M9 the harness had *two build modes* — an `NTAPI_ORACLE` mingw `.exe`
> and an `NTAPI_PROSKRNL` freestanding flat binary over generated syscall stubs, with a
> `manifest.txt` selecting the proskrnl subset. Once the kernel ran the unmodified Wine PE
> userland (M7–M9) the flat binary was an anachronism that forced a bogus "oracle-only"
> class (threads, APC delivery, vectored handlers, Win32 file APIs). Both modes were
> consolidated into the single binary described here; the manifest is gone — proskrnl runs
> **everything**.

---

## One binary, two runners

Every test is one mingw-built Windows PE `.exe`: `<test>.c` + `tests/ntapi/ntapi.c`,
compiled against the **system NT headers** (`winternl.h` — the oracle's contract, never
`abi/`), built `-nostdlib` (no CRT; entry `ntapi_start` in `ntapi.c`), and linked against
the **pinned Wine import libraries** (`ntdll` + `kernel32` + `kernelbase`). Import
libraries bind by DLL name, so the same bytes resolve against Wine's DLLs under the oracle
and against the baked `C:\windows\system32` DLLs on proskrnl.

| Runner | How the test runs | Output | Verdict |
|---|---|---|---|
| **oracle** | under the pinned `third_party/wine` | `NtWriteFile(hStdOutput)` | `[KTEST]` line + exit code |
| **proskrnl** | baked at `C:\ntapi\<name>.exe`; the kernel's ntapi runner (`kernel/init/main.c`) sweeps the directory and runs each `.exe` console-less | `NtDisplayString` → serial log | `[KTEST]` line + exit code |

**Which side the binary landed on is probed at run time,** not compiled in: the proskrnl
runner launches tests without a console, so *no std output handle* means proskrnl. That
probe is a **runner contract** (both runners are ours), not an OS sniff — proskrnl's
PEB/KUSER_SHARED_DATA deliberately mimic Windows 10 (Art. 1), so version fields could
never discriminate. The probe selects the output sink and drives `todo_proskrnl`.

**Compiling against the system headers is itself a conformance check.** The kernel's
`abi/` headers are generated from the pinned Wine tree (Art. 4); the tests never include
them. The same binary passing on both sides proves the kernel's generated contract agrees
with the oracle's headers — at every test, for free.

**Why `ntapi` exists at all**, given Wine already ships `dlls/ntdll/tests/*`: those link
the full CRT and test far more than the `Nt*` boundary. `ntapi` stays a permanently
maintained first-class suite: it is small enough to run on every change, and it is where
every confirmed divergence — whether found by the differential fuzzer or by Wine's suite —
is pinned as a deterministic regression test (Art. 6).

The `ntapi` harness is also the base the **differential fuzzer** (`tests/fuzz/`,
`docs/08`) is built on: its interpreter is one more single-binary ntapi client (baked at
`C:\ntapi\interp.exe` on the fuzz image), and its op model is generated from the same
`tools/gen_syscalls.py` list.

---

## Harness API (`tests/ntapi/ntapi.h`)

Deliberately close to Wine's, so distilling `ok()`s out of Wine tests is near-mechanical:

- `START_TEST(name) { ... }` — declares the test body; `ntapi.c`'s `ntapi_start` entry
  probes the runner side and calls it.
- `ok(cond, fmt, ...)` — one assertion. Failures are counted and logged with `file:line`.
- `todo_proskrnl { ... }` — an in-source block whose assertions are *expected to fail on
  proskrnl but must pass on the oracle* — for a **known, documented divergence**
  (`docs/03`). Semantics mirror Wine's `todo_wine`, decided by the runtime side probe:
  - **on the oracle:** transparent — the block must pass like any other.
  - **on proskrnl:** an `ok()` failure inside is **not** a test failure; an `ok()` that
    unexpectedly *passes* is reported as `todo succeeded` — a signal to delete the tag,
    because the behaviour now works and should be held to it.
- `beyond_oracle { ... }` — the exact inverse: assertions the **oracle cannot answer** but
  proskrnl must, for a service the pinned Wine does not implement.
  - **on the oracle:** skipped (counted, printed once) — a Wine `STATUS_NOT_IMPLEMENTED`
    is unbuilt, never authoritative (Art. 12), so there is no verdict to take from it.
  - **on proskrnl:** transparent — the block must pass.

  The block's comment names the Microsoft documentation the behaviour is written against;
  that citation is the tag's whole authority, standing in for the oracle's green run
  (Art. 5, G5 — the same discipline G8 imposes on a hand-typed constant). It is wrong
  wherever Wine *does* implement the case: there the oracle is the spec (Art. 6) and the
  tag would be fixing the test instead of the kernel.
- `skip(reason, fmt, ...)` — record and continue; for unavailable preconditions.

`ntapi.c` also carries the freestanding pieces a CRT would otherwise provide (`mem*`,
`strcat`, a tiny `vsnprintf`, `__main`) — tests may use `memcmp`/`memset` freely but
nothing else from libc.

Every run ends by emitting a machine-greppable verdict line (`docs/08`):

```
[KTEST] <name> PASS
[KTEST] <name> FAIL failures=<n> todo_unexpected=<n>
```

and exits through `NtTerminateProcess` with that verdict as the exit code. `tests/run/`
and the kernel runner grep/check these; nothing parses free-text.

---

## The runner (`tests/run/run.sh`)

One entry point, the same shape from M1 to the desktop (`docs/08`):

```
tests/run/run.sh oracle     # run every test .exe under the pinned Wine (the SPEC gate)
tests/run/run.sh proskrnl   # bake the same .exes into a disk image, boot QEMU (the REGRESSION gate)
tests/run/run.sh winetest   # the M10 stretch gate: the curated CUI subset of Wine's OWN
                            # test suite (tests/winetest/manifest.txt), oracle + proskrnl
tests/run/run.sh firstboot  # the CUI-1 gate: boot a virgin image, diff the firstboot
                            # SYSTEM hive against a fresh oracle prefix (regdump/regdiff)
```

Both modes share one build of each `.exe` (`build/tests/ntapi/`). The proskrnl image
carries the Wine PE userland (`windows/system32`: ntdll/kernel32/kernelbase + NLS tables)
plus every test under `C:\ntapi\`; the kernel sweep (`KiRunNtapiTests`) runs whatever is
there — **the image, not a kernel-side list, decides what runs** — and ends with
`[KTEST] ntapi done tests=<n> failures=<n>`, the boot's stop condition. Both modes collect
`[KTEST] … PASS/FAIL` lines and exit non-zero if any test fails.

---

## Directory layout

```
tests/
  ntapi/
    ntapi.h              # the harness API (this doc)
    ntapi.c              # freestanding harness impl + the ntapi_start entry
    syscall/             # generated raw-syscall stubs (user/init-tests flat clients only)
    sem_wait/            # dispatcher/wait semantics
    sem_ob/              # object-manager semantics
    sem_mm/              # virtual memory semantics
    sem_file/            # file semantics
    sem_ps/              # process/thread query surface
    sem_reg/             # registry semantics
    sem_pipe/            # named-pipe semantics
  run/
    run.sh               # oracle | proskrnl | winetest | fuzz | persist | console
  winetest/
    manifest.txt         # the winetest gate's curated <test_exe>:<subtest> pairs
  fuzz/                  # the differential fuzzer (same single-binary shape)
```

The winetest gate's binaries are NOT ntapi tests — they are Wine's own `dlls/*/tests`
objects linked standalone (Makefile `wtests`, glue in `user/wtest/`), swept by
`KiRunWineTests` from `C:\wtests\manifest.txt` with a console. The manifest is curated:
a pair joins only when it exits 0 on BOTH runners (`docs/03` "M10 winetest notes").

(`tests/ntapi/syscall/` is no longer part of the ntapi build; the generated stubs remain
for the M4/M5-era flat boot modules under `user/init-tests/`.)

---

## Workflow, end to end (one Nt*)

1. Find the behaviour in Wine's `dlls/ntdll/tests/*` (or Windows docs). Distil the
   relevant `ok()`s into a `tests/ntapi/<bucket>/<name>.c` using this harness.
2. `tests/run/run.sh oracle` → the new test is **green on the oracle**. It is now the
   executable spec. Commit it *before* kernel code (Article 5).
3. Implement the `Nt*` in the kernel until `tests/run/run.sh proskrnl` passes it. A
   still-wrong corner that is a *documented deviation* (`docs/03`) gets `todo_proskrnl`;
   anything else stays red until fixed.
4. "Done" = the test is green on **both** runners (`docs/09` Art. 5), not the code
   compiling.
