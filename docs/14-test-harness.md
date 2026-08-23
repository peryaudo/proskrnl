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
tests/run/run.sh winetest   # the M10 stretch gate: the full non-GUI sweep of Wine's OWN
                            # test suite (tests/winetest/manifest.txt), oracle + proskrnl
                            # (takes a <module>[:<subtest>] filter — see "Iterating")
tests/run/run.sh firstboot  # the CUI-1 gate: boot a virgin image, diff the firstboot
                            # SYSTEM hive against a fresh oracle prefix (regdump/regdiff)
tests/run/run.sh prebuild   # build every test .exe and run NOTHING — a build step with no
                            # verdict. Nothing in the pipeline calls it any more (the
                            # Makefile owns the compiles); a hand tool for warming a tree
```

Both modes share one build of each `.exe` (`build/tests/ntapi/`). The proskrnl leg boots a
copy of the one test image, whose payload the Makefile owns in a single list, so
`wineboot --init` has run on it (in the warm-up boot) and a pin is taken against the
machine the product has — plus every test under `C:\ntapi\`, the helper DLL and the WOW64
payload. The session manager's sweep (`user/smss/session.c`) runs whatever is there,
filtered by `GUEST_SUBTESTS`, and ends with
`[KTEST] ntapi done tests=<n> failures=<n>`, the boot's stop condition. Both modes collect
`[KTEST] … PASS/FAIL` lines and exit non-zero if any test fails.

### Iterating on one test

Both legs take optional `<subtest>` arguments — a test's base name (unique across the
buckets), or a glob over base names:

```
tests/run/run.sh oracle   query_dir           # one test under the oracle
tests/run/run.sh proskrnl query_dir           # boot, but RUN only that .exe
tests/run/run.sh proskrnl 'se_*' handle_life  # globs and several names are fine
```

The filter reaches the GUEST: the query goes on the QEMU command line as
`-fw_cfg opt/org.proskrnl/subtests`, the kernel publishes it as
`HKLM\Hardware\qemu` `Subtests` (HACK-006), and the session manager's sweep applies the
same glob rule the harness applies host side (`user/smss/session.c`
`SessionQuerySelects`) — so the sweep, and the boot, is as short as the subset while the
IMAGE stays the gate's. It used to be the image that decided: a subset run baked only the
named `.exe`s, so the media recorded which subset had last been asked for and
`build/tests/proskrnl-subset.hdd` was a second image the gate's could be confused with.
The subset run still writes its own copy and log (`build/tests/proskrnl-subset.hdd`,
`proskrnl-subset-serial.log`) — a boot mutates what it boots — and runs the structural FAT
oracles only (the full leg's per-test expectations do not hold when only some tests ran).

A subset run is for **iteration, never for a verdict** — it says so on stdout, and the
gates in `docs/CONTRIBUTING.md` are the unfiltered runs. A pattern matching nothing is an
error listing the known names, so a typo can never read as "everything passed".

The winetest leg takes the same filter, over manifest **pairs**. A pair's name is
`<module>:<subtest>`, the module being the exe without its `_test.exe` tail (`ntdll`,
`kernel32`, `msvcrt`, `ucrtbase`, `cmd`); a bare word with no `:` matches either half:

```
tests/run/run.sh winetest ntdll:env      # one pair
tests/run/run.sh winetest ntdll          # a whole module
tests/run/run.sh winetest printf         # that subtest wherever it exists (msvcrt+ucrtbase)
tests/run/run.sh winetest 'rtl*' cmd     # globs and several patterns are fine
```

Here the filter is the same `subtests` boot string, carrying the selected PAIR NAMES: a
`<module>:<subtest>` key is a pattern that matches exactly its own pair, so the harness's
CUI/audio partition — which needs two boots, one with a virtio-snd device — reaches the
guest as a decision rather than as two baked manifests. Both curated manifests
(`manifest.txt`, and `manifest-gui.txt` for the `guiwtest` trophy) are baked verbatim on
every image and the boot's `leg` picks which one the sweep reads.

It used to be a **generated manifest**: the selected lines were written out and baked as
`C:\wtests\manifest.txt`, so a filtered run produced a third image whose file on disk
recorded which subset had last been asked for. The subset run's own copy and log
(`build/tests/wtest-subset.hdd`, `wtest-subset-serial.log`) keep it clear of the gate's,
and the same typo rule applies (the error lists every known pair). This is the way to
work a red pair without paying for the whole sweep: the manifest lists the entire non-GUI
surface, so an unfiltered run is long by design.

### The oracle runs on a display the runner owns (`start_xvfb`)

The pinned Wine is built `--with-x`, so its display driver is `winex11.drv` — and that
driver is `dlopen`'d and fail-soft exactly like the font backend: with no X connection
user32 falls back to the null driver, which *refuses* every window rather than failing.
An oracle in that state answers plausibly and is wrong about everything windowed, which
is why the runner owns the display instead of borrowing one:

- **One `Xvfb` per `run.sh` invocation**, started for every mode that runs host Wine
  (`RUNS_WINE`) and killed with the leg. `-displayfd` lets the server pick a free display
  number, so concurrent legs (`make fulltest` runs eight at once) never fight over `:0`.
- **Fixed geometry, `$XVFB_SCREEN`, default `1280x800x24`** — proskrnl's own scanout size,
  so the oracle's screen metrics are the *target's* rather than merely constant. A
  developer's 4K HiDPI screen never enters an answer, because `$DISPLAY` is overwritten,
  not inherited.
- **A missing display is refused, not worked around.** The generated wine wrapper
  (`build/tests/wine-fonts`) exits non-zero when `$DISPLAY` is empty, and `start_xvfb`
  refuses a pinned tree whose `config.h` has no `SONAME_LIBX11`. Both failures name
  themselves; neither can be answered from the null driver by accident.

This is what makes a GUI winetest gate two-sided at all — `run.sh guiwtest` runs Wine's
own `user32:msg` under the oracle as well as on proskrnl (docs/03 "GUI-5 winetest notes").

### The oracle leg is fanned out (`ORACLE_JOBS`)

The oracle leg is one short-lived process per case and nothing else, so it runs
`ORACLE_JOBS` (default: `nproc`) of them at a time. Two properties make that a speedup
rather than a new source of flakes:

- **Each worker gets its own wineprefix, created — never copied.** Worker *n* uses
  `build/tests/wineprefix-<n>`, worker 0 the base prefix, and wine creates each one the
  way it creates the sequential leg's. The cases address absolute paths under `C:\` and
  keys under `\Registry\Machine\Software`, wineserver's namespace is per-prefix, and
  `NtQuerySystemInformation`'s process list is exactly what a neighbour would pollute; a
  private prefix makes a parallel run *semantically* identical to a sequential one, not
  merely faster. Cloning a finished prefix with `cp -a` looks equivalent and is not — in a
  copy, `sem_file/ea_volume`'s `\??\C:` open fails `STATUS_OBJECT_NAME_NOT_FOUND`
  deterministically, while a *created* prefix at the same path passes. Creation costs ~8 s
  and the workers pay it concurrently, so the copy bought nothing anyway. Concurrent
  creation is safe because each worker owns its prefix; the race worth avoiding is two
  processes creating the *same* one.
- **Cases that measure the machine run alone** (`$ORACLE_SERIAL_CASES`, currently
  `times`). `sem_ps/times.c` asserts the processor idle counter grew across a 60 ms sleep;
  the oracle's Wine answers that out of the host's `/proc/stat`, so on a runner whose every
  core is busy running the rest of this leg it does not. A private prefix cannot isolate a
  host-global quantity — the neighbours *are* the load — so those cases are held back and
  run one at a time once the workers are done. A name belongs on that list only if it can
  say which host-global quantity it measures.
- **The log is replayed in source order.** Each case's whole output is captured to
  `build/tests/ntapi/out/<name>` and `cat` back in the order `all_tests` produced, so the
  transcript and the `[KTEST]` grading are byte-for-byte what a sequential run printed.
- **Cases the oracle answers WRONGLY are parked, by name** (`$ORACLE_PARKED_CASES`,
  currently `thread_skip_flags`). This is the third and rarest reason a case moves: not
  "the oracle cannot answer" (that is `beyond_oracle`, whose contract forbids this use)
  and not "proskrnl diverges" (`todo_proskrnl`), but *the pinned Wine returns a wrong
  answer, intermittently*. A spec that is right most of the time is not a spec, and a leg
  that re-runs until green is worse than one that says so. Only the **oracle sweep** skips
  it — loudly, with a printed line — and naming the case explicitly still runs it, so the
  evidence for un-parking is one command away; the **proskrnl leg is untouched** and still
  gates every assertion. The entry must name the mechanism *in the pinned tree's own
  source* and show a trace, never just a failure rate: `thread_skip_flags`'s entry quotes
  the `+server` trace where `new_thread` replies `INVALID_CID` while carrying the valid tid
  and handle of the thread it did create, because a dying thread's last fd message reached
  `server/request.c` `receive_fd()` after its sender was gone and that path returns without
  `clear_error()`. Un-park when the pin carries a fix.

`ORACLE_JOBS=1` is the strictly sequential run: the fallback where `nproc` is missing, and
what to set when a case is suspected of depending on its neighbours.

---

## Directory layout

```
tests/
  ntapi/
    ntapi.h              # the harness API (this doc)
    ntapi.c              # freestanding harness impl + the ntapi_start entry
    syscall/             # generated raw-syscall stubs (tests/boot flat clients only)
                         #   + the generated pointer-torture matrix (docs/08)
    sem_wait/            # dispatcher/wait semantics
    sem_ob/              # object-manager semantics
    sem_mm/              # virtual memory semantics
    sem_file/            # file semantics
    sem_ps/              # process/thread query surface
    sem_reg/             # registry semantics
    sem_pipe/            # named-pipe semantics
  run/
    run.sh               # oracle [subtest...] | proskrnl [subtest...] | winetest
                         #   | fuzz | persist | console | ...
  winetest/
    manifest.txt         # the winetest gate's <test_exe>:<subtest> pairs (all non-GUI)
  fuzz/                  # the differential fuzzer (same single-binary shape)
```

The winetest gate's binaries are NOT ntapi tests — they are Wine's own `dlls/*/tests`
objects linked standalone (Makefile `wtests`, glue in `tests/winetest/glue/`), swept by the
session manager (`user/smss/session.c`) from `C:\wtests\manifest.txt` with a console. The manifest
lists every subtest of ntdll, kernel32, msvcrt, ucrtbase and programs/cmd — the whole non-GUI
surface — so the leg measures the frontier rather than the part already crossed; advapi32 and
user32 are out (`docs/03` "M10 winetest notes").

It boots a copy of the one test image — the Makefile owns its payload as a single list
(one list, one authority), so `wineboot --init` has run on it and the sweep meets
`wine.inf`'s machine-state registry payload, the SCM binaries and the WOW64 payload the
product has, alongside what this leg reads: the wtest binaries and both manifests under
`C:\wtests`, the full NLS set, `tzres.dll` and the `win.ini`/`system.ini` furniture
(`tools/gen_sysini.py`).

(`tests/ntapi/syscall/`'s generated STUBS are no longer part of the ntapi build; they
remain for the M4/M5-era flat boot modules under `tests/boot/`. The directory does hold one
ordinary ntapi test — `ptr_torture.c`, over the generated `torture_matrix.inc` — because
that is where the generator writes.)

### A third disposition: proskrnl-only, by construction

`todo_proskrnl` and `beyond_oracle` both assume the oracle is being ASKED something. One
test is not asking: `syscall/ptr_torture.c` (docs/08, "The pointer-torture matrix") sweeps
every service with hostile pointers and grades survival, and Wine — no ring boundary, no
kernel — has nothing to say about a kernel address. It therefore probes
`ntapi_ctx.on_proskrnl` and `skip()`s the whole body on the oracle leg, with the reason in
the skip text.

This is not an escape hatch and it does not weaken Art. 5: nothing there pins a boundary
SEMANTICS. A test that asserts what a status IS still measures the oracle first, or cites
a Microsoft contract in a `beyond_oracle` block. The distinction is whether a runner that
is not a kernel could be the authority for the question — for liveness under a hostile
ring-3 argument, it cannot be.

---

## Workflow, end to end (one Nt*)

1. Find the behaviour in Wine's `dlls/ntdll/tests/*` (or Windows docs). Distil the
   relevant `ok()`s into a `tests/ntapi/<bucket>/<name>.c` using this harness.
2. `tests/run/run.sh oracle` → the new test is **green on the oracle**. It is now the
   executable spec. Commit it *before* kernel code (Article 5).
3. Implement the `Nt*` in the kernel until `tests/run/run.sh proskrnl` passes it —
   iterate with `run.sh proskrnl <name>`, then confirm with the unfiltered leg. A
   still-wrong corner that is a *documented deviation* (`docs/03`) gets `todo_proskrnl`;
   anything else stays red until fixed.
4. "Done" = the test is green on **both** runners (`docs/09` Art. 5), not the code
   compiling.
