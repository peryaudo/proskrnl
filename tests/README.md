# tests/

The project's lifeline (Article 5, `docs/08`). Layout and conventions are specified in
**`docs/14-test-harness.md`** — read it before adding tests.

- `ntapi/` — `Nt*`-boundary tests. Each test is ONE mingw-built, CRT-less PE `.exe`
  (test + `ntapi.c`, linked against the pinned Wine import libs) that runs unmodified
  under the Wine **oracle** and on **proskrnl** (baked at `C:\ntapi\`, swept by the
  kernel's ntapi runner).
  - `ntapi.h` / `ntapi.c` — the harness (`START_TEST`, `ok`, `todo_proskrnl`, `skip`).
  - `sem_wait/`, `sem_ob/`, `sem_mm/`, `sem_file/`, `sem_ps/`, `sem_reg/`, `sem_pipe/` —
    semantic buckets.
- `boot/` — the M4–M8 boot-module clients the kernel's own runners launch: flat binaries
  (`crt0.S` + `user.ld`) and minimal PEs over the generated raw-syscall stubs, plus the
  standing `abi_probe.c` (docs/08).
- `clients/` — the M7/M9 acceptance PEs that run over the baked userland: `hello.c`
  (ntdll-only + a hand-written SEH frame) and `m9_{smoke,echo}.c` (kernel32/kernelbase).
- `cui/` — the M10 third-party-CUI stand-ins, built with the plain mingw toolchain and its
  full CRT (`hello_crt.c`, `upcase.c`, `svcdemo.c`, `looper.c`, `jobtool.c`).
- `winetest/` — the curated winetest gate: the manifests, plus `glue/` (the `.CRT$X??`
  boundary symbols and the user32 stand-ins the standalone links need).
- `fuzz/` — the differential fuzzer; its interpreter is one more single-binary client.
- `run/run.sh` — the runner: `oracle` (spec gate), `proskrnl` (regression gate), plus
  `fuzz`, `persist`, `console`, and the FS battery legs `fatinterop` (mtools-baked
  interop corpus), `fatstress` (shadow-model churn, three geometries, two-boot cold
  verify), `tornwrite` (write-log prefix replay). Every disk-mutating leg ends in
  `run/fatcheck.sh` — fsck.fat + `run/fatsweep.py` + mcopy byte-compares (docs/08
  "The FAT on-disk format has its own oracles").

Quick start (needs a mingw toolchain + the pinned `third_party/wine` build):

```sh
tests/run/run.sh oracle
tests/run/run.sh oracle query_dir     # one test (or a glob) while iterating; both
tests/run/run.sh proskrnl query_dir   # legs take it — iteration only, the gate is
                                      # the unfiltered run (docs/14)
```

Workflow for one `Nt*`: write the test → green on `oracle` (commit before kernel code) →
implement until green on `proskrnl`. Done = green on **both**.
