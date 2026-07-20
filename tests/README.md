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
- `fuzz/` — the differential fuzzer; its interpreter is one more single-binary client.
- `run/run.sh` — the runner: `oracle` (spec gate), `proskrnl` (regression gate), plus
  `fuzz`, `persist`, `console`.

Quick start (needs a mingw toolchain + the pinned `third_party/wine` build):

```sh
tests/run/run.sh oracle
```

Workflow for one `Nt*`: write the test → green on `oracle` (commit before kernel code) →
implement until green on `proskrnl`. Done = green on **both**.
