# tests/

The project's lifeline (Article 5, `docs/08`). Layout and conventions are specified in
**`docs/14-test-harness.md`** — read it before adding tests.

- `ntapi/` — portable Nt*-boundary tests. Same source builds as a Windows `.exe` (the
  Wine/Windows **oracle**) and, from M4, as a freestanding **proskrnl** client.
  - `ntapi.h` / `ntapi.c` — the harness (`START_TEST`, `ok`, `todo_proskrnl`, `skip`).
  - `manifest.txt` — which tests must be green on the proskrnl target *now*.
  - `sem_wait/`, `sem_mm/`, `sem_file/` — semantic buckets.
- `run/run.sh` — the runner: `oracle` (spec gate) and `proskrnl` (regression gate).

Quick start (oracle side, needs a mingw toolchain + wine):

```sh
tests/run/run.sh oracle
```

Workflow for one `Nt*`: write the test → green on `oracle` (commit before kernel code) →
implement until green on `proskrnl` → add its line to `manifest.txt`.
