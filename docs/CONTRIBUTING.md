# Contributing to proskrnl

proskrnl is defined by its **boundaries**, not its features. A contribution that adds a
feature while eroding a boundary is a net negative. This applies equally to human and LLM
contributors — and LLM contributors will violate these rules by default, so they are
stated as hard gates.

## Before you write code

1. Read `docs/09-constitution.md`. It is not guidance; it is the set of gates below.
2. Read `docs/00-overview.md` and `docs/01-tradeoffs.md` for *why* the gates exist.
3. If a Windows term is unfamiliar, read `docs/13-glossary.md`.

## The gates (a PR that fails any of these is rejected)

- **G1 — Boundary only.** You may reproduce NT behaviour *exactly* at the observable
  boundary (`Nt*` semantics Wine uses, PEB/TEB/params/KUSER_SHARED_DATA layout, NT file
  semantics). You may not reproduce anything else in Microsoft-compatible form.
  (Constitution Art. 1)

- **G2 — No NT-absent entities in the core.** Nothing NT lacks may enter `kernel/`, `abi/`,
  `arch/`, `fs/`, or the existing `Nt*` surface. GUI-only exception: new devices or new
  processes at the *outside* of the boundary, each logged in `docs/10-hacks-ledger.md`.
  (Art. 2)

- **G3 — Stupidly correct.** No COW, no eviction, immediate writeback, one dispatcher lock,
  uniprocessor, no kernel preemption, one pool. Any exception must be justified in
  `docs/03-nt-deviations.md` against *user-observable semantics*, never performance. The
  list is closed: **synchronous I/O is not on it** (`docs/19-io-strategy.md` §1), so do not
  cite Art. 3 for inline completion. Lifting a mandate is a commit of its own and only
  through the entry conditions its strategy document names — COW: `docs/17` §10;
  uniprocessor: `docs/18` §13. (Art. 3)

- **G4 — Generated contract.** No hand-typed or model-recalled numeric constants in `abi/`.
  All generated from Wine headers via `tools/gen_abi.py`; layouts carry `static_assert`
  offsets. Mechanically checked: **`make gen-check`** (run by the CI style shard) re-runs
  every generator against the current pin — `gen_abi`, `gen_syscalls`, `gen_upcase`,
  `gen_license`, `gen_timezones` — and fails naming any checked-in output that differs. So
  a hand-edit to a generated file is not a style nit that review might miss: it is red. A
  generated file whose *content* needs to change is changed in its GENERATOR (for
  `gen_syscalls`, the `IMPLEMENTED` list) and regenerated in the same commit. (Art. 4)

- **G5 — Test first.** A boundary behaviour needs a `tests/ntapi/` test green on the
  Wine/Windows oracle *before* the kernel implements it, and green on proskrnl before the
  change is "done"; not-yet-implemented cases are tagged `todo_proskrnl`, never left
  failing. A test never asserts `STATUS_NOT_IMPLEMENTED` — the oracle refusing is not a
  behaviour to reproduce (see G12). **A Wine gap is not a ceiling:** where the pinned Wine
  refuses, the case may be built against NT's own documented contract and pinned in a
  `beyond_oracle { ... }` block (skipped on the oracle, enforced on proskrnl) whose comment
  names the Microsoft documentation it is written against. That tag is only for cases the
  oracle *cannot* answer — using it where Wine does implement the behaviour fixes the test
  instead of the kernel and FAILS G6. (Art. 5, `docs/08`)

- **G6 — Conviction by differential test.** Sanitizers/asserts name suspects; only a
  passing differential/conformance test closes an issue. "Sanitizer went quiet" is not a
  fix. (Art. 6)

- **G7 — Additive & removable.** Anything outside the CUI core (GUI, WOW64, ROS shell) must
  be subtractable without touching the core. (Art. 7)

- **G8 — Constants cite a trusted source.** Every hand-typed constant whose value is fixed
  by an external contract (hardware registers/bits, on-disk formats, NT magic addresses —
  anything not covered by the generated `abi/`) is cross-checked at introduction time and
  carries a comment, in the same file, naming where a reader can re-verify it: the pinned
  Wine tree (path + symbol), official Microsoft documentation, the vendor spec (Intel
  SDM / datasheet / virtio spec), or the pinned QEMU tree. An uncited externally-fixed
  constant is rejected even if correct — it is indistinguishable from a hallucinated one.
  (Art. 4)

- **G9 — Wine is patched only at the unixlib seam.** Wine may be modified only to replace
  the unixlib side with proskrnl syscall stubs and adjust build glue — nothing else. No
  change may alter PE-side observable behaviour, and above all none may exist to make a
  proskrnl divergence pass: that fixes the oracle instead of the kernel (Art. 6). All
  modifications are commits on the fork's `proskrnl-target` branch, pinned at
  `third_party/wine` — no patches directory, no vendored diffs, no build-time patching.
  Each modification is one logical commit carrying a header (what it changes / why the
  seam is the right place / upstream disposition: `upstreamable`, `proskrnl-only`, or
  `temporary`-until-a-named-feature). Every commit must be **dormant under regular Wine**
  (runtime `!__wine_unix_call_dispatcher` guard, or a new file/build target the oracle
  never executes — docs/06 "One tree, three roles"): the pinned tree is also the oracle,
  and the oracle must keep testing the exact bytes proskrnl ships. The hack meter is the
  submodule diff vs. the winehq base (`tools/hack_meter.sh`; the base is the fork's
  `master` branch, fast-forwarded to the new winehq commit in the same push that rebases
  `proskrnl-target` onto it); a PR that bumps the pin states the old → new line counts,
  justifies any growth, and re-runs `tests/run/run.sh oracle` against the new pin,
  stating so. (Art. 10)

- **G10 — No parallel engines.** Does the diff resolve names, perform create/open access
  checks, allocate handles, or mint identity values without going through the Ob/Ps
  engine that already does it? If yes, reroute through the engine (extend it with a hook
  or flag if needed) or justify in the PR why the engine cannot serve the case. A
  parallel reimplementation is rejected **even when currently equivalent** — two
  implementations of one rule drift apart silently, and the drift is invisible to every
  other gate until a consumer samples it (the `a53dd04` shape: Cm's private resolution
  path skipped Ob's zero-access refusal). (Art. 11)

- **G11 — Ownership audit.** A diff that creates, copies, or stores an identity value
  (thread/process ids, cookies, handle values), or that touches a kernel object's
  creation, reference counting, or teardown, must answer the audit in the PR description:
  1. For each identity value the diff writes: what is its single source of truth, and
     does this diff introduce a second assignment site? (The `4fc732c` shape: TEB and
     ETHREAD ids from two counters.)
  2. For each object whose lifetime the diff touches: who holds a reference at each point
     of its life, and what happens if every handle is closed — or the owning thread
     exits — at the earliest legal moment? (The `edf9f0b` shape: a live thread's ETHREAD
     freed when its creator closed its handles promptly.)
  An unanswered audit, or one answered with "the caller won't do that", is a rejection.
  (Art. 11)

- **G12 — Loud refusal.** Does the diff add a stub, default case, or stand-in that
  fabricates a plausible answer — a success status from a no-op, a hardwired
  count/id/device-type/exit-status, a `-1`/`0` sentinel the caller will interpret —
  instead of refusing loudly (`STATUS_NOT_IMPLEMENTED` or the oracle's own refusal
  shape, plus a serial line naming what was asked — the `KI_SYSCALL_MISSING` pattern)?
  Every silent-plausible stub in the project's history became a deferred bug
  (`1d6dafd`, `7cd6189`, `87bb03e`, `4fc732c`, `15e72d8`, `3ce0031`); every loud stub
  surfaced instantly and harmlessly. A fixed answer is acceptable **only** when it is
  the pinned oracle behaviour — backed by a `tests/ntapi/` case green on the oracle or
  a `docs/03-nt-deviations.md` entry — which makes it an implementation, not a stub. A
  value invented so callers keep going is rejected regardless of how reasonable it
  looks. **`STATUS_NOT_IMPLEMENTED` is never such a fixed answer**: it means *unbuilt*,
  so a `tests/ntapi/` case must never assert it — not even when the oracle answers it,
  because an oracle that refuses is unbuilt too, never authoritative. A diff that adds
  such an assertion, or a `KiPinnedNotImplemented`-style exemption that spares a refusal
  from the dispatcher's panic, FAILS. An oracle that refuses is also not a reason to
  leave the case unbuilt — see G5's `beyond_oracle`. Where a real caller depends on a refusal, that
  refusal is the specific NT failure for the case (`STATUS_INVALID_INFO_CLASS`,
  `STATUS_INVALID_DEVICE_REQUEST`, …), implemented and pinned like any other behaviour.
  (Art. 12)

- **G13 — Commits are meaningful units.** A PR's history is curated: each commit is one
  logical change — a test pin, a kernel behaviour with its `docs/03` note, an `abi/`
  regeneration, a mechanical rename — that builds and passes the gates on its own, so a
  bisect can convict it (Art. 6). Subjects name the department(s) and the change (the
  `io+ob: ...` convention); bodies state what changed, why, and how it was verified.
  The G5 ordering must be visible in the history: the oracle-pin commit precedes the
  kernel commit it specifies. No WIP/fixup/checkpoint commits and no drive-by mixes of
  behaviour change with unrelated refactoring reach the PR — reorder and squash locally
  first. (Art. 13)

- **G14 — The blocking frontier is declared.** Which code can reach a park is a
  machine-computable property (`tools/blocking_frontier.py`, issue #96), and the CUI-8
  post-mortem showed what happens when it is left to judgement: the census drew the
  frontier at `fs/`, never asked Ob, and missed that `NtClose` parks (`docs/20` §10.1).
  The check (`make frontier-check`, run by `make format` and CI) enforces two facts:
  1. **No must-not-block region has a path to a park** — the completion drain, the
     interrupt/tick path, the idle consistency sweep, and the panic path (the same set
     the runtime `KiEnterNoBlockRegion`/`KI_MAY_BLOCK()` brackets declare — the static
     and runtime halves must name the same regions).
  2. **The entry-point frontier matches `tools/blocking_frontier.txt`.** A diff that
     makes a service newly able to park regenerates the baseline
     (`--write-baseline`) **in the same commit and says so in its body** — widening the
     frontier is a stated design decision, and it re-opens `docs/20`'s STILL-TRUE
     tables per §8.4 (a new blocking point invalidates every "nothing can run here"
     claim that survives on the old frontier). A baseline row appearing without a
     commit-body sentence acknowledging it FAILS, even when the widening itself is
     correct — silent widening is how the C1 defect shipped. (Art. 6's spirit: the
     machine names the fact; the human owns the decision.)

## Provenance rules (see docs/11)

- **No GPL-source translation** into drivers or kernel. Drivers are written from **public
  specifications** (virtio/AHCI/NVMe/xHCI/USB).
- Kernel-code reference material is limited to **Wine headers and official Microsoft
  documentation** — not ReactOS, not Windows leaked source, not model memory.
- Record component provenance in `docs/provenance.md`.

## Style / structure

- **Modern Win32/NT code style** (PascalCase, `UPPER_SNAKE` typedefs, NT names; not Linux
  `snake_case`). Full rules + `make format` in **`docs/15-code-style.md`**.
- Match NT department prefixes for kernel code (`Ke`/`Mm`/`Ob`/`Ps`/`Io`/`Cm`), so code
  cross-references Windows Internals.
- Keep the Wine fork's diff vs. winehq **minimal** — its line count is the project's
  "hack meter." The binding rules for what it may contain are gate G9 / Constitution
  Art. 10.
- Put contract-bearing async logic in `io/async.c`; keep the free internal driver interface
  in `io/vfs.h`.
- Machine-verdict log lines use fixed prefixes (`[KTEST]`, `[PANIC]`, `[ASSERT]`); keep them
  separate from human free-text.

## Debugging expectations

Build against the thick panic handler and structured logs (Art. 9). Under LLM-driven
development the panic dump is the debugger; a change that degrades diagnostics is a
regression.

State invariants with **`ASSERT(exp)`** (`kernel/init/panic.h`) as you write kernel code —
it is always compiled in, fatal, and emits the `[ASSERT] file:line: expr` verdict plus a
stack trace. Invariant asserts are the highest-value verification tool per line
(`docs/08`); a PR that adds nontrivial kernel state machinery without asserting its
invariants is leaving the cheapest defence unbuilt.

## A note to LLM agents specifically

You are trained mostly on Linux and on ReactOS. You will, unprompted, want to add IRQL,
split the cache into a separate Cc, introduce fine-grained locks and COW, recall
`STATUS_*` constants from memory, and type hardware register numbers that are "well
known" to you without citing where they can be checked. **Each of these violates a
gate.** When in doubt, prefer
the simplest thing that passes the boundary tests, and leave optimizations and NT-faithful
internals unbuilt. The project's difficulty is not the code you can write; it is the
boundary you must not erode.
