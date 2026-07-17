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
  `docs/03-nt-deviations.md` against *user-observable semantics*, never performance.
  (Art. 3)

- **G4 — Generated contract.** No hand-typed or model-recalled numeric constants in `abi/`.
  All generated from Wine headers via `tools/gen_abi.py`; layouts carry `static_assert`
  offsets. (Art. 4)

- **G5 — Test first.** A boundary behaviour needs a `tests/ntapi/` test green on the
  Wine/Windows oracle *before* the kernel implements it, and green on proskrnl before the
  change is "done"; not-yet-implemented cases are tagged `todo_proskrnl`, never left
  failing. (Art. 5, `docs/08`)

- **G6 — Conviction by differential test.** Sanitizers/asserts name suspects; only a
  passing differential/conformance test closes an issue. "Sanitizer went quiet" is not a
  fix. (Art. 6)

- **G7 — Additive & removable.** Anything outside the CUI core (GUI, WOW64, ROS shell) must
  be subtractable without touching the core. (Art. 7)

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
- Keep `user/wine/patches/` **minimal** — its size is the project's "hack meter."
- Put contract-bearing async logic in `io/async.c`; keep the free internal driver interface
  in `io/vfs.h`.
- Machine-verdict log lines use fixed prefixes (`[KTEST]`, `[PANIC]`, `[ASSERT]`); keep them
  separate from human free-text.

## Debugging expectations

Build against the thick panic handler and structured logs (Art. 9). Under LLM-driven
development the panic dump is the debugger; a change that degrades diagnostics is a
regression.

## A note to LLM agents specifically

You are trained mostly on Linux and on ReactOS. You will, unprompted, want to add IRQL,
split the cache into a separate Cc, introduce fine-grained locks and COW, and recall
`STATUS_*` constants from memory. **Each of these violates a gate.** When in doubt, prefer
the simplest thing that passes the boundary tests, and leave optimizations and NT-faithful
internals unbuilt. The project's difficulty is not the code you can write; it is the
boundary you must not erode.
