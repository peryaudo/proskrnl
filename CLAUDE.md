# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

proskrnl is a minimal, Windows-NT-semantics-compatible kernel that boots on bare metal / a VM and runs the **unmodified Wine PE user-mode stack** (ntdll, kernelbase, user32, gdi32, …). We reimplement only the clean, observable boundary — the `Nt*` syscall surface plus PEB/TEB/file semantics that an unprivileged `.exe` can see — and reuse Wine above it and self-written virtio drivers below it. It is **not** a Windows clone or a ReactOS competitor.

**Status: pre-M1.** The repo is currently a *constitution* — design docs that fix decisions before implementation. There is no kernel source, build system, or tests yet.

## Read before writing code (hard rules, not guidance)

`docs/09-constitution.md` and `docs/CONTRIBUTING.md` are **gates**, not suggestions — a change that erodes a boundary is rejected even if it adds a feature. The nine constitution articles map to PR gates G1–G7. Key ones you will violate by default:

- **G1 / Art. 1 — Boundary only.** Reproduce NT behavior *exactly* only at the observable boundary (`Nt*` semantics Wine uses; PEB/TEB/RTL_USER_PROCESS_PARAMETERS/KUSER_SHARED_DATA layout; NT file semantics). Reproduce nothing else in Microsoft-compatible form.
- **G2 / Art. 2 — No NT-absent entities in the core.** Never add to `kernel/`, `abi/`, `arch/`, `fs/`, or the `Nt*` surface anything NT lacks. GUI-only exception: a new device or new process at the *outside* of the boundary, logged in `docs/10-hacks-ledger.md` (use `/log-hack`).
- **G3 / Art. 3 — Stupidly correct.** Mandates, not choices: **no copy-on-write; no eviction / immediate writeback; one dispatcher lock, uniprocessor, no kernel preemption; one pool.** Any deviation goes in `docs/03-nt-deviations.md`, justified against user-observable semantics — never performance.
- **G4 / Art. 4 — Generate the contract; never recall it.** Every numeric value in `abi/` (NTSTATUS, info-class numbers, struct offsets, flags) is generated from Wine headers via `tools/gen_abi.py` (`/gen-abi`). **No hand-typed constants. No `STATUS_*`/offset values from your memory** — plausible-but-approximate constants are worse than wrong ones. Layouts carry `static_assert(offsetof(...) == ...)`.
- **G5 / Art. 5 — Test first.** A boundary behavior needs a `tests/ntapi/` test green on Wine/Windows *before* the kernel implements it. "Done" = test passing, not code compiling.
- **G6 / Art. 6 — Only a differential test convicts.** Sanitizers/asserts name suspects; only a passing differential/conformance test closes an issue. "The sanitizer went quiet" is not a fix.
- **G7 / Art. 7 — Additive & removable.** Everything outside the CUI core (GUI, WOW64, ROS shell) must be subtractable without touching the core.

**LLM failure mode (called out in the docs):** you are trained mostly on Linux/ReactOS and will unprompted add IRQL, split the cache into a separate `Cc`, introduce fine-grained locks / COW, import POSIX idioms, and recall constants from memory. Each violates a gate. When in doubt, prefer the simplest thing that passes the boundary tests and leave NT-faithful internals and optimizations unbuilt.

## Provenance (legal gates — see `docs/11-licensing.md`)

- **No GPL-source translation** into kernel or drivers. Drivers are written from **public specs** (virtio/AHCI/NVMe/xHCI/USB).
- Kernel-code reference material is limited to **Wine headers and official Microsoft documentation** — **not** ReactOS, not leaked Windows source, not model memory.
- Record component provenance in `docs/provenance.md`.

## Toolchain & code style (decided; formalized here)

- **Compiler: clang** (+ LLD + `llvm-*` binutils), cross-targeting `--target=x86_64-elf -ffreestanding`. Chosen over GCC because it cross-compiles from any host (Linux/macOS/arm64) without building a per-host cross-toolchain. **x86_64 only** (`docs/adr/0006-x64-only.md`).
- **Style: modern Win32/NT** as in ReactOS / the Windows Research Kernel — **PascalCase** functions (`KeInitializeIdt`), `UPPER_SNAKE` typedefs (`KTRAP_FRAME`), PascalCase locals; **not** Linux-kernel `snake_case`; no strict systems Hungarian. Full rules + rename map in **`docs/15-code-style.md`**. Layout enforced by `.clang-format` / `make format` (naming is on you). When editing kernel C, match the NT name of a thing (`KeBugCheck`, not `panic`).
- **Kernel code uses NT department prefixes** `Ke`/`Mm`/`Ob`/`Ps`/`Io`/`Cm`/`Se` so it cross-references Windows Internals (`docs/04-repository-layout.md`).
- **Machine-verdict log lines use fixed prefixes** `[KTEST]` / `[PANIC]` / `[ASSERT]`, kept separate from human free-text. Under LLM-driven dev the panic dump is the debugger (Art. 9).
- Keep `user/wine/patches/` **minimal** — its size is the project's "hack meter."

## Workflow

- **Feature branches + PRs; every change must satisfy gates G1–G7.** Run `/gate-check` on a diff before committing.
- `abi/` constants: regenerate with `/gen-abi`, never hand-edit.
- Introducing an NT-absent device/process: log it with `/log-hack` before/with the code.

## Key docs

- `docs/00-overview.md` — the design in one sitting.
- `docs/09-constitution.md` — the hard rules. **Read before writing a line.**
- `docs/02-milestones.md` — the plan, M0 → WOW64. `docs/04-repository-layout.md` — where code goes.
- `docs/12-llm-workflow.md` — where an LLM is strong (info-class filling, virtio, fat32, `abi/` decls, tests) vs. dangerous (`mm/`, `ke/wait`, `ps/usermode`, `arch/*.S`).
- `docs/13-glossary.md` — IRQL, APC, section object, etc.
