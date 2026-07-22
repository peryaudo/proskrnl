# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

proskrnl is a minimal, Windows-NT-semantics-compatible kernel that boots on bare metal / a VM and runs the **unmodified Wine PE user-mode stack** (ntdll, kernelbase, user32, gdi32, …). We reimplement only the clean, observable boundary — the `Nt*` syscall surface plus PEB/TEB/file semantics that an unprivileged `.exe` can see — and reuse Wine above it and self-written virtio drivers below it. It is **not** a Windows clone or a ReactOS competitor.

## Read before writing code (hard rules, not guidance)

`docs/09-constitution.md` and `docs/CONTRIBUTING.md` are **gates**, not suggestions — a change that erodes a boundary is rejected even if it adds a feature. The thirteen constitution articles map to PR gates G1–G13. Key ones you will violate by default:

- **G1 / Art. 1 — Boundary only.** Reproduce NT behavior *exactly* only at the observable boundary (`Nt*` semantics Wine uses; PEB/TEB/RTL_USER_PROCESS_PARAMETERS/KUSER_SHARED_DATA layout; NT file semantics). Reproduce nothing else in Microsoft-compatible form.
- **G2 / Art. 2 — No NT-absent entities in the core.** Never add to `kernel/`, `abi/`, `arch/`, `fs/`, or the `Nt*` surface anything NT lacks. GUI-only exception: a new device or new process at the *outside* of the boundary, logged in `docs/10-hacks-ledger.md` (use `/log-hack`).
- **G3 / Art. 3 — Stupidly correct.** Mandates, not choices: **no copy-on-write; no eviction / immediate writeback; one dispatcher lock, uniprocessor, no kernel preemption; one pool.** Any deviation goes in `docs/03-nt-deviations.md`, justified against user-observable semantics — never performance.
- **G4 / Art. 4 — Generate the contract; never recall it.** Every numeric value in `abi/` (NTSTATUS, info-class numbers, struct offsets, flags) is generated from Wine headers via `tools/gen_abi.py` (`/gen-abi`). **No hand-typed constants. No `STATUS_*`/offset values from your memory** — plausible-but-approximate constants are worse than wrong ones. Layouts carry `static_assert(offsetof(...) == ...)`.
- **G8 / Art. 4 — Constants cite a trusted source.** Any hand-typed constant fixed by an external contract *outside* `abi/` (MSRs, LAPIC/UART/PIT registers, page-table bits, PE fields, NT magic addresses) must be cross-checked at introduction and carry a comment naming where to re-verify it: pinned Wine tree (path + symbol), official MS docs, vendor spec (Intel SDM / datasheet / virtio), or the pinned QEMU tree. An uncited externally-fixed constant is rejected even if correct.
- **G5 / Art. 5 — Test first.** A boundary behavior needs a `tests/ntapi/` test green on Wine/Windows *before* the kernel implements it. "Done" = test passing, not code compiling.
- **G6 / Art. 6 — Only a differential test convicts.** Sanitizers/asserts name suspects; only a passing differential/conformance test closes an issue. "The sanitizer went quiet" is not a fix.
- **G7 / Art. 7 — Additive & removable.** Everything outside the CUI core (GUI, WOW64, ROS shell) must be subtractable without touching the core.
- **G9 / Art. 10 — Wine is patched only at the unixlib seam.** Wine modifications replace unixlib plumbing with syscall stubs (+ build glue), nothing else — managed solely as commits on the fork's `proskrnl-target` branch pinned at `third_party/wine`; there is no patches directory, no vendored diffs, no build-time patching. Never change PE-side observable behavior, and **never patch Wine to make a proskrnl divergence pass** — that fixes the oracle instead of the kernel (Art. 6). Every commit carries a what/why/upstream-disposition header; the hack meter is the submodule diff vs. the winehq merge-base, and a pin-bump PR reports its delta.
- **G10+G11 / Art. 11 — One authority.** Never reimplement what a shared engine already does (Ob name resolution / create-open access checks / handle allocation, Ps identity minting) in a second code path — extend the engine instead; parallel paths drift even while currently equivalent. Every identity value (ids, cookies, handle values) has exactly one allocation site; a diff touching object creation/refcounts/teardown answers the ownership audit: who holds a reference at each point, and what happens if every handle closes — or the owning thread exits — at the earliest legal moment.
- **G12 / Art. 12 — Unbuilt behavior refuses loudly.** A stub never fabricates a plausible answer (a no-op success, a hardwired exit status/count/device type, a `-1`/`0` sentinel) — it returns `STATUS_NOT_IMPLEMENTED` (or the oracle's refusal shape) and names itself on serial (the `KI_SYSCALL_MISSING` pattern). Every silent-plausible stub in the bug history became a deferred bug; every loud stub was harmless. A fixed answer is legitimate only as pinned oracle behavior (G5 test or `docs/03` entry) — then it's an implementation, not a stub.
- **G13 / Art. 13 — Commits are meaningful units.** One logical change per commit (test pin, kernel behavior + its `docs/03` note, `abi/` regen, mechanical rename — never a drive-by mix), each buildable and gate-passing alone so a bisect can convict it; subject names the department(s) (`io+ob: ...`), body states what/why/how-verified; the G5 pin commit precedes the kernel commit in history; no WIP/fixup commits reach a PR — reorder and squash locally first.

**LLM failure mode (called out in the docs):** you are trained mostly on Linux/ReactOS and will unprompted add IRQL, split the cache into a separate `Cc`, introduce fine-grained locks / COW, import POSIX idioms, and recall constants from memory. Each violates a gate. When in doubt, prefer the simplest thing that passes the boundary tests and leave NT-faithful internals and optimizations unbuilt.

## Provenance (legal gates — see `docs/11-licensing.md`)

- **No GPL-source translation** into kernel or drivers. Drivers are written from **public specs** (virtio/AHCI/NVMe/xHCI/USB).
- Kernel-code reference material is limited to **Wine headers and official Microsoft documentation** — **not** ReactOS, not leaked Windows source, not model memory.
- Record component provenance in `docs/provenance.md`.

## Toolchain & code style (decided; formalized here)

- **Compiler: clang** (+ LLD + `llvm-*` binutils), cross-targeting `--target=x86_64-elf -ffreestanding`. Chosen over GCC because it cross-compiles from any host (Linux/macOS/arm64) without building a per-host cross-toolchain. **x86_64 only** (`docs/adr/0006-x64-only.md`).
- **Environment setup (Linux/Ubuntu 24.04): run `tools/setup_linux.sh` once.** It installs the apt toolchain and builds the pinned `third_party/` submodules in place: `limine` (bootloader stages prebuilt on the pinned `-binary` branch + deploy tool), `limine-protocol` (the boot-protocol header), `qemu` (Ubuntu 24.04's QEMU 8.2 lacks TCG x2APIC — ≥ 9.0 is required or `make run` hangs after `[KTEST] pool PASS`), and `wine` (the ntapi oracle runtime, same pinned tree `abi/` is generated from — never use a distro wine for the oracle; version divergence corrupts the spec). `tools/mkimage.sh`, `tools/qemu.sh`, and `tests/run/run.sh` prefer these in-tree builds automatically. **In an ephemeral container (Claude Code on the web), run `tools/fetch_third_party.sh` first** — it restores the finished QEMU/Wine/limine builds from the `third-party-cache` GitHub release in minutes (published by CI, keyed on the submodule pins) so `setup_linux.sh` skips the hours-long source builds.
- **Style: modern Win32/NT naming** — the *convention*, not WRK/ReactOS *source* (provenance, `docs/11`). `PascalCase` functions, `UPPER_SNAKE` typedefs, **camelCase** locals/params/struct members, `PascalCase` prefixed globals; no Linux `snake_case`, no strict Hungarian, **no `Hal` prefix** (HAL absorbed → default `Ki`; `Mi`/`Ke`/… only when it clearly belongs to that department). Match the real NT name **and signature** (grep `third_party/wine`; absent → free, use an internal `Ki`/`Mi` name — e.g. `KiPanic`, not a wrong-signature `KeBugCheck`). Full rules: **`docs/15-code-style.md`**; enforced by `make tidy` + `make format`. Tests use Wine snake_case style (exempt).
- **Kernel code uses NT department prefixes** `Ke`/`Mm`/`Ob`/`Ps`/`Io`/`Cm`/`Se` so it cross-references Windows Internals (`docs/04-repository-layout.md`).
- **Machine-verdict log lines use fixed prefixes** `[KTEST]` / `[PANIC]` / `[ASSERT]`, kept separate from human free-text. Under LLM-driven dev the panic dump is the debugger (Art. 9).
- **State invariants with `ASSERT(exp)`** (`kernel/init/panic.h`) as you write kernel code — always compiled in, fatal via the panic path, emits `[ASSERT] file:line: expr` + stack trace. Highest-value verification tool per line (docs/08): assert lock-held preconditions, state transitions, dispatcher type tags, count/list agreement (pattern: `kernel/ke/`, `kernel/lib/list.h`). A firing assert names a suspect; only a differential test convicts (Art. 6).
- Keep the Wine fork's diff vs. winehq **minimal** — its line count is the "hack meter"; Wine-modification rules are gate G9 / Art. 10 (commits on `proskrnl-target` only, unixlib seam only, never mask a divergence).

## Workflow

- **Feature branches + PRs; every change must satisfy gates G1–G13.** Run `/gate-check` on a diff before committing.
- `abi/` constants: regenerate with `/gen-abi`, never hand-edit.
- Introducing an NT-absent device/process: log it with `/log-hack` before/with the code.
- **On completing a milestone**, update the **Status** line in the README "Status" section (current milestone, what is achieved and what couldn't be achieved, what's next); confirm `make test` is green.

## Key docs

- `docs/00-overview.md` — the design in one sitting.
- `docs/09-constitution.md` — the hard rules. **Read before writing a line.**
- `docs/02-milestones.md` — the plan, M0 → WOW64. `docs/04-repository-layout.md` — where code goes.
- `docs/12-llm-workflow.md` — where an LLM is strong (info-class filling, virtio, fat32, `abi/` decls, tests) vs. dangerous (`mm/`, `ke/wait`, `ps/usermode`, `arch/*.S`).
- `docs/13-glossary.md` — IRQL, APC, section object, etc.
