# ADR 0004 — Reuse Wine's PE user-land; swap only ntdll's unix backend

**Status:** Accepted

## Context
Modern Wine builds its DLLs as real PE files, each split into a **PE side** (Windows logic,
app-visible) and a **unixlib side** (host calls), meeting at a thin function table. The PE
side holds ~all of Wine's value (30 years of message-ordering/API compatibility); the unix
side is thin plumbing. This split — created by Wine for copy-protection resistance — is
exactly NT's own structure: a PE ntdll that syscalls.

## Decision
Keep Wine's PE side unchanged. Replace only ntdll's unixlib side with syscall stubs to
proskrnl. Wine is a SHA-pinned submodule at `third_party/wine`, pointing at the fork's
`proskrnl-target` branch; swaps live as commits on that branch, and the size of its diff
vs. winehq is the project's "hack meter" (Constitution Art. 10).

## Consequences
- 30 years of Win32 compatibility arrive as data, for free (M7).
- ntdll's Ldr/Rtl/SEH logic is reused unchanged.
- Ties us to Wine's release cadence and to tracking its unixlib boundary; mitigated by a
  fork + `proskrnl-target` branch and a partial (ntdll-only) build mode.
- License stays clean: the PE DLLs are LGPL but linked into user-mode processes, across a
  process boundary from the kernel (docs/11).
