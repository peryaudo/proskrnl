# ADR 0002 — Compatibility target is the NT native-API boundary

**Status:** Accepted

## Context
Every OS-compatibility project's fate is set by which boundary it promises to reproduce.
After dropping the driver ABI (ADR 0001), the remaining candidate boundary is the NT native
API — the surface Wine's PE DLLs read and call.

## Decision
The compatibility target is exactly three things, reproduced precisely and nothing else in
Microsoft-compatible form:
1. `Nt*` syscall semantics (the subset Wine uses).
2. User-visible structure layouts: `PEB`, `TEB`, `RTL_USER_PROCESS_PARAMETERS`,
   `KUSER_SHARED_DATA` — byte-exact.
3. NT file semantics: share modes, case rules, delete-on-close, byte-range locks,
   `NtQuery*File` info classes, async I/O with APC/event/completion-port notification.

## Consequences
- This boundary is **narrow, observable from an unprivileged .exe, and already specified by
  Wine's headers and tests.** Oracles exist; differential testing works; clean-room and
  clean-provenance become feasible (docs/08, docs/11).
- Syscall *numbers* are free to invent (ntdll and kernel are built as a set); only behaviour
  is fixed.
- The internal design is free wherever the boundary casts no shadow (docs/05). This yields
  "an NT skeleton with Unix-teaching-kernel viscera."
- The correct comparison becomes FreeBSD's Linuxulator, not ReactOS or Wine.
