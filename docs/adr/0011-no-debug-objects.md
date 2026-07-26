# ADR 0011 — Debug objects are not supported

**Status:** Accepted (post-CUI-4)

## Context
The `NtCreateDebugObject` family (`NtDebugActiveProcess`, `NtWaitForDebugEvent`,
`NtDebugContinue`, `NtRemoveProcessDebug`, `NtSetInformationDebugObject`) was CUI-4's
stretch goal. No baked binary reaches it: the whole surface sits behind ntdll's
on-demand `DbgUi*` entry points and kernelbase's `DEBUG_PROCESS |
DEBUG_ONLY_THIS_PROCESS` flags — a debugger is a development tool, not an app the
boundary exists to run (Art. 1). And the tooling it would invite doesn't fit:
proskrnl's toolchain is clang/LLD/DWARF end-to-end (panic-path traces,
`tools/symbolize.py`), while native Windows debuggers (windbg et al.) expect PDB
symbol flow that nothing here produces — syscall surface without the ecosystem it
exists to serve.

## Decision
Debug objects are permanently out of scope — a decision, not deferred work. The six
syscalls (plus the kernel-debug control pair `NtSystemDebugControl` /
`NtSetDebugFilterState`) keep their loud `KI_SYSCALL_MISSING` refusals forever
(Art. 12) and never fake success.

## Consequences
- `DebugActiveProcess` / `WaitForDebugEvent`-style attach and `CreateProcess` with
  `DEBUG_PROCESS` fail — loudly, never silently.
- Debugging of proskrnl user processes stays what it is today: the panic dump,
  serial tracing, and the differential suites (Art. 6/9).
- Foreign-thread `NtGet/SetContextThread` is NOT covered by this ADR — it stays
  planned (CUI-6) for the `SuspendThread`+`GetThreadContext` profiler/GC pattern.
- Reopening requires a real consumer (e.g. a DWARF-native debugger) entering
  through the front door: an oracle-green `tests/ntapi` pin first (Art. 5), and an
  amendment here — never a silent contradiction.

Expanded reasoning: `docs/03-nt-deviations.md` "Debug objects are out of scope";
the measured surface accounting: `docs/16-syscall-status.md`.
