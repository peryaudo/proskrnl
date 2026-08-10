# ADR 0011 — Debug objects are not supported

**Status:** Accepted (post-CUI-4); **amended at the WOW64 milestone** —
attach only (see "Amendment" below)

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

## Amendment (WOW64 milestone) — attach, and only attach

The reopening condition above was met, through the front door and in the order
it specifies.

**The consumer.** `ntdll:wow64` — a gate of the WOW64 milestone — calls
`DebugActiveProcess` on its 32-bit child and then reads `BeingDebugged` out of
*both* PEBs (`third_party/wine dlls/ntdll/tests/wow64.c:1041-1051`). That is not
a debugger arriving; it is a conformance test measuring a **boundary** behavior:
whether the flag a process can read about itself in its own PEB tracks the
kernel's idea of who is attached. Art. 1 covers it, and refusing keeps the pair
red for a reason that has nothing to do with WOW64.

**The pin.** `tests/ntapi/sem_ps/debug_attach.c`, green on the oracle before a
line of kernel code (Art. 5). It measures the observable effect — `BeingDebugged`
going 1 on attach and 0 on detach — and the statuses of the refusals around it,
including one that contradicts the documentation and follows the oracle instead
(double attach answers `STATUS_ACCESS_DENIED`, not `STATUS_PORT_ALREADY_SET`).

**What the amendment carves out.** Exactly the three calls `DebugActiveProcess` /
`DebugActiveProcessStop` make, and no others:

- `NtCreateDebugObject` — a real object with `DEBUG_KILL_ON_CLOSE`;
- `NtDebugActiveProcess` — binds it to a target and sets `BeingDebugged` in the
  PEB (and, for a WOW64 target, the PEB32);
- `NtRemoveProcessDebug` — unbinds and clears it.

**What stays refused, permanently.** The **event queue**:
`NtWaitForDebugEvent`, `NtDebugContinue`, `NtSetInformationDebugObject`,
`DEBUG_PROCESS` at create, and the kernel-debug control pair. They keep their
loud `KI_SYSCALL_MISSING` refusals (Art. 12). This is the line that matters:
attach is a flag with an owner, while the event queue is a scheduling contract —
every debuggee thread blocking until a debugger answers — and building it would
put a second stop/continue authority beside the dispatcher (Art. 11) for a
consumer that still does not exist.

The original Decision above therefore reads, from here on, as covering the event
queue rather than the whole family; the rest of it stands unchanged, reopening
condition included. Nothing here makes proskrnl debuggable: a process that
attaches learns only that `BeingDebugged` is set, and receives no events.

Expanded reasoning: `docs/03-nt-deviations.md` "Debug objects are out of scope";
the measured surface accounting: `docs/16-syscall-status.md`.
