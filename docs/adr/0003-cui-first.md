# ADR 0003 — CUI is the final supported target; GUI is opt-in

**Status:** Accepted

## Context
Most real Windows demand is GUI demand, but win32k — NT's windowing kernel — is a
>1000-entry, cross-process concurrent state machine whose "public API" is a *temporal
protocol* (message order, timing, re-entrancy, `DefWindowProc` behaviour) that apps depend
on by observation. Together with GDI (a rasterizer + font engine) it is larger than the
entire rest of the kernel, and it is where ReactOS has spent the most effort with the least
completion.

## Decision
CUI is the final *supported* target. A GUI path exists but is opt-in, additive, removable,
and built by **reusing Wine's win32u/user32** rather than reimplementing win32k (see ADR
0007).

## Consequences
- Closes the entrance to the win32k temporal-protocol swamp — the highest-leverage decision
  after ADR 0001.
- calc.exe is still reachable (via Wine's GUI stack) but sits late in the plan; a shell is
  not required for a usable windowing system because window frames/buttons are USER's job.
- Gives up being a general-purpose desktop OS. Accepted: the project sells NT *semantics*,
  not a desktop.
