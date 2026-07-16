# 11 — Licensing & Provenance

Licensing here is not paperwork — it is a **project-survival** concern, for two distinct
reasons: the multi-upstream code map, and the LLM-provenance risk. Constitution Article 8
requires the kernel license be fixed **before M13**.

## The upstream license map

| Component | Origin | License |
|---|---|---|
| `kernel/`, `abi/`, `arch/`, `drivers/`, `fs/` | proskrnl | **our choice** (see below) |
| Wine PE DLLs, wineserver-lite | Wine | **LGPL-2.1** |
| ReactOS shell (optional M17), its INF data | ReactOS | **GPL-2.0** |

## Why route (a) keeps the kernel license free

The kernel talks to Wine/wineserver-lite across a **process boundary** (syscalls; shared
sections; pipes). Under route (a), wineserver-lite stays a **separate LGPL process** and no
LGPL/GPL code is linked into the kernel image. Therefore **the kernel's license is
unconstrained** — this is a direct, second dividend of choosing route (a) over (b).

Under **route (b)** (desktop state moved into `kernel/win32k`), LGPL Wine-derived code
would enter the kernel image, constraining the kernel license. If (b) is ever pursued, the
license must be settled first; alternatively, win32k could be a *loadable* module (buying
back exactly one module loader we otherwise dropped) to preserve a different kernel
license. **Decide before attempting (b).**

## The GPL/LGPL interaction (for the optional shell)

If the ReactOS shell is adopted (M17): explorer.exe is **GPLv2**; it calls Wine DLLs that
are **LGPL**. LGPL is absorbable into GPL, so **GPL explorer calling LGPL user32 in one
process is fine.** The kernel, being a separate process, is unaffected. A `licenses/MAP.md`
should record provenance per process/file, and `user/dllmap.toml` records which DLL comes
from which upstream at the collision points (chiefly shell32).

## The real risk: LLM provenance

This is the more dangerous item, and it mirrors a wound this domain already suffered.
ReactOS underwent a 2006 code audit over clean-room-provenance doubts that drained
enormous energy — a *procedural*, not technical, injury.

Two provenance traps apply to proskrnl:

1. **GPL/LGPL laundering via translation.** Translating GPL source (e.g. Linux drivers)
   through an LLM does **not** strip copyright; a functional mapping of a specific work is a
   textbook derivative. "AI laundering" is an untested legal bet. **Do not** produce driver
   code by translating GPL sources. Our drivers are written from **public specifications**
   (virtio, AHCI, NVMe, xHCI, USB) instead — which also happens to be where LLMs are
   strongest and where no license attaches.

2. **Unwitting reproduction of ReactOS in the kernel.** ReactOS is GPLv2 and is heavily
   present in LLM training data. Asking a model to "implement `NtQueryInformationFile`" may
   surface ReactOS-derived code. The irony would be complete: contaminating our kernel not
   with Microsoft's code but with open-source code.

**Clean-room note.** Classic clean-room separates the *reader* of the reference from the
*writer* of the new code. An LLM fuses reader and writer inside one statistical model, so
the separation cannot be proven. This is *why* Article 4 (generate `abi/` from Wine headers;
never recall constants) and the rule below exist.

## Mandated provenance discipline

- **Fix the kernel license before M13.** If GPL is acceptable, the ReactOS-reproduction
  risk is neutralized (the outputs would be license-compatible). If a permissive license is
  desired, restrict the model's reference material for kernel code to **Wine headers and
  official Microsoft documentation**, and generate `abi/` mechanically (Article 4).
- **Drivers from specifications only**, never from GPL source translation.
- **`abi/` numeric values generated**, never hand-copied or model-recalled (Article 4).
- Record provenance in `docs/provenance.md` as components are added.

## Why the boundary choice helps here too

The same property that makes the boundary testable (it is small, observable, and already
specified by Wine's *headers and tests*) also makes it possible to build the kernel's
contract **without ever reading Microsoft's or ReactOS's implementation** — from Wine's
public headers and MS's public docs. The clean boundary is also the clean-provenance
boundary. As with everything else in this project, choosing the clean boundary pays a
dividend the dirty one never could.
