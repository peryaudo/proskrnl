# 11 — Licensing & Provenance

Licensing here is not paperwork — it is a **project-survival** concern, for two distinct
reasons: the multi-upstream code map, and the LLM-provenance risk. Per Constitution
Article 8 the kernel license is fixed: **GPL-2.0** — the full text lives in the repository
root `LICENSE`.

## The upstream license map

| Component | Origin | License |
|---|---|---|
| `kernel/`, `abi/`, `arch/`, `drivers/`, `fs/` | proskrnl | **GPL-2.0** (`LICENSE`) |
| Wine PE DLLs, wineserver-lite | Wine | **LGPL-2.1** |
| ReactOS shell (optional GUI-7), its INF data | ReactOS | **GPL-2.0** |
| `third_party/flanterm` (the boot console's glyph renderer) | Flanterm | **BSD-2-Clause** |

## Third-party code inside the kernel image

The default is that no third-party code is linked into the kernel: everything under
`third_party/` is either build/run tooling or user-mode. Flanterm is the one exception,
and it sets the rule for any future one — a third-party component may be **linked into
the GPL-2.0 kernel image** only when all of these hold:

- its license is **permissive and GPL-2.0-compatible** (BSD-2-Clause here) — never a
  copyleft or GPL-incompatible one;
- it is a **pinned submodule of the official upstream, used unmodified**: no vendored
  copy, no local patches, no build-time patching, so its provenance stays a single sha;
- we call its **public API only** and translate none of it — its source is not reference
  material for our own code (the Art. 8 / `docs/11` "reference material" rule below is
  unchanged: Wine headers and MS documentation);
- it is recorded in `docs/provenance.md` with the license named.

## Route (a) and the kernel image

The kernel talks to Wine/wineserver-lite across a **process boundary** (syscalls; shared
sections; pipes). Under route (a), wineserver-lite stays a **separate LGPL process** and no
LGPL/GPL code is linked into the kernel image — the upstream licenses never touch the
kernel at all.

Under **route (b)** (desktop state moved into `kernel/win32k`), LGPL Wine-derived code
would enter the kernel image. With the kernel licensed **GPL-2.0** this is permitted —
LGPL-2.1 code may be conveyed under GPL-2 (LGPL-2.1 §3) — so route (b) is not
license-blocked; it remains avoided for the engineering reasons in `docs/07`.

## The GPL/LGPL interaction (for the optional shell)

If the ReactOS shell is adopted (GUI-7): explorer.exe is **GPLv2**; it calls Wine DLLs that
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

- **The kernel license is GPL-2.0** (`LICENSE`), fixed well before GUI-3. This neutralizes
  the ReactOS-reproduction *license* risk — any such output would be license-compatible.
  The reference-material restriction stands regardless: kernel-code reference material is
  **Wine headers and official Microsoft documentation** only, because provenance and
  attribution must stay traceable even when licenses are compatible; `abi/` is generated
  mechanically (Article 4).
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
