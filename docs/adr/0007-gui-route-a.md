# ADR 0007 — GUI via route (a): a user-mode wineserver-lite desktop server

**Status:** Accepted

## Context
Cross-process desktop state (window tree, Z-order, focus, input queue, clipboard, atoms)
must live somewhere. Route (a) keeps it in a user-mode server (this is NT 3.1's actual
architecture); route (b) moves it into a kernel win32k (NT 4.0). Both are real NT. Route (b)
requires transplanting wineserver's GUI objects — with their refcounts and handle tables —
onto our Ob, and embeds LGPL code in the kernel.

## Decision
Ship route (a): run a **stripped wineserver** (only window/queue/hook/clipboard/atom
survive; sync/registry/file/etc. are the kernel's) as a PE process. Transport is a **shared
section + two kernel events**, not npfs. Migrate to (b) later only if performance demands
it, using (a) as a regression baseline — mirroring Microsoft's own (a)→(b) history.

## Consequences
- ~half the GUI cost: no transplant surgery; we do not fight Wine's structure.
- Clean license: the desktop server stays a separate LGPL process; the kernel license is
  unconstrained.
- Trivially removable: `rm -rf user/wine/ drivers/fb.c drivers/hid.c` restores the CUI
  kernel.
- The one genuine friction is `MsgWaitForMultipleObjects`: solved by backing the message
  queue with a kernel event. Bonus: user APCs/alertable waits become the kernel's real
  mechanism, moving us closer to NT.
- Pulls calc.exe off the npfs critical path (shared-section transport, not named pipes).
