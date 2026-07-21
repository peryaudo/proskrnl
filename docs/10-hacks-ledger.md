# 10 — Hacks Ledger

Every deliberate NT-absent addition is recorded here, in one format. This ledger is the
enforcement mechanism for Constitution Article 2 (downgraded rule) and Article 7
(additive/removable). **Its length is a metric:** if it grows beyond the entries below, the
design has drifted from "no hacks" toward ReactOS's compounding tax.

Rules for an entry:
- The addition lives **only** as a new device or new process at the *outside* of the
  boundary — never inside existing `Nt*` or Wine PE code.
- It has a **retirement condition**: the concrete state of the world under which it is
  deleted.
- It is **subtractable**: removing its files restores the prior kernel intact.

---

## Format

```
## HACK-NNN: <name>
Status:     proposed | active | retired
Introduced: <milestone>
Not in NT:  <what NT does instead>
Reason:     <why we add it anyway>
Scope:      <files touched — must be new files at the boundary's outside>
Retirement: <the condition under which this is deleted>
```

---

## HACK-001: `\Device\Fb0`

```
Status:     proposed
Introduced: GUI-1
Not in NT:  NT owns the framebuffer behind a display driver, below win32k (WDDM/XDDM).
Reason:     We implement no display-driver model; win32u needs somewhere to blit.
Scope:      drivers/fb.c ; user/wine/winefb.drv/display.c
Retirement: if an NtGdi-side display-driver abstraction is ever built.
```

## HACK-002: `\Device\Input0`

```
Status:     proposed
Introduced: GUI-1
Not in NT:  NT routes raw input through win32k / csrss into the input queue.
Reason:     win32u needs a raw keyboard/mouse event source.
Scope:      drivers/hid.c ; user/wine/winefb.drv/input.c
Retirement: if input routing moves into a kernel win32k (route (b)).
```

## HACK-003: wineserver-lite as a user-mode desktop server

```
Status:     proposed
Introduced: GUI-3 (route (a))
Not in NT:  NT holds desktop state in kernel win32k (since NT 4.0). NOTE: this is a
            return to NT 3.1's architecture, so it is only "not in NT 4.0+", not
            un-NT-like in principle.
Reason:     Reusing Wine's 30-years-tuned GUI state code without transplanting it onto Ob;
            keeps a clean kernel license; trivially removable.
Scope:      user/wine (stripped server build) ; transport via shared section + 2 events
Retirement: if/when route (b) moves desktop state into kernel/win32k.
```

## HACK-004: serial-backed console (COM1 ↔ condrv)

```
Status:     active (M9: \Device\Serial0 over the UART, RX polled — no IRQ4;
            conhost opens it as its tty both ways)
Introduced: M9
Not in NT:  conhost's input arrives from win32k's raw input path (i8042prt/kbdclass →
            win32k → conhost) and its output is drawn into a window. A COM port is never
            the interactive console's transport. (NT's EMS/SAC serial console is a
            separate management channel, not condrv's backend.)
Reason:     M9 needs interactive console I/O before any display or keyboard hardware
            exists (both are GUI-1+). The 16550 is bidirectional, already carries all
            kernel output, and a socket/pty chardev keeps the headless scripted test
            loop (docs/08) unchanged — the cheapest input source an LLM-driven runner
            can drive deterministically.
Scope:      drivers/condrv.c (backend hookup) ; arch/x86_64/serial.c (RX side)
Retirement: when the real input path (\Device\Input0, GUI-1 / HACK-002) exists and conhost
            is GUI-ified (GUI-5), delete the serial backend; condrv's transport becomes
            the input queue + window like real NT.
```

---

## Non-hacks (recorded here to prevent re-litigation)

These are sometimes *mistaken* for hacks but are real NT mechanisms, so they carry **no**
ledger entry and no retirement condition:

- **WOW64 / 32-bit support** — NT's real mechanism. Kernel cost is a few hundred lines; no
  `Nt*` semantics change.
- **conhost + condrv** — real NT (Vista/Win8) architecture; adopted, not invented. (Their
  M9 *serial transport* is not NT, and is the logged item — HACK-004.)
- **smss-equivalent initial process** — real NT boot structure.
- **Section objects, APCs, unified waiting, handles** — the NT core we deliberately keep.
- **Shared-section transport for wineserver-lite** — NT itself uses shared sections between
  win32k and user mode; this is NT-spirited, not a hack. (Only wineserver-lite's
  *existence as a separate server* is the logged item, HACK-003.)

## Simplifications are not hacks either

The Article 3 mandates (no COW, no eviction, one lock, uniprocessor) are **deviations from
NT's implementation, not from its observable semantics.** They belong in
`docs/03-nt-deviations.md`, not here — a hack adds an NT-absent entity; a simplification
removes an unobservable optimization.
