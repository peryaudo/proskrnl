# 07 — GUI Strategy

GUI is **opt-in, additive, and removable**. It sits outside the CUI core; deleting
`user/wine/`, `drivers/fb.c`, `drivers/hid.c` leaves the M10 kernel intact.

## Why GUI is tractable here at all

Wine already solved win32k's hard half. Wine's approach to the "win32k problem" was:
**the upper half** (messaging, window management, `DefWindowProc`, controls) solved by
brute force over 30 years and living as **PE code**; **the lower half** (rasterization +
connection to a window manager) delegated to the host. Two tailwinds follow:

1. Modern Wine's **GDI upper half is also self-contained** — `dibdrv` rasterizes in
   software; fonts via FreeType. The GPU can draw zero pixels and everything still renders
   to an in-memory bitmap.
2. Wine's display-driver interface already supports **non-X11 backends** (null / framebuffer
   shapes).

So the question is never "write win32k" — it is **"write the smallest backend for Wine's
display-driver interface,"** plus route input, plus decide where cross-process desktop
state lives.

## Two routes; we ship (a)

|  | Structure | The NT it *is* |
|---|---|---|
| **(a)** | a user-mode server holds desktop state; clients talk to it over IPC | **NT 3.1** (USER/GDI in a subsystem, LPC to clients) |
| **(b)** | the kernel holds desktop state | **NT 4.0** (win32k) |

Both are real NT. We ship **(a)** because it avoids the expensive surgery of transplanting
wineserver's GUI objects (with their `struct object`/refcount/handle-table) onto our Ob;
keeps the desktop server as a separate LGPL process (clean kernel license); and is trivially
removable. Microsoft went (a)→(b) for performance; if we ever need to, we do the same —
*after* (a) works, using it as a regression baseline. (Modern Wine avoids the NT-4.0
performance motive differently, via shared memory for hot read paths — the same escape
hatch is available to us before ever considering (b).)

## The kernel additions (all of GUI's kernel cost)

Just **two drivers**, both logged in `docs/10`:

- **`\Device\Fb0`** (HACK-001) — maps the framebuffer to user mode. QEMU ramfb or
  virtio-gpu 2D scanout; a few hundred lines. NT would own this behind a display driver.
- **`\Device\Input0`** (HACK-002) — raw keyboard/mouse events to user mode; a few hundred
  lines. NT routes this through win32k/csrss.

`kernel/`, `abi/`, `arch/`, `fs/` gain **nothing** under route (a). No `NtUser*` syscalls
are minted.

## The user-mode additions

- **`winefb.drv`** — a display backend written *as a Wine driver* (implements
  `user_driver_funcs`). Enumerates a mode, maps `\Device\Fb0`, blits `dibdrv`'s composed
  bitmap to scanout, draws the cursor, and creates the desktop window as *the whole
  framebuffer*. Simpler than winex11 because there is no host WM to negotiate with.
- **win32u unix side, built as PE** (POSIX → our `Nt*`; FreeType statically linked).
- **wineserver-lite** (route (a)) — see `docs/06`. Transport: **shared section + two kernel
  events**, *not* npfs. This is what pulls calc.exe off the npfs critical path.

## The one genuine friction: unified waiting

In Wine, *all* waiting goes through wineserver; in proskrnl, waiting is the kernel's job.
The clash is `MsgWaitForMultipleObjects` (wait on events *and* the message queue at once).
Resolution: **back the message queue with a kernel event.**

```
win32u: NtWaitForMultipleObjects([user handles..., queue_event])
                                                     ^
wineserver-lite: SetEvent when the queue becomes non-empty
```

wineserver's msg_queue already has a "signalled" concept, so "wait in the server" becomes
"the server sets an event." Re-check wake bits on wakeup; spurious → wait again (Wine
already has this logic). `SendMessage`'s re-entrant pump forms the same way. Bonus: user
APCs and alertable waits become the kernel's real mechanism — closer to NT than Wine is.

## The WM-conflict dividend

No host window manager means the class of non-compat Wine can never fix on Linux — focus
stealing, Z-order authority, override-redirect, minimize behaviour — **vanishes**. Each
app's `DefWindowProc` draws its own non-client frame (title bar, close/minimize buttons);
win32k-lite only decides which window is where, in what Z-order, clipped how. This is the
payoff of the boundary choice, collected: the parts Wine solved by force we inherit as
assets; the parts it couldn't solve disappear with the environment.

## Who implements the close/minimize buttons?

**Wine, entirely.** The whole window (title bar, borders, buttons) is *non-client area*,
drawn by the app — which in practice means every app calls the same `DefWindowProc`, i.e.
Wine's `user32`. A click travels: our `hid` driver → `\Device\Input0` → wineserver-lite
routes by coordinate → `WM_NCHITTEST` (DefWindowProc → `HTCLOSE`) → `WM_NCLBUTTONDOWN` →
`WM_SYSCOMMAND(SC_CLOSE)` → `WM_CLOSE` (the one message the app sees) → `DestroyWindow`.
We touch only the entrance (input device) and exit (framebuffer); everything between is
Wine's 30-years-tuned code, verified by `user32/tests/msg.c`. Minimized windows, with no
taskbar present, fall back to USER's old Win3.1 behaviour — which is why a shell is not
needed for a usable windowing system.

## Milestones

M11 (pixels/input) · M12 (win32u + winefb.drv, single process → **calc.exe on screen**) ·
M13 (wineserver-lite, multi-process state ⛰️) · M14 (compositing + input routing) ·
M15 (clipboard/hooks/`AttachThreadInput`/GUI conhost + `msg.c`) · M16 (Wine desktop).

## Verification

QEMU monitor `screendump` dumps the framebuffer as PPM, so the M1 loop (build → run →
inject events → screendump → compare golden → exit code) works unchanged for GUI. Semantics
are judged by `msg.c`. The plumbing is hacky; the *semantics* are all borrowed and
Windows-verified — which is why the "90%-done, 90%-left" trap (sprung only when authoring
semantics yourself) is not sprung here.

## The "downgrade, don't discard" rule for hacks

When hacks are permitted for GUI, do not abandon "no NT-absent entities" — *downgrade* it
to: **NT-absent things may be added only as new devices or new processes at the outside of
the boundary, never inside existing `Nt*` or Wine PE code.** This keeps hacks additive:
if GUI collapses, subtract the ledger entries and the CUI kernel remains untouched.

## Risks (honest)

- **user32/gdi32 PE reading shared memory** — Wine may expect some window info via a shared
  section (`GetWindowLong` fast path); the kernel/server may need to supply it. Main source
  of M13 estimate uncertainty.
- **Fonts** — statically linking FreeType into PE means peeling Wine's unix-assuming build;
  metrics must match (dialog layout depends on them). Same FreeType + fonts as Wine-on-Linux
  ⇒ same numbers ⇒ oracle exists.
- **License** — under route (a), wineserver-lite stays a separate LGPL process, so the
  kernel license is unconstrained. (Route (b) would embed LGPL in the kernel — decide before
  attempting it.)
