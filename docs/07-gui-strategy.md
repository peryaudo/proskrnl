# 07 — GUI Strategy

*(Written before GUI-1; revised after GUI-2. Claims below that GUI-1/GUI-2 tested are
marked with what actually happened — see also the "GUI-2 notes" in `docs/03`.)*

GUI is **opt-in, additive, and removable**. It sits outside the CUI core; deleting
`user/wine/`, `drivers/fb.c`, `drivers/hid.c` leaves the M10 kernel intact. (What GUI-2
did pull into the kernel — registry symlinks, two boot directories, see below — is
NT-present boundary surface with its own G5 pins, kept regardless of GUI.)

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
performance motive differently, via shared memory for hot read paths — and GUI-2 already
ships that mechanism: win32u reads hot state out of the session section,
`\KernelObjects\__wine_session`, exactly as under Wine.)

## The kernel additions (all of GUI's kernel cost)

Just **two drivers**, both logged in `docs/10`:

- **`\Device\Fb0`** (HACK-001) — maps the framebuffer to user mode. **Built at GUI-1** over
  the linear framebuffer Limine sets through the VGA BIOS's VBE (QEMU's default stdvga), which
  turned out to need no display driver of our own at all: ~230 lines, no virtio-gpu, no ramfb,
  no mode set. Mapping rides the existing section path (`GetCache`), so `kernel/mm` gained
  nothing. NT would own this behind a display driver.
- **`\Device\Input0`** (HACK-002) — raw keyboard/mouse events to user mode; a few hundred
  lines. NT routes this through win32k/csrss. **Built at GUI-1** as a virtio-input
  keyboard (eventq polled from a blocking read, no IRQ path); the pointer device joins at
  GUI-4, when there is routing for it to feed.

No `NtUser*` syscalls are minted, and `kernel/`, `abi/`, `arch/`, `fs/` gain **no
NT-absent entities** under route (a). What GUI-2 *did* pull into the kernel — each
NT-present, G5-pinned, and not GUI-specific — was ordinary NT surface nobody had consumed
before: the `\KernelObjects` and `\Sessions\1\Windows\WindowStations` boot directories
(`sem_ob/session_dirs`), and Cm registry symbolic links (`REG_OPTION_CREATE_LINK`,
`sem_reg/symlink` — win32u's display-device commit writes and resolves them). That is the
pattern to expect from the remaining milestones: GUI exposes unconsumed NT boundary
surface rather than adding kernel machinery of its own.

## The user-mode additions

- **`winefb.drv`** ✅ (GUI-2) — a display backend written *as a Wine driver*. Landed even
  simpler than budgeted: four `user_driver_funcs` entries (`pUpdateDisplayDevices`,
  `pCreateWindowSurface`, `pWindowPosChanged`, `pSetDesktopWindow`) plus a surface flush —
  the `nulldrv_*` defaults are right for a framebuffer with no host WM to negotiate with,
  including the one that flushes surfaces on every message wait (the flush clock the
  driver would otherwise invent; per-window surfaces and dirty rectangles are GUI-4).
- **win32u unix side, built as PE** ✅ (GUI-2; `user/wine/win32u`). user32/gdi32/imm32
  bind to it by name, unmodified — all ~434 `NtUser*`/`NtGdi*` imports, checked at build
  time (`tools/gen_win32u_def.py`). FreeType is pinned and cross-built as a PE static
  library (`third_party/freetype`, `tools/build_freetype.sh`).
- **wineserver-lite** (route (a)) — see `docs/06`. **Already running since GUI-2, but
  in-process**: the pinned server's GUI object model (window/queue/hook/clipboard/atom)
  compiled unmodified into win32u.dll behind an in-process `wine_server_call`
  (`user/wine/server/shim.c`; 120 of 308 request handlers link, the rest refuse by name
  from a generated table). GUI-3's job shrank accordingly: not *build* the server —
  give it a process boundary. Transport: **shared section + kernel events**, *not* npfs
  (which is what pulled the first-pixels path off the npfs critical path, as planned).

## The one genuine friction: unified waiting — *resolved at GUI-2*

In Wine, *all* waiting goes through wineserver; in proskrnl, waiting is the kernel's job.
The clash is `MsgWaitForMultipleObjects` (wait on events *and* the message queue at once).
Resolution, **built a milestone early** because it was also the simplest thing that
worked: **back the message queue with a kernel event.**

```
win32u: NtWaitForMultipleObjects([user handles..., queue_event])
                                                     ^
wineserver-lite: SetEvent when the queue becomes non-empty
```

wineserver's msg_queue already had exactly the seam hoped for: a queue's signalled state
is a `struct object *sync` driven by `signal_sync`/`reset_sync` (`server/queue.c`), so
the shim implements that one object as an NT event (`create_internal_sync` →
`NtCreateEvent`; `signal_sync`/`reset_sync` → `NtSet/ResetEvent`,
`user/wine/server/shim.c`) and win32u's existing wait in `wait_message` blocks and wakes
with **no changes to the message loop**. Wake bits are re-checked on wakeup; spurious →
wait again (Wine's own logic). GUI-3 keeps the mechanism unchanged — only the process
that calls SetEvent moves. Bonus, still standing: user APCs and alertable waits are the
kernel's real mechanism — closer to NT than Wine is.

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

GUI-1 (pixels/input) ✅ · GUI-2 (win32u + winefb.drv, single process →
**winemine.exe on screen**) ✅ · GUI-3 (wineserver-lite becomes a process ⛰️ — the
mountain, half-climbed at GUI-2) · GUI-4 (compositing + input routing) ·
GUI-5 (clipboard/hooks/`AttachThreadInput`/GUI conhost + `msg.c`) · GUI-6 (Wine desktop).
Current wording and done-criteria live in `docs/02`; the deliberate GUI-2 single-process
shortcuts that GUI-3 must retire are in `docs/03` "GUI-2 notes".

## Verification

QEMU monitor `screendump` dumps the framebuffer as PPM, so the M1 loop (build → run →
inject events → screendump → compare golden → exit code) works unchanged for GUI —
confirmed twice now: `tests/run/run.sh gui` (GUI-1 rectangle + QMP `send-key`) and
`tests/run/run.sh gui2` (winemine's window rect reported by the guest, pixels judged by
QEMU's device model). One learned detail: dump the *settled* frame — with the GUI-2 flush
clock an idle app paints once and stops, so the harness owns QEMU's lifetime and waits
for the frame to stabilize rather than for a flush count. Semantics are judged by
`msg.c`. The plumbing is hacky; the *semantics* are all borrowed and Windows-verified —
which is why the "90%-done, 90%-left" trap (sprung only when authoring semantics
yourself) is not sprung here.

## The "downgrade, don't discard" rule for hacks

When hacks are permitted for GUI, do not abandon "no NT-absent entities" — *downgrade* it
to: **NT-absent things may be added only as new devices or new processes at the outside of
the boundary, never inside existing `Nt*` or Wine PE code.** This keeps hacks additive:
if GUI collapses, subtract the ledger entries and the CUI kernel remains untouched.

## Risks (honest, rescored after GUI-2)

- **user32/gdi32 PE reading shared memory** — *materialized, and mostly retired.* This was
  called "the main source of GUI-3 estimate uncertainty"; it turned out to be real (the
  pinned tree reads user entries and desktop/queue state through the session mapping,
  `server/mapping.c` / `dlls/win32u/winstation.c`) and GUI-2 already supplies it: the
  session mapping is a real named NT section (`\KernelObjects\__wine_session`) that
  win32u opens read-only by name exactly as under Wine, pinned by `sem_mm/session_shm`.
  What GUI-3 still owes is only moving the writer out of the client process.
- **Fonts** — *collected at GUI-3.* Peeling Wine's unix-assuming build worked at GUI-2
  (FreeType pinned, cross-built as a PE static library), but the promised metrics oracle
  did not exist: the pinned Wine was `--without-freetype`, so the two builds shared no
  font backend. GUI-3 took the scheduled decision and reconfigured the pin
  `--with-freetype --without-fontconfig` against the *same* `third_party/freetype`, built
  native by the same script — so backend, version and font set now agree on both sides
  and "same FreeType ⇒ same numbers" is a fact rather than a plan. This was not
  touched-oracle territory: no font test existed to fail, so the spec was *extended*
  rather than moved to make something pass (docs/03 "the font oracle"). Dialog-layout
  tests (GUI-5) are unblocked; what is still owed there is the metric differential
  itself — GUI-3 pins only that the oracle's backend loads and answers
  (`tests/gdi/fontsmoke.c`), which guards a real failure mode, since win32u `dlopen`s its
  backend and silently falls back to *no fonts* rather than failing.
- **Machine-state furniture** — *the risk class that actually bit, unlisted here before.*
  None of GUI-2's six stacked boot stalls were in the predicted spots; most were furniture
  Wine's userland assumes exists: registry symlinks under `Control\Video`, the
  `HKU\<sid>` root the font loader opens, the ole32 delay-import chain (the rest were two
  in-process-glue bugs and the single-process desktop fixtures, docs/03 "GUI-2 notes").
  Assume the same shape at GUI-6 — explorer/shell32 assume strictly more machine state
  than winemine.
- **License** — unchanged in substance. The LGPL server sources currently compile into
  win32u.dll — a user-mode PE, still outside the GPL-2.0 kernel image; route (a)'s end
  state moves them into a separate LGPL process at GUI-3. (Route (b) would embed
  LGPL-2.1 code in the kernel — compatible with GPL-2.0, so not license-blocked; route
  (a) is preferred on engineering grounds alone.)
