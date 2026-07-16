# 01 — Major Trade-offs

Each decision below is stated as a trade: what we give up, what we get, and the
reasoning. These are the load-bearing choices. Reversing any of them changes the
project into a different (and mostly harder) one.

## T1 — Drop Windows driver binary compatibility

**Give up:** running unmodified Windows kernel-mode drivers (and therefore AV,
anti-cheat, VPN, backup drivers — the things people actually install drivers for).

**Get:** deletion of the largest and dirtiest part of NT — IRP, driver stacks, PnP,
power, the kernel-mode PE loader for drivers, the hundreds of `Io*/Ke*/Mm*` exports,
and the obligation to reproduce IRQL semantics for third parties.

**Why:** the driver boundary is a contract over **struct layouts and context-dependent
timing**, not over function calls. There is no marshaling point; drivers share the
kernel's address space and read fields like `IRP->IoStatus` at compile-time-baked
offsets (see `docs/03-nt-deviations.md`). This boundary is untestable and
non-redesignable. Microsoft itself broke it twice (x64, ARM64) because it *could not*
be preserved across an address-width change. ReactOS spent 30 years imprisoned by it.
We refuse it on day one. This is the decision that makes everything else possible.

## T2 — CUI is the final supported target; GUI is an opt-in hack

**Give up:** being a general-purpose desktop OS. Most real Windows demand is GUI demand.

**Get:** we never have to write win32k as NT built it — a >1000-entry, cross-process
concurrent state machine of message ordering, plus GDI (a rasterizer + font engine),
together larger than the entire rest of the kernel.

**Why:** win32k is hard not because of struct-offset archaeology (that part is actually
clean) but because its "public API" is a **temporal protocol** — message order, timing,
re-entrancy, `DefWindowProc`'s per-message behaviour — that apps depend on by observation,
not documentation. Cutting the CUI scope closes the entrance to that swamp. It is the
single highest-leverage decision after T1.

*Caveat:* a GUI path still exists, but by reusing Wine's win32u/user32 (which already
solved the temporal-protocol problem) rather than reimplementing it. See T7 and
`docs/07-gui-strategy.md`.

## T3 — Reuse Wine's PE user-land; replace only ntdll's unix backend

**Give up:** owning the user-mode stack; independence from Wine's release cadence.

**Get:** 30 years of Win32 compatibility, for free, as data. Modern Wine already splits
each DLL into a **PE side** (Windows logic) and a **unixlib side** (host calls) across a
thin, explicit boundary. We keep the PE side and point the unixlib side at our own
syscalls — which is exactly the structure NT itself has (a PE ntdll that syscalls).

**Why:** Wine's value is almost entirely in the PE side; the unix side is thin plumbing.
The split Wine created for its own reasons (copy-protection resistance) happens to be
exactly the seam we need. This is not a hack against Wine's design; it *is* Wine's design.

## T4 — "Stupidly correct" internals: no COW, no eviction, one big lock, uniprocessor

**Give up:** performance, memory efficiency, SMP (initially).

**Get:** the elimination of ~90% of the difficulty in Mm and Ke. The Mm/Cc/Io triangle
that ReactOS is *still* rewriting after 30 years collapses when the cache is unified,
nothing is evicted, writeback is immediate, and there is one dispatcher lock. The
mapped-view/`ReadFile` consistency that is NT's genuine hard problem becomes
*structurally trivial* because everything looks at the same page-cache page.

**Why:** every source of difficulty in these components — COW, eviction, writeback
windows, fine-grained locking, SMP, kernel preemption — is **unobservable from user
mode**, i.e. it is a performance concern, not a contract. We sell semantics, not speed.
This is also our defence against being unable to review the hardest code: **a bug that
cannot exist does not need to be reviewed** (see `docs/09-constitution.md`, `docs/12`).

## T5 — Route (a) for GUI: keep a stripped wineserver as a user-mode desktop server

**Give up:** having the desktop state (window tree, Z-order, focus, input queue) inside
the kernel, as real win32k does.

**Get:** roughly half the GUI implementation cost, a clean license story (the desktop
server stays a separate LGPL process, the kernel stays uncontaminated), and trivial
removability (`rm -rf user/wine/ drivers/fb.c drivers/hid.c`).

**Why:** this is literally NT 3.1's architecture (USER/GDI in a user-mode subsystem,
talking to clients over IPC). Route (b) — moving that state into the kernel — is NT 4.0.
Both are real NT. Route (a) avoids the expensive part (transplanting wineserver's GUI
objects onto our Ob) entirely. Ship (a); migrate to (b) later only if performance
demands it, exactly as Microsoft did. See `docs/07-gui-strategy.md`.

## T6 — x86-64 only; WOW64 for 32-bit apps, added last

**Give up:** i386-native simplicity and Wine's most-mature 32-bit path.

**Get:** the cleaner ABI. x64 is where Microsoft burned 30 years of debt — table-based
SEH instead of stack-chained `fs:[0]` frames, one calling convention instead of the
`__cdecl/__stdcall/__fastcall/__thiscall` zoo. Our `ps/usermode.c` exception delivery is
*simpler* on x64.

**Why:** 32-bit apps still run — via WOW64, which lives entirely in user mode (the
32→64 transition never reaches the kernel) and costs the kernel only a few hundred
lines. But WOW64 is purely additive, touches no semantics, and `calc.exe` is 64-bit, so
it goes last. See `docs/03` §WOW64.

## T7 — Use Wine's desktop, not ReactOS's shell (initially)

**Give up:** a Windows-looking desktop (taskbar, Start menu, desktop icons).

**Get:** deletion of the entire two-upstream integration risk — shell32 collision,
version mismatch (NT 5.2 vs. Win10), extracting modules from ReactOS's build system, the
GPL/LGPL map, and "nobody has tried this combination." Wine's explorer + Wine's shell32
are the *same upstream, same assumptions, same CI, tested daily*.

**Why:** window frames, the close/minimize buttons, and hit-testing are USER's job, not
the shell's; they work with zero shell present. Wine's `wineboot` initializes the
registry (hundreds of CLSIDs) at runtime by calling our `NtCreateKey`, which also serves
as our Cm integration test. ReactOS's richer shell becomes an optional later milestone,
not a dependency. See `docs/06-userland-strategy.md`.

## Trade-off summary

| # | Decision | Primary thing given up | Primary thing gained |
|---|---|---|---|
| T1 | Drop driver ABI | Real Windows drivers | The whole IRP/PnP/IRQL swamp |
| T2 | CUI final | Desktop-OS demand | win32k (bigger than the kernel) |
| T3 | Reuse Wine PE | Independence | 30 yrs of Win32, for free |
| T4 | Stupidly correct | Performance, SMP | 90% of Mm/Ke difficulty |
| T5 | GUI route (a) | Kernel-side desktop state | Half the GUI cost; clean license |
| T6 | x64 only | i386 simplicity | The cleaner ABI |
| T7 | Wine desktop | Windows-looking shell | The two-upstream integration risk |

Every one of these is the same move applied to a different target: **avoid the dirty
boundary, take the clean one.** T1 avoids the driver ABI. T2 avoids win32k's temporal
protocol. T4 avoids the concurrency/optimization swamp. T7 avoids the undocumented
explorer↔shell32 seam. The through-line is the whole project.
