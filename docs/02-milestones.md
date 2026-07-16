# 02 — Milestones

Each milestone closes on **a runnable artifact + a verification method**. Never on "code
written." The empirical effort split is roughly: **M1–M6 = 40%, M7 alone = 30%,
M8–M16 = 30%**. M7 is both the biggest mountain and the biggest return.

Ordering rules that matter:
- **No separate "prerequisites" phase.** There is no M0. The xv6 labs a prep phase would
  have run are unnecessary under Article 3 — you never write COW, eviction, or fine-grained
  locking, so there is nothing to rehearse. The QEMU build→run→exit-code→log harness is the
  first task *of M1*, proven on a trivial payload before any kernel logic. See `docs/12`.
- **RAM-disk before real Mm** (M5 seeds it) to break the Mm↔Io circular dependency.
- **Test-first, per milestone (Article 5).** For each milestone, write the `tests/ntapi/`
  cases for exactly the `Nt*` it implements, green them on the Wine/Windows oracle *first*,
  then implement until they pass on proskrnl. Do not author the whole boundary suite up
  front. The suite grows monotonically, and the proskrnl run is gated by a `todo_proskrnl`
  manifest so it is always green-or-regression rather than a sea of expected reds. See
  `docs/08`.
- **The critical path to calc.exe deliberately excludes npfs/condrv/conhost/cmd.** See
  the GUI note below and `docs/07`.

---

## M1 — Boot and kernel scaffold
Minimal loader path (Limine/Multiboot2) into long mode; serial console; IDT/exception
handlers; timer interrupt; physical page allocator. NT loader protocol is unnecessary
(binary compat dropped), so ride an existing boot protocol.
**Do first:** get the QEMU loop (build → run → `isa-debug-exit` code → serial log) green on
a trivial "hello over serial" payload *before* writing kernel logic, so the harness is never
a variable while you debug (see `docs/08`).
**Done when:** boots in QEMU; an exception dumps registers over serial; the timer ticks.
**Do on day one:** thick panic handler (register dump, stack trace, last syscall) — this
is the LLM's eyes for the rest of the project.

## M2 — In-kernel multithreading
Kernel page-table management; pool allocator; kernel threads + context switch; priority
scheduler; **dispatcher objects** (event/mutex/semaphore/timer) and `KeWaitFor*`. Get NT
semantics (notification vs. synchronization events, wait-all/any) exactly right here.
**Done when:** in-kernel test — threads ping-pong on events/mutexes; timed waits time out
correctly.

## M3 — Ob: handles and namespace
Object manager (type system, refcount, handle table); `\Device` and `\??` namespaces;
`NTSTATUS` conventions. Move M2's dispatcher objects under Ob.
**Done when:** a named event opened from two places resolves to one object; closing a
handle drops the ref correctly.

## M4 — User mode and the syscall boundary
User address-space separation; `syscall/sysret` entry; TEB allocation;
`NtAllocateVirtualMemory` (reserve/commit); first `Nt*` group. Test client is a flat
binary, not yet a PE.
**Done when:** user-mode code allocates memory and waits on an event via syscalls; a
user crash is contained as process termination, not a kernel fault.

## M5 — Sections and image mapping
Seed a RAM-disk + trivial read-only FS first. Then section objects: anonymous,
file-backed, and PE image sections (per-section protection, relocation copy). Guard-page
stack growth. **Under T4: no COW initially** — private/image mappings copy fully on map.
**Done when:** `NtCreateSection` + `NtMapViewOfSection` maps a PE image; the mapped-view /
`ReadFile` consistency test passes (structurally trivial under the unified page cache).

## M6 — I/O manager and a real filesystem
Async I/O skeleton (IOSB update rules, APC/event completion); `NtCreateFile/ReadFile/
WriteFile/QueryInformationFile/QueryDirectoryFile` main info classes; virtio-blk driver;
FAT32. NT-specific semantics land here: share modes, case-insensitivity, delete-on-close,
byte-range locks.
**Done when:** the file-semantics suite is green (e.g. share-mode violation →
`STATUS_SHARING_VIOLATION`); M5's image mapping works from an on-disk file.

## M7 — NtCreateUserProcess + Wine ntdll ⛰️ (the mountain)
PEB/TEB/`RTL_USER_PROCESS_PARAMETERS`/KUSER_SHARED_DATA layout; `NtCreateUserProcess`;
`KiUserExceptionDispatcher`/`KiUserApcDispatcher` return protocol; thread creation. Then
bring in Wine's ntdll PE side with its unixlib replaced by our syscall stubs. Place the
NLS files ntdll reads at startup.
**Done when:** a `hello.exe` linked only against ntdll starts and exits; an SEH test
(deliberate access violation caught by `__except`) passes. **After this, the rest of Wine
is data.**

## M8 — Cm (registry) + the initial process chain
Hive read/write (our own format); `NtCreateKey/SetValueKey/QueryValueKey`; boot-time
SYSTEM hive mount. An smss-equivalent initial process (mount hive, set `\??` drive
letters, launch next).
**Done when:** a value written by a user program survives reboot; boot completes as
kernel → smss-equiv → test process.

## M9 — npfs, condrv, interactive console *(off the calc critical path)*
Named-pipe FS (byte/message mode, listen/connect via `NtFsControlFile`); a ConDrv-style
console device; keyboard driver; port Wine's conhost.
**Done when:** input echoes through conhost; the pipe client/server test (message-mode
behaviour rpcrt4 needs) passes.
*Note:* if pursuing calc.exe first, this milestone moves **after** the GUI path — see below.

## M10 — Full Wine user-land (CUI)
kernelbase/kernel32, msvcrt, advapi32, rpcrt4, services.exe, Wine's cmd.exe; full
`CreateProcess` paths (env/handle inheritance, cwd), completion ports, DLL search order.
**Done when:** cmd.exe prompts; pipes/redirection work; an off-the-shelf MSVC-built CUI
app runs unmodified. Ideal regression: the CUI subset of Wine's own test suite.

---

## GUI path (opt-in, additive, route (a) — see docs/07)

> **calc.exe does not need npfs/condrv/conhost/cmd.** Give wineserver-lite a
> shared-section + two-event transport instead of npfs, and the critical path to a
> window shortens by months. npfs (M9) and cmd (M10) can come *after* the calculator.

## M11 — Pixels and input
virtio-gpu (2D scanout) or ramfb; virtio-input. `\Device\Fb0` (map framebuffer to user)
and `\Device\Input0` (input event stream). **HACK-001 and HACK-002** (see `docs/10`).
**Done when:** a user program maps the framebuffer and draws a rectangle visible in a
screendump; key input is readable.

## M12 — win32u + framebuffer backend (single process)
Bring in win32u/user32/gdi32/comctl32 PE sides; build win32u's unix side as PE (POSIX →
our `Nt*`, FreeType statically linked). Write `winefb.drv`: implement Wine's display
driver table, blit dibdrv's bitmap to `\Device\Fb0`. Desktop state lives in-process; one
GUI process.
**Done when:** **calc.exe appears on screen.**

## M13 — win32k-lite / wineserver-lite ⛰️ (the GUI mountain, lowered by route (a))
Under route (a): run a stripped wineserver as a PE process holding GUI state
(window/queue/hook/clipboard/atom); transport via shared-section + kernel event (message
queue backed by a kernel event; the genuine friction point). Under route (b) — later,
optional — transplant that state into a `kernel/win32k/` module exposed via generated
`NtUser*` syscalls.
**Done when:** two GUI processes run at once; Z-order, focus, cross-thread `SendMessage`,
`FindWindow` all behave.

## M14 — Compositing, input routing, cursor
Inject `\Device\Input0` events into the input queue; hit-test and route; composite
per-Z-order with clipping; draw the cursor; manage dirty rectangles. No window manager
needed — each app's `DefWindowProc` draws its own frame.
**Done when:** windows can be grabbed and moved; clicks reach the right window.

## M15 — GUI finishing
Clipboard, hooks, `AttachThreadInput`, GUI-ifying conhost, and the real trophy: run
Wine's `user32/tests/msg.c`. Value accrues incrementally; keep an honest `todo_` list.

## M16 — Desktop *(Wine desktop; not the ReactOS shell)*
Run `wineboot` once (initializes the registry via our `NtCreateKey`), then
`explorer.exe /desktop=shell,WxH`. The golden artifact is a wallpaper rectangle + a file
window. `gen_hive.py` is **not** needed — wineboot does it at runtime.
**Done when:** `tests/gui/golden/desktop.ppm` matches.
*Optional M17:* the ReactOS shell (taskbar/Start menu/icons) — a separate integration
effort with a two-upstream cost; see `docs/06`.

## WOW64 — 32-bit apps *(last, purely additive)*
GDT compat-mode descriptors; `NtCreateUserProcess` detects `IMAGE_FILE_MACHINE_I386` and
marks a WOW64 process; restrict its address space to low memory; deliver compat-mode
exceptions; a second (32-bit) set of Wine PE DLLs under `SysWOW64`. The 32→64 transition
is entirely in user mode (Wine's "new WoW64"); the kernel never sees a 32-bit syscall.
**Done when:** a 32-bit CUI app runs. Touches no semantics; removable.

---

## Success probability (honest)

For an implementer driving this with an LLM under real time pressure, the estimate to
"calc.exe on screen" is **~7%** — dominated not by difficulty but by **attrition** and by
the fact that **nobody has ever built this combination before**. Note that **M7
(Wine ntdll runs hello.exe) at ~30% is itself a world-first** and a complete result on
its own. See `docs/12` for how to raise the odds (constitution first; pull the calc
critical path off npfs; generate `abi/`; thick logging on day one).
