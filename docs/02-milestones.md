# 02 — Milestones

Each milestone closes on **a runnable artifact + a verification method**. Never on "code
written." The empirical effort split is roughly: **M1–M6 = 40%, M7 alone = 30%,
M8 onward = 30%** (an estimate that predates the CUI consolidation path below — Net-1
alone is M6-sized). M7 is both the biggest mountain and the biggest return.

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
- **The differential fuzzer is available from M5, not gated to M7.** Its prerequisites — the
  one-source/two-mode `ntapi` harness, the generated syscall list, the deterministic
  serial-log verdict — all exist from M4/M5, so it was built early (`tests/fuzz/`, `docs/08`)
  and its op model grows with each milestone's new `Nt*`. Run it with `tests/run/run.sh fuzz`.
- **The critical path to winemine.exe deliberately excludes npfs/condrv/conhost/cmd.** See
  the GUI note below and `docs/07`.

---

## M1 — Boot and kernel scaffold
Boot via **Limine** (ADR 0010): it hands off in 64-bit long mode with a higher-half map,
memory map, and framebuffer already set up, so `boot.S` is a thin entry stub — no 32→long-
mode trampoline to hand-write (the exact fiddly asm an LLM gets subtly wrong). Then: serial
console; IDT/exception handlers; timer interrupt; physical page allocator. NT loader protocol
is unnecessary (binary compat dropped), so ride an existing boot protocol.
**Do first:** get the QEMU loop (build → run → `isa-debug-exit` code → serial log) green on
a trivial "hello over serial" payload *before* writing kernel logic, so the harness is never
a variable while you debug (see `docs/08`).
**Done when:** boots in QEMU; an exception dumps registers over serial; the timer ticks.
**Do on day one:** thick panic handler (register dump, stack trace, last syscall) — this
is the LLM's eyes for the rest of the project. Turn on **UBSan in trap mode** the same day
(`-fsanitize=undefined -fsanitize-trap=undefined`): no runtime library needed, a violation
emits `ud2`, and the panic handler above reports the site (`docs/08`).

## M2 — In-kernel multithreading
Kernel page-table management; pool allocator; kernel threads + context switch; priority
scheduler; **dispatcher objects** (event/mutex/semaphore/timer) and `KeWaitFor*`. Get NT
semantics (notification vs. synchronization events, wait-all/any) exactly right here.
**Done when:** in-kernel test — threads ping-pong on events/mutexes; timed waits time out
correctly.

## M3 — Ob: handles and namespace
Object manager (type system, refcount, handle table); `\Device` and `\??` namespaces;
`NTSTATUS` conventions. Move M2's dispatcher objects under Ob.
**Add here:** **minimal KASAN** (~1000 lines: shadow memory + `__asan_load/store` hooks +
pool redzones). Handle tables and object refcounts are the LLM's favourite bug site and
exactly what KASAN catches — the highest-return sanitizer, so it earns its keep the moment
Ob exists (`docs/08`).
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
**Do first:** the self-checking Mm stress test (`docs/08`) — write via a mapped view, read
via `NtReadFile`, write via `NtWriteFile`, read via the view again, verifying a known
pattern every time. It needs this milestone's `NtReadFile`/`NtWriteFile`, so it becomes
expressible exactly here; write it and green it on the oracle *before* any Io code
(Article 5). It is M6's acceptance test for mapped-view/read-write coherence — Mm
consistency bugs surface *only* in this form, and reliably do (`docs/08`) — and it stays
in the suite as a permanent regression guard. Until M7 (`NtCreateThread`) it runs
single-threaded; sequential view/read/write interleavings already convict coherence bugs.
The anonymous-section slice of it, `sem_mm/section_stress`, runs from M5.
**Done when:** the file-semantics suite is green (e.g. share-mode violation →
`STATUS_SHARING_VIOLATION`); M5's image mapping works from an on-disk file; the Mm
stress test is green on proskrnl.

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

## M9 — npfs, condrv, interactive console
Named-pipe FS (byte/message mode, listen/connect via `NtFsControlFile`); a ConDrv-style
console device; port Wine's conhost.
**The console transport is the COM1 serial port, in both directions** (HACK-004,
`docs/10`). The 16550 is bidirectional and already carries all kernel output
(`arch/x86_64/serial.c`); its receive side becomes console input — the "keyboard driver"
of this milestone is the UART RX path, not a keyboard device. A real keyboard
(virtio-input, `\Device\Input0`) is GUI-1's problem and a GUI conhost is GUI-5's; condrv is
agnostic of its backend, so the serial transport is subtracted when those arrive. Testing
stays inside the headless finite-time loop (`docs/08`): QEMU's serial chardev becomes a
socket/pty instead of a plain log file, the runner writes keystrokes into it and greps the
echo — no QEMU window, no screendump, no change to the loop's shape.
**Done when:** input typed into the serial console echoes through conhost; the pipe
client/server test (message-mode behaviour rpcrt4 needs) passes.

## M10 — Full Wine user-land (CUI)
kernelbase/kernel32, msvcrt, advapi32, rpcrt4, services.exe, Wine's cmd.exe; full
`CreateProcess` paths (env/handle inheritance, cwd), completion ports, DLL search order.
**Done when:** cmd.exe prompts; pipes/redirection work; an off-the-shelf MSVC-built CUI
app runs unmodified. Ideal regression: the CUI subset of Wine's own test suite —
**live since the M10 stretch work**: `tests/run/run.sh winetest` gates a curated manifest
of Wine's-own-suite subtests (ntdll/kernel32/msvcrt/ucrtbase modules) green on the oracle
AND on proskrnl (`docs/03` "M10 winetest notes").

---

## CUI consolidation path (post-M10: from "acceptance passed" to "off-the-shelf")

> M10's acceptance proves the *mechanism* (process/file/pipe/console plumbing). It does
> not provide the *machine state* real console software expects: registry content, a
> token surface, an SCM, process enumeration, an interruptible console, a true clock.
> These milestones close that gap, consumer-first (Article 5: each new `Nt*` arrives
> because a baked binary calls it, pinned by an oracle-green test — never
> speculatively). The path is independent of the GUI path; either may come first.
> Sockets are NOT on this path: they are a genuinely new subsystem, not consolidation,
> and live as their own **Net-1** milestone below. The measured gap this path closes —
> which ids are missing, which are permanently out of scope, which partial services
> refuse the classes real apps ask for — is `docs/16-syscall-status.md`; CUI-5…CUI-7
> are its build plan, and after them the buildable syscall surface is complete
> (202 of the 264 Wine x64 ids; the other 62 are out of scope by decision, not debt).
> **Verification spine:** the winetest gate (`tests/run/run.sh winetest`, live since the
> M10 stretch work — `docs/03` "M10 winetest notes") — every CUI milestone grows its
> manifest, unparking pairs blocked on that milestone's surface, so "fully functional"
> ends as a measured pair count, not a feeling.

## CUI-1 — firstboot: wineboot + machine state
Bake rundll32/setupapi/cfgmgr32/ws2_32 + `wine.inf`; build wineboot as a standalone PE
with cmd.exe-style glue (`user/cmd/proskrnl_glue.c` precedent: user32 stand-ins for the
wait window / message pump; rundll32 hard-imports user32 and needs the same). `user/smss`
grows the `firstboot.c` hand-off (`docs/04`). The registry payload (~500 `AddReg` lines:
Classes/CurrentVersion/OLE/Services/SessionMgr/codepages) is applied by setupapi's INF
engine inside rundll32 children (`InstallHinfSection`), so this also stress-exercises
`NtCreateUserProcess` and is the Cm integration test ADR 0008 promises.
**Landmine (design around, don't discover on serial):** setupapi's fake-dll machinery
treats the "Wine builtin DLL" signature as overwritable and truncates the destination
*before* reading the (absent-on-proskrnl) source — a naive `--init` with the
`WineFakeDlls` sections deletes the baked system32. Drive registry-only INF sections or
neuter the directive in glue. Also here: **retire the no-RTC deviation** (`docs/03`) —
read the CMOS RTC once at boot (MC146818 via ports 0x70/0x71, cited per G8; QEMU supplies
host UTC) and seed the 1601-epoch SystemTime base from it instead of the fixed date.
That fixes FAT32 mtimes (build tools compare them) and wineboot's own freshness check,
and is a hard prerequisite for Net-1's TLS acceptance. wineboot's remaining legs degrade
gracefully (missing `__wine_user_shared_data` section, failing
`NtQuerySystemInformationEx`, unloadable RegisterDlls GUI DLLs all warn-and-continue).
**Done when:** `wineboot --init` completes; a registry differential vs. the oracle's
prefix is green (Article 6: the diff convicts, not "it didn't crash"); the populated
hive survives reboot; winetest pairs parked on missing machine state join the manifest.

## CUI-2 — Se: the minimal-but-real security model
The widest latent syscall gap: token reads are dormant in the already-baked DLLs
(kernelbase/security.c, ntdll/sec.c, advapi32) and `OpenProcessToken` is the first thing
most real tools call. One fixed identity, but structurally real NT objects: a token
object type; `NtOpenProcessToken(Ex)`/`NtOpenThreadToken(Ex)`; the
`NtQueryInformationToken` classes advapi32/kernelbase actually read;
`NtAdjustPrivilegesToken`; `NtDuplicateToken`; `NtAccessCheck`/`NtPrivilegeCheck`;
`NtQuery/SetSecurityObject`; `NtAllocateLocallyUniqueId`. Scope strictly to what
baked callers hit (Article 1); pin `sem_se/` on the oracle first.
**Done when:** `sem_se/` is green on both sides; a real tool that opens its own token at
startup gets past the point where today it dies on `STATUS_NOT_IMPLEMENTED`.

## CUI-3 — SCM: services.exe + rpcss
Cheap on transport: Wine's local RPC is named pipes, **not ALPC** (`ncalrpc` opens
`\pipe\lrpc_*` — `dlls/rpcrt4/rpc_transport.c`; the SCM endpoint is
`ncacn_np:[\pipe\svcctl]`), so M9's npfs already carries it and the entire LPC/ALPC
syscall surface stays permanently unimplemented for the Wine userland. Bake services.exe
(+ its userenv import) and rpcss; firstboot starts them; sechost/advapi32 clients bind
over the pipe. Depends on CUI-1 (wine.inf writes the `Services` key) and CUI-2 (the SCM
checks tokens). This is the deferred-since-M10 SCM finally getting its first consumer
(`docs/03` "M10 CUI-userland notes").
**Done when:** an `sc`-style query round-trips; a real service installs, starts, and
survives reboot, all driven from ring 3.

## CUI-4 — the process ecosystem
`SystemProcessInformation` (today only `SystemBasicInformation` exists — no
tasklist/toolhelp shape without it); `NtOpenProcess`; `NtRead/WriteVirtualMemory`;
`NtGetNextProcess/Thread`; `NtSuspend/ResumeProcess`; job objects (real build tools use
them); and the M10-deferred **Ctrl+C / console-control delivery** through condrv — the
most user-visible CUI hole (a running program cannot be interrupted today). Debug
objects (`NtCreateDebugObject` family) are the stretch goal, not the gate.
**Done when:** a tasklist/taskkill pair works against live processes; Ctrl+C interrupts
a loop under cmd.exe; a job-object-using build tool completes.
*(Outcome: the stretch goal was not taken, and afterwards debug objects were ruled
permanently out of scope — no baked consumer, and the native debugger toolchain
expects PDB where proskrnl is DWARF end-to-end. ADR 0011; `docs/03` "Debug
objects"; `docs/16`.)*

## CUI-5 — Io completion
The file surface's last mile (12 missing ids + the refused info classes, `docs/16`),
led by the single largest hole on either list: **rename**.
`FileRenameInformation(Ex)`/`FileLinkInformation` in `NtSetInformationFile` —
`MoveFile`/`ren`/`move` and every write-tmp-then-rename tool fail today, and rename
does not exist anywhere in `fs/` yet. Then: `NtNotifyChangeDirectoryFile`
(`ReadDirectoryChangesW` — file watchers, build tools), `NtCancelSynchronousIoFile`,
`NtRead/WriteFile{Scatter,Gather}`, `NtFlushBuffersFileEx`, `NtDeleteFile`,
`NtQuery/SetEaFile`, `NtSetVolumeInformationFile`, `NtQueryDirectoryObject`
(kernelbase volume enumeration), `NtOpenIoCompletion`, `NtSetIoCompletionEx`; the
missing query classes (`FileNetworkOpen`/`AttributeTag`/`Stream`/
`FileIdBothDirectory`, `FileFsFullSizeInformation`); and widening async I/O past
CUI-3's single pended verb (`FSCTL_PIPE_LISTEN`) where a consumer convicts it.
**Done when:** `move`/`ren` work under cmd.exe; a write-tmp-then-rename tool
completes; a directory watcher sees a change; the unparked winetest file pairs join
the manifest.

## CUI-6 — handles, identity, and the query surface
What real tools ask *about* processes, threads, and handles — plus the Se leftovers.
Ob/Ke/Ps ids: `NtSetInformationObject` (**`SetHandleInformation`**, the
stdio-redirect idiom) with `ObjectHandleFlagInformation` in `NtQueryObject`
(`GetHandleInformation`); `NtCompareObjects`; `NtSignalAndWaitForSingleObject`;
`NtOpenTimer`; `NtMakePermanentObject`; `NtQueueApcThreadEx2`;
`NtAlertResumeThread`; `NtFlushProcessWriteBuffers` and
`NtGetCurrentProcessorNumber` (kernel32/kernelbase forward these exports straight to
ntdll); `NtSetThreadExecutionState`. Query classes: `ProcessTimes`/`PriorityClass`/
`HandleCount`/`ImageFileName`, `ThreadTimes`, `SystemHandle`/`Module`/
`ProcessorPerformanceInformation`. Foreign-thread `NtGet/SetContextThread` (the
`SuspendThread`+`GetThreadContext` profiler/GC pattern — its debugger consumer is
gone) and `NtOpenThread` by CLIENT_ID. Jobs finish here: nesting, limit enforcement,
real accounting. Se-2: `NtSetInformationToken`, `NtFilterToken`
(`CreateRestrictedToken`), `NtAdjustGroupsToken`, `NtImpersonateAnonymousToken`,
impersonation attach, and **retiring Ob's always-allow create/open access check** —
a one-authority engine change (Art. 11) that must be its own commit.
**Done when:** a handle-inheritance redirect chain round-trips; a `timeit`-style
tool reads real process/thread times; a restricted-token launch works.

## CUI-7 — Cm-2 + Mm-2 + system furniture
The largest by id count (29) and the cheapest per id — the `*Ex` forms delegate to
engines that already exist (Art. 11: extend, never fork). Registry: `NtLoadKey{,2,Ex}`,
`NtUnloadKey`, `NtSaveKey`, `NtRestoreKey`, `NtReplaceKey`, `NtRenameKey`,
`NtNotifyChangeKey{,MultipleKeys}` (`RegNotifyChangeKeyValue` — services block on
it), `NtSetInformationKey`, `NtQueryMultipleValueKey`. Memory:
`NtAllocateVirtualMemoryEx`, `NtCreateSectionEx`, `NtMap/UnmapViewOfSectionEx` (the
`VirtualAlloc2`/`MapViewOfFile3` family), `NtFlushVirtualMemory`,
`NtLock/UnlockVirtualMemory`, `NtGet/ResetWriteWatch` (write-watch heaps),
`NtSetInformationVirtualMemory`. Locale/system: `NtQueryDefaultUILanguage`,
`NtQueryInstallUILanguage`, `NtSetDefaultUILanguage`, `NtSetDefaultLocale` (natural
fit with Cm-2 — they are NLS/registry reads), `NtSetSystemTime` (pairs with CUI-1's
CMOS RTC work), `NtSetSystemInformation`, `NtShutdownSystem`.
Ordering: CUI-5 → CUI-6 is a hard order (jobs and foreign-context work want the
query surface); CUI-7 is independent and can land in parallel or slot anywhere.
**Done when:** `reg save`/`reg load` round-trips and survives reboot; an app on the
`VirtualAlloc2`/write-watch path runs; after CUI-5…7 the buildable id surface is
complete (202/264, `docs/16`) and every remaining `KI_SYSCALL_MISSING` row is an
out-of-scope decision, not debt.

---

## Networking path (independent of the CUI path; formerly CUI-5)

## Net-1 — sockets: virtio-net + `\Device\Afd`
The one genuinely new subsystem and the largest single item post-M10 (2–3× a CUI
consolidation milestone) — moved off the CUI path because it is new capability, not
consolidation, and nothing on CUI-5…CUI-7 depends on it (nor it on them; it needs
only CUI-1's clock).
virtio-net over the existing virtio-pci transport (spec-cited per constant, like
virtio-blk); a deliberately dumb TCP/UDP stack (Article 3: correctness only, no
performance work); the AFD ioctl surface Wine's PE ws2_32 issues via
`NtDeviceIoControlFile`, generated into `abi/` from the pinned tree's `wine/afd.h`.
Requires CUI-1's real clock: TLS certificate validation (`notBefore`/`notAfter`) is the
test that finally *convicts* a fake SystemTime — a frozen 2026 base date rejects every
newer certificate. **Scope note (record in `docs/03`):** acceptance uses an app with
*bundled* TLS (off-the-shelf python/git/curl ship OpenSSL) — Windows-native schannel
stays out of scope, because its protocol engine is GnuTLS behind the unixlib seam
(null-dispatched on proskrnl), while raw bcrypt works as-is (the pinned tree vendors
SymCrypt PE-side, `libs/symcrypt`).
**Done when:** an off-the-shelf tool completes an HTTPS fetch over virtio-net.

---

## GUI path (opt-in, additive, route (a) — see docs/07)

## GUI-1 — Pixels and input ✅
Limine framebuffer; virtio-input. `\Device\Fb0` (map framebuffer to user)
and `\Device\Input0` (input event stream). **HACK-001 and HACK-002** (see `docs/10`).
**Done when:** a user program maps the framebuffer and draws a rectangle visible in a
screendump; key input is readable.

**Done** (`tests/run/run.sh gui`). Cheaper than budgeted: no virtio-gpu and no ramfb — the
framebuffer Limine sets through the VGA BIOS's VBE is the framebuffer we publish, so the display
side is one driver with one ioctl. Mapping needed no new Mm machinery either: `\Device\Fb0`
implements the existing `GetCache` vfs op, so `NtCreateSection` + `NtMapViewOfSection` over the
device handle work unchanged. Input is polled from the virtio-input eventq by the blocking read
(no IRQ path was added). Both halves are convicted by QEMU rather than by the kernel — screendump
for the pixels, QMP `send-key` for the key (`docs/03` "GUI-1 notes" for the G5 adaptation a HACK
device forces).

## GUI-2 — win32u + framebuffer backend (single process) ✅
Bring in win32u/user32/gdi32/comctl32 PE sides; build win32u's unix side as PE (POSIX →
our `Nt*`, FreeType statically linked). Write `winefb.drv`: implement Wine's display
driver table, blit dibdrv's bitmap to `\Device\Fb0`. Desktop state lives in-process; one
GUI process.
**Done when:** **winemine.exe appears on screen.**

**Done** (`tests/run/run.sh gui2`): winemine paints its window onto the scanout and the
screendump differential convicts it (the guest reports the window rect, QEMU's device
model returns the pixels — the GUI-1 shape). `make rungui` boots the same image with a
host window for a human.

The structure: win32u.dll is the pinned tree's *unix-side* sources compiled as PE
(`user/wine/`, `make win32u`) — user32/gdi32/imm32 bind to it by name, unmodified, because
that is how they import win32u anyway (all 434 imports covered). The desktop state is the
pinned wineserver's own GUI object model compiled into the same DLL behind an in-process
`wine_server_call`, so it is Wine's state machine rather than a second one (Art. 11); 120
of its 308 request handlers link and the rest refuse by name. Queue wake-ups are real
kernel events, which is `docs/07`'s "message queue backed by a kernel event" arriving one
milestone early because it was also the simplest thing that worked. `winefb.drv` is four
driver entries plus a surface flush. FreeType is pinned (`third_party/freetype`) and
linked in. **Nothing in `third_party/wine` is patched** — the hack meter is unchanged.

What completing the boot took, in the order the boot found it: registry symbolic links in
Cm (`sem_reg/symlink` pins the semantics; win32u's display-device commit creates volatile
links under `Control\Video` and the read-back resolves them — the CUI-era refusal was the
reason `lock_display_devices` found no sources), the `HKU\<sid>` root the font loader
opens, two in-process-glue bugs (`ntdll_wcsicmp` compiled to a self-jump via the unixlib.h
macro trap; the queue-handle fixup read a cleared pointer), and three single-process
fixtures the docs/03 "GUI-2 notes" record: `get_desktop_window` is always forced, the
desktop/message windows' user entries are made to look foreign (explorer owns them on real
Wine — with our own pid in the entries, win32u skipped the `WND_DESKTOP` paths and the
first `ShowWindow` never exposed the window), and winefb.drv sizes the desktop window to
the scanout (`pSetDesktopWindow`, the `X11DRV` repair). The image also bakes the ole32
chain (ole32/combase/coml2) because imm32's `CoRegisterInitializeSpy` delay-import aborts
the process when it cannot resolve — every real Windows has ole32.

## GUI-3 — win32k-lite / wineserver-lite ⛰️ (the GUI mountain, lowered by route (a))
Under route (a): run a stripped wineserver as a PE process holding GUI state
(window/queue/hook/clipboard/atom); transport via shared-section + kernel event (message
queue backed by a kernel event; the genuine friction point). Under route (b) — later,
optional — transplant that state into a `kernel/win32k/` module exposed via generated
`NtUser*` syscalls.
**Done when:** two GUI processes run at once; Z-order, focus, cross-thread `SendMessage`,
`FindWindow` all behave.

## GUI-4 — Compositing, input routing, cursor
Inject `\Device\Input0` events into the input queue; hit-test and route; composite
per-Z-order with clipping; draw the cursor; manage dirty rectangles. No window manager
needed — each app's `DefWindowProc` draws its own frame.
**Done when:** windows can be grabbed and moved; clicks reach the right window.

## GUI-5 — GUI finishing
Clipboard, hooks, `AttachThreadInput`, GUI-ifying conhost, and the real trophy: run
Wine's `user32/tests/msg.c`. Value accrues incrementally; keep an honest `todo_` list.

## GUI-6 — Desktop *(Wine desktop; not the ReactOS shell)*
Run `wineboot` once (already done if the CUI path ran — CUI-1's firstboot; otherwise it
initializes the registry via our `NtCreateKey` here), then
`explorer.exe /desktop=shell,WxH`. The golden artifact is a wallpaper rectangle + a file
window. `gen_hive.py` is **not** needed — wineboot does it at runtime.
**Done when:** `tests/gui/golden/desktop.ppm` matches.
*Optional GUI-7:* the ReactOS shell (taskbar/Start menu/icons) — a separate integration
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
