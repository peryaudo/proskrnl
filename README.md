# proskrnl

**A minimal, Windows-NT-semantics-compatible kernel that boots on bare metal (or a VM),
runs the Wine user-mode stack unmodified, and — eventually — opens a real Windows
application in a window.**

proskrnl is not a Windows clone and not a ReactOS competitor. It is a deliberate,
narrow bet:

> Reimplement only the part of Windows that is a **clean, observable boundary** — the
> `Nt*` system-call surface plus the PEB/TEB/file semantics that user mode can see —
> and reuse everyone else's 30 years of work for the parts above and below it.

- **Above the boundary:** the Wine PE user-mode DLLs (ntdll, kernelbase, user32,
  gdi32, …). We swap only ntdll's unix backend for our own syscall stubs. Wine's
  three decades of message-ordering and API-behaviour compatibility come along for free.
- **Below the boundary:** we write drivers ourselves — but only for a *chosen*,
  spec-documented hardware set (virtio first). No Windows driver ABI, no IRP, no PnP.

## Why this can work when ReactOS took 30 years

ReactOS chose the *dirty* boundary: binary compatibility with Windows kernel-mode
drivers. That boundary is a contract over **struct layouts and context-dependent
timing**, which is untestable, unmarshalable, and impossible to redesign around once
drivers depend on it. It taxed every commit and paid out only after everything was
finished.

proskrnl chose the *clean* boundary. It is:

- **narrow** — a few hundred `Nt*` calls, and only the subset Wine actually uses;
- **observable** — everything crossing it can be exercised from an unprivileged `.exe`;
- **already specified** — Wine's test suite is a third-party, Windows-verified,
  legally-clean specification of that boundary, and we import it.

The correct comparison for proskrnl is not ReactOS or Wine. It is **FreeBSD's
Linuxulator**: a small, maintainable ABI-compatibility layer over a clean, stable,
observable syscall surface — except placed on bare metal instead of on a host OS.

## Scope

- **Final goal:** CUI is the supported target. A hacky, opt-in GUI path exists on top
  (see `docs/07-gui-strategy.md`), but it is strictly additive and removable.
- **Not in scope (by design):** the Windows driver ABI, win32k-as-NT-built-it, the NT
  cache manager as a separate component, pageout/working-set management, a real
  security model (initially), ALPC, HAL as a swappable module.

## Where to start reading

1. `docs/00-overview.md` — the design in one sitting.
2. `docs/09-constitution.md` — **the hard rules. Read before writing a line of code.**
3. `docs/02-milestones.md` — the plan, M1 through WOW64.
4. `docs/13-glossary.md` — if terms like IRQL, APC, or "section object" are unfamiliar.

## Prerequisites (development toolchain)

Supported host environments: **macOS** (Apple Silicon or Intel) and **Linux**
(x86-64; instructions below are for Debian/Ubuntu). The tool set is the same on
both — clang + lld (freestanding cross-toolchain), QEMU (the run/test loop,
`docs/08`), Limine (the bootloader, ADR 0010), mtools + sgdisk
(`tools/mkimage.sh` builds the GPT/FAT32 image without mounting), GNU make,
and python3 (the `tools/gen_*.py` generators).

The version-sensitive dependencies are **pinned git submodules** under
`third_party/` so every environment builds against the same bits: `limine`
(bootloader stages + deploy tool, a `-binary` release branch), `limine-protocol`
(the kernel-facing boot-protocol header), `qemu` (the official GitHub mirror,
a fallback for hosts with no QEMU — see below), `freetype` (the font backend, built twice: a PE
static library for the target and a native one for the oracle), and `wine`
(both the `abi/` generation source *and* the ntapi oracle runtime). `tools/mkimage.sh`, `tools/qemu.sh`, and
`tests/run/run.sh` all prefer the in-tree builds automatically and fall back to
host tools on PATH.

### macOS (Homebrew)

Install everything with `brew bundle` (reads `./Brewfile`), or the M1-critical
set directly:

```sh
brew install llvm lld qemu limine mtools gptfdisk
```

- **llvm + lld** — the freestanding cross-toolchain: `clang --target=x86_64-elf`,
  `llvm-objcopy`, and `ld.lld` (macOS's own `ld` is Mach-O only). Homebrew's `llvm` is
  **keg-only** *and does not ship `ld.lld`* — point the build at `/opt/homebrew/opt/llvm/bin`
  and install **`lld` separately**.
- **qemu** — `qemu-system-x86_64`, the run/test loop (`docs/08`). On Apple Silicon the
  x86-64 guest runs under TCG emulation (no HVF) — correct, just slower.
- **limine** — the bootloader (ADR 0010); provides the `limine` deploy tool.
  Optional: the pinned `third_party/limine` submodule works on macOS too
  (`git submodule update --init third_party/limine{,-protocol} && make -C
  third_party/limine limine`) and takes precedence over the brew keg.
- **mtools** — `mformat`/`mcopy`, to populate the FAT32 ESP without mounting
  (`tools/mkimage.sh`).
- **gptfdisk** — `sgdisk`, to lay down the GPT + BIOS-boot partition the Limine BIOS
  image needs (`tools/mkimage.sh`).

### Linux (Ubuntu 24.04)

One command:

```sh
tools/setup_linux.sh
```

It installs the apt toolchain (clang/lld, make, gdisk, mtools, mingw-w64, the
QEMU/Wine build dependencies) and then builds the pinned `third_party/`
submodules **in place** — no `sudo make install`, nothing on PATH to conflict
with distro packages:

- **limine** — the deploy tool is one `cc` invocation; the BIOS/UEFI boot
  stages come prebuilt on the pinned `-binary` release branch (upstream's
  intended integration), so no autotools/nasm and no network-fetching
  bootstrap.
- **qemu** — built from the pinned submodule (official GitHub mirror,
  `x86_64-softmmu` only) **only when the host has no `qemu-system-x86_64` on
  PATH**. There is no version floor: the kernel's clock drives the LAPIC timer
  through the xAPIC MMIO window, which every QEMU has, so `apt install
  qemu-system-x86` (8.2 on 24.04 LTS) runs the whole suite and the long source
  build is skipped.
- **wine** — the ntapi oracle runtime, built (64-bit, no X) from the very
  same pinned tree `abi/` is generated from, so the oracle and the contract
  cannot version-diverge. Since GUI-3 it is also the **font-metrics oracle**:
  configured `--with-freetype --without-fontconfig` against the pinned
  `third_party/freetype`, so the oracle and the target answer font questions
  from the same FreeType and the same font set, and no host fonts can leak
  into the spec.

The first run takes a while if Wine has to build; re-runs skip finished work.
Any distro QEMU works and is preferred over building one — the runner scripts
prefer the in-tree builds when they exist and fall back to PATH, and `QEMU=`,
`WINE=`, `LIMINE=`/`LIMINE_SHARE=` override either way.

### Ephemeral containers (Claude Code on the web, fresh CI-like boxes)

Building QEMU + Wine from source in a throwaway container wastes hours, so CI
publishes the finished build trees to the rolling `third-party-cache` GitHub
prerelease (zstd tarballs, keyed on the submodule pins — the publish step in
`.github/actions/third-party`, the prep every CI job shares).
`tools/fetch_third_party.sh` restores them in
minutes and then `tools/setup_linux.sh`'s skip-logic only installs the apt
toolchain:

```sh
tools/fetch_third_party.sh && tools/setup_linux.sh
```

For **Claude Code on the web**, paste exactly that line as the environment's
*setup script* (environment settings in the web UI): the sandbox snapshots the
filesystem after the setup script succeeds, so the download cost is paid once
per environment and every later session starts with the builds already in
place. Sessions without a configured setup script still recover: a
`SessionStart` hook in `.claude/settings.json` kicks off the same fetch in the
background on remote Linux containers. If the pins were bumped and main's CI
hasn't republished yet, the fetch fails loudly — fall back to
`tools/setup_linux.sh`.

### ntapi oracle target (both hosts; from M2, not needed for M1)

**mingw-w64** builds the tests as a Windows `.exe` (`docs/14`) and a **Wine**
runtime runs it: `tests/run/run.sh oracle`. On Linux both come from
`tools/setup_linux.sh` (the oracle wine is the pinned `third_party/wine` — see
above). On macOS, Homebrew's `wine-*` casks are deprecated (they fail macOS
Gatekeeper) — on Apple Silicon use the Game Porting Toolkit's `wine64`, or
better, run the oracle target on Linux/CI or Windows, which is smoother than
local macOS Wine.

## Status

**WOW64 complete** — the last planned milestone (`docs/02`). An
unmodified 32-bit Win32 CUI binary runs: `tests/cui/hello32.c` is an
ordinary i686 mingw console program over the same Wine import libraries
the 64-bit clients use, and nothing in it knows it is a guest — every
syscall it makes has travelled guest → wow64cpu → wow64.dll → the
64-bit ntdll before arriving, because Wine's "new WoW64" keeps the whole
32→64 transition in user mode and the kernel never sees a 32-bit
syscall. `ntdll_test.exe:wow64` is green on both legs, unparked.

What the kernel owes a guest turned out to be furniture plus machine
state: a second ntdll from `syswow64` with `SYSTEM_DLL_INIT_BLOCK`
written into both copies, PEB32 + `WOW64INFO` and a 32-bit parameter
block, TEB32 cross-linked with the TEB64, two stacks, and the
`WOW64_CPURESERVED` + `I386_CONTEXT` area the guest's first context
lives in. The GDT moved to NT's own selector *values* (0x23/0x2b/0x33,
per-thread 0x53) because every `CONTEXT` leaks them, and the ring-3
return path now *loads* the compat segments — staging them in a trap
frame is not enough, since `iretq` nullifies the kernel's DPL-0 data
selectors. Three surfaces were built because a gate consumer depended
on them and for no other reason: `ThreadWow64Context`, debugger
**attach** (`docs/adr/0011` amended to allow it and to state why the
event queue stays refused forever), and a real per-process **LDT** —
the last because `STATUS_NOT_IMPLEMENTED` is never an answer proskrnl
may give, so a Wine gap became a case built against NT's contract in a
`beyond_oracle` block rather than an exemption. Two placement rules were
measured and both contradicted the plan: the 64-bit stack of a WOW64
thread lives **above** 4GB, and the CPU area is that stack's ceiling —
starting the thread above it let its own first call frames overwrite the
guest context. Along the way the pins convicted two pre-existing 64-bit
bugs: every TEB carried a bogus `Tib.ExceptionList`, and a process
created without a Desktop or ShellInfo got a null pointer where the
contract promises an empty string.

**WOW64 now reaches the desktop, too.** `make rungui` carries both
bitnesses of the applet shelf, so a 32-bit Win32 GUI app runs in the
interactive session beside the 64-bit ones — the guest's `user32`/`gdi32`
import the pinned tree's stock i386 `win32u.dll` (pure syscall thunks),
`wow64cpu` catches the syscalls, `wow64.dll` routes service table 1 to
`wow64win.dll`, and `wow64win` calls the SAME 64-bit `win32u.dll` this
build already ships. Nothing was minted for it; one desktop authority,
one more door. `tests/run/run.sh wow64gui` is the acceptance: a 32-bit
client typed at the windowed console, its window found on QEMU's
screendump, its bitness confirmed by asking the kernel
(`ProcessWow64Information`) rather than by trusting the file. It cost
four defects, all older than the feature and none of them 32-bit in
nature — a misaligned-buffer assumption in `NtQueryDirectoryFile`, the
interrupt return path never reloading the ring-3 data selectors (the
syscall path's twin, fixed a milestone earlier), a WOW64 process's
second thread getting no 32-bit furniture at all, and
`THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` accepted and dropped. `docs/03`
"WOW64 GUI notes" has each one and its pin.

**CUI-9 complete**: shared, already-relocated image masters plus
copy-on-write — the machine no longer pays a full private copy of every
DLL per process. The Article 3 "no COW" mandate was lifted the way
`docs/09` demands: measurement first (`tests/run/run.sh cui9`, the
pinned 512M boot — ≈5.9 MB per resident process, the machine refusing at
**70** processes), the amendment as its own commit (`docs/03` "CUI-9 COW
notes"), the oracle pins before any kernel code. One `MI_IMAGE_MASTER`
per `(file, base)` — the `IO_FCB` is the identity, the base is in the
key because its fixups differ — holds relocated frames built once;
views map them outright, hardware-read-only even where the recorded
protection is writecopy, and the first store resolves through the ONE
write-fault authority (the CUI-7 write-watch resolver, extended to
`MiResolveWriteFault`, consulted identically by the ring-3 fault,
`NtWriteVirtualMemory` and the syscall-buffer probe): copy the master
frame, repoint, open the per-page gate. The pins reversed the plan's
NT-derived guess before any kernel code, as pins do: the pinned oracle
never transitions a written writecopy page's `Protect` and never splits
the region (wine realizes writecopy silently via `MAP_PRIVATE`), so
proskrnl pins the no-transition shape and keeps the private/shared
state out of the reported protection entirely. Hazard F closed on the
share-mode side (a write-open under a live image mapping refuses,
`sem_mm/image_deny_write`); the per-section raw-byte snapshot — half
the measured cost, unaccounted in the plan — is released at first bind
and re-sourced from the resident cache through one authority. **The
ceiling moved**: 70 → **319** resident processes (per-process cost
5965 → 1500 KB), the refusal now surfacing as
`ERROR_NOT_ENOUGH_MEMORY`, and the `cui9` leg ratchets a committed
floor of 250 so the win stays a machine verdict alongside the kmt
sharing metrics (master hit/build counters, exact free-frame
round-trips, the no-writable-master-PTE sweep, the counted `invlpg`).
**Not yet:** a pre-existing writable handle can still write an
image-mapped file (real NT refuses via `MmFlushImageSection`, the
oracle permits it, no baked consumer does it — recorded residual);
file-backed data writecopy keeps its pinned eager-copy form (lazy COW
there lands on mapped-view coherence, deliberately unspent).

**GUI-6 complete** — the Wine desktop. The gui6 image carries
`explorer.exe` at the path win32u's auto-launch hardcodes, which turns
wineserver-lite's GUI-2 forced-desktop fixtures off: explorer creates
and owns the desktop (wallpaper + taskbar-mode systray), and its own
`CreateProcessW` child opens the shell32 `IExplorerBrowser` file window
over it — landing on desktop "shell" through the connect-time
winstation/desktop inheritance GUI-3 had left for this milestone,
now run through the pinned `connect_process_winstation` at attach. The
verdict is the exact-match golden `tests/gui/golden/desktop.ppm`
(`tests/run/run.sh gui6`; re-bless with `GUI6_BLESS=1`). The furniture
that bit was small and named on serial both times: uxtheme.dll (the SxS
comctl32's delay import — absent, explorer aborts in the systray
toolbar) and atl100.dll (the registrar behind every
`DllRegisterServer` — absent, wine.inf's `RegisterDllsSection` ran to a
silent `E_NOINTERFACE` and shell32's CLSIDs never landed in the hive).
`make rungui` gets the same desktop: the gui5con image carries the
shell payload too, its clients routed onto desktop "shell" by Wine's
own virtual-desktop registry configuration (written natively by smss
before the first client), so the windowed prompt, the applets it
launches, and the WOW64 clients all live on the explorer desktop with
its taskbar.
**Not yet:** the gui2..gui5 and guiwtest images stay explorerless by
decision (docs/03 "GUI-2 notes"), so the fixture survives as their
fallback and the two desktop-ownership `user32:msg` assertions stay in
`msg-budget.txt`'s bound; `CLSID_ShellWindows` registration
(rpcss/local-server) is still refused, which explorer tolerates.

Next: **Net-1** — sockets
(virtio-net, `\Device\Afd`; the former CUI-5, now its own path) — its
machine prerequisite, **CUI-8**, now stands complete: an AFD `accept`
that never completes on its own has a pending engine and a drain seam to
land on. Or **GUI-7**, the ReactOS shell (docs/06), now that Wine's
desktop provides its regression baseline.

The CUI path then ends with one remaining milestone of the machine kind
— no `Nt*`, `docs/16`'s count untouched: **CUI-10** SMP behind a giant
lock (`docs/18-smp-strategy.md`). CUI-8 (`docs/19-io-strategy.md`) and
CUI-9 (`docs/17-cow-strategy.md`) are done; CUI-9's write-protect sites
join CUI-10's shootdown enumeration (`docs/17` §11). The last mandate
retirement stays gated on its measurement, deliberately not a speed
argument: slowness having already stopped a suite from reaching a
verdict.

Either way, growing the winetest manifest as its parked blockers land
(`docs/03` "M10 winetest notes"). Debug objects stay out of scope apart
from the attach carve-out WOW64 needed: `NtCreateDebugObject`,
`NtDebugActiveProcess`, `NtRemoveProcessDebug` and the `BeingDebugged`
flag they move, with the event queue permanently refused (ADR 0011 and
its WOW64 amendment).

## Build instructions

```sh
make test     # build the image, boot headless in QEMU, verify proskrnl's kernel-mode tests pass
make fulltest # every leg CI runs, fanned out over this machine (docs/08) — the whole verdict
make run      # boot interactively: a cmd.exe prompt on your terminal ('exit' powers off)
make rungui   # boot the GUI-2 image with a host window on the scanout (winemine.exe)
tests/run/run.sh oracle     # the ntapi contracts, green against Wine/Windows ntdll
tests/run/run.sh proskrnl   # the SAME test .exes, green ON the kernel (baked at C:\ntapi\)
tests/run/run.sh proskrnl query_dir   # ...or one test / a glob, while iterating (both legs)
tests/run/run.sh fuzz       # the differential fuzzer: random Nt* sequences, oracle vs kernel
tests/run/run.sh persist    # tests that registry values survive a reboot (boot twice)
tests/run/run.sh console    # tests that typing into the serial console is working
tests/run/run.sh winetest   # runs the full non-GUI sweep of winetest
tests/run/run.sh winetest ntdll:env   # ...or one pair / a module / a glob, while iterating
tests/run/run.sh firstboot  # CUI-1: diff the firstboot registry against the oracle's prefix
tests/run/run.sh scm        # CUI-3: sc install/start round-trip, then reboot-survival autostart
tests/run/run.sh procs      # CUI-4: Ctrl+C interrupts a loop, tasklist/taskkill, a job tool
tests/run/run.sh gui        # GUI-1: framebuffer screendump + an injected key
tests/run/run.sh gui2       # GUI-2: winemine on screen (screendump differential)
tests/run/run.sh gui3       # GUI-3: two GUI processes over wineserver-lite
tests/run/run.sh gui4       # GUI-4: overlap composited, click routed, window dragged
tests/run/run.sh gui5       # GUI-5: clipboard, low-level hooks, AttachThreadInput, font diff
tests/run/run.sh gui5con    # GUI-5: conhost dual-mode — real user32/gdi32 command prompt
tests/run/run.sh wow64gui   # WOW64: a 32-bit GUI app on the same desktop, typed at that prompt
tests/run/run.sh gui6       # GUI-6: the Wine desktop vs tests/gui/golden/desktop.ppm (exact match)
tests/run/run.sh guiwtest   # GUI-5: Wine's own user32:msg suite end to end, budget-ratcheted
```

## License

**GPL-2.0** — see [`LICENSE`](LICENSE) and `docs/11-licensing.md`. Third-party components
keep their own licenses (Wine is LGPL-2.1; FreeType is FTL/GPL-2.0; the vendored Limine
header is BSD-2-Clause);
the kernel/user process boundary keeps user-mode code out of the kernel image.
