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
- **wine** — the ntapi oracle runtime, built from the very
  same pinned tree `abi/` is generated from, so the oracle and the contract
  cannot version-diverge. Since GUI-3 it is also the **font-metrics oracle**:
  configured `--with-freetype --without-fontconfig` against the pinned
  `third_party/freetype`, so the oracle and the target answer font questions
  from the same FreeType and the same font set, and no host fonts can leak
  into the spec. It is built `--with-x`, and every leg that runs it starts
  its own **Xvfb** at a fixed geometry (`tests/run/run.sh`) — so the oracle
  has the display driver a window question needs, and gets the same one on a
  laptop and on a headless CI runner. The X development packages and `xvfb`
  are in the apt list above for that reason.

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

**M11 console rearchitecture complete** (issue #232) — consoles are
**per-client and on demand**, wineserver's own object model
(`server/console.c`) implemented by `drivers/condrv.c`: every
`\Device\ConDrv\Server` open mints a console, `Reference` relative to it
mints THE console once, `Connection` binds the opening process, and
Input/Output route through the caller's binding at every call — so
**stock kernelbase's `alloc_console` runs unmodified**: launching a CUI
program on the desktop spawns its own windowed conhost (the reworked
`gui5con` leg drives one end to end), a GUI program never gets a console
(the create-time subsystem gate, pinned by `sem_console/subsystem_gate`),
and nothing empty sits on the idle desktop — explorer is launched
explicitly, the way userinit does it. The boot console is the SERIAL
console on **every** boot now, GUI boots included (HACK-004 rescoped
again: the debug channel is permanent and universal), and the whole
contract is pinned green on the oracle first (`tests/ntapi/sem_console/`,
7 cases). Couldn't be achieved within the milestone: conhost still
initializes the full GDI font sweep per console client (a measured
multi-second cost under TCG — pre-existing, newly load-bearing), and the
console-dependent winetest pairs stay parked pending un-parking sweeps.
What's next: un-park the console winetest pairs the per-client model
unblocks, or continue WOW64/GUI hardening.

**Net-3 complete** — resolution + the acceptance fetch (`docs/02` "Net-3";
the design is `docs/24` §4e/§4f/§6f). The acceptance is the headline:
**an UNMODIFIED off-the-shelf tool — curl.exe with bundled LibreSSL —
completes a TLS-1.3 HTTPS fetch over virtio-net** (`tests/run/run.sh
net3`: slirp, a fresh test CA whose `notBefore` postdates the retired
frozen clock — the armed docs/22 conviction — with exit-code and
content-hash verdicts). Below it, the milestone's one fork seam:
ws2_32's five resolver entries dispatch through superproject
`wsresolv.dll` when no unixlib is below (level-1 dormant `WS_CALL` leg,
hack meter 504→559 lines, oracle re-run green on the pin), and the
resolver serves numeric literals, localhost, the machine's registry
names, `drivers\etc\hosts` (now mkimage furniture) and a minimal
UDP-only DNS client over ws2_32's own sockets against the lease's
servers — the wire format convicted hermetically by the `tests/resolv`
corpus through its transport seam (`run.sh resolvunit`). `\Device\Nsi`
serves the three table verbs over the tables the pinned
`GetAdaptersAddresses` was measured to read (ndis-ifinfo, ip-unicast,
ip-forward; get-parameter for `ConvertInterfaceLuidToGuid`), from lwIP
netif state under one identity authority — the ethernet `if_guid` IS the
adapter's registry key name — with everything else refusing loudly
(`sem_nsi` pins green on both runners). The resolver un-wedged
`ws2_32:afd` past its parking crash, and the newly reached rows'
parity round (thread-exit port exemption, accept synchronicity
inheritance, ignored socket offsets, consume-edge READ-relatch and
deferred half-close HUP — each pinned first) took the pair to **0
failures on proskrnl; `ws2_32:afd` is ACTIVE in the manifest**.
Couldn't be achieved within the milestone: `ws2_32:sock` and
`ws2_32:protocol` stay parked with fresh triage — protocol's WSAAsync
window block spins forever under the user32 stand-ins on both runners
(a GUI-winetest-shelf follow-up) and its IDN rows want the live
internet; sock shares the user32/v6 families and the long sockopt tail —
and in-guest `GetAdaptersAddresses` still stops at dnsapi's dormant
unixlib (its DNS legs), a seam deliberately not taken this milestone.
What's next: the GUI path continues (docs/07), or WOW64 hardening —
the networking path is complete.

**AUD-3 complete** — capture, the audio path's last milestone (`docs/02`;
the design is `docs/23` §4a "Capture is the mirror"). The kernel driver
consumes rxq: PREPARE on a capture stream posts the whole slot set as rx
chains, `NtReadFile` of exactly `period_bytes` parks until the device
completes a captured period (the capture clock emerges from rx
completion — reached through NtReadFile's existing blocking-frontier
row), RELEASE's flush unparks the reader with what was captured, and the
used length — not the status footer, which the pinned QEMU model writes
immediately after the payload — carries the completion. A flushed short
period relays as a short success, never padded to fabricated silence
(Art. 12). winevsnd.drv grew its capture half (zero fork lines — the
AUD-2 seam already dispatched the entries): the eCapture endpoint from
the node's own INFO claim, a TIME_CRITICAL capture thread whose blocking
read paces deposits into every started stream's ring at the stream's own
rate/format, and winealsa's exact get/release_capture_buffer protocol.
The capture thread keeps draining at pace while clients are stopped —
stopping instead lets QEMU's rate control bank the gap and dump it as a
burst at the next Start (measured; audio/audio.c audio_rate_peek_bytes).
Capture exclusivity mirrors render's docs/03 deviation
(AUDCLNT_E_DEVICE_IN_USE; audiodg-lite stays HACK-008, reserved).
`tests/run/run.sh audio` grew two `none`-audiodev boots — the one
backend with an input side; wav has none (audio/wavaudio.c
max_voices_in=0), the docs/23 §7 cadence claim corrected — asserting
silence content and exact accounting, never speed: the device-contract
client ([KTEST] audio capture PASS periods=8 pos=18432) and the
event-driven WASAPI client (packets=16 frames=7680). The winetest
capture pairs re-measured with the endpoint real: oracle 14/14;
proskrnl 13/14 — `winmm:capture` records every format's exact second,
and `mmdevapi:capture` is parked with its signature (its padding <=
2*period asserts starve on a TCG guest against host-clocked delivery,
the docs/23 §6d class; unparks on a real-time-pace runner). Couldn't be
achieved within the milestone: a content-asserting capture test (QEMU
offers no input backend that plays a file — the docs/23 §7 gap stands),
and mmdevapi:capture green under TCG. What's next: the audio path is
done; the open frontier is Net-3 — the resolver seam (`WS_CALL` +
`wsresolv.dll`), minimal `\Device\Nsi`, and the off-the-shelf HTTPS
fetch.

**Net-2 complete** — `\Device\Afd`, the socket boundary Wine's ws2_32
issues (`docs/02` "Net-2"; the design is `docs/24` §5). The stack and its
netd thread now come up on every image (loopback needs no NIC), and
`drivers/afd.c` serves the AFD surface over lwIP's raw API in condrv's
device shape: create/bind/listen/connect/accept (the ULONG-handle-mint in
the accept issuer's table), scatter send/recv with the UDP datagram
rules, `NtReadFile`/`NtWriteFile` on socket handles, the 13-bit readiness
machine (poll + exclusive displacement, event-select/get-events with the
event-as-input-pointer *sic* convention, the FIONBIO interlock), the
Net-2 sockopt set, and waitable socket handles — pending riding the CUI-8
engine exactly as `kernel/io/io.h` promised, with `CancelPending`,
close-cancels and thread-exit cancels, and the cancellable
synchronous-handle wait as the frontier's second Net entry (`docs/20`
§13). Semantics were pinned first (G5) by `tests/ntapi/sem_net/` — eleven
suites, loopback-only and device-free, green on both runners — then
hardened against `ws2_32:afd` run raw on proskrnl (the parity round:
poll teardown shapes, WRITE hysteresis, the loopback OOB sidechannel,
minimal AF_INET6 bind surface — `docs/03` "Net-2 notes"). Unbuilt verbs
refuse loudly in the oracle-pinned inline shape, named on serial (G12),
and the `[KTEST] net` stats line now carries pended/refused/retransmit
numbers with a pended>0 floor on the full ntapi leg (docs/24 §6e: the
win is a verdict). Couldn't be achieved within the milestone:
`ws2_32:afd` is *parked, not active* in the winetest manifest — the
boundary rows are all green on proskrnl, but the suite's own
`gethostbyname("")` dies on the dormant resolver unixlib, which is
exactly Net-3's `WS_CALL` fork seam; `ws2_32:sock` crashes the same way
at startup and is parked with its family triage; TCP urgent data beyond
the loopback sidechannel and the v6 data path are recorded `docs/03`
scope cuts. What's next: Net-3 — the resolver seam (`WS_CALL` +
`wsresolv.dll`), minimal `\Device\Nsi`, and the off-the-shelf HTTPS
fetch.

**Net-1 complete** — the wire is up (`docs/02` "Networking path"; the
design is `docs/24`). The pinned lwIP (STABLE-2_2_1, the second
third-party component ever linked into the kernel image, admitted under
`docs/11`'s four conditions) runs in NO_SYS mainloop mode over a new
`drivers/virtio/net.c` — VERSION_1 + F_MAC only, no offloads, no MSI-X
vector, `VioNetDrain` a pure harvest-store-wake arm of the one drain
authority off the tick tail. The netd kernel thread drives the stack;
its park is the blocking frontier's first kernel-thread row (G14, with
`docs/20` §12's re-check). DHCP binds against slirp — bought for the
pinned QEMU with the tp-v8 cache bump and gated by netsmoke — and the
lease lands in the `Tcpip\Parameters\Interfaces\<adapter>` values real
Windows uses, written through the ordinary `NtSetValueKey` path, nothing
baked. `tests/run/run.sh net` is the acceptance: `[KTEST] net dhcp`
carries the address, the in-kernel TCP echo completes against the
harness, and the filter-dump pcap — networking's screendump — holds our
MAC, the DISCOVER/REQUEST exchange, and the echo payload both ways as
content assertions, never timing. Couldn't be achieved within the
milestone: nothing ring-3-visible speaks sockets yet — that is Net-2's
`\Device\Afd` (its `abi/afd.h`/`abi/nsi.h` contract is already
generated), and name resolution + the off-the-shelf HTTPS fetch are
Net-3's. What's next: Net-2 — `sem_net` pins on the oracle first, then
`drivers/afd.c` over lwIP's raw API on the CUI-8 pending engine.

**AUD-2 complete** — WASAPI render through the unmodified Wine PE audio
stack. The oracle bought its audio backend first (`--with-pulse` + the
runner-owned per-leg null-sink daemon + the audiosmoke pin — the
fonts/display lesson a third time, tp-v9), then the mmdevapi seam landed
on `proskrnl-target` (three dispatch surfaces, level-1 dormant behind a
latch that flips only on the kernel's own refusal of the wine-unixlib
`NtQueryVirtualMemory` class — behaviour only a missing unixlib
produces, the conhost probe's shape; hack meter 439→504), and
`user/wine/dlls/winevsnd.drv` — superproject PE code, zero fork lines —
implements the 37-entry unixlib surface over `\Device\Snd0`: endpoints
from the nodes' own INFO claims, float32 mix format over the S16 device,
the TIME_CRITICAL feeder whose blocking period write is the clock,
software session volumes, silence-on-underrun with the miss counted, the
period-granularity padding/position staircase. mmdevapi's COM class
registers through Wine's own registrar (`filter_inf.py --add-register` +
atl100) and smss seeds `Drivers\Audio=vsnd` natively, gated on the driver
being on the image. `tests/run/run.sh audio` now has a WASAPI half —
the same seeded pattern, sample-exact in the recorded WAV through the
whole stack (symmetric 1/32768 scaling makes S16 round-trip bit-exact),
with `[KTEST] audio PASS underruns=<n> bits=<n>` carrying the measured
count and the client's own bitness —
and the audio winetest pairs entered `manifest.txt` under the (c)
amendment, booting their own audio image. Couldn't be achieved within
the milestone: cross-process playback deliberately refuses
(`AUDCLNT_E_DEVICE_IN_USE`, the docs/03 deviation; audiodg-lite is
HACK-008, reserved), capture is unbuilt, and `winmm:mci` is parked on the
pinned oracle's own failure. What's next: AUD-3 — rxq, the capture node,
the `get_capture_buffer` legs.

**AUD-1 complete** — the first milestone of the opt-in audio path
(`docs/23`). The kernel grew its third HACK-shaped device family:
`\Device\Snd<n>`, one node per PCM stream the virtio-snd device reports,
direction the stream's own `PCM_INFO` claim (HACK-007), behind the
one-line Article 2 amendment extending the console/GUI exception to
audio. The wire contract mirrors the six virtio control verbs plus
`POSITION`; `NtWriteFile` of exactly `period_bytes` rides one txq chain
and parks on the CUI-8 engine when the device buffer is full — the
pacing clock is tx completion, no timer invented — and harvest joined
`IoDrainDeviceCompletions` off the tick tail, so snd has no MSI-X
vector (docs/19 §11f). No format translation, resampling, mixing, or
volume in the kernel, ever. `tests/run/run.sh audio` is the acceptance:
the guest plays a seeded S16 pattern into QEMU's wav audiodev and the
harness finds every sample of it, exact and contiguous, in the recorded
WAV — the audio analog of the GUI screendump. eventq/rxq are
deliberately unconsumed (capture is AUD-3), and a capture read refuses
honestly — which convicted a pre-existing Io bug: `NtReadFile` on a
device with neither `Read` nor `GetCache` called through a NULL pointer
in ring 0. Next: AUD-2 — the oracle grows a PulseAudio backend, the
mmdevapi seam commit lands on `proskrnl-target`, and `winevsnd.drv`
takes the WASAPI render pairs green on both runners.

**WOW64 complete** — the last milestone of the original plan
(`docs/02`). An
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
client started by smss from the GUI leg table, its window found on QEMU's
screendump, its bitness confirmed by asking the kernel
(`ProcessWow64Information`) rather than by trusting the file. It cost
four defects, all older than the feature and none of them 32-bit in
nature — a misaligned-buffer assumption in `NtQueryDirectoryFile`, the
interrupt return path never reloading the ring-3 data selectors (the
syscall path's twin, fixed a milestone earlier), a WOW64 process's
second thread getting no 32-bit furniture at all, and
`THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` accepted and dropped. `docs/03`
"WOW64 GUI notes" has each one and its pin.

**And it hears, too.** The same interactive image carries the 32-bit half
of the audio shelf under `syswow64` — `mmdevapi`, `winmm`, `dsound`, the
ACM codecs, and `winevsnd.drv` built from the one driver's sources by the
i686 cross — so a WOW64 app reaches WASAPI through the redirector the way
it reaches `user32`. The kernel below is unchanged: `\Device\Snd0`'s wire
contract is pointer-free by construction, so it reads the same from either
bitness. `tests/run/run.sh wow64aud` is the acceptance — the 64-bit
WASAPI client's own source, built i386, its samples found sample-exact in
QEMU's recording, with the bitness on the verdict line
(`underruns=0 bits=32`) because the image could carry either build under
that name.

**CUI-9 complete**: shared, already-relocated image masters plus
copy-on-write — the machine no longer pays a full private copy of every
DLL per process. The Article 3 "no COW" mandate was lifted the way
`docs/09` demands: measurement first (`tests/run/run.sh cui9`, the
pinned 512M boot — ≈5.9 MB per resident process, the machine refusing at
**70** processes), the amendment as its own commit (`docs/03` "CUI-9 COW
notes"), the oracle pins before any kernel code. One `MI_IMAGE_MASTER`
per image identity (the `IO_FCB`; the base stays OUT of the key — the
master relocates once and stamps its `ImageBase`, so ntdll fixes up a
view placed elsewhere, `docs/17` §6F) holds relocated frames built once;
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
`make rungui` gets the same desktop: it is an interactive, non-serial
GUI boot, which is exactly what `ShellBoot` derives, so its clients are
routed onto desktop "shell" by Wine's own virtual-desktop registry
configuration (written natively by smss before the first client) and
the windowed prompt, the applets it launches, and the WOW64 clients all
live on the explorer desktop with its taskbar.
**Not yet:** the gui2..gui5 and winetest-gui BOOTS stay explorerless by
decision (docs/03 "GUI-2 notes"), so the fixture survives as their
fallback and the two desktop-ownership `user32:msg` assertions stay in
the msg pair's budget in `manifest-gui.txt`; `CLSID_ShellWindows` registration
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
(`docs/03` "M10 winetest notes"). Debug objects: attach is built — the
carve-out WOW64 needed, `NtCreateDebugObject`, `NtDebugActiveProcess`,
`NtRemoveProcessDebug` and the `BeingDebugged` flag they move — while the
event queue still refuses, now as unbuilt work rather than an exclusion
(ADR 0011, now deprecated; `kernel32_test.exe:debugger` is the consumer
waiting on it).

## Build instructions

There are exactly TWO images. `build/proskrnl-test.hdd` is what every test leg
boots: it carries the whole userland — CUI, desktop, applets, shell, both
bitnesses of the WOW64 shelf, audio — plus every acceptance client and the
whole ntapi/winetest payload. `build/proskrnl-dev.hdd` is the same userland
without the test payload, for `make run` and `make rungui`.

WHICH leg a boot runs is a QEMU command-line flag, not a property of the
media: `GUEST_LEG` names the leg and `GUEST_SUBTESTS` filters the ntapi and
winetest sweeps, both published through fw_cfg and read out of
`HKLM\Hardware\qemu` (`kernel/cm/registry.c`, HACK-006) — the same channel
`GUEST_INTERACTIVE`, `GUEST_GUI` (does the boot have a desktop at all) and
`GUEST_SERIAL` (where the console goes on a boot that has one) ride. Two
things are NOT flags, because the boot already says them: whether explorer
owns the desktop is derived by smss and published as `ShellBoot`, and whether
this volume carries a Windows userland at all is derived from the leg name by
the kernel and published as `Userland` — the hermetic kernel fixtures name a
fixture leg, and everything that would look for a userland stands down.

```sh
make test     # build the image, boot headless in QEMU, verify proskrnl's kernel-mode tests pass
make fulltest # every leg CI runs, fanned out over this machine (docs/08) — the whole verdict
make run      # boot interactively: a cmd.exe prompt on your terminal ('exit' powers off)
make rungui   # boot the windowed command prompt with a host window on the scanout,
              # a NIC on the host's network and a sound card on its speakers
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
tests/run/run.sh winetest-gui   # GUI-5: Wine's own user32:msg suite end to end, budget-ratcheted
```

## License

**GPL-2.0** — see [`LICENSE`](LICENSE) and `docs/11-licensing.md`. Third-party components
keep their own licenses (Wine is LGPL-2.1; FreeType is FTL/GPL-2.0; the vendored Limine
header is BSD-2-Clause);
the kernel/user process boundary keeps user-mode code out of the kernel image.
