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
pinned ≥ 9.0 — see below), and `wine` (both the `abi/` generation source *and*
the ntapi oracle runtime). `tools/mkimage.sh`, `tools/qemu.sh`, and
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
- **qemu** — **QEMU must be ≥ 9.0**: the kernel's clock drives the LAPIC timer
  in x2APIC mode, and QEMU's TCG only gained x2APIC in 9.0 — on Ubuntu 24.04
  LTS's QEMU 8.2 the calibration silently reads a dead timer and `make test`
  hangs after `[KTEST] pool PASS`. 24.04 ships 8.2, so the pinned submodule
  (official GitHub mirror, `x86_64-softmmu` only) is built instead of trusting
  the distro.
- **wine** — the ntapi oracle runtime, built (64-bit only, no GUI/font
  dependencies) from the very same pinned tree `abi/` is generated from, so
  the oracle and the contract cannot version-diverge.

The first run takes a while (QEMU and Wine are real builds); re-runs skip
finished work. A distro QEMU ≥ 9.0 (Ubuntu ≥ 24.10, recent Fedora/Arch) also
works — the runner scripts prefer the in-tree builds and fall back to PATH,
and `QEMU=`, `WINE=`, `LIMINE=`/`LIMINE_SHARE=` override either way.

### ntapi oracle target (both hosts; from M2, not needed for M1)

**mingw-w64** builds the tests as a Windows `.exe` (`docs/14`) and a **Wine**
runtime runs it: `tests/run/run.sh oracle`. On Linux both come from
`tools/setup_linux.sh` (the oracle wine is the pinned `third_party/wine` — see
above). On macOS, Homebrew's `wine-*` casks are deprecated (they fail macOS
Gatekeeper) — on Apple Silicon use the Game Porting Toolkit's `wine64`, or
better, run the oracle target on Linux/CI or Windows, which is smoother than
local macOS Wine.

## Status

**CUI-1 complete** (on M10's full Wine CUI userland): first boot runs
`wineboot --init`. `smss.exe firstboot` (`KiRunFirstBoot`) spawns a standalone
`wineboot.exe`, which drives `wine.inf`'s ~500-line machine-state registry
payload through `rundll32 setupapi,InstallHinfSection` children — the Cm
integration test ADR 0008 promised and an `NtCreateUserProcess` stress test.
The populated hive (~35 KB of `HKLM\Software` + `HKLM\System`) persists and
survives reboot; wineboot's own `.update-timestamp` check makes later boots
skip the work. The no-RTC deviation is retired: the CMOS clock seeds
`SystemTime` and FAT timestamps at boot. Two runtime-dormant setupapi seam
commits on the fork (ole32 + shell32 tolerance) let a registry-only install
run on a disk that bakes only the CUI DLL set; the baked `wine.inf` is
filtered to registry-only sections at image-bake time (`tools/filter_inf.py`).
The registry differential vs. the oracle's prefix (`tests/run/run.sh
firstboot`, the milestone's Art. 6 conviction gate) is green: the whole INF
payload — 195 keys / 345 values — matches the oracle exactly. **Not yet:**
the `HKLM\Software\Wow6432Node` mirror keys (WOW64 scope) and HKCU
population (needs the token surface, CUI-2); the differential excludes both
(`docs/03` "CUI-1 firstboot notes").

**CUI-2 complete**: the Se minimal-but-real security model. A real Ob token
object with ONE fixed identity — wineserver's `token_create_admin`,
byte-identical (user `S-1-5-21-0-0-0-1000`, 8 groups, 21 privileges, session
1, `TokenElevationTypeLimited`) — and the twelve token/security syscalls the
already-baked DLLs read (`kernel/se/`): open/query/adjust/duplicate,
`NtPrivilegeCheck`, `NtAccessCheck` (the wineserver ACE walk),
`NtQuery/SetSecurityObject`, `NtAllocateLocallyUniqueId`, plus the magic
token pseudo-handles. Pinned by `tests/ntapi/sem_se/` — 8 tests green on the
oracle AND proskrnl (Art. 5/6) — and by the acceptance the milestone names:
Wine's unmodified `whoami.exe` opens its own token under cmd.exe and prints
the logon SID (`tests/run/run.sh console`). HKCU now resolves
(`RtlFormatCurrentUserKeyPath` → `\Registry\User\S-1-5-21-0-0-0-1000`).
**Not yet:** impersonation attach (thread tokens — CUI-3, the SCM needs
them); object create/open stays always-allow (`NtAccessCheck` is a service,
Ob grants unconditionally); `NtSetInformationToken`/`NtFilterToken`/linked
tokens stay unimplemented until a baked caller convicts (`docs/03` "CUI-2 Se
notes").

Next: **CUI-3..CUI-5** — the SCM (services.exe + rpcss over npfs), the
process ecosystem, sockets — or **the GUI path (GUI-1+)** — pixels/input,
win32u (`docs/02`); either way, growing the winetest manifest as its parked
blockers land (`docs/03` "M10 winetest notes").

## Build instructions

```sh
make test    # build the image, boot headless in QEMU, verify proskrnl's kernel-mode tests pass
make run     # boot interactively: a cmd.exe prompt on your terminal ('exit' powers off)
tests/run/run.sh oracle     # the ntapi contracts, green against Wine/Windows ntdll
tests/run/run.sh proskrnl   # the SAME test .exes, green ON the kernel (baked at C:\ntapi\)
tests/run/run.sh fuzz       # the differential fuzzer: random Nt* sequences, oracle vs kernel
tests/run/run.sh persist    # tests that registry values survive a reboot (boot twice)
tests/run/run.sh console    # tests that typing into the serial console is working
tests/run/run.sh winetest   # runs the curated subset of winetest
tests/run/run.sh firstboot  # CUI-1: diff the firstboot registry against the oracle's prefix
```

## License

**GPL-2.0** — see [`LICENSE`](LICENSE) and `docs/11-licensing.md`. Third-party components
keep their own licenses (Wine is LGPL-2.1; the vendored Limine header is BSD-2-Clause);
the kernel/user process boundary keeps user-mode code out of the kernel image.
