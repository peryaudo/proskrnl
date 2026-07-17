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
- **mtools** — `mformat`/`mcopy`, to populate the FAT32 ESP without mounting
  (`tools/mkimage.sh`).
- **gptfdisk** — `sgdisk`, to lay down the GPT + BIOS-boot partition the Limine BIOS
  image needs (`tools/mkimage.sh`).

### Linux (Debian/Ubuntu)

```sh
sudo apt install clang lld llvm make gdisk mtools
```

(`gdisk` is Debian's package name for gptfdisk's `sgdisk`; the distro clang/lld
on PATH are used as-is — no keg-only dance needed.)

**QEMU must be ≥ 9.0.** The kernel's clock drives the LAPIC timer in x2APIC
mode, and QEMU's TCG emulation only gained x2APIC in 9.0 — on Ubuntu 24.04
LTS's QEMU 8.2 the calibration silently reads a dead timer and `make run`
hangs after `[KTEST] pool PASS`. A distro package ≥ 9.0 (Ubuntu ≥ 24.10,
recent Fedora/Arch) is fine: `sudo apt install qemu-system-x86`. On 24.04,
build from source instead:

```sh
sudo apt install ninja-build meson pkg-config libglib2.0-dev libpixman-1-dev \
                 flex bison python3-venv
curl -LO https://download.qemu.org/qemu-10.0.2.tar.xz && tar xf qemu-10.0.2.tar.xz
cd qemu-10.0.2 && mkdir build && cd build
../configure --target-list=x86_64-softmmu --disable-docs --disable-user
make -j"$(nproc)" && sudo make install
```

**Limine** is not packaged in Ubuntu 24.04 LTS — build the deploy tool and boot
files from the v12.x branch (keep the major version in step with
`third_party/limine/README.md`; needs `git autoconf automake nasm` on top of
the packages above):

```sh
git clone --depth 1 --branch v12.x https://github.com/limine-bootloader/limine.git
cd limine
./bootstrap
./configure --enable-bios --enable-uefi-x86-64 \
    CC_FOR_TARGET=clang LD_FOR_TARGET=ld.lld OBJCOPY_FOR_TARGET=llvm-objcopy \
    OBJDUMP_FOR_TARGET=llvm-objdump READELF_FOR_TARGET=llvm-readelf
make && sudo make install    # /usr/local/bin/limine + /usr/local/share/limine
```

(On a distro that does package Limine — Arch, Fedora, Ubuntu ≥ 24.10 —
`tools/mkimage.sh` finds `/usr/share/limine` automatically; `LIMINE_SHARE`
overrides the search either way.)

### ntapi oracle target (both hosts; from M2, not needed for M1)

**mingw-w64** builds the tests as a Windows `.exe` (`docs/14`) and a **Wine**
runtime runs it. On Linux: `sudo apt install gcc-mingw-w64-x86-64 wine` and run
`tests/run/run.sh oracle`. On macOS, Homebrew's `wine-*` casks are deprecated
(they fail macOS Gatekeeper) — on Apple Silicon use the Game Porting Toolkit's
`wine64`, or better, run the oracle target on Linux/CI or Windows, which is
smoother than local macOS Wine.

## Status

**M2 complete.** The repository began as a **constitution** — documents that fix the design
decisions before implementation, so neither a human nor an LLM contributor can quietly erode
them (start at `docs/09`). On top of the M1 bring-up (Limine boot, register-dumping panic
handler, physical page frames), the kernel now runs real multithreading: its own page
tables, a single kernel pool (Art. 3: one pool), kernel threads with a 32-level priority
scheduler under one dispatcher lock (uniprocessor, no kernel preemption), and the NT
dispatcher — notification/synchronization events, mutexes (recursion, abandonment),
semaphores, notification/synchronization/periodic timers, and `KeWaitForSingleObject` /
`KeWaitForMultipleObjects` wait-any/wait-all with timeouts on a PIT-calibrated 1 ms clock.
All `Ke*` signatures match Wine's ntoskrnl exports; `abi/ntstatus.h` and `abi/ntdef.h` are
generated from Wine's headers by `tools/gen_abi.py` (Art. 4 — no hand-typed constants).
The in-kernel `tests/kmt` suite (ping-pong, wait-all atomicity, abandonment, timed waits,
priority ordering) is the milestone's proof:

```sh
make run     # build the image, boot headless in QEMU, verify [KTEST] M2 PASS on serial
```

Next: **M3** — Ob: object manager, handle table, `\Device`/`\??` namespace; minimal KASAN
(`docs/02`).

## License

To be fixed **before M13** (see `docs/11-licensing.md`). The kernel/user boundary is a
process boundary, which keeps the kernel's license free of the LGPL/GPL user-mode code.
