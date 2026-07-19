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
  LTS's QEMU 8.2 the calibration silently reads a dead timer and `make run`
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

**M7 complete: the unmodified Wine PE ntdll boots `hello.exe` on the kernel.**
M7 is the mountain: the process lifecycle and the ring-3 return protocol Wine's ntdll
depends on. The syscall boundary now speaks the **NT x64 calling convention using the
pinned Wine tree's own 64-bit syscall ids** (generated from `dlls/ntdll/ntsyscalls.h`),
so an *unmodified* PE ntdll's thunks — which place that id in `eax` and execute a raw
`syscall` — land on the right kernel service; `kernel/syscall/entry.S` synthesizes a full
trap frame and returns via `iretq` so an arbitrary user context can be restored. On top of
that the kernel now builds the **byte-exact PEB / TEB / `RTL_USER_PROCESS_PARAMETERS` /
KUSER_SHARED_DATA** an unmodified ntdll reads (`kernel/ps/peb.c`; the shared page mapped at
NT's fixed `0x7ffe0000` with `SystemCall == 0`, keeping Wine's thunks on the raw-syscall
path), creates **user threads** as first-class Ob objects (`kernel/ps/thread.c` —
`NtCreateThreadEx`, join via handle, `NtQueryInformationThread`), delivers **user-mode
APCs** through `KiUserApcDispatcher` at alertable points (`kernel/ke/apc.c`), and implements
the **exception/return protocol** (`kernel/ps/usermode.c`): a contained fault (or
`NtRaiseException`) is delivered to the process's `KiUserExceptionDispatcher` with an
`EXCEPTION_RECORD` + `CONTEXT` laid out exactly where Wine's dispatcher reads them, and
`NtContinue` / `NtContinueEx` resume an arbitrary context. The dispatcher entry points are
resolved from the image's export table exactly as they will be from ntdll
(`kernel/mm/pecoff.c`). The acceptance artifact is a real PE client,
`user/init-tests/m7_smoke.exe`, that drives the whole boundary from ring 3 — reading the
kernel-built PEB/TEB/KUSER_SHARED_DATA, creating and joining a second thread, taking a
delivered APC, flipping page protection, and **catching an access violation in its own
`KiUserExceptionDispatcher` and resuming via `NtContinue`** (the milestone's SEH test) —
and exits cleanly. On top of that boundary the **Wine bring-up itself** now runs: the
pinned fork's `proskrnl-target` branch replaces ntdll's unixlib plumbing with
null-dispatcher fallbacks (27 lines — the whole "hack meter" diff), and the build bakes
the *unmodified* PE `ntdll.dll` + `kernel32`/`kernelbase` and the NLS files onto the FAT
boot volume as `C:\windows\system32`. The kernel maps ntdll beside the executable, resolves
`LdrInitializeThunk`/`RtlUserThreadStart`/`KiUser*` from **its** exports, and starts the
first thread on the NT CONTEXT protocol; ntdll's own loader then runs the process — heap,
TLS, NLS tables mapped via `NtInitializeNlsFiles`/`NtGetNlsSectionPtr`, `kernel32.dll`
loaded from disk through `NtCreateSection(SEC_IMAGE)`. The acceptance client
`user/hello/hello.exe` — a real MS-ABI PE **linked only against Wine's ntdll** — prints
over `NtDisplayString`, then takes a deliberate access violation inside a
`.seh_handler`-guarded frame and resumes through ntdll's real `KiUserExceptionDispatcher` →
`RtlDispatchException` → `.pdata` unwind path (docs/02's SEH test), and exits 0:
`[KTEST] module hello.exe PASS`, `[KTEST] M7 PASS`. After this, the rest of Wine is data.

**Everything below describes the M1–M6 foundation this builds on.** The repository began as
a **constitution** — documents that fix the design
decisions before implementation, so neither a human nor an LLM contributor can quietly erode
them (start at `docs/09`). On the M1 bring-up (Limine boot, register-dumping panic handler,
physical page frames), the M2 multithreading core (own page tables, one pool, 32-level
priority scheduler under one dispatcher lock, the NT dispatcher objects and `KeWaitFor*`),
the M3 **object manager** (refcounted headers + type system, growable handle table, the
`\`-rooted namespace), the M4 **user-mode/syscall boundary** (own GDT/TSS +
`syscall`/`sysret`, per-process address spaces and handle tables, the reserve/commit VAD
engine, TEB allocation, user-fault containment), and the M5 **section engine** (anonymous /
file-backed / `SEC_IMAGE` sections, the PE32+ parser, NT-shaped guard-page stacks), the
kernel now has a real storage stack. M6 adds a **virtio-blk driver** over the modern
virtio-pci transport (`drivers/pci.c`, `drivers/virtio/` — a polled split virtqueue,
written from the OASIS virtio 1.2 specification with per-constant citations, the pinned
QEMU as runtime cross-check), **FAT32 read/write** on the GPT boot disk (`fs/fat32/` —
BPB/FAT-chain/long-file-name handling per the Microsoft FAT specification; one FCB per
on-disk file carries the NT share/lock/delete state), and the **I/O manager**
(`kernel/io/` — Device and File object types, a namespace parse hook so
`NtCreateFile("\??\C:\...")` resolves through the `C:` symlink into the FS, an internal
`file_operations`-style vfs, and no IRP — docs/03). File data lives in the generalized
**unified page cache** (`kernel/mm/pagecache.c`): `NtReadFile`/`NtWriteFile` copy through
the very frames data sections map, so the mapped-view/read/write coherence stress test
(`tests/ntapi/sem_mm/file_coherence.c`, the docs/08 "self-checking stress test") is
structural rather than lucky, and every write goes straight to disk (immediate writeback,
Art. 3). The surface — `NtCreateFile`/`NtOpenFile`/`NtReadFile`/`NtWriteFile`/
`NtQueryInformationFile`/`NtSetInformationFile`/`NtQueryDirectoryFile`/
`NtQueryAttributesFile`/`NtFlushBuffersFile`/`NtLockFile`/`NtUnlockFile` — carries the NT
file semantics this project exists for: share modes (`STATUS_SHARING_VIOLATION`),
case-insensitive lookup with case-preserving long names, delete-on-close and
`FileDispositionInformation`, byte-range locks, and the async-completion contract (IOSB
written before the completion event fires), all pinned FIRST on the Wine oracle
(`tests/ntapi/sem_file/`, Art. 5) and green on the kernel; `NtCreateSection(SEC_IMAGE)`
now maps images from on-disk files. `abi/` (now also `ntioapi.h`) stays generated from
Wine's headers by `tools/gen_abi.py` + `tools/gen_syscalls.py` (Art. 4 — no hand-typed
constants):

```sh
make run     # build the image, boot headless in QEMU, verify [KTEST] M7 PASS on serial
tests/run/run.sh oracle     # the ntapi contracts, green against Wine/Windows ntdll
tests/run/run.sh proskrnl   # the same contracts, green ON the kernel as flat-binary syscalls
tests/run/run.sh fuzz       # the differential fuzzer: random Nt* sequences, oracle vs kernel
```

The **differential fuzzer** (`tests/fuzz/`, `docs/08` "the hidden weapon") generates random
`Nt*` sequences, runs each on the Wine oracle and on proskrnl, and flags any divergence in
the normalized result trace; its op model is generated from the same syscall list, so the
M6 file surface became fuzzable the day it landed — and promptly convicted two real
divergences (a wrong-access `FileEndOfFileInformation` status pair and unwaitable file
handles), both fixed and pinned in `tests/ntapi/`. A checked-in `known_divergences.txt`
baseline keeps it green as a regression gate while documenting the current proskrnl-vs-Wine
gaps it surfaces.

Next: **M7** — `NtCreateUserProcess` + Wine's ntdll, the mountain: byte-exact
PEB/TEB/`RTL_USER_PROCESS_PARAMETERS`/KUSER_SHARED_DATA, thread creation, the
`KiUserExceptionDispatcher`/`KiUserApcDispatcher` return protocol, and Wine's ntdll PE
brought up with its unixlib replaced by our syscall stubs — after which "the rest of Wine
is data" (`docs/02`).

## License

**GPL-2.0** — see [`LICENSE`](LICENSE) and `docs/11-licensing.md`. Third-party components
keep their own licenses (Wine is LGPL-2.1; the vendored Limine header is BSD-2-Clause);
the kernel/user process boundary keeps user-mode code out of the kernel image.
