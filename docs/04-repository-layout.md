# 04 — Planned Repository Layout

The tree is a projection of the design. Three principles shape it:

1. **NT prefixes become department names.** Ke/Mm/Ob/Ps/Io/Cm mirror Windows Internals,
   so the code cross-references the book and reads as a teaching artifact.
2. **ABI-forming headers are physically isolated.** Only `abi/` holds contracts; changing
   anything there is a compatibility break. Everything else is free to be rewritten. This
   is the structural fence against building ReactOS's prison.
3. **Tests are first-class.** `tests/` is top-level and expected to be *larger* than the
   kernel. That is healthy here, not bloat.

Notably absent — and their absence *is* the design: **no `hal/`, no `cc/`, no
`irql`/`dpc` in `ke/`.** The page cache lives in `mm/pagecache.c`; platform code is
directly in `arch/`. The missing directories testify to the dropped tax.

```
proskrnl/
├── Makefile                        # kernel + thin superbuild (ADR 0009)
├── README.md
├── docs/                            # this constitution
│   ├── 00-overview.md … 19-io-strategy.md
│   ├── CONTRIBUTING.md
│   └── adr/                         # architecture decision records
│
├── abi/                             # ★ the CONTRACT. kernel+user shared. generated where possible.
│   ├── ntstatus.h                   # NTSTATUS values (match real NT)
│   ├── ntdef.h                      # UNICODE_STRING, OBJECT_ATTRIBUTES, LARGE_INTEGER…
│   ├── ntpebteb.h                   # PEB/TEB layout (byte-exact; static_assert offsets)
│   ├── ntpsapi.h                    # RTL_USER_PROCESS_PARAMETERS
│   ├── ntioapi.h                    # IO_STATUS_BLOCK, FILE_*_INFORMATION classes
│   ├── ntmmapi.h                    # MEM_RESERVE/COMMIT, PAGE_* protection
│   ├── ntkeapi.h                    # KUSER_SHARED_DATA
│   ├── ntregapi.h                   # KEY_*_INFORMATION
│   └── syscall_numbers.h            # our own numbers (the one part free to invent)
│
├── kernel/
│   ├── init/
│   │   ├── main.c                   # KiSystemStartup-equiv: per-department phase init
│   │   ├── bootvid.c                # the boot console: DbgPrint mirrored onto the
│   │   │                            #   Limine framebuffer (Flanterm), released to
│   │   │                            #   the GUI at FbInitialize. Serial is unaffected
│   │   └── initrd.c                 # M5 seed RAM-disk
│   ├── ke/                          # M1–M2
│   │   ├── sched.c                  # scheduler (internals free; keep it simple)
│   │   ├── thread.c                 # KTHREAD, context-switch high half
│   │   ├── wait.c                   # ★ DISPATCHER_HEADER, wait blocks, WaitFor*
│   │   ├── event.c / mutex.c / sema.c / timer.c
│   │   ├── apc.c                    # ★ kernel/user APC queues + delivery
│   │   └── irq.c                    # interrupt dispatch (no IRQL; plain top/bottom half)
│   ├── ob/                          # M3
│   │   ├── object.c                 # type system, refcount, create/delete
│   │   ├── handle.c                 # handle table (array + lock)
│   │   ├── namespace.c              # \Device, \??, directories, symlinks
│   │   └── wait.c                   # handle→object resolution for NtWaitFor*
│   ├── mm/                          # M4–M5
│   │   ├── phys.c                   # physical page allocator
│   │   ├── pool.c                   # kernel heap (single pool, no Paged/NonPaged split)
│   │   ├── vad.c                    # address-space interval management
│   │   ├── virtual.c                # NtAllocate/Protect/FreeVirtualMemory
│   │   ├── section.c                # ★ sections: anonymous / file / image
│   │   ├── pecoff.c                 # PE parser for image sections
│   │   ├── fault.c                  # page fault: (later) COW, guard pages, demand-zero
│   │   └── pagecache.c              # ★ unified page cache (stands in for Cc)
│   ├── ps/                          # M4, M7
│   │   ├── process.c                # EPROCESS-equiv, NtCreateUserProcess
│   │   ├── thread.c                 # ETHREAD-equiv, TEB allocation
│   │   ├── peb.c                    # PEB/ProcessParameters build (follows abi/ strictly)
│   │   └── usermode.c               # ★ return path to KiUser{Exception,Apc}Dispatcher
│   ├── io/                          # M6
│   │   ├── file.c                   # FILE_OBJECT, NtCreateFile path resolution
│   │   ├── rw.c                     # NtRead/WriteFile, async skeleton
│   │   ├── async.c                  # ★ completion record (non-IRP), IOSB, APC/event/port
│   │   ├── ioctl.c                  # NtDeviceIoControlFile / NtFsControlFile
│   │   ├── query.c                  # NtQuery{Information,Directory}File info classes
│   │   ├── completion.c             # I/O completion ports
│   │   └── vfs.h                    # internal driver IF (file_operations-style; FREE)
│   ├── cm/                          # M8
│   │   ├── registry.c               # NtCreateKey/SetValueKey/QueryValueKey
│   │   └── hive.c                   # persistence (our own format)
│   ├── se/
│   │   └── stub.c                   # always-allow + correctly-shaped token
│   ├── win32k/                      # ★ ROUTE (b) ONLY — absent under route (a)
│   │   └── (see docs/07)            #   present only if desktop state moves into kernel
│   └── syscall/
│       ├── table.c                  # function table (SSDT-equiv)
│       ├── entry.S                  # syscall/sysret entry
│       └── uaccess.c                # user-pointer validation, fault-trapping copy in/out
│
├── arch/x86_64/                     # thin — HAL is absorbed here
│   ├── boot.S                       # Limine entry, long-mode scaffold
│   ├── trap.S / idt.c               # low-level exception/interrupt
│   ├── ctxswitch.S
│   ├── mmu.c                        # page-table ops
│   ├── lapic.c / hpet.c             # direct hardware (not abstracted)
│   ├── smbios.c / fwcfg.c           # firmware tables read for ourselves (SMBIOS; QEMU fw_cfg)
│   └── acpi.c / power.c             # ACPI tables (RSDP→FADT/DSDT \_S5/MADT); S5 power-off
│
├── drivers/                         # all statically linked; implement vfs.h directly
│   ├── virtio/
│   │   ├── pci.c                    # modern virtio-pci transport (the one bring-up path)
│   │   ├── virtqueue.c              # shared ring
│   │   └── blk.c / console.c / input.c
│   ├── condrv.c                     # M9: ConDrv-style console device, COM1 serial
│   │                                #   transport both ways        ★ HACK-004
│   ├── fb.c / fbproto.h             # GUI-1: \Device\Fb0            ★ HACK-001
│   ├── hid.c / hidproto.h           # GUI-1: \Device\Input0         ★ HACK-002
│   └── usb/                         # USB-1: the bare-metal input path behind HACK-002
│       ├── xhci.c                   # xHCI host controller: ports, slots, EP0, one interrupt IN
│       ├── hidboot.c                # HID boot-protocol keyboard/mouse -> \Device\Input0/1
│       └── usbkeymap.h              # generated: HID usage -> evdev (tools/gen_usb_keymap.py)
│
├── fs/
│   ├── fat32/
│   │   ├── fat.c / dir.c / file.c
│   │   └── ntsem.c                  # ★ share modes, case-insensitivity, del-on-close, locks
│   └── npfs/                        # M9 (OFF the calc critical path)
│       └── pipe.c                   # byte/message mode, listen/connect
│
├── user/                            # user-mode side
│   ├── smss/                        # the session manager: the ONE image the kernel starts;
│   │   │                            #   spawns servers + every flow via NtCreateUserProcess
│   │   └── firstboot.c              # runs wineboot.exe on first boot
│   └── wine/                        # build glue; Wine itself is the third_party/wine
│       │                            #   submodule — unixlib→syscall swaps live as commits
│       │                            #   on its proskrnl-target fork branch (Art. 10 / G9)
│       │                            # MIRRORS the pinned tree: every directory below
│       │                            #   shadows the third_party/wine one of the same name
│       ├── include/                 # the POSIX headers mingw lacks (pthread, dlfcn,
│       │                            #   poll, mmap, dirent) + config.h/unixlib.h shadows
│       ├── dlls/                    # glue for pinned sources WE compile and link
│       │   ├── win32u/              # ★ win32u's unix half, compiled as PE (GUI-2)
│       │   │   ├── glue.c           #   pthreads, the user-mode callback pair, ntdll's
│       │   │   │                    #   unix-side helpers, the libc corners
│       │   │   ├── font_unix.c      #   open/mmap/opendir for the font backend, over Nt*
│       │   │   └── freetype_link.c  #   dlsym → the linked-in FreeType (generated table)
│       │   └── winefb.drv/          # ★ display backend written AS a Wine driver
│       │       ├── init.c           #   user_driver_funcs table
│       │       ├── display.c        #   mode enumeration, \Device\Fb0 map, desktop create
│       │       ├── blit.c           #   dibdrv output → scanout, the repaint authority
│       │       ├── compose.c        #   the z-order queries behind clip-at-flush (GUI-4)
│       │       ├── cursor.c         #   the software cursor: the window's HCURSOR,
│       │       │                    #   decoded in the owning process (pSetCursor),
│       │       │                    #   overlaid by every writer
│       │       └── cursorshape.h    #   the cursor image contract, shared with the pump
│       ├── programs/                # per-exe standalone-PE glue (CRT entry + the imports
│       │   │                        #   this build does not bake) around the pinned tree's
│       │   │                        #   OWN program objects — no program source is copied
│       │   ├── conhost/             # M9 + GUI-5: headless_stubs.c / window_glue.c are the
│       │   │                        #   two links' halves (serial console vs. a real window)
│       │   ├── cmd/ · rundll32/ · wineboot/          # M10 / CUI-1
│       │   └── tasklist/ · taskkill/                 # CUI-4
│       └── wineserver-lite/         # ★ wineserver's GUI object model (shadows server/),
│           │                        #   ONE state machine with two links (HACK-003)
│           ├── common/              # BOTH links: shim.c (the session mapping, queue
│           │                        #   events, timeouts, the one process/thread),
│           │                        #   srv_glue.c, transport.h — the wire both ends share
│           ├── client/              # win32u.dll only: call.c == wine_server_call
│           └── server/              # wineserver-lite.exe only: main.c == the serve loop
│                                    # (the boot-module test clients live under tests/)
│
├── third_party/
│   ├── wine/                        # submodule, SHA-pinned (fork on GitHub recommended)
│   ├── freetype/                    # submodule, SHA-pinned; cross-built as a PE static
│   │                                #   library and linked into win32u (GUI-2)
│   └── flanterm/                    # submodule, SHA-pinned; the ONLY third_party code
│                                    #   compiled into the kernel image (BSD-2-Clause,
│                                    #   unmodified) — kernel/init/bootvid.c (docs/11)
│
├── system/                          # "furniture": data, not code (GUI/desktop era)
│   └── skel/
│       └── layout.txt               # C:\Program Files, Documents and Settings, …
│
├── tests/                           # ★ first-class, expected to exceed kernel size
│   ├── kmt/                         # in-kernel unit tests (M2–M3: wait/apc/ob)
│   ├── boot/                        # M4–M8 boot-module clients: flat binaries (crt0.S,
│   │                                #   user.ld) + minimal PEs, run by the kernel's runners
│   ├── clients/                     # M7/M9 acceptance PEs over the baked userland
│   │                                #   (hello.c = ntdll-only + SEH; m9_*.c = kernel32/base)
│   ├── cui/                         # M10 third-party-CUI stand-ins, full mingw CRT
│   ├── ntapi/                       # Nt* conformance: ONE PE .exe per test, oracle + proskrnl (docs/14)
│   │   ├── ntapi.h                  # harness API: START_TEST / ok / todo_proskrnl / skip
│   │   ├── ntapi.c                  # freestanding harness + runtime side probe + [KTEST] verdicts
│   │   ├── syscall/                 # generated raw-syscall stubs (tests/boot flat clients)
│   │   ├── sem_file/                # share modes, info classes, async+APC
│   │   ├── sem_mm/                  # reserve/commit, guard pages, (later) COW
│   │   └── sem_wait/                # wait-all/any, alertable, APC interruption
│   ├── fuzz/                        # differential fuzzer: random Nt* sequences vs. Windows
│   ├── winetest/                    # the winetest gate: manifests + glue/ (the
│   │                                #   .CRT$X?? boundary symbols and user32 stand-ins)
│   ├── gui/
│   │   ├── screenshot.c             # FB hash / PPM dump
│   │   ├── golden/                  # expected images (desktop.ppm is the goal)
│   │   └── shell/run-desktop.sh
│   └── run/                         # runner: oracle (.exe) + proskrnl (QEMU→serial→verdict)
│
├── tools/
│   ├── mkimage.sh                   # build FAT32 image (NLS, hive, Wine DLLs, skel)
│   ├── gen_syscalls.py              # numbers → stubs + table
│   ├── gen_abi.py                   # ★ generate abi/ numeric values from Wine headers
│   └── qemu.sh                      # launch config (virtio-fixed, headless, exit-device)
│
├── docs/adr/                        # (listed above)
├── licenses/                        # LGPL / (GPL if ROS shell used) / MAP.md
└── LICENSE                          # GPL-2.0 (kernel license)
```

## Build model (federated — ADR 0009)

Three independently-built components joined by **artifacts, not build graphs**: the kernel
(our **Make** build, clang `--target=x86_64-elf -ffreestanding`), Wine (its *own* autotools,
driven by `tools/setup_linux.sh`), and — at GUI-6/GUI-7 only — the ReactOS shell (its *own*
CMake/RosBE). Each foreign project builds itself into PE binaries; `tools/mkimage.sh` bakes
those plus the kernel into the FAT32 image. The top-level `Makefile` is a thin orchestrator
(build kernel → bake the pinned PE output → run `mkimage.sh`), not a single graph that owns
everything.

One deliberate exception, added at GUI-2: the `win32u` target compiles Wine *sources* out of
the pinned tree with mingw rather than taking a built artifact. That is not a port of Wine
into our build system — it is the same trick `user/wine/programs/conhost/` has used since
M9, applied to the half of win32u Wine builds as a `.so` and we need as a `.dll`. Nothing is copied and
nothing is patched; the pinned tree stays the single source (docs/06 "one tree, three
roles").

The rule this encodes: **never port Wine or ROS into our build system.** Their build risk
(flag-combination extraction — `docs/06`, `docs/12`) lives inside their native builds and is
independent of ours; the clean PE-artifact seam is the same clean boundary the whole project
rests on.

## Size expectations

- `kernel/` ≈ 30k lines; `arch/` + `drivers/` + `fs/` ≈ 10k; GUI plumbing (GUI-1–GUI-5) ≈ 8k;
  GUI-6 ≈ 1.5k; `tests/` (self-authored) ≈ 18k. **Self-written total ≈ 70k**, realistically
  **100–140k** after error paths, info-class tails, `#ifdef` mud, and debug scaffolding.
- **Borrowed** (Wine PE, Wine tests, stripped wineserver, optional ROS shell/INF) ≈ 1.5M+.
  Leverage ≈ **25×**. See `docs/12` for the size analysis and where difficulty concentrates
  (the ~7k lines of `mm/{section,fault,pagecache}` + `ke/{wait,apc}` + `ps/usermode` are
  10% of the code and ~50% of the effort).

## How the tree maps to milestones

M1 = `arch/` + `init/` · M2 = `ke/` · M3 = `ob/` · M4 = `syscall/` + user split ·
M5 = `mm/section+fault+pagecache` · M6 = `io/` + `fs/fat32` + `drivers/virtio/blk` ·
M7 = `ps/usermode+peb` + `user/wine` · M8 = `cm/` + `smss` · M9 = `fs/npfs` + `condrv` ·
GUI-1 = `drivers/{fb,hid,virtio/input}` · GUI-2–GUI-5 = `user/wine/dlls/winefb.drv`
(+ `kernel/win32k` iff route (b)).
Progress is visible as a coloring of the tree.
