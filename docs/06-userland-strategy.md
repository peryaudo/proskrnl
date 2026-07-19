# 06 — User-land Strategy

## The principle: take each part from whoever is best at it

Three projects, each contributing only the one thing it is uniquely good at:

| Layer | From | Their unique strength |
|---|---|---|
| NT semantics (the kernel) | **proskrnl** | the part Wine structurally cannot reproduce |
| Win32 runtime (PE DLLs) | **Wine** | 30 years of message-ordering/API compatibility |
| Shell (optional, later) | **ReactOS** | the one area they wrote themselves, from scratch |

proskrnl is the only ground on which Wine and ReactOS can actually meet: Wine has the
user-land but no kernel; ReactOS has the shell but pays the driver-ABI/Mm-Cc tax forever.

## What "reuse Wine's PE layer" means precisely

A Windows app cannot run alone; it calls `kernel32.dll`, `user32.dll`, etc. Wine
reimplements those. Modern Wine builds them as **real PE files** (post-2019 "PE
conversion") and splits each into:

- **PE side** — the Windows logic, built Windows-format, visible to the app. Holds the
  value (arg checks, error codes, internal state, message ordering).
- **unixlib side** — talks to the host, built host-format, thin plumbing.

They meet across a thin, explicit function-table boundary. **We keep the PE side and
replace the unixlib side with syscall stubs to our own kernel.** ntdll's Ldr (PE loader),
Rtl, and SEH unwind logic come along unchanged. This is precisely NT's own structure (a
PE ntdll that syscalls), so it does not violate "no hacks."

The unix-swap is done via `user/wine/patches/`. **The line count of that directory is the
project's "hack meter"** — if it grows, the design has drifted. What may live there is
governed by **Constitution Art. 10 / gate G9**: unixlib plumbing and build glue only,
never PE-side behaviour, and never a patch that masks a proskrnl divergence.

## Checkout: submodule, pinned

Wine lives at `third_party/wine` as a **git submodule**, SHA-pinned, so proskrnl commits
and Wine commits correspond and `git bisect` works across both repos.

- Origin is a **GitHub fork**; every Wine modification is a commit on its
  `proskrnl-target` branch, pinned by the submodule — that commit is the operative
  change. `patches/` is the mechanically exported diff vs. winehq: bookkeeping and hack
  meter only, never hand-edited, never applied at build time (Art. 10 / gate G9).
- Isolate at `third_party/` also for **license** clarity (Wine is LGPL; the process
  boundary keeps the kernel's license free — see `docs/11`).
- Provide a **partial-build** mode in `build.sh` (ntdll + a few DLLs) from day one; M7
  needs only ntdll. Built DLLs are *not* committed; `mkimage.sh` bakes them into the disk
  image.

## wineserver: kill it, keep only the desktop remnant (route (a))

For CUI, wineserver is **not present** — its jobs (objects, handles, sync, registry,
process management) are the real kernel's. For GUI under route (a), a **stripped
wineserver** survives *only* as the holder of desktop state:

| server/ file | fate | reason |
|---|---|---|
| `window.c` `queue.c` `class.c` `winstation.c` `hook.c` `clipboard.c` `atom.c` | **keep** | this *is* the desktop state |
| `object.c` `handle.c` `request.c` `main.c` | keep (internal bookkeeping) | HWNDs aren't NT handles |
| `process.c` `thread.c` | keep, slim | client tracking only |
| `event/mutex/semaphore/timer/completion` | **kill** | the kernel has these |
| `file/fd/mapping/named_pipe/sock/console` | **kill** | the kernel has these |
| `registry.c` | **kill** | Cm exists |
| `token/security/debugger/ptrace` | **kill** | unneeded |

~30% survives — and it is exactly Wine's *strongest* code (message-order compat), while
the killed part is exactly what Wine was *weakest* at and we implemented ourselves (async
I/O, share modes, npfs). The cut line matches the project thesis.

Transport is **not npfs** (that would be needed only for NT-faithfulness, and wineserver
is not NT anyway): a **shared section + two kernel events** (both already exist). This is
also what pulls calc.exe off the npfs critical path. The genuine friction is backing the
message queue with a kernel event so `MsgWaitForMultipleObjects` works; as a bonus,
alertable waits and user APCs become the *real* kernel's, moving us closer to NT. See
`docs/07`.

## The shell: Wine's desktop first, ReactOS shell optional

**Take Wine's desktop, not ReactOS's shell (initially).** Wine's `programs/explorer` gives
a desktop window (wallpaper), a system tray, and a simple file browser — but **no taskbar,
Start menu, or desktop icons** (Wine delegates those to the host). The golden image is a
wallpaper rectangle.

Why Wine's, not ReactOS's:

- **shell32 collision.** ReactOS's explorer is written against ReactOS's shell32; Wine has
  its own. They cannot coexist (same name, same CLSIDs). explorer and shell32 are a
  *set* — their seam is an **undocumented internal interface** (same-vendor, so never
  specified), and each project invented its own. Taking ROS explorer forces ROS shell32,
  which then runs on Wine's user32/gdi32 — a combination **nobody has tested**.
- **version mismatch.** ROS shell assumes NT 5.2; modern Wine defaults to Win10 and
  changes behaviour by version.
- **build extraction.** Pulling shell32 out of ReactOS's CMake/RosBE for mingw-w64 against
  Wine import libs is unexplored.
- **license.** ROS shell is GPLv2; Wine desktop is LGPL only. Route (a)'s process boundary
  keeps the kernel clean either way, but Wine-only is simpler.

`wineboot.exe` (a plain PE) processes `wine.inf` at runtime to initialize the registry
(CLSIDs, defaults, folders) by calling our `NtCreateKey` — so **`gen_hive.py` is not
needed**, and wineboot doubles as the Cm integration test. This touches no "no hacks"
rule.

The **only real "lie"** Wine's shell32 tells is `winemenubuilder` writing Start-menu
shortcuts into the *host's* application menu — meaningless here (no host); it likely
no-ops.

**Optional M17:** the ReactOS shell for a Windows-looking desktop. A separate integration
effort (registry via ROS `mkhive` INF data, shell32-stack build glue, version/layout/COM
mud), governed by a `user/dllmap.toml` that declares which DLL comes from which upstream —
the collision map. Do this *after* Wine desktop works, so there is a working regression
baseline to bisect against.
