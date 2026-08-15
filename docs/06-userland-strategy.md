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

The unix-swap is done as commits on the Wine fork's `proskrnl-target` branch, pinned at
`third_party/wine`. **The line count of that diff vs. winehq is the project's "hack
meter"** — if it grows, the design has drifted. What the diff may contain is governed by
**Constitution Art. 10 / gate G9**: unixlib plumbing and build glue only, never PE-side
behaviour, and never a change that masks a proskrnl divergence.

## One tree, three roles: the dormancy invariant

The single pinned tree serves three roles at once, deliberately:

1. **Oracle** — built as regular Linux Wine; `tests/run/run.sh oracle` and the
   differential fuzzer run against it (Art. 6: it is the behavioral spec). "Regular" is
   load-bearing and has cost the project twice: a Wine configured without a backend does
   not fail, it answers *plausibly* without one. GUI-3 fixed the font half
   (`--with-freetype` against the pinned FreeType — an oracle with no fonts silently
   answered metric questions from nothing); the display half was fixed the same way, by
   building `--with-x` and giving every leg that runs the oracle its own Xvfb at a fixed
   geometry (`tests/run/run.sh start_xvfb`). Under the `--without-x` build that preceded
   it, user32 refused every window and no oracle answer about a window existed at all.
   The environment is pinned around it for the same reason — a created (never copied)
   scratch wineprefix, `LC_ALL=C.UTF-8`, not root, one screen size — because each of
   those, left to the host, changed an answer.
2. **Userland source** — the same build's PE artifacts (`ntdll.dll`,
   `kernel32`/`kernelbase`) and `nls/` files are what `mkimage.sh` bakes onto proskrnl's
   boot volume (Makefile `WINFILES`).
3. **Contract source** — `tools/gen_abi.py` / `gen_syscalls.py` generate `abi/` and the
   syscall ids from its headers.

One pin keeps the three from drifting — and it means **the oracle tests the exact bytes
proskrnl ships**: the `ntdll.dll` the oracle suite exercises under Wine is byte-for-byte
the file on proskrnl's disk. That only works under one invariant:

**Every fork commit is dormant under regular Wine**, by one of (in order of preference):

1. **Runtime-dormant** — the change sits behind `if (!__wine_unix_call_dispatcher)`,
   which is non-NULL whenever a unixlib loaded (always, under real Wine) and NULL only on
   proskrnl, where no unixlib exists. Same bytes tested and shipped; zero gap. This is
   the sanctioned seam mechanism and, as of M7, the only one in use.
2. **Additive-by-construction** — new files / new build targets that never enter any
   binary the oracle executes (the future `winefb.drv`; wineserver-lite). Sharp edge:
   wineserver-lite must be a **new build target** assembled from the keep-list above,
   never an in-place stripping of `server/` — that would mutate the oracle's wineserver
   and corrupt the spec.
3. **Compile-time-dormant** (escape hatch; documented here, built only when first
   needed) — `#ifdef PROSKRNL_TARGET` with two out-of-tree build directories from the
   **same pin**: an unflagged oracle build and a flagged target build. Still one tree,
   one pin, one `abi/` source; the tested-vs-shipped delta narrows to exactly the
   grep-auditable `#ifdef PROSKRNL_TARGET` regions. Enacting this hatch is a visible,
   gated event: the same PR must amend this section and `tools/setup_linux.sh`.

**The canonical worked example is the conhost seam commit** on the fork — "conhost: pump
the kernel ConDrv transport when no wineserver is below" (M9; superproject context:
`31e7b57`). Its shape is the one to imitate when adding a new seam, rather than inventing
a fresh arrangement: the two `get_next_console_request` call sites take the proskrnl leg
only after ntdll's own no-unixlib fallback answers a **side-effect-free probe** with
`STATUS_NOT_SUPPORTED` — the guard is the oracle's own refusal, a level-1 runtime
dormancy — and the transport implementation lives in **new files**
(`programs/conhost/proskrnl.{c,h}`) that are dead code in the oracle's `conhost.exe`
(level 2). Probe first; guard the proskrnl leg behind behaviour only a missing unixlib
produces; keep the implementation additive.

`run.sh oracle` running the **patched** tree is therefore intentional and load-bearing:
a green oracle run is the continuous, empirical proof that every seam commit is
behavior-neutral under Wine. Measure the meter with `tools/hack_meter.sh`. The base is
the fork's own `master` branch, kept pointing at the winehq commit `proskrnl-target` is
based on — a base bump fast-forwards `master` to the new winehq commit in the same push
that rebases `proskrnl-target` onto it, so the meter derives entirely from the fork and
no separate SHA needs recording.

**Rejected: two submodules** (a vanilla `wine-oracle` + a patched `wine-target`, pinned
to different branches). It downgrades the dormancy enforcement from empirical (the
oracle *runs* the patched bytes) to a promise (nothing ever executes the patched PE code
under a known-good host again), doubles the ~40-minute build, the disk, and the pin-bump
ceremony, and creates a three-way drift hazard between the abi-generation, oracle, and
target trees that would need its own merge-base-equality check — machinery to police a
problem the split itself created. A worktree-of-the-merge-base variant is strictly worse:
it pays the second build *and* loses tested-bytes even for dormant patches. If a
non-dormant change ever becomes necessary, the answer is level 3 above, not a second pin.

## Landing a fork commit (the recipe)

The mechanics of a Wine modification, end to end — there is no other path (no patches
directory, no vendored diffs, no build-time patching):

1. **Commit on the fork.** Inside `third_party/wine`, commit to `proskrnl-target` — one
   logical change (Art. 10) whose message carries the required header: what it changes /
   why the unixlib seam (and not the kernel) is the right place / upstream disposition
   (`upstreamable` | `proskrnl-only` | `temporary`-until-a-named-feature) — and names its
   dormancy mechanism (level 1/2/3 above). Follow the conhost seam commit's shape.
2. **Push the fork branch** to the fork remote (the submodule's origin,
   `proskrnl-target`). On a winehq base bump, `master` is fast-forwarded to the new base
   in the same push that rebases `proskrnl-target` onto it (the hack-meter base).
3. **Bump the pin in the superproject**: one pin-bump commit updating the
   `third_party/wine` SHA. Its message/PR reports the old → new hack meter
   (`tools/hack_meter.sh`) with a justification for any growth, and states that
   `tests/run/run.sh oracle` was re-run green on the new pin — the dormancy proof.

## Checkout: submodule, pinned

Wine lives at `third_party/wine` as a **git submodule**, SHA-pinned, so proskrnl commits
and Wine commits correspond and `git bisect` works across both repos.

- Origin is a **GitHub fork**; every Wine modification is a commit on its
  `proskrnl-target` branch, pinned by the submodule — there is no patches directory,
  no vendored diffs, no build-time patching. The submodule diff vs. winehq is the hack
  meter (Art. 10 / gate G9).
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

**Optional GUI-7:** the ReactOS shell for a Windows-looking desktop. A separate integration
effort (registry via ROS `mkhive` INF data, shell32-stack build glue, version/layout/COM
mud), governed by a `user/dllmap.toml` that declares which DLL comes from which upstream —
the collision map. Do this *after* Wine desktop works, so there is a working regression
baseline to bisect against.
