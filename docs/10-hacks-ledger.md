# 10 — Hacks Ledger

Every deliberate NT-absent addition is recorded here, in one format. This ledger is the
enforcement mechanism for Constitution Article 2 (downgraded rule) and Article 7
(additive/removable). **Its length is a metric:** if it grows beyond the entries below, the
design has drifted from "no hacks" toward ReactOS's compounding tax.

Rules for an entry:
- The addition lives **only** as a new device or new process at the *outside* of the
  boundary — never inside existing `Nt*` or Wine PE code.
- It has a **retirement condition**: the concrete state of the world under which it is
  deleted.
- It is **subtractable**: removing its files restores the prior kernel intact.

---

## Format

```
## HACK-NNN: <name>
Status:     proposed | active | retired
Introduced: <milestone>
Not in NT:  <what NT does instead>
Reason:     <why we add it anyway>
Scope:      <files touched — must be new files at the boundary's outside>
Retirement: <the condition under which this is deleted>
```

---

## HACK-001: `\Device\Fb0`

```
Status:     active (GUI-1: the Limine-set linear framebuffer, published as-is;
            GUI-2: mapped by winefb.drv, which blits dibdrv's surfaces to it)
Introduced: GUI-1
Not in NT:  NT owns the framebuffer behind a display driver, below win32k (WDDM/XDDM).
Reason:     We implement no display-driver model; win32u needs somewhere to blit.
Scope:      drivers/fb.c ; drivers/fb.h ; drivers/fbproto.h ;
            kernel/init/main.c (the FbInitialize call) ;
            user/wine/dlls/winefb.drv/display.c (GUI-2)
Retirement: if an NtGdi-side display-driver abstraction is ever built.
```

The device does no mode set, no drawing, no cursor: it publishes whatever
mode the bootloader chose and lets a process map it. Mapping rides the
ordinary Mm path — the device implements the existing `GetCache` vfs op and
returns a page cache whose frames are the scanout's physical pages, so
`NtCreateSection` + `NtMapViewOfSection` over the handle work unchanged and
`kernel/mm` gains nothing (G10/Art. 11). The wire contract is
`drivers/fbproto.h`; the mode ioctl is the only verb, and every other code
names itself on serial and refuses with `STATUS_NOT_IMPLEMENTED` (Art. 12).

## HACK-002: `\Device\Input0` / `\Device\Input1`

```
Status:     active (GUI-1: virtio-input keyboard, eventq polled from a
            blocking read -- no IRQ; statusq unconfigured; exclusive open;
            GUI-2: read by winefb.drv's input thread, injected as scancodes;
            GUI-4: a second virtio-input function -- QEMU's tablet -- joins
            as \Device\Input1: same per-stream contract (verbatim events,
            blocking, one exclusive reader), FILE_DEVICE_MOUSE, plus one
            ioctl reporting the device's ABS_INFO range verbatim)
Introduced: GUI-1
Not in NT:  NT routes raw input through win32k / csrss into the input queue.
Reason:     win32u needs a raw keyboard/mouse event source.
Scope:      drivers/hid.c ; drivers/hid.h ; drivers/hidproto.h ;
            drivers/virtio/input.c ; drivers/virtio/input.h ;
            kernel/io/file.c + kernel/init/main.c (the two init calls) ;
            user/wine/dlls/winefb.drv/input.c (GUI-2; GUI-4: + the pointer
            reader) ; user/wine/dlls/winefb.drv/cursor.c (GUI-4)
Retirement: if input routing moves into a kernel win32k (route (b)).
```

Reads deliver `virtio_input_event` records verbatim (`drivers/hidproto.h`):
no scancode translation, because translation is a keyboard layout and a
layout belongs in user32 above the boundary. Blocking-only, one reader at a
time per stream (enforced through the existing Io share engine, not a
private flag), no write path — the statusq that would carry LED output to
the device is deliberately unconfigured on both instances, and the missing
ops make the Io layer refuse rather than accept-and-drop (Art. 12). The
keyboard has no ioctl at all; the pointer has exactly one, answering the
absolute-axis range the device itself published, so scaling lives in user
mode and no QEMU constant is baked on either side. Which virtio function is
the pointer is the device's own claim (its `EV_BITS` advertise `EV_ABS`),
never PCI enumeration order.

## HACK-003: wineserver-lite as a user-mode desktop server

```
Status:     active (GUI-3). It became a process: wineserver-lite.exe serves the
            GUI object model to every client over a shared section plus kernel
            events, and the kernel starts it beside conhost. Until GUI-3 the
            same state machine ran in-process inside win32u.dll, which was NOT
            an entry in this ledger -- nothing NT-absent crossed the boundary
            there, because the kernel saw one process running one PE image.
            It is one now: the kernel sees a process NT does not have.
Introduced: GUI-3 (route (a))
Not in NT:  NT holds desktop state in kernel win32k (since NT 4.0). NOTE: this is a
            return to NT 3.1's architecture, so it is only "not in NT 4.0+", not
            un-NT-like in principle.
Reason:     Reusing Wine's 30-years-tuned GUI state code without transplanting it onto Ob;
            keeps a clean kernel license; trivially removable.
Scope:      user/wine/wineserver-lite/server/main.c (the process), user/wine/wineserver-lite/
            {transport.h,call.c,srv_glue.c,shim.c} (the wire and the state
            machine's environment), the WINESERVER_LITE link in the Makefile,
            and SmssStartWineServer in user/smss/launch.c, which starts it.
            The exe is a NEW LINK over the same objects win32u.dll uses, never
            a stripped copy of server/ (docs/06). The transport itself is not
            part of this entry -- NT carries win32k state in sections shared
            with user mode too; only the SEPARATE PROCESS is the logged item.
Retirement: if/when route (b) moves desktop state into kernel/win32k.
```

## HACK-004: serial-backed console (COM1 ↔ condrv)

```
Status:     active, PERMANENT by decision (GUI-5). Since GUI-5 conhost is dual-mode:
            the windowed link (CONHOST_GUI — real window.c, input from the real input
            queue, exactly NT's shape) is the console on images that carry the desktop
            server, and this entry no longer covers those. The serial backend remains
            the console on every CUI image and stays indefinitely as a debug channel —
            a serial console that works while the whole GUI stack is broken is a
            debugging capability deliberately kept (decided at GUI-5 planning; it also
            carries the entire CUI test surface: console/scm/procs/winetest legs).
Introduced: M9
Not in NT:  conhost's input arrives from win32k's raw input path (i8042prt/kbdclass →
            win32k → conhost) and its output is drawn into a window. A COM port is never
            the interactive console's transport. (NT's EMS/SAC serial console is a
            separate management channel, not condrv's backend.)
Reason:     M9 needs interactive console I/O before any display or keyboard hardware
            exists (both are GUI-1+). The 16550 is bidirectional, already carries all
            kernel output, and a socket/pty chardev keeps the headless scripted test
            loop (docs/08) unchanged — the cheapest input source an LLM-driven runner
            can drive deterministically.
Scope:      drivers/condrv.c (backend hookup) ; arch/x86_64/serial.c (RX side) ;
            user/wine/programs/conhost/headless_stubs.c (the headless link's
            user32/window stand-ins)
Retirement: none planned — see Status. The original retirement condition ("delete the
            serial backend once conhost is GUI-ified") was met at GUI-5 and explicitly
            NOT taken: the hack shrank in scope (GUI images run the windowed conhost)
            but the serial console is a kept debug feature, not a debt.
```

---

## HACK-005: `NtQuerySystemInformation(SystemWineVersionInformation)` (class 1000)

```
Status:     active (answers version\0build\0sysname\0release)
Introduced: (this change — the Art. 12 tightening that made unbuilt fatal)
Not in NT:  NT has no class 1000 at all. It is a Wine extension — the pinned tree's own
            switch files it under "/* Wine extensions */" (dlls/ntdll/unix/system.c), and
            real NT answers an out-of-range class STATUS_INVALID_INFO_CLASS.
Reason:     The unmodified PE ntdll asks for it at EVERY process start (version_init,
            dlls/ntdll/version.c) and ignores the status. Once Art. 12 made an unbuilt
            answer a kernel panic, "refuse it" stopped meaning "the caller limps on" and
            started meaning "the first user process kills the machine" — so the only
            options were to implement the class or to stop booting.
Scope:      kernel/ps/query.c (PspQueryWineVersion + its one switch arm)
Retirement: when the Wine fork stops asking — i.e. if version_init ever gains a
            "no unixlib below" path, or the class leaves Wine. Deleting the arm restores
            the refusal, and nothing else in the kernel refers to it.
```

**This entry is a weaker fit for Article 2 than HACK-001..004, and says so.** The other
four add a new *device* or *process* at the boundary's outside, which Art. 2's GUI
exception explicitly allows. This one adds an info class **inside the `Nt*` surface** —
the thing Art. 2 names first. It is logged rather than quietly taken because the
alternative (the kernel panicking on every boot) is worse, and because the cost is
bounded: one `case` arm, one static string, no new state, no new device, and no other
kernel code depends on it.

The values are facts about the image, never an imitation of a host. `version`/`build` name
the Wine the PE stack is built from (what `wine_get_version`'s real consumers mean: wined3d
parses it as a version triple, shell32's About box prints the build id); `sysname` is
`proskrnl`, which is precisely what `wine_get_host_version` exists to report; `release` is
**empty**, because proskrnl has no release versioning and inventing a number would be the
plausible-answer stub Art. 12 forbids. `tests/ntapi/sem_ps/process_query` pins the shape —
a non-empty version and the four-string layout — and never the text, which differs between
the two runners by construction.

---

## HACK-006: `\Registry\Machine\Hardware\qemu` (the QEMU boot flags)

```
Status:     active (two values: "Interactive", "PanicOnNotImplemented")
Introduced: (this change — moving the boot switches off the image)
Not in NT:  NT builds HKLM\HARDWARE at boot from firmware, and boot options arrive from
            the loader as HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions. NT has
            no `qemu` key, because NT has no fw_cfg device to read.
Reason:     A boot knob has to live somewhere, and every existing one is BAKED INTO THE
            IMAGE (a marker file the kernel probes for). That means one image variation
            per knob combination — the interactive boot was a whole second 64 MiB image
            differing from the default by one zero-byte file. Reading the knob off the
            QEMU command line instead makes it a property of the RUN, so one image serves
            both, and QEMU's fw_cfg device is the only channel that carries a command-line
            string to a guest booted from a disk image (`-append` needs `-kernel`).
Scope:      arch/x86_64/fwcfg.c ; arch/x86_64/fwcfg.h ;
            kernel/cm/registry.c (CmpSeedQemuBootFlags + CmQueryQemuBootFlag) ;
            the consumers that used to probe for a marker file
            (kernel/init/main.c KiIsInteractiveBoot and
            KiConfigurePanicOnNotImplemented, user/smss/smss.c
            SmssIsInteractiveBoot) ; tools/qemu.sh (GUEST_INTERACTIVE,
            PANIC_NOTIMPL)
Retirement: when proskrnl boots something other than QEMU often enough to want a real
            boot-options channel — at which point the values move to SystemStartOptions
            parsed from a Limine cmdline, and the readers change but the callers do not.
```

**This entry is a weaker fit for Article 2 than HACK-001..004, and says so** — the same
admission HACK-005 carries. The other four add a device or a process at the boundary's
outside; this one adds a *key* served through the existing `Nt*Key*` surface, and its
`Scope` names `kernel/cm/registry.c` and `kernel/init/main.c`, so deleting
`arch/x86_64/fwcfg.*` alone does not restore the prior kernel (Art. 7). It is logged
rather than quietly taken because the cost is bounded and the alternative is worse: the
only NT-shaped home for a boot option is `Control\SystemStartOptions`, which lives under
a *persisted* key, so honouring "never written to the hive" there would mean inventing
value-level volatility — machinery NT does not have, in the middle of the Cm the boundary
tests pin. One seeded key with one value under an NT-real volatile hive is the smaller
addition. `HKLM\HARDWARE` itself is not part of the hack: NT builds it, the oracle builds
it (`wineboot --init`'s `create_hardware_registry_keys`), and
`tests/ntapi/sem_reg/hardware_hive.c` pins it against both.

**Volatility is not a deviation here, it is the NT mechanism.** In real NT the whole
HARDWARE hive is volatile: constructed at boot from firmware, never written to disk. This
Cm gets the same property nearly for free — `CmpSaveHive` skips a volatile node and
everything under it (`hive.c` `CmpWriteSubtree`), and `CmpCreateKey` refuses a stable child
of a volatile parent (`registry.c:1233`, propagating at `:1249`), so no ring-3 create can
re-open the subtree to persistence. The propagation is the *create* path's, not the tree
walk's: `CmpWalkPathCounted` deliberately does not infer volatility, because the hive LOAD
path builds its content keys through that same walk and those are ordinary keys on purpose
(docs/03 "A loaded hive is a volatile graft"). So the two seeded nodes are each marked at
their own creation site. What the hive is **not** is read-only: this
Cm has no per-key security descriptors, so a ring-3 write lands and is visible until the
next boot, when fw_cfg re-seeds. Nothing depends on it being unwritable.

**The absent key is the contract.** `Machine\Hardware` exists on every boot; the `qemu`
subkey exists if and only if the fw_cfg signature probe answered. So a consumer that does
not find the key is not running under QEMU, and applies its own default rather than
reading a fabricated one. A flag missing from a key that does exist reads as 0: under QEMU
the command line is authoritative.

**There are three states per flag, not two, and each flag chooses its own middle one.**
No `qemu` key at all means not a QEMU guest, and the consumer applies its own default. The
key present with the item absent means *under QEMU, nothing said*, and that answer lives in
`CmpQemuBootFlags`. The key present with the item set means the command line decided.

The two flags differ in both defaults, on purpose. `Interactive` is off under QEMU when
unspecified (almost every QEMU boot of this kernel is a scripted session) and on off-QEMU
(nothing on real hardware is scraping a serial log for `[KTEST]` lines, so the unknown
machine is assumed to have a human at it). `PanicOnNotImplemented` is the mirror: **on**
under QEMU when unspecified, off off-QEMU. Arming it is a development stance — "convict
the first unbuilt service I needed" — so every development VM should have it and an
unknown machine should not be pushed into a kernel panic over a missing service.

Putting that default in the seeding table rather than in `tools/qemu.sh` is deliberate:
it makes the panic net a property of **booting under QEMU** rather than of having launched
through one particular script. Every leg does go through that script today, but only by
discipline — a hand-rolled `qemu` line (docs/08's own recipe) would have lost the net
silently, and losing it is invisible because the run still passes. `PANIC_NOTIMPL=0` now
passes `string=0` to say otherwise out loud.

Two flags have moved: `interactive` and `panic_not_implemented`. `C:\cui8_stress.flag` is
still image-baked — it is set by exactly one leg and is the least of the three; the
remaining image variations want their own look.

---

## Non-hacks (recorded here to prevent re-litigation)

These are sometimes *mistaken* for hacks but are real NT mechanisms, so they carry **no**
ledger entry and no retirement condition:

- **WOW64 / 32-bit support** — NT's real mechanism. Kernel cost is a few hundred lines; no
  `Nt*` semantics change.
- **conhost + condrv** — real NT (Vista/Win8) architecture; adopted, not invented. (Their
  M9 *serial transport* is not NT, and is the logged item — HACK-004.)
- **smss-equivalent initial process** — real NT boot structure.
- **Section objects, APCs, unified waiting, handles** — the NT core we deliberately keep.
- **The boot console** (`kernel/init/bootvid.c`) — NT's own boot path paints text on the
  framebuffer (bootvid.sys / `InbvDisplayString`); mirroring the kernel log there is that
  mechanism, not an invented one. It publishes no device and starts no process, no `Nt*`
  call learns of it, and nothing it does is observable from an unprivileged `.exe`
  (Art. 1) — so there is nothing here to retire. Its one genuinely new commitment is a
  third-party renderer inside the kernel image, which is a licensing/provenance item
  (`docs/11`, `docs/provenance.md`), not a boundary one.
- **Shared-section transport for wineserver-lite** — NT itself uses shared sections between
  win32k and user mode; this is NT-spirited, not a hack. (Only wineserver-lite's
  *existence as a separate server* is the logged item, HACK-003.)

## Simplifications are not hacks either

The Article 3 mandates (no eviction, one lock, uniprocessor — and, until the CUI-9
amendment, no COW) are **deviations from
NT's implementation, not from its observable semantics.** They belong in
`docs/03-nt-deviations.md`, not here — a hack adds an NT-absent entity; a simplification
removes an unobservable optimization.
