# 23 — Audio Strategy (virtio-snd)

Like `docs/19` and `docs/22`, this document is **not** an argument for amending
Article 3 — the mandate list is closed, and nothing below is justified on performance.
What it *is* is the third use of **Article 2's downgraded exception**, and that is an
amendment: the exception's wording is "for the interactive console (M9) and GUI only",
and audio is neither. The precedent is exact — the exception was written for M9's
console and extended once for GUI, each time as the same downgrade (NT-absent things
only as new devices or new processes at the outside of the boundary, ledger-logged,
subtractable) — and this document is the argument for extending it the same way once
more. The one-line amendment to `docs/09` lands as **its own commit** carrying a
pointer here, the way a mandate exit would (CLAUDE.md: "lifting one is a commit of its
own"), before any audio code. Refusing the amendment is a legitimate outcome; the
additive structure below prices it in — nothing else depends on audio existing.

Everything past that gate is ordinary work: consumer-driven (Art. 5), verbatim at the
device (the HACK-002 philosophy), one authority per mechanism (Art. 11), loud when
unbuilt (Art. 12).

---

## 1. What the contract actually is

On NT, the audio surface an unprivileged `.exe` sees is **entirely user-mode API**:
mmdevapi/WASAPI (COM), winmm, dsound, xaudio2. Below those sit audiodg (the mixing
service — a *process*) and the kernel-streaming stack (ks.sys/portcls) that only the
service talks to. No `Nt*` call in the boundary sense carries audio; an ordinary app
never issues a KS ioctl itself.

Wine's PE layer implements everything above one seam: mmdevapi (and through it winmm,
dsound) is PE code down to a single unixlib driver interface —
`dlls/mmdevapi/unixlib.h`, `enum unix_funcs` (line 322), 37 entries — behind which
winealsa/winepulse/winecoreaudio talk to a host. **Consequence:** the kernel owes
audio *no new `Nt*` surface, no `abi/` change, no syscall id.* What it owes is a PCM
transport below that seam, reached through the existing `NtCreateFile` /
`NtDeviceIoControlFile` / `NtWriteFile` surface on a ledger-logged device — exactly
the `\Device\Fb0` / `\Device\Input0` shape.

The semantics that must survive are WASAPI's, and they are pinned by Wine's own test
suite rather than authored here: endpoint enumeration, shared-mode render/capture,
format negotiation, the period/padding/position clocks (a stream's clock keeps
advancing through an underrun), event-driven pacing, session volumes. The winetest
pairs (§6c) are the boundary tests; G5's "green on the oracle first" applies to them
as written.

## 2. What exists today (measured)

- **mmdevapi loads no driver.** `load_driver` (`dlls/mmdevapi/main.c:72`) calls
  `__wine_load_unix_lib` (`main.c:86`), which the fork refuses when no unix side
  exists (`dlls/ntdll/loader.c:2858`, `STATUS_INVALID_IMAGE_NOT_MZ` — "proskrnl: no
  .so builtins"). Every candidate fails, `main.c:190` logs "No driver … could be
  initialized", and the process has zero endpoints: `waveOutGetNumDevs()` answers 0,
  `PlaySound` no-ops, dsound enumerates nothing. Degradation, not a crash — that is
  the current steady state, and it is honest (a machine with no sound device).
- **No audio pair is in either winetest manifest** (`tests/winetest/manifest.txt`
  covers ntdll/kernel32/cmd/msvcrt/ucrtbase; `manifest-gui.txt` covers user32).
- **The pinned QEMU (10.0.2) ships the device and the verdict channel.**
  `hw/audio/virtio-snd.c` + `virtio-snd-pci.c` (`-device virtio-sound-pci`), and the
  wav audiodev backend (`audio/wavaudio.c`) that records what the guest plays into a
  host WAV file — the audio analog of the QMP `screendump` the GUI loop is built on.
- **The oracle has no audio backend.** The pinned Wine build configures none, so the
  oracle also enumerates zero endpoints and Wine's audio tests `skip`. This is the
  **third instance of the docs/06 trap** — "a Wine configured without a backend does
  not fail, it answers plausibly without one" — after fonts (GUI-3) and display
  (Xvfb). An oracle that skips is not an oracle; §6b buys the backend before any pair
  is judged.
- **The kernel assets audio needs already exist**: the virtio core
  (`drivers/virtio/virtqueue.c`, `pci.c` capability walk), the CUI-8 park/drain
  engine with `IoDrainDeviceCompletions` as the one harvest authority
  (`kernel/io/file.c:389`) reached from the tick tail every millisecond
  (`kernel/ke/timer.c:456`), and the Io share engine that enforced Input0's
  exclusive-reader rule without a private flag.

## 3. Why virtio-snd

The device choice is the cheapest decision in the document, made against two real
alternatives QEMU offers:

- **intel-hda** — public Intel spec, but it is a codec *graph* (widget enumeration,
  CORB/RIRB command DMA, BDL descriptor lists) plus a codec model to parse; the spec
  surface dwarfs the feature.
- **AC97** — small, but I/O-port DMA, fixed 48 kHz, legacy interrupt routing (the
  kernel has no IOAPIC/PIC path by design — `docs/19` §11a), and a device class QEMU
  keeps for compatibility rather than development.

virtio-snd (virtio 1.2 §5.14, device id 25) is four virtqueues — controlq, eventq,
txq, rxq — and six PCM control verbs (`VIRTIO_SND_R_PCM_INFO`, `SET_PARAMS`,
`PREPARE`, `START`, `STOP`, `RELEASE`). It rides the virtio transport code the tree
already runs for blk and input, its spec is public (provenance clean, `docs/11`),
and every constant lands under G8 citing the spec section and cross-checked against
the pinned QEMU model, exactly as blk did.

What the pinned model advertises (facts to negotiate against, never to bake —
HACK-002's rule): jacks 0, **streams 2**, chmaps 0 by default
(`hw/audio/virtio-snd.c:29-31`); stream direction is assigned first-half-output
(`:445` — stream 0 renders, stream 1 captures); formats S8…FLOAT, rates
5512…384000 Hz (`:40-61`); default `buffer_bytes` 8192 / `period_bytes` 2048
(`:1075`). The driver consumes controlq + txq at AUD-1/2 and rxq at AUD-3; **eventq
is left unpopulated** — nothing consumes jack or xrun events, and per Art. 12 the
absence is loud (no buffers are posted; no verb pretends to deliver events).

## 4. Design

### a. Kernel: `\Device\Snd<n>` — HACK-007

One device node **per PCM stream the device reports**, `\Device\Snd0`,
`\Device\Snd1`, …; each node's direction is the stream's own `PCM_INFO` answer
relayed verbatim, never instance order — the same "the device's claim, not PCI
enumeration" rule HACK-002 established for the pointer.

The wire contract (`drivers/sndproto.h`, beside `fbproto.h`/`hidproto.h`) mirrors
the virtio control verbs one-to-one, as ioctls: `INFO` (the stream's
`virtio_snd_pcm_info`, verbatim), `SET_PARAMS` (buffer_bytes, period_bytes,
channels, format, rate — forwarded; the device's own status decides), `PREPARE`,
`START`, `STOP`, `RELEASE`, plus one query the wire needs and virtio answers
implicitly: `POSITION` — total bytes the device has consumed, counted at tx
completion harvest. **No format translation, no resampling, no mixing, no volume in
the kernel.** All of that is policy, and policy lives above the boundary (the
keyboard-layout argument from HACK-002, applied to PCM).

Data path: `NtWriteFile` of exactly `period_bytes` per call maps to one txq
descriptor chain (`virtio_snd_pcm_xfer` header + frames + status footer, §5.14.6).
Up to `buffer_bytes / period_bytes` chains ride in flight; when the ring is full the
writer **parks on the CUI-8 engine** and is woken when the device returns a buffer —
the pacing clock emerges from tx completion, no timer invented. Blocking-only,
exclusive open per stream through the existing Io share engine (G10/G11: no private
flag). Capture is the mirror: `NtReadFile` of `period_bytes` from rxq.

Harvest: `VioSndDrain` joins `IoDrainDeviceCompletions` — extending the single
authority, not adding a second (Art. 11). The tick-tail call gives a 1 ms
guest-clocked completion bound against a 10 ms period, so **snd gets no MSI-X
vector**: `docs/19` §11f is the controlling precedent (poll-and-nap stays until a
consumer convicts it; blk's interrupt was convicted by idle-`hlt` and microsecond
parks, and a 10 ms cadence convicts nothing). If a consumer ever does, it is the
same separate-change-against-the-drain-seam that §11 was.

Gates, named: the new park joins `tools/blocking_frontier.txt` **in the same
commit** (G14), re-opening `docs/20` §8.4's checklist for it. Unbuilt verbs refuse
loudly with `STATUS_NOT_IMPLEMENTED` and name themselves on serial (G12);
`POSITION` before `START` answering 0 is a fact about the device, not a fabricated
answer.

### b. User: `winevsnd.drv` — a PE mmdevapi driver, in-repo

The winefb.drv recipe applied to sound: a new driver at
`user/wine/dlls/winevsnd.drv`, built as PE in the superproject, additive by
construction — the oracle never executes a byte of it. It implements mmdevapi's
unixlib surface (the 37 entries) as ordinary PE code over `Nt*` calls against
`\Device\Snd*`:

- **Endpoints**: one render, one capture, from the stream nodes that exist and what
  their `INFO` claims. `get_mix_format` derives from device caps — under QEMU,
  48 kHz stereo, float32 reported to WASAPI (the Windows-typical mix format), with
  the feeder converting to the negotiated device format.
- **The feeder thread** (per process, `THREAD_PRIORITY_TIME_CRITICAL` — the priority
  mmdevapi's own helper uses): mixes *this process's* shared-mode streams in float,
  applies session volumes (`set_volumes` — software gain; QEMU's device has no
  mixer), slices into `period_bytes`, and blocking-writes; the parked write is the
  period clock. On underrun it writes **silence**, so the stream clock keeps
  advancing — WASAPI's observable contract, pinned on the oracle before it is
  implemented (§6). Event-driven clients are signaled per completed period;
  `get_current_padding` / `get_position` derive from `POSITION` plus bytes queued.
  Position advances in period-granularity steps; that is legal WASAPI, and QPC
  interpolation (`docs/22`) is the known refinement if a pair ever convicts the
  staircase.
- **MIDI**: `midi_get_driver` answers empty, so mmdevapi routes MIDI to this driver
  (`main.c:182`); `midi_init` reports **zero devices** — the true count for hardware
  that does not exist, not an Art. 12 fabrication. `aux_message` likewise. dsound
  and winmm ride mmdevapi PE-side and need nothing of their own.

### c. The seam: three dispatch sites in mmdevapi, dormant (the only fork commits)

mmdevapi reaches its driver exclusively through `__wine_load_unix_lib` plus two
dispatch wrappers — the `wine_unix_call` inline (`mmdevapi_private.h:115`) and
`MIDI_CALL` (`main.c:53`). The fork commit gives each a proskrnl leg taken **only
when `__wine_unix_call_dispatcher` is NULL**: `load_driver` loads the same
`wine<name>.drv` as an ordinary PE via `LdrLoadDll` and resolves one exported entry
table; the wrappers dispatch through that per-driver table. The global dispatcher is
**never** set — its NULLness is the fork's own level-1 dormancy guard at every other
seam, and faking it non-NULL would repeal all of them at once.

This is the conhost seam's shape, reused as `docs/06` instructs: probe first, guard
the proskrnl leg behind behaviour only a missing unixlib produces (level-1 runtime
dormancy), keep the implementation additive (level-2 — the driver itself is
superproject code). Commit header: what/why/`proskrnl-only`; the pin-bump PR reports
the hack-meter delta. Under real Wine the dispatcher is non-NULL, the legs are dead,
and `run.sh oracle` green on the bumped pin is the dormancy proof.

Driver selection is the registry mechanism mmdevapi already reads
(`Software\Wine\Drivers`, value `Audio`): the image sets `Audio=vsnd`, the same way
the Graphics key selects winefb. The winealsa/winepulse PE modules are not on the
image, so nothing else even loads.

### d. Cross-process playback: staged, like the desktop-state question was

NT mixes shared-mode streams in **audiodg — a process**; Wine delegates mixing to
the host sound server. proskrnl has neither, and one virtio output stream. The
staging mirrors `docs/07`'s route choice:

- **AUD-2 ships single-process audio.** The device opens exclusive per direction
  (the Io share engine again); in-process concurrency is real — the feeder mixes all
  of its process's streams, which is what Wine's own render tests exercise — and a
  *second process's* `IAudioClient::Initialize` answers `AUDCLNT_E_DEVICE_IN_USE`. A
  real WASAPI status in circumstances Windows would not produce it (Windows shared
  mode admits N processes): a **recorded `docs/03` deviation**, stated with exactly
  that divergence, justified against consumers (no baked scenario plays audio from
  two processes at once), never against performance.
- **If a consumer convicts it** (a shell beep while an app plays, two apps), the
  NT-shaped fix is **audiodg-lite**: a user-mode mixer process owning the device,
  clients reaching it over shared sections + kernel events — the GUI-3 transport
  recipe, and NT's own architecture adopted rather than invented (the conhost
  argument). That is HACK-008, reserved and unbuilt until convicted.

## 5. What deliberately stays unbuilt

Named, per the `docs/22` §5 discipline, because each is seductive:

- **No MSI-X vector for snd** — §4a; the tick-tail drain is the latency bound.
- **No eventq/jack/chmap consumption** — QEMU advertises none by default; nothing
  consumes them.
- **No exclusive-mode WASAPI, no raw mode** — no consumer; refuses per the oracle's
  shape for an unsupported mode.
- **No loopback capture** (`get_loopback_capture_device` refuses as the oracle's
  driverless path does) and **no spatial audio** beyond mmdevapi's own PE-side
  answers.
- **No MIDI devices** — zero is the true count; virtio-snd carries no MIDI.
- **No mixer process until convicted** — §4d.
- **No xaudio2 backend** — Wine's xaudio2 is FAudio, a unixlib; the day a game
  convicts it, the recipe is FreeType's (`third_party/` pin, cross-built as a PE
  static library — `docs/07`), not a kernel feature.
- **No resampling, mixing, or volume in the kernel, ever** — policy above the
  boundary (§4a).

## 6. Testability

### a. The AUD-1 verdict: a WAV file is the screendump

`tests/run/run.sh audio`: QEMU gets `-device virtio-sound-pci,audiodev=wav0
-audiodev wav,id=wav0,path=<artifact>.wav`; the guest client configures the render
stream and plays a deterministic S16 pattern; the harness reads the recorded WAV
back. The leg pins the audiodev's rate/format to exactly what `SET_PARAMS`
negotiates, so QEMU's mixeng conversion is the identity and the played span is
**sample-exact** — note the wav backend refuses float and 32-bit formats
(`audio/wavaudio.c:95`), which is why the verdict path is S16 end-to-end. The check
is **property-based, never byte-golden on the file**: locate the non-silent span,
assert it contains the generated reference sequence; leading/trailing silence and
span *length* are host-scheduling artifacts (the wav backend consumes on host
timers), the same class of guest-vs-host-clock trap `docs/19` §11c ate, and must not
be asserted.

### b. The oracle grows an audio backend — before any pair is judged

The audio Xvfb: `run.sh` gains `start_pulse` beside `start_xvfb`
(`tests/run/run.sh:173`) — one per-leg PulseAudio (or pipewire-pulse) daemon with a
null sink at a fixed rate, never a borrowed session daemon; `tools/setup_linux.sh`
reconfigures the pinned oracle build `--with-pulse` (a cache-key bump for
`fetch_third_party.sh`). And the fontsmoke lesson becomes an **audiosmoke pin**: a
test asserting the oracle enumerates at least one render endpoint — guarding the
real failure mode, an oracle that silently answers "no devices" and turns every
audio pair into a skip that counts as green.

### c. The winetest spine is the conformance suite

The pairs are Wine's own, unmodified, per the manifest discipline (`docs/21`):
`mmdevapi:mmdevenum,render,capture,propstore,dependency,spatialaudio`,
`winmm:wave,capture,mixer,midi,mci,mmio,timer`, and the dsound set
(`dsound:dsound,dsound8,ds3d,ds3d8,propset,duplex,capture`). They enter
`manifest.txt` under its existing rules: every pair listed, red ones parked with
triage and `# TODO: Implement`, counts as the yardstick. G5 order holds: each pair
green on the oracle (with §6b's backend) before the kernel/driver work that unparks
it on proskrnl. AUD-2's done-when is the render-path pairs green **on both
runners**, with a `[KTEST] audio` verdict line carrying the underrun counter (§7) —
a number, not an inference (`docs/19` §8.4's rule).

### d. Timing honesty

On a TCG CI runner the feeder *will* miss deadlines; silence insertion turns each
miss into a glitch, not a failure — but pairs that assert wall-clock-tight position
advancement can flake. The manifest's parking discipline exists for exactly this: a
flaking pair is parked with its signature written down, never tolerated red and
never "fixed" by widening a tolerance in the test (Art. 6 — the oracle is not
patched to make a divergence pass).

### e. What has no oracle

The device contract itself (`sndproto.h`) is NT-absent, so no differential oracle
exists for it — like Fb0, its verdicts are kmt tests (control-verb round trips, a
written period completing, the park actually parking) plus the §6a artifact, the
golden-image pattern already governing GUI.

## 7. Risks (honest)

- **The period deadline on a non-preemptible uniprocessor.** The feeder needs the
  CPU every 10 ms; Art. 3's machine gives it no kernel preemption and one dispatcher
  lock, so a long kernel operation delays it. Mitigations, in order: a deep device
  buffer (default ≥ 4 periods in flight — 40 ms of schedule slack), the
  TIME_CRITICAL feeder priority, silence-on-underrun (a glitch, not a hang), and the
  underrun counter in the `[KTEST]` line so the cost is *measured* on both KVM and
  TCG rather than argued. If the number is ugly under TCG, that is a fact about the
  CI machine to record, not a reason to widen a kernel mandate — the named exits
  exist (`docs/18`) and audio alone does not open them.
- **WASAPI clock fidelity is authored, not bought.** The GUI argument — "the
  semantics are all borrowed and Windows-verified" — is weaker here: winevsnd.drv's
  padding/position/event arithmetic is ours, comparable in scope to winealsa's unix
  side (~2.5k lines). The compensation is that its conformance suite pre-exists
  (§6c) and is merciless about exactly this arithmetic.
- **The seam grows the hack meter.** Three dispatch sites in mmdevapi, all level-1
  dormant; the pin-bump PR carries the delta and the oracle-green proof. The driver
  itself adds zero fork lines (superproject code).
- **Capture has no content source in CI.** The wav backend records output only;
  with no input backend QEMU supplies silence at the correct cadence. Capture pairs
  mostly assert cadence, not content, so AUD-3 is testable — but a content-asserting
  capture test would need an audiodev that plays a file into the guest, which QEMU
  does not offer today. Named now so it is not discovered as a surprise.
- **Article 2.** The amendment could be refused; then nothing lands. The structure
  above (all-additive, ledger-logged, subtractable) is what makes accepting it cheap.

## 8. Build order (G13: one meaningful unit per commit)

1. **The Article 2 amendment** — one line in `docs/09` naming audio beside console
   and GUI, pointing here. Own commit, before any code.
2. **HACK-007** ledger entry (`/log-hack`) with the device skeleton's commit.
3. **`drivers/virtio/snd.c` + `drivers/snd.c` + `drivers/sndproto.h`** — controlq +
   txq, the park, the drain hook, G8 citations throughout, the
   `blocking_frontier.txt` entry in the same commit; kmt smoke (verb round trips, a
   period completes, the park parks).
4. **The `run.sh audio` leg + wav verdict** (§6a) — AUD-1's done-when.
5. **The oracle backend + audiosmoke** (§6b) — before any pair is judged.
6. **The mmdevapi seam commit** on `proskrnl-target` + the pin bump (hack-meter
   delta, oracle-green proof).
7. **`winevsnd.drv` render path** — endpoints, feeder, clocks; the render pairs
   enter the manifest and go green on both runners with the underrun verdict —
   AUD-2's done-when.
8. **Capture** — rxq, the capture node, `get_capture_buffer` legs; capture pairs
   triaged — AUD-3's done-when.
9. **The `docs/03` entry** for single-process concurrency (§4d) with its convicting
   consumer named as the audiodg-lite trigger.

## 9. Relationship to the other documents

- **`docs/19`** — audio rides the CUI-8 engine and drain authority unchanged; §11f
  is why snd polls; §11c is why no verdict asserts host-clocked timing.
- **`docs/07`** — the additive pattern, the winefb.drv recipe, and route (a)'s
  process-boundary argument, which §4d's audiodg-lite would replay for sound.
- **`docs/06`** — the seam levels and the landing recipe (§4c is a conhost-shaped
  commit); the oracle-without-a-backend trap, instance three (§6b).
- **`docs/22`** — QPC is the position-interpolation refinement if a pair convicts
  the period staircase.
- **`docs/02`** — the Audio path milestones (AUD-1…3) carry the contract; this
  document is the design.
- **`docs/10`** — HACK-007 (`\Device\Snd*`); HACK-008 (audiodg-lite) reserved,
  unbuilt.
