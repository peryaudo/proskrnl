# 22 — Timekeeping Strategy

Like `docs/19` and unlike `docs/17`/`docs/18`, this document is **not** an argument for
amending the constitution. Article 3 mandates a uniprocessor, one pool, no COW, no
eviction; it says nothing about how time is measured, and the list is closed. Everything
here is ordinary Article 1 work: `NtQueryPerformanceCounter`, `NtQuerySystemTime` and
KUSER_SHARED_DATA are boundary surface, their accuracy is user-observable, and an
inaccurate clock is a wrong answer rather than a slow one. Nothing below is justified on
performance.

The document exists because the clock is currently **correct in shape and wrong in rate**,
and because the two mainstream kernels solved this the same way for reasons that apply
here unchanged.

---

## 1. What the contract actually is

Four parts, all boundary-observable, none of them satisfied by a tick counter.

1. **The performance counter is sampled during the call.** QPC's documented resolution is
   "1 microsecond or better", and its resolution is `1 / QueryPerformanceFrequency` — a
   property of the counter, not of the clock interrupt. Microsoft states the separation
   directly: *"GetTickCount and GetTickCount64 aren't related to QPC."*
   (learn.microsoft.com, "Acquiring high-resolution time stamps".)
2. **The frequency is fixed at boot and never changes.** *"The performance counter
   frequency that QueryPerformanceFrequency returns is determined during system
   initialization and doesn't change while the system is running."* A caller is entitled to
   query it once and cache it — Wine's `RtlQueryPerformanceFrequency` does exactly that,
   hardcoding `TICKSPERSEC`.
3. **The rate must be calibrated against another reference before use.** Also stated
   outright: *"Like other timers, the TSC is based on a crystal oscillator whose exact
   frequency is not known in advance and that has a frequency offset error. Thus before it
   can be used, it must be calibrated using another timing reference. During system
   initialization, Windows checks if the TSC is suitable for timing purposes and performs
   the necessary frequency calibration and core synchronization."* Windows 8 and later
   *"use multiple hardware timers to detect the frequency offset and compensate for it"*.
   This is worth recording because the opposite is a natural assumption: NT does calibrate,
   it just does it once, at boot, and then lives with the residual.
4. **QPC is a difference clock.** *"independent of, and isn't synchronized to, any external
   time reference"* — no NTP discipline, monotone, unaffected by `NtSetSystemTime`, DST or
   time zones, and it *includes* time spent asleep. Wall-clock accuracy is a separate
   problem solved by a separate mechanism (W32Time on NT, `adjtimex` on Linux); it is not
   in scope here and should not be conflated with it.

**Consequence.** The tick rate bounds *timer expiry* granularity and *scheduling*
granularity. It must not bound *time reading*. Both mainstream kernels enforce that split
structurally — Linux with the clocksource/clockevent separation (a thing you read versus a
thing you program to interrupt), NT with QPC versus `InterruptTime` — and both then publish
the read side into a user-mappable page (vvar / KUSER_SHARED_DATA) so the common case costs
no ring transition.

## 2. What exists today (measured)

**The shape is already right, and that is the important starting fact.** `KiTickFraction`
(`kernel/ke/timer.c:75`) interpolates `(rdtsc − KiTickTsc) * 10000 / KiTscPerMillisecond`,
clamped to `KI_100NS_PER_TICK − 1`; `KeQueryInterruptTime` (`timer.c:94`) adds it to the
tick; `NtQueryPerformanceCounter` (`kernel/ps/query.c:3166`) returns that and reports
10 MHz. That is `base + (delta * mult >> shift)` with a division standing in for the shift —
structurally `timekeeping_cycles_to_ns()`, with the clamp doing the job Linux gives to
`max_cycles`/`maxadj`. The 10 MHz figure is honest, not a staircase.

The parts that are not right:

- **The clock is the LAPIC, and the LAPIC is assumed perfect.** `KiUpdateClock`
  (`timer.c:248`) does `KeTickCount++; KiInterruptTime += KI_100NS_PER_TICK;`
  unconditionally — one interrupt, one millisecond, no matter how long the interrupt
  actually took to arrive.
- **One 10 ms PIT gate sets both rates.** `KiCalibrateApicTimer` (`arch/x86_64/lapic.c:124`)
  measures LAPIC ticks and TSC cycles across a single gate. No second reference, no error
  band, no retry: a zero result panics (correctly, G12), any non-zero result is accepted.
- **The QPC bypass fields are zero.** `PspInitializeSharedUserData` (`kernel/ps/peb.c:42`)
  memsets the page and never writes `QpcFrequency`/`QpcBias`/`QpcShift`/`QpcBypassEnabled`,
  so every `QueryPerformanceCounter` is a full syscall.
- **`NtQueryTimer` reads a second expression of "now"** — `KeTickCount * KI_100NS_PER_TICK`
  rather than `KiInterruptTime` (`kernel/ob/sync.c:712`). Equal today; a G11 hazard.

## 3. The defects, and the consumer that convicts each

Ranked by how wrong the answer gets, not by how hard the fix is.

**a. Lost time on delayed or coalesced ticks.** Every LAPIC interrupt the platform fails to
deliver on schedule is one millisecond deleted from the clock, permanently — and the next
tick re-bases `KiTickTsc` to the current TSC, erasing the evidence. Under QEMU (TCG always,
KVM under host contention) this is routine, not exotic. **Measured, once §4a made it
visible: 1326 ms lost across a 69.6 s TCG boot, a clock running 1.9% slow.** Convicted by
measurement rather than by a test — see §6.

**b. The clamp converts a stall into a frozen clock.** During a long inter-tick gap the
fraction saturates at 9999 and QPC stops advancing entirely; a 50 ms stall reads as ≈0
elapsed. The clamp is doing its job — it buys monotonicity, and `timer.c:61-74` says so —
but it is only a *bound* on the error, and with (a) unfixed there is nothing keeping the
error small. Convicted by: a delta histogram over a stalled interval.

**c. The long-run rate is one busy-wait's worth of luck.** No second reference, no error
band, no post-boot refinement, no watchdog. Linux rejects a PIT calibration that disagrees
with HPET/PM by more than 10%, and rejects a fast calibration whose error exceeds 500 ppm;
we accept anything. Convicted by: comparing QPC elapsed against the host clock across a
long run.

**d. Every read is a syscall.** Precision is `MAX[resolution, access time]` — Microsoft's
own formula — so a 100 ns resolution behind a ring transition delivers whatever the
transition costs, not 100 ns. See §4d for why this one is *not* ours to fix unilaterally.

**e. Expiry rounds the wrong way.** `KiComputeDueTime` (`timer.c:165`) arms relative
timeouts off the raw tick, so a wait armed late in a tick can expire early; NT rounds the
other way. Already recorded (`docs/21` W13) and already waiting on a lower-bound pin.

## 4. The proposals

### a. Make the TSC the clock and the tick the sampling point

`KiUpdateClock` derives elapsed time from the TSC delta since the last tick and advances by
however many whole ticks actually passed, rather than by exactly one. In Linux terms this is
`logarithmic_accumulation()`; the reason Linux needs it (NO_HZ lets many ticks' worth
accumulate) and the reason we need it (a hypervisor may not deliver every interrupt) are
different, but the arithmetic is the same. It fixes (a) and bounds (b) at the same time.

This is the change that matters, and it is small — but it is not a one-liner, because three
things in `KiUpdateClock` currently assume "one interrupt, one tick":

- **The CPU-time invariant.** `ASSERT(KiIdleTime100ns + KiTotalKernelTime100ns +
  KiTotalUserTime100ns == KiInterruptTime)` (`timer.c:279`) is the accounting subsystem's
  cheapest defence and must survive. Catch-up ticks have to be charged to a bucket — all to
  the interrupted thread's bucket is the honest reading (the machine really was doing that,
  or was stalled while doing it) and keeps whole-tick sampling intact.
- **Periodic timer re-arm** already re-arms relative to now specifically so a late tick
  causes no expiry storm (`timer.c:291-296`) — that comment becomes load-bearing rather
  than defensive, and should say so.
- **G14.** `KiUpdateClock` is a must-not-block region. The change is pure arithmetic and
  adds no park, so `tools/blocking_frontier.py --check` is unaffected — worth stating in the
  commit body rather than leaving to the reader.

One consequence to state plainly, because it reverses which hardware is authoritative:
after this change the long-run rate of the clock is `KiTscPerMillisecond`, not the LAPIC
period. That makes §4b a companion to this change, not an independent nicety.

### b. Ask the hardware for the TSC frequency; keep the gate as fallback

Linux's calibration path is mostly an *avoidance* path: CPUID leaf 0x15 (crystal ratio) then
0x16 (nominal frequency) first, because *"TSC frequency reported directly by CPUID is a
'hardware reported' frequency and is the most accurate one so far we have"*; then the
hypervisor (leaf 0x40000010, EAX = virtual TSC kHz, EBX = LAPIC bus kHz — VMware-originated,
implemented widely); and only then `quick_pit_calibrate()` against the PIT with a 500 ppm
acceptance band, falling back to three 50 ms PIT loops cross-checked against HPET/PM within
10%.

We should do the same in the same order, with the existing gate demoted to last resort:

1. Hypervisor timing leaf, when the hypervisor-present bit is set. This is the case that
   matters most here, because the machine we actually run on is QEMU and an emulated PIT is
   the worst possible reference.
2. CPUID 0x15/0x16.
3. The existing 10 ms gate.

Two gate notes. **G8**: leaves 0x15/0x16 are Intel SDM Vol. 2A (CPUID), citable directly;
leaf 0x40000010 is not in the SDM — it is a de facto hypervisor interface, so the citation
is the pinned QEMU tree, and the introducing comment must name the file it was verified
against. **G12**: if a source answers, believe it; if none answers, the gate runs; if the
gate returns zero, panic as it does now. No silent fallback to a plausible constant.

Cheap addition once two numbers exist: when both a reported frequency and the measured gate
are available, disagreeing by more than a fixed band is a panic or a loud serial line, not
a silent preference. That is Linux's 500 ppm warning, and it is the only cross-check we can
afford without a second timer device.

**What it took to execute the reported path at all, and what it then said (issue #176).**
Under TCG nothing answers: the pinned QEMU caps the basic CPUID maximum at 0x0D for every
CPU model, and its hypervisor timing leaf is written on the KVM path only
(`target/i386/kvm/kvm.c`). KVM alone is not enough either — that leaf is gated on
`tsc_is_stable_and_known()` (invariant TSC exposed, or an explicit `tsc-freq`), on
`vmware_cpuid_freq` (default on) and `expose_kvm`, and on the KVM signature leaf not having
been displaced by Hyper-V enlightenments — so `-accel kvm -cpu host` still measures, and
`+invtsc` is what makes the leaf appear. `tools/qemu.sh` therefore passes
`-cpu host,+invtsc` on every KVM run: an exact rate is the point of §4b, and a path only a
remembered command line reaches is a path that rots (CI has no KVM and takes the gate
regardless, so leaving it opt-in left the reported path unexercised everywhere). On a Ryzen
5950X leaf `0x40000010` reports 3399997 TSC cycles/ms and 62500 LAPIC ticks/ms where the
gate measures 3400965 and 62541 — 0.03% and 0.07% apart, the reported LAPIC rate landing
exactly on QEMU's `KVM_APIC_BUS_FREQUENCY / 16`. Full suite green with the reported rates
driving the clock. Two things follow, and both matter more than the agreement itself: the
reported path is reachable and exact where it is reachable (so the order above stands), and
the platform CI tests on will not reach it (so the maximum-leaf guards around the sources
that stay *unreachable* are load-bearing rather than tidy — an ungated leaf-0x15 read
answers a confident 68 kHz on a 2.8 GHz machine, and a kernel that believes reported rates
would adopt it).

The cost of the default is that a KVM dev box and a TCG CI runner no longer calibrate the
same way, which is a real loss for reproducing a CI timing failure — mitigated by the boot
log naming the source on both, and by `ACCEL=tcg` reproducing CI's configuration exactly
when that is what a bisect needs.

**Why not a second timer device at boot.** Linux's slow path cross-checks the PIT against
HPET or the ACPI PM timer and demands 10% agreement, and NT *"uses multiple hardware
timers to detect the frequency offset"*. The equivalent here would mean bringing up HPET or
the PM timer solely as a calibration reference — a device with no other consumer, which is
a poor trade when the two sources above answer directly on the platform we actually target
and are exact rather than measured. If neither answers on some future machine, this is the
next thing to build, not a permanent exclusion. Note this is a *boot* cross-check and is a
different question from the runtime watchdog dismissed in §5.

**Deferred: post-boot refinement.** Linux does not stop at boot — `tsc_refine_calibration_work`
re-measures roughly a second after boot over a ~1 s window and, if the result is within 1%,
updates `tsc_khz` and re-derives the cycles-to-ns scale on every CPU. The analogue here
costs no new device: re-measure the TSC against accumulated LAPIC ticks over the first
second and correct `KiTscPerMillisecond`. Its value is narrower than it looks, and the
limit should be stated rather than discovered later — both rates come from the same PIT
gate, so refinement cancels *measurement* noise (gate start/stop skew, I/O latency, a
truncated `ticksPerMs`) by measuring over 100× longer, but it cannot correct a systematic
error in the PIT reference itself. It therefore improves the TSC:LAPIC ratio, which is what
the sub-tick sawtooth depends on, and leaves the absolute rate where it was. That makes it
worth building only if §4b's sources fail and the gate is what we are actually running on;
until then it is measurement for its own sake, and it competes with a real consumer for
attention.

### c. Bound the interpolation error explicitly

With §4a in place the clamp stops being the only thing standing between a stalled platform
and a wrong answer, and its role can be stated as what it is: a monotonicity guarantee, not
an accuracy guarantee. Worth revisiting at that point whether a tick that arrives *late by
more than one tick* should also be recorded — a counter and a serial line — so the condition
is visible in a panic dump instead of being silently absorbed. Under Article 9 the dump is
the debugger; a clock that quietly compensates is a clock that hides its own platform's
misbehaviour.

### d. QPC bypass — populate the fields, do not patch Wine for it

This is the one that looks like the biggest win and is not available to us.

On NT, `RtlQueryPerformanceCounter` skips the kernel entirely when `QpcBypassEnabled` is
set, computing `(rdtsc + QpcBias) >> QpcShift` (bare metal, `QpcShift == 10`) or
`__umulh(rdtsc, QpcMultiplier) + biases` (Hyper-V enlightened). The exact arithmetic is
pinned by `third_party/wine/dlls/ntdll/tests/time.c::test_RtlQueryPerformanceCounter`.

The blocker is **G9**. Wine's PE-side `RtlQueryPerformanceCounter`
(`dlls/ntdll/time.c:388`) has no bypass path at all — it forwards to the syscall
unconditionally, and its own conformance test `todo_wine win_skip`s when the flag is clear.
Adding the bypass would be a PE-side observable behaviour change in the fork, which is
exactly what Article 10 forbids: fork commits replace unixlib plumbing, nothing else. It is
also upstreamable work that belongs upstream — the test asserting it already exists there.

So the proposal is narrow: **write the fields correctly and leave the flag off.**
`QpcFrequency` should carry the same 10 MHz the syscall reports, because NT's own test
asserts `RtlQueryPerformanceFrequency() == usd->QpcFrequency` and the page is the authority
for the frequency even on systems where the counter bypass is unavailable. That is a
correctness fix to a currently-zero field, costs nothing, and does not pretend to be a
performance change. The syscall cost stays until upstream Wine grows the path.

**G5 note**: Wine cannot pin this — its own test skips. Any pin is a `beyond_oracle` block
built against the documented contract, which is legitimate (a Wine gap is a gap in the
oracle) but must be labelled as such rather than smuggled in as a Wine-green assertion.

### e. One authority for "now"

`NtQueryTimer` (`kernel/ob/sync.c:712`) computes remaining time from
`KeTickCount * KI_100NS_PER_TICK` instead of `KiInterruptTime`. The two are numerically
equal today and stop being obviously equal the moment §4a lands — `KeTickCount` and
`KiInterruptTime` would still advance together, but there would then be two places
expressing the same catch-up rule. Fold it onto the single reader before §4a, as its own
commit, so a bisect can tell the two changes apart (G13).

## 5. What deliberately stays unbuilt

Naming these matters more than usual here, because the Linux material is seductive and most
of it is machinery we have no consumer for.

- **No clocksource abstraction, no rating table, no `/sys` override.** One counter, chosen
  at boot. An abstraction over a set of size one is an NT-absent entity in the core (G2).
- **No clocksource watchdog.** Linux re-checks the TSC against a reference twice a second
  forever and unregisters it on skew; NT does no such thing for QPC, fixing the frequency at
  boot (§1.2). We follow NT. This is the *runtime* question only — the boot-time
  cross-check is answered in §4b, and the post-boot refinement deferred there is a
  one-shot, not a watchdog. Revisit only if a real divergence is traced to TSC
  misbehaviour.
- **No NTP / `adjtimex` slewing.** QPC is a difference clock by contract (§1.4), and NT does
  not discipline it either. Wall-clock discipline is `NtSetSystemTime`'s problem.
- **No tickless, no one-shot rearm, no TSC-deadline, no hrtimer tree.** Expiry stays at 1 ms
  on the single sorted list. NT's own default is 15.625 ms; we are already finer than the
  contract requires, and `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` has no consumer yet.
- **No per-CPU anything.** Uniprocessor is an Article 3 mandate with its own exit
  (`docs/18`).

## 6. Testability

Each item has to close on a differential or a pinned measurement, not on an inference
(Article 6).

- **§4a** — **no in-guest test can convict this, and the first draft of this section was
  wrong to claim one could.** The proposal was a case comparing QPC against a
  tick-derived elapsed; they are the same clock in two units, so they track each other
  exactly whether or not the clock is losing time. Every clock a guest can read shares the
  error, which is precisely why the defect survived this long. The only independent
  reference inside the guest is the CMOS RTC, and its one-second granularity makes a cheap
  assertion impossible.

  What replaces it is a **measurement**, reported on every boot: the count of ticks the
  clock had to recover (`KiCatchUpTicks`, in the end-of-run `clock:` line and in the panic
  dump). It is evidence rather than a verdict, and it must be labelled as such — but it is
  a number that was 0 before this change existed and is not 0 now, which is what makes the
  defect real rather than theoretical. **Measured on the TCG runner: 1326 ticks recovered
  across a 69.6 s boot — the clock had been running 1.9% slow.** A regression here shows up
  as that number climbing, or as timing-sensitive tests flaking.
- **§4b** — a boot line reporting the source chosen and, whenever both numbers exist, the
  gate's own measurement beside it with an agreement verdict, so a regression shows as a
  changed source or a changed verdict rather than as drift nobody notices. Deliberately
  *not* a `[KTEST]` line: that prefix is a machine verdict the runner counts, and there is
  nothing here to fail — a machine on which no source answers is a legitimate machine
  (it is the one CI runs on), so a suite verdict would have to pass on every outcome.
- **§4c** — a delta histogram over back-to-back QPC reads: mass at zero and a single spike
  is the staircase signature; a smooth spread is the correct one. Also the cheapest way to
  demonstrate that the current implementation is *not* staircased, which is worth pinning
  before changing anything near it.
- **§4d** — `beyond_oracle`, asserting `QpcFrequency` matches the syscall's frequency.
- **§4e** — covered by existing `NtQueryTimer` pins; the commit is a refactor and should
  claim nothing more.

## 7. Build order and size

1. §4e — one-line fold onto `KiInterruptTime`. Own commit, no behaviour change.
2. §4c's histogram test, pinned green against today's behaviour, so the next two commits
   have a before/after.
3. §4b — frequency discovery. Own commit; carries its G8 citations.
4. §4a — catch-up accumulation. Own commit; carries the accounting-invariant argument, the
   G14 sentence, and a `docs/03` note if the page/query relationship shifts.
5. §4d — populate `QpcFrequency`, flag stays off. Own commit; `beyond_oracle` pin.

Steps 3 and 4 are the change; 1, 2 and 5 are cheap and make the change legible. None of the
five touches `mm/`, `ke/wait`, or `arch/*.S` beyond `lapic.c`'s calibration function, which
keeps this on the safer side of `docs/12`'s map.

## 8. Relationship to the other documents

`docs/03` §"Sub-tick system time" records the current divergence (query runs up to one tick
ahead of the shared page) and already names the QPC baseline in KUSER_SHARED_DATA as the
unbuilt proper fix; `docs/21` W13 carries the narrative and the two open items. This
document does not reopen either — §4a changes how far the clock can drift, not the
page ≤ query direction those pins depend on, and §4d deliberately stops short of the
baseline interpolation both documents describe, because Wine cannot consume it yet.
