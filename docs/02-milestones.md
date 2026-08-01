# 02 — Milestones

Each milestone closes on **a runnable artifact + a verification method**. Never on "code
written." The empirical effort split is roughly: **M1–M6 = 40%, M7 alone = 30%,
M8 onward = 30%** (an estimate that predates the CUI consolidation path below — Net-1
alone is M6-sized). M7 is both the biggest mountain and the biggest return.

Ordering rules that matter:
- **No separate "prerequisites" phase.** There is no M0. The xv6 labs a prep phase would
  have run are unnecessary under Article 3 — you write no COW, no eviction and no
  fine-grained locking for the whole of M1…CUI-7, so there is nothing to rehearse. (COW and
  SMP arrive at the very end, at CUI-9 and CUI-10, each behind a measurement and its own
  amendment; fine-grained locking never does.) The QEMU build→run→exit-code→log harness is the
  first task *of M1*, proven on a trivial payload before any kernel logic. See `docs/12`.
- **RAM-disk before real Mm** (M5 seeds it) to break the Mm↔Io circular dependency.
- **Test-first, per milestone (Article 5).** For each milestone, write the `tests/ntapi/`
  cases for exactly the `Nt*` it implements, green them on the Wine/Windows oracle *first*,
  then implement until they pass on proskrnl. Do not author the whole boundary suite up
  front. The suite grows monotonically, and the proskrnl run is gated by a `todo_proskrnl`
  manifest so it is always green-or-regression rather than a sea of expected reds. See
  `docs/08`.
- **The differential fuzzer is available from M5, not gated to M7.** Its prerequisites — the
  one-source/two-mode `ntapi` harness, the generated syscall list, the deterministic
  serial-log verdict — all exist from M4/M5, so it was built early (`tests/fuzz/`, `docs/08`)
  and its op model grows with each milestone's new `Nt*`. Run it with `tests/run/run.sh fuzz`.
- **The critical path to winemine.exe deliberately excludes npfs/condrv/conhost/cmd.** See
  the GUI note below and `docs/07`.

---

## M1 — Boot and kernel scaffold
Boot via **Limine** (ADR 0010): it hands off in 64-bit long mode with a higher-half map,
memory map, and framebuffer already set up, so `boot.S` is a thin entry stub — no 32→long-
mode trampoline to hand-write (the exact fiddly asm an LLM gets subtly wrong). Then: serial
console; IDT/exception handlers; timer interrupt; physical page allocator. NT loader protocol
is unnecessary (binary compat dropped), so ride an existing boot protocol.
**Do first:** get the QEMU loop (build → run → `isa-debug-exit` code → serial log) green on
a trivial "hello over serial" payload *before* writing kernel logic, so the harness is never
a variable while you debug (see `docs/08`).
**Done when:** boots in QEMU; an exception dumps registers over serial; the timer ticks.
**Do on day one:** thick panic handler (register dump, stack trace, last syscall) — this
is the LLM's eyes for the rest of the project. Turn on **UBSan in trap mode** the same day
(`-fsanitize=undefined -fsanitize-trap=undefined`): no runtime library needed, a violation
emits `ud2`, and the panic handler above reports the site (`docs/08`).

## M2 — In-kernel multithreading
Kernel page-table management; pool allocator; kernel threads + context switch; priority
scheduler; **dispatcher objects** (event/mutex/semaphore/timer) and `KeWaitFor*`. Get NT
semantics (notification vs. synchronization events, wait-all/any) exactly right here.
**Done when:** in-kernel test — threads ping-pong on events/mutexes; timed waits time out
correctly.

## M3 — Ob: handles and namespace
Object manager (type system, refcount, handle table); `\Device` and `\??` namespaces;
`NTSTATUS` conventions. Move M2's dispatcher objects under Ob.
**Add here:** **minimal KASAN** (~1000 lines: shadow memory + `__asan_load/store` hooks +
pool redzones). Handle tables and object refcounts are the LLM's favourite bug site and
exactly what KASAN catches — the highest-return sanitizer, so it earns its keep the moment
Ob exists (`docs/08`).
**Done when:** a named event opened from two places resolves to one object; closing a
handle drops the ref correctly.

## M4 — User mode and the syscall boundary
User address-space separation; `syscall/sysret` entry; TEB allocation;
`NtAllocateVirtualMemory` (reserve/commit); first `Nt*` group. Test client is a flat
binary, not yet a PE.
**Done when:** user-mode code allocates memory and waits on an event via syscalls; a
user crash is contained as process termination, not a kernel fault.

## M5 — Sections and image mapping
Seed a RAM-disk + trivial read-only FS first. Then section objects: anonymous,
file-backed, and PE image sections (per-section protection, relocation copy). Guard-page
stack growth. **Under T4: no COW initially** — private/image mappings copy fully on map.
**Done when:** `NtCreateSection` + `NtMapViewOfSection` maps a PE image; the mapped-view /
`ReadFile` consistency test passes (structurally trivial under the unified page cache).

## M6 — I/O manager and a real filesystem
Async I/O skeleton (IOSB update rules, APC/event completion); `NtCreateFile/ReadFile/
WriteFile/QueryInformationFile/QueryDirectoryFile` main info classes; virtio-blk driver;
FAT32. NT-specific semantics land here: share modes, case-insensitivity, delete-on-close,
byte-range locks.
**Do first:** the self-checking Mm stress test (`docs/08`) — write via a mapped view, read
via `NtReadFile`, write via `NtWriteFile`, read via the view again, verifying a known
pattern every time. It needs this milestone's `NtReadFile`/`NtWriteFile`, so it becomes
expressible exactly here; write it and green it on the oracle *before* any Io code
(Article 5). It is M6's acceptance test for mapped-view/read-write coherence — Mm
consistency bugs surface *only* in this form, and reliably do (`docs/08`) — and it stays
in the suite as a permanent regression guard. Until M7 (`NtCreateThread`) it runs
single-threaded; sequential view/read/write interleavings already convict coherence bugs.
The anonymous-section slice of it, `sem_mm/section_stress`, runs from M5.
**Done when:** the file-semantics suite is green (e.g. share-mode violation →
`STATUS_SHARING_VIOLATION`); M5's image mapping works from an on-disk file; the Mm
stress test is green on proskrnl.

## M7 — NtCreateUserProcess + Wine ntdll ⛰️ (the mountain)
PEB/TEB/`RTL_USER_PROCESS_PARAMETERS`/KUSER_SHARED_DATA layout; `NtCreateUserProcess`;
`KiUserExceptionDispatcher`/`KiUserApcDispatcher` return protocol; thread creation. Then
bring in Wine's ntdll PE side with its unixlib replaced by our syscall stubs. Place the
NLS files ntdll reads at startup.
**Done when:** a `hello.exe` linked only against ntdll starts and exits; an SEH test
(deliberate access violation caught by `__except`) passes. **After this, the rest of Wine
is data.**

## M8 — Cm (registry) + the initial process chain
Hive read/write (our own format); `NtCreateKey/SetValueKey/QueryValueKey`; boot-time
SYSTEM hive mount. An smss-equivalent initial process (mount hive, set `\??` drive
letters, launch next).
**Done when:** a value written by a user program survives reboot; boot completes as
kernel → smss-equiv → test process.

## M9 — npfs, condrv, interactive console
Named-pipe FS (byte/message mode, listen/connect via `NtFsControlFile`); a ConDrv-style
console device; port Wine's conhost.
**The console transport is the COM1 serial port, in both directions** (HACK-004,
`docs/10`). The 16550 is bidirectional and already carries all kernel output
(`arch/x86_64/serial.c`); its receive side becomes console input — the "keyboard driver"
of this milestone is the UART RX path, not a keyboard device. A real keyboard
(virtio-input, `\Device\Input0`) is GUI-1's problem and a GUI conhost is GUI-5's; condrv is
agnostic of its backend, so the serial transport is subtracted when those arrive. Testing
stays inside the headless finite-time loop (`docs/08`): QEMU's serial chardev becomes a
socket/pty instead of a plain log file, the runner writes keystrokes into it and greps the
echo — no QEMU window, no screendump, no change to the loop's shape.
**Done when:** input typed into the serial console echoes through conhost; the pipe
client/server test (message-mode behaviour rpcrt4 needs) passes.

## M10 — Full Wine user-land (CUI)
kernelbase/kernel32, msvcrt, advapi32, rpcrt4, services.exe, Wine's cmd.exe; full
`CreateProcess` paths (env/handle inheritance, cwd), completion ports, DLL search order.
**Done when:** cmd.exe prompts; pipes/redirection work; an off-the-shelf MSVC-built CUI
app runs unmodified. Ideal regression: the CUI subset of Wine's own test suite —
**live since the M10 stretch work**: `tests/run/run.sh winetest` gates a curated manifest
of Wine's-own-suite subtests (ntdll/kernel32/msvcrt/ucrtbase modules) green on the oracle
AND on proskrnl (`docs/03` "M10 winetest notes").

---

## CUI consolidation path (post-M10: from "acceptance passed" to "off-the-shelf")

> M10's acceptance proves the *mechanism* (process/file/pipe/console plumbing). It does
> not provide the *machine state* real console software expects: registry content, a
> token surface, an SCM, process enumeration, an interruptible console, a true clock.
> These milestones close that gap, consumer-first (Article 5: each new `Nt*` arrives
> because a baked binary calls it, pinned by an oracle-green test — never
> speculatively). The path is independent of the GUI path; either may come first.
> Sockets are NOT on this path: they are a genuinely new subsystem, not consolidation,
> and live as their own **Net-1** milestone below. The measured gap this path closes —
> which ids are missing, which are permanently out of scope, which partial services
> refuse the classes real apps ask for — is `docs/16-syscall-status.md`; CUI-5…CUI-7
> are its build plan, and after them the buildable syscall surface is complete
> (202 of the 264 Wine x64 ids; the other 62 are out of scope by decision, not debt).
> The path then ends with three milestones of a different kind — CUI-8…CUI-10, the
> machine-level gaps (async I/O, COW, SMP) that add no `Nt*` at all; see the note above
> CUI-8.
> **Verification spine:** the winetest gate (`tests/run/run.sh winetest`, live since the
> M10 stretch work — `docs/03` "M10 winetest notes") — every CUI milestone grows its
> manifest, unparking pairs blocked on that milestone's surface, so "fully functional"
> ends as a measured pair count, not a feeling.

## CUI-1 — firstboot: wineboot + machine state
Bake rundll32/setupapi/cfgmgr32/ws2_32 + `wine.inf`; build wineboot as a standalone PE
with cmd.exe-style glue (`user/wine/programs/cmd/proskrnl_glue.c` precedent: user32
stand-ins for the wait window / message pump; rundll32 hard-imports user32 and needs the
same). `user/smss`
grows the `firstboot.c` hand-off (`docs/04`). The registry payload (~500 `AddReg` lines:
Classes/CurrentVersion/OLE/Services/SessionMgr/codepages) is applied by setupapi's INF
engine inside rundll32 children (`InstallHinfSection`), so this also stress-exercises
`NtCreateUserProcess` and is the Cm integration test ADR 0008 promises.
**Landmine (design around, don't discover on serial):** setupapi's fake-dll machinery
treats the "Wine builtin DLL" signature as overwritable and truncates the destination
*before* reading the (absent-on-proskrnl) source — a naive `--init` with the
`WineFakeDlls` sections deletes the baked system32. Drive registry-only INF sections or
neuter the directive in glue. Also here: **retire the no-RTC deviation** (`docs/03`) —
read the CMOS RTC once at boot (MC146818 via ports 0x70/0x71, cited per G8; QEMU supplies
host UTC) and seed the 1601-epoch SystemTime base from it instead of the fixed date.
That fixes FAT32 mtimes (build tools compare them) and wineboot's own freshness check,
and is a hard prerequisite for Net-1's TLS acceptance. wineboot's remaining legs degrade
gracefully (missing `__wine_user_shared_data` section, failing
`NtQuerySystemInformationEx`, unloadable RegisterDlls GUI DLLs all warn-and-continue).
**Done when:** `wineboot --init` completes; a registry differential vs. the oracle's
prefix is green (Article 6: the diff convicts, not "it didn't crash"); the populated
hive survives reboot; winetest pairs parked on missing machine state join the manifest.

## CUI-2 — Se: the minimal-but-real security model
The widest latent syscall gap: token reads are dormant in the already-baked DLLs
(kernelbase/security.c, ntdll/sec.c, advapi32) and `OpenProcessToken` is the first thing
most real tools call. One fixed identity, but structurally real NT objects: a token
object type; `NtOpenProcessToken(Ex)`/`NtOpenThreadToken(Ex)`; the
`NtQueryInformationToken` classes advapi32/kernelbase actually read;
`NtAdjustPrivilegesToken`; `NtDuplicateToken`; `NtAccessCheck`/`NtPrivilegeCheck`;
`NtQuery/SetSecurityObject`; `NtAllocateLocallyUniqueId`. Scope strictly to what
baked callers hit (Article 1); pin `sem_se/` on the oracle first.
**Done when:** `sem_se/` is green on both sides; a real tool that opens its own token at
startup gets past the point where today it dies on `STATUS_NOT_IMPLEMENTED`.

## CUI-3 — SCM: services.exe + rpcss
Cheap on transport: Wine's local RPC is named pipes, **not ALPC** (`ncalrpc` opens
`\pipe\lrpc_*` — `dlls/rpcrt4/rpc_transport.c`; the SCM endpoint is
`ncacn_np:[\pipe\svcctl]`), so M9's npfs already carries it and the entire LPC/ALPC
syscall surface stays permanently unimplemented for the Wine userland. Bake services.exe
(+ its userenv import) and rpcss; firstboot starts them; sechost/advapi32 clients bind
over the pipe. Depends on CUI-1 (wine.inf writes the `Services` key) and CUI-2 (the SCM
checks tokens). This is the deferred-since-M10 SCM finally getting its first consumer
(`docs/03` "M10 CUI-userland notes").
**Done when:** an `sc`-style query round-trips; a real service installs, starts, and
survives reboot, all driven from ring 3.

## CUI-4 — the process ecosystem
`SystemProcessInformation` (today only `SystemBasicInformation` exists — no
tasklist/toolhelp shape without it); `NtOpenProcess`; `NtRead/WriteVirtualMemory`;
`NtGetNextProcess/Thread`; `NtSuspend/ResumeProcess`; job objects (real build tools use
them); and the M10-deferred **Ctrl+C / console-control delivery** through condrv — the
most user-visible CUI hole (a running program cannot be interrupted today). Debug
objects (`NtCreateDebugObject` family) are the stretch goal, not the gate.
**Done when:** a tasklist/taskkill pair works against live processes; Ctrl+C interrupts
a loop under cmd.exe; a job-object-using build tool completes.
*(Outcome: the stretch goal was not taken, and afterwards debug objects were ruled
permanently out of scope — no baked consumer, and the native debugger toolchain
expects PDB where proskrnl is DWARF end-to-end. ADR 0011; `docs/03` "Debug
objects"; `docs/16`.)*

## CUI-5 — Io completion
The file surface's last mile (12 missing ids + the refused info classes, `docs/16`),
led by the single largest hole on either list: **rename**.
`FileRenameInformation(Ex)`/`FileLinkInformation` in `NtSetInformationFile` —
`MoveFile`/`ren`/`move` and every write-tmp-then-rename tool fail today, and rename
does not exist anywhere in `fs/` yet. Then: `NtNotifyChangeDirectoryFile`
(`ReadDirectoryChangesW` — file watchers, build tools), `NtCancelSynchronousIoFile`,
`NtRead/WriteFile{Scatter,Gather}`, `NtFlushBuffersFileEx`, `NtDeleteFile`,
`NtQuery/SetEaFile`, `NtSetVolumeInformationFile`, `NtQueryDirectoryObject`
(kernelbase volume enumeration), `NtOpenIoCompletion`, `NtSetIoCompletionEx`; the
missing query classes (`FileNetworkOpen`/`AttributeTag`/`Stream`/
`FileIdBothDirectory`, `FileFsFullSizeInformation`); and widening async I/O past
CUI-3's single pended verb (`FSCTL_PIPE_LISTEN`) where a consumer convicts it.
**Done when:** `move`/`ren` work under cmd.exe; a write-tmp-then-rename tool
completes; a directory watcher sees a change; the unparked winetest file pairs join
the manifest.
*(Outcome: complete. All 12 ids plus the refused classes landed test-first
(`tests/run/run.sh files` is the cmd.exe acceptance; six new/extended ntapi
suites; the churn shadow model learned rename). The suite's first
`beyond_oracle` blocks arrived here — FAT has no hard links or streams, the
oracle's set-volume-info is a stub, and its recursive inotify watch never
fires in the oracle environment, so those cases pin NT's own FAT contract.
Async widened by exactly one verb (the directory watch); completion-port
file association stayed out for want of a consumer, and watches do not
buffer across the re-arm window — docs/03 "CUI-5 Io-completion notes"
carries these and the FileId-moves-on-rename deviation.)*

## CUI-6 — handles, identity, and the query surface
What real tools ask *about* processes, threads, and handles — plus the Se leftovers.
Ob/Ke/Ps ids: `NtSetInformationObject` (**`SetHandleInformation`**, the
stdio-redirect idiom) with `ObjectHandleFlagInformation` in `NtQueryObject`
(`GetHandleInformation`); `NtCompareObjects`; `NtSignalAndWaitForSingleObject`;
`NtOpenTimer`; `NtMakePermanentObject`; `NtQueueApcThreadEx2`;
`NtAlertResumeThread`; `NtFlushProcessWriteBuffers` and
`NtGetCurrentProcessorNumber` (kernel32/kernelbase forward these exports straight to
ntdll); `NtSetThreadExecutionState`. Query classes: `ProcessTimes`/`PriorityClass`/
`HandleCount`/`ImageFileName`, `ThreadTimes`, `SystemHandle`/`Module`/
`ProcessorPerformanceInformation`. Foreign-thread `NtGet/SetContextThread` (the
`SuspendThread`+`GetThreadContext` profiler/GC pattern — its debugger consumer is
gone) and `NtOpenThread` by CLIENT_ID. Jobs finish here: nesting, limit enforcement,
real accounting. Se-2: `NtSetInformationToken`, `NtFilterToken`
(`CreateRestrictedToken`), `NtAdjustGroupsToken`, `NtImpersonateAnonymousToken`,
impersonation attach, and **retiring Ob's always-allow create/open access check** —
a one-authority engine change (Art. 11) that must be its own commit.
**Done when:** a handle-inheritance redirect chain round-trips; a `timeit`-style
tool reads real process/thread times; a restricted-token launch works.
*(Outcome: complete. All 14 ids landed test-first (`tests/run/run.sh cui6` is
the cmd.exe acceptance — timeit/redirchain/restricted; ten new `tests/ntapi`
suites across `sem_ob`/`sem_ps`/`sem_wait`/`sem_se`). The one piece of new
machinery was **per-thread CPU-time accounting** — whole-tick sampling at the
clock interrupt, discriminated by the interrupted CS — which `ProcessTimes`/
`ThreadTimes`/`SystemProcessorPerformanceInformation` and the real job
accounting all ride. Jobs finished with wineserver's parent/child nesting,
create-time breakaway, and subtree accounting. Foreign `NtGet/SetContextThread`
reads a suspended, parked target's saved trap frame + `fxArea`; a syscall-free
spinner became visible to it by publishing the interrupted ring-3 frame across
the off-CPU window. Se-2 added token set-info/filter, impersonation attach
(retiring the CUI-2 "no impersonation" deviation), and the two oracle-stub ids
(`NtAdjustGroupsToken`/`NtImpersonateAnonymousToken`) pinned `beyond_oracle`.
The always-allow retirement (its own commit) enforces a create-time SD's DACL
at open — no-SD objects stay permissive, as wineserver's null-SD path does.
Deviations in `docs/03` "CUI-6 handles/identity notes": 1 ms sampling
granularity, suspended-only foreign context, single real `SystemModule`
entry, `beyond_oracle` handle-count/job-time values, and the retirement's
scope. The fuzzer's CUI-6 ops convicted one ordering divergence
(`NtQueryObject` length-before-handle), fixed. The buildable id surface is now
173/264; `docs/16` is re-derived. The winetest manifest gained no CUI-6 pairs —
no parked pair was blocked on this surface, and none was added unverified.)*

## CUI-7 — Cm-2 + Mm-2 + system furniture
The largest by id count (29) and the cheapest per id — the `*Ex` forms delegate to
engines that already exist (Art. 11: extend, never fork). Registry: `NtLoadKey{,2,Ex}`,
`NtUnloadKey`, `NtSaveKey`, `NtRestoreKey`, `NtReplaceKey`, `NtRenameKey`,
`NtNotifyChangeKey{,MultipleKeys}` (`RegNotifyChangeKeyValue` — services block on
it), `NtSetInformationKey`, `NtQueryMultipleValueKey`. Memory:
`NtAllocateVirtualMemoryEx`, `NtCreateSectionEx`, `NtMap/UnmapViewOfSectionEx` (the
`VirtualAlloc2`/`MapViewOfFile3` family), `NtFlushVirtualMemory`,
`NtLock/UnlockVirtualMemory`, `NtGet/ResetWriteWatch` (write-watch heaps),
`NtSetInformationVirtualMemory`. Locale/system: `NtQueryDefaultUILanguage`,
`NtQueryInstallUILanguage`, `NtSetDefaultUILanguage`, `NtSetDefaultLocale` (natural
fit with Cm-2 — they are NLS/registry reads), `NtSetSystemTime` (pairs with CUI-1's
CMOS RTC work), `NtSetSystemInformation`, `NtShutdownSystem`.
Ordering: CUI-5 → CUI-6 is a hard order (jobs and foreign-context work want the
query surface); CUI-7 is independent and can land in parallel or slot anywhere.
**Done when:** `reg save`/`reg load` round-trips and survives reboot; an app on the
`VirtualAlloc2`/write-watch path runs; after CUI-5…7 the buildable id surface is
complete (202/264, `docs/16`) and every remaining `KI_SYSCALL_MISSING` row is an
out-of-scope decision, not debt.
*(Outcome: complete. All 29 ids landed test-first (`tests/run/run.sh cui7` is
the cmd.exe acceptance — a regtool save/load round trip that survives a power
cycle, the watchapp `VirtualAlloc2`/write-watch run, and a ring-3
`NtShutdownSystem` poweroff; eleven new ntapi suites across
`sem_reg`/`sem_mm`/`sem_ps`). The `*Ex` forms extended the existing engines as
promised — placement constraints ride the one free-range search, the map path
delegates, `NtCreateSectionEx` ignores its parameters as the oracle does — and
the two pieces of new machinery were fault-driven write-watch (per-VAD dirty
array authoritative, kernel writes marking through the probe chokepoint) and
wineserver-shaped registry notification records keyed by the arming open.
Hive attach reuses the PHV1 engine both ways (subtree serialize for
`NtSaveKey`, volatile grafts for `NtLoadKey`); the four oracle-FIXME ids
(`NtRestoreKey`/`NtReplaceKey`/`NtSetInformationKey`/`NtQueryMultipleValueKey`)
are built against their MS contracts `beyond_oracle`, as are the privileged
set-time/shutdown arms (the CMOS writeback pairs with CUI-1's RTC read; a
privileged set survives reboot). The pin runs themselves convicted two
server truths the plan had wrong — load's dropped destination attributes
(collision, not open-if) and mlock's PROT_NONE refusal. The buildable id
surface is complete: 202/264, every remaining `KI_SYSCALL_MISSING` row an
out-of-scope decision (`docs/16` re-derived). Deviations in `docs/03` "CUI-7
Cm-2/Mm-2/system notes": volatile grafts and `CHILD_MUST_BE_VOLATILE`, the
notify dup-handle footnote, placeholders' loud refusal, lock/prefetch as
validating no-ops, absolute-timer non-reevaluation, and the set-info
unknown-class refusal vs the oracle's blanket success. The fuzzer gained
eight deterministic CUI-7 ops; the winetest manifest again gained no pairs —
the parked `ntdll:virtual`/`kernel32:virtual` pairs exercise placeholders,
which stay deliberately unbuilt.)*

---

> **CUI-8…CUI-10 are a different kind of milestone.** Everything above closes gaps in the
> *boundary* — ids and info classes a baked binary asks for. These three close gaps in the
> *machine*: they add no `Nt*`, change no observable semantics, and would leave
> `docs/16`'s count untouched. They sit here because they are the last things the CUI target
> needs and because two of them gate work beyond it (Net-1 needs CUI-8; nothing needs
> CUI-9 or CUI-10). Each has a strategy document that is the actual spec; the entries below
> are the milestone contract, not the design. Order is fixed: **CUI-8 → CUI-9 → CUI-10**,
> and only the CUI-8 → CUI-10 edge is a hard dependency.

## CUI-8 — async: overlapping I/O in the block layer
Spec: **`docs/19-io-strategy.md`**. The only one of the three needing **no constitutional
amendment** — Article 3's mandate list is closed and synchronous I/O was never on it;
inline completion is a legal point inside the NT contract, valid exactly while a device
completes in bounded time (`docs/19` §1). Today every file transfer completes inside the
syscall against a polled virtqueue of structural depth 1, so while the disk is busy the
machine is effectively single-threaded — no other thread runs, no APC is delivered, a
console `^C` is not seen.
The work: per-request virtio-blk buffers and a depth above 1 (retiring the global
control/bounce singletons); a completion drain on the idle/timer path via the existing
`VioTryPopUsed` — **no interrupt path**, which is a separate change against the same seam
if a consumer ever convicts the latency; FS read/write parking through the
`IOP_PENDING_REQUEST` engine that CUI-3 and CUI-5 already use; and generalizing that
engine's cross-context ownership rule from an npfs-specific note into the department's
convention (Art. 11).
**Landmine (the actual work, not the driver):** once a request can be in flight, another
thread can enter the same FCB or page-cache page, and a large amount of code is lock-free
*because that could not happen* — 21 greppable "atomic under the no-preemption model"
justifications, `fs/fat32/fat.c:676` the archetype. The enumeration of re-enterable paths
is a **deliverable before the code that makes re-entry possible**. Also decide and pin
first (`docs/19` §7): whether an async-handle read pends or completes inline when the page
cache already has the data, what cancelling a pended read leaves in the IOSB, and the
ordering of two operations issued back-to-back on one handle.
Ordering: hard prerequisite for **Net-1** (an AFD `accept`/`recv` may never complete, so a
polled-synchronous socket path deadlocks by construction) and for **CUI-10** (a spin under
a giant lock stalls every CPU at the kernel gate). Independent of CUI-1…CUI-7. Roughly one
consolidation milestone.
**Done when:** a second thread observably makes progress while the first waits on the disk
— the property the milestone exists for, and one no current test states; two threads' file
I/O genuinely overlaps, with in-flight depth reported as a `[KTEST]` verdict against a
committed budget, because an implementation that pends but never overlaps passes every
semantic test (`docs/19` §8.4); a **concurrent** `file_coherence` is green (today's runs
single-threaded, so the existing net guards the semantics an in-flight operation must not
break, never the in-flight state itself); the differential fuzzer has learned that
operations can be in flight, so a pended-completion divergence can be convicted rather than
suspected (Art. 6; `tests/fuzz/interp.c` is single-threaded today); a pended file read
cancels; and the existing run legs' verdicts are byte-identical, with the drain-stress knob
off by default.

## CUI-9 — COW: shared image masters
Spec: **`docs/17-cow-strategy.md`**. Needs an **Article 3 amendment**, and the amendment
needs its measurement first (`docs/09` "Lifting a mandate"): today every process gets a
full private copy of every DLL it maps, relocations applied into the copy, so the first
deliverable is *how many MB per process and at what process count the machine refuses* —
the justification is that ceiling surfacing as `STATUS_NO_MEMORY`, never memory efficiency.
**Scope: image sections only.** File-backed `PAGE_WRITECOPY` stays refusing loudly (G12)
because data sections map the file's cache, where the one genuinely hard Mm problem —
mapped-view/`ReadFile` coherence — lives; image sections bypass the cache entirely, which
is what makes this tractable at all.
The work is mostly **not COW**: because relocations land in the private copy, sharing
requires an already-relocated master keyed on `(FCB, base)`. That half touches no fault
path, carries the large majority of the win (`.text`/`.rdata` are the bulk of a DLL; the
IAT always dirties), and is **a legitimate stopping point** — the COW fault itself is a
second, separately committed 200–300 lines.
**Landmine:** kernel-side writes bypass write-protect entirely — `MiCopyToUserRange` and
friends walk the page tables and `memcpy` into the frame, so `NtWriteVirtualMemory` would
short-write and `KiProbeForWrite` would refuse where NT succeeds. Exactly one authority may
resolve a write (Art. 11); fixing only the fault handler is the expected failure. Nine more
hazards, worst-first, in `docs/17` §6.
**Done when:** the sharing metric moves — free-frame count after N processes against a
committed budget, plus a master-hit counter — because a non-sharing implementation passes
every semantic test; `PAGE_WRITECOPY` semantics and the `NtQueryVirtualMemory` protection
transition are green on the oracle *and* proskrnl; the `sem_mm` net and the SEH test stay
green; and the debug sweep finds **no writable PTE pointing at a master frame**.

## CUI-10 — uniprocessor retired: SMP behind a giant lock
Spec: **`docs/18-smp-strategy.md`**. The amendment is **one word** — Article 3's "one
dispatcher lock" and "no kernel preemption" survive literally; only "uniprocessor" retires.
**Fine-grained locking is out of scope permanently at this milestone**, not for effort but
because a race cannot be pinned by an oracle-green test and Article 6 would go out of
reach. The giant lock keeps the existing invariant intact — "I did not block, therefore no
one else ran" — which is why `kernel/mm/pool.c` with no lock, `fs/fat32`'s lock-free
sweeps and the non-atomic refcounts all stay correct as written, and the 27-kloc audit
never happens.
Do not start until all four entry conditions hold (`docs/18` §13): **CUI-8 is done**; the
amendment exists with its measurement (which of the timing-lost `guiwtest` assertions
recover with more wall-clock, and whether mttcg converts vCPUs into throughput here); the
`-smp 1` permanent gate and an `-smp 4` leg exist; and the **seeded lock hand-off** is
designed — it is what keeps Article 6 reachable and is not retrofittable in spirit.
The work the lock does *not* cover: per-CPU state (cheap — `KiPcr` + `swapgs` already
exist, merely singleton; array-ify it, retire the `KiCurrentThread` global, per-CPU
TSS/GDT/idle, global ready queues stay); **TLB shootdown**, whose hazard is a hardware
cache rather than a data race, in broadcast-and-acknowledge form; AP bringup (INIT-SIPI-SIPI,
trampoline, per-CPU LAPIC, IPI send); the interrupt-versus-lock policy; and user-space
concurrency, which gets exercised for the first time in `wineserver-lite` and its clients.
If CUI-9 landed, its write-protect sites join the shootdown enumeration.
Roughly 1.5 consolidation milestones, with **no permanent audit tax** — the invariant stays
one sentence.
**Done when:** `-smp 4` is green across every existing suite with `-smp 1` still the gate
(so any later failure bisects into "concurrency or not"); a real race is convicted by a
seeded replay rather than by a sanitizer going quiet (Art. 6); and the `guiwtest`
timing-lost assertions are re-measured against the budget the amendment was justified on.

---

## Networking path (independent of the CUI path; formerly CUI-5)

## Net-1 — sockets: virtio-net + `\Device\Afd`
The one genuinely new subsystem and the largest single item post-M10 (2–3× a CUI
consolidation milestone) — moved off the CUI path because it is new capability, not
consolidation, and nothing on CUI-5…CUI-7 depends on it (nor it on them). Its
prerequisites are **CUI-1's clock and CUI-8's overlapping I/O** — the latter is not
optional plumbing but the reason the milestone is buildable at all: an AFD
`accept`/`recv` may never complete, so the polled-synchronous transfer model every
device uses today deadlocks by construction (`docs/19` §4).
virtio-net over the existing virtio-pci transport (spec-cited per constant, like
virtio-blk); a deliberately dumb TCP/UDP stack (Article 3: correctness only, no
performance work); the AFD ioctl surface Wine's PE ws2_32 issues via
`NtDeviceIoControlFile`, generated into `abi/` from the pinned tree's `wine/afd.h`.
Requires CUI-1's real clock: TLS certificate validation (`notBefore`/`notAfter`) is the
test that finally *convicts* a fake SystemTime — a frozen 2026 base date rejects every
newer certificate. **Scope note (record in `docs/03`):** acceptance uses an app with
*bundled* TLS (off-the-shelf python/git/curl ship OpenSSL) — Windows-native schannel
stays out of scope, because its protocol engine is GnuTLS behind the unixlib seam
(null-dispatched on proskrnl), while raw bcrypt works as-is (the pinned tree vendors
SymCrypt PE-side, `libs/symcrypt`).
**Done when:** an off-the-shelf tool completes an HTTPS fetch over virtio-net.

---

## GUI path (opt-in, additive, route (a) — see docs/07)

## GUI-1 — Pixels and input ✅
Limine framebuffer; virtio-input. `\Device\Fb0` (map framebuffer to user)
and `\Device\Input0` (input event stream). **HACK-001 and HACK-002** (see `docs/10`).
**Done when:** a user program maps the framebuffer and draws a rectangle visible in a
screendump; key input is readable.

**Done** (`tests/run/run.sh gui`). Cheaper than budgeted: no virtio-gpu and no ramfb — the
framebuffer Limine sets through the VGA BIOS's VBE is the framebuffer we publish, so the display
side is one driver with one ioctl. Mapping needed no new Mm machinery either: `\Device\Fb0`
implements the existing `GetCache` vfs op, so `NtCreateSection` + `NtMapViewOfSection` over the
device handle work unchanged. Input is polled from the virtio-input eventq by the blocking read
(no IRQ path was added). Both halves are convicted by QEMU rather than by the kernel — screendump
for the pixels, QMP `send-key` for the key (`docs/03` "GUI-1 notes" for the G5 adaptation a HACK
device forces).

## GUI-2 — win32u + framebuffer backend (single process) ✅
Bring in win32u/user32/gdi32/comctl32 PE sides; build win32u's unix side as PE (POSIX →
our `Nt*`, FreeType statically linked). Write `winefb.drv`: implement Wine's display
driver table, blit dibdrv's bitmap to `\Device\Fb0`. Desktop state lives in-process; one
GUI process.
**Done when:** **winemine.exe appears on screen.**

**Done** (`tests/run/run.sh gui2`): winemine paints its window onto the scanout and the
screendump differential convicts it (the guest reports the window rect, QEMU's device
model returns the pixels — the GUI-1 shape). `make rungui` boots the same image with a
host window for a human.

The structure: win32u.dll is the pinned tree's *unix-side* sources compiled as PE
(`user/wine/`, `make win32u`) — user32/gdi32/imm32 bind to it by name, unmodified, because
that is how they import win32u anyway (all 434 imports covered). The desktop state is the
pinned wineserver's own GUI object model compiled into the same DLL behind an in-process
`wine_server_call`, so it is Wine's state machine rather than a second one (Art. 11); 120
of its 308 request handlers link and the rest refuse by name. Queue wake-ups are real
kernel events, which is `docs/07`'s "message queue backed by a kernel event" arriving one
milestone early because it was also the simplest thing that worked. `winefb.drv` is four
driver entries plus a surface flush. FreeType is pinned (`third_party/freetype`) and
linked in. **Nothing in `third_party/wine` is patched** — the hack meter is unchanged.

What completing the boot took, in the order the boot found it: registry symbolic links in
Cm (`sem_reg/symlink` pins the semantics; win32u's display-device commit creates volatile
links under `Control\Video` and the read-back resolves them — the CUI-era refusal was the
reason `lock_display_devices` found no sources), the `HKU\<sid>` root the font loader
opens, two in-process-glue bugs (`ntdll_wcsicmp` compiled to a self-jump via the unixlib.h
macro trap; the queue-handle fixup read a cleared pointer), and three single-process
fixtures the docs/03 "GUI-2 notes" record: `get_desktop_window` is always forced, the
desktop/message windows' user entries are made to look foreign (explorer owns them on real
Wine — with our own pid in the entries, win32u skipped the `WND_DESKTOP` paths and the
first `ShowWindow` never exposed the window), and winefb.drv sizes the desktop window to
the scanout (`pSetDesktopWindow`, the `X11DRV` repair). The image also bakes the ole32
chain (ole32/combase/coml2) because imm32's `CoRegisterInitializeSpy` delay-import aborts
the process when it cannot resolve — every real Windows has ole32.

## GUI-3 — wineserver-lite becomes a process ⛰️ (the GUI mountain, half-climbed at GUI-2)
The stripped wineserver this milestone was budgeted to *build* already runs: GUI-2
compiled the pinned server's GUI object model (window/queue/hook/clipboard/atom)
unmodified into win32u.dll behind an in-process `wine_server_call`
(`user/wine/wineserver-lite/common/shim.c`), publishing the session shared mapping as a real named
section (`\KernelObjects\__wine_session`, pinned by `sem_mm/session_shm` — win32u's hot
read paths open it by name exactly as under Wine) and backing queue wake-ups with real
kernel events, so `wait_message`'s `NtWaitForMultipleObjects` blocks and wakes unmodified
— the "genuine friction point" resolved a milestone early. What remains is giving that
library a process boundary:
- the request transport — shared section + kernel events (`docs/06`) — replacing the
  in-process call;
- real process/thread records with real lifetimes: thread records currently leak by
  design (no closing socket to learn thread death from), and one-process shortcuts
  answer `get_process_from_handle`/`get_process_from_id`/`enum_processes` with the only
  process there is;
- the window-station directory resolved through the kernel namespace instead of
  `get_directory_obj`'s probe-and-answer-self;
- the session mapping's writer moving into the server process (readers already open by
  name).
The checklist is the docs/03 "GUI-2 notes" shortcut list — each entry retired or
re-justified multi-process. Also decided here (docs/03 deferred it to "GUI-3+"): the
**font-metrics oracle** — *decided yes*. The pin is now configured `--with-freetype
--without-fontconfig` against the same `third_party/freetype` the PE build links, so
oracle and target agree on backend, version and font set; it is a visible
`tools/setup_linux.sh` event (with a cache-prefix bump, tp-v3 → tp-v4, to force the one
rebuild), and it lands before the milestone that judges dialog layout (GUI-5). Under
route (b) — later, optional — transplant the server state into a `kernel/win32k/` module
exposed via generated `NtUser*` syscalls.
**Done when:** two GUI processes run at once; Z-order, focus, cross-thread `SendMessage`,
`FindWindow` all behave; the docs/03 GUI-2 single-process shortcuts are retired.

**Done** — `tests/run/run.sh gui3` is green: two GUI processes over wineserver-lite, with
`find`/`send`/`zorder`/`focus`/`xthread` all passing and both windows' pixels verified on
one scanout. The font-metrics oracle (the decision above, taken and built). The transport:
`wineserver-lite.exe` is a real process, built as a second link over the *same* server
objects `win32u.dll` uses, and clients reach it through a shared section plus kernel
events. Real client records with the kernel as the only identity source; window stations
resolved per session; thread and process reaping (a client's death is learned from its
process handle going signalled, no socket needed). Cross-process `NtDuplicateObject` in
the kernel, which the handout of a queue's sync event and the station-handle check both
need. The suspected "missing connect step" turned out to be the oracle's own behaviour for
a parentless first process; the real stopper was the transport dropping the reply body on
error, against Wine's wire contract — diagnosis and the narrow residual (connect-time
handle inheritance for processes spawned *by* a GUI process, first relevant at GUI-6):
docs/03 "Desktop inheritance".

## GUI-4 — Compositing, input routing, cursor
Inject `\Device\Input0` events into the input queue; hit-test and route; composite
per-Z-order with clipping; draw the cursor; manage dirty rectangles. No window manager
needed — each app's `DefWindowProc` draws its own frame. Two GUI-2 findings land here:
`\Device\Input0` carries only a virtio keyboard so far, so the pointer device joins
HACK-002 at this milestone; and the current flush clock is winefb.drv riding win32u's
flush-on-message-wait (an idle app paints once and stops — why the gui2 leg dumps the
settled first frame), which per-window surfaces + dirty rectangles replace.
**Done when:** windows can be grabbed and moved; clicks reach the right window.

**Done** — `tests/run/run.sh gui4` is green: two *overlapping* windows over
wineserver-lite, a click in the overlap reaching only the upper one, focus following a
click on the lower one's exposed part (characters following focus both times), and the
upper window grabbed by its caption and dragged +150,+120 — DefWindowProc's own modal
loop under server-side capture, none of it our code — with both screendumps holding
pictorially: the upper window's fill wins the overlap, the moved window sits at its
reported new rectangle, what it uncovered is repainted cross-process, the vacated strip
returns to the desktop background, and the software cursor's arrow sits at both park
points. The pointer is `\Device\Input1` — QEMU's tablet, identified by its own `EV_BITS`
never PCI order, its abs range served verbatim by one ioctl (HACK-002 grew; docs/10) —
read by the same client-side reader as the keyboard, whose start hook was also fixed
(it was dead for the app under test since GUI-2; docs/03). Compositing is clip-at-flush
against a fresh server z-order query plus mover-repairs-the-world exposure — the two
halves of the "native windowing system" role Wine's server explicitly delegates — and
the desktop got a background, painted by the driver because the forced-foreign desktop
window has no other painter. Hit-testing, routing, capture and the drag loop are the
pinned server's and win32u's own, unmodified; the hack meter is unchanged. The flush
clock survives as flush-on-message-wait by measurement, not assumption: with input
flowing, message waits are continuous, and win32u's dirty-bounds tracking plus the
clipped blits complete the dirty-rectangle story. What is deliberately *not* built:
per-window `HCURSOR` shapes (the cursor is one software arrow with a single writer —
the escalation path is named in docs/03), `HWND_BOTTOM` lowering exposure, and
`pMoveWindowBits` (the forced full re-blit covers pure moves). Residuals and the
focus-stealing lesson the leg surfaced: docs/03 "GUI-4 notes".

## GUI-5 — GUI finishing
Clipboard, hooks, `AttachThreadInput`, GUI-ifying conhost, and the real trophy: run
Wine's `user32/tests/msg.c`. Value accrues incrementally; keep an honest `todo_` list.
Anything here that judges dialog layout builds on the font-metrics oracle decided at
GUI-3 (docs/03 "the font oracle": oracle and target now share backend, version and font
set). What GUI-3 did *not* pin is the metric differential itself — the same measurement
run on both sides — which belongs here.

**Done.** `tests/run/run.sh gui5` is green:
clipboard, hooks and `AttachThreadInput` all hold cross-process over the unmodified pinned
server, which needed **nothing built** — every server half has been compiled and
dispatchable since GUI-2, and the leg passed on first bring-up (the strongest statement yet
about route (a)'s "compile the pinned server unmodified" bet). The delayed-render round trip
(`WM_RENDERFORMAT` into another process), the ownership handoff, a thread-local `WH_CBT`
hook, the cross-thread focus wall opening and closing, and a `WH_KEYBOARD_LL` hook meeting
real injected virtio input — with the unhook proved by counting, not by absence.
The **font-metrics differential** GUI-3 deferred here is pinned: one binary, both sides, one
committed golden table (`tests/gdi/fontdiff.golden`), re-diffed on every oracle run so it
cannot go stale, and compared exactly (no epsilon) on the target.
`tests/run/run.sh gui5con` is green: conhost is **dual-mode** — the pinned tree's `window.c`
and resources compiled UNMODIFIED (zero fork commits, hack meter unchanged) and linked
against the real user32/gdi32, chosen by which binary an image bakes. A windowed console
found on the scanout, typed into through the real input queue, `^C` reaching a busy program
through conhost's own `map_to_ctrlevent` (the CUI-4 serial intercept out of the loop), and
the session's files read back out of the image. `make rungui` now boots that command prompt.
The serial console is **permanent** by decision (docs/10 HACK-004 rescoped, not retired):
a console that works while the GUI stack is broken is a kept debugging capability.
**The trophy: `user32:msg` runs end to end** on the full GUI stack (`run.sh guiwtest`,
now IN CI) — 21.5 kloc and ~85 test functions, every one of them entered, winetest's own
failure count arriving as the NT exit status and ratcheted against
`tests/winetest/msg-budget.txt`: **9999 (a sentinel: the module could not reach a verdict)
→ 23 → 20 → 18 → 17**. Six real bugs convicted along the way, three of them by the run *not*
finishing: a missing per-session `BaseNamedObjects`, an unimplemented
`get_process_idle_event`, a lock-order inversion of ours that deadlocked the suite, an
unbuilt `NtQueryInformationFile` class that ntdll's activation-context loader needs, an
idle event handed to console processes that should not have one, and — worth ten failures
on its own — GUI-2's forced desktop-window creation silently re-homing the whole process
onto whatever desktop a thread last visited. What is left is named and split in docs/03
"GUI-5 winetest notes": two assertions that wait on GUI-6 (the desktop window has no
owning thread until explorer owns it), up to twelve decided by how slow TCG is rather than
by any semantics of ours, two genuine message-sequence divergences still open, and two `todo_wine`
tags that are stale here because proskrnl passes what Wine fails — winetest counts those
against us and only Wine can retire them. Three tools the campaign left
behind: a timeout/deadlock dump that prints every thread's state, waits, user RIP and stack
frames; a sweep-driven detector that catches a user-space deadlock within seconds of it
forming (docs/03 GUI-5 notes); and `tools/unscreen.py`, which replays a test's own text
back out of the console screen diff so a non-zero budget is a list of names.

## GUI-6 — Desktop *(Wine desktop; not the ReactOS shell)*
`wineboot` has already run (CUI-1's firstboot), so this is
`explorer.exe /desktop=shell,WxH` plus whatever machine-state furniture explorer/shell32
turn out to assume — GUI-2's lesson: the stalls on that boot were mostly absent furniture
Wine's userland expects (registry symlinks, `HKU\<sid>`, the ole32 delay-import chain —
the last already baked), not the predicted risk spots. explorer
becoming the desktop's real owner retires GUI-2's forced-desktop / foreign-entries
fixture (docs/03 "GUI-2 notes"). The golden artifact is a wallpaper rectangle + a file
window. `gen_hive.py` is **not** needed — wineboot did it at runtime.
**Done when:** `tests/gui/golden/desktop.ppm` matches.
*Optional GUI-7:* the ReactOS shell (taskbar/Start menu/icons) — a separate integration
effort with a two-upstream cost; see `docs/06`.

## WOW64 — 32-bit apps *(last, purely additive)*
GDT compat-mode descriptors; `NtCreateUserProcess` detects `IMAGE_FILE_MACHINE_I386` and
marks a WOW64 process; restrict its address space to low memory; deliver compat-mode
exceptions; a second (32-bit) set of Wine PE DLLs under `SysWOW64`. The 32→64 transition
is entirely in user mode (Wine's "new WoW64"); the kernel never sees a 32-bit syscall.
**Done when:** a 32-bit CUI app runs. Touches no semantics; removable.

---

## Success probability (honest)

For an implementer driving this with an LLM under real time pressure, the estimate to
"calc.exe on screen" is **~7%** — dominated not by difficulty but by **attrition** and by
the fact that **nobody has ever built this combination before**. Note that **M7
(Wine ntdll runs hello.exe) at ~30% is itself a world-first** and a complete result on
its own. See `docs/12` for how to raise the odds (constitution first; pull the calc
critical path off npfs; generate `abi/`; thick logging on day one).
