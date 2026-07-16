# 05 — Component Design

Per-component notes. For each, the pattern is: **what the semantic shadow forces**
(NT-shaped, non-negotiable) vs. **what is free** (build the simplest thing). The forced
parts are, by construction, the good core of NT.

---

## Ke — the most NT-shaped, because forced

`NtWaitForMultipleObjects` must handle wait-any/wait-all over an arbitrary mix of
events, processes, threads, timers, semaphores. This single requirement nearly
determines the internal design: every waitable object carries a common header
(`DISPATCHER_HEADER`-equivalent) with a signalled flag and a list of waiting threads,
linked to threads by wait blocks. We *will* reinvent this shape.

**Forced:** dispatcher-header + wait-block structure; notification vs. synchronization
events; mutex ownership/recursion; alertable wait + user-APC delivery timing; APC
mechanism (per-thread queues, interruption at alertable points).

**Free:** the scheduler (round-robin or CFS-like — only the observable results of
`NtDelayExecution` etc. matter); **no IRQL**; **no DPC as a contract** — interrupt
handling is plain Unix-style top/bottom half.

**Under T4:** uniprocessor, one dispatcher lock, no kernel preemption. This turns
`wait.c` from "a nest of races" into a plain state machine — the single most important
simplification for an implementer who cannot review concurrent code. This is *not*
cutting a corner: Linux 0.01 and early NT's dispatcher were effectively this.

`ke/{wait,apc}.c` is ~2000 lines, ~10% of code, but if subtly wrong it is the hidden
culprit behind every post-M7 bug (they surface months later as "calc occasionally
hangs"). Guard it with invariant asserts and the `sem_wait` tests.

---

## Ob — concept NT, implementation free

**Forced:** the object-manager *concept device* — handles, `OBJECT_ATTRIBUTES`,
namespaces (`\Device`, `\??`), inheritance/duplication. Writing these naturally yields
NT's shape.

**Free:** NT's 3-level handle tables and pushlocks are unnecessary — a locked growable
array suffices. Security-descriptor storage can be vestigial. Ob is small and tidy in NT;
here it is the closest thing to "a shrunken exact copy."

The handle table and object refcounting are where an LLM contributor is *most* likely to
introduce a use-after-free, and where KASAN pays off most (see `docs/08`).

---

## Mm — skeleton NT, viscera fully Unix

**Forced (boundary):** reserve/commit two-step; protection changes; guard pages (needed
for stack growth); **section objects** — named, handle-passable, first-class, backed by
file or by nothing (NT-unique; Unix's mmap has no equivalent). `SEC_IMAGE` sections drive
`CreateProcess`.

**Free (the biggest freedom in the kernel):** none of NT's Mm folklore — prototype PTEs,
working sets, the balance-set manager, the PFN state machine. Under T4:

```
page cache = hashtable (file, offset) -> physical page   [never evicted; writeback immediate]
ReadFile/WriteFile = memcpy against the page cache
shared mapping     = point at page-cache pages
private/image      = copy fully on map (NO COW initially)
demand-zero        = zero page on fault (kept — needed for guard pages / stack)
```

Under this design, **mapped-view / `ReadFile` consistency is structurally trivial**
because both see the same page-cache page. This is the exact problem the NT Mm/Cc/Io
"triangle" makes hellish, and which ReactOS is *still* rewriting — dissolved by unifying
the cache and refusing eviction. Cost is only RAM (e.g. ntdll `.text` duplicated per
process); irrelevant with a few GB.

`mm/{section,fault,pagecache}.c` is ~3500 lines nominal → ~1200 under T4, and its
difficulty drops by an order of magnitude. This is where the "stupidly correct" mandate
earns its keep. COW is added later (v2) behind the same `sem_mm` tests, if ever.

---

## Ps — only the *outside* of the structs is strict

**Forced:** the user-visible side — TEB/PEB/`RTL_USER_PROCESS_PARAMETERS`/KUSER_SHARED_DATA
— byte-exact against `abi/`. The user-mode return protocol
(`KiUserExceptionDispatcher`/`KiUserApcDispatcher`) — SEH dies without it; solidify early.

**Free:** `EPROCESS`/`ETHREAD` internal layout — nobody reads it (no drivers). `usermode.c`
is the difficult file: stack layout + assembly correctness. Wine's source is the spec;
verify against it rather than from memory.

On x64 the exception path is *simpler* than x86 (table-based unwind vs. chained `fs:[0]`
frames) — a direct benefit of T6.

---

## Io — the furthest from NT

**Forced:** the async-completion protocol — "return pending, write the `IO_STATUS_BLOCK`,
notify via APC/event/completion-port" is observable and depended-upon. A completion-record
structure necessarily grows (the *essence* of IRP), even though we discard IRP's
*complexity* (stacks, layering).

**Free:** no IRP, no `IO_STACK_LOCATION`, no `StartIo`, no cancel routines. Device objects
live in the Ob namespace (so `NtCreateFile("\Device\...")` resolves), but past that it's a
`file_operations`-style table (`vfs.h`) — internal, rewritable at will.

`io/query.c` (info classes) is ~1500 lines of near-mechanical struct-filling — the *easiest*
kernel file and an ideal LLM task. `io/async.c` is the contract-bearing file — small, but
wire it to `sem_file` tests directly.

---

## Cm — interface only

**Forced:** `NtCreateKey`/value-query semantics and information classes.

**Free:** the hive binary format need not match Windows (we never read a real Windows
hive). Internals can be a B-tree or a logged KV store. NT's Cm complexity is mostly hive
format + recovery logging; we shed both. `wineboot` writing hundreds of CLSIDs is Cm's
integration test (see `docs/06`).

---

## Se — shape only

**Forced:** a token object; every relevant `Nt*` accepts a `SECURITY_DESCRIPTOR`;
`NtQueryInformationToken` info classes return sane values (advapi32 reads them).

**Free:** everything else. "Always allow", fixed admin token, ~300 lines. A single-user OS
needs no guest list. (If sandboxing *research* is later pursued, Se must be built for
real — a deliberate buy-back of this simplification; see `docs/00` and the research note.)

---

## Syscall layer — shape only

A plain function table (SSDT-equivalent) and user-pointer validation (bad pointers must
surface as `STATUS_ACCESS_VIOLATION` — observable, so fault-trapping copy-in is required).
None of NT's `KiSystemService` acrobatics.

---

## Is it monolithic?

**Yes — more monolithic than NT.** Drivers statically linked, HAL absorbed, no module
loader, a single static image. NT is called "hybrid" for microkernel *heritage*
(subsystem processes, LPC), not structure. What remains of that heritage in proskrnl is
only in **user mode** (smss-equivalent; conhost+condrv for CUI), and only because modern
NT itself evolved into that shape — we adopt the result, not the ideology.

The microkernel *vocabulary*, however, is everywhere and is inherited wholesale:
everything is an object, referenced by a handle, waitable through one mechanism. That
vocabulary — NT's habit of making implicit conventions explicit — is exactly what the
boundary preserves.
