# 13 — Glossary (for SWEs without a Windows background)

NT's defining habit: it turns Unix's **implicit conventions** into **explicit entities**.
Most terms below have a Unix counterpart; the difference is usually just the name plus this
explicitness. That explicitness is a design virtue — and also the reason each entity, once
it leaks across an ABI, becomes an un-redesignable contract.

## Naming convention (read this first)

A function's two-letter prefix is its **department**:

| Prefix | Subsystem | | Prefix | Subsystem |
|---|---|---|---|---|
| `Ke` | Kernel core (sched/sync) | | `Cm` | Config manager (registry) |
| `Ki` | Kernel internal | | `Cc` | Cache controller |
| `Mm` | Memory manager | | `Se` | Security |
| `Ob` | Object manager | | `Ex` | Executive utilities |
| `Ps` | Process/thread | | `Rtl` | Runtime library (pure fns) |
| `Io` | I/O manager | | `Hal` | Hardware abstraction |

`Nt*` and `Zw*` are the same syscall via two entrances: `Nt*` from user mode (caller
untrusted; pointers validated), `Zw*` from kernel (validation skipped) — like Linux's
`sys_read` vs. `kernel_read`.

## Interrupts, and why handlers must be short

Hardware interrupts the CPU; the CPU jumps to a handler (ISR). While the handler runs,
other (equal/lower priority) interrupts are blocked, so the handler must be tiny. Hence the
**two-halves** pattern: a **top half** does the minimum and queues the rest; a **bottom
half** does the real work once interrupts are free again.

- **softirq** (Linux term) = the bottom-half mechanism ("software interrupt").
- **DPC** (Windows) = the same idea: Deferred Procedure Call. Runs later, in *no particular
  thread's* context, so it cannot block or touch pageable memory. **DPC ≈ softirq/tasklet.**

## IRQL — one number for "what is allowed right now"

A **per-CPU** number that fuses three separate Unix ideas into one dial: interrupt masking
(`local_irq_disable`), preemption disable (`preempt_disable`), and the *implicit* rule "you
may not sleep in interrupt context." NT makes that last rule a **number**. Two rules follow:
raising it masks lower-priority interrupts; the scheduler itself runs at IRQL 2
(`DISPATCH_LEVEL`), so at IRQL ≥ 2 you cannot block, cannot fault, and must use non-pageable
memory. **proskrnl drops IRQL entirely** — with no third-party drivers, the contract is owed
to no one, and ordinary interrupt-disable + one lock suffices.

## APC — "run this function in *that specific thread*"

Asynchronous Procedure Call: a queue of "run function F in thread T's context." Unlike a
DPC (per-CPU, context-agnostic), an APC is per-thread and context-specific. **Why it
exists:** an async `ReadFile` must eventually copy data into the *caller's* buffer, which
lives only in the caller's address space — so completion must run in that thread's context.
Two kinds:

- **Kernel APC** (delivered when the thread is at PASSIVE) — forced; used for I/O-completion
  copy, thread suspend/terminate.
- **User APC** — runs user code, but only when the thread enters an **alertable wait**
  (e.g. `SleepEx(ms, TRUE)`).

Closest Unix analogue: **signals**. User APC ≈ signal handler; alertable wait ≈
interruptible sleep; APC interrupting a wait (`STATUS_USER_APC`) ≈ `EINTR`. But an APC is a
queue of (function, args), which is cleaner than (number, handler). NT solved with APCs in
1993 what Linux later revisited with `io_uring`.

## Dispatcher objects & unified waiting — NT's best idea

In NT, **everything waitable has the same shape**: a common header
(`DISPATCHER_HEADER`) with a "signalled" flag and a waiter list. So
`WaitForMultipleObjects` can wait on an event, a timer, a process, a mutex, and a file **in
one call**. Unix split this across `select/poll` (fds), `waitpid` (children), `sigwait`
(signals), `pthread_join` (threads); Linux spent 20 years adding `signalfd`/`timerfd`/`pidfd`
to catch up — i.e. to make everything a waitable fd, which is what NT did from the start.

## Section object — a named, first-class mmap

"Something mappable," promoted to a kernel object. Unlike Unix `mmap(fd,…)` (an ephemeral
fd↔process relation), a section is independent: it has a name, is passed by handle, and is
backed by a file *or by nothing* (`MAP_ANONYMOUS|MAP_SHARED`). With `SEC_IMAGE` it parses a
PE, sets per-section protection, and maps copy-on-write — so **`CreateProcess` is built on
image sections.** That is why sections must exist before processes can start.

## SSDT — just the syscall table

System Service Descriptor Table = Linux's `sys_call_table`. Famous only because 2000s AV/
rootkits hooked it; x64 PatchGuard forbade that. Nothing special in itself.

## IRP & MDL — the driver-world vocabulary (dropped here)

- **IRP** (I/O Request Packet): an I/O request turned into a heap object, passed *down* a
  stack of driver layers, completing back *up*. Linux's `struct bio` is similar but only for
  block I/O; NT makes *all* I/O this shape. proskrnl drops IRP (T1) and keeps only the
  async-completion essence.
- **MDL** (Memory Descriptor List): the physical pages backing a virtual buffer — Linux's
  `get_user_pages()` + scatter-gather.

## npfs — Named Pipe File System

A pipe is a byte conduit between two processes (`ls | grep`'s `|`). A **named** pipe adds a
name so *unrelated* processes can connect (`\\.\pipe\name`). In NT it is implemented **as a
filesystem** (`npfs.sys`) living in the object namespace at `\Device\NamedPipe\…`, opened
with `NtCreateFile` like any file. Unlike Unix pipes, NT pipes support **message mode**
(record boundaries preserved) — one of the things Wine struggles to reproduce on Unix.
Nearest Unix analogue is a Unix-domain socket, not `mkfifo`. proskrnl needs npfs for
rpcrt4/services, but **keeps it off the calc.exe critical path** by giving wineserver-lite a
shared-section transport instead.

## The user-mode NT cast (all just `.exe`s, except condrv)

- **smss.exe** — first process after the kernel; the `init`/`systemd` of NT. Mounts hives,
  makes the page file, launches the next process.
- **csrss.exe** — the Win32 subsystem's "receptionist." Once did window management and
  consoles; lost windows to win32k (NT 4.0) and consoles to conhost (Win8). Killing it BSODs
  Windows. GUI-less proskrnl mostly omits it (and ALPC with it).
- **conhost.exe** — draws the black console window. The app only says "print this"; conhost
  lays out glyphs, scrolls, handles selection. Split out of csrss in Win7 to reduce that
  process's power.
- **condrv.sys** — the *kernel* driver connecting an app to conhost (Win8+), so a console
  looks like an ordinary device/file to the app.

## Executive / Ke split, "hybrid kernel"

NT's Executive (Mm/Ob/Ps/Io/…) sits on the Ke core (scheduling/sync). All same address
space, direct calls — the split is code organization, not a microkernel. NT is called
"hybrid" for microkernel *heritage* (subsystems, LPC), not structure. proskrnl is **more
monolithic than NT**: static drivers, absorbed HAL, single image. What it inherits from the
microkernel world is **vocabulary** (objects, handles, unified waiting), not architecture.

## Wine PE side / unixlib side

Modern Wine builds each DLL as a real **PE** file split into a **PE side** (Windows logic,
app-visible) and a **unixlib side** (host calls), meeting at a thin function table. proskrnl
keeps the PE side and swaps the unixlib side for syscall stubs — which is exactly NT's own
structure (a PE ntdll that syscalls). See `docs/06`.
