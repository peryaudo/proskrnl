# 00 — Design Overview

## The single idea

Every long-lived OS-compatibility project lives or dies on **one choice: which
boundary do you promise to reproduce?** Everything else follows from it.

proskrnl promises to reproduce the **NT native API boundary** — the surface that Wine's
PE-side DLLs read and call — and *nothing below or above it in Microsoft-compatible
form*.

Concretely, the boundary is three things:

1. **The `Nt*` system calls** — their arguments, information classes, `NTSTATUS`
   results, and asynchronous-completion behaviour, for the subset Wine invokes.
2. **The user-visible structures** — `PEB`, `TEB`, `RTL_USER_PROCESS_PARAMETERS`,
   `KUSER_SHARED_DATA` — byte-for-byte, because Wine's DLLs read their fields directly.
3. **NT file semantics** — share modes, case-insensitive/case-preserving names,
   delete-on-close, byte-range locks, the `NtQuery*File` information classes, and
   asynchronous I/O with APC/event/completion-port notification.

If it is on that list, we reproduce it exactly. If it is not, we are free.

## The "semantic shadow" principle

The boundary casts a shadow onto our internal design. Where a behaviour is
**observable from user mode**, the internal structure that produces it is effectively
forced — we will reinvent NT's shape whether we mean to or not. Where the shadow does
not reach, we build whatever is simplest, and "simplest" almost always means a plain
Unix-style teaching kernel.

The result is a chimera: **an NT skeleton with Unix-teaching-kernel viscera.**

| Component | Forced to be NT-shaped by… | Free to be simple in… |
|---|---|---|
| **Ke** | unified waitable objects, APC delivery, alertable waits | scheduler internals, no IRQL, no DPC-as-contract |
| **Ob** | handles, `OBJECT_ATTRIBUTES`, `\Device`/`\??` namespace | table structure, no 3-level tables, no pushlocks |
| **Mm** | section objects, reserve/commit, guard pages, protection | everything else — unified page cache, no eviction; COW for image sections only (CUI-9, `docs/17`) |
| **Ps** | PEB/TEB/params layout, user-mode return protocol | EPROCESS/ETHREAD internal layout (nobody reads it) |
| **Io** | async completion protocol (IOSB, APC/event/port) | no IRP, no driver stack — a VFS-style internal interface |
| **Cm** | `NtCreateKey` semantics, information classes | hive format (our own), no transactions/notifications |
| **Se** | token shape read by advapi32; one fixed identity; SD-bearing objects get the real DACL check (CUI-6) | no-SD objects stay permissive; one admin identity, no audit |

The forced column is, almost exactly, **the good, deliberate core of Cutler's NT
design** (unified waitable objects, handles, async I/O with APCs, section objects). The
free column is the part of NT that grew for historical or performance reasons. The
boundary conveniently slices along the seam between NT's essence and NT's accidents.

## What this is *not*

- **Not a monolithic-vs-microkernel debate.** proskrnl is **more monolithic than NT**:
  drivers are statically linked, HAL is absorbed, there is no loadable module system,
  the whole kernel is a single static image. What survives of NT's microkernel heritage
  is not structure but **vocabulary** — everything is an object, referenced by a handle,
  waitable through one mechanism.
- **Not bug-for-bug compatible with any Windows build.** We target NT *semantics as Wine
  expects them*, not a specific `ntoskrnl.exe` version. There is no fixed NT version to
  chase; Wine tracks the modern world for us.
- **Not a performance project.** We ship the *stupidly correct* implementation (see
  `docs/09-constitution.md`). We sell semantics, not speed. The one asset nobody else has
  is a transparent, instrumentable, deterministic NT-semantics implementation — not a
  fast one.

## The shape of the system

```
  Windows application (CUI; later GUI; later 32-bit)
        |
  Wine PE user-mode DLLs  (unmodified: user32, gdi32, kernelbase, msvcrt, …)
        |
  ntdll  (Wine PE side kept; unix backend replaced by our syscall stubs)   <-- M7
        |
  ============ THE BOUNDARY: Nt* + PEB/TEB + file semantics ============
        |
  proskrnl  (monolithic: Ke, Mm, Ob, Ps, Io-lite, Cm, Se-stub, syscall)
        |
  in-tree drivers (virtio, condrv) + FAT32 + npfs   [no Windows driver ABI]
        |
  chosen hardware (QEMU/KVM + virtio first; one specific bare-metal box later)
```

## Why the boundary is also the verification story

Because the boundary is observable from an unprivileged `.exe`, three things become
possible that were impossible for ReactOS at the driver boundary:

1. **Oracles exist.** The real Windows behaviour can be captured as executable tests.
2. **Wine's test suite is our conformance suite.** It is a third-party specification,
   already verified against Windows.
3. **Differential fuzzing works.** The same test binary runs on Windows and on
   proskrnl; any divergence is a bug, found automatically.

This is the deepest reason the project is tractable. See `docs/08-verification.md`.
