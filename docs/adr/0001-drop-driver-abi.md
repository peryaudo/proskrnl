# ADR 0001 — Drop Windows driver binary compatibility

**Status:** Accepted

## Context
Windows kernel-mode driver compatibility is a contract over **struct layouts and
context-dependent timing**, not over function calls. Drivers share the kernel's address
space, hold IRPs directly, read fields like `IRP->IoStatus` at compile-time-baked offsets
(WDM's "API" is largely inline functions in `wdm.h`, copied into each driver binary), and
depend on IRQL semantics. There is no marshaling point, so no compatibility layer can exist
— which is precisely why Microsoft itself broke this ABI at both the x64 and ARM64
transitions. ReactOS chose this boundary and has been taxed by it for 30 years.

## Decision
proskrnl does **not** run unmodified Windows kernel-mode drivers. Drivers are written
in-tree, statically linked, against a free internal interface (`io/vfs.h`), for a *chosen*,
spec-documented hardware set (virtio first).

## Consequences
- Deletes the largest, dirtiest part of NT: IRP, driver stacks, PnP, power, the kernel PE
  loader for drivers, hundreds of exports, and the obligation to reproduce IRQL/DPC as
  external contracts. HAL collapses into `arch/`.
- Removes the untestable, un-redesignable part of the system. What remains at the boundary
  is observable from user mode and therefore testable.
- Gives up AV/anti-cheat/VPN/backup drivers — i.e., most reasons people install drivers.
  Accepted, because those depend on exactly the struct-offset archaeology we refuse.
- This is the decision that makes every other simplification possible. See docs/03 §Dropped.
