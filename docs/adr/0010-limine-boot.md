# ADR 0010 — Boot with Limine, not Multiboot2/GRUB

**Status:** Accepted

## Context
The kernel needs a boot protocol to reach a running 64-bit environment. proskrnl is x86-64
only (ADR 0006), tests in QEMU first and targets bare metal later, wants a higher-half
kernel, and — under LLM-driven development — must minimise bespoke assembly, which is a named
danger zone (`docs/12`). The candidates:

- **Multiboot2 (+GRUB).** Entry is 32-bit protected mode, so the kernel must hand-write the
  32→long-mode trampoline (GDT, PAE, LME, paging). Booting needs GRUB tooling
  (`grub-mkrescue`/`xorriso`) because QEMU's `-kernel` implements Multiboot **1**, not 2.
  GRUB is GPLv3. This is the worst of the options: external tooling *and* the trampoline.
- **Multiboot1 + `qemu -kernel`.** Fast loop, no image tooling — but still 32-bit entry (the
  trampoline again), a legacy protocol with a weak framebuffer/memmap story.
- **Limine.** Hands off in **64-bit long mode** with a higher-half direct map, paging, a
  clean memory map, and a linear framebuffer already set up. x86-64-first. BSD-2 licensed
  (clean for `docs/11`). Deploys onto exactly the FAT32 image `tools/mkimage.sh` already
  builds; supports both BIOS and UEFI, so the same image boots real hardware.

## Decision
Boot with **Limine**. `boot.S` is a thin Limine-entry stub (request markers → stack → into
C); no 32→long-mode trampoline is written.

## Consequences
- Removes the most error-prone piece of early bring-up — the trampoline — which is exactly
  the fiddly assembly the model gets subtly wrong (`docs/12`).
- The kernel is a higher-half ELF; long mode, paging, memory map, and a framebuffer are
  provided at entry (the framebuffer also helps GUI-1 and early logging).
- The QEMU loop boots `build/proskrnl-test.hdd` (a Limine-installed FAT32 image from
  `mkimage.sh`) instead of `-kernel build/proskrnl` (`docs/08`). Cost: an image build per
  run — marginal, since `mkimage.sh` exists and Limine installs straight onto it.
- Adds a vendored, version-pinned Limine binary + the `limine` deploy tool to the toolchain;
  its permissive licence keeps provenance clean.
- Gives up `qemu -kernel`'s zero-tooling fast load — but that only ever paired with
  Multiboot1, and always at the price of the trampoline.
