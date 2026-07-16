# Brewfile — proskrnl development toolchain (macOS / Homebrew).
#
#   brew bundle          # install everything below
#   brew bundle check    # verify it is all present
#
# Why each package: see README "Prerequisites" and docs/adr.

# ── Kernel build + run (needed for M1) ───────────────────────────────
brew "llvm"    # clang --target=x86_64-elf, llvm-objcopy; keg-only (not linked onto PATH)
brew "lld"     # ld.lld — ELF linker for the kernel; SEPARATE from llvm (macOS ld is Mach-O only)
brew "qemu"    # qemu-system-x86_64 — the run/test loop (docs/08)
brew "limine"  # bootloader; hands off in long mode (ADR 0010)
brew "mtools"  # mformat/mcopy — build the FAT32 boot image without mounting (tools/mkimage.sh)

# ── ntapi oracle test target (from M2; not required for M1) ──────────
brew "mingw-w64"     # build ntapi tests as a Windows .exe (docs/14)
cask "wine-stable"   # run the oracle .exe — finicky on Apple Silicon; Linux/CI is smoother

# ── Codegen / build driver ───────────────────────────────────────────
brew "python"  # tools/gen_abi.py, tools/gen_syscalls.py (used from M4)
# GNU make ships with the Xcode Command Line Tools — no formula needed.
