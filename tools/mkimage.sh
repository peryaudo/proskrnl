#!/usr/bin/env bash
# mkimage.sh — build a Limine BIOS-bootable disk image (ADR 0010).
#
#   mkimage.sh <kernel-elf> <out-hdd>
#
# Canonical Limine recipe: a GPT disk with one ESP-typed FAT partition; format
# and populate it, then install the Limine BIOS stage. Needs sgdisk (gptfdisk)
# + mtools + the limine deploy tool. See docs/04 "Build model".
set -euo pipefail

KERNEL="${1:?usage: mkimage.sh <kernel-elf> <out-hdd>}"
IMG="${2:?usage: mkimage.sh <kernel-elf> <out-hdd>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/../arch/x86_64/limine.conf"
LIMINE_SHARE="$(brew --prefix limine)/share/limine"
SIZE_MB="${SIZE_MB:-64}"
# p1 = BIOS boot partition (EF02, sectors 2048..4095 = 1 MiB) for Limine's stage.
# p2 = ESP (EF00, FAT32) from sector 4096; mtools targets it at a byte offset.
ESP_OFF=2097152    # 4096 * 512

mkdir -p "$(dirname "$IMG")"
rm -f "$IMG"
dd if=/dev/zero of="$IMG" bs=1m count="$SIZE_MB" 2>/dev/null

# GPT: a BIOS-boot partition (required for Limine BIOS on GPT) + a FAT32 ESP.
sgdisk "$IMG" \
    -n 1:2048:+1M -t 1:ef02 -c 1:"BIOS boot" \
    -n 2:0:0      -t 2:ef00 -c 2:"ESP" >/dev/null

# Format the ESP FAT32 and populate it (mtools '::' at a byte offset).
mformat -i "$IMG@@$ESP_OFF" -F ::
mmd     -i "$IMG@@$ESP_OFF" ::/EFI ::/EFI/BOOT 2>/dev/null || true
mcopy   -i "$IMG@@$ESP_OFF" "$KERNEL"                       ::/proskrnl
mcopy   -i "$IMG@@$ESP_OFF" "$CONF"                         ::/limine.conf
mcopy   -i "$IMG@@$ESP_OFF" "$LIMINE_SHARE/limine-bios.sys" ::/limine-bios.sys
mcopy   -i "$IMG@@$ESP_OFF" "$LIMINE_SHARE/BOOTX64.EFI"     ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null || true

# Install the Limine BIOS boot stage into the BIOS-boot partition.
limine bios-install "$IMG"

echo "mkimage: built $IMG (${SIZE_MB} MiB, GPT/FAT32)"
