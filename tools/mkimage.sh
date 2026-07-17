#!/usr/bin/env bash
# mkimage.sh — build a Limine BIOS-bootable disk image (ADR 0010).
#
#   mkimage.sh <kernel-elf> <out-hdd> [<module.bin>=<cmdline> ...]
#
# Canonical Limine recipe: a GPT disk with one ESP-typed FAT partition; format
# and populate it, then install the Limine BIOS stage. Needs sgdisk (gptfdisk)
# + mtools + the limine deploy tool. See docs/04 "Build model".
#
# M4: any extra "<module.bin>=<cmdline>" arguments are baked in as Limine boot
# modules (the flat-binary user clients, docs/02). Each becomes module_path +
# module_string lines appended to a generated copy of limine.conf; the kernel
# reads the cmdline as the module's expected outcome (kernel/init/main.c).
set -euo pipefail

KERNEL="${1:?usage: mkimage.sh <kernel-elf> <out-hdd> [module.bin=cmdline ...]}"
IMG="${2:?usage: mkimage.sh <kernel-elf> <out-hdd> [module.bin=cmdline ...]}"
shift 2 || true
MODULE_SPECS=("$@")
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF_BASE="$HERE/../arch/x86_64/limine.conf"
SIZE_MB="${SIZE_MB:-64}"

# Build the effective config: the checked-in base plus one module_path /
# module_string pair per requested module.
CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT
cp "$CONF_BASE" "$CONF"
for spec in "${MODULE_SPECS[@]}"; do
    modfile="${spec%%=*}"
    modstring="${spec#*=}"
    base="$(basename "$modfile")"
    printf '    module_path: boot():/%s\n' "$base" >> "$CONF"
    printf '    module_string: %s\n' "$modstring" >> "$CONF"
done

# Limine's data dir (limine-bios.sys, BOOTX64.EFI) and `limine` deploy tool:
# the pinned third_party/limine submodule (binary release branch; built by
# tools/setup_linux.sh) is preferred, then $LIMINE_SHARE / $LIMINE overrides,
# then Homebrew's keg (macOS), then the usual Linux install prefixes.
find_limine_share() {
    local d
    d="$HERE/../third_party/limine"
    [[ -f "$d/limine-bios.sys" ]] && { echo "$d"; return 0; }
    if command -v brew >/dev/null 2>&1; then
        d="$(brew --prefix limine 2>/dev/null)/share/limine"
        [[ -f "$d/limine-bios.sys" ]] && { echo "$d"; return 0; }
    fi
    for d in /usr/local/share/limine /usr/share/limine; do
        [[ -f "$d/limine-bios.sys" ]] && { echo "$d"; return 0; }
    done
    return 1
}
LIMINE_SHARE="${LIMINE_SHARE:-$(find_limine_share)}" || {
    echo "mkimage: Limine data dir not found (no limine-bios.sys)." >&2
    echo "         Run tools/setup_linux.sh (or install Limine per the README" >&2
    echo "         \"Prerequisites\") or set LIMINE_SHARE." >&2
    exit 1
}
find_limine_tool() {
    if [[ -x "$HERE/../third_party/limine/limine" ]]; then
        echo "$HERE/../third_party/limine/limine"
    else
        echo "limine"
    fi
}
LIMINE="${LIMINE:-$(find_limine_tool)}"
# p1 = BIOS boot partition (EF02, sectors 2048..4095 = 1 MiB) for Limine's stage.
# p2 = ESP (EF00, FAT32) from sector 4096; mtools targets it at a byte offset.
ESP_OFF=2097152    # 4096 * 512

mkdir -p "$(dirname "$IMG")"
rm -f "$IMG"
# bs=1048576: BSD dd spells 1 MiB "1m", GNU dd "1M" — the byte count is portable.
dd if=/dev/zero of="$IMG" bs=1048576 count="$SIZE_MB" 2>/dev/null

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
for spec in "${MODULE_SPECS[@]}"; do
    modfile="${spec%%=*}"
    mcopy -i "$IMG@@$ESP_OFF" "$modfile" "::/$(basename "$modfile")"
done
mcopy   -i "$IMG@@$ESP_OFF" "$LIMINE_SHARE/BOOTX64.EFI"     ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null || true

# Install the Limine BIOS boot stage into the BIOS-boot partition.
"$LIMINE" bios-install "$IMG"

echo "mkimage: built $IMG (${SIZE_MB} MiB, GPT/FAT32)"
