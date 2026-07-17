#!/usr/bin/env bash
# setup_linux.sh — one-shot development setup for Ubuntu 24.04 (README
# "Prerequisites"). Installs the apt toolchain and builds the pinned
# third_party dependencies IN PLACE, so nothing version-drifts between
# environments and nothing needs `make install`:
#
#   third_party/limine          bootloader stages (prebuilt on the pinned
#                               binary-release branch) + the `limine` deploy
#                               tool (one cc invocation)
#   third_party/limine-protocol the kernel-facing boot-protocol header
#   third_party/qemu            qemu-system-x86_64 (>= 9.0 is required for
#                               TCG x2APIC; Ubuntu 24.04 ships 8.2)
#   third_party/wine            the ntapi oracle's wine — the SAME pinned
#                               tree abi/ is generated from, so the oracle
#                               can never diverge from the contract
#
# tools/{mkimage,qemu}.sh and tests/run/run.sh pick these up automatically.
# Idempotent: finished builds are skipped; re-run after a submodule bump.
# Expect the first run to take a while (QEMU and Wine are real builds).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    SUDO="sudo"
fi

echo "== apt packages =="
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
    clang lld llvm clang-format clang-tidy make git ca-certificates python3 \
    gdisk mtools \
    ninja-build meson pkg-config libglib2.0-dev libpixman-1-dev \
    flex bison python3-venv \
    gcc libc6-dev gcc-mingw-w64-x86-64

echo "== pinned submodules =="
git submodule update --init --depth 1 \
    third_party/limine third_party/limine-protocol third_party/qemu third_party/wine

echo "== limine: deploy tool (stages are prebuilt on the binary branch) =="
make -C third_party/limine limine

echo "== qemu: x86_64-softmmu =="
if [[ -x third_party/qemu/build/qemu-system-x86_64 ]]; then
    echo "   already built — skipping"
else
    mkdir -p third_party/qemu/build
    (cd third_party/qemu/build &&
        ../configure --target-list=x86_64-softmmu --disable-docs --disable-user)
    make -C third_party/qemu/build -j"$(nproc)"
fi

echo "== wine: the ntapi oracle (64-bit only, no GUI/font deps) =="
if [[ -x third_party/wine/wine64 || -x third_party/wine/wine ]]; then
    echo "   already built — skipping"
else
    (cd third_party/wine &&
        ./configure --enable-win64 --without-x --without-freetype --disable-tests)
    make -C third_party/wine -j"$(nproc)"
fi

echo
echo "setup_linux: done. Next:"
echo "  make run                    # boot the kernel in QEMU, expect [KTEST] M3 PASS"
echo "  tests/run/run.sh oracle     # run the ntapi suite against the pinned wine"
