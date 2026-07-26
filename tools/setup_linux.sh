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
#   third_party/freetype        the PE static library win32u's font backend
#                               links against (tools/build_freetype.sh) —
#                               seconds, not a real build like the two below
#   third_party/qemu            qemu-system-x86_64 (>= 9.0 is required for
#                               TCG x2APIC; Ubuntu 24.04 ships 8.2)
#   third_party/wine            the ntapi oracle's wine — the SAME pinned
#                               tree abi/ is generated from, so the oracle
#                               can never diverge from the contract. It is
#                               also the source of the PE dlls + nls files
#                               baked onto proskrnl's boot volume (Makefile
#                               WINFILES): one build is oracle, shipped
#                               userland, and dormancy check at once
#                               (docs/06 "One tree, three roles")
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
    gdisk mtools dosfstools \
    ninja-build meson pkg-config libglib2.0-dev libpixman-1-dev \
    libgtk-3-dev bzip2 \
    flex bison python3-venv \
    gcc libc6-dev gcc-mingw-w64-x86-64

# Bring every third_party submodule to its pinned gitlink, one at a time so
# a single broken tree cannot strand the rest (an empty clone with an unborn
# HEAD aborts a no-path `git submodule update` before it reaches the later
# submodules, leaving them at clone-time default-branch tips). Per-path
# update first; on failure, repair the clone directly by fetching the pinned
# sha and detaching onto it. Then fail loudly on any remaining drift — the
# builds below and abi/ generation silently trust these checkouts.
echo "== pinned submodules =="
while IFS=$'\t' read -r sha path; do
    if git submodule update --init --depth 1 -- "$path" </dev/null; then
        continue
    fi
    echo "   $path: submodule update failed; fetching pin $sha directly"
    git -C "$path" fetch --depth 1 origin "$sha" </dev/null ||
        git -C "$path" fetch origin "$sha" </dev/null ||
        git -C "$path" fetch origin </dev/null
    git -C "$path" checkout -q --detach "$sha" </dev/null
done < <(git ls-tree HEAD third_party/ | awk '$2 == "commit" { print $3 "\t" $4 }')
drift="$(git submodule status third_party/ | grep -v '^ ' || true)"
if [[ -n "$drift" ]]; then
    echo "setup_linux: submodules are NOT at their pinned commits:" >&2
    echo "$drift" >&2
    exit 1
fi

echo "== limine: deploy tool (stages are prebuilt on the binary branch) =="
make -C third_party/limine limine

# GUI-2 needs real glyphs, and there is no dynamic loader on the target to
# hand win32u a libfreetype.so, so FreeType is cross-built as a PE static
# library and linked in. The Makefile has the same rule on demand; doing it
# here means a provisioned box never discovers it mid-build. The mingw
# cross-compiler it needs is in the apt list above.
echo "== freetype: the PE static library (win32u's font backend) =="
tools/build_freetype.sh

echo "== qemu: x86_64-softmmu =="
if [[ -x third_party/qemu/build/qemu-system-x86_64 ]]; then
    echo "   already built — skipping"
else
    mkdir -p third_party/qemu/build
    # --enable-gtk (not autodetect) so `make rungui` deterministically gets a
    # host window; libgtk-3-dev is in the apt list above. The headless test
    # legs never open a display, so nothing else changes.
    (cd third_party/qemu/build &&
        ../configure --target-list=x86_64-softmmu --disable-docs --disable-user \
            --enable-gtk)
    make -C third_party/qemu/build -j"$(nproc)"
fi

# One wine build, three roles (docs/06): the ntapi/fuzz oracle, the source of
# the PE dlls + nls files shipped on proskrnl's disk (Makefile WINFILES), and
# — because the pinned fork's seam commits are dormant under a live unixlib —
# the continuous proof that the patched PE ntdll behaves identically on
# regular Wine.
echo "== wine: the ntapi oracle (64-bit only, no GUI/font deps) =="
if [[ -x third_party/wine/wine64 || -x third_party/wine/wine ]]; then
    echo "   already built — skipping"
else
    # --without-fontconfig is explicit, not autodetect: libgtk-3-dev (for the
    # QEMU GTK build above) drags the fontconfig dev headers in, and an
    # oracle whose config.h depends on which host built it is exactly the
    # drift the pins exist to prevent (user/wine/include/config.h pins the
    # win32u build against it regardless).
    (cd third_party/wine &&
        ./configure --enable-win64 --without-x --without-freetype \
            --without-fontconfig --disable-tests)
    make -C third_party/wine -j"$(nproc)"
fi

# M10 stretch (docs/02): the winetest gate (tests/run/run.sh winetest) links
# its standalone test binaries from the pinned tree's own PE test objects.
# --disable-tests only trims makedep's directory list — config.h is untouched
# — so re-configuring with tests enabled is incremental over the build above.
# Only the five in-scope CUI test directories are built; note a bare `make`
# in third_party/wine after this point would build every test module.
echo "== wine: the CUI test modules (the winetest gate) =="
if [[ -f third_party/wine/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe ]]; then
    echo "   already built — skipping"
else
    (cd third_party/wine &&
        ./configure --enable-win64 --without-x --without-freetype \
            --without-fontconfig)
    make -C third_party/wine -j"$(nproc)" \
        dlls/ntdll/tests/all dlls/kernel32/tests/all dlls/msvcrt/tests/all \
        dlls/ucrtbase/tests/all programs/cmd/tests/all
fi

echo
echo "setup_linux: done. Next:"
echo "  make test                   # boot the kernel in QEMU, expect the [KTEST] verdict"
echo "  tests/run/run.sh oracle     # run the ntapi suite against the pinned wine"
