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
#                               links against, and the native shared library
#                               the wine below is configured against
#                               (tools/build_freetype.sh) — seconds, not a
#                               real build like the two below
#   third_party/qemu            qemu-system-x86_64, built only when the host
#                               has none on PATH (any distro build runs the
#                               tests — there is no version floor)
#   third_party/wine            the ntapi oracle's wine — the SAME pinned
#                               tree abi/ is generated from, so the oracle
#                               can never diverge from the contract. It is
#                               also the source of the PE dlls + nls files
#                               baked onto proskrnl's boot volume (Makefile
#                               WINFILES): one build is oracle, shipped
#                               userland, and dormancy check at once
#                               (docs/06 "One tree, three roles"). Since
#                               GUI-3 it is the font-metrics oracle too,
#                               built against the pinned FreeType above
#
# tools/{mkimage,qemu}.sh and tests/run/run.sh pick these up automatically.
# Idempotent: finished builds are skipped; re-run after a submodule bump.
# Expect the first run to take a while (QEMU and Wine are real builds).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Parallelism for the two real source builds. nproc is the portable default,
# but it reports the process's CPU affinity / cgroup quota rather than the
# machine's width — on a box whose container is pinned to half its cores it
# silently halves the wine and qemu builds, which are the long poles here.
# Override with JOBS=<n> when you know better than the cgroup does.
JOBS="${JOBS:-$(nproc)}"

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
# cross-compiler it needs is in the apt list above. Since GUI-3 the same
# script also builds the native shared library the wine below is configured
# against, so this must run BEFORE wine's configure.
echo "== freetype: the PE static library + the native one (font backends) =="
tools/build_freetype.sh

echo "== qemu: x86_64-softmmu =="
if [[ -x third_party/qemu/build/qemu-system-x86_64 ]]; then
    echo "   already built — skipping"
elif command -v qemu-system-x86_64 >/dev/null 2>&1; then
    # No version floor since the kernel's clock moved to the xAPIC MMIO window
    # (arch/x86_64/lapic.c): a distro qemu-system-x86_64 runs the tests, so the
    # long source build is only for hosts that have none. tools/qemu.sh still
    # prefers an in-tree build when one exists.
    echo "   $(qemu-system-x86_64 --version | head -1) on PATH — skipping the source build"
else
    mkdir -p third_party/qemu/build
    # --enable-gtk (not autodetect) so `make rungui` deterministically gets a
    # host window; libgtk-3-dev is in the apt list above. The headless test
    # legs never open a display, so nothing else changes.
    (cd third_party/qemu/build &&
        ../configure --target-list=x86_64-softmmu --disable-docs --disable-user \
            --enable-gtk)
    make -C third_party/qemu/build -j"$JOBS"
fi

# One wine build, three roles (docs/06): the ntapi/fuzz oracle, the source of
# the PE dlls + nls files shipped on proskrnl's disk (Makefile WINFILES), and
# — because the pinned fork's seam commits are dormant under a live unixlib —
# the continuous proof that the patched PE ntdll behaves identically on
# regular Wine. Since GUI-3, a fourth: the font-METRICS oracle.
#
# The font backend is the PINNED third_party/freetype built native above,
# never the distro's. The oracle is the spec (docs/06), and a spec that
# answers metric questions from a different FreeType than the one
# win32u.dll links is not one — Ubuntu 24.04 ships 2.13.2, the pin is
# 2.13.3. FREETYPE_CFLAGS/FREETYPE_LIBS are configure's own precious
# variables and bypass pkg-config entirely, so no libfreetype-dev and no .pc
# file are needed. fontconfig is explicitly OFF: it autodetects ON on Linux
# (libgtk-3-dev, installed above for QEMU, drags its dev files in), and with
# it on, win32u's freetype_load_fonts() would pull the HOST's font set into
# the oracle. With it off the oracle's fonts are the build tree's own fonts/
# plus C:\windows\fonts — exactly the set Makefile WINE_FONTS bakes onto the
# GUI images. Both sides then match in backend, version, and font set.
FT_NATIVE="$ROOT/third_party/freetype/x86_64-linux"
WINE_FT_ENV=(
    FREETYPE_CFLAGS="-I$ROOT/third_party/freetype/include"
    FREETYPE_LIBS="-L$FT_NATIVE -lfreetype"
)
WINE_CONFIGURE=(--enable-win64 --without-x --with-freetype --without-fontconfig)

# A box provisioned before GUI-3 carries a --without-freetype wine, and the
# two "already built — skipping" guards below would serve it forever. wine's
# configure writes SONAME_LIBFREETYPE into the generated include/config.h
# exactly when the font backend is on, and ERRORS OUT when freetype is wanted
# but missing (WINE_ERROR_WITH, third_party/wine/aclocal.m4) — so that define
# is a truthful "this tree has fonts" marker, not a heuristic. Computed ONCE,
# before either pass, so pass 1's own reconfigure cannot wash the flag out and
# both passes rerun exactly once.
wineStale=0
if [[ -f third_party/wine/include/config.h ]] &&
    ! grep -q '^#define SONAME_LIBFREETYPE ' third_party/wine/include/config.h; then
    wineStale=1
    echo "== wine: pre-GUI-3 (--without-freetype) build found — reconfiguring =="
fi

echo "== wine: the ntapi + font-metrics oracle (64-bit only, no X) =="
if [[ $wineStale -eq 0 && ( -x third_party/wine/wine64 || -x third_party/wine/wine ) ]]; then
    echo "   already built — skipping"
else
    # --without-fontconfig is explicit, not autodetect: libgtk-3-dev (for the
    # QEMU GTK build above) drags the fontconfig dev headers in, and an
    # oracle whose config.h depends on which host built it is exactly the
    # drift the pins exist to prevent (user/wine/include/config.h pins the
    # win32u build against it regardless).
    (cd third_party/wine &&
        env "${WINE_FT_ENV[@]}" ./configure "${WINE_CONFIGURE[@]}" --disable-tests)
    # With fonts enabled the build also builds and RUNS the host tool
    # sfnt2fon, which links the pinned library directly — it has to be
    # findable at build time, not just at wine's runtime dlopen.
    LD_LIBRARY_PATH="$FT_NATIVE${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        make -C third_party/wine -j"$JOBS"
fi

# M10 stretch (docs/02): the winetest gate (tests/run/run.sh winetest) links
# its standalone test binaries from the pinned tree's own PE test objects.
# --disable-tests only trims makedep's directory list — config.h is untouched
# — so re-configuring with tests enabled is incremental over the build above.
# Only the five in-scope CUI test directories are built; note a bare `make`
# in third_party/wine after this point would build every test module.
echo "== wine: the CUI test modules (the winetest gate) + user32 (the GUI-5 msg gate) =="
if [[ $wineStale -eq 0 && -f third_party/wine/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe &&
      -f third_party/wine/dlls/user32/tests/x86_64-windows/user32_test.exe ]]; then
    echo "   already built — skipping"
else
    (cd third_party/wine &&
        env "${WINE_FT_ENV[@]}" ./configure "${WINE_CONFIGURE[@]}")
    LD_LIBRARY_PATH="$FT_NATIVE${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        make -C third_party/wine -j"$JOBS" \
        dlls/ntdll/tests/all dlls/kernel32/tests/all dlls/msvcrt/tests/all \
        dlls/ucrtbase/tests/all programs/cmd/tests/all dlls/user32/tests/all
fi

echo
echo "setup_linux: done. Next:"
echo "  make test                   # boot the kernel in QEMU, expect the [KTEST] verdict"
echo "  tests/run/run.sh oracle     # run the ntapi suite against the pinned wine"
