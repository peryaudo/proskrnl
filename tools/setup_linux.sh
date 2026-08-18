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

# The oracle wine is built --with-x (see WINE_CONFIGURE below), and wine's
# configure AUTODETECTS every X extension one header at a time: which of them
# it finds is written into the generated include/config.h, so the set of X
# development packages on the box IS part of the oracle's contract. Naming the
# whole set explicitly — rather than letting whatever a distro image happens
# to preinstall decide — is the same rule --without-fontconfig follows: an
# oracle whose config.h depends on which machine built it is not a spec.
# xvfb is the runtime half: the display every oracle leg runs on
# (tests/run/run.sh start_xvfb), pinned to one geometry.
#
# Each package answers a named configure check in third_party/wine/configure.ac
# ("Check for X cursor", "Check for X input extension", ...); dropping one
# silently turns that extension off in winex11.drv.
#
# What this pins is what the box MUST have, not everything configure could
# find: two X-gated probes stay unpinned and are named here rather than
# claimed away. `xkbregistry` (configure.ac, gated on have_x) decides whether
# winex11's keyboard.c enumerates layouts from the host's xkeyboard-config
# database — pinning it ON would make the oracle's layout list depend on host
# DATA, which is worse than leaving it off, and it IS off here: neither
# ubuntu-24.04's default set nor libgtk-3-dev (installed above) brings
# libxkbregistry-dev, and the built tree answers `#undef
# SONAME_LIBXKBREGISTRY`. The wayland driver probes are the same shape and
# equally off (`#undef HAVE_LIBWAYLAND_EGL`). A box that installs either by
# hand gets a different config.h; if that ever stops being hypothetical, the
# fix is another explicit --without-, the way --without-opengl below was.
X11_PACKAGES=(
    xvfb
    libx11-dev libxext-dev libxrender-dev libxrandr-dev libxinerama-dev
    libxcomposite-dev libxfixes-dev libxcursor-dev libxi-dev libxxf86vm-dev
)

# AUD-2 (docs/23 §6b): the oracle's audio backend. libpulse-dev answers
# configure's pulse probe (--with-pulse below errors out without it — the
# same truthful WINE_ERROR_WITH gate as freetype and X), and pulseaudio is
# the per-leg null-sink daemon tests/run/run.sh start_pulse owns, the audio
# Xvfb. Never a borrowed session daemon.
AUDIO_PACKAGES=(
    pulseaudio libpulse-dev
)

echo "== apt packages =="
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
    clang lld llvm clang-format clang-tidy make git ca-certificates python3 \
    gdisk mtools dosfstools \
    ninja-build meson pkg-config libglib2.0-dev libpixman-1-dev \
    libgtk-3-dev libslirp-dev bzip2 \
    flex bison python3-venv \
    gcc libc6-dev gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 \
    "${X11_PACKAGES[@]}" "${AUDIO_PACKAGES[@]}"

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
# Net-1 needs the slirp backend (-netdev user) for the net legs. The skip
# guard below asks the finished binary itself rather than trusting its
# existence: a tree built before the --enable-slirp flag joined the
# configure (or restored from a pre-slirp cache) satisfies an existence
# check forever — the tp-v2 GTK lesson, .github/actions/third-party — so a
# slirp-less in-tree build is stale and reconfigures in place.
QemuTreeIsStale() {
    [[ -x third_party/qemu/build/qemu-system-x86_64 ]] || return 1
    third_party/qemu/build/qemu-system-x86_64 -netdev help 2>/dev/null |
        grep -qx user && return 1
    return 0
}
if [[ -x third_party/qemu/build/qemu-system-x86_64 ]] && ! QemuTreeIsStale; then
    echo "   already built — skipping"
elif [[ ! -x third_party/qemu/build/qemu-system-x86_64 ]] &&
    command -v qemu-system-x86_64 >/dev/null 2>&1; then
    # No version floor since the kernel's clock moved to the xAPIC MMIO window
    # (arch/x86_64/lapic.c): a distro qemu-system-x86_64 runs the tests, so the
    # long source build is only for hosts that have none. tools/qemu.sh still
    # prefers an in-tree build when one exists. (A distro build almost always
    # carries slirp; the runner's netsmoke check asserts it before any net leg
    # is judged, so a bare one fails loudly there, not silently.)
    echo "   $(qemu-system-x86_64 --version | head -1) on PATH — skipping the source build"
else
    if QemuTreeIsStale; then
        echo "   in-tree build has no slirp (-netdev user) — reconfiguring"
    fi
    mkdir -p third_party/qemu/build
    # --enable-gtk (not autodetect) so `make rungui` deterministically gets a
    # host window; libgtk-3-dev is in the apt list above. The headless test
    # legs never open a display, so nothing else changes.
    # --enable-slirp (not autodetect, docs/24 §6c) so the net legs' user-mode
    # backend deterministically exists: libslirp-dev is in the apt list above,
    # and a box without it must fail HERE, at configure, not later as a
    # false leg verdict.
    (cd third_party/qemu/build &&
        ../configure --target-list=x86_64-softmmu --disable-docs --disable-user \
            --enable-gtk --enable-slirp)
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
# --enable-archs=i386,x86_64 (WOW64 milestone): one 64-bit host build carrying
# BOTH PE arch trees — dlls/*/x86_64-windows/ as before plus dlls/*/i386-windows/,
# the syswow64 payload and the reason wow64.dll has a 32-bit ntdll to load. On an
# x86_64 host a non-empty --enable-archs alone keeps the host build 64-bit
# (configure.ac's -m32 fallback tests `x"$enable_archs" = x`), so --enable-win64
# is subsumed. The i386 PE side needs the i686 mingw cross from the apt list.
#
# --with-x (was --without-x through GUI-6): under the null display driver
# user32 refuses every window ("The graphics driver is missing"), so the
# oracle could not answer a single question about a window — no oracle half
# for user32:msg, none for any tests/ntapi case that would need a desktop,
# and the font-metrics oracle answered from a Wine whose USER half was a
# stub. An oracle that cannot run the code the kernel runs is not a spec, so
# the display driver joins the font backend: winex11.drv against an Xvfb
# display the runner starts (tests/run/run.sh start_xvfb), pinned to one
# geometry and one DPI so it is reproducible on a laptop and on a headless
# CI runner alike. X11_PACKAGES above pins what configure may detect.
#
# --without-opengl is explicit for the same reason --without-fontconfig is:
# configure's OpenGL probe lives INSIDE the X block (configure.ac, "Check for
# the presence of OpenGL"), so enabling X is what first exposes it to host
# variance — a box with libgl-dev would get an oracle with a different
# config.h than one without. No oracle leg draws through GL, and the pinned
# tree answered `#undef SONAME_LIBGL` before this change too, so pinning it
# off keeps the oracle's GL surface exactly where it already was.
# --with-pulse (AUD-2, docs/23 §6b): the oracle's audio backend, bought the
# way fonts and the display were. Explicit rather than autodetect so a box
# without libpulse-dev errors out at configure instead of shipping an oracle
# whose mmdevapi enumerates zero endpoints and turns every audio pair into a
# skip that counts as green.
WINE_CONFIGURE=(--enable-archs=i386,x86_64 --with-x --without-opengl
                --with-freetype --without-fontconfig --with-pulse)

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

# Same trap, one milestone later: a box provisioned before WOW64 carries a
# --enable-win64 (x86_64-only) wine. configure writes the arch list verbatim
# into the generated Makefile's PE_ARCHS, so its lacking i386 is a truthful
# "this tree has no 32-bit PE side" marker — reconfigure such a tree too.
if [[ $wineStale -eq 0 && -f third_party/wine/Makefile ]] &&
    ! grep -q '^PE_ARCHS *=.*i386' third_party/wine/Makefile; then
    wineStale=1
    echo "== wine: pre-WOW64 (x86_64-only) build found — reconfiguring =="
fi

# Third time, same trap: a box provisioned before the X switch above carries a
# --without-x wine, whose USER half refuses every window. configure records
# the X11 client library it will dlopen as SONAME_LIBX11 (and ERRORS OUT when
# X is wanted but missing, WINE_ERROR_WITH(x) in configure.ac), so that define
# is a truthful "this tree has a display driver" marker.
if [[ $wineStale -eq 0 && -f third_party/wine/include/config.h ]] &&
    ! grep -q '^#define SONAME_LIBX11 ' third_party/wine/include/config.h; then
    wineStale=1
    echo "== wine: pre-X (--without-x) build found — reconfiguring =="
fi

# Fourth time, same trap: a box provisioned before AUD-2 carries a
# --without-pulse wine whose mmdevapi enumerates zero endpoints, so every
# audio pair skips and counts as green. configure writes the pulse client
# libraries into the generated Makefile's PULSE_LIBS exactly when the
# backend is on (and errors out when it is wanted but missing), so that
# assignment is a truthful "this tree has an audio backend" marker.
if [[ $wineStale -eq 0 && -f third_party/wine/Makefile ]] &&
    ! grep -q '^PULSE_LIBS *=.*-lpulse' third_party/wine/Makefile; then
    wineStale=1
    echo "== wine: pre-audio (--without-pulse) build found — reconfiguring =="
fi

echo "== wine: the ntapi + font-metrics oracle (x86_64 + i386 PE, X11) =="
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
echo "== wine: the CUI test modules (the winetest gate) + user32 (the GUI-5 msg gate) + audio =="
if [[ $wineStale -eq 0 && -f third_party/wine/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe &&
      -f third_party/wine/dlls/user32/tests/x86_64-windows/user32_test.exe &&
      -f third_party/wine/dlls/mmdevapi/tests/x86_64-windows/mmdevapi_test.exe &&
      -f third_party/wine/dlls/ws2_32/tests/x86_64-windows/ws2_32_test.exe ]]; then
    echo "   already built — skipping"
else
    (cd third_party/wine &&
        env "${WINE_FT_ENV[@]}" ./configure "${WINE_CONFIGURE[@]}")
    LD_LIBRARY_PATH="$FT_NATIVE${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        make -C third_party/wine -j"$JOBS" \
        dlls/ntdll/tests/all dlls/kernel32/tests/all dlls/msvcrt/tests/all \
        dlls/ucrtbase/tests/all programs/cmd/tests/all dlls/user32/tests/all \
        dlls/mmdevapi/tests/all dlls/winmm/tests/all \
        dlls/ws2_32/tests/all
fi

# --- Net-3: the acceptance tool (docs/24 Â§6f) ------------------------------
# An UNMODIFIED off-the-shelf bundled-TLS tool: the pinned curl-for-win
# build (LibreSSL statically linked â the docs/02 scope note: bundled TLS,
# never schannel). Pinned by URL + sha256 the way every third_party
# admission is pinned by a SHA; a hash mismatch is a hard stop, never a
# silently different tool. The run.sh net3 leg REFUSES loudly when the
# tool is absent (the netsmoke lesson).
echo "== net3: the acceptance tool (curl-for-win, bundled LibreSSL) =="
NET3_CURL_URL="https://curl.se/windows/dl-8.21.0_7/curl-8.21.0_7-win64-mingw.zip"
NET3_CURL_SHA256="e469dcdb219d0eca9236b01c7e4bb34fe04af3d4036d350829178dc60f241ae4"
if [[ -f third_party/curlwin/bin/curl.exe ]]; then
    echo "   already present — skipping"
else
    mkdir -p third_party/curlwin
    curl -fsSL -o third_party/curlwin/curlwin.zip "$NET3_CURL_URL"
    echo "$NET3_CURL_SHA256  third_party/curlwin/curlwin.zip" | sha256sum -c - \
        || { echo "setup_linux: curl-for-win sha256 MISMATCH — refusing"; exit 1; }
    unzip -o -q third_party/curlwin/curlwin.zip -d third_party/curlwin
    cp third_party/curlwin/curl-*/bin/curl.exe third_party/curlwin/bin_curl.exe 2>/dev/null || true
    mkdir -p third_party/curlwin/bin
    cp third_party/curlwin/curl-*/bin/curl.exe third_party/curlwin/bin/curl.exe
    cp third_party/curlwin/curl-*/COPYING.txt third_party/curlwin/COPYING.txt
    rm -f third_party/curlwin/curlwin.zip third_party/curlwin/bin_curl.exe
    echo "   installed third_party/curlwin/bin/curl.exe"
fi

echo
echo "setup_linux: done. Next:"
echo "  make test                   # boot the kernel in QEMU, expect the [KTEST] verdict"
echo "  tests/run/run.sh oracle     # run the ntapi suite against the pinned wine"
