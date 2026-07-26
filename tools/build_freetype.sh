#!/usr/bin/env bash
#
# build_freetype.sh — the pinned FreeType, built twice from one file list:
# once cross-compiled as a PE static library, once native as a host shared
# library. Both consumers must be the SAME FreeType, which is the whole
# reason one script owns both.
#
#   x86_64-windows/libfreetype.a    win32u.dll's font backend on the target.
#                                   GUI-2 needs real glyphs (docs/02:
#                                   "FreeType statically linked"), and there
#                                   is no dynamic loader on the target to
#                                   hand win32u a libfreetype.so, so FreeType
#                                   is linked into win32u.dll and reached
#                                   through a symbol table
#                                   (user/wine/win32u/freetype_link.c).
#
#   x86_64-linux/libfreetype.so.6   the ORACLE wine's font backend (GUI-3).
#                                   third_party/wine is configured
#                                   --with-freetype against THIS library, not
#                                   the distro's, so the oracle's font
#                                   metrics come from the same FreeType code
#                                   the PE static library above is built
#                                   from. That identity is what makes
#                                   docs/07's "same FreeType + same fonts =>
#                                   same numbers" a fact rather than a plan;
#                                   a distro libfreetype would reintroduce
#                                   the version skew the oracle exists to
#                                   remove. See tools/setup_linux.sh.
#
# Built by hand rather than through FreeType's autotools: the file list is
# the one docs/INSTALL.ANY specifies for a manual build, the whole thing is
# one compiler invocation per file with no configure step to drift, and it
# cross-compiles from any host the way the rest of this project does
# (CLAUDE.md "cross-compiles from any host"). No external dependencies are
# enabled -- no zlib, libpng, harfbuzz or brotli -- so nothing else has to be
# built to make either output link.
#
# Idempotent per output: skips a build when its artifact is newer than the
# checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/freetype"
PE_OUT="$SRC/x86_64-windows"
PE_LIB="$PE_OUT/libfreetype.a"
HOST_OUT="$SRC/x86_64-linux"
HOST_LIB="$HOST_OUT/libfreetype.so.6"

: "${MINGW:=x86_64-w64-mingw32-gcc}"
: "${MINGW_AR:=x86_64-w64-mingw32-ar}"
: "${HOSTCC:=gcc}"

[[ -d "$SRC/src" ]] || { echo "build_freetype: $SRC is empty — run git submodule update" >&2; exit 1; }

# docs/INSTALL.ANY: the base layer plus every module the default
# include/freetype/config/ftmodule.h enumerates. The list is not trimmed to
# what win32u happens to open, because ftinit.c's FT_DEFAULT_MODULES
# references all of them by name -- a shorter list is a link error, and
# editing ftmodule.h would be a change to the pinned tree. ftsystem.c is the
# ANSI one: stdio and malloc, which ucrtbase provides on the PE side and
# glibc on the host side. ftgzip.c carries its own zlib, so nothing else has
# to be built. Both outputs compile this same list -- the two backends
# differ in nothing but their target.
SOURCES=(
    src/base/ftsystem.c src/base/ftinit.c src/base/ftdebug.c src/base/ftbase.c
    src/base/ftbbox.c src/base/ftbitmap.c src/base/ftglyph.c src/base/ftmm.c
    src/base/ftwinfnt.c src/base/fttype1.c src/base/ftfstype.c src/base/ftgasp.c
    src/base/ftpatent.c src/base/ftsynth.c src/base/ftstroke.c
    src/sfnt/sfnt.c src/truetype/truetype.c src/cff/cff.c
    src/type1/type1.c src/cid/type1cid.c src/type42/type42.c
    src/winfonts/winfnt.c src/pcf/pcf.c src/bdf/bdf.c src/pfr/pfr.c
    src/smooth/smooth.c src/raster/raster.c src/sdf/sdf.c src/svg/svg.c
    src/autofit/autofit.c src/psaux/psaux.c src/pshinter/pshinter.c src/psnames/psnames.c
    src/gzip/ftgzip.c src/lzw/ftlzw.c
)

# The object name a source compiles to inside an output directory:
# src/base/ftinit.c -> <out>/base_ftinit.o (flat, so the two trees can share
# one naming rule without mirroring src/'s directory layout).
ObjectFor() {
    local out="$1" source="$2" object
    object="$out/$(echo "${source#src/}" | tr / _)"
    echo "${object%.c}.o"
}

echo "== freetype: PE static library (win32u's font backend) =="
if [[ -f "$PE_LIB" && "$PE_LIB" -nt "$SRC/include/freetype/freetype.h" ]]; then
    echo "   already built — skipping"
else
    mkdir -p "$PE_OUT"
    rm -f "$PE_LIB"
    peObjects=()
    for source in "${SOURCES[@]}"; do
        object="$(ObjectFor "$PE_OUT" "$source")"
        "$MINGW" -c -O2 -g0 -fno-builtin -DFT2_BUILD_LIBRARY \
            -I"$SRC/include" -o "$object" "$SRC/$source"
        peObjects+=("$object")
    done
    "$MINGW_AR" rcs "$PE_LIB" "${peObjects[@]}"
    echo "   built $PE_LIB"
fi

# The soname is load-bearing, not decoration. Wine's configure records the
# font backend it will dlopen at runtime by linking a conftest and reading
# the NEEDED entry back out with readelf (WINE_CHECK_SONAME,
# third_party/wine/aclocal.m4), and stores it as SONAME_LIBFREETYPE in the
# generated include/config.h. Setting it explicitly to the bare
# "libfreetype.so.6" keeps that string free of any absolute path, so a wine
# tree restored onto a different checkout path (tools/fetch_third_party.sh)
# still resolves -- via LD_LIBRARY_PATH, which tests/run/run.sh exports.
# The unversioned symlink is what -lfreetype resolves at configure- and
# sfnt2fon-link time.
echo "== freetype: native shared library (the oracle wine's font backend) =="
if [[ -f "$HOST_LIB" && "$HOST_LIB" -nt "$SRC/include/freetype/freetype.h" ]]; then
    echo "   already built — skipping"
else
    mkdir -p "$HOST_OUT"
    rm -f "$HOST_LIB" "$HOST_OUT/libfreetype.so"
    hostObjects=()
    for source in "${SOURCES[@]}"; do
        object="$(ObjectFor "$HOST_OUT" "$source")"
        "$HOSTCC" -c -O2 -g0 -fPIC -fno-builtin -DFT2_BUILD_LIBRARY \
            -I"$SRC/include" -o "$object" "$SRC/$source"
        hostObjects+=("$object")
    done
    "$HOSTCC" -shared -Wl,-soname,libfreetype.so.6 -o "$HOST_LIB" "${hostObjects[@]}"
    ln -sfn libfreetype.so.6 "$HOST_OUT/libfreetype.so"
    echo "   built $HOST_LIB"
fi
