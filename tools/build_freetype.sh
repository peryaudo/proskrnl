#!/usr/bin/env bash
#
# build_freetype.sh — the pinned FreeType, cross-built as a PE static library.
#
# GUI-2 needs real glyphs (docs/02: "FreeType statically linked"), and
# win32u's font backend is written against FreeType's C API. There is no
# dynamic loader on the target to hand it a libfreetype.so, so FreeType is
# linked into win32u.dll and reached through a symbol table
# (user/wine/win32u/freetype_link.c).
#
# Built by hand rather than through FreeType's autotools: the file list is
# the one docs/INSTALL.ANY specifies for a manual build, the whole thing is
# one compiler invocation per file with no configure step to drift, and it
# cross-compiles from any host the way the rest of this project does
# (CLAUDE.md "cross-compiles from any host"). No external dependencies are
# enabled -- no zlib, libpng, harfbuzz or brotli -- so nothing else has to be
# cross-built to make it link.
#
# Idempotent: skips the build when the archive is newer than the checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/third_party/freetype"
OUT="$SRC/x86_64-windows"
LIB="$OUT/libfreetype.a"

: "${MINGW:=x86_64-w64-mingw32-gcc}"
: "${MINGW_AR:=x86_64-w64-mingw32-ar}"

[[ -d "$SRC/src" ]] || { echo "build_freetype: $SRC is empty — run git submodule update" >&2; exit 1; }
if [[ -f "$LIB" && "$LIB" -nt "$SRC/include/freetype/freetype.h" ]]; then
    echo "   already built — skipping"
    exit 0
fi

# docs/INSTALL.ANY: the base layer plus every module the default
# include/freetype/config/ftmodule.h enumerates. The list is not trimmed to
# what win32u happens to open, because ftinit.c's FT_DEFAULT_MODULES
# references all of them by name -- a shorter list is a link error, and
# editing ftmodule.h would be a change to the pinned tree. ftsystem.c is the
# ANSI one: stdio and malloc, both of which ucrtbase provides. ftgzip.c
# carries its own zlib, so nothing else has to be cross-built.
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

mkdir -p "$OUT"
rm -f "$LIB"
objects=()
for source in "${SOURCES[@]}"; do
    object="$OUT/$(echo "${source#src/}" | tr / _)"
    object="${object%.c}.o"
    "$MINGW" -c -O2 -g0 -fno-builtin -DFT2_BUILD_LIBRARY \
        -I"$SRC/include" -o "$object" "$SRC/$source"
    objects+=("$object")
done
"$MINGW_AR" rcs "$LIB" "${objects[@]}"
echo "   built $LIB"
