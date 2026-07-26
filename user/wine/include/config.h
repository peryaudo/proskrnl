/*
 * config.h - shadows the pinned tree's, to turn win32u's font backend on.
 *
 * Found before third_party/wine/include because -Iuser/wine/include comes
 * first; the real header is pulled in unchanged through #include_next, so
 * this adds to it rather than forking it.
 *
 * The pinned Wine is configured --without-freetype and --without-x
 * (tools/setup_linux.sh), which is right for its three roles -- oracle,
 * shipped PE userland, dormancy check -- and must not change: the oracle is
 * the spec (docs/06), and reconfiguring it would move the spec to make a
 * proskrnl build easier, which is the one thing Art. 6 forbids.
 *
 * But GUI-2's win32u is a different build of the same sources, and it DOES
 * have FreeType: third_party/freetype, cross-built as a PE static library
 * (tools/build_freetype.sh) and linked in. So the two defines that gate
 * dlls/win32u/freetype.c's real body are set here, for this build only.
 *
 * fontconfig is deliberately NOT enabled. It is a font-discovery service
 * for unix desktops; with SONAME_LIBFONTCONFIG undefined, freetype.c falls
 * back to scanning the fonts directory, which is where the gui2 image bakes
 * Wine's own font files.
 */
#ifndef PRSK_CONFIG_H
#define PRSK_CONFIG_H

#include_next <config.h>

#ifdef PRSK_WITH_FREETYPE

#undef HAVE_FT2BUILD_H
#define HAVE_FT2BUILD_H 1

/* The name freetype.c passes to dlopen(). There is no shared object behind
 * it -- prsk_dlopen answers for exactly this string and prsk_dlsym resolves
 * against the linked-in library (user/wine/win32u/freetype_link.c) -- but it
 * still has to be the spelling both sides agree on. */
#undef SONAME_LIBFREETYPE
#define SONAME_LIBFREETYPE "libfreetype.so.6"

#endif /* PRSK_WITH_FREETYPE */

#endif /* PRSK_CONFIG_H */
