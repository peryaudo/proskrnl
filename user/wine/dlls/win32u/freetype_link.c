/*
 * freetype_link.c - hands win32u's font backend a statically linked FreeType.
 *
 * dlls/win32u/freetype.c is written against a FreeType it dlopen()s: one
 * handle, then ~60 LOAD_FUNCPTR lookups by name. There is no dynamic loader
 * here to satisfy that, but there IS a FreeType - third_party/freetype,
 * cross-built as a PE static library by tools/setup_linux.sh and linked into
 * win32u.dll. So rather than teach freetype.c a second way to find its entry
 * points (which would mean patching Wine - Art. 10 says no), the loader it
 * already uses is answered from a table: prsk_dlopen returns a cookie for
 * the one soname it knows, and prsk_dlsym resolves against the linked-in
 * symbols.
 *
 * The table is generated (tools/gen_freetype_syms.py) from the names
 * freetype.c actually asks for, so a Wine pin that starts using a new
 * FreeType entry point fails the build instead of failing at run time with a
 * NULL function pointer.
 */

#include <string.h>

#include "config.h"

#ifdef SONAME_LIBFREETYPE

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H
#include FT_TYPES_H
#include FT_TRUETYPE_TABLES_H
#include FT_SFNT_NAMES_H
#include FT_TRUETYPE_IDS_H
#include FT_OUTLINE_H
#include FT_TRIGONOMETRY_H
#include FT_MODULE_H
#include FT_WINFONTS_H
#include FT_LCD_FILTER_H

#include "prsk_freetype_syms.h"

/* Any non-NULL value distinguishable from a real pointer would do; this one
 * reads back in a log. */
static char freetype_cookie[] = "prsk:libfreetype";

void *prsk_freetype_handle( const char *name )
{
    if (name && !strcmp( name, SONAME_LIBFREETYPE )) return freetype_cookie;
    return NULL;
}

void *prsk_freetype_symbol( void *handle, const char *symbol )
{
    unsigned int i;

    if (handle != freetype_cookie) return NULL;
    for (i = 0; i < prsk_freetype_sym_count; i++)
        if (!strcmp( prsk_freetype_syms[i].name, symbol )) return prsk_freetype_syms[i].address;
    return NULL;
}

#else /* SONAME_LIBFREETYPE */

void *prsk_freetype_handle( const char *name )
{
    return NULL;
}

void *prsk_freetype_symbol( void *handle, const char *symbol )
{
    return NULL;
}

#endif /* SONAME_LIBFREETYPE */
