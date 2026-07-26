/*
 * blit.c - dibdrv's composed bitmap onto the scanout.
 *
 * win32u asks the driver for a window_surface, hands it to dibdrv as a
 * plain top-down 32bpp DIB, lets every paint compose into it, and then
 * calls flush() with the dirty rectangle. So the whole display path is one
 * copy: no per-primitive driver entry points, no back buffer, no present
 * call - writes to the mapping ARE the picture (HACK-001).
 *
 * Two coordinate systems meet in flush(). The surface's own rect is
 * origin-based and padded out to 128-pixel multiples (dlls/win32u/dce.c,
 * get_surface_rect), so surface (0,0) is the window's visible top-left, not
 * screen (0,0). pWindowPosChanged is where that top-left arrives, and it is
 * the only reason this driver implements it.
 */

#include <stdlib.h>

#include "winefb.h"
#include "ntgdi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

struct winefb_surface
{
    struct window_surface header;
    POINT                 origin;    /* the visible rect's top-left, in screen pixels */
    SIZE                  visible;   /* how much of the padded surface is the window */
    UINT                  flushes;
    RECT                 *clip_rects; /* win32u's surface clip, surface-local; NULL = none */
    UINT                  clip_count;
};

static struct winefb_surface *surface_from_header( struct window_surface *surface );

/* win32u computes the surface region server-side (shaped windows,
 * pixel-format children) and hands it down as a rect array in
 * surface-local coordinates (dlls/win32u/window.c update_surface_region
 * offsets it by -visible.left/top). Stored verbatim; the flush intersects
 * with it. Called with the surface lock held (dce.c), so this only
 * stores. */
static void winefb_surface_set_clip( struct window_surface *surface, const RECT *rects, UINT count )
{
    struct winefb_surface *impl = surface_from_header( surface );

    free( impl->clip_rects );
    impl->clip_rects = NULL;
    impl->clip_count = 0;
    if (!count) return;

    if (!(impl->clip_rects = malloc( count * sizeof(*rects) ))) return;
    memcpy( impl->clip_rects, rects, count * sizeof(*rects) );
    impl->clip_count = count;
}

static void copy_rows( char *dst, int dst_pitch, const char *src, int src_pitch, int width,
                       int height )
{
    int y;

    for (y = 0; y < height; y++)
    {
        memcpy( dst, src, width * 4 );
        dst += dst_pitch;
        src += src_pitch;
    }
}

/* The slow path: the scanout's channel layout is not the DIB's. Same
 * arithmetic as tests/gui/gui_smoke.c's pack_pixel, which is what proved
 * the masks mean what fbproto.h says they mean. */
static void repack_rows( char *dst, int dst_pitch, const char *src, int src_pitch, int width,
                         int height )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    int x, y;

    for (y = 0; y < height; y++)
    {
        const UINT *in = (const UINT *)src;
        UINT *out = (UINT *)dst;

        for (x = 0; x < width; x++)
        {
            UINT pixel = in[x];
            UINT r = (pixel >> 16) & 0xff, g = (pixel >> 8) & 0xff, b = pixel & 0xff;

            out[x] = ((r >> (8 - mode->redMaskSize)) << mode->redMaskShift) |
                     ((g >> (8 - mode->greenMaskSize)) << mode->greenMaskShift) |
                     ((b >> (8 - mode->blueMaskSize)) << mode->blueMaskShift);
        }
        dst += dst_pitch;
        src += src_pitch;
    }
}

/* Blit one surface-local rect (already clipped to the visible part and the
 * scanout) into the scanout. */
static void blit_rect( const struct winefb_surface *surface, const RECT *r, const void *color_bits,
                       int src_pitch )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    int width = r->right - r->left, height = r->bottom - r->top;
    const char *src;
    char *dst;

    if (width <= 0 || height <= 0) return;
    src = (const char *)color_bits + (size_t)r->top * src_pitch + (size_t)r->left * 4;
    dst = winefb_scanout.pixels + (size_t)(surface->origin.y + r->top) * mode->pitch +
          (size_t)(surface->origin.x + r->left) * 4;
    if (winefb_scanout.bgrx) copy_rows( dst, mode->pitch, src, src_pitch, width, height );
    else repack_rows( dst, mode->pitch, src, src_pitch, width, height );
}

static BOOL winefb_surface_flush( struct window_surface *base, const RECT *rect, const RECT *dirty,
                                  const BITMAPINFO *color_info, const void *color_bits,
                                  BOOL shape_changed, const BITMAPINFO *shape_info,
                                  const void *shape_bits )
{
    struct winefb_surface *surface = surface_from_header( base );
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    int src_pitch = color_info->bmiHeader.biSizeImage /
                    abs( color_info->bmiHeader.biHeight );
    RECT clipped = *dirty;
    RECT above[WINEFB_MAX_TOPLEVELS];
    /* 1024 rects (16 KB of stack): far beyond what subtracting ≤ 64
     * rectangles from one can band out to in practice. */
    char region_buffer[FIELD_OFFSET( RGNDATA, Buffer[1024 * sizeof(RECT)] )];
    RGNDATA *data = (RGNDATA *)region_buffer;
    HRGN dirty_rgn, tmp_rgn;
    UINT i, above_count;
    DWORD size;

    /* Clip to the window's visible part (the surface is padded past it) and
     * then to the screen: a window can be positioned partly off either
     * edge, and the mapping has nothing beyond the scanout. */
    if (clipped.right > surface->visible.cx) clipped.right = surface->visible.cx;
    if (clipped.bottom > surface->visible.cy) clipped.bottom = surface->visible.cy;
    if (clipped.left < -surface->origin.x) clipped.left = -surface->origin.x;
    if (clipped.top < -surface->origin.y) clipped.top = -surface->origin.y;
    if (clipped.right > (int)mode->width - surface->origin.x)
        clipped.right = (int)mode->width - surface->origin.x;
    if (clipped.bottom > (int)mode->height - surface->origin.y)
        clipped.bottom = (int)mode->height - surface->origin.y;

    if (clipped.right - clipped.left <= 0 || clipped.bottom - clipped.top <= 0) return TRUE;

    /* The compositor: what actually reaches the scanout is
     * dirty ∧ win32u's surface clip ∧ ¬(anything above in z-order).
     * Region algebra is Wine's own engine (G10) -- these are win32u's
     * NtGdi entry points, and this file is compiled into win32u. */
    dirty_rgn = NtGdiCreateRectRgn( clipped.left, clipped.top, clipped.right, clipped.bottom );
    tmp_rgn = NtGdiCreateRectRgn( 0, 0, 0, 0 );

    if (surface->clip_count)
    {
        HRGN clip_rgn = NtGdiCreateRectRgn( 0, 0, 0, 0 );

        for (i = 0; i < surface->clip_count; i++)
        {
            const RECT *r = &surface->clip_rects[i];

            NtGdiSetRectRgn( tmp_rgn, r->left, r->top, r->right, r->bottom );
            NtGdiCombineRgn( clip_rgn, clip_rgn, tmp_rgn, RGN_OR );
        }
        NtGdiCombineRgn( dirty_rgn, dirty_rgn, clip_rgn, RGN_AND );
        NtGdiDeleteObjectApp( clip_rgn );
    }

    /* Screen rects of the windows above, translated to surface-local. */
    above_count = winefb_windows_above( base->hwnd, above, WINEFB_MAX_TOPLEVELS );
    for (i = 0; i < above_count; i++)
    {
        NtGdiSetRectRgn( tmp_rgn, above[i].left - surface->origin.x,
                         above[i].top - surface->origin.y, above[i].right - surface->origin.x,
                         above[i].bottom - surface->origin.y );
        NtGdiCombineRgn( dirty_rgn, dirty_rgn, tmp_rgn, RGN_DIFF );
    }
    NtGdiDeleteObjectApp( tmp_rgn );

    /* A region built from ≤ 1 dirty ∧ clip and ≤ 64 subtractions cannot
     * exceed the buffer above; 0 from NtGdiGetRegionData would mean it
     * somehow did, and skipping the blit (repaired by the next flush)
     * beats writing through a lying rect list. */
    size = NtGdiGetRegionData( dirty_rgn, sizeof(region_buffer), data );
    NtGdiDeleteObjectApp( dirty_rgn );
    if (size)
    {
        const RECT *rects = (const RECT *)data->Buffer;

        for (i = 0; i < data->rdh.nCount; i++)
            blit_rect( surface, &rects[i], color_bits, src_pitch );
    }

    /* The harness needs one self-describing line naming where a window
     * actually reached the scanout (tests/gui/check_window.py). The first
     * flush is the whole first paint and an idle app never flushes again;
     * the flush=8 line only appears under interaction, as corroboration. */
    surface->flushes++;
    if (surface->flushes == 1 || surface->flushes == 8)
        winefb_report( "[KTEST] gui2 window rect=%d,%d,%dx%d flush=%u\n",
                       (int)surface->origin.x, (int)surface->origin.y, (int)surface->visible.cx,
                       (int)surface->visible.cy, surface->flushes );
    return TRUE;
}

static void winefb_surface_destroy( struct window_surface *base )
{
    struct winefb_surface *surface = surface_from_header( base );

    /* win32u owns the bitmaps; the clip copy is all this driver added. */
    free( surface->clip_rects );
}

static const struct window_surface_funcs winefb_surface_funcs =
{
    winefb_surface_set_clip,
    winefb_surface_flush,
    winefb_surface_destroy,
};

static struct winefb_surface *surface_from_header( struct window_surface *surface )
{
    if (!surface || surface->funcs != &winefb_surface_funcs) return NULL;
    return (struct winefb_surface *)surface;
}

BOOL winefb_create_window_surface( HWND hwnd, BOOL layered, const RECT *surface_rect,
                                   struct window_surface **surface )
{
    struct winefb_surface *previous;
    BITMAPINFO *info;
    char buffer[FIELD_OFFSET( BITMAPINFO, bmiColors[256] )];

    if ((previous = surface_from_header( *surface )) &&
        EqualRect( &previous->header.rect, surface_rect ))
        return TRUE;   /* the existing surface still fits */

    if (*surface) window_surface_release( *surface );
    *surface = NULL;

    info = (BITMAPINFO *)buffer;
    memset( info, 0, sizeof(buffer) );
    info->bmiHeader.biSize = sizeof(info->bmiHeader);
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = 32;
    info->bmiHeader.biCompression = BI_RGB;
    info->bmiHeader.biWidth = surface_rect->right - surface_rect->left;
    /* Negative height: top-down, so a row's address grows with y and the
     * flush is a straight copy rather than a reversed one. */
    info->bmiHeader.biHeight = -(surface_rect->bottom - surface_rect->top);
    info->bmiHeader.biSizeImage = info->bmiHeader.biWidth *
                                  (surface_rect->bottom - surface_rect->top) * 4;

    *surface = window_surface_create( sizeof(struct winefb_surface), &winefb_surface_funcs, hwnd,
                                      surface_rect, info, 0 );

    /* A process creating a window surface is exactly the kind that should
     * try for the input devices: pUpdateDisplayDevices (the GUI-2 start
     * hook) is skipped entirely once the display cache is warm, which left
     * the app under test with no reader at all (docs/03 GUI-4 notes). */
    winefb_start_input();
    return TRUE;
}

void winefb_window_pos_changed( HWND hwnd, HWND insert_after, HWND owner_hint, UINT swp_flags,
                                const struct window_rects *new_rects,
                                struct window_surface *base )
{
    struct winefb_surface *surface = surface_from_header( base );

    if (!surface) return;
    surface->origin.x = new_rects->visible.left;
    surface->origin.y = new_rects->visible.top;
    surface->visible.cx = new_rects->visible.right - new_rects->visible.left;
    surface->visible.cy = new_rects->visible.bottom - new_rects->visible.top;
}
