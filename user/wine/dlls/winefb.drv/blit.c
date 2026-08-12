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
#include "win32u_private.h"
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
static void repair_uncovered( HWND hwnd, const RECT *old_rect, const RECT *new_rect );

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

/* Pack one 8-bit-per-channel color the way the scanout wants it: one
 * authority for the mask arithmetic, shared with the cursor (cursor.c) and
 * the background fill below. */
UINT winefb_pack_pixel( UINT r, UINT g, UINT b )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;

    return ((r >> (8 - mode->redMaskSize)) << mode->redMaskShift) |
           ((g >> (8 - mode->greenMaskSize)) << mode->greenMaskShift) |
           ((b >> (8 - mode->blueMaskSize)) << mode->blueMaskShift);
}

/* Fill a screen rect with one color, clipped to the scanout. */
void winefb_fill_rect( const RECT *screen_rect, COLORREF color )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    RECT r = *screen_rect;
    UINT pixel;
    int x, y;

    if (!winefb_scanout.pixels) return;
    if (r.left < 0) r.left = 0;
    if (r.top < 0) r.top = 0;
    if (r.right > (int)mode->width) r.right = (int)mode->width;
    if (r.bottom > (int)mode->height) r.bottom = (int)mode->height;
    if (r.right <= r.left || r.bottom <= r.top) return;

    pixel = winefb_pack_pixel( GetRValue( color ), GetGValue( color ), GetBValue( color ) );
    for (y = r.top; y < r.bottom; y++)
    {
        UINT *out = (UINT *)(winefb_scanout.pixels + (size_t)y * mode->pitch) + r.left;

        for (x = 0; x < r.right - r.left; x++) out[x] = pixel;
    }
    winefb_cursor_present();
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

    /* The cursor is above every window, so a writer that just painted the
     * scanout owes the arrow back on top of it (cursor.c). Nothing is
     * coordinated and nothing is saved: the position comes from the
     * server's shared desktop state, which is readable here -- inside the
     * surface lock -- precisely because that read takes no user lock. */
    winefb_cursor_present();

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
    RECT old_rect, empty = { 0, 0, 0, 0 };

    /* A destroyed surface vacates everything it covered: the hide/close
     * analogue of the move repair below (a dying transport during process
     * teardown just fails the server calls, and the repaint is lost with
     * the process -- tolerated, the next mover repairs again). */
    old_rect.left = surface->origin.x;
    old_rect.top = surface->origin.y;
    old_rect.right = surface->origin.x + surface->visible.cx;
    old_rect.bottom = surface->origin.y + surface->visible.cy;
    if (!IsRectEmpty( &old_rect )) repair_uncovered( base->hwnd, &old_rect, &empty );

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

/* Ask one window to repaint the part of itself that `screen_rect` covers.
 *
 * Rect-scoped when the area lies wholly inside the client rect, because
 * the cursor asks for this on every motion (cursor.c) and a whole-window
 * repaint per mouse move is a repaint storm on anything the size of a
 * console. Anything that reaches the frame falls back to the whole window:
 * NtUserRedrawWindow's rect is client-relative and cannot name non-client
 * pixels, and a redundant repaint is cheaper than a wrong one. */
static void invalidate_covered( const struct winefb_toplevel *window, const RECT *screen_rect )
{
    RECT client;

    if (screen_rect->left >= window->client.left && screen_rect->top >= window->client.top &&
        screen_rect->right <= window->client.right && screen_rect->bottom <= window->client.bottom)
    {
        client = *screen_rect;
        OffsetRect( &client, -window->client.left, -window->client.top );
        NtUserRedrawWindow( window->hwnd, &client, 0,
                            RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN );
        return;
    }
    NtUserRedrawWindow( window->hwnd, NULL, 0,
                        RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN );
}

/* Make one screen rect show what it should show again. Every visible
 * top-level it touches is asked to repaint its part (NtUserRedrawWindow ->
 * server redraw_window wakes their queues; their next clipped flush
 * restores the pixels), and the remainder belongs to the desktop, filled
 * here and now: on an explorerless image the desktop window is forced and
 * foreign and this driver is its only painter (docs/03 GUI-2 notes); with
 * explorer (GUI-6) its PaintDesktop would repaint the same
 * COLOR_BACKGROUND blue eventually, and the direct fill just gets there
 * first with the same pixels (winefb.h WINEFB_DESKTOP_BG).
 *
 * The single repaint authority (Art. 11): the mover below vacates the rect
 * a window left, the cursor vacates the rect an arrow left, and a second
 * copy of this walk would drift from the first even while equivalent.
 *
 * Runs OUTSIDE the surface locks: NtUserRedrawWindow re-enters surface
 * code and must never be called from inside a flush. */
void winefb_repaint_rect( const RECT *screen_rect, HWND exclude )
{
    struct winefb_toplevel others[WINEFB_MAX_TOPLEVELS];
    char region_buffer[FIELD_OFFSET( RGNDATA, Buffer[1024 * sizeof(RECT)] )];
    RGNDATA *data = (RGNDATA *)region_buffer;
    HRGN remainder, tmp;
    UINT i, count;
    DWORD size;

    if (IsRectEmpty( screen_rect )) return;

    remainder = NtGdiCreateRectRgn( screen_rect->left, screen_rect->top, screen_rect->right,
                                    screen_rect->bottom );
    tmp = NtGdiCreateRectRgn( 0, 0, 0, 0 );

    count = winefb_other_toplevels( exclude, others, WINEFB_MAX_TOPLEVELS );
    for (i = 0; i < count; i++)
    {
        RECT overlap;

        if (!intersect_rect( &overlap, &others[i].rect, screen_rect )) continue;
        invalidate_covered( &others[i], &overlap );
        NtGdiSetRectRgn( tmp, others[i].rect.left, others[i].rect.top, others[i].rect.right,
                         others[i].rect.bottom );
        NtGdiCombineRgn( remainder, remainder, tmp, RGN_DIFF );
    }
    NtGdiDeleteObjectApp( tmp );

    size = NtGdiGetRegionData( remainder, sizeof(region_buffer), data );
    NtGdiDeleteObjectApp( remainder );
    if (size)
    {
        const RECT *rects = (const RECT *)data->Buffer;

        for (i = 0; i < data->rdh.nCount; i++) winefb_fill_rect( &rects[i], WINEFB_DESKTOP_BG );
    }
}

/* The mover repairs the world. The server neither clips top-level siblings
 * nor exposes them (server/window.c expose_window skips children of the
 * desktop -- that too is "up to the native windowing system"), so when this
 * window stops covering part of the screen, nobody else will notice. What
 * it vacated -- its old rect minus its new one -- is handed band by band to
 * the repaint authority above.
 *
 * Runs OUTSIDE the surface locks (pWindowPosChanged / destroy). */
static void repair_uncovered( HWND hwnd, const RECT *old_rect, const RECT *new_rect )
{
    char region_buffer[FIELD_OFFSET( RGNDATA, Buffer[1024 * sizeof(RECT)] )];
    RGNDATA *data = (RGNDATA *)region_buffer;
    HRGN vacated, tmp;
    DWORD size;
    UINT i;

    vacated = NtGdiCreateRectRgn( old_rect->left, old_rect->top, old_rect->right,
                                  old_rect->bottom );
    tmp = NtGdiCreateRectRgn( new_rect->left, new_rect->top, new_rect->right, new_rect->bottom );
    NtGdiCombineRgn( vacated, vacated, tmp, RGN_DIFF );
    NtGdiDeleteObjectApp( tmp );

    size = NtGdiGetRegionData( vacated, sizeof(region_buffer), data );
    NtGdiDeleteObjectApp( vacated );
    if (size)
    {
        const RECT *rects = (const RECT *)data->Buffer;

        for (i = 0; i < data->rdh.nCount; i++) winefb_repaint_rect( &rects[i], hwnd );
    }
}

void winefb_window_pos_changed( HWND hwnd, HWND insert_after, HWND owner_hint, UINT swp_flags,
                                const struct window_rects *new_rects,
                                struct window_surface *base )
{
    struct winefb_surface *surface = surface_from_header( base );
    RECT old_rect, new_rect;

    if (!surface) return;
    old_rect.left = surface->origin.x;
    old_rect.top = surface->origin.y;
    old_rect.right = surface->origin.x + surface->visible.cx;
    old_rect.bottom = surface->origin.y + surface->visible.cy;
    new_rect = new_rects->visible;

    surface->origin.x = new_rect.left;
    surface->origin.y = new_rect.top;
    surface->visible.cx = new_rect.right - new_rect.left;
    surface->visible.cy = new_rect.bottom - new_rect.top;

    if (!IsRectEmpty( &old_rect ) && !EqualRect( &old_rect, &new_rect ))
        repair_uncovered( hwnd, &old_rect, &new_rect );

    /* Always re-blit the whole surface at its (possibly new) place. A pure
     * move dirties nothing -- the surface is reused (create_window_surface's
     * EqualRect path) and win32u's move_window_bits is an identity no-op for
     * it -- and a raise generates no server exposure, so this forced flush
     * is what paints the window at its new position or above a previously
     * covering sibling. A window-sized copy per SetWindowPos, with no flag
     * decoding to get wrong. */
    window_surface_lock( base );
    base->bounds.left = 0;
    base->bounds.top = 0;
    base->bounds.right = base->rect.right - base->rect.left;
    base->bounds.bottom = base->rect.bottom - base->rect.top;
    window_surface_unlock( base );
    window_surface_flush( base );
}
