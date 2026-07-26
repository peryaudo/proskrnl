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

#include "winefb.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

struct winefb_surface
{
    struct window_surface header;
    POINT                 origin;    /* the visible rect's top-left, in screen pixels */
    SIZE                  visible;   /* how much of the padded surface is the window */
    UINT                  flushes;
};

static struct winefb_surface *surface_from_header( struct window_surface *surface );

static void winefb_surface_set_clip( struct window_surface *surface, const RECT *rects, UINT count )
{
    /* One app window over a static desktop: whatever the clip says, the
     * last flush wins and is correct. Z-order-aware flushing arrives with
     * the compositor (GUI-4); until there are two windows to order there is
     * nothing here to get wrong. */
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
    const char *src;
    char *dst;
    int width, height;

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

    width = clipped.right - clipped.left;
    height = clipped.bottom - clipped.top;
    if (width <= 0 || height <= 0) return TRUE;

    src = (const char *)color_bits + (size_t)clipped.top * src_pitch + (size_t)clipped.left * 4;
    dst = winefb_scanout.pixels + (size_t)(surface->origin.y + clipped.top) * mode->pitch +
          (size_t)(surface->origin.x + clipped.left) * 4;

    if (winefb_scanout.bgrx) copy_rows( dst, mode->pitch, src, src_pitch, width, height );
    else repack_rows( dst, mode->pitch, src, src_pitch, width, height );

    /* The harness needs one self-describing line naming where a window
     * actually reached the scanout; the second, later one gives it a
     * settled frame to screendump instead of the first blank fill
     * (tests/gui/check_window.py). */
    surface->flushes++;
    if (surface->flushes == 1 || surface->flushes == 8)
        winefb_report( "[KTEST] gui2 window rect=%d,%d,%dx%d flush=%u\n",
                       (int)surface->origin.x, (int)surface->origin.y, (int)surface->visible.cx,
                       (int)surface->visible.cy, surface->flushes );
    return TRUE;
}

static void winefb_surface_destroy( struct window_surface *base )
{
    /* win32u owns the bitmaps; the header is all this driver added. */
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
