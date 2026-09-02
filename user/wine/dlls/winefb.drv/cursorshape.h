/*
 * cursorshape.h - the cursor image contract, and the desktop background.
 *
 * Shared between the two kinds of writer that paint the software cursor:
 * winefb.drv (cursor.c draws it at the tail of every flush, blit.c/display.c
 * fill the background) and wineserver-lite's raw-input pump
 * (server/rawinput.c), which draws it and repairs the rect it vacated when
 * the pointer moves on an otherwise idle desktop. One layout, one reader,
 * one blit, one file -- two copies would drift the day someone touches one
 * of them (Art. 11).
 *
 * The SHAPE is the window's real HCURSOR, decoded from Wine's own cursor
 * resources (dlls/user32/resources/ocr_*.cur, baked in user32.dll) by the
 * one process that can read its pixels -- the process that owns the handle
 * (win32u keeps cursor bitmaps per process; dlls/win32u/window.c
 * get_user_handle_ptr answers OBJ_OTHER_PROCESS for anyone else). That
 * process publishes the decoded image to the server (pSetCursor, cursor.c),
 * the server writes it into a section every GUI process maps read-only
 * (transport.h PRSK_SRV_CURSOR), and every writer draws from that one copy.
 * The position stays where it always was: desktop_shm->cursor, the pinned
 * server's own state.
 *
 * The image is opaque-or-transparent, never blended, and that is a rule
 * rather than a shortcut: every writer re-presents the cursor over pixels
 * it did not necessarily repaint (the overlay design cursor.c documents),
 * so a translucent edge would darken again on every present. The cut is
 * the pinned X11 driver's own -- dlls/winex11.drv/mouse.c
 * create_xlib_color_cursor derives its mask from "more than 10% alpha"
 * (alpha > 25); the same threshold, so the shape here is the shape Wine
 * shows on an X server without Xcursor.
 *
 * Requires windef.h/wingdi.h (LONG, RECT, RGB) before inclusion.
 */
#ifndef PRSK_CURSORSHAPE_H
#define PRSK_CURSORSHAPE_H

/* The largest frame a stock cursor carries: the 64x64 entries of
 * dlls/user32/resources/ocr_*.cur (the 32x32 entry is what LR_DEFAULTSIZE
 * selects -- SM_CXCURSOR, dlls/win32u/sysparams.c). A bigger app cursor is
 * refused loudly by the publisher, never truncated. */
#define PRSK_CURSOR_MAX 64

/* The "more than 10% alpha" cut of dlls/winex11.drv/mouse.c
 * create_xlib_color_cursor: alpha above this is opaque, the rest is not
 * drawn. Re-verify there. */
#define PRSK_CURSOR_ALPHA_OPAQUE 25

/* One decoded cursor. `pixels` is row-major, `width` entries per row,
 * 0xAARRGGBB with A either 0 (transparent) or 0xff (opaque). width == 0
 * means nothing to draw -- the hidden cursor (ShowCursor below zero, or a
 * window whose class has no cursor: WM_WINE_SETCURSOR carries handle 0)
 * and the state before any process has published a shape.
 *
 * The server is the ONLY writer (shim.c prsk_cursor_publish, under the
 * server lock); `seq` is its seqlock, odd while a write is in progress --
 * the same protocol the pinned server uses for its own shared objects
 * (server/file.h SHARED_WRITE_BEGIN, dlls/win32u/winstation.c
 * shared_object_acquire_seqlock), spelled here because the pump has no
 * win32u. `generation` counts accepted publishes, so a writer can tell a
 * shape change from a move. */
struct prsk_cursor_image
{
    volatile LONG seq;
    LONG          generation;
    unsigned int  width, height;
    int           hot_x, hot_y;
    unsigned int  pixels[PRSK_CURSOR_MAX * PRSK_CURSOR_MAX];
};

/* What a publisher hands the server (transport.h PRSK_OP_SET_CURSOR).
 * `hwnd` is the server user handle of the cursor window the shape belongs
 * to -- the window WM_WINE_SETCURSOR named -- and the server refuses a
 * publish for a window the pointer has since left (shim.c), so a slow
 * process cannot overwrite the shape a faster one published for the
 * window under the pointer now. PRSK_CURSOR_PUBLISH_DESKTOP marks the
 * desktop's own arrow (display.c), the shape the pump falls back to while
 * the cursor is over a window no thread owns (the explorerless fixture's
 * forced desktop, docs/03 "GUI-2 notes"); it carries no window. The
 * image's seq/generation are the server's and ignored on the way in. */
#define PRSK_CURSOR_PUBLISH_DESKTOP 0x1
struct prsk_cursor_publish
{
    unsigned int             hwnd;
    unsigned int             flags;
    struct prsk_cursor_image image;
};

/* A consistent copy of the published image, for ANY reader: spin while a
 * write is in progress, copy, and retry if a write began meanwhile. Takes
 * no lock, so it is legal inside a surface flush (compose.c's rule). The
 * spin is bounded: the server's death is the session's, but a reader
 * inside a flush must never park on it -- after the bound it reports
 * nothing to draw. */
static inline BOOL prsk_cursor_read( const volatile struct prsk_cursor_image *shared,
                                     struct prsk_cursor_image *out )
{
    unsigned int spins = 0;
    LONG before, after;

    if (!shared) return FALSE;
    for (;;)
    {
        before = __atomic_load_n( &shared->seq, __ATOMIC_ACQUIRE );
        if (!(before & 1))
        {
            out->generation = shared->generation;
            out->width = shared->width;
            out->height = shared->height;
            out->hot_x = shared->hot_x;
            out->hot_y = shared->hot_y;
            if (out->width > PRSK_CURSOR_MAX || out->height > PRSK_CURSOR_MAX)
                out->width = out->height = 0;
            else
            {
                unsigned int i, count = out->width * out->height;

                for (i = 0; i < count; i++) out->pixels[i] = shared->pixels[i];
            }
            __atomic_thread_fence( __ATOMIC_ACQUIRE );
            after = __atomic_load_n( &shared->seq, __ATOMIC_ACQUIRE );
            if (after == before)
            {
                out->seq = after;
                return TRUE;
            }
        }
        if (++spins > (1u << 22))
        {
            out->width = out->height = 0;
            return FALSE;
        }
        YieldProcessor();
    }
}

/* The screen rect the image covers when the pointer is at (x,y): the
 * hotspot sits on the pointer, so the image starts above and to the left
 * of it. Unclipped; empty for an empty image. */
static inline void prsk_cursor_rect( const struct prsk_cursor_image *img, int x, int y, RECT *out )
{
    out->left = x - img->hot_x;
    out->top = y - img->hot_y;
    out->right = out->left + (int)img->width;
    out->bottom = out->top + (int)img->height;
}

/* Draw the image's opaque pixels with the hotspot at (x,y) into a 32bpp
 * scanout of `width` x `height` pixels and `pitch` bytes per row, clipped
 * at all four edges. `pack` is the caller's channel packer (blit.c
 * winefb_pack_pixel, rawinput.c pack_pixel): one authority each side for
 * the mask arithmetic, the image itself stays 0xAARRGGBB. */
static inline void prsk_cursor_blit( const struct prsk_cursor_image *img, int x, int y,
                                     char *pixels, unsigned int pitch, unsigned int width,
                                     unsigned int height, UINT (*pack)( UINT, UINT, UINT ) )
{
    int left = x - img->hot_x, top = y - img->hot_y;
    int col0 = left < 0 ? -left : 0, row0 = top < 0 ? -top : 0;
    int col1 = (int)img->width, row1 = (int)img->height;
    int row, col;

    if (!pixels || !img->width || !img->height) return;
    if (col1 > (int)width - left) col1 = (int)width - left;
    if (row1 > (int)height - top) row1 = (int)height - top;
    for (row = row0; row < row1; row++)
    {
        UINT *out = (UINT *)(pixels + (size_t)(top + row) * pitch) + left;
        const unsigned int *in = img->pixels + (size_t)row * img->width;

        for (col = col0; col < col1; col++)
        {
            unsigned int argb = in[col];

            if (argb >> 24)
                out[col] = pack( (argb >> 16) & 0xff, (argb >> 8) & 0xff, argb & 0xff );
        }
    }
}

/* The desktop wallpaper color every repaint-remainder is filled with:
 * COLOR_BACKGROUND, RGB(58,110,165) -- re-verify against the pinned
 * dlls/win32u/sysparams.c system_colors[]. Reported on serial, never
 * assumed by a checker. */
#define WINEFB_DESKTOP_BG RGB( 0x3a, 0x6e, 0xa5 ) /* the classic desktop blue */

#endif /* PRSK_CURSORSHAPE_H */
