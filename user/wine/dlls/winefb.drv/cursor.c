/*
 * cursor.c - the software cursor (GUI-4; composited GUI-5; shaped since
 * the window's HCURSOR replaced the builtin arrow).
 *
 * There is no hardware cursor plane: the scanout is the VBE linear
 * framebuffer and nothing else (HACK-001), so the cursor is pixels this
 * driver draws itself. GUI-1..3 left this file empty because a cursor with
 * no mouse would have been a fixed picture of a lie; the mouse arrived
 * (\Device\Input1), so the position is now real.
 *
 * It is drawn as an OVERLAY, not with a save-under, and that is the whole
 * design. The scanout has one writer per process and every GUI process
 * blits into it, so a save-under is a private cache of shared pixels: the
 * snapshot a save takes goes stale the moment another process flushes over
 * it, and restoring it deposits pixels captured somewhere else (that
 * artifact was real, documented, and worked around in the gui4 clients
 * until this file stopped taking snapshots). Instead:
 *
 *   - every writer that touches the scanout draws the cursor back on top
 *     of what it just painted (winefb_cursor_present, called at the tail
 *     of the surface flush and the background fill in blit.c). The cursor
 *     is above everything, so this is always the right answer, and no
 *     writer has to know a cursor was there;
 *   - when the pointer moves, the rect it left is repainted from whoever
 *     OWNS those pixels rather than from a snapshot, so nothing is ever
 *     restored and nothing can be stale. The MOVER is not this process:
 *     wineserver-lite's raw-input pump (server/rawinput.c) owns the
 *     devices, moves the cursor and repairs the vacated rect. This file
 *     only ever draws the cursor where the server says it is.
 *
 * Position comes from the server, which owns it: desktop_shm->cursor is
 * published in the desktop's shared memory and read here through the same
 * seqlock NtUserGetCursorPos uses. That is what makes the overlay legal
 * inside a flush -- it takes no user lock (compose.c documents the
 * lock-order wedge a blocking NtUser* call there caused), and it is why
 * the design needs no cross-process protocol of its own: every process
 * reads the one authority.
 *
 * The SHAPE is the window's real HCURSOR, and it reaches the writers the
 * same way the position does: through one copy every process reads. The
 * pinned server posts WM_WINE_SETCURSOR to the process owning the window
 * under the pointer (dlls/win32u/cursoricon.c process_wine_setcursor ->
 * pSetCursor, below), and that process is the ONLY one that can turn the
 * handle into pixels -- win32u keeps cursor bitmaps per process
 * (dlls/win32u/window.c get_user_handle_ptr answers OBJ_OTHER_PROCESS for
 * anyone else), which is why winex11 decodes in-process too. So
 * pSetCursor decodes here, from the message pump where the user lock is
 * free to take, and publishes the image to wineserver-lite
 * (PRSK_OP_SET_CURSOR); the server copies it into a section every writer
 * maps read-only (cursorshape.h has the layout and the reading rule), and
 * winefb_cursor_present draws whatever is there, lock-free, exactly as it
 * reads the position. The pixels are Wine's own cursor resources
 * (dlls/user32/resources/ocr_*.cur through user32's LoadCursor), decoded
 * the way the pinned X11 and Wayland drivers decode them.
 * pGetCursorPos/pSetCursorPos/pClipCursor stay nulldrv: the server owns
 * cursor position and clip state, and this driver only ever ASKS for
 * them, never answers.
 *
 * Residual, named: the vacated rect over a window is repaired by that
 * window's own repaint, so a window whose thread is wedged keeps the trail
 * until it pumps again. Same latency class the mover already accepts for
 * an uncovered window, and it degrades to briefly-stale rather than
 * permanently-wrong.
 */

#include <stdlib.h>

#include "winefb.h"
#include "ntgdi.h"
#include "win32u_private.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* wineserver-lite/client/call.c: the published image (read-only view of
 * the server's section) and the op that publishes one. */
extern const volatile struct prsk_cursor_image *prsk_client_cursor_image(void);
extern unsigned int prsk_client_publish_cursor( const struct prsk_cursor_publish *publish );

/* Where the cursor is, for ANY process. The server owns the position and
 * publishes it in the desktop's shared memory; this is the seqlock read
 * NtUserGetCursorPos does (dlls/win32u/input.c), which takes no user lock
 * and at most one raw server request per thread -- the rule compose.c
 * established for code that runs inside a surface flush.
 *
 * No "is there a pointer device" flag, on purpose: the only mover is the
 * server's pump (this process never opens \Device\Input1), so on a
 * keyboard-only image the published position simply never leaves the
 * desktop's initial (0,0) -- and the (0,0) test below already refuses to
 * draw there. A cursor parked at (0,0) on the gui5 BOOT would be exactly
 * the fixed picture of a lie this file refused to draw before the mouse
 * existed; absence needs no signal beyond the position itself. */
static BOOL cursor_position( POINT *pt )
{
    struct object_lock lock = OBJECT_LOCK_INIT;
    const desktop_shm_t *desktop_shm;
    NTSTATUS status;

    while ((status = get_shared_desktop( &lock, &desktop_shm )) == STATUS_PENDING)
    {
        pt->x = desktop_shm->cursor.x;
        pt->y = desktop_shm->cursor.y;
    }
    if (status) return FALSE;

    /* (0,0) is the desktop's initial cursor position (server/winstation.c
     * zeroes it), so it cannot be told apart from "the pointer has never
     * reported one" -- and is therefore treated as no position yet. An
     * image must not paint a cursor in its top-left corner before the mouse
     * has moved: the gui4 dumps check that corner for the desktop
     * background, and gui5con LOCATES its console window as the bounding
     * box of everything that is not background, which a corner cursor would
     * stretch to the screen edge for any window not already touching the
     * origin.
     *
     * cursor.last_change is the field that looks like the "has it ever
     * moved" flag and is not one: the server stamps it from the ordinary
     * motion path whenever it resyncs the cursor, which a visible window
     * changing rect does (server/window.c set_window_pos ->
     * update_cursor_pos -> set_cursor_pos), as does releasing capture
     * (server/queue.c). Every tablet-equipped image trips that during
     * startup, while the position is still (0,0).
     *
     * The cost of the position test is that a pointer parked at exactly
     * (0,0) draws no cursor until it moves again: bounded, cosmetic,
     * self-correcting, and it fails to no cursor rather than to a cursor
     * where the pointer has never been. */
    return pt->x != 0 || pt->y != 0;
}

/* Draw the published image at the position the server publishes. Called
 * at the tail of every write to the scanout, in every process: whoever
 * just painted owes the topmost picture back, and drawing it
 * unconditionally is both idempotent (the image is opaque-or-transparent,
 * cursorshape.h) and free of any protocol -- there is nothing to
 * coordinate when the only state is "where does the server say the cursor
 * is" and "what does the server say it looks like". */
void winefb_cursor_present(void)
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    struct prsk_cursor_image image;
    POINT pt;

    const volatile struct prsk_cursor_image *shared = prsk_client_cursor_image();
    static LONG stalled_said;

    if (!winefb_scanout.pixels) return;
    if (!cursor_position( &pt )) return;
    if (!prsk_cursor_read( shared, &image ))
    {
        /* The reader's spin bound fired: the server stopped mid-write. Named
         * once (Art. 12) -- this runs inside a flush, so it must neither
         * park nor repeat itself per flush. */
        if (shared && !InterlockedExchange( &stalled_said, 1 ))
            winefb_report( "[KTEST] gui4 cursor read STALLED (the server's write never finished)\n" );
        return;
    }
    if (!image.width) return;
    prsk_cursor_blit( &image, pt.x, pt.y, winefb_scanout.pixels, mode->pitch, mode->width,
                      mode->height, winefb_pack_pixel );
}

/* --- HCURSOR -> image ------------------------------------------------------
 *
 * The two shapes a cursor comes in, decoded the way the pinned drivers
 * decode them (they are the reference, not a description of the format):
 *
 *   - monochrome (no color bitmap): the mask bitmap is DOUBLE height, the
 *     AND plane over the XOR plane (dlls/win32u/cursoricon.c
 *     NtUserGetIconSize reports height * 2 for the same reason). The
 *     AND/XOR truth table and the WORD-aligned GetBitmapBits stride are
 *     dlls/winewayland.drv/wayland_pointer.c create_mono_cursor_buffer's;
 *     "invert" pixels, which no framebuffer can show, are drawn black there
 *     and here;
 *   - color: a 32bpp top-down DIB of the color bitmap, with the alpha
 *     channel if the cursor has one (the "more than 10% alpha" cut,
 *     cursorshape.h PRSK_CURSOR_ALPHA_OPAQUE) and the 1bpp AND mask
 *     otherwise -- dlls/winex11.drv/mouse.c create_xlib_color_cursor. */

static BOOL decode_mono( HBITMAP mask, const BITMAP *bm, struct prsk_cursor_image *out )
{
    unsigned int stride = ((bm->bmWidth + 15) >> 3) & ~1;   /* GetBitmapBits: WORD-aligned rows */
    unsigned int height = bm->bmHeight / 2;
    unsigned int x, y;
    unsigned char *bits;

    if (!(bits = malloc( stride * bm->bmHeight ))) return FALSE;
    if (!NtGdiGetBitmapBits( mask, stride * bm->bmHeight, bits ))
    {
        free( bits );
        return FALSE;
    }
    out->width = bm->bmWidth;
    out->height = height;
    for (y = 0; y < height; y++)
    {
        for (x = 0; x < out->width; x++)
        {
            int and = (bits[y * stride + x / 8] << (x % 8)) & 0x80;
            int xor = (bits[(y + height) * stride + x / 8] << (x % 8)) & 0x80;
            unsigned int *pixel = &out->pixels[y * out->width + x];

            if (!xor && and) *pixel = 0;                 /* screen */
            else if (xor && !and) *pixel = 0xffffffff;   /* white */
            else *pixel = 0xff000000;                    /* black, and "invert" */
        }
    }
    free( bits );
    return TRUE;
}

static BOOL decode_color( HDC hdc, HBITMAP color, HBITMAP mask, const BITMAP *bm,
                          struct prsk_cursor_image *out )
{
    char info_buffer[FIELD_OFFSET( BITMAPINFO, bmiColors[256] )];
    BITMAPINFO *info = (BITMAPINFO *)info_buffer;
    unsigned int width = bm->bmWidth, height = bm->bmHeight;
    unsigned int i, x, y, stride;
    unsigned char *mask_bits;
    BOOL has_alpha = FALSE;

    memset( info_buffer, 0, sizeof(info_buffer) );
    info->bmiHeader.biSize = sizeof(info->bmiHeader);
    info->bmiHeader.biWidth = width;
    info->bmiHeader.biHeight = -(int)height;   /* top-down, the image's own row order */
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = 32;
    info->bmiHeader.biCompression = BI_RGB;
    info->bmiHeader.biSizeImage = width * height * 4;
    if (!NtGdiGetDIBitsInternal( hdc, color, 0, height, out->pixels, info, DIB_RGB_COLORS,
                                 width * height * 4, sizeof(info_buffer) ))
        return FALSE;
    out->width = width;
    out->height = height;

    for (i = 0; i < width * height; i++)
        if ((has_alpha = (out->pixels[i] & 0xff000000) != 0)) break;

    if (has_alpha)
    {
        for (i = 0; i < width * height; i++)
        {
            if ((out->pixels[i] >> 24) > PRSK_CURSOR_ALPHA_OPAQUE) out->pixels[i] |= 0xff000000;
            else out->pixels[i] = 0;
        }
        return TRUE;
    }

    /* No alpha: the AND mask says what is transparent (bit set). */
    stride = ((width + 31) / 32) * 4;   /* 1bpp DIB rows are DWORD-aligned */
    if (!(mask_bits = malloc( stride * height ))) return FALSE;
    info->bmiHeader.biBitCount = 1;
    info->bmiHeader.biSizeImage = stride * height;
    if (!NtGdiGetDIBitsInternal( hdc, mask, 0, height, mask_bits, info, DIB_RGB_COLORS,
                                 stride * height, sizeof(info_buffer) ))
    {
        free( mask_bits );
        return FALSE;
    }
    for (y = 0; y < height; y++)
    {
        for (x = 0; x < width; x++)
        {
            unsigned int *pixel = &out->pixels[y * width + x];

            if (mask_bits[y * stride + x / 8] & (0x80 >> (x % 8))) *pixel = 0;
            else *pixel |= 0xff000000;
        }
    }
    free( mask_bits );
    return TRUE;
}

/* Decode this process's HCURSOR into `out`; `res_id` is the OCR_* resource
 * id for a stock cursor (include/winuser.rh), 0 otherwise -- for the
 * serial line only, the shape itself never depends on it. FALSE for a
 * handle this process cannot read or a frame past PRSK_CURSOR_MAX. */
static BOOL decode_cursor( HCURSOR handle, struct prsk_cursor_image *out, unsigned int *res_id )
{
    UNICODE_STRING module, res_name;
    WCHAR module_buf[64];
    ICONINFO info;
    BITMAP bm;
    HDC hdc;
    unsigned int height;
    BOOL ret = FALSE;

    module.Buffer = module_buf;
    module.Length = 0;
    module.MaximumLength = sizeof(module_buf) - sizeof(WCHAR);
    res_name.Buffer = NULL;
    res_name.Length = 0;
    res_name.MaximumLength = 0;
    /* The bitmaps come back as COPIES this caller owns
     * (dlls/win32u/cursoricon.c NtUserGetIconInfo). */
    if (!NtUserGetIconInfo( handle, &info, &module, &res_name, NULL, 0 )) return FALSE;
    *res_id = res_name.Length ? 0 : LOWORD( (ULONG_PTR)res_name.Buffer );

    if (!NtGdiExtGetObjectW( info.hbmMask, sizeof(bm), &bm )) goto done;
    height = info.hbmColor ? bm.bmHeight : bm.bmHeight / 2;
    if (bm.bmWidth < 1 || height < 1 || bm.bmWidth > PRSK_CURSOR_MAX || height > PRSK_CURSOR_MAX)
    {
        /* Bigger than the contract carries: refused by name, never
         * truncated (Art. 12). */
        winefb_report( "[KTEST] gui4 cursor %p REFUSED %dx%u exceeds %d\n", handle, (int)bm.bmWidth,
                       height, PRSK_CURSOR_MAX );
        goto done;
    }

    if (!(hdc = NtGdiCreateCompatibleDC( 0 ))) goto done;
    if (info.hbmColor) ret = decode_color( hdc, info.hbmColor, info.hbmMask, &bm, out );
    else ret = decode_mono( info.hbmMask, &bm, out );
    NtGdiDeleteObjectApp( hdc );

    /* An out-of-range hotspot is centred, as winex11 mouse.c create_cursor
     * and winewayland wayland_pointer.c do. */
    out->hot_x = info.xHotspot;
    out->hot_y = info.yHotspot;
    if (out->hot_x < 0 || out->hot_y < 0 || out->hot_x >= (int)out->width ||
        out->hot_y >= (int)out->height)
    {
        out->hot_x = out->width / 2;
        out->hot_y = out->height / 2;
    }

done:
    NtGdiDeleteObjectApp( info.hbmMask );
    if (info.hbmColor) NtGdiDeleteObjectApp( info.hbmColor );
    return ret;
}

/* Publish, then make the picture right: the footprint the PREVIOUS shape
 * covers at the current position is handed to the repaint authority
 * (blit.c winefb_repaint_rect -- every window it touches repaints its part,
 * the desktop remainder is filled here and now, and each of those writes
 * ends in winefb_cursor_present with the new shape), and the new shape is
 * drawn at once so it does not wait for the next writer. Runs from the
 * message pump, outside every surface lock, which is what the repaint
 * authority requires.
 *
 * STATUS_INVALID_HANDLE is the ordinary race: the pointer left this window
 * before its owner answered, and the window it is in now publishes for
 * itself (shim.c prsk_cursor_publish). Nothing to repair then either --
 * the shape on screen is the other window's, legitimately. */
static void publish_image( const struct prsk_cursor_publish *publish, BOOL repair )
{
    struct prsk_cursor_image previous;
    RECT vacated;
    POINT pt;
    BOOL have_previous = FALSE;
    unsigned int status;

    if (repair && cursor_position( &pt ) &&
        prsk_cursor_read( prsk_client_cursor_image(), &previous ) && previous.width)
    {
        prsk_cursor_rect( &previous, pt.x, pt.y, &vacated );
        have_previous = TRUE;
    }

    status = prsk_client_publish_cursor( publish );
    if (status == STATUS_INVALID_HANDLE) return;
    if (status)
    {
        winefb_report( "[KTEST] gui4 cursor publish FAIL %08x\n", status );
        return;
    }
    if (!repair) return;
    if (have_previous) winefb_repaint_rect( &vacated, 0 );
    winefb_cursor_present();
}

/* pSetCursor: the server said the window under the pointer (`hwnd`, the
 * one WM_WINE_SETCURSOR named) shows `handle` -- 0 for hidden (ShowCursor
 * below zero, or a class with no cursor). Delivered to the process that
 * owns the window, on its message pump (dlls/win32u/message.c
 * process_hardware_message -> process_wine_setcursor). */
void winefb_set_cursor( HWND hwnd, HCURSOR handle )
{
    struct prsk_cursor_publish publish;
    unsigned int res_id = 0;

    publish.hwnd = HandleToULong( hwnd );
    publish.flags = 0;
    publish.image.seq = 0;
    publish.image.generation = 0;
    publish.image.width = publish.image.height = 0;
    publish.image.hot_x = publish.image.hot_y = 0;
    if (handle && !decode_cursor( handle, &publish.image, &res_id ))
    {
        /* A handle this process cannot read -- another process's, reachable
         * under attached inputs (get_icon_ptr -> OBJ_OTHER_PROCESS) -- or a
         * frame the contract refused above: the shape stays what it was,
         * as winex11's create_cursor returning 0 leaves the window's cursor
         * alone. */
        TRACE( "hwnd %p cursor %p not decodable here\n", hwnd, handle );
        return;
    }
    winefb_report( "[KTEST] gui4 cursor hwnd=%x handle=%p res=%u size=%ux%u hot=%d,%d\n",
                   publish.hwnd, handle, res_id, publish.image.width, publish.image.height,
                   publish.image.hot_x, publish.image.hot_y );
    publish_image( &publish, TRUE );
}

/* The desktop's own arrow (display.c, when the desktop window is sized):
 * the shape the pump falls back to over a window no thread answers for --
 * the explorerless fixture's forced desktop (shim.c
 * prsk_cursor_reassert_default), where the pinned server posts no
 * WM_WINE_SETCURSOR because there is nobody to post it to. Decoded from
 * the same user32 resource IDC_ARROW resolves to for every window
 * (dlls/win32u/defwnd.c handle_set_cursor). LoadImageW here is win32u's
 * own: a user-mode callback into user32 (dlls/win32u/cursoricon.c), the
 * call register_builtin_classes makes in the same context; a process with
 * no callback table gets 0 and publishes nothing. */
void winefb_cursor_publish_desktop_default(void)
{
    struct prsk_cursor_publish publish;
    unsigned int res_id = 0;
    HCURSOR arrow;

    arrow = LoadImageW( 0, (const WCHAR *)IDC_ARROW, IMAGE_CURSOR, 0, 0,
                        LR_SHARED | LR_DEFAULTSIZE );
    if (!arrow)
    {
        TRACE( "no IDC_ARROW in this process; no desktop cursor published\n" );
        return;
    }
    publish.hwnd = 0;
    publish.flags = PRSK_CURSOR_PUBLISH_DESKTOP;
    publish.image.seq = 0;
    publish.image.generation = 0;
    if (!decode_cursor( arrow, &publish.image, &res_id )) return;
    winefb_report( "[KTEST] gui4 cursor desktop res=%u size=%ux%u hot=%d,%d\n", res_id,
                   publish.image.width, publish.image.height, publish.image.hot_x,
                   publish.image.hot_y );
    publish_image( &publish, FALSE );
}
