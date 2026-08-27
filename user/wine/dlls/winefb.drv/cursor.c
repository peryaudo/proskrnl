/*
 * cursor.c - the software cursor (GUI-4; composited GUI-5).
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
 *   - every writer that touches the scanout draws the arrow back on top of
 *     what it just painted (winefb_cursor_present, called at the tail of
 *     the surface flush and the background fill in blit.c). The cursor is
 *     above everything, so this is always the right answer, and no writer
 *     has to know a cursor was there;
 *   - when the pointer moves, the rect it left is repainted from whoever
 *     OWNS those pixels rather than from a snapshot, so nothing is ever
 *     restored and nothing can be stale. The MOVER is not this process:
 *     wineserver-lite's raw-input pump (server/rawinput.c) owns the
 *     devices, moves the cursor and repairs the vacated rect. This file
 *     only ever draws the arrow where the server says it is.
 *
 * Position comes from the server, which owns it: desktop_shm->cursor is
 * published in the desktop's shared memory and read here through the same
 * seqlock NtUserGetCursorPos uses. That is what makes the overlay legal
 * inside a flush -- it takes no user lock (compose.c documents the
 * lock-order wedge a blocking NtUser* call there caused), and it is why
 * the design needs no cross-process protocol of its own: every process
 * reads the one authority.
 *
 * The SHAPE is still deliberately not the window's real HCURSOR: the
 * server posts WM_WINE_SETCURSOR to the process owning the window under
 * the cursor (dlls/win32u/cursoricon.c process_wine_setcursor), and
 * honoring per-window shapes would mean tracking that cross-process for
 * zero milestone value. One builtin arrow.
 * pSetCursor/pGetCursorPos/pSetCursorPos/pClipCursor stay nulldrv: the
 * server owns cursor position and clip state, and this driver only ever
 * ASKS for them, never answers.
 *
 * Residual, named: the vacated rect over a window is repaired by that
 * window's own repaint, so a window whose thread is wedged keeps the trail
 * until it pumps again. Same latency class the mover already accepts for
 * an uncovered window, and it degrades to briefly-stale rather than
 * permanently-wrong.
 */

#include "winefb.h"
#include "ntgdi.h"
#include "win32u_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* The arrow shape lives in cursorshape.h, shared with wineserver-lite's
 * raw-input pump -- the session's cursor MOVER -- which draws the same
 * pixels from its own scanout mapping (server/rawinput.c). */
#include "cursorshape.h"

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
 * draw there. An arrow parked at (0,0) on the gui5 BOOT would be exactly
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
     * image must not paint an arrow in its top-left corner before the mouse
     * has moved: the gui4 dumps check that corner for the desktop
     * background, and gui5con LOCATES its console window as the bounding
     * box of everything that is not background, which a corner arrow would
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
     * (0,0) draws no arrow until it moves again: bounded, cosmetic,
     * self-correcting, and it fails to no cursor rather than to a cursor
     * where the pointer has never been. */
    return pt->x != 0 || pt->y != 0;
}

static UINT *scanout_at( int x, int y )
{
    return (UINT *)(winefb_scanout.pixels + (size_t)y * winefb_scanout.mode.pitch +
                    (size_t)x * 4);
}

/* Draw the arrow at the position the server publishes. Called at the tail
 * of every write to the scanout, in every process: whoever just painted
 * owes the topmost picture back, and drawing it unconditionally is both
 * idempotent and free of any protocol -- there is nothing to coordinate
 * when the only state is "where does the server say the cursor is". */
void winefb_cursor_present(void)
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    UINT black, white;
    int row, col, width, height;
    POINT pt;

    if (!winefb_scanout.pixels) return;
    if (!cursor_position( &pt )) return;
    if (pt.x < 0 || pt.y < 0) return;

    width = min( CURSOR_W, (int)mode->width - pt.x );
    height = min( CURSOR_H, (int)mode->height - pt.y );
    if (width <= 0 || height <= 0) return;

    black = winefb_pack_pixel( 0x00, 0x00, 0x00 );
    white = winefb_pack_pixel( 0xff, 0xff, 0xff );
    for (row = 0; row < height; row++)
    {
        UINT *out = scanout_at( pt.x, pt.y + row );

        for (col = 0; col < width; col++)
        {
            char pixel = cursor_image[row][col];

            if (pixel == 'X') out[col] = black;
            else if (pixel == '.') out[col] = white;
        }
    }
}

