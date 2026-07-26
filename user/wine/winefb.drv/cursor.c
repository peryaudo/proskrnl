/*
 * cursor.c - the software cursor (GUI-4).
 *
 * There is no hardware cursor plane: the scanout is the VBE linear
 * framebuffer and nothing else (HACK-001), so the cursor is pixels this
 * driver draws itself -- save what is under the new position, draw the
 * arrow, restore on the next move. GUI-1..3 left this file empty because a
 * cursor with no mouse would have been a fixed picture of a lie; the mouse
 * arrived (\Device\Input1), so the position is now real.
 *
 * The SHAPE is deliberately not the window's real HCURSOR: the server
 * posts WM_WINE_SETCURSOR to the process owning the window under the
 * cursor (dlls/win32u/cursoricon.c process_wine_setcursor), which is not
 * the process reading the pointer device -- honoring per-window cursor
 * shapes would make cursor drawing a cross-process protocol for zero
 * milestone value. One builtin arrow, drawn by the one pointer reader
 * (input.c), is a single-writer design with no protocol at all.
 * pSetCursor/pGetCursorPos/pSetCursorPos/pClipCursor stay nulldrv: the
 * server owns cursor position and clip state (desktop_shm->cursor), and
 * this driver only ever ASKS the device, never answers for it.
 *
 * Known, bounded artifact: a window flush that overlaps the cursor paints
 * over it (the cursor reappears on the next motion), and the restore after
 * such a flush deposits at most one cursor-sized patch of pre-flush
 * pixels, wiped by any later flush of that window. The gui4 leg parks the
 * cursor over the desktop background before every screendump, so the
 * dumps are deterministic. If that artifact ever matters, the escalation
 * path is compositing the cursor in every process's surface flush from
 * the shared cursor position (desktop_shm->cursor is readable by every
 * client); not built until something needs it.
 */

#include "winefb.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* A 12x20 left-pointing arrow, hotspot at (0,0): 'X' outline pixels, '.'
 * fill pixels, ' ' transparent. The classic two-color shape every
 * software cursor since CGA has drawn; visible on any background because
 * outline and fill contrast with each other. */
#define CURSOR_W 12
#define CURSOR_H 20

static const char *const cursor_image[CURSOR_H] =
{
    "X           ",
    "XX          ",
    "X.X         ",
    "X..X        ",
    "X...X       ",
    "X....X      ",
    "X.....X     ",
    "X......X    ",
    "X.......X   ",
    "X........X  ",
    "X.....XXXXX ",
    "X..X..X     ",
    "X.X X..X    ",
    "XX  X..X    ",
    "X    X..X   ",
    "     X..X   ",
    "      X..X  ",
    "      X..X  ",
    "       XX   ",
    "            ",
};

static struct
{
    BOOL saved;
    int x, y, w, h; /* the saved rect: position clipped to the scanout */
    UINT under[CURSOR_W * CURSOR_H];
} cursor_state;

/* Pack one 8-bit-per-channel color the way the scanout wants it -- the
 * same arithmetic blit.c's repack_rows uses, so the masks mean the same
 * thing in both places. */
static UINT pack_pixel( UINT r, UINT g, UINT b )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;

    return ((r >> (8 - mode->redMaskSize)) << mode->redMaskShift) |
           ((g >> (8 - mode->greenMaskSize)) << mode->greenMaskShift) |
           ((b >> (8 - mode->blueMaskSize)) << mode->blueMaskShift);
}

static UINT *scanout_at( int x, int y )
{
    return (UINT *)(winefb_scanout.pixels + (size_t)y * winefb_scanout.mode.pitch +
                    (size_t)x * 4);
}

static void cursor_restore(void)
{
    int row;

    if (!cursor_state.saved) return;
    for (row = 0; row < cursor_state.h; row++)
        memcpy( scanout_at( cursor_state.x, cursor_state.y + row ),
                &cursor_state.under[row * CURSOR_W], (size_t)cursor_state.w * 4 );
    cursor_state.saved = FALSE;
}

/* Move the cursor picture to (x, y), screen pixels, already clamped to the
 * scanout by the caller (input.c scale_axis). Single writer: only the
 * pointer thread calls this, so the save-under state needs no lock. */
void winefb_cursor_update( int x, int y )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    UINT black, white;
    int row, col;

    if (!winefb_scanout.pixels) return;

    cursor_restore();

    cursor_state.x = x;
    cursor_state.y = y;
    cursor_state.w = min( CURSOR_W, (int)mode->width - x );
    cursor_state.h = min( CURSOR_H, (int)mode->height - y );
    if (cursor_state.w <= 0 || cursor_state.h <= 0) return;

    for (row = 0; row < cursor_state.h; row++)
        memcpy( &cursor_state.under[row * CURSOR_W], scanout_at( x, y + row ),
                (size_t)cursor_state.w * 4 );
    cursor_state.saved = TRUE;

    black = pack_pixel( 0x00, 0x00, 0x00 );
    white = pack_pixel( 0xff, 0xff, 0xff );
    for (row = 0; row < cursor_state.h; row++)
    {
        UINT *out = scanout_at( x, y + row );

        for (col = 0; col < cursor_state.w; col++)
        {
            char pixel = cursor_image[row][col];

            if (pixel == 'X') out[col] = black;
            else if (pixel == '.') out[col] = white;
        }
    }
}
