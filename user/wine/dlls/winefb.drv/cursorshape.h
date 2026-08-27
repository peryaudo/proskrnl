/*
 * cursorshape.h - the software arrow and the desktop background color.
 *
 * Shared between the two writers that paint them: winefb.drv (cursor.c
 * draws the arrow at the tail of every flush, blit.c/display.c fill the
 * background) and wineserver-lite's raw-input pump (server/rawinput.c),
 * which draws the arrow and repairs the rect it vacated when the pointer
 * moves on an otherwise idle desktop. One shape, one color, one file --
 * two copies would drift the day someone touches one of them (Art. 11).
 *
 * Requires windef.h/wingdi.h (RGB) before inclusion.
 */
#ifndef PRSK_CURSORSHAPE_H
#define PRSK_CURSORSHAPE_H

/* A 12x20 left-pointing arrow, hotspot at (0,0): 'X' outline pixels, '.'
 * fill pixels, ' ' transparent. The classic two-color shape every
 * software cursor since CGA has drawn; visible on any background because
 * outline and fill contrast with each other. */
#define CURSOR_W 12
#define CURSOR_H 20

static const char *const cursor_image[CURSOR_H] __attribute__((unused)) =
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

/* The desktop wallpaper color every repaint-remainder is filled with:
 * COLOR_BACKGROUND, RGB(58,110,165) -- re-verify against the pinned
 * dlls/win32u/sysparams.c system_colors[]. Reported on serial, never
 * assumed by a checker. */
#define WINEFB_DESKTOP_BG RGB( 0x3a, 0x6e, 0xa5 ) /* the classic desktop blue */

#endif /* PRSK_CURSORSHAPE_H */
