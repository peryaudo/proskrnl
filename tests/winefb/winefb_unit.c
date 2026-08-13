/*
 * winefb_unit.c - the compositor's unit verdict (docs/08).
 *
 * The winefb compositor is policy over three authorities: the server's
 * z-order (who is above, who is visible), Wine's region engine (what
 * survives the subtraction), and the scanout (where the bytes land). The
 * QEMU gui legs prove the whole stack end to end but cost a boot each;
 * every COMPOSITOR bug so far -- the desktop erasing the console, the
 * winemine close afterimage -- was policy, reproducible against a fixture.
 * So the policy is pinned here: the REAL compose.c and blit.c objects (the
 * same ones linked into win32u.dll), the real Wine region engine (gdi32,
 * running under the pinned Wine), and a mocked seam for the rest
 * (winefb_mocks.c). Runs in under a second; tests/run/run.sh winefbunit.
 *
 * Every case seeds a fixture desktop (topmost first, the get_window_list
 * order), drives the driver through its real entry points, and asserts on
 * the two outputs the driver has: pixels on the scanout, and
 * NtUserRedrawWindow calls to other windows.
 */

#include "ntapi.h"
#include "winefb_unit.h"

/* fixture handles; arbitrary values, distinct on purpose */
#define DESKTOP 0x9990u
#define WIN_A   0x1010u
#define WIN_B   0x2020u
#define WIN_C   0x3030u

#define COLOR_A 0x00cc00u
#define COLOR_B 0xcc2200u
#define COLOR_D 0x0000ccu

#define SCREEN_W 640
#define SCREEN_H 480

/* Occlusion: a flush only paints where nothing is above. The overlap with
 * the topmost sibling keeps its pixels; the rest of the dirty rect gets
 * the window's. */
static void test_flush_clips_above(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_B, 100, 100, 300, 300, 110, 130, 290, 290, 1); /* topmost */
    unit_add_window(WIN_A, 50, 50, 350, 350, 60, 80, 340, 340, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 384, 384), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 50, 50, 350, 350, 1);

    ok(unit_pixel(60, 60) == COLOR_A, "A's exposed part painted (got %08x)\n", unit_pixel(60, 60));
    ok(unit_pixel(340, 340) == COLOR_A, "A below B's rect painted (got %08x)\n",
       unit_pixel(340, 340));
    ok(unit_pixel(150, 150) == 0, "the overlap under B stays B's (got %08x)\n",
       unit_pixel(150, 150));
    ok(unit_pixel(49, 49) == 0, "outside A untouched (got %08x)\n", unit_pixel(49, 49));
}

/* The desktop window composes below EVERYTHING: its flush must clip out
 * every visible top-level (the gui5con vanishing-console bug: an
 * explorer-owned desktop repaint erased the console). */
static void test_desktop_flush_clips_below(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 200, 200, 100, 100, 200, 200, 1);

    ok(unit_create_surface(DESKTOP, 0, 0, SCREEN_W, SCREEN_H), "desktop surface\n");
    unit_surface_fill(DESKTOP, COLOR_D);
    unit_pos_changed(DESKTOP, 0, SWP_NOZORDER, 0, 0, SCREEN_W, SCREEN_H, 1);

    ok(unit_pixel(10, 10) == COLOR_D, "desktop painted its own share (got %08x)\n",
       unit_pixel(10, 10));
    ok(unit_pixel(150, 150) == 0, "the window's pixels survive a desktop repaint (got %08x)\n",
       unit_pixel(150, 150));
    ok(unit_pixel(210, 210) == COLOR_D, "desktop painted past the window (got %08x)\n",
       unit_pixel(210, 210));
}

/* A window the desktop no longer shows paints NOTHING: a flush racing its
 * own hide must not stamp the window back over its siblings (the old
 * hwnd-not-found fallback subtracted nothing and painted unclipped). */
static void test_hidden_flush_paints_nothing(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 50, 50, 250, 250, 50, 50, 250, 250, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 256, 256), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 50, 50, 250, 250, 1);
    ok(unit_pixel(60, 60) == COLOR_A, "A painted while visible (got %08x)\n", unit_pixel(60, 60));

    unit_set_visible(WIN_A, 0); /* the server-side hide lands first */
    unit_surface_fill(WIN_A, COLOR_B);
    unit_flush_dirty(WIN_A, 0, 0, 256, 256);
    ok(unit_pixel(60, 60) == COLOR_A, "a hidden window's flush painted nothing (got %08x)\n",
       unit_pixel(60, 60));
}

/* THE winemine close afterimage (the pin this suite replaced a QEMU leg
 * for): the hide's pWindowPosChanged arrives with the dummy surface, and
 * the vacated rect must be repaired from the rects win32u hands over --
 * the sibling under it invalidated, the desktop remainder filled with the
 * background. No surface refcount may be involved (cached DCs pin
 * surfaces past DestroyWindow, so a surface-destroy-keyed repair never
 * ran). */
static void test_hide_repairs_vacated(void)
{
    unsigned int bg;

    unit_reset(SCREEN_W, SCREEN_H);
    bg = unit_bg();
    unit_set_desktop(DESKTOP);
    /* the closing window is already hidden server-side when the repair
     * runs (DestroyWindow hides first); only the console remains */
    unit_add_window(WIN_C, 0, 0, 400, 300, 10, 30, 390, 290, 1);

    unit_pos_changed(WIN_A, 0, SWP_HIDEWINDOW, 200, 150, 360, 376, 0);

    ok(unit_redraw_count() == 1, "one window invalidated (got %u)\n", unit_redraw_count());
    ok(unit_redraw_hwnd(0) == WIN_C, "the console was invalidated (got %x)\n", unit_redraw_hwnd(0));
    ok(unit_redraw_whole(0) == 1, "an overlap reaching the frame invalidates whole\n");
    ok(unit_pixel(250, 350) == bg, "the desktop part is background again (got %08x)\n",
       unit_pixel(250, 350));
    ok(unit_pixel(210, 310) == bg, "the strip below the console too (got %08x)\n",
       unit_pixel(210, 310));
    ok(unit_pixel(250, 200) == 0, "the fill never touches the console's share (got %08x)\n",
       unit_pixel(250, 200));
    ok(unit_pixel(199, 350) == 0, "no fill left of the vacated rect (got %08x)\n",
       unit_pixel(199, 350));
    ok(unit_pixel(250, 377) == 0, "no fill below the vacated rect (got %08x)\n",
       unit_pixel(250, 377));
}

/* A LAYERED window's hide arrives with its REAL surface still attached
 * (win32u's get_window_surface keeps needs_surface TRUE for layered
 * surfaces, so the dummy swap never happens), and the repair must run all
 * the same -- and must not re-blit the hidden window back. */
static void test_hide_with_surface_repairs(void)
{
    unsigned int bg;

    unit_reset(SCREEN_W, SCREEN_H);
    bg = unit_bg();
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 200, 200, 100, 100, 200, 200, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 128, 128), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 200, 200, 1);
    ok(unit_pixel(150, 150) == COLOR_A, "A painted (got %08x)\n", unit_pixel(150, 150));

    unit_set_visible(WIN_A, 0); /* the server-side hide lands first */
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER | SWP_HIDEWINDOW, 100, 100, 200, 200, 1);
    ok(unit_pixel(150, 150) == bg, "the vacated rect is background again (got %08x)\n",
       unit_pixel(150, 150));
    ok(unit_pixel(110, 190) == bg, "  ... whole (got %08x)\n", unit_pixel(110, 190));
}

/* The mover: what a moved window uncovered is background again, and the
 * window is painted whole at its new place. */
static void test_move_repairs_vacated(void)
{
    unsigned int bg;

    unit_reset(SCREEN_W, SCREEN_H);
    bg = unit_bg();
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 200, 200, 100, 100, 200, 200, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 128, 128), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 200, 200, 1);
    ok(unit_pixel(110, 110) == COLOR_A, "A painted (got %08x)\n", unit_pixel(110, 110));

    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 150, 150, 250, 250, 1);
    ok(unit_pixel(110, 110) == bg, "the vacated corner is background (got %08x)\n",
       unit_pixel(110, 110));
    ok(unit_pixel(145, 195) == bg, "the vacated band is background (got %08x)\n",
       unit_pixel(145, 195));
    ok(unit_pixel(160, 160) == COLOR_A, "A painted at the new place (got %08x)\n",
       unit_pixel(160, 160));
    ok(unit_pixel(245, 245) == COLOR_A, "A's new corner painted (got %08x)\n",
       unit_pixel(245, 245));
    ok(unit_redraw_count() == 0, "nothing else to invalidate (got %u)\n", unit_redraw_count());
}

/* A resize replaces the surface; the vacated strip of the predecessor
 * rides over on the stash and is repaired exactly once. */
static void test_resize_repairs_vacated(void)
{
    unsigned int bg;

    unit_reset(SCREEN_W, SCREEN_H);
    bg = unit_bg();
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 260, 260, 100, 100, 260, 260, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 256, 256), "surface A v1\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 260, 260, 1);
    ok(unit_pixel(250, 250) == COLOR_A, "A painted large (got %08x)\n", unit_pixel(250, 250));

    /* shrink: new padded surface, new geometry */
    ok(unit_create_surface(WIN_A, 0, 0, 128, 128), "surface A v2\n");
    unit_surface_fill(WIN_A, COLOR_B);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 180, 180, 1);
    ok(unit_pixel(150, 150) == COLOR_B, "A painted small (got %08x)\n", unit_pixel(150, 150));
    ok(unit_pixel(250, 250) == bg, "the vacated corner is background (got %08x)\n",
       unit_pixel(250, 250));
    ok(unit_pixel(150, 200) == bg, "the vacated band is background (got %08x)\n",
       unit_pixel(150, 200));
}

/* Lowering: the sibling that rose above must be told to repaint -- the
 * server exposes nothing for top-levels, and the risen window's surface
 * has no new bounds of its own. */
static void test_zdrop_repaints_risen(void)
{
    unsigned int i, b_invalidated = 0;

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    /* fixture is POST-change: B already above A; C stays below A and also
     * intersects it -- nothing about C changed, so C must hear NOTHING (a
     * z-drop that invalidates the whole neighbourhood is a cross-process
     * repaint storm on every lowering) */
    unit_add_window(WIN_B, 100, 100, 300, 300, 100, 100, 300, 300, 1);
    unit_add_window(WIN_A, 50, 50, 350, 350, 50, 50, 350, 350, 1);
    unit_add_window(WIN_C, 40, 40, 360, 360, 40, 40, 360, 360, 1);

    ok(unit_create_surface(WIN_B, 0, 0, 256, 256), "surface B\n");
    unit_surface_fill(WIN_B, COLOR_B);
    unit_pos_changed(WIN_B, 0, SWP_NOZORDER, 100, 100, 300, 300, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 384, 384), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    /* the lowering SetWindowPos: insert_after names B */
    unit_pos_changed(WIN_A, WIN_B, 0, 50, 50, 350, 350, 1);

    for (i = 0; i < unit_redraw_count(); i++)
        if (unit_redraw_hwnd(i) == WIN_B)
            b_invalidated = 1;
    ok(b_invalidated, "the risen sibling was invalidated\n");
    ok(unit_redraw_count() == 1, "and NOBODY else was (got %u)\n", unit_redraw_count());
    ok(unit_pixel(150, 150) == COLOR_B, "the overlap stays the risen window's (got %08x)\n",
       unit_pixel(150, 150));
    ok(unit_pixel(60, 60) == COLOR_A, "the lowered window keeps its exposed part (got %08x)\n",
       unit_pixel(60, 60));
    ok(unit_pixel(340, 340) == COLOR_A, "  ... on every side (got %08x)\n", unit_pixel(340, 340));
}

/* Raising to the top needs no invalidation walk at all: the forced flush
 * paints the risen window over everything, and nobody else changed. */
static void test_raise_no_invalidation(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 50, 50, 350, 350, 50, 50, 350, 350, 1);
    unit_add_window(WIN_B, 100, 100, 300, 300, 100, 100, 300, 300, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 384, 384), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0 /* HWND_TOP */, 0, 50, 50, 350, 350, 1);

    ok(unit_redraw_count() == 0, "a raise invalidates nobody (got %u)\n", unit_redraw_count());
    ok(unit_pixel(150, 150) == COLOR_A, "the raised window painted over the sibling (got %08x)\n",
       unit_pixel(150, 150));
}

/* win32u's surface clip (shaped/pixel-format regions computed server-side)
 * bounds every blit. */
static void test_surface_clip_honored(void)
{
    static const int clip[4] = {0, 0, 50, 50}; /* surface-local */

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 228, 228, 100, 100, 228, 228, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 128, 128), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 228, 228, 1);
    unit_set_clip(WIN_A, clip, 1);
    unit_surface_fill(WIN_A, COLOR_B);
    unit_flush_dirty(WIN_A, 0, 0, 128, 128);

    ok(unit_pixel(110, 110) == COLOR_B, "inside the clip painted (got %08x)\n",
       unit_pixel(110, 110));
    ok(unit_pixel(160, 160) == COLOR_A, "outside the clip untouched (got %08x)\n",
       unit_pixel(160, 160));
}

/* A shaped surface (SetWindowRgn, a color-keyed layered window -- dce.c
 * turns both into the 1bpp shape bitmap handed to flush) must not paint
 * outside its shape: the pixels under the holes belong to whoever is
 * beneath. MSB-first bits, byte-aligned width, row order by biHeight's
 * sign -- the set_surface_shape layout. */
static void shape_case(int topdown)
{
    static unsigned char shape[8 * 64]; /* 64x64 at 1bpp: 8-byte rows */
    int x, y;

    /* opaque everywhere except a hole at surface-local 16..32 x 16..32 */
    for (y = 0; y < 64; y++)
    {
        int row = topdown ? y : 63 - y;

        for (x = 0; x < 64; x++)
        {
            int hole = x >= 16 && x < 32 && y >= 16 && y < 32;

            if (!hole)
                shape[row * 8 + (x >> 3)] |= 0x80 >> (x & 7);
            else
                shape[row * 8 + (x >> 3)] &= ~(0x80 >> (x & 7));
        }
    }

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 164, 164, 100, 100, 164, 164, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 64, 64), "surface A\n");
    /* geometry first (the forced flush paints only zeros), the color and
     * the shaped flush after -- so the hole's pixels were never painted */
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 100, 100, 164, 164, 1);
    unit_surface_fill(WIN_A, COLOR_A);
    unit_flush_shaped(WIN_A, shape, 8, topdown);

    ok(unit_pixel(108, 108) == COLOR_A, "inside the shape painted (got %08x, %s)\n",
       unit_pixel(108, 108), topdown ? "top-down" : "bottom-up");
    ok(unit_pixel(140, 140) == COLOR_A, "past the hole painted (got %08x, %s)\n",
       unit_pixel(140, 140), topdown ? "top-down" : "bottom-up");
    ok(unit_pixel(120, 120) == 0, "the hole is not painted (got %08x, %s)\n", unit_pixel(120, 120),
       topdown ? "top-down" : "bottom-up");
    ok(unit_pixel(117, 131) == 0, "  ... anywhere (got %08x, %s)\n", unit_pixel(117, 131),
       topdown ? "top-down" : "bottom-up");
}

static void test_shape_masks_flush(void)
{
    shape_case(1);
    shape_case(0);
}

/* More top-levels than the z-order query carries: every caller treats the
 * answer as "not visible" and paints nothing -- the safe direction (an
 * unclipped flush would be soup) -- but a silently frozen desktop is a
 * debugging pit, so the overflow must name itself on serial (Art. 12).
 * Runs LAST: the report is a per-process one-shot. */
static void test_toplevel_overflow_refuses_loudly(void)
{
    unsigned int i;

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 50, 50, 250, 250, 50, 50, 250, 250, 1);
    for (i = 0; i < 65; i++)
        unit_add_window(0x5000u + i, 400, 400, 420, 420, 400, 400, 420, 420, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 256, 256), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 50, 50, 250, 250, 1);

    ok(unit_pixel(60, 60) == 0, "an overflowed desktop paints nothing (got %08x)\n",
       unit_pixel(60, 60));
    ok(unit_report_count() >= 1, "and says so on serial (got %u reports)\n", unit_report_count());
}

/* Activation raises: clicking a covered window must bring it to the front
 * of the z-order, not just move focus -- win32u and the server never
 * reorder top-levels on activation (on Wine the X11 window manager does
 * the raise; here winefb is the window manager). The hook issues one
 * SetWindowPos to HWND_TOP without re-activating; the desktop window
 * never raises. */
static void test_activate_raises(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_B, 100, 100, 300, 300, 100, 100, 300, 300, 1);
    unit_add_window(WIN_A, 50, 50, 350, 350, 50, 50, 350, 350, 1);
    ok(unit_create_surface(WIN_A, 0, 0, 384, 384), "surface A\n");
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 50, 50, 350, 350, 1);

    unit_activate(WIN_A, WIN_B);
    ok(unit_raise_count() == 1, "one raise issued (got %u)\n", unit_raise_count());
    ok(unit_raise_hwnd(0) == WIN_A, "the activated window raises (got %x)\n", unit_raise_hwnd(0));
    ok(unit_raise_after(0) == (unsigned int)(UINT_PTR)HWND_TOP,
       "  ... to HWND_TOP, the band left to link_window (got %x)\n", unit_raise_after(0));
    ok((unit_raise_flags(0) & SWP_NOACTIVATE) != 0, "  ... without re-activating\n");
    ok((unit_raise_flags(0) & (SWP_NOSIZE | SWP_NOMOVE)) == (SWP_NOSIZE | SWP_NOMOVE),
       "  ... moving nothing\n");
    ok((unit_raise_flags(0) & SWP_NOZORDER) == 0, "  ... and actually restacking\n");
    ok(unit_raise_carries_surface(0) == 1,
       "  ... preserving the visible+surface rects and the surface paint flag\n");
    ok(unit_redraw_count() == 0, "the raise is message-silent: no client-side invalidation\n");

    unit_activate(DESKTOP, WIN_A);
    ok(unit_raise_count() == 1, "the desktop window never raises (got %u)\n", unit_raise_count());
}

START_TEST(winefbunit)
{
    test_flush_clips_above();
    test_desktop_flush_clips_below();
    test_hidden_flush_paints_nothing();
    test_hide_repairs_vacated();
    test_hide_with_surface_repairs();
    test_move_repairs_vacated();
    test_resize_repairs_vacated();
    test_zdrop_repaints_risen();
    test_raise_no_invalidation();
    test_surface_clip_honored();
    test_shape_masks_flush();
    test_toplevel_overflow_refuses_loudly();
    test_activate_raises();
}
