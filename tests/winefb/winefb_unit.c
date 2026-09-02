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

/* MINIMIZE is a surface-losing transition with no SWP_HIDEWINDOW: Wine
 * parks the iconic window at -32000 and a fully-offscreen window gets no
 * surface, so pWindowPosChanged arrives with the dummy surface and the
 * new rects name a place that is not on the scanout. The vacate must come
 * from the tracker (the surface that knew the old rect is gone) -- the
 * minimize button used to leave a full afterimage here. */
static void test_minimize_repairs_vacated(void)
{
    unsigned int bg;

    unsigned int redraws;

    unit_reset(SCREEN_W, SCREEN_H);
    bg = unit_bg();
    unit_set_desktop(DESKTOP);
    /* A straddles the console's corner and the empty desktop, the guiclose
     * geometry: both repaint authorities are on the hook */
    unit_add_window(WIN_A, 200, 150, 360, 376, 200, 150, 360, 376, 1);
    unit_add_window(WIN_C, 0, 0, 400, 300, 10, 30, 390, 290, 1);

    ok(unit_create_surface(WIN_A, 0, 0, 256, 256), "surface A\n");
    unit_surface_fill(WIN_A, COLOR_A);
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, 200, 150, 360, 376, 1);
    ok(unit_pixel(250, 350) == COLOR_A, "A painted over the desktop (got %08x)\n",
       unit_pixel(250, 350));

    /* the minimize, as traced live: a REAL surface (get_surface_rect only
     * refuses larger-than-screen windows), freshly REPLACED (the iconic
     * padded rect differs, so the predecessor went to apply_window_pos and
     * never through create -- the dummy-swap unit_create_surface models),
     * at the iconic -32000 rect; no SWP_HIDEWINDOW anywhere */
    ok(unit_create_surface(WIN_A, 0, 0, 256, 128), "iconic surface A\n");
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER | SWP_FRAMECHANGED, -32000, -32000, -31840, -31976, 1);
    ok(unit_redraw_count() == 1, "the covered sibling was invalidated (got %u)\n",
       unit_redraw_count());
    ok(unit_redraw_hwnd(0) == WIN_C, "  ... the console (got %x)\n", unit_redraw_hwnd(0));
    ok(unit_pixel(250, 350) == bg, "the desktop share is background again (got %08x)\n",
       unit_pixel(250, 350));
    ok(unit_pixel(210, 310) == bg, "  ... the strip below the console too (got %08x)\n",
       unit_pixel(210, 310));
    ok(unit_pixel(199, 350) == 0, "no fill left of the vacated rect (got %08x)\n",
       unit_pixel(199, 350));
    ok(unit_pixel(250, 377) == 0, "no fill below the vacated rect (got %08x)\n",
       unit_pixel(250, 377));

    /* a second surfaceless pos-change finds nothing to vacate: the take is
     * destructive, so nothing is invalidated or filled twice */
    redraws = unit_redraw_count();
    unit_pos_changed(WIN_A, 0, SWP_NOZORDER, -32000, -32000, -31840, -31776, 0);
    ok(unit_redraw_count() == redraws, "a repeated loss vacates nothing (got %u)\n",
       unit_redraw_count());
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

    /* programmatic activation (no click in flight): the z-order is not the
     * driver's to change -- SetActiveWindow-driven sequences must see
     * neither a message nor a z-state change (the user32:msg conviction) */
    unit_activate(WIN_A, WIN_B);
    ok(unit_raise_count() == 0, "programmatic activation never raises (got %u)\n",
       unit_raise_count());

    unit_set_button_down(1); /* the click that drove this activation */
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

/* --- the cursor (cursor.c) ---------------------------------------------------
 *
 * The decode runs against the pinned user32's own cursor objects (the mock
 * forwards NtUserGetIconInfo / NtGdiGetDIBits to user32/gdi32), so every
 * fact below is the oracle's: what LoadCursor(IDC_ARROW) is, where the
 * I-beam's hotspot sits, how a CreateCursor mask decodes. The gui4 leg
 * grades the same shapes on the scanout against the .cur files. */

static unsigned int pack(unsigned int argb)
{
    return argb & 0xffffff; /* the mock scanout is BGRX: 0xRRGGBB is the pixel */
}

static unsigned int opaque_count(void)
{
    unsigned int x, y, n = 0;

    for (y = 0; y < unit_cursor_height(); y++)
        for (x = 0; x < unit_cursor_width(); x++)
            if (unit_cursor_pixel(x, y) >> 24)
                n++;
    return n;
}

/* The stock arrow: the 32x32 frame LR_DEFAULTSIZE selects, hotspot at the
 * tip, opaque there and transparent in the far corner; both black and
 * white pixels present (an outline around a fill), every alpha binary. */
static void test_cursor_arrow_decodes(void)
{
    HCURSOR arrow = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    unsigned int x, y, black = 0, white = 0, partial = 0;

    unit_reset(SCREEN_W, SCREEN_H);
    ok(arrow != NULL, "LoadCursorW(IDC_ARROW)\n");
    unit_set_cursor(WIN_A, (ULONG_PTR)arrow);
    ok(unit_cursor_publish_count() == 1, "published once (got %u)\n", unit_cursor_publish_count());
    ok(unit_cursor_hwnd() == WIN_A, "published for the window named (got %x)\n",
       unit_cursor_hwnd());
    ok(unit_cursor_flags() == 0, "an ordinary publish, not the desktop default\n");
    ok(unit_cursor_width() == 32 && unit_cursor_height() == 32, "32x32 frame (got %ux%u)\n",
       unit_cursor_width(), unit_cursor_height());
    ok(unit_cursor_hot_x() == 0 && unit_cursor_hot_y() == 0, "hotspot at the tip (got %d,%d)\n",
       unit_cursor_hot_x(), unit_cursor_hot_y());
    ok(unit_cursor_pixel(0, 0) >> 24 == 0xff, "the tip is opaque (got %08x)\n",
       unit_cursor_pixel(0, 0));
    ok((unit_cursor_pixel(0, 0) & 0xffffff) < 0x101010, "the tip is (near) black (got %08x)\n",
       unit_cursor_pixel(0, 0));
    ok(unit_cursor_pixel(31, 31) == 0, "the far corner is transparent (got %08x)\n",
       unit_cursor_pixel(31, 31));
    for (y = 0; y < 32; y++)
        for (x = 0; x < 32; x++)
        {
            unsigned int p = unit_cursor_pixel(x, y);
            unsigned int r = (p >> 16) & 0xff, g = (p >> 8) & 0xff, b = p & 0xff;
            if ((p >> 24) == 0xff && r < 0x40 && g < 0x40 && b < 0x40)
                black++;
            else if ((p >> 24) == 0xff && r > 0xc0 && g > 0xc0 && b > 0xc0)
                white++;
            if ((p >> 24) != 0 && (p >> 24) != 0xff)
                partial++;
        }
    ok(black > 40 && white > 30, "an outline around a fill (%u dark, %u light)\n", black, white);
    ok(partial == 0, "alpha is binary (%u partial pixels)\n", partial);
}

static void test_cursor_ibeam_hotspot(void)
{
    HCURSOR ibeam = LoadCursorW(NULL, (LPCWSTR)IDC_IBEAM);

    unit_reset(SCREEN_W, SCREEN_H);
    ok(ibeam != NULL, "LoadCursorW(IDC_IBEAM)\n");
    unit_set_cursor(WIN_B, (ULONG_PTR)ibeam);
    ok(unit_cursor_width() == 32 && unit_cursor_height() == 32, "32x32 frame (got %ux%u)\n",
       unit_cursor_width(), unit_cursor_height());
    ok(unit_cursor_hot_x() == 3 && unit_cursor_hot_y() == 9, "the I-beam's hotspot (got %d,%d)\n",
       unit_cursor_hot_x(), unit_cursor_hot_y());
    ok(unit_cursor_pixel(3, 9) >> 24 == 0xff, "opaque at the hotspot (got %08x)\n",
       unit_cursor_pixel(3, 9));
}

/* A monochrome CreateCursor: the four AND/XOR outcomes, one per column.
 * 16 wide so each plane row is exactly one WORD (CreateCursor's row
 * alignment), 2 high so the double-height mask is exercised. */
static void test_cursor_mono_truth_table(void)
{
    /* columns 0..3: AND 1,0,0,1 / XOR 0,1,0,1 -> screen, white, black, invert */
    static const unsigned char and_plane[4] = {0x90, 0xff, 0x90, 0xff};
    static const unsigned char xor_plane[4] = {0x50, 0x00, 0x50, 0x00};
    HCURSOR mono = CreateCursor(NULL, 1, 0, 16, 2, and_plane, xor_plane);

    unit_reset(SCREEN_W, SCREEN_H);
    ok(mono != NULL, "CreateCursor\n");
    unit_set_cursor(WIN_A, (ULONG_PTR)mono);
    ok(unit_cursor_width() == 16 && unit_cursor_height() == 2, "16x2 (got %ux%u)\n",
       unit_cursor_width(), unit_cursor_height());
    ok(unit_cursor_hot_x() == 1 && unit_cursor_hot_y() == 0, "hotspot kept (got %d,%d)\n",
       unit_cursor_hot_x(), unit_cursor_hot_y());
    ok(unit_cursor_pixel(0, 0) == 0, "AND 1 XOR 0: screen (got %08x)\n", unit_cursor_pixel(0, 0));
    ok(unit_cursor_pixel(1, 0) == 0xffffffff, "AND 0 XOR 1: white (got %08x)\n",
       unit_cursor_pixel(1, 0));
    ok(unit_cursor_pixel(2, 0) == 0xff000000, "AND 0 XOR 0: black (got %08x)\n",
       unit_cursor_pixel(2, 0));
    ok(unit_cursor_pixel(3, 0) == 0xff000000, "AND 1 XOR 1: invert, drawn black (got %08x)\n",
       unit_cursor_pixel(3, 0));
    ok(unit_cursor_pixel(0, 1) == 0 && unit_cursor_pixel(1, 1) == 0xffffffff,
       "the second row decodes the same (got %08x %08x)\n", unit_cursor_pixel(0, 1),
       unit_cursor_pixel(1, 1));
    DestroyCursor(mono);
}

/* A colour cursor with an alpha channel: the "more than 10% alpha" cut,
 * straight from a 32bpp DIB section (alphas 0, 20, 30, 255). */
static void test_cursor_color_alpha_cut(void)
{
    BITMAPINFO info;
    ICONINFO ii;
    HBITMAP color, mask;
    unsigned int *bits = NULL;
    HCURSOR cursor;

    unit_reset(SCREEN_W, SCREEN_H);
    memset(&info, 0, sizeof(info));
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = 4;
    info.bmiHeader.biHeight = -1;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    color = CreateDIBSection(NULL, &info, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    ok(color != NULL && bits != NULL, "CreateDIBSection\n");
    if (!bits)
        return;
    bits[0] = 0x00102030;
    bits[1] = 0x14405060;
    bits[2] = 0x1e708090;
    bits[3] = 0xffa0b0c0;
    mask = CreateBitmap(4, 1, 1, 1, NULL);
    memset(&ii, 0, sizeof(ii));
    ii.fIcon = FALSE;
    ii.xHotspot = 1;
    ii.yHotspot = 0;
    ii.hbmMask = mask;
    ii.hbmColor = color;
    cursor = CreateIconIndirect(&ii);
    ok(cursor != NULL, "CreateIconIndirect\n");
    unit_set_cursor(WIN_A, (ULONG_PTR)cursor);
    ok(unit_cursor_width() == 4 && unit_cursor_height() == 1, "4x1 (got %ux%u)\n",
       unit_cursor_width(), unit_cursor_height());
    ok(unit_cursor_pixel(0, 0) == 0, "alpha 0: transparent (got %08x)\n", unit_cursor_pixel(0, 0));
    ok(unit_cursor_pixel(1, 0) == 0, "alpha 20: below the cut (got %08x)\n",
       unit_cursor_pixel(1, 0));
    ok(unit_cursor_pixel(2, 0) == 0xff708090, "alpha 30: opaque, colour kept (got %08x)\n",
       unit_cursor_pixel(2, 0));
    ok(unit_cursor_pixel(3, 0) == 0xffa0b0c0, "alpha 255: opaque (got %08x)\n",
       unit_cursor_pixel(3, 0));
    DestroyCursor(cursor);
    DeleteObject(color);
    DeleteObject(mask);
}

/* handle 0 (hidden: ShowCursor below zero, a class without a cursor) is
 * an empty image; a refused publish (the pointer left the window) repairs
 * nothing and reports nothing. */
static void test_cursor_hidden_and_refused(void)
{
    HCURSOR arrow = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_cursor(WIN_A, 0);
    ok(unit_cursor_publish_count() == 1, "hidden is published (got %u)\n",
       unit_cursor_publish_count());
    ok(unit_cursor_width() == 0 && unit_cursor_height() == 0, "hidden is empty (got %ux%u)\n",
       unit_cursor_width(), unit_cursor_height());
    unit_set_pointer(200, 200);
    unit_present();
    ok(unit_pixel(200, 200) == 0, "an empty image draws nothing (got %08x)\n",
       unit_pixel(200, 200));

    unit_cursor_refuse(STATUS_INVALID_HANDLE);
    unit_set_cursor(WIN_A, (ULONG_PTR)arrow);
    ok(unit_cursor_publish_count() == 1, "a refused publish is not counted (got %u)\n",
       unit_cursor_publish_count());
    ok(unit_redraw_count() == 0, "a refused publish repairs nothing (got %u redraws)\n",
       unit_redraw_count());
}

/* The overlay: nothing at the desktop's initial (0,0); the hotspot on the
 * pointer; clipped at every edge; idempotent (the picture after two
 * presents is the picture after one, the whole no-save-under argument). */
static void test_cursor_present(void)
{
    HCURSOR ibeam = LoadCursorW(NULL, (LPCWSTR)IDC_IBEAM);
    unsigned int x, y, drawn = 0, drawn_again = 0, expected;

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_cursor(WIN_A, (ULONG_PTR)ibeam);
    /* the desktop background as the baseline: a black cursor pixel over the
     * zeroed scanout would be invisible to the census (the fill's own
     * present finds the pointer at (0,0) and draws nothing) */
    unit_repaint_rect(0, 0, SCREEN_W, SCREEN_H, 0);
    for (y = 0; y < SCREEN_H; y++)
        for (x = 0; x < SCREEN_W; x++)
            if (unit_pixel(x, y) != unit_bg())
                drawn++;
    ok(drawn == 0, "nothing drawn at the initial (0,0) (%u pixels)\n", drawn);

    unit_set_pointer(100, 100);
    unit_present();
    expected = pack(unit_cursor_pixel(3, 9));
    ok(unit_pixel(100, 100) == expected,
       "the hotspot pixel lands on the pointer (got %08x, want %08x)\n", unit_pixel(100, 100),
       expected);
    for (y = 0; y < SCREEN_H; y++)
        for (x = 0; x < SCREEN_W; x++)
            if (unit_pixel(x, y) != unit_bg())
                drawn++;
    ok(drawn == opaque_count(), "every opaque pixel and nothing else (%u drawn, %u opaque)\n",
       drawn, opaque_count());
    unit_present();
    for (y = 0; y < SCREEN_H; y++)
        for (x = 0; x < SCREEN_W; x++)
            if (unit_pixel(x, y) != unit_bg())
                drawn_again++;
    ok(drawn_again == drawn, "presenting twice changes nothing (%u vs %u)\n", drawn_again, drawn);

    /* clipped top-left: the image origin is (-2,-8), the hotspot at (1,1) */
    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_cursor(WIN_A, (ULONG_PTR)ibeam);
    unit_set_pointer(1, 1);
    unit_present();
    ok(unit_pixel(1, 1) == expected,
       "clipped at the top-left, hotspot still on the pointer (got %08x)\n", unit_pixel(1, 1));
    /* clipped bottom-right: only the pixels on screen are written */
    unit_set_pointer(SCREEN_W - 1, SCREEN_H - 1);
    unit_present();
    ok(unit_pixel(SCREEN_W - 1, SCREEN_H - 1) == expected,
       "clipped at the bottom-right, hotspot still on the pointer (got %08x)\n",
       unit_pixel(SCREEN_W - 1, SCREEN_H - 1));
}

/* A shape change is a move that stays put: the previous shape's footprint
 * at the pointer is handed to the repaint authority (the window under it
 * is invalidated there), and the new shape is drawn at once. */
static void test_cursor_change_repairs(void)
{
    HCURSOR arrow = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    HCURSOR ibeam = LoadCursorW(NULL, (LPCWSTR)IDC_IBEAM);
    int rect[4];

    unit_reset(SCREEN_W, SCREEN_H);
    unit_set_desktop(DESKTOP);
    unit_add_window(WIN_A, 100, 100, 400, 400, 100, 100, 400, 400, 1);
    unit_set_pointer(150, 150);
    unit_set_cursor(WIN_A, (ULONG_PTR)arrow);
    ok(unit_redraw_count() == 0, "the first shape has nothing to repair (got %u)\n",
       unit_redraw_count());
    ok(unit_pixel(150, 150) == pack(unit_cursor_pixel(0, 0)), "the arrow is drawn at once\n");

    unit_set_cursor(WIN_A, (ULONG_PTR)ibeam);
    ok(unit_redraw_count() == 1, "the arrow's footprint is repaired through the window (got %u)\n",
       unit_redraw_count());
    ok(unit_redraw_hwnd(0) == WIN_A, "the window under the footprint (got %x)\n",
       unit_redraw_hwnd(0));
    unit_redraw_rect(0, rect);
    ok(!unit_redraw_whole(0) && rect[0] == 50 && rect[1] == 50 && rect[2] == 82 && rect[3] == 82,
       "the arrow's 32x32 footprint, client-relative (got whole=%d %d,%d,%d,%d)\n",
       unit_redraw_whole(0), rect[0], rect[1], rect[2], rect[3]);
    ok(unit_pixel(150, 150) == pack(unit_cursor_pixel(3, 9)), "the I-beam is drawn at once\n");
}

/* The desktop default: IDC_ARROW published with the desktop flag and no
 * window, for the pump to fall back to where nobody is asked. */
static void test_cursor_desktop_default(void)
{
    unit_reset(SCREEN_W, SCREEN_H);
    unit_publish_desktop_default();
    ok(unit_cursor_publish_count() == 1, "published (got %u)\n", unit_cursor_publish_count());
    ok(unit_cursor_flags() == 1 && unit_cursor_hwnd() == 0,
       "the desktop flag, no window (got %x/%x)\n", unit_cursor_flags(), unit_cursor_hwnd());
    ok(unit_cursor_width() == 32 && unit_cursor_hot_x() == 0 && unit_cursor_hot_y() == 0,
       "the arrow (got %ux%u hot %d,%d)\n", unit_cursor_width(), unit_cursor_height(),
       unit_cursor_hot_x(), unit_cursor_hot_y());
}

START_TEST(winefbunit)
{
    test_cursor_arrow_decodes();
    test_cursor_ibeam_hotspot();
    test_cursor_mono_truth_table();
    test_cursor_color_alpha_cut();
    test_cursor_hidden_and_refused();
    test_cursor_present();
    test_cursor_change_repairs();
    test_cursor_desktop_default();
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
    test_minimize_repairs_vacated();
    test_activate_raises();
}
