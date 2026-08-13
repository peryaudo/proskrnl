/*
 * winefb.h - what the winefb.drv sources share.
 *
 * winefb.drv is the display backend for GUI-2: a Wine user driver
 * (struct user_driver_funcs) whose scanout is \Device\Fb0 (HACK-001) and
 * whose input comes from \Device\Input0 (HACK-002). docs/07: "the question
 * is never 'write win32k' -- it is 'write the smallest backend for Wine's
 * display-driver interface'".
 *
 * It is linked into win32u.dll rather than loaded as a separate module: it
 * uses win32u's internal window_surface_create, and win32u itself cannot
 * LoadLibrary. The registry/NtUserLoadDriver path a real Wine driver is
 * found through needs a desktop window and a user-mode callback that exist
 * only after the driver has been set, so the table is handed to
 * __wine_set_user_driver directly.
 */
#ifndef PRSK_WINEFB_H
#define PRSK_WINEFB_H

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "ntuser.h"
#include "wine/gdi_driver.h"

#include "drivers/fbproto.h"

/* The scanout, as \Device\Fb0 describes it. Valid once winefb_map_scanout
 * has succeeded; width == 0 means there is no framebuffer and every entry
 * point below degrades rather than drawing into nothing. */
struct winefb_scanout
{
    FB_MODE_INFO mode;
    char        *pixels;
    BOOL         bgrx;      /* the DIB byte order needs no repacking */
};

extern struct winefb_scanout winefb_scanout;

extern BOOL winefb_map_scanout(void);
extern UINT winefb_update_display_devices( const struct gdi_device_manager *manager, void *param );
extern void winefb_set_desktop_window( HWND hwnd );
extern BOOL winefb_create_window_surface( HWND hwnd, BOOL layered, const RECT *surface_rect,
                                          struct window_surface **surface );
extern void winefb_window_pos_changed( HWND hwnd, HWND insert_after, HWND owner_hint,
                                       UINT swp_flags, const struct window_rects *new_rects,
                                       struct window_surface *surface );
extern void winefb_start_input(void);

/* cursor.c: the software cursor. winefb_cursor_present is the overlay
 * every scanout writer owes back (the cursor is above everything);
 * winefb_cursor_update is the pointer thread's move. winefb_pointer_present
 * says whether this session has a pointer device at all -- no device, no
 * cursor. */
extern BOOL winefb_pointer_present;
extern void winefb_cursor_present(void);
extern void winefb_cursor_update(void);

/* compose.c: the z-order queries behind the compositing flush and the
 * uncover repair (blit.c). More top-level windows than this and the excess
 * is treated as invisible; 64 is far beyond anything the milestones put on
 * one desktop. */
#define WINEFB_MAX_TOPLEVELS 64
struct winefb_toplevel
{
    HWND hwnd;
    RECT rect;   /* window rect, screen coordinates */
    RECT client; /* client rect, screen coordinates -- what a rect-scoped
                  * invalidation can name (blit.c) */
};
extern BOOL winefb_windows_above( HWND hwnd, struct winefb_toplevel *above_list, UINT max_count,
                                  UINT *count );
extern UINT winefb_other_toplevels( HWND exclude, struct winefb_toplevel *out, UINT max_count );

/* blit.c: the desktop background. On an explorerless image the desktop
 * window is forced and foreign (docs/03 GUI-2 notes) -- no process runs its
 * WndProc, so winefb is its painter, the same authority split as an X root
 * window. With explorer (GUI-6) its PaintDesktop erases in the same color,
 * so the two painters agree by construction: the value is Wine's default
 * COLOR_BACKGROUND, RGB(58,110,165) -- re-verify against the pinned
 * dlls/win32u/sysparams.c system_colors[]. Reported on serial, never
 * assumed by a checker. */
#define WINEFB_DESKTOP_BG RGB( 0x3a, 0x6e, 0xa5 ) /* the classic desktop blue */
extern void winefb_fill_rect( const RECT *screen_rect, COLORREF color );
extern UINT winefb_pack_pixel( UINT r, UINT g, UINT b );

/* blit.c: make one screen rect show what it should again -- the single
 * repaint authority behind both the mover and the cursor. */
extern void winefb_repaint_rect( const RECT *screen_rect, HWND exclude );

/* The harness reads these off the serial log and checks the screendump
 * against them; nothing about the expected picture is hardcoded host-side
 * (tests/gui/check_window.py, the GUI-1 precedent). */
extern void winefb_report( const char *format, ... );

#endif /* PRSK_WINEFB_H */
