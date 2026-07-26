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
extern BOOL winefb_create_window_surface( HWND hwnd, BOOL layered, const RECT *surface_rect,
                                          struct window_surface **surface );
extern void winefb_window_pos_changed( HWND hwnd, HWND insert_after, HWND owner_hint,
                                       UINT swp_flags, const struct window_rects *new_rects,
                                       struct window_surface *surface );
extern void winefb_start_input(void);

/* The harness reads these off the serial log and checks the screendump
 * against them; nothing about the expected picture is hardcoded host-side
 * (tests/gui/check_window.py, the GUI-1 precedent). */
extern void winefb_report( const char *format, ... );

#endif /* PRSK_WINEFB_H */
