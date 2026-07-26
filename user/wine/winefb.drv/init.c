/*
 * init.c - the user_driver_funcs table, and the report channel.
 *
 * Three entries. __wine_set_user_driver fills every NULL with a nulldrv_*
 * default (dlls/win32u/driver.c), and for a framebuffer with no window
 * manager to negotiate with, the defaults are what we want:
 *
 *   nulldrv_WindowPosChanging returns TRUE, which is the signal that makes
 *   win32u ask for a surface at all; the keyboard entries decline, so
 *   win32u falls back to its built-in kbdus tables (input.c) - the same
 *   tables that turn the scancodes winefb injects into vkeys;
 *   nulldrv_ProcessEvents returns FALSE, which makes win32u flush window
 *   surfaces on every message wait, which is the flush clock this driver
 *   needs and would otherwise have to invent;
 *   nulldrv_GetDeviceCaps answers from the display cache that
 *   UpdateDisplayDevices populates.
 *
 * dc_funcs is left entirely zero: a driver with no pCreateDC never lands on
 * the GDI physdev stack, and dibdrv does all the drawing. winewayland.drv's
 * table has no dc_funcs either (waylanddrv_main.c), so this is the shape
 * Wine already supports rather than a shortcut.
 */

#include <stdarg.h>
#include <stdio.h>

#include "winefb.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

void winefb_report( const char *format, ... )
{
    char text[256];
    WCHAR wide[256];
    UNICODE_STRING str;
    va_list args;
    int len, i;

    va_start( args, format );
    len = vsnprintf( text, sizeof(text) - 1, format, args );
    va_end( args );
    if (len < 0) return;
    if (len > (int)sizeof(text) - 1) len = sizeof(text) - 1;

    for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
    str.Buffer = wide;
    str.Length = len * sizeof(WCHAR);
    str.MaximumLength = str.Length;
    NtDisplayString( &str );
}

static const struct user_driver_funcs winefb_funcs =
{
    .pUpdateDisplayDevices = winefb_update_display_devices,
    .pCreateWindowSurface  = winefb_create_window_surface,
    .pWindowPosChanged     = winefb_window_pos_changed,
};

void winefb_init(void)
{
    if (!winefb_map_scanout())
    {
        /* No \Device\Fb0 means this image is not a GUI image. Refusing the
         * driver outright is better than registering one that draws
         * nowhere: win32u then has no display source, and the first window
         * fails visibly instead of succeeding invisibly (Art. 12). */
        winefb_report( "[KTEST] gui2 fb ABSENT\n" );
        return;
    }

    /* Before anything asks for a display: user_driver starts out as
     * lazy_load_driver, and the first thing that touches it runs
     * load_display_driver, which goes looking in the registry for a driver
     * name and needs a desktop window to read a property off. Setting the
     * table first makes that path unreachable (dlls/win32u/driver.c,
     * init_display_driver only acts while the lazy driver is still in
     * place). The input thread is NOT started here - this runs under the
     * loader lock, and a new thread would want it back for its own
     * DLL_THREAD_ATTACH. */
    __wine_set_user_driver( &winefb_funcs, WINE_GDI_DRIVER_VERSION );
}
