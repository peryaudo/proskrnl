/*
 * display.c - \Device\Fb0, and the one display device it makes.
 *
 * The mapping sequence is the one drivers/fbproto.h documents and
 * tests/gui/gui_smoke.c already proved at GUI-1: open the device, ask for
 * the mode, make a section over the handle, map it. \Device\Fb0 implements
 * the vfs GetCache op, so NtCreateSection + NtMapViewOfSection reach the
 * scanout's own physical pages through the ordinary Mm path - there is no
 * framebuffer-specific mapping call and no new Mm machinery.
 *
 * There is exactly one mode, because Limine set it through the VGA BIOS's
 * VBE before the kernel started and nothing can change it (HACK-001: no
 * mode set path exists). So the enumeration is one GPU, one source, one
 * monitor, one mode - which is also all a single-desktop milestone needs.
 */

#include "winefb.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

struct winefb_scanout winefb_scanout;

static HANDLE open_device( const WCHAR *path, ACCESS_MASK access, ULONG sharing )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE handle = NULL;

    RtlInitUnicodeString( &name, path );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtCreateFile( &handle, access | SYNCHRONIZE, &attr, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                      sharing, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 ))
        return NULL;
    return handle;
}

BOOL winefb_map_scanout(void)
{
    static const WCHAR fb0[] =
        {'\\','D','e','v','i','c','e','\\','F','b','0',0};
    IO_STATUS_BLOCK io;
    HANDLE fb, section;
    void *view = NULL;
    SIZE_T view_size = 0;
    FB_MODE_INFO mode;

    winefb_report( "[KTEST] gui2 fb opening\n" );
    if (winefb_scanout.pixels) return TRUE;

    if (!(fb = open_device( fb0, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0 )))
    {
        WARN( "no \\Device\\Fb0\n" );
        return FALSE;
    }
    if (NtDeviceIoControlFile( fb, NULL, NULL, NULL, &io, IOCTL_PRSFB_GET_MODE, NULL, 0,
                               &mode, sizeof(mode) ) || io.Information != sizeof(mode))
    {
        ERR( "IOCTL_PRSFB_GET_MODE failed\n" );
        NtClose( fb );
        return FALSE;
    }
    if (NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, fb ))
    {
        ERR( "cannot section the framebuffer\n" );
        NtClose( fb );
        return FALSE;
    }
    NtClose( fb );
    if (NtMapViewOfSection( section, GetCurrentProcess(), &view, 0, 0, NULL, &view_size, ViewShare,
                            0, PAGE_READWRITE ))
    {
        ERR( "cannot map the framebuffer\n" );
        NtClose( section );
        return FALSE;
    }
    NtClose( section );

    winefb_scanout.mode = mode;
    winefb_scanout.pixels = view;
    /* A BI_RGB 32bpp DIB is 0x00RRGGBB little-endian, i.e. the bytes
     * B,G,R,X. When the scanout says the same, a flush is a memcpy per row;
     * anything else has to be repacked pixel by pixel (blit.c). */
    winefb_scanout.bgrx = (mode.bpp == 32 && mode.redMaskShift == 16 && mode.redMaskSize == 8 &&
                           mode.greenMaskShift == 8 && mode.greenMaskSize == 8 &&
                           mode.blueMaskShift == 0 && mode.blueMaskSize == 8);

    winefb_report( "[KTEST] gui2 mode w=%u h=%u pitch=%u bpp=%u bgrx=%u\n",
                   (unsigned)mode.width, (unsigned)mode.height, (unsigned)mode.pitch,
                   (unsigned)mode.bpp, winefb_scanout.bgrx ? 1u : 0u );
    return TRUE;
}

/* The desktop window is born with empty rects, and this driver entry sizes
 * it to the scanout — the same repair X11DRV_SetDesktopWindow makes when it
 * finds the rects uninitialized (dlls/winex11.drv/window.c). On an
 * explorer-bearing image (gui6, GUI-6) the hook fires where it fires on
 * Wine: in explorer's own process, during its CreateWindowExW of the
 * desktop window, before explorer's SetWindowPos. On an explorerless image
 * it fires in whichever app force-created the desktop (the GUI-2 fixture,
 * docs/03) and is the only sizing the window ever gets. The scanout mode
 * is the driver's whole truth about the display (one mode, HACK-001), so
 * it is the size used directly. */
void winefb_set_desktop_window( HWND hwnd )
{
    unsigned int width, height;

    if (!winefb_scanout.pixels) return;

    SERVER_START_REQ( get_window_rectangles )
    {
        req->handle = wine_server_user_handle( hwnd );
        req->relative = COORDS_CLIENT;
        wine_server_call( req );
        width  = reply->window.right;
        height = reply->window.bottom;
    }
    SERVER_END_REQ;

    if (!width && !height)  /* not initialized yet */
    {
        RECT rect = { 0, 0, winefb_scanout.mode.width, winefb_scanout.mode.height };

        SERVER_START_REQ( set_window_pos )
        {
            req->handle        = wine_server_user_handle( hwnd );
            req->previous      = 0;
            req->swp_flags     = SWP_NOZORDER;
            req->window        = wine_server_rectangle( rect );
            req->client        = req->window;
            wine_server_call( req );
        }
        SERVER_END_REQ;

        /* Someone must ground the scanout in the background color before
         * windows composite over it. With explorer (GUI-6) its WM_ERASEBKGND
         * -> PaintDesktop paints the same COLOR_BACKGROUND blue through the
         * ordinary surface path; this direct fill still runs first -- in
         * explorer's process, the moment that sizes the window -- so the
         * scanout is never the boot framebuffer while explorer's first
         * paint is still in flight. Under the explorerless fixture the
         * desktop window is forced and foreign, no process runs its
         * WndProc, and this fill plus the uncover repair (blit.c) IS the
         * desktop painter -- the same authority split as an X root window.
         * The checkers sample the background rather than assume it; this
         * line is what they sample against. */
        winefb_fill_rect( &rect, WINEFB_DESKTOP_BG );
        winefb_report( "[KTEST] gui2 desktop w=%u h=%u bg=%02x%02x%02x\n",
                       (unsigned)winefb_scanout.mode.width, (unsigned)winefb_scanout.mode.height,
                       GetRValue( WINEFB_DESKTOP_BG ), GetGValue( WINEFB_DESKTOP_BG ),
                       GetBValue( WINEFB_DESKTOP_BG ) );
    }
}

UINT winefb_update_display_devices( const struct gdi_device_manager *manager, void *param )
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;
    struct pci_id pci_id = { 0 };
    struct gdi_monitor monitor = { 0 };
    DEVMODEW current = { .dmSize = sizeof(current) };

    if (!winefb_scanout.pixels) return STATUS_UNSUCCESSFUL;

    /* Display enumeration is certainly off the loader lock, so it is one of
     * the points the input reader may start from. It is no longer the only
     * one: once the display cache is warm in the registry, a client can run
     * its whole life without this entry being called (the GUI-3 logs proved
     * it), so the first window surface is a second chance (blit.c).
     * winefb_start_input itself is idempotent. */
    winefb_start_input();

    current.dmFields = DM_DISPLAYORIENTATION | DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT |
                       DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY;
    current.dmDisplayOrientation = DMDO_DEFAULT;
    current.dmBitsPerPel = mode->bpp;
    current.dmPelsWidth = mode->width;
    current.dmPelsHeight = mode->height;
    /* Nothing reports a refresh rate: Limine's VBE mode carries none, and
     * QEMU's stdvga has no vertical blank to count. 60 is what every other
     * Wine driver reports for a mode it cannot measure. */
    current.dmDisplayFrequency = 60;

    SetRect( &monitor.rc_monitor, 0, 0, mode->width, mode->height );
    monitor.rc_work = monitor.rc_monitor;

    manager->add_gpu( NULL, &pci_id, NULL, param );
    manager->add_source( "Fb0", DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE |
                                DISPLAY_DEVICE_VGA_COMPATIBLE,
                         NtUserGetSystemDpiForProcess( NULL ), param );
    manager->add_monitor( &monitor, param );

    current.dmFields |= DM_POSITION;
    current.dmPosition.x = 0;
    current.dmPosition.y = 0;
    manager->add_modes( &current, 1, &current, param );
    return STATUS_SUCCESS;
}
