/*
 * rawinput.c - the session's raw-input pump: \Device\Input0/1 into the
 * server's own hardware-message queueing.
 *
 * This is the Raw Input Thread's role, hosted where NT 3.x hosted it --
 * in the user-mode session server (csrss then, wineserver-lite here).
 * The devices hand out raw evdev events under an exclusive-open contract
 * (drivers/hidproto.h): exclusivity elects exactly one reader, because
 * the stream is consumed by reads. Before this file the electorate was
 * "whichever GUI client attempted first", and on a cold boot the winners
 * were firstboot transients, serially, until the last one exited and the
 * session had no reader left (docs/03 "GUI-4 notes"). The server opens
 * the devices at bring-up, BEFORE the transport is published, and holds
 * them for the session's lifetime; clients never open them at all (the
 * old per-client election is deleted, docs/03 "GUI-4 notes").
 *
 * Injection is the same engine a client's NtUserSendHardwareInput reaches
 * (Art. 11): each event batch becomes a send_hardware_message request run
 * through prsk_internal_dispatch (shim.c) -- the pinned handler, under the
 * server lock, with hardware origin (no SEND_HWMSG_INJECTED), for which
 * the whole pinned path is current-independent. What win32u would have
 * done CLIENT-side before the request is mirrored here, because the
 * server has no win32u to do it: the tablet's absolute axes scale to
 * screen pixels (inputmap.h -- the harness inverts the exact formula, so
 * it lives apart where it can be audited), and a scancode resolves
 * to its vkey through the kbdus tables before the request, exactly as
 * dlls/win32u/message.c server_send_hardware_message does ("wineserver
 * doesn't have access to keyboard layout tables").
 *
 * The pump is also the cursor's MOVER (cursorshape.h): the server maps
 * the scanout like any other writer and, after each batch, repaints the
 * rect the cursor vacated -- every overlapped top-level is invalidated
 * through redraw_window so its owner repaints (the same rect-scoped
 * invalidation winefb's repaint authority issues, blit.c), the uncovered
 * remainder is filled with the desktop background directly -- and draws
 * the cursor at the position the reply reports back (post-clip: the
 * server's answer, not the injected value, is where the cursor IS). The
 * SHAPE is the image the server publishes (shim.c prsk_cursor_publish):
 * the window's HCURSOR, decoded by the process that owns it. Every winefb
 * process still composites the same image over its own flushes from the
 * shared position, unchanged.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winuser.h"
#include "kbd.h"

#include "wine/server_protocol.h"
#include "wine/server.h"

#include "transport.h"
#include "shim.h"

#include "drivers/hidproto.h"
#include "drivers/fbproto.h"
#include "cursorshape.h"
#include "inputmap.h"

/* --- the kbdus scancode -> vkey tables --------------------------------------
 *
 * A verbatim copy of the pinned tree's kbdus tables (dlls/win32u/input.c
 * vsc_to_vk / vsc_to_vk_e0 / vsc_to_vk_e1, macro-identical via kbd.h) --
 * re-verify there on a pin bump. win32u resolves KEYEVENTF_SCANCODE
 * against these before its request reaches the server; the pump has no
 * win32u, so it carries the same tables and the same resolution. */

static const USHORT vsc_to_vk[] =
{
    T00, T01, T02, T03, T04, T05, T06, T07,
    T08, T09, T0A, T0B, T0C, T0D, T0E, T0F,
    T10, T11, T12, T13, T14, T15, T16, T17,
    T18, T19, T1A, T1B, T1C, T1D, T1E, T1F,
    T20, T21, T22, T23, T24, T25, T26, T27,
    T28, T29, T2A, T2B, T2C, T2D, T2E, T2F,
    T30, T31, T32, T33, T34, T35, T36 | KBDEXT, T37 | KBDMULTIVK,
    T38, T39, T3A, T3B, T3C, T3D, T3E, T3F,
    T40, T41, T42, T43, T44, T45 | KBDEXT | KBDMULTIVK, T46 | KBDMULTIVK, T47 | KBDNUMPAD | KBDSPECIAL,
    T48 | KBDNUMPAD | KBDSPECIAL, T49 | KBDNUMPAD | KBDSPECIAL, T4A, T4B | KBDNUMPAD | KBDSPECIAL,
    T4C | KBDNUMPAD | KBDSPECIAL, T4D | KBDNUMPAD | KBDSPECIAL, T4E, T4F | KBDNUMPAD | KBDSPECIAL,
    T50 | KBDNUMPAD | KBDSPECIAL, T51 | KBDNUMPAD | KBDSPECIAL, T52 | KBDNUMPAD | KBDSPECIAL,
    T53 | KBDNUMPAD | KBDSPECIAL, T54, T55, T56, T57,
    T58, T59, T5A, T5B, T5C, T5D, T5E, T5F,
    T60, T61, T62, T63, T64, T65, T66, T67,
    T68, T69, T6A, T6B, T6C, T6D, T6E, T6F,
    T70, T71, T72, T73, T74, T75, T76, T77,
    T78, T79, T7A, T7B, T7C, T7D, T7E
};

static const VSC_VK vsc_to_vk_e0[] =
{
    {0x10, X10 | KBDEXT}, {0x19, X19 | KBDEXT}, {0x1d, X1D | KBDEXT},
    {0x20, X20 | KBDEXT}, {0x21, X21 | KBDEXT}, {0x22, X22 | KBDEXT},
    {0x24, X24 | KBDEXT}, {0x2e, X2E | KBDEXT}, {0x30, X30 | KBDEXT},
    {0x32, X32 | KBDEXT}, {0x35, X35 | KBDEXT}, {0x37, X37 | KBDEXT},
    {0x38, X38 | KBDEXT}, {0x47, X47 | KBDEXT}, {0x48, X48 | KBDEXT},
    {0x49, X49 | KBDEXT}, {0x4b, X4B | KBDEXT}, {0x4d, X4D | KBDEXT},
    {0x4f, X4F | KBDEXT}, {0x50, X50 | KBDEXT}, {0x51, X51 | KBDEXT},
    {0x52, X52 | KBDEXT}, {0x53, X53 | KBDEXT}, {0x5b, X5B | KBDEXT},
    {0x5c, X5C | KBDEXT}, {0x5d, X5D | KBDEXT}, {0x5f, X5F | KBDEXT},
    {0x65, X65 | KBDEXT}, {0x66, X66 | KBDEXT}, {0x67, X67 | KBDEXT},
    {0x68, X68 | KBDEXT}, {0x69, X69 | KBDEXT}, {0x6a, X6A | KBDEXT},
    {0x6b, X6B | KBDEXT}, {0x6c, X6C | KBDEXT}, {0x6d, X6D | KBDEXT},
    {0x1c, X1C | KBDEXT}, {0x46, X46 | KBDEXT},
    {0},
};

static const VSC_VK vsc_to_vk_e1[] =
{
    {0x1d, Y1D},
    {0},
};

/* The pinned kbd_tables_init_vsc2vk, folded to the one layout this build
 * has. The pinned loop reads one entry past vsc_to_vk (<= bMaxVSCtoVK with
 * bMaxVSCtoVK = ARRAY_SIZE); iterated safely here -- scancode 0x7f is not
 * producible by prsk_key_to_scan, so no lookup can see the difference. */
static USHORT pump_vsc2vk( USHORT vsc )
{
    static USHORT table[0x300];
    static BOOL initialized;

    if (!initialized)
    {
        const VSC_VK *entry;
        UINT i;

        for (i = 0; i < ARRAYSIZE(vsc_to_vk); i++)
            if (vsc_to_vk[i] != VK__none_) table[i] = vsc_to_vk[i];
        for (entry = vsc_to_vk_e0; entry->Vsc; entry++)
            if (entry->Vk != VK__none_) table[entry->Vsc + 0x100] = entry->Vk;
        for (entry = vsc_to_vk_e1; entry->Vsc; entry++)
            if (entry->Vk != VK__none_) table[entry->Vsc + 0x200] = entry->Vk;
        initialized = TRUE;
    }
    return vsc < ARRAYSIZE(table) ? table[vsc] : 0;
}

/* --- devices and the scanout ------------------------------------------------ */

static NTSTATUS open_device( const WCHAR *path, ACCESS_MASK access, ULONG sharing, HANDLE *handle )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    NTSTATUS status;

    *handle = NULL;
    RtlInitUnicodeString( &name, path );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = NtCreateFile( handle, access, &attr, &io, NULL, FILE_ATTRIBUTE_NORMAL, sharing,
                           FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 );
    if (status) *handle = NULL;
    return status;
}

/* The scanout, mapped the way every winefb process maps it (display.c, the
 * fbproto.h sequence): the pump is one more writer of the shared pixels. */
static struct
{
    FB_MODE_INFO mode;
    char        *pixels;
} scanout;

static BOOL map_scanout(void)
{
    static const WCHAR fb0[] = {'\\','D','e','v','i','c','e','\\','F','b','0',0};
    IO_STATUS_BLOCK io;
    FB_MODE_INFO mode;
    HANDLE fb, section;
    SIZE_T view_size = 0;
    void *view = NULL;

    if (open_device( fb0, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &fb )) return FALSE;
    if (NtDeviceIoControlFile( fb, NULL, NULL, NULL, &io, IOCTL_PRSFB_GET_MODE, NULL, 0,
                               &mode, sizeof(mode) ) || io.Information != sizeof(mode))
    {
        NtClose( fb );
        return FALSE;
    }
    if (NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, fb ))
    {
        NtClose( fb );
        return FALSE;
    }
    NtClose( fb );
    if (NtMapViewOfSection( section, GetCurrentProcess(), &view, 0, 0, NULL, &view_size, ViewShare,
                            0, PAGE_READWRITE ))
    {
        NtClose( section );
        return FALSE;
    }
    NtClose( section );
    scanout.mode = mode;
    scanout.pixels = view;
    return TRUE;
}

static UINT pack_pixel( UINT r, UINT g, UINT b )
{
    const FB_MODE_INFO *mode = &scanout.mode;

    return ((r >> (8 - mode->redMaskSize)) << mode->redMaskShift) |
           ((g >> (8 - mode->greenMaskSize)) << mode->greenMaskShift) |
           ((b >> (8 - mode->blueMaskSize)) << mode->blueMaskShift);
}

static UINT *scanout_at( int x, int y )
{
    return (UINT *)(scanout.pixels + (size_t)y * scanout.mode.pitch + (size_t)x * 4);
}

static void fill_rect( const RECT *screen_rect, COLORREF color )
{
    RECT r = *screen_rect;
    UINT pixel;
    int x, y;

    if (!scanout.pixels) return;
    if (r.left < 0) r.left = 0;
    if (r.top < 0) r.top = 0;
    if (r.right > (int)scanout.mode.width) r.right = (int)scanout.mode.width;
    if (r.bottom > (int)scanout.mode.height) r.bottom = (int)scanout.mode.height;
    if (r.right <= r.left || r.bottom <= r.top) return;

    pixel = pack_pixel( GetRValue( color ), GetGValue( color ), GetBValue( color ) );
    for (y = r.top; y < r.bottom; y++)
    {
        UINT *out = scanout_at( r.left, y );
        for (x = 0; x < r.right - r.left; x++) out[x] = pixel;
    }
}

/* Draw the published image at the server-reported position -- cursor.c's
 * own draw, against the pump's mapping (cursorshape.h holds the one blit).
 * `footprint` is the unclipped rect it covered, empty when nothing was
 * drawn. */
static void draw_cursor( const struct prsk_cursor_image *image, int px, int py, RECT *footprint )
{
    footprint->left = footprint->top = footprint->right = footprint->bottom = 0;
    if (!scanout.pixels || !image->width) return;
    prsk_cursor_blit( image, px, py, scanout.pixels, scanout.mode.pitch, scanout.mode.width,
                      scanout.mode.height, pack_pixel );
    prsk_cursor_rect( image, px, py, footprint );
}

static void rect_union( RECT *dst, const RECT *a, const RECT *b )
{
    if (a->right <= a->left || a->bottom <= a->top) { *dst = *b; return; }
    if (b->right <= b->left || b->bottom <= b->top) { *dst = *a; return; }
    dst->left = min( a->left, b->left );
    dst->top = min( a->top, b->top );
    dst->right = max( a->right, b->right );
    dst->bottom = max( a->bottom, b->bottom );
}

/* --- requests through the internal dispatch --------------------------------- */

/* One request, no varargs either way. */
static unsigned int pump_request( struct __server_request_info *info )
{
    info->data_count = 0;
    if (!info->reply_data) info->u.req.request_header.reply_size = 0;
    return prsk_internal_dispatch( info );
}

static unsigned int send_hw_input( const union hw_input *input, unsigned int flags,
                                   int *new_x, int *new_y )
{
    struct __server_request_info info;
    struct send_hardware_message_request *req = &info.u.req.send_hardware_message_request;
    unsigned int ret;

    memset( &info, 0, sizeof(info) );
    req->__header.req = REQ_send_hardware_message;
    req->win = 0;      /* the reader serves the whole desktop; the server hit-tests */
    req->input = *input;
    req->flags = flags;
    ret = pump_request( &info );
    if (new_x) *new_x = info.u.reply.send_hardware_message_reply.new_x;
    if (new_y) *new_y = info.u.reply.send_hardware_message_reply.new_y;
    return ret;
}

/* The visible top-levels with screen and client rects -- compose.c
 * query_visible_toplevels, spelled as internal requests. */
struct pump_toplevel
{
    user_handle_t handle;
    RECT rect;
    RECT client;
};

#define PUMP_MAX_TOPLEVELS 64

/* -1 means the ENUMERATION failed, and the caller must treat the coverage
 * as unknown -- filling on an unknown answer painted desktop background
 * over a live window (the gui4 foreign-pixel check convicted it). 0 means
 * the desktop verifiably has no top-levels, and filling is correct. The
 * desktop is named explicitly: the synthetic record has none for the
 * request's desktop=0 fallback (shim.h prsk_internal_input_desktop). */
static int query_toplevels( unsigned int desktop, struct pump_toplevel *out, UINT max_count )
{
    user_handle_t handles[PUMP_MAX_TOPLEVELS];
    struct __server_request_info info;
    unsigned int count, i;
    UINT found = 0;

    memset( &info, 0, sizeof(info) );
    info.u.req.get_window_list_request.__header.req = REQ_get_window_list;
    info.u.req.get_window_list_request.desktop = desktop;
    info.u.req.get_window_list_request.handle = 0;
    info.u.req.get_window_list_request.tid = 0;
    info.u.req.get_window_list_request.children = 0;
    info.reply_data = handles;
    info.u.req.request_header.reply_size = sizeof(handles);
    if (prsk_internal_dispatch( &info )) return -1;
    count = info.u.reply.get_window_list_reply.count;
    if (count > PUMP_MAX_TOPLEVELS) return -1;  /* coverage unknown past the cap */

    for (i = 0; i < count && found < max_count; i++)
    {
        struct pump_toplevel *entry = &out[found];
        unsigned int style = 0;

        memset( &info, 0, sizeof(info) );
        info.u.req.get_window_info_request.__header.req = REQ_get_window_info;
        info.u.req.get_window_info_request.handle = handles[i];
        info.u.req.get_window_info_request.offset = GWL_STYLE;
        info.u.req.get_window_info_request.size = sizeof(LONG);
        if (pump_request( &info )) continue;
        style = info.u.reply.get_window_info_reply.info;
        if (!(style & WS_VISIBLE)) continue;

        memset( &info, 0, sizeof(info) );
        info.u.req.get_window_rectangles_request.__header.req = REQ_get_window_rectangles;
        info.u.req.get_window_rectangles_request.handle = handles[i];
        info.u.req.get_window_rectangles_request.relative = COORDS_SCREEN;
        if (pump_request( &info )) continue;
        entry->rect.left     = info.u.reply.get_window_rectangles_reply.window.left;
        entry->rect.top      = info.u.reply.get_window_rectangles_reply.window.top;
        entry->rect.right    = info.u.reply.get_window_rectangles_reply.window.right;
        entry->rect.bottom   = info.u.reply.get_window_rectangles_reply.window.bottom;
        entry->client.left   = info.u.reply.get_window_rectangles_reply.client.left;
        entry->client.top    = info.u.reply.get_window_rectangles_reply.client.top;
        entry->client.right  = info.u.reply.get_window_rectangles_reply.client.right;
        entry->client.bottom = info.u.reply.get_window_rectangles_reply.client.bottom;
        if (entry->rect.right <= entry->rect.left || entry->rect.bottom <= entry->rect.top)
            continue;
        entry->handle = handles[i];
        found++;
    }
    return found;
}

/* Invalidate one screen rect of one window so its owner repaints it --
 * blit.c invalidate_covered, spelled as a redraw_window request. The
 * region rides the request varargs as server rectangles; whole-window
 * (no region) when the rect reaches the frame, for the same reason. */
static void invalidate_covered( const struct pump_toplevel *window, const RECT *screen_rect )
{
    struct __server_request_info info;
    struct rectangle region;

    memset( &info, 0, sizeof(info) );
    info.u.req.redraw_window_request.__header.req = REQ_redraw_window;
    info.u.req.redraw_window_request.window = window->handle;
    info.u.req.redraw_window_request.flags = RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN;

    if (screen_rect->left >= window->client.left && screen_rect->top >= window->client.top &&
        screen_rect->right <= window->client.right && screen_rect->bottom <= window->client.bottom)
    {
        /* redraw_window regions are CLIENT-relative, like RedrawWindow's. */
        region.left   = screen_rect->left - window->client.left;
        region.top    = screen_rect->top - window->client.top;
        region.right  = screen_rect->right - window->client.left;
        region.bottom = screen_rect->bottom - window->client.top;
        info.data_count = 1;
        info.data[0].ptr = &region;
        info.data[0].size = sizeof(region);
        info.u.req.request_header.request_size = sizeof(region);
        prsk_internal_dispatch( &info );
        return;
    }
    info.u.req.redraw_window_request.flags |= RDW_FRAME;
    pump_request( &info );
}

/* vacated minus the top-levels: the fragments the desktop owns. A tiny
 * rect against few windows; the fragment list is generously capped and an
 * overflow leaves at worst a briefly-stale sliver of background. */
static void repaint_vacated( const RECT *vacated )
{
    struct pump_toplevel windows[PUMP_MAX_TOPLEVELS];
    RECT fragments[64];
    unsigned int desktop;
    int queried;
    UINT count, i, f, nfrag = 1;

    fragments[0] = *vacated;
    desktop = prsk_internal_input_desktop();
    queried = desktop ? query_toplevels( desktop, windows, PUMP_MAX_TOPLEVELS ) : -1;
    if (desktop) prsk_internal_close( desktop );
    if (queried < 0) return;    /* coverage unknown: a stale arrow beats a
                                 * blue patch on a live window; the next
                                 * writer's flush repairs it */
    count = queried;
    for (i = 0; i < count; i++)
    {
        RECT overlap;
        RECT next[64];
        UINT nnext = 0;

        overlap.left   = max( vacated->left, windows[i].rect.left );
        overlap.top    = max( vacated->top, windows[i].rect.top );
        overlap.right  = min( vacated->right, windows[i].rect.right );
        overlap.bottom = min( vacated->bottom, windows[i].rect.bottom );
        if (overlap.right > overlap.left && overlap.bottom > overlap.top)
            invalidate_covered( &windows[i], &overlap );

        /* Subtract this window from every remaining fragment: up to four
         * bands per fragment (above, below, left, right of the window). */
        for (f = 0; f < nfrag; f++)
        {
            const RECT *src = &fragments[f];
            const RECT *sub = &windows[i].rect;
            RECT band;

            if (sub->left >= src->right || sub->right <= src->left ||
                sub->top >= src->bottom || sub->bottom <= src->top)
            {
                if (nnext < ARRAYSIZE(next)) next[nnext++] = *src;
                continue;
            }
            if (sub->top > src->top)
            {
                band = *src; band.bottom = sub->top;
                if (nnext < ARRAYSIZE(next)) next[nnext++] = band;
            }
            if (sub->bottom < src->bottom)
            {
                band = *src; band.top = sub->bottom;
                if (nnext < ARRAYSIZE(next)) next[nnext++] = band;
            }
            if (sub->left > src->left)
            {
                band = *src;
                band.top = max( src->top, sub->top );
                band.bottom = min( src->bottom, sub->bottom );
                band.right = sub->left;
                if (nnext < ARRAYSIZE(next)) next[nnext++] = band;
            }
            if (sub->right < src->right)
            {
                band = *src;
                band.top = max( src->top, sub->top );
                band.bottom = min( src->bottom, sub->bottom );
                band.left = sub->right;
                if (nnext < ARRAYSIZE(next)) next[nnext++] = band;
            }
        }
        memcpy( fragments, next, nnext * sizeof(*next) );
        nfrag = nnext;
        if (!nfrag) return;
    }
    for (f = 0; f < nfrag; f++) fill_rect( &fragments[f], WINEFB_DESKTOP_BG );
}

/* The mover's whole step, after a batch injected: repaint what the cursor
 * left, draw it where the server says it now is, against the pump's own
 * mapping. Single writer for `drawn`: only the pointer thread calls this.
 *
 * The shape is whatever the server publishes (shim.c prsk_cursor_publish;
 * cursorshape.h). A shape change is a move that stays put: the publisher
 * repaired its own footprint and drew the new shape where the pointer was,
 * so the rect this step vacates is the last draw's footprint widened to
 * what the CURRENT shape covers at the old position. Over a window no
 * thread answers for, the desktop's arrow is put back first
 * (prsk_cursor_reassert_default). */
static void cursor_moved( int new_x, int new_y )
{
    static struct { int x, y; RECT rect; LONG generation; BOOL valid; } drawn;
    struct prsk_cursor_image image;
    RECT vacated, now;

    if (!scanout.pixels && !map_scanout()) return;

    prsk_cursor_reassert_default();
    if (!prsk_cursor_read( prsk_cursor_shared(), &image ))
    {
        /* The reader's spin bound fired: a write never finished. Named once
         * (Art. 12); the step goes on with nothing to draw. */
        static BOOL said;

        if (!said) prsk_log( "[KTEST] gui4 cursor read STALLED (a write never finished)\n" );
        said = TRUE;
        image.width = image.height = 0;
    }

    if (drawn.valid && (drawn.x != new_x || drawn.y != new_y || drawn.generation != image.generation))
    {
        now.left = now.top = now.right = now.bottom = 0;
        if (image.width) prsk_cursor_rect( &image, drawn.x, drawn.y, &now );
        rect_union( &vacated, &drawn.rect, &now );
        if (vacated.right > vacated.left && vacated.bottom > vacated.top) repaint_vacated( &vacated );
    }
    drawn.x = new_x;
    drawn.y = new_y;
    drawn.generation = image.generation;
    drawn.valid = TRUE;
    draw_cursor( &image, new_x, new_y, &drawn.rect );
}

/* --- the keyboard reader ---------------------------------------------------- */

static void inject_key( const HID_INPUT_EVENT *event )
{
    WORD scan = prsk_key_to_scan( event->code );
    union hw_input input;
    UINT flags, uscan;
    USHORT vkey;

    memset( &input, 0, sizeof(input) );
    input.type = INPUT_KEYBOARD;

    /* winefb's inject_key builds KEYEVENTF_SCANCODE input; win32u then
     * resolves it before the request (dlls/win32u/message.c
     * server_send_hardware_message). Both steps, mirrored: */
    flags = 0;
    if (scan & ~0xff) flags |= KEYEVENTF_EXTENDEDKEY;
    if (!event->value) flags |= KEYEVENTF_KEYUP;    /* value 2 = autorepeat = press */

    uscan = (scan & 0x300) ? scan + 0xdf00 : scan;
    if (flags & KEYEVENTF_EXTENDEDKEY) uscan |= 0xe000;
    if (uscan & 0xe000) uscan -= 0xdf00;
    vkey = pump_vsc2vk( uscan );
    switch (vkey & 0xff)    /* map_scan_to_kbd_vkey's native remaps */
    {
    case VK_PAUSE:   uscan = 0x45; break;
    case VK_RSHIFT:  uscan = 0x136; break;
    case VK_NUMLOCK: uscan = 0x145; break;
    default: break;
    }
    if (uscan & ~0xff) flags |= KEYEVENTF_EXTENDEDKEY;
    else flags &= ~KEYEVENTF_EXTENDEDKEY;

    input.kbd.vkey = vkey;
    input.kbd.scan = uscan & 0xff;
    input.kbd.flags = flags;
    input.kbd.time = 0;
    input.kbd.info = 0;
    send_hw_input( &input, 0, NULL, NULL );
}

static DWORD WINAPI input_thread( void *arg )
{
    HID_INPUT_EVENT events[32];
    IO_STATUS_BLOCK io;
    HANDLE device = arg;    /* opened by prsk_rawinput_start, pre-transport */

    for (;;)
    {
        ULONG count, i;

        if (NtReadFile( device, NULL, NULL, NULL, &io, events, sizeof(events), NULL, NULL )) break;
        count = io.Information / sizeof(events[0]);
        for (i = 0; i < count; i++)
        {
            if (events[i].type != HID_EV_KEY) continue;   /* EV_SYN and the rest */
            inject_key( &events[i] );
        }
    }
    NtClose( device );
    return 0;
}

/* --- the pointer reader ----------------------------------------------------- */

#define POINTER_MAX_CLICKS 8

struct pointer_report
{
    UINT last_x, last_y; /* raw device values; persist across reports */
    BOOL moved;          /* an axis changed since the last SYN */
    int rel_x, rel_y;    /* a relative device's deltas since the last SYN */
    BOOL moved_rel;
    UINT buttons;        /* bit 0/1/2 = left/right/middle, for the marker */
    union hw_input clicks[POINTER_MAX_CLICKS];
    UINT click_count;
    int screen_x, screen_y; /* last injected position */
    int cursor_x, cursor_y; /* where the server says the cursor ended up */
};

static void inject_pointer( union hw_input *input, struct pointer_report *report )
{
    int x = report->cursor_x, y = report->cursor_y;

    /* SEND_HWMSG_RAWINPUT with no raw data, hwnd 0: winefb's own injection
     * flags (input.c inject_pointer -> win32u, raw_count 0). */
    if (!send_hw_input( input, SEND_HWMSG_RAWINPUT, &x, &y ))
    {
        report->cursor_x = x;
        report->cursor_y = y;
    }
}

static void pointer_add_click( struct pointer_report *report, unsigned int flags, unsigned int data )
{
    union hw_input *input;

    if (report->click_count >= POINTER_MAX_CLICKS) return;
    input = &report->clicks[report->click_count++];
    memset( input, 0, sizeof(*input) );
    input->type = INPUT_MOUSE;
    input->mouse.flags = flags;
    input->mouse.data = data;
}

static void pointer_flush_report( struct pointer_report *report, const HID_ABS_INFO *abs )
{
    UINT i;

    /* Motion first: a button in the same report belongs at the report's
     * position (server/queue.c queue_mouse_message stamps buttons with the
     * position it already has). */
    if (report->moved)
    {
        union hw_input input;

        memset( &input, 0, sizeof(input) );
        report->screen_x = prsk_scale_axis( report->last_x, abs->minX, abs->maxX,
                                            scanout.mode.width );
        report->screen_y = prsk_scale_axis( report->last_y, abs->minY, abs->maxY,
                                            scanout.mode.height );
        input.type = INPUT_MOUSE;
        input.mouse.x = report->screen_x;
        input.mouse.y = report->screen_y;
        input.mouse.flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;
        inject_pointer( &input, report );
        report->moved = FALSE;
    }
    /* A relative device (USB-1's boot mouse, drivers/hidproto.h: its abs
     * range is all zeros) moves the cursor the way mouse_event does: a
     * MOUSEEVENTF_MOVE without ABSOLUTE is a delta from wherever the server
     * has the cursor, clipped by the server (queue.c queue_mouse_message).
     * The position the server answers is the one reported and drawn. */
    if (report->moved_rel)
    {
        union hw_input input;

        memset( &input, 0, sizeof(input) );
        input.type = INPUT_MOUSE;
        input.mouse.x = report->rel_x;
        input.mouse.y = report->rel_y;
        input.mouse.flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_MOVE_NOCOALESCE;
        inject_pointer( &input, report );
        report->screen_x = report->cursor_x;
        report->screen_y = report->cursor_y;
        report->rel_x = report->rel_y = 0;
        report->moved_rel = FALSE;
    }
    for (i = 0; i < report->click_count; i++) inject_pointer( &report->clicks[i], report );
    report->click_count = 0;
}

static HID_ABS_INFO pointer_abs;    /* filled by prsk_rawinput_start */

static DWORD WINAPI pointer_thread( void *arg )
{
    HID_INPUT_EVENT events[32];
    struct pointer_report report = { 0 };
    const HID_ABS_INFO abs = pointer_abs;
    IO_STATUS_BLOCK io;
    HANDLE device = arg;    /* opened by prsk_rawinput_start, pre-transport */

    for (;;)
    {
        ULONG count, i;
        BOOL flushed = FALSE;

        if (NtReadFile( device, NULL, NULL, NULL, &io, events, sizeof(events), NULL, NULL )) break;
        count = io.Information / sizeof(events[0]);
        for (i = 0; i < count; i++)
        {
            const HID_INPUT_EVENT *event = &events[i];

            switch (event->type)
            {
            case HID_EV_ABS:
                if (event->code == HID_ABS_X) { report.last_x = event->value; report.moved = TRUE; }
                else if (event->code == HID_ABS_Y) { report.last_y = event->value; report.moved = TRUE; }
                break;
            case HID_EV_KEY:
                switch (event->code)
                {
                case HID_BTN_LEFT:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_LEFTDOWN
                                                             : MOUSEEVENTF_LEFTUP, 0 );
                    report.buttons = event->value ? report.buttons | 1 : report.buttons & ~1u;
                    break;
                case HID_BTN_RIGHT:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_RIGHTDOWN
                                                             : MOUSEEVENTF_RIGHTUP, 0 );
                    report.buttons = event->value ? report.buttons | 2 : report.buttons & ~2u;
                    break;
                case HID_BTN_MIDDLE:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_MIDDLEDOWN
                                                             : MOUSEEVENTF_MIDDLEUP, 0 );
                    report.buttons = event->value ? report.buttons | 4 : report.buttons & ~4u;
                    break;
                }
                break;
            case HID_EV_REL:
                /* One wheel detent is WHEEL_DELTA, same sign. */
                if (event->code == HID_REL_WHEEL)
                    pointer_add_click( &report, MOUSEEVENTF_WHEEL,
                                       (DWORD)((int)event->value * WHEEL_DELTA) );
                else if (event->code == HID_REL_X)
                {
                    report.rel_x += (int)event->value;
                    report.moved_rel = TRUE;
                }
                else if (event->code == HID_REL_Y)
                {
                    report.rel_y += (int)event->value;
                    report.moved_rel = TRUE;
                }
                break;
            case HID_EV_SYN:
                if (report.moved || report.moved_rel || report.click_count)
                {
                    pointer_flush_report( &report, &abs );
                    flushed = TRUE;
                }
                break;
            }
        }
        /* One line per drained batch (the harness gates on it), and the
         * cursor follows the batch's final position -- the position the
         * SERVER answered, which a ClipCursor may have narrowed. */
        if (flushed)
        {
            cursor_moved( report.cursor_x, report.cursor_y );
            prsk_log( "[KTEST] gui4 ptr x=%d y=%d btn=%x\n", report.screen_x,
                      report.screen_y, (unsigned)report.buttons );
        }
    }
    NtClose( device );
    return 0;
}

/* --- bring-up ---------------------------------------------------------------- */

void prsk_rawinput_start(void)
{
    static const WCHAR input0[] =
        {'\\','D','e','v','i','c','e','\\','I','n','p','u','t','0',0};
    static const WCHAR input1[] =
        {'\\','D','e','v','i','c','e','\\','I','n','p','u','t','1',0};
    IO_STATUS_BLOCK io;
    HANDLE keyboard, pointer;
    HANDLE thread;
    NTSTATUS status;

    /* The exclusive opens happen HERE, synchronously, before the caller
     * publishes the transport: a claim that raced client start-up would be
     * a claim that can lose, and losing is the whole bug. Exclusive by
     * contract (drivers/hidproto.h): sharing 0. */
    /* ABSENT is for a device that is not there; any other failure is a
     * FAULT and says so by status -- an absence marker over a real fault
     * would read as "keyboard-less image" on an image that has one. */
    switch (status = open_device( input0, FILE_GENERIC_READ | SYNCHRONIZE, 0, &keyboard ))
    {
    case STATUS_SUCCESS:
        break;
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
        /* No keyboard: keyboard-less images say so once and stand alone. */
        prsk_log( "[KTEST] gui2 input ABSENT\n" );
        break;
    default:
        prsk_log( "[KTEST] gui2 input FAULT open %08x\n", status );
        break;
    }

    switch (status = open_device( input1, FILE_GENERIC_READ | SYNCHRONIZE, 0, &pointer ))
    {
    case STATUS_SUCCESS:
        break;
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
        /* No pointer: keyboard-only images say so once. No cursor either --
         * with no mover the published position never leaves the desktop's
         * initial (0,0), which every client's winefb refuses to draw at
         * (cursor.c cursor_position); absence needs no flag. */
        prsk_log( "[KTEST] gui4 mouse ABSENT\n" );
        break;
    default:
        prsk_log( "[KTEST] gui4 mouse FAULT open %08x\n", status );
        break;
    }
    /* The device's own range, once (it cannot change: the device model
     * fixes it before DRIVER_OK). Scaling also needs the scanout mode, and
     * the map is what the cursor draws into; a GUI boot always has
     * \Device\Fb0, so refusing loudly beats scaling to pixel 0 (Art. 12). */
    if (pointer &&
        (NtDeviceIoControlFile( pointer, NULL, NULL, NULL, &io, IOCTL_PRSHID_GET_ABS_INFO,
                                NULL, 0, &pointer_abs, sizeof(pointer_abs) ) ||
         io.Information != sizeof(pointer_abs)))
    {
        prsk_log( "[KTEST] gui4 mouse FAULT absinfo\n" );
        NtClose( pointer );
        pointer = NULL;
    }
    if (pointer && !map_scanout())
    {
        prsk_log( "[KTEST] gui4 mouse FAULT scanout\n" );
        NtClose( pointer );
        pointer = NULL;
    }

    /* Wine's own cast for a DWORD-returning routine (dlls/kernelbase/thread.c,
     * CreateRemoteThreadEx): the return value becomes the thread's exit
     * status. Same idiom as shim.c's timeout thread. The READY markers
     * print only once the reading thread exists -- a claimed device nobody
     * drains is not a reader. */
    if (keyboard)
    {
        if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                              (PRTL_THREAD_START_ROUTINE)input_thread, keyboard,
                              0, 0, 0, 0, NULL ))
        {
            prsk_log( "[KTEST] wineserver-lite: no keyboard reader thread\n" );
            NtClose( keyboard );
        }
        else
        {
            NtClose( thread );
            prsk_log( "[KTEST] gui2 input READY\n" );
        }
    }

    if (pointer)
    {
        if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                              (PRTL_THREAD_START_ROUTINE)pointer_thread, pointer,
                              0, 0, 0, 0, NULL ))
        {
            prsk_log( "[KTEST] wineserver-lite: no pointer reader thread\n" );
            NtClose( pointer );
        }
        else
        {
            NtClose( thread );
            prsk_log( "[KTEST] gui4 mouse READY abs=%u..%u,%u..%u\n", (unsigned)pointer_abs.minX,
                      (unsigned)pointer_abs.maxX, (unsigned)pointer_abs.minY,
                      (unsigned)pointer_abs.maxY );
        }
    }
}
