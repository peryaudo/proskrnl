/*
 * winefb_mocks.c - the seam behind the winefb compositor, mocked (docs/08).
 *
 * The unit half of the compositor verdict: compose.c and blit.c are linked
 * UNMODIFIED (the same objects the win32u.dll link uses), and this file
 * supplies everything they reach for -- the wineserver round-trips, the
 * window-surface plumbing, the scanout, the cross-process invalidation --
 * as a fixture the test script can load and interrogate. What stays REAL
 * is the region algebra: NtGdi* forwards to gdi32, and the binary runs
 * under the pinned Wine (tests/run/run.sh winefbunit), so the engine doing
 * the subtraction is the same Wine region code the shipped driver leans on
 * (G10 -- no second implementation, not even for the test).
 *
 * Compiled with the driver's own flags and include stack (Makefile
 * WINEFB_UNIT rules): this file lives in wine-header land, and the test
 * script (winefb_unit.c, ntapi-harness land) talks to it only through the
 * plain-integer API in winefb_unit.h -- the two header worlds never meet
 * in one translation unit.
 */

#include <pthread.h>
#include <stdarg.h>

#include "winefb.h"
#include "ntgdi.h"
#include "win32u_private.h"
#include "ntuser_private.h"
#include "wine/server.h"
#include "wine/debug.h"

#include "winefb_unit.h"

/* the activation raise's record (filled by the wine_server_call dispatcher,
 * read back through the unit_raise_* API below) */
static struct
{
    user_handle_t hwnd;
    user_handle_t after;
    unsigned int flags;
    unsigned int paint_flags;
    unsigned int extra_count;
} raises[UNIT_MAX_REDRAWS];
static unsigned int raise_count;

static struct window_surface **held_slot(user_handle_t hwnd);
static void remember_handle(user_handle_t hwnd);

/* --- libc the driver objects expect (the exe links no CRT) --------------- */

/* Under WINE_UNIX_LIB this is a call, not the PE headers' inline TEB read;
 * the definition is the inline one, the srv_glue.c spelling. */
struct _TEB *WINAPI NtCurrentTeb(void)
{
    struct _TEB *teb;

    __asm__("movq %%gs:0x30,%0" : "=r"(teb));
    return teb;
}

void *malloc(size_t size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void free(void *ptr)
{
    if (ptr)
        HeapFree(GetProcessHeap(), 0, ptr);
}

/* single-threaded here; the driver's tracker lock needs the symbols only */
int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    return 0;
}

int abs(int value)
{
    return value < 0 ? -value : value;
}

/* --- wine/debug.h ---------------------------------------------------------
 *
 * Every channel answers "off", so TRACE/WARN/ERR compile to nothing at run
 * time; the four externs still have to exist to link. */

unsigned char __cdecl __wine_dbg_get_channel_flags(struct __wine_debug_channel *channel)
{
    return 0;
}

const char *__cdecl __wine_dbg_strdup(const char *str)
{
    return str;
}

int __cdecl __wine_dbg_output(const char *str)
{
    return 0;
}

int __cdecl __wine_dbg_header(enum __wine_debug_class cls, struct __wine_debug_channel *channel,
                              const char *function)
{
    return -1;
}

/* --- the driver globals display.c/input.c/cursor.c/init.c would provide -- */

struct winefb_scanout winefb_scanout;
BOOL winefb_pointer_present;

void winefb_cursor_present(void)
{
}

void winefb_cursor_update(void)
{
}

void winefb_start_input(void)
{
}

static unsigned int report_count;

void winefb_report(const char *format, ...)
{
    /* the unit verdict comes from the harness, not from serial lines; the
     * COUNT is observable so a case can assert a refusal was loud */
    report_count++;
}

unsigned int unit_report_count(void)
{
    return report_count;
}

/* --- the fixture: what the "server" answers -------------------------------
 *
 * A flat desktop model: one desktop window handle and a topmost-first list
 * of top-level windows, exactly the order get_window_list replies with
 * (the shallow_window_from_point walk). */

struct fixture_window
{
    user_handle_t hwnd;
    RECT rect;   /* window rect, screen */
    RECT client; /* client rect, screen */
    int visible;
};

static struct fixture_window fixture[UNIT_MAX_WINDOWS];
static unsigned int fixture_count;
static user_handle_t fixture_desktop;

static struct fixture_window *fixture_find(user_handle_t hwnd)
{
    unsigned int i;

    for (i = 0; i < fixture_count; i++)
        if (fixture[i].hwnd == hwnd)
            return &fixture[i];
    return NULL;
}

void unit_add_window(unsigned int hwnd, int left, int top, int right, int bottom, int clientLeft,
                     int clientTop, int clientRight, int clientBottom, int visible)
{
    struct fixture_window *win;

    if (fixture_count >= UNIT_MAX_WINDOWS)
        return;
    win = &fixture[fixture_count++];
    win->hwnd = hwnd;
    SetRect(&win->rect, left, top, right, bottom);
    SetRect(&win->client, clientLeft, clientTop, clientRight, clientBottom);
    win->visible = visible;
}

void unit_set_desktop(unsigned int hwnd)
{
    fixture_desktop = hwnd;
}

void unit_set_visible(unsigned int hwnd, int visible)
{
    struct fixture_window *win = fixture_find(hwnd);

    if (win)
        win->visible = visible;
}

/* --- wine_server_call: the four raw requests compose.c issues ------------ */

unsigned int CDECL wine_server_call(void *req_ptr)
{
    struct __server_request_info *info = req_ptr;

    switch (info->u.req.request_header.req)
    {
    case REQ_get_window_list:
    {
        user_handle_t *out = info->reply_data;
        unsigned int i, max = info->u.req.request_header.reply_size / sizeof(*out);
        unsigned int n = 0;

        for (i = 0; i < fixture_count; i++)
        {
            if (n < max)
                out[n] = fixture[i].hwnd;
            n++;
        }
        info->u.reply.get_window_list_reply.count = n;
        return 0;
    }
    case REQ_get_window_info:
    {
        const struct get_window_info_request *req = &info->u.req.get_window_info_request;
        struct fixture_window *win = fixture_find(req->handle);

        if (!win)
            return STATUS_INVALID_HANDLE;
        info->u.reply.get_window_info_reply.info = win->visible ? WS_VISIBLE : 0;
        return 0;
    }
    case REQ_get_window_rectangles:
    {
        const struct get_window_rectangles_request *req =
            &info->u.req.get_window_rectangles_request;
        struct get_window_rectangles_reply *reply = &info->u.reply.get_window_rectangles_reply;
        struct fixture_window *win = fixture_find(req->handle);

        if (!win)
            return STATUS_INVALID_HANDLE;
        reply->window.left = win->rect.left;
        reply->window.top = win->rect.top;
        reply->window.right = win->rect.right;
        reply->window.bottom = win->rect.bottom;
        reply->client.left = win->client.left;
        reply->client.top = win->client.top;
        reply->client.right = win->client.right;
        reply->client.bottom = win->client.bottom;
        return 0;
    }
    case REQ_get_desktop_window:
        info->u.reply.get_desktop_window_reply.top_window = fixture_desktop;
        return 0;
    case REQ_set_window_pos:
    {
        /* the activation raise: recorded, never restacked -- the band and
         * exposure semantics belong to the pinned server (link_window) */
        const struct set_window_pos_request *req = &info->u.req.set_window_pos_request;

        if (raise_count < UNIT_MAX_REDRAWS)
        {
            raises[raise_count].hwnd = req->handle;
            raises[raise_count].after = req->previous;
            raises[raise_count].flags = req->swp_flags;
            raises[raise_count].paint_flags = req->paint_flags;
            raises[raise_count].extra_count =
                info->u.req.request_header.request_size / sizeof(RECT);
        }
        raise_count++;
        return 0;
    }
    default:
        return STATUS_NOT_IMPLEMENTED; /* the unit seam is five requests wide */
    }
}

/* --- NtGdi regions: gdi32, the same engine --------------------------------- */

HRGN WINAPI NtGdiCreateRectRgn(INT left, INT top, INT right, INT bottom)
{
    return CreateRectRgn(left, top, right, bottom);
}

BOOL WINAPI NtGdiSetRectRgn(HRGN hrgn, INT left, INT top, INT right, INT bottom)
{
    return SetRectRgn(hrgn, left, top, right, bottom);
}

INT WINAPI NtGdiCombineRgn(HRGN dest, HRGN src1, HRGN src2, INT mode)
{
    return CombineRgn(dest, src1, src2, mode);
}

BOOL WINAPI NtGdiDeleteObjectApp(HGDIOBJ obj)
{
    return DeleteObject(obj);
}

DWORD WINAPI NtGdiGetRegionData(HRGN hrgn, DWORD count, RGNDATA *data)
{
    return GetRegionData(hrgn, count, data);
}

/* --- NtUserRedrawWindow: recorded, never executed ------------------------- */

static struct
{
    user_handle_t hwnd;
    RECT rect;
    int whole; /* NULL rect: whole window + frame */
    unsigned int flags;
} redraws[UNIT_MAX_REDRAWS];
static unsigned int redraw_count;

BOOL WINAPI NtUserRedrawWindow(HWND hwnd, const RECT *rect, HRGN hrgn, UINT flags)
{
    if (redraw_count < UNIT_MAX_REDRAWS)
    {
        redraws[redraw_count].hwnd = (user_handle_t)(UINT_PTR)hwnd;
        redraws[redraw_count].whole = !rect;
        if (rect)
            redraws[redraw_count].rect = *rect;
        else
            SetRectEmpty(&redraws[redraw_count].rect);
        redraws[redraw_count].flags = flags;
    }
    redraw_count++;
    return TRUE;
}

/* --- the activation raise's seam ------------------------------------------
 *
 * The raise is a raw set_window_pos request (recorded in the dispatcher
 * above); what the hook needs client-side is the window's cached rects and
 * surface, which win32u keeps behind get_win_ptr. The mock serves a
 * fabricated WND from the fixture, with the held surface attached. */

struct window_surface dummy_surface; /* the driver compares against its address only */

void user_unlock(void)
{
    /* release_win_ptr's inline body; the mock takes no lock */
}

static WND mock_wnd;

WND *get_win_ptr(HWND hwnd)
{
    struct fixture_window *win = fixture_find((user_handle_t)(UINT_PTR)hwnd);
    struct window_surface **slot = held_slot((user_handle_t)(UINT_PTR)hwnd);

    if (!win)
        return WND_OTHER_PROCESS;
    memset(&mock_wnd, 0, sizeof(mock_wnd));
    mock_wnd.rects.window = win->rect;
    mock_wnd.rects.client = win->client;
    mock_wnd.rects.visible = win->rect;
    mock_wnd.surface = slot ? *slot : NULL;
    return &mock_wnd;
}

/* the async key state the click gate reads: nonzero = a button is down */
/* The click gate reads the thread's input-message source the way win32u
 * does (get_user_thread_info()->client_info->msg_source); the mock serves
 * a static thread-info block the fixture writes the way the hardware
 * dispatch would. */
static struct ntuser_thread_info mock_client_info;
static struct user_thread_info mock_thread_info;

struct user_thread_info *get_user_thread_info(void)
{
    mock_thread_info.client_info = &mock_client_info;
    return &mock_thread_info;
}

void unit_set_button_down(int down)
{
    mock_client_info.msg_source.deviceType = down ? IMDT_MOUSE : IMDT_UNAVAILABLE;
}

/* NtUserGetDesktopWindow is an ntuser.h inline over this entry point */
ULONG_PTR WINAPI NtUserCallNoParam(ULONG code)
{
    if (code == NtUserCallNoParam_GetDesktopWindow)
        return fixture_desktop;
    return 0;
}

/* every fixture window is a top-level: its root is itself */
HWND WINAPI NtUserGetAncestor(HWND hwnd, UINT type)
{
    return hwnd;
}

void unit_activate(unsigned int hwnd, unsigned int previous)
{
    winefb_activate_window((HWND)(UINT_PTR)hwnd, (HWND)(UINT_PTR)previous);
}

unsigned int unit_raise_count(void)
{
    return raise_count;
}

unsigned int unit_raise_hwnd(unsigned int i)
{
    return i < raise_count ? raises[i].hwnd : 0;
}

unsigned int unit_raise_after(unsigned int i)
{
    return i < raise_count ? raises[i].after : 0xdeadbeef;
}

unsigned int unit_raise_flags(unsigned int i)
{
    return i < raise_count ? raises[i].flags : 0;
}

int unit_raise_carries_surface(unsigned int i)
{
    if (i >= raise_count)
        return -1;
    /* the request must preserve the load-bearing rects (visible + surface
     * as extra data) and keep the surface paint flag, or the server's
     * stored state degrades (blit.c winefb_activate_window) */
    return raises[i].extra_count == 2 && (raises[i].paint_flags & SET_WINPOS_PAINT_SURFACE) != 0;
}

unsigned int unit_redraw_count(void)
{
    return redraw_count;
}

unsigned int unit_redraw_hwnd(unsigned int i)
{
    return i < redraw_count ? redraws[i].hwnd : 0;
}

int unit_redraw_whole(unsigned int i)
{
    return i < redraw_count ? redraws[i].whole : -1;
}

void unit_redraw_rect(unsigned int i, int out[4])
{
    out[0] = out[1] = out[2] = out[3] = 0;
    if (i >= redraw_count)
        return;
    out[0] = redraws[i].rect.left;
    out[1] = redraws[i].rect.top;
    out[2] = redraws[i].rect.right;
    out[3] = redraws[i].rect.bottom;
}

/* --- window surfaces: the two dce.c entry points blit.c uses -------------- */

struct mock_surface
{
    struct window_surface *surface;
    char *pixels; /* 32bpp top-down, rect-sized */
    struct mock_surface *next;
};

static struct mock_surface *mock_surfaces;

static struct mock_surface *mock_from_surface(struct window_surface *surface)
{
    struct mock_surface *mock;

    for (mock = mock_surfaces; mock; mock = mock->next)
        if (mock->surface == surface)
            return mock;
    return NULL;
}

struct window_surface *window_surface_create(UINT size, const struct window_surface_funcs *funcs,
                                             HWND hwnd, const RECT *rect, BITMAPINFO *info,
                                             HBITMAP bitmap)
{
    struct window_surface *surface;
    struct mock_surface *mock;
    UINT width = rect->right - rect->left, height = rect->bottom - rect->top;

    if (!(surface = malloc(size)))
        return NULL;
    memset(surface, 0, size);
    surface->funcs = funcs;
    surface->ref = 1;
    surface->hwnd = hwnd;
    surface->rect = *rect;

    if (!(mock = malloc(sizeof(*mock))))
    {
        free(surface);
        return NULL;
    }
    mock->surface = surface;
    mock->pixels = malloc((size_t)width * height * 4);
    memset(mock->pixels, 0, (size_t)width * height * 4);
    mock->next = mock_surfaces;
    mock_surfaces = mock;
    return surface;
}

void window_surface_add_ref(struct window_surface *surface)
{
    surface->ref++;
}

void window_surface_release(struct window_surface *surface)
{
    struct mock_surface **link, *mock;

    if (--surface->ref)
        return;
    surface->funcs->destroy(surface);
    for (link = &mock_surfaces; (mock = *link); link = &mock->next)
    {
        if (mock->surface != surface)
            continue;
        *link = mock->next;
        free(mock->pixels);
        free(mock);
        break;
    }
    free(surface);
}

void window_surface_lock(struct window_surface *surface)
{
}

void window_surface_unlock(struct window_surface *surface)
{
}

void window_surface_flush(struct window_surface *surface)
{
    char info_buffer[FIELD_OFFSET(BITMAPINFO, bmiColors[256])];
    BITMAPINFO *info = (BITMAPINFO *)info_buffer;
    struct mock_surface *mock = mock_from_surface(surface);
    RECT dirty = surface->rect, bounds = surface->bounds;

    if (!mock)
        return;
    OffsetRect(&dirty, -dirty.left, -dirty.top);
    if (!intersect_rect(&dirty, &dirty, &bounds))
        return;

    memset(info, 0, sizeof(info_buffer));
    info->bmiHeader.biSize = sizeof(info->bmiHeader);
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = 32;
    info->bmiHeader.biCompression = BI_RGB;
    info->bmiHeader.biWidth = surface->rect.right - surface->rect.left;
    info->bmiHeader.biHeight = -(surface->rect.bottom - surface->rect.top);
    info->bmiHeader.biSizeImage =
        info->bmiHeader.biWidth * (surface->rect.bottom - surface->rect.top) * 4;

    if (surface->funcs->flush(surface, &surface->rect, &dirty, info, mock->pixels, FALSE, NULL,
                              NULL))
        SetRectEmpty(&surface->bounds);
}

/* --- the driver under test, driven through plain integers ------------------
 *
 * The test script names windows by handle value; the mock keeps one live
 * winefb surface per handle. */

struct held_surface
{
    user_handle_t hwnd;
    struct window_surface *surface;
};

static struct held_surface held[UNIT_MAX_WINDOWS];

static struct window_surface **held_slot(user_handle_t hwnd)
{
    unsigned int i, empty = UNIT_MAX_WINDOWS;

    for (i = 0; i < UNIT_MAX_WINDOWS; i++)
    {
        if (held[i].hwnd == hwnd && held[i].surface)
            return &held[i].surface;
        if (!held[i].surface && empty == UNIT_MAX_WINDOWS)
            empty = i;
    }
    if (empty == UNIT_MAX_WINDOWS)
        return NULL;
    held[empty].hwnd = hwnd;
    return &held[empty].surface;
}

int unit_create_surface(unsigned int hwnd, int left, int top, int right, int bottom)
{
    struct window_surface **slot = held_slot(hwnd);
    RECT rect;

    if (!slot)
        return 0;
    SetRect(&rect, left, top, right, bottom);
    return winefb_create_window_surface((HWND)(UINT_PTR)hwnd, FALSE, &rect, slot) && *slot != NULL;
}

void unit_release_surface(unsigned int hwnd)
{
    struct window_surface **slot = held_slot(hwnd);

    if (!slot || !*slot)
        return;
    window_surface_release(*slot);
    *slot = NULL;
}

void unit_surface_fill(unsigned int hwnd, unsigned int argb)
{
    struct window_surface **slot = held_slot(hwnd);
    struct mock_surface *mock;
    unsigned int *pixel, count;

    if (!slot || !*slot || !(mock = mock_from_surface(*slot)))
        return;
    count = ((*slot)->rect.right - (*slot)->rect.left) * ((*slot)->rect.bottom - (*slot)->rect.top);
    for (pixel = (unsigned int *)mock->pixels; count; count--)
        *pixel++ = argb;
}

void unit_pos_changed(unsigned int hwnd, unsigned int insert_after, unsigned int swp_flags,
                      int left, int top, int right, int bottom, int with_surface)
{
    struct window_surface **slot = held_slot(hwnd);
    struct window_rects rects;

    remember_handle(hwnd);

    SetRect(&rects.window, left, top, right, bottom);
    rects.client = rects.window;
    rects.visible = rects.window;
    winefb_window_pos_changed((HWND)(UINT_PTR)hwnd, (HWND)(INT_PTR)(int)insert_after, 0, swp_flags,
                              &rects, with_surface && slot ? *slot : NULL);
}

void unit_flush_dirty(unsigned int hwnd, int left, int top, int right, int bottom)
{
    struct window_surface **slot = held_slot(hwnd);

    if (!slot || !*slot)
        return;
    SetRect(&(*slot)->bounds, left, top, right, bottom);
    window_surface_flush(*slot);
}

void unit_set_clip(unsigned int hwnd, const int *rects, unsigned int count)
{
    struct window_surface **slot = held_slot(hwnd);
    RECT converted[UNIT_MAX_WINDOWS];
    unsigned int i;

    if (!slot || !*slot || count > UNIT_MAX_WINDOWS)
        return;
    for (i = 0; i < count; i++)
        SetRect(&converted[i], rects[i * 4], rects[i * 4 + 1], rects[i * 4 + 2], rects[i * 4 + 3]);
    (*slot)->funcs->set_clip(*slot, count ? converted : NULL, count);
}

void unit_flush_shaped(unsigned int hwnd, const unsigned char *shape, int stride, int topdown)
{
    char info_buffer[FIELD_OFFSET(BITMAPINFO, bmiColors[256])];
    char shape_buffer[FIELD_OFFSET(BITMAPINFO, bmiColors[256])];
    BITMAPINFO *info = (BITMAPINFO *)info_buffer;
    BITMAPINFO *shape_info = (BITMAPINFO *)shape_buffer;
    struct window_surface **slot = held_slot(hwnd);
    struct mock_surface *mock;
    int width, height;
    RECT dirty;

    if (!slot || !*slot || !(mock = mock_from_surface(*slot)))
        return;
    width = (*slot)->rect.right - (*slot)->rect.left;
    height = (*slot)->rect.bottom - (*slot)->rect.top;
    SetRect(&dirty, 0, 0, width, height);

    memset(info, 0, sizeof(info_buffer));
    info->bmiHeader.biSize = sizeof(info->bmiHeader);
    info->bmiHeader.biPlanes = 1;
    info->bmiHeader.biBitCount = 32;
    info->bmiHeader.biCompression = BI_RGB;
    info->bmiHeader.biWidth = width;
    info->bmiHeader.biHeight = -height;
    info->bmiHeader.biSizeImage = width * height * 4;

    /* the 1bpp shape the way dce.c's set_surface_shape lays it out */
    memset(shape_info, 0, sizeof(shape_buffer));
    shape_info->bmiHeader.biSize = sizeof(shape_info->bmiHeader);
    shape_info->bmiHeader.biPlanes = 1;
    shape_info->bmiHeader.biBitCount = 1;
    shape_info->bmiHeader.biWidth = width;
    shape_info->bmiHeader.biHeight = topdown ? -height : height;
    shape_info->bmiHeader.biSizeImage = stride * height;

    (*slot)->funcs->flush(*slot, &(*slot)->rect, &dirty, info, mock->pixels, TRUE, shape_info,
                          shape);
}

/* --- the scanout ----------------------------------------------------------- */

/* every handle a case ever named, so unit_reset can drain the driver's
 * per-process rect tracker between cases (it is static state in blit.c,
 * exactly as in a real process; a stale entry would leak one case's
 * geometry into the next) */
static user_handle_t seen_handles[UNIT_MAX_WINDOWS];
static unsigned int seen_count;

static void remember_handle(user_handle_t hwnd)
{
    unsigned int i;

    for (i = 0; i < seen_count; i++)
        if (seen_handles[i] == hwnd)
            return;
    if (seen_count < UNIT_MAX_WINDOWS)
        seen_handles[seen_count++] = hwnd;
}

void unit_reset(unsigned int width, unsigned int height)
{
    static char *pixels;
    FB_MODE_INFO mode = {0};
    struct window_rects gone = {{0}};
    unsigned int i;

    /* drain the driver's rect tracker: a surfaceless hide with empty rects
     * takes each entry and repairs nothing new into the about-to-die
     * scanout */
    for (i = 0; i < seen_count; i++)
        winefb_window_pos_changed((HWND)(UINT_PTR)seen_handles[i], 0, 0, SWP_HIDEWINDOW, &gone,
                                  NULL);
    seen_count = 0;

    /* fixture */
    fixture_count = 0;
    fixture_desktop = 0;
    redraw_count = 0;
    raise_count = 0;
    unit_set_button_down(0);
    report_count = 0;
    for (i = 0; i < UNIT_MAX_WINDOWS; i++)
    {
        if (held[i].surface)
            window_surface_release(held[i].surface);
        held[i].surface = NULL;
        held[i].hwnd = 0;
    }

    /* scanout: 32bpp BGRX, the QEMU stdvga layout every gui leg sees */
    free(pixels);
    pixels = malloc((size_t)width * height * 4);
    memset(pixels, 0, (size_t)width * height * 4);
    mode.width = width;
    mode.height = height;
    mode.pitch = width * 4;
    mode.bpp = 32;
    mode.redMaskSize = 8;
    mode.redMaskShift = 16;
    mode.greenMaskSize = 8;
    mode.greenMaskShift = 8;
    mode.blueMaskSize = 8;
    mode.blueMaskShift = 0;
    winefb_scanout.mode = mode;
    winefb_scanout.pixels = pixels;
    winefb_scanout.bgrx = TRUE;
}

unsigned int unit_pixel(int x, int y)
{
    const FB_MODE_INFO *mode = &winefb_scanout.mode;

    if (x < 0 || y < 0 || x >= (int)mode->width || y >= (int)mode->height)
        return 0xdeadbeef;
    return *(unsigned int *)(winefb_scanout.pixels + (size_t)y * mode->pitch + (size_t)x * 4);
}

unsigned int unit_bg(void)
{
    return winefb_pack_pixel(GetRValue(WINEFB_DESKTOP_BG), GetGValue(WINEFB_DESKTOP_BG),
                             GetBValue(WINEFB_DESKTOP_BG));
}

void unit_repaint_rect(int left, int top, int right, int bottom, unsigned int exclude)
{
    RECT rect;

    SetRect(&rect, left, top, right, bottom);
    winefb_repaint_rect(&rect, (HWND)(UINT_PTR)exclude);
}
