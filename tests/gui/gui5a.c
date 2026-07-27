/*
 * gui5a.c - GUI-5's clipboard owner, and the input host.
 *
 * A starts first (so its winefb.drv hosts the input readers for the leg,
 * the gui4 arrangement) and becomes the clipboard owner BEFORE printing its
 * ready marker: an immediate payload in a registered format, plus a DELAYED
 * CF_UNICODETEXT (SetClipboardData with NULL) that the server will come
 * asking for when B reads it -- the WM_RENDERFORMAT round trip is the
 * cross-process behaviour under test. It also registers as a clipboard
 * listener, so B later taking the clipboard over must produce BOTH
 * WM_DESTROYCLIPBOARD (the ownership handoff) and WM_CLIPBOARDUPDATE (the
 * listener notification) here, each reported on serial for the checker.
 *
 * The window itself is a disjoint solid fill (no overlap: compositing is
 * gui4's pinned job); its pixels only prove A is really on the scanout.
 * Verdicts go out as [KTEST] lines on serial; there is no console.
 */

#include "ntapi.h"

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'A', 0};
static const WCHAR title_a[] = {'g', 'u', 'i', '5', 'a', 0};
static const WCHAR fmt_name[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'F', 'm', 't', 0};

/* What B must read back. The immediate payload is raw bytes (a registered
 * format has no conversion semantics); the delayed one is CF_UNICODETEXT,
 * rendered only when WM_RENDERFORMAT arrives. */
static const char immediate_payload[] = "gui5-immediate-payload";
static const WCHAR rendered_payload[] = {'g', 'u', 'i', '5', '-', 'r', 'e', 'n', 'd', 'e',
                                         'r', 'e', 'd', '-', 't', 'e', 'x', 't', 0};

#define A_X     40
#define A_Y     40
#define A_W     320
#define A_H     240
#define A_COLOR RGB(0x20, 0xa0, 0x40)

static HANDLE make_global(const void *data, SIZE_T size)
{
    HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, size);
    void *mem;
    if (!handle)
        return NULL;
    mem = GlobalLock(handle);
    if (!mem)
    {
        GlobalFree(handle);
        return NULL;
    }
    memcpy(mem, data, size);
    GlobalUnlock(handle);
    return handle;
}

static LRESULT CALLBACK wndproc_a(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_RENDERFORMAT:
        /* The delayed-rendering callback: the owner sets the data WITHOUT
         * opening the clipboard (the documented contract -- the requester
         * holds it open right now, blocked inside GetClipboardData). */
        if (wp == CF_UNICODETEXT)
            SetClipboardData(CF_UNICODETEXT,
                             make_global(rendered_payload, sizeof(rendered_payload)));
        ntapi_printf("[KTEST] gui5 A renderfmt f=%u\n", (unsigned)wp);
        return 0;
    case WM_DESTROYCLIPBOARD:
        ntapi_printf("[KTEST] gui5 A destroyclip\n");
        return 0;
    case WM_CLIPBOARDUPDATE:
        ntapi_printf("[KTEST] gui5 A clipupdate\n");
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        HBRUSH brush = CreateSolidBrush(A_COLOR);
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect(dc, &rect, brush);
        DeleteObject(brush);
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

START_TEST(gui5a)
{
    WNDCLASSW cls;
    HWND hwnd;
    UINT fmt;
    MSG msg;
    int clip_ok;

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_a;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_a;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW");

    hwnd = CreateWindowExW(0, class_a, title_a, WS_POPUP | WS_VISIBLE, A_X, A_Y, A_W, A_H, NULL,
                           NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowExW");
    if (!hwnd)
        return;
    UpdateWindow(hwnd);

    /* Become the clipboard owner BEFORE the ready marker: B keys its whole
     * run off the registered format being available, so there is no window
     * where B could read a half-set clipboard. */
    fmt = RegisterClipboardFormatW(fmt_name);
    ok(fmt != 0, "RegisterClipboardFormatW");
    clip_ok = 0;
    if (OpenClipboard(hwnd))
    {
        clip_ok = EmptyClipboard() &&
                  SetClipboardData(fmt, make_global(immediate_payload, sizeof(immediate_payload)));
        /* NULL data = delayed rendering: the server records the format with
         * no payload and sends WM_RENDERFORMAT on first read. Success
         * RETURNS NULL here (the return is the data handle), so the verdict
         * is the absence of a last error (user32 sets one only on failure). */
        SetLastError(0);
        SetClipboardData(CF_UNICODETEXT, NULL);
        clip_ok = clip_ok && GetLastError() == 0;
        CloseClipboard();
    }
    ok(clip_ok, "clipboard ownership setup failed");
    ok(AddClipboardFormatListener(hwnd) != 0, "AddClipboardFormatListener");

    ntapi_printf("[KTEST] gui5 A ready rect=%d,%d,%dx%d\n", A_X, A_Y, A_W, A_H);

    /* Park pumping: WM_RENDERFORMAT / WM_DESTROYCLIPBOARD / the listener
     * update all arrive through this loop while B judges. The leg owns
     * QEMU's lifetime (the gui3/gui4 precedent). */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
