/*
 * gui4b.c - the upper window of GUI-4's pair: the one that gets clicked,
 * dragged and moved.
 *
 * B is a CAPTIONED window created strictly after A's exists, overlapping
 * it from above. The caption is the whole point: docs/07's click contract
 * ends in DefWindowProc drawing and dragging its own frame, so grabbing B
 * by its caption and moving it exercises WM_NCHITTEST -> HTCAPTION ->
 * WM_SYSCOMMAND(SC_MOVE) -> the modal drag loop under server-side capture
 * -- none of it our code.
 *
 * B probes its own caption with WM_NCHITTEST rather than computing metrics
 * host-side, and advertises the point on serial; the harness presses
 * exactly there. On WM_EXITSIZEMOVE it reports where it landed and
 * repaints itself, so the second screendump is deterministic.
 */

#include "ntapi.h"

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '4', 'A', 0};
static const WCHAR class_b[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '4', 'B', 0};
static const WCHAR title_a[] = {'g', 'u', 'i', '4', 'a', 0};
static const WCHAR title_b[] = {'g', 'u', 'i', '4', 'b', 0};

/* Window rect. Overlaps A (100,100 400x300): the overlap is
 * 350..500 x 250..400, and B being above, its pixels must win there --
 * the compositor's pictorial proof (check_gui4.py). */
#define B_X     350
#define B_Y     250
#define B_W     400
#define B_H     300
#define B_COLOR RGB(0xc0, 0x40, 0x20)

static LRESULT CALLBACK wndproc_b(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_LBUTTONDOWN:
    {
        POINT pt = {(short)LOWORD(lp), (short)HIWORD(lp)};
        ClientToScreen(hwnd, &pt);
        ntapi_printf("[KTEST] gui4 B click %d,%d\n", (int)pt.x, (int)pt.y);
        return 0;
    }
    case WM_CHAR:
        /* 'r' is the harness's repaint request: after the drag it parks the
         * cursor and asks for one more paint, so the cursor's save-under
         * restore (which can deposit a stale patch over the caption once
         * the cursor leaves -- cursor.c documents the artifact) cannot be
         * in the settled dump. */
        if (wp == 'r')
        {
            /* RDW_FRAME: the stale patch sits where the cursor was last
             * over the CAPTION, and a client-area invalidation would leave
             * the non-client pixels as they are. */
            RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
        }
        ntapi_printf("[KTEST] gui4 B char=%02x\n", (unsigned)wp);
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wp) != WA_INACTIVE)
            ntapi_printf("[KTEST] gui4 B active\n");
        return 0;
    case WM_EXITSIZEMOVE:
    {
        RECT rect;
        GetWindowRect(hwnd, &rect);
        ntapi_printf("[KTEST] gui4 B moved rect=%d,%d,%dx%d\n", (int)rect.left, (int)rect.top,
                     (int)(rect.right - rect.left), (int)(rect.bottom - rect.top));
        /* Self-heal before the settled dump: the drag may have left a
         * cursor smudge or stale band on this window (cursor.c documents
         * the artifact); a full repaint makes dump 2 deterministic. */
        RedrawWindow(hwnd, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
        return 0;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        HBRUSH brush = CreateSolidBrush(B_COLOR);
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

static HWND wait_for_a(void)
{
    int spins;
    for (spins = 0; spins < 600; spins++)
    {
        HWND hwnd = FindWindowW(class_a, title_a);
        if (hwnd)
            return hwnd;
        Sleep(50);
    }
    return NULL;
}

/* Find a caption point by asking the window itself: walk down the middle
 * of the top edge until DefWindowProc answers HTCAPTION. Asking beats
 * recomputing the NC layout host-side -- whatever the oracle's metrics
 * are, this is where the caption actually is. */
static int find_caption_point(HWND hwnd, POINT *pt)
{
    RECT rect;
    int dy;

    GetWindowRect(hwnd, &rect);
    for (dy = 1; dy < 48; dy++)
    {
        pt->x = (rect.left + rect.right) / 2;
        pt->y = rect.top + dy;
        if (SendMessageW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(pt->x, pt->y)) == HTCAPTION)
            return 1;
    }
    return 0;
}

START_TEST(gui4b)
{
    WNDCLASSW cls;
    HWND hwnd_b, hwnd_a, walk;
    RECT wrect, crect;
    POINT caption, corner;
    MSG msg;
    int ztop;

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_b;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_b;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW");

    /* Created strictly after A exists: the deterministic-activation order
     * gui3b.c pinned (the last window shown takes the foreground; created
     * the other way, the server's own focus-stealing rule would apply). */
    hwnd_a = wait_for_a();
    if (!hwnd_a)
    {
        ntapi_printf("[KTEST] gui4 B ready FAIL (no A)\n");
        return;
    }

    hwnd_b = CreateWindowExW(0, class_b, title_b, WS_CAPTION | WS_SYSMENU | WS_VISIBLE, B_X, B_Y,
                             B_W, B_H, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd_b != NULL, "CreateWindowExW");
    if (!hwnd_b)
        return;
    UpdateWindow(hwnd_b);

    /* B must be above A for the overlap and click checks to mean anything:
     * walk the z-order from the top and note which comes first. */
    ztop = 0;
    for (walk = GetTopWindow(NULL); walk; walk = GetWindow(walk, GW_HWNDNEXT))
    {
        if (walk == hwnd_b)
        {
            ztop = 1;
            break;
        }
        if (walk == hwnd_a)
            break;
    }

    GetWindowRect(hwnd_b, &wrect);
    GetClientRect(hwnd_b, &crect);
    corner.x = crect.left;
    corner.y = crect.top;
    ClientToScreen(hwnd_b, &corner);
    if (!find_caption_point(hwnd_b, &caption))
        ntapi_printf("[KTEST] gui4 B ready FAIL (no caption)\n");
    else
        ntapi_printf("[KTEST] gui4 B ready wrect=%d,%d,%dx%d crect=%d,%d,%dx%d caption=%d,%d "
                     "ztop=%s\n",
                     (int)wrect.left, (int)wrect.top, (int)(wrect.right - wrect.left),
                     (int)(wrect.bottom - wrect.top), (int)corner.x, (int)corner.y,
                     (int)(crect.right - crect.left), (int)(crect.bottom - crect.top),
                     (int)caption.x, (int)caption.y, ztop ? "PASS" : "FAIL");

    /* Park pumping: every remaining verdict (clicks, chars, the drag) is
     * driven by the harness through the input devices and reported from
     * the wndproc above. */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
