/*
 * gui4a.c - the lower window of GUI-4's pair, and the input host.
 *
 * A puts up a borderless window with a solid known colour and parks
 * pumping. It starts first, so its winefb.drv wins the exclusive opens of
 * \Device\Input0 and \Device\Input1 and hosts the reader threads for the
 * whole leg (docs/03 GUI-4 notes: the reader lives in whichever GUI
 * process attempts first) -- the leg's `mouse READY` marker comes from
 * this process.
 *
 * Everything A reports is for the harness to sequence against
 * (tests/run/run.sh gui4): a click landing in its client area, a
 * character reaching it after a click gave it focus, its activation and
 * deactivation. B (gui4b.c) overlaps this window from above, so a click
 * in the overlap must NOT reach here -- check_gui4.py greps for exactly
 * that.
 *
 * Verdicts go out as [KTEST] lines on serial (NtDisplayString); there is
 * no console on these images.
 */

#include "ntapi.h"

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '4', 'A', 0};
static const WCHAR title_a[] = {'g', 'u', 'i', '4', 'a', 0};

/* Overlapping B on purpose: the compositor is what GUI-4 adds, and the
 * overlap's pixels (B's colour must win) are the proof. B's window rect is
 * 350,250 400x300, so the overlap is 350..500 x 250..400. */
#define A_X     100
#define A_Y     100
#define A_W     400
#define A_H     300
#define A_COLOR RGB(0x20, 0x60, 0xc0)

static LRESULT CALLBACK wndproc_a(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_LBUTTONDOWN:
    {
        POINT pt = {(short)LOWORD(lp), (short)HIWORD(lp)};
        ClientToScreen(hwnd, &pt);
        ntapi_printf("[KTEST] gui4 A click %d,%d\n", (int)pt.x, (int)pt.y);
        return 0;
    }
    case WM_CHAR:
        ntapi_printf("[KTEST] gui4 A char=%02x\n", (unsigned)wp);
        return 0;
    case WM_ACTIVATE:
        ntapi_printf("[KTEST] gui4 A %s\n", LOWORD(wp) == WA_INACTIVE ? "deactivated" : "active");
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

START_TEST(gui4a)
{
    WNDCLASSW cls;
    HWND hwnd;
    MSG msg;

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
    ntapi_printf("[KTEST] gui4 A ready rect=%d,%d,%dx%d\n", A_X, A_Y, A_W, A_H);

    /* Park pumping. A must outlive the whole choreography and still be on
     * the scanout for both screendumps; the leg owns QEMU's lifetime and
     * kills it (the gui3 precedent). */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
