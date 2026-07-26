/*
 * gui3a.c - the first of GUI-3's two GUI processes.
 *
 * A registers a class, puts up a window with a solid known colour, and then
 * stays pumping messages. Everything it offers is for gui3b.c to find and
 * poke from ANOTHER process:
 *
 *   - the class name and window title FindWindow looks up;
 *   - a wndproc that answers WM_APP with a value derived from the sender's,
 *     so a cross-process SendMessage is proved by the ANSWER rather than by
 *     "it returned";
 *   - the activation it loses when B takes the foreground.
 *
 * It also proves the cross-THREAD case inside one process, which the
 * milestone names separately: a second thread of A owns its own window and
 * A's main thread sends to it. In-process that already worked at GUI-2; with
 * the server out of process it means two slots and two thread records.
 *
 * Verdicts go out as [KTEST] lines on serial (NtDisplayString, the same sink
 * the kernel's own verdicts use); the harness greps them and the screendump
 * checks the pixels. There is no console on these images.
 */

#include "ntapi.h"

#define GUI3_APP_MESSAGE (WM_APP + 1)
#define GUI3_MAGIC       0x5a5a0000u

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '3', 'A', 0};
static const WCHAR title_a[] = {'g', 'u', 'i', '3', 'a', 0};
static const WCHAR class_thread[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '3', 'T', 0};

/* The rect and colour the checker looks for. Disjoint from B's: winefb.drv
 * still flushes whole windows with no clipping (per-window surfaces and
 * compositing are GUI-4), so overlapping them would make the pixels
 * last-writer-wins and the check flaky. Z-order is judged through the API
 * instead, which is where it is actually defined. */
#define A_X     40
#define A_Y     40
#define A_W     320
#define A_H     240
#define A_COLOR RGB(0x20, 0x60, 0xc0)

static HWND thread_window;
static volatile LONG thread_ready;

static LRESULT CALLBACK wndproc_a(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case GUI3_APP_MESSAGE:
        /* Derived from the caller's cookie, so a reply can only come from
         * code that actually ran here. */
        return (LRESULT)(((unsigned int)wp) ^ GUI3_MAGIC);
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE)
            ntapi_printf("[KTEST] gui3 A deactivated\n");
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

static DWORD WINAPI second_thread(void *arg)
{
    WNDCLASSW cls;
    MSG msg;

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_a;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_thread;
    RegisterClassW(&cls);

    thread_window = CreateWindowExW(0, class_thread, class_thread, WS_POPUP, 0, 0, 16, 16, NULL,
                                    NULL, GetModuleHandleW(NULL), NULL);
    __atomic_store_n(&thread_ready, 1, __ATOMIC_RELEASE);
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

START_TEST(gui3a)
{
    WNDCLASSW cls;
    HWND hwnd;
    MSG msg;
    HANDLE thread;
    LRESULT answer;
    int spins;

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
    ntapi_printf("[KTEST] gui3 A rect=%d,%d,%dx%d\n", A_X, A_Y, A_W, A_H);

    /* Cross-thread, one process. */
    thread = CreateThread(NULL, 0, second_thread, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread");
    for (spins = 0; spins < 200 && !__atomic_load_n(&thread_ready, __ATOMIC_ACQUIRE); spins++)
    {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(50);
    }
    if (thread_window)
    {
        answer = SendMessageW(thread_window, GUI3_APP_MESSAGE, 0x1234, 0);
        ntapi_printf("[KTEST] gui3 xthread %s\n",
                     answer == (LRESULT)(0x1234u ^ GUI3_MAGIC) ? "PASS" : "FAIL");
    }
    else
        ntapi_printf("[KTEST] gui3 xthread FAIL (no window)\n");

    ntapi_printf("[KTEST] gui3 A ready\n");

    /* Park pumping. A must outlive B's checks and still be on the scanout
     * when the harness takes its screendump, so this does not exit -- the
     * leg owns QEMU's lifetime and kills it (the winemine-idles precedent
     * from GUI-2). */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
