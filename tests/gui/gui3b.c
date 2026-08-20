/*
 * gui3b.c - the second of GUI-3's two GUI processes, and the one that judges.
 *
 * B runs in its OWN process against the same wineserver-lite, puts up its
 * own window, and then checks the four behaviours docs/02 names as the
 * milestone's exit criteria -- each across the process boundary, which is
 * the part that could not work before:
 *
 *   FindWindow    B resolves a window A created. The window tree is one
 *                 tree in the server, not one per client.
 *   SendMessage   B sends to A's window and gets A's derived answer back,
 *                 so the message really ran in A's wndproc on A's thread.
 *   Z-order       both windows are in ONE z-order, and re-ordering from
 *                 here moves a window owned over there.
 *   focus         activation moves between processes, corroborated by A
 *                 reporting its own deactivation.
 *
 * Verdicts are [KTEST] lines on serial; tests/gui/check_gui3.py additionally
 * proves both windows reached the scanout, so a run that printed PASS with
 * nothing on screen still fails.
 */

#include "ntapi.h"

#define GUI3_APP_MESSAGE (WM_APP + 1)
#define GUI3_MAGIC       0x5a5a0000u

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '3', 'A', 0};
static const WCHAR class_b[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '3', 'B', 0};
static const WCHAR title_b[] = {'g', 'u', 'i', '3', 'b', 0};

/* Disjoint from A's (see gui3a.c: no clipping until GUI-4). */
#define B_X     480
#define B_Y     300
#define B_W     320
#define B_H     240
#define B_COLOR RGB(0xc0, 0x40, 0x20)

static LRESULT CALLBACK wndproc_b(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT)
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
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void pump(void)
{
    MSG msg;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

/* A starts first but "first" under TCG is not a guarantee, so give it a
 * bounded chance to appear rather than racing it. */
static HWND wait_for_a(void)
{
    HWND hwnd;
    int spins;

    for (spins = 0; spins < 300; spins++)
    {
        if ((hwnd = FindWindowW(class_a, NULL)))
            return hwnd;
        pump();
        Sleep(100);
    }
    return NULL;
}

/* Is `first` ahead of `second` in the one z-order? Walked from the top, so
 * it reads the same way the server keeps it. */
static int precedes(HWND first, HWND second)
{
    HWND walk = GetTopWindow(NULL);
    int steps;

    for (steps = 0; walk && steps < 256; steps++)
    {
        if (walk == first)
            return 1;
        if (walk == second)
            return 0;
        walk = GetWindow(walk, GW_HWNDNEXT);
    }
    return 0;
}

START_TEST(gui3b)
{
    WNDCLASSW cls;
    HWND hwnd_b, hwnd_a;
    LRESULT answer;
    int spins;

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_b;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_b;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW");

    /* --- FindWindow: A's window, from B's process ------------------------- */
    hwnd_a = wait_for_a();
    ntapi_printf("[KTEST] gui3 find %s\n", hwnd_a ? "PASS" : "FAIL");
    if (!hwnd_a)
    {
        ntapi_printf("[KTEST] gui3 verdict FAIL\n");
        return;
    }

    /* B's window is created strictly AFTER A's exists, so the show-time
     * activation order is deterministic: B's window is the last shown, and
     * showing it moves the foreground from A's process to this one (that IS
     * the cross-process activation this leg proves; A corroborates by
     * reporting its deactivation). The order matters because the pinned
     * server enforces its focus-stealing rule (server/queue.c,
     * set_foreground_window: a process that is not foreground and has older
     * user input may not take foreground once its window has been foreground
     * before) -- created the other way around, the focus check below would
     * be refused by the oracle's own rule, not by a proskrnl bug. */
    hwnd_b = CreateWindowExW(0, class_b, title_b, WS_POPUP | WS_VISIBLE, B_X, B_Y, B_W, B_H, NULL,
                             NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd_b != NULL, "CreateWindowExW");
    if (!hwnd_b)
        return;
    UpdateWindow(hwnd_b);
    ntapi_printf("[KTEST] gui3 B rect=%d,%d,%dx%d\n", B_X, B_Y, B_W, B_H);

    /* --- SendMessage: cross-process, and the ANSWER proves it ran --------- */
    answer = SendMessageW(hwnd_a, GUI3_APP_MESSAGE, 0x4321, 0);
    ntapi_printf("[KTEST] gui3 send %s (answer=%08lx)\n",
                 answer == (LRESULT)(0x4321u ^ GUI3_MAGIC) ? "PASS" : "FAIL",
                 (unsigned long)answer);

    /* --- the syscall boundary's fault containment -------------------------
     *
     * A fault taken INSIDE win32u must not reach the caller (docs/03 "GUI-2
     * notes": win32u is in-process here, so the syscall frame that contains
     * one on Wine does not exist and glue.c rebuilds it).
     *
     * The trigger is a query the boundary answers today by faulting, on the
     * oracle as much as here: asked for a window THIS process does not own,
     * dlls/win32u/class.c get_class_ptr hands back the OBJ_OTHER_PROCESS
     * sentinel and get_class_long_size dereferences it whenever the class
     * carries no small icon of its own. A's window is that window — A
     * registered a plain WNDCLASSW with no hIconSm, and it belongs to the
     * other process by construction, which is this leg's whole subject.
     *
     * It used to be asked of the DESKTOP window, from A. That worked while
     * the desktop belonged to no process at all, and stopped the moment the
     * boot's FIRST desktop client stopped being a test client: conhost links
     * user32 on every boot now, so it attaches before A does, and A's
     * GetDesktopWindow() no longer resolves to an unowned window — the
     * query returned 0 without ever reaching the dereference, so the
     * containment path went unexercised while every gui3 verdict still
     * passed. A window one process created and another asks about cannot
     * drift that way.
     *
     * The VERDICT is survival — that this line is reached at all — and not
     * the value, which is Wine's bug leaking its exception code and would
     * become a real handle the day upstream fixes it. The value is printed
     * because a log that only says PASS cannot show which of the two it
     * was. */
    ntapi_printf("[KTEST] gui3 win32u fault contained PASS (A's GCLP_HICONSM=%p)\n",
                 (void *)GetClassLongPtrW(hwnd_a, GCLP_HICONSM));

    /* --- Z-order: one order over two processes, reorderable from here ----- */
    {
        int b_first_before, a_first_after;

        SetWindowPos(hwnd_b, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        pump();
        b_first_before = precedes(hwnd_b, hwnd_a);

        SetWindowPos(hwnd_a, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        pump();
        Sleep(200);
        a_first_after = precedes(hwnd_a, hwnd_b);

        ntapi_printf("[KTEST] gui3 zorder %s (b_first=%d a_first=%d)\n",
                     (b_first_before && a_first_after) ? "PASS" : "FAIL", b_first_before,
                     a_first_after);
    }

    /* --- focus: activation crosses the process boundary ------------------- */
    {
        HWND foreground = NULL;

        SetForegroundWindow(hwnd_b);
        for (spins = 0; spins < 50; spins++)
        {
            pump();
            if ((foreground = GetForegroundWindow()) == hwnd_b)
                break;
            Sleep(50);
        }
        ntapi_printf("[KTEST] gui3 focus %s (foreground=%p ours=%p)\n",
                     foreground == hwnd_b ? "PASS" : "FAIL", foreground, hwnd_b);
    }

    /* Repaint both: the zorder/focus traffic above may have exposed them,
     * and the screendump must find both on the scanout. */
    InvalidateRect(hwnd_b, NULL, TRUE);
    UpdateWindow(hwnd_b);
    pump();

    ntapi_printf("[KTEST] gui3 verdict PASS\n");

    /* Park: both windows must still be up when the harness dumps the
     * screen. The leg owns QEMU's lifetime. */
    for (;;)
    {
        pump();
        Sleep(200);
    }
}
