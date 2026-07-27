/*
 * gui5b.c - GUI-5's judge: clipboard, hooks and AttachThreadInput, all
 * cross-process against gui5a over the unmodified pinned server.
 *
 * B is created strictly after A exists (the deterministic-activation order
 * gui3b pinned) and then works through three phases, each verdict a
 * [KTEST] line the checker requires:
 *
 *   clipboard  cross-process owner identity, registered-format identity,
 *              the immediate payload read back, the DELAYED CF_UNICODETEXT
 *              read (the server's WM_RENDERFORMAT round trip into A --
 *              corroborated by A's own serial line), sequence-number
 *              movement, and the ownership handoff when B empties the
 *              clipboard (A must see WM_DESTROYCLIPBOARD + the listener's
 *              WM_CLIPBOARDUPDATE).
 *   cbt        a thread-local WH_CBT hook observing this thread's own
 *              window creation -- the server hook-chain requests
 *              (set_hook/start_hook_chain/finish_hook_chain) plus win32u's
 *              user-mode callback dispatch, no hook module needed.
 *   ati        AttachThreadInput to A's thread: SetFocus across threads
 *              must fail detached, work attached (shared thread_input --
 *              the server's attach_thread_input), and fail again after
 *              detach.
 *
 * Then it arms a WH_KEYBOARD_LL hook and parks: the LL hook is the
 * CROSS-PROCESS hook coverage (no module needed by design), fed by real
 * injected virtio keyboard input, and unhooked mid-leg on the harness's
 * 'u' keystroke -- the second 'k' must reach the wndproc but NOT the hook,
 * which the checker enforces by counting llhook lines.
 */

#include "ntapi.h"

static const WCHAR class_a[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'A', 0};
static const WCHAR class_b[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'B', 0};
static const WCHAR class_t[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'T', 0};
static const WCHAR title_a[] = {'g', 'u', 'i', '5', 'a', 0};
static const WCHAR title_b[] = {'g', 'u', 'i', '5', 'b', 0};
static const WCHAR fmt_name[] = {'P', 'R', 'S', 'K', 'G', 'u', 'i', '5', 'F', 'm', 't', 0};

static const char immediate_payload[] = "gui5-immediate-payload";
static const WCHAR rendered_payload[] = {'g', 'u', 'i', '5', '-', 'r', 'e', 'n', 'd', 'e',
                                         'r', 'e', 'd', '-', 't', 'e', 'x', 't', 0};
static const WCHAR b_payload[] = {'g', 'u', 'i', '5', '-', 'b', '-', 'o', 'w', 'n', 'e', 'd', 0};

/* Disjoint from A (40,40 320x240): compositing is gui4's pinned job, these
 * fills only prove both processes are really on the scanout. */
#define B_X     480
#define B_Y     300
#define B_W     320
#define B_H     240
#define B_COLOR RGB(0xa0, 0x40, 0xc0)

static HHOOK ll_hook;
static int cbt_created;

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

static int global_equals(HANDLE handle, const void *want, SIZE_T size)
{
    const char *mem;
    int equal;
    if (!handle || GlobalSize(handle) < size)
        return 0;
    mem = GlobalLock(handle);
    if (!mem)
        return 0;
    equal = memcmp(mem, want, size) == 0;
    GlobalUnlock(handle);
    return equal;
}

static LRESULT CALLBACK cbt_proc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HCBT_CREATEWND)
        cbt_created++;
    return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK ll_proc(int code, WPARAM wp, LPARAM lp)
{
    if (code == HC_ACTION && wp == WM_KEYDOWN)
    {
        const KBDLLHOOKSTRUCT *kb = (const KBDLLHOOKSTRUCT *)lp;
        ntapi_printf("[KTEST] gui5 llhook vk=%02x\n", (unsigned)kb->vkCode);
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK wndproc_b(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CHAR:
        if (wp == 'u' && ll_hook)
        {
            int unhooked = UnhookWindowsHookEx(ll_hook) != 0;
            ll_hook = NULL;
            ntapi_printf("[KTEST] gui5 unhook ok=%d\n", unhooked);
        }
        ntapi_printf("[KTEST] gui5 B char=%02x\n", (unsigned)wp);
        return 0;
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

static LRESULT CALLBACK wndproc_t(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* A is ready when its window exists AND its clipboard payload is readable:
 * gui5a sets both before its ready marker, so polling the format (readable
 * without opening the clipboard) closes the race completely. */
static HWND wait_for_a(UINT fmt)
{
    int spins;
    for (spins = 0; spins < 600; spins++)
    {
        HWND hwnd = FindWindowW(class_a, title_a);
        if (hwnd && IsClipboardFormatAvailable(fmt))
            return hwnd;
        Sleep(50);
    }
    return NULL;
}

static void phase_clipboard(HWND hwnd_a, HWND hwnd_b, UINT fmt)
{
    HANDLE data;
    DWORD seq_before, seq_after;
    int pass;

    /* Owner identity crosses the process boundary: the HWND the server
     * hands back must be A's. */
    ntapi_printf("[KTEST] gui5 clip owner %s\n", GetClipboardOwner() == hwnd_a ? "PASS" : "FAIL");

    /* Atom identity: B registering the same name must land on A's format. */
    ntapi_printf("[KTEST] gui5 clip fmt %s\n",
                 fmt != 0 && IsClipboardFormatAvailable(fmt) ? "PASS" : "FAIL");

    pass = 0;
    if (OpenClipboard(hwnd_b))
    {
        data = GetClipboardData(fmt);
        pass = global_equals(data, immediate_payload, sizeof(immediate_payload));
        ntapi_printf("[KTEST] gui5 clip text %s\n", pass ? "PASS" : "FAIL");

        /* The delayed read: win32u finds no payload behind CF_UNICODETEXT,
         * sends WM_RENDERFORMAT to A (parked pumping in another process),
         * and retries -- the round trip under test. */
        data = GetClipboardData(CF_UNICODETEXT);
        pass = global_equals(data, rendered_payload, sizeof(rendered_payload));
        ntapi_printf("[KTEST] gui5 clip render %s\n", pass ? "PASS" : "FAIL");
        CloseClipboard();
    }
    else
    {
        ntapi_printf("[KTEST] gui5 clip text FAIL\n");
        ntapi_printf("[KTEST] gui5 clip render FAIL\n");
        ok(0, "OpenClipboard(read) failed");
    }

    /* Take the clipboard over: A must see WM_DESTROYCLIPBOARD (ownership
     * handoff) and, once the take-over completes, WM_CLIPBOARDUPDATE (the
     * listener A registered) -- both corroborated by A's serial lines, which
     * the harness awaits. The sequence number must move. */
    seq_before = GetClipboardSequenceNumber();
    pass = 0;
    if (OpenClipboard(hwnd_b))
    {
        pass = EmptyClipboard() &&
               SetClipboardData(CF_UNICODETEXT, make_global(b_payload, sizeof(b_payload)));
        CloseClipboard();
    }
    seq_after = GetClipboardSequenceNumber();
    ntapi_printf("[KTEST] gui5 clip seq %s\n", pass && seq_after != seq_before ? "PASS" : "FAIL");
}

static void phase_cbt(void)
{
    HWND hwnd;
    WNDCLASSW cls;
    HHOOK hook;

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_t;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_t;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW(throwaway)");

    /* Thread-local, so no hook module: the hook proc lives in this very
     * thread. The window creation below must be observed through the whole
     * server chain (set_hook -> start_hook_chain -> callback -> finish). */
    hook = SetWindowsHookExW(WH_CBT, cbt_proc, NULL, GetCurrentThreadId());
    ok(hook != NULL, "SetWindowsHookExW(WH_CBT)");
    if (hook)
    {
        hwnd = CreateWindowExW(0, class_t, NULL, WS_POPUP, 0, 0, 10, 10, NULL, NULL,
                               GetModuleHandleW(NULL), NULL);
        ok(hwnd != NULL, "CreateWindowExW(throwaway)");
        if (hwnd)
            DestroyWindow(hwnd);
        ok(UnhookWindowsHookEx(hook) != 0, "UnhookWindowsHookEx(WH_CBT)");
    }
    ntapi_printf("[KTEST] gui5 cbt %s\n", cbt_created > 0 ? "PASS" : "FAIL");
}

static void phase_ati(HWND hwnd_a, HWND hwnd_b)
{
    DWORD tid_a, tid_b;
    int pass;

    tid_a = GetWindowThreadProcessId(hwnd_a, NULL);
    tid_b = GetCurrentThreadId();
    ok(tid_a != 0 && tid_a != tid_b, "GetWindowThreadProcessId(A)");

    /* Detached, focusing another thread's window must refuse: the two
     * threads have separate thread_input records. */
    SetLastError(0);
    pass = SetFocus(hwnd_a) == NULL && GetFocus() != hwnd_a;
    ntapi_printf("[KTEST] gui5 ati pre %s\n", pass ? "PASS" : "FAIL");

    pass = AttachThreadInput(tid_b, tid_a, TRUE) != 0;
    ntapi_printf("[KTEST] gui5 ati attach %s\n", pass ? "PASS" : "FAIL");

    /* Attached, the two threads share one thread_input, so the same call
     * must now land: GetFocus reads the SHARED state back. */
    SetFocus(hwnd_a);
    pass = GetFocus() == hwnd_a;
    ntapi_printf("[KTEST] gui5 ati focus %s\n", pass ? "PASS" : "FAIL");

    /* Put focus back on B while still attached (allowed for the same
     * reason), then detach and prove the wall is back up. */
    SetFocus(hwnd_b);
    pass = AttachThreadInput(tid_b, tid_a, FALSE) != 0;
    pass = pass && SetFocus(hwnd_a) == NULL && GetFocus() != hwnd_a;
    ntapi_printf("[KTEST] gui5 ati detach %s\n", pass ? "PASS" : "FAIL");

    /* Leave the leg deterministic: B foreground + focused, so the injected
     * keystrokes that follow route here. */
    SetForegroundWindow(hwnd_b);
    SetFocus(hwnd_b);
}

START_TEST(gui5b)
{
    WNDCLASSW cls;
    HWND hwnd_a, hwnd_b;
    UINT fmt;
    MSG msg;

    fmt = RegisterClipboardFormatW(fmt_name);
    ok(fmt != 0, "RegisterClipboardFormatW");

    hwnd_a = wait_for_a(fmt);
    if (!hwnd_a)
    {
        ntapi_printf("[KTEST] gui5 B ready FAIL (no A)\n");
        ntapi_printf("[KTEST] gui5 verdict FAIL\n");
        return;
    }

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_b;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_b;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW");

    hwnd_b = CreateWindowExW(0, class_b, title_b, WS_POPUP | WS_VISIBLE, B_X, B_Y, B_W, B_H, NULL,
                             NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd_b != NULL, "CreateWindowExW");
    if (!hwnd_b)
        return;
    UpdateWindow(hwnd_b);
    ntapi_printf("[KTEST] gui5 B rect=%d,%d,%dx%d\n", B_X, B_Y, B_W, B_H);

    phase_clipboard(hwnd_a, hwnd_b, fmt);
    phase_cbt();
    phase_ati(hwnd_a, hwnd_b);

    ntapi_printf("[KTEST] gui5 verdict %s\n", ntapi_ctx.failures == 0 ? "PASS" : "FAIL");

    /* Arm the cross-process hook LAST so the injected keys the harness now
     * sends meet a settled arrangement (B foreground, phases done). */
    ll_hook = SetWindowsHookExW(WH_KEYBOARD_LL, ll_proc, NULL, 0);
    ok(ll_hook != NULL, "SetWindowsHookExW(WH_KEYBOARD_LL)");
    ntapi_printf("[KTEST] gui5 hooks armed\n");

    /* Park pumping: llhook/char/unhook lines are driven by the harness
     * through the keyboard; the leg owns QEMU's lifetime. */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
