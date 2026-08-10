/*
 * wow64gui.c — the WOW64 GUI acceptance client: a 32-bit Win32 program that
 * paints a window on the same desktop the 64-bit ones use.
 *
 * The same shape as gui4a.c (a borderless window, one solid known colour,
 * park pumping) and deliberately so: what is under test is not the drawing
 * but the BITNESS of the process that did it. Everything below is ordinary
 * Win32 — the interesting part is that this .exe is IMAGE_FILE_MACHINE_I386,
 * so every call in it goes 32-bit user32 -> the stock 32-bit win32u thunks ->
 * a syscall wow64cpu catches -> wow64.dll's service table 1 -> wow64win.dll
 * -> the SAME 64-bit win32u.dll this build ships (Art. 11: one desktop
 * authority, reached through one more door).
 *
 * It reports three things on serial through NtDisplayString, which reaches
 * the kernel through wow64.dll's own thunk (dlls/wow64/system.c
 * wow64_NtDisplayString) like every other syscall it makes:
 *
 *   wow64=1     ProcessWow64Information is non-zero — i.e. the KERNEL agrees
 *               this is a WOW64 process, not just that the file was a PE32.
 *               A 64-bit build of this same source would print wow64=0 and
 *               fail the leg, so the marker cannot be satisfied by accident.
 *   ptrsize=4   the compiler's view, which must agree with the kernel's.
 *   ready rect= where the window is, for tests/gui/check_wow64gui.py to find
 *               its colour on QEMU's screendump.
 *
 * Built by the i686 toolchain against the pinned tree's i386 import
 * libraries, CRT-less on ntapi.c like the other GUI clients.
 */

#include "ntapi.h"

static const WCHAR class_w[] = {'P', 'R', 'S', 'K', 'W', 'o', 'w', '6', '4', 0};
static const WCHAR title_w[] = {'w', 'o', 'w', '6', '4', 'g', 'u', 'i', 0};

/* Deliberately clear of the console window the leg types into (which starts
 * at the top-left corner) and of the desktop's own background colour. */
#define W_X     420
#define W_Y     420
#define W_W     360
#define W_H     240
#define W_COLOR RGB(0xc0, 0x30, 0x90)

/* ProcessWow64Information: the pointer-sized PEB32 address, 0 in a 64-bit
 * process (abi/ntpsapi.h; pinned by tests/ntapi/sem_ps/wow64_process.c). */
#define PS_PROCESS_WOW64_INFORMATION 26

static LRESULT CALLBACK wndproc_wow64(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        HBRUSH brush = CreateSolidBrush(W_COLOR);
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect(dc, &rect, brush);
        DeleteObject(brush);
        EndPaint(hwnd, &ps);
        ntapi_printf("[KTEST] wow64gui painted\n");
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

START_TEST(wow64gui)
{
    WNDCLASSW cls;
    HWND hwnd;
    MSG msg;
    ULONG_PTR peb32 = 0;
    NTSTATUS status;

    /* Unlike the other GUI clients this one is launched FROM the console
     * window, so it inherits std handles and the harness's runner probe
     * (ntapi.h: "no std output handle == proskrnl") would send every line
     * into that window instead of the serial log the leg greps. Say where
     * we are outright. */
    ntapi_ctx.on_proskrnl = 1;

    status = NtQueryInformationProcess(GetCurrentProcess(), PS_PROCESS_WOW64_INFORMATION, &peb32,
                                       sizeof(peb32), NULL);
    ok(status == 0, "ProcessWow64Information -> %08lx", (unsigned long)status);
    ntapi_printf("[KTEST] wow64gui wow64=%d ptrsize=%d\n", peb32 != 0 ? 1 : 0, (int)sizeof(void *));

    memset(&cls, 0, sizeof(cls));
    cls.lpfnWndProc = wndproc_wow64;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.lpszClassName = class_w;
    ok(RegisterClassW(&cls) != 0, "RegisterClassW");

    hwnd = CreateWindowExW(0, class_w, title_w, WS_POPUP | WS_VISIBLE, W_X, W_Y, W_W, W_H, NULL,
                           NULL, GetModuleHandleW(NULL), NULL);
    ok(hwnd != NULL, "CreateWindowExW");
    if (!hwnd)
        return;
    UpdateWindow(hwnd);
    ntapi_printf("[KTEST] wow64gui ready rect=%d,%d,%dx%d color=%02x%02x%02x\n", W_X, W_Y, W_W, W_H,
                 (unsigned)GetRValue(W_COLOR), (unsigned)GetGValue(W_COLOR),
                 (unsigned)GetBValue(W_COLOR));

    /* Park pumping: the window must still be on the scanout when the leg
     * takes its screendump, and the leg owns the guest's lifetime. */
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
