/*
 * tests/winetest/glue/user32_stubs.c — user32 stand-ins for the standalone Wine-test
 * binaries (M10 stretch, Makefile `wtests`).
 *
 * The ntdll and kernel32 test objects (the pinned tree's own PE build,
 * linked unmodified) declare IMPORTS = user32, but user32 is the M12 GUI
 * path — constitutionally off the CUI image (Art. 7). Same precedent as
 * user/cmd/proskrnl_glue.c: the referenced imports are stood in here, so ONE
 * binary runs on both runners (docs/14). Policy: honest, loud failure
 * (ERROR_CALL_NOT_IMPLEMENTED) for every GUI entity — a subtest whose
 * assertions need a real window/winstation fails IDENTICALLY under the
 * oracle and on proskrnl and stays off the manifest — plus real
 * implementations only where ntdll/msvcrt already carry the semantics
 * (character case, wsprintf), mirroring the cmd glue.
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

/* ntdll/msvcrt imports the real implementations lean on */
NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(WCHAR);
NTSYSAPI WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR);
int __cdecl _vsnwprintf(WCHAR *, size_t, const WCHAR *, va_list);

/* ---- honest failures: windows, classes, messages ------------------------- */

static void set_not_implemented(void)
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
}

HWND WINAPI CreateWindowExA(DWORD exStyle, LPCSTR className, LPCSTR windowName, DWORD style, int x,
                            int y, int width, int height, HWND parent, HMENU menu,
                            HINSTANCE instance, void *param)
{
    (void)exStyle;
    (void)className;
    (void)windowName;
    (void)style;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)parent;
    (void)menu;
    (void)instance;
    (void)param;
    set_not_implemented();
    return NULL;
}

BOOL WINAPI DestroyWindow(HWND window)
{
    (void)window;
    set_not_implemented();
    return FALSE;
}

LRESULT WINAPI DefWindowProcA(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)window;
    (void)message;
    (void)wparam;
    (void)lparam;
    return 0;
}

BOOL WINAPI IsWindow(HWND window)
{
    (void)window;
    return FALSE; /* no windows exist: the honest answer, not an error */
}

BOOL WINAPI IsWindowVisible(HWND window)
{
    (void)window;
    return FALSE;
}

HWND WINAPI GetDesktopWindow(void)
{
    set_not_implemented();
    return NULL;
}

BOOL WINAPI EnumWindows(WNDENUMPROC callback, LPARAM lparam)
{
    (void)callback;
    (void)lparam;
    set_not_implemented();
    return FALSE;
}

DWORD WINAPI GetWindowThreadProcessId(HWND window, DWORD *processId)
{
    (void)window;
    if (processId != NULL)
        *processId = 0;
    set_not_implemented();
    return 0;
}

int WINAPI GetSystemMetrics(int index)
{
    (void)index;
    return 0; /* the documented failure value */
}

BOOL WINAPI SystemParametersInfoW(UINT action, UINT param, PVOID data, UINT winIni)
{
    (void)action;
    (void)param;
    (void)data;
    (void)winIni;
    set_not_implemented();
    return FALSE;
}

BOOL WINAPI GetClientRect(HWND window, RECT *rect)
{
    (void)window;
    (void)rect;
    set_not_implemented();
    return FALSE;
}

HWND WINAPI GetWindow(HWND window, UINT relation)
{
    (void)window;
    (void)relation;
    set_not_implemented();
    return NULL;
}

ATOM WINAPI RegisterClassA(const WNDCLASSA *wndclass)
{
    (void)wndclass;
    set_not_implemented();
    return 0;
}

ATOM WINAPI RegisterClassExA(const WNDCLASSEXA *wndclass)
{
    (void)wndclass;
    set_not_implemented();
    return 0;
}

BOOL WINAPI UnregisterClassA(LPCSTR className, HINSTANCE instance)
{
    (void)className;
    (void)instance;
    set_not_implemented();
    return FALSE;
}

LRESULT WINAPI SendMessageA(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)window;
    (void)message;
    (void)wparam;
    (void)lparam;
    set_not_implemented();
    return 0;
}

BOOL WINAPI PostMessageA(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)window;
    (void)message;
    (void)wparam;
    (void)lparam;
    set_not_implemented();
    return FALSE;
}

BOOL WINAPI GetMessageW(MSG *message, HWND window, UINT first, UINT last)
{
    (void)message;
    (void)window;
    (void)first;
    (void)last;
    set_not_implemented();
    return -1; /* GetMessage's documented error return */
}

LRESULT WINAPI DispatchMessageW(const MSG *message)
{
    (void)message;
    return 0;
}

UINT_PTR WINAPI SetTimer(HWND window, UINT_PTR id, UINT elapse, TIMERPROC proc)
{
    (void)window;
    (void)id;
    (void)elapse;
    (void)proc;
    set_not_implemented();
    return 0;
}

BOOL WINAPI KillTimer(HWND window, UINT_PTR id)
{
    (void)window;
    (void)id;
    set_not_implemented();
    return FALSE;
}

/* ---- honest failures: window stations, desktops, input ------------------- */

HWINSTA WINAPI CreateWindowStationA(LPCSTR name, DWORD flags, ACCESS_MASK access,
                                    LPSECURITY_ATTRIBUTES security)
{
    (void)name;
    (void)flags;
    (void)access;
    (void)security;
    set_not_implemented();
    return NULL;
}

HWINSTA WINAPI OpenWindowStationA(LPCSTR name, BOOL inherit, ACCESS_MASK access)
{
    (void)name;
    (void)inherit;
    (void)access;
    set_not_implemented();
    return NULL;
}

BOOL WINAPI CloseWindowStation(HWINSTA winsta)
{
    (void)winsta;
    set_not_implemented();
    return FALSE;
}

HWINSTA WINAPI GetProcessWindowStation(void)
{
    set_not_implemented();
    return NULL;
}

HDESK WINAPI CreateDesktopA(LPCSTR name, LPCSTR device, DEVMODEA *devmode, DWORD flags,
                            ACCESS_MASK access, LPSECURITY_ATTRIBUTES security)
{
    (void)name;
    (void)device;
    (void)devmode;
    (void)flags;
    (void)access;
    (void)security;
    set_not_implemented();
    return NULL;
}

BOOL WINAPI CloseDesktop(HDESK desktop)
{
    (void)desktop;
    set_not_implemented();
    return FALSE;
}

HDESK WINAPI GetThreadDesktop(DWORD threadId)
{
    (void)threadId;
    set_not_implemented();
    return NULL;
}

HDESK WINAPI OpenDesktopA(LPCSTR name, DWORD flags, BOOL inherit, ACCESS_MASK access)
{
    (void)name;
    (void)flags;
    (void)inherit;
    (void)access;
    set_not_implemented();
    return NULL;
}

HDESK WINAPI OpenInputDesktop(DWORD flags, BOOL inherit, ACCESS_MASK access)
{
    (void)flags;
    (void)inherit;
    (void)access;
    set_not_implemented();
    return NULL;
}

BOOL WINAPI AttachThreadInput(DWORD from, DWORD to, BOOL attach)
{
    (void)from;
    (void)to;
    (void)attach;
    set_not_implemented();
    return FALSE;
}

DWORD WINAPI WaitForInputIdle(HANDLE process, DWORD timeout)
{
    (void)process;
    (void)timeout;
    return 0; /* console processes are "idle" immediately — the NT answer */
}

/* ---- real implementations over ntdll/msvcrt ------------------------------ */

/* Single-character form when the high word is zero, else in-place string
 * downcase (MS CharLowerW documentation); case tables are ntdll's own. */
LPWSTR WINAPI CharLowerW(LPWSTR str)
{
    if (((ULONG_PTR)str >> 16) == 0)
        return (LPWSTR)(ULONG_PTR)RtlDowncaseUnicodeChar((WCHAR)(ULONG_PTR)str);
    for (WCHAR *p = str; *p != 0; p++)
        *p = RtlDowncaseUnicodeChar(*p);
    return str;
}

int WINAPIV wsprintfW(WCHAR *buffer, const WCHAR *format, ...)
{
    va_list args;
    va_start(args, format);
    int n = _vsnwprintf(buffer, 1024, format, args); /* wsprintf's documented cap */
    va_end(args);
    return n < 0 ? 0 : n;
}

/* ---- dllimport indirection ----------------------------------------------- */

/* The test objects were compiled with winuser.h's dllimport declarations, so
 * their calls go through __imp_* pointers (the cmd-glue pattern). */
HWND(WINAPI *__imp_CreateWindowExA)
(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE,
 void *) = CreateWindowExA;
BOOL(WINAPI *__imp_DestroyWindow)(HWND) = DestroyWindow;
LRESULT(WINAPI *__imp_DefWindowProcA)(HWND, UINT, WPARAM, LPARAM) = DefWindowProcA;
BOOL(WINAPI *__imp_IsWindow)(HWND) = IsWindow;
BOOL(WINAPI *__imp_IsWindowVisible)(HWND) = IsWindowVisible;
HWND(WINAPI *__imp_GetDesktopWindow)(void) = GetDesktopWindow;
BOOL(WINAPI *__imp_EnumWindows)(WNDENUMPROC, LPARAM) = EnumWindows;
DWORD(WINAPI *__imp_GetWindowThreadProcessId)(HWND, DWORD *) = GetWindowThreadProcessId;
int(WINAPI *__imp_GetSystemMetrics)(int) = GetSystemMetrics;
BOOL(WINAPI *__imp_SystemParametersInfoW)(UINT, UINT, PVOID, UINT) = SystemParametersInfoW;
BOOL(WINAPI *__imp_GetClientRect)(HWND, RECT *) = GetClientRect;
HWND(WINAPI *__imp_GetWindow)(HWND, UINT) = GetWindow;
ATOM(WINAPI *__imp_RegisterClassA)(const WNDCLASSA *) = RegisterClassA;
ATOM(WINAPI *__imp_RegisterClassExA)(const WNDCLASSEXA *) = RegisterClassExA;
BOOL(WINAPI *__imp_UnregisterClassA)(LPCSTR, HINSTANCE) = UnregisterClassA;
LRESULT(WINAPI *__imp_SendMessageA)(HWND, UINT, WPARAM, LPARAM) = SendMessageA;
BOOL(WINAPI *__imp_PostMessageA)(HWND, UINT, WPARAM, LPARAM) = PostMessageA;
BOOL(WINAPI *__imp_GetMessageW)(MSG *, HWND, UINT, UINT) = GetMessageW;
LRESULT(WINAPI *__imp_DispatchMessageW)(const MSG *) = DispatchMessageW;
UINT_PTR(WINAPI *__imp_SetTimer)(HWND, UINT_PTR, UINT, TIMERPROC) = SetTimer;
BOOL(WINAPI *__imp_KillTimer)(HWND, UINT_PTR) = KillTimer;
HWINSTA(WINAPI *__imp_CreateWindowStationA)
(LPCSTR, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES) = CreateWindowStationA;
HWINSTA(WINAPI *__imp_OpenWindowStationA)(LPCSTR, BOOL, ACCESS_MASK) = OpenWindowStationA;
BOOL(WINAPI *__imp_CloseWindowStation)(HWINSTA) = CloseWindowStation;
HWINSTA(WINAPI *__imp_GetProcessWindowStation)(void) = GetProcessWindowStation;
HDESK(WINAPI *__imp_CreateDesktopA)
(LPCSTR, LPCSTR, DEVMODEA *, DWORD, ACCESS_MASK, LPSECURITY_ATTRIBUTES) = CreateDesktopA;
BOOL(WINAPI *__imp_CloseDesktop)(HDESK) = CloseDesktop;
HDESK(WINAPI *__imp_GetThreadDesktop)(DWORD) = GetThreadDesktop;
HDESK(WINAPI *__imp_OpenDesktopA)(LPCSTR, DWORD, BOOL, ACCESS_MASK) = OpenDesktopA;
HDESK(WINAPI *__imp_OpenInputDesktop)(DWORD, BOOL, ACCESS_MASK) = OpenInputDesktop;
BOOL(WINAPI *__imp_AttachThreadInput)(DWORD, DWORD, BOOL) = AttachThreadInput;
DWORD(WINAPI *__imp_WaitForInputIdle)(HANDLE, DWORD) = WaitForInputIdle;
LPWSTR(WINAPI *__imp_CharLowerW)(LPWSTR) = CharLowerW;
int(WINAPIV *__imp_wsprintfW)(WCHAR *, const WCHAR *, ...) = wsprintfW;
