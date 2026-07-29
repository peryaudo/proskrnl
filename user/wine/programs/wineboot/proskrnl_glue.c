/*
 * user/wine/programs/wineboot/proskrnl_glue.c — standalone-PE glue for Wine's wineboot (CUI-1).
 *
 * wineboot.c is compiled DIRECTLY from the pinned tree (the conhost recipe:
 * programs/wineboot is in the tree's disabled PE subdirs, so there are no
 * prebuilt objects). Under `--init` its load-bearing legs are the machine
 * registry keys and the rundll32/InstallHinfSection passes over wine.inf;
 * everything else warns-and-continues. This file supplies what the exe needs
 * beyond the baked kernel32/kernelbase/ntdll/advapi32/setupapi/version/
 * rpcrt4/ucrtbase surface:
 *
 *   - the narrow CRT entry (wineboot is a -mconsole main() app),
 *   - the user32/gdi32 wait-window set as headless stand-ins — the exact
 *     precedent user/wine/programs/cmd/proskrnl_glue.c sets (Art. 7: GUI stays absent);
 *     MsgWaitForMultipleObjects degrades to WaitForMultipleObjects so the
 *     rundll32-wait loop still blocks correctly,
 *   - honest-failure stand-ins for the shell32/shlwapi/wininet/newdev/ws2_32
 *     imports (their DLLs are not loadable here; wineboot's callers of these
 *     all tolerate failure),
 *   - the three shutdown.c entry points (never reached under --init;
 *     shutdown.c itself is not compiled — it is pure user32).
 */
#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windows.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <wininet.h>
#include <newdev.h>
#undef WIN32_NO_STATUS

/* ---- ucrtbase app-startup surface (user/wine/programs/cmd/proskrnl_glue.c precedent) --- */

void __cdecl _set_app_type(int);
int __cdecl _initialize_narrow_environment(void);
int __cdecl _configure_narrow_argv(int);
int *__cdecl __p___argc(void);
char ***__cdecl __p___argv(void);
void __cdecl exit(int);

int __cdecl main(int argc, char *argv[]); /* programs/wineboot/wineboot.c */

/* ---- CRT entry ----------------------------------------------------------- */

void __attribute__((used)) wineboot_start(void)
{
    _set_app_type(1 /* _crt_console_app */);
    _initialize_narrow_environment();
    _configure_narrow_argv(1);
    exit(main(*__p___argc(), *__p___argv()));
}

/* ---- shutdown.c stand-ins ------------------------------------------------ */

/* wineboot.c externs these from shutdown.c (pure user32 window enumeration,
 * not compiled here); only --end-session/--kill reach them. */
BOOL shutdown_close_windows(BOOL force)
{
    (void)force;
    return FALSE;
}

BOOL shutdown_all_desktops(BOOL force)
{
    (void)force;
    return FALSE;
}

void kill_processes(BOOL kill_desktop)
{
    (void)kill_desktop;
}

/* ---- user32/gdi32 wait-window stand-ins ---------------------------------- */

/* show_wait_window's dialog never exists (NULL HWND); every window call
 * no-ops against it and the message pump has nothing to pump. */
HWND WINAPI CreateDialogParamW(HINSTANCE instance, LPCWSTR template, HWND parent,
                               DLGPROC dialogProc, LPARAM param)
{
    (void)instance;
    (void)template;
    (void)parent;
    (void)dialogProc;
    (void)param;
    return NULL;
}

BOOL WINAPI ShowWindow(HWND hwnd, int command)
{
    (void)hwnd;
    (void)command;
    return FALSE;
}

BOOL WINAPI DestroyWindow(HWND hwnd)
{
    (void)hwnd;
    return FALSE;
}

HWND WINAPI GetDlgItem(HWND dialog, int controlId)
{
    (void)dialog;
    (void)controlId;
    return NULL;
}

LRESULT WINAPI SendMessageW(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    (void)hwnd;
    (void)msg;
    (void)wparam;
    (void)lparam;
    return 0;
}

BOOL WINAPI SetWindowPos(HWND hwnd, HWND after, int x, int y, int width, int height, UINT flags)
{
    (void)hwnd;
    (void)after;
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)flags;
    return FALSE;
}

HANDLE WINAPI LoadImageW(HINSTANCE instance, LPCWSTR name, UINT type, int width, int height,
                         UINT flags)
{
    (void)instance;
    (void)name;
    (void)type;
    (void)width;
    (void)height;
    (void)flags;
    return NULL;
}

BOOL WINAPI GetClientRect(HWND hwnd, RECT *rect)
{
    (void)hwnd;
    if (rect != NULL)
    {
        rect->left = rect->top = rect->right = rect->bottom = 0;
    }
    return FALSE;
}

HDC WINAPI GetDC(HWND hwnd)
{
    (void)hwnd;
    return NULL;
}

int WINAPI ReleaseDC(HWND hwnd, HDC hdc)
{
    (void)hwnd;
    (void)hdc;
    return 0;
}

int WINAPI DrawTextW(HDC hdc, LPCWSTR text, int count, RECT *rect, UINT format)
{
    (void)hdc;
    (void)text;
    (void)count;
    (void)rect;
    (void)format;
    return 0;
}

HGDIOBJ WINAPI SelectObject(HDC hdc, HGDIOBJ object)
{
    (void)hdc;
    (void)object;
    return NULL;
}

int WINAPI LoadStringW(HINSTANCE instance, UINT id, WCHAR *buffer, int buflen)
{
    (void)instance;
    (void)id;
    if (buffer != NULL && buflen > 0)
    {
        buffer[0] = 0;
    }
    return 0;
}

/* The rundll32-wait loop: with no window there is no input to wake for, so
 * a plain object wait preserves the blocking semantics exactly. */
DWORD WINAPI MsgWaitForMultipleObjects(DWORD count, const HANDLE *handles, BOOL waitAll,
                                       DWORD milliseconds, DWORD wakeMask)
{
    (void)wakeMask;
    return WaitForMultipleObjects(count, handles, waitAll, milliseconds);
}

BOOL WINAPI PeekMessageW(MSG *msg, HWND hwnd, UINT filterMin, UINT filterMax, UINT remove)
{
    (void)msg;
    (void)hwnd;
    (void)filterMin;
    (void)filterMax;
    (void)remove;
    return FALSE;
}

LRESULT WINAPI DispatchMessageW(const MSG *msg)
{
    (void)msg;
    return 0;
}

LRESULT WINAPI SendDlgItemMessageW(HWND dialog, int controlId, UINT msg, WPARAM wparam,
                                   LPARAM lparam)
{
    (void)dialog;
    (void)controlId;
    (void)msg;
    (void)wparam;
    (void)lparam;
    return 0;
}

BOOL WINAPI GetWindowRect(HWND hwnd, RECT *rect)
{
    (void)hwnd;
    if (rect != NULL)
    {
        rect->left = rect->top = rect->right = rect->bottom = 0;
    }
    return FALSE;
}

/* ---- shell32/shlwapi stand-ins (dllimport: __imp_* below) ---------------- */

/* update_user_profile / start-menu legs: honest failure skips them. */
static HRESULT WINAPI glue_SHGetFolderPathW(HWND hwnd, int folder, HANDLE token, DWORD flags,
                                            WCHAR *path)
{
    (void)hwnd;
    (void)folder;
    (void)token;
    (void)flags;
    if (path != NULL)
    {
        path[0] = 0;
    }
    return E_FAIL;
}

static BOOL WINAPI glue_SHGetSpecialFolderPathW(HWND hwnd, WCHAR *path, int folder, BOOL create)
{
    (void)hwnd;
    (void)folder;
    (void)create;
    if (path != NULL)
    {
        path[0] = 0;
    }
    return FALSE;
}

static HRESULT WINAPI glue_SHGetSpecialFolderLocation(HWND hwnd, int folder, ITEMIDLIST **pidl)
{
    (void)hwnd;
    (void)folder;
    if (pidl != NULL)
    {
        *pidl = NULL;
    }
    return E_FAIL;
}

static HRESULT WINAPI glue_SHGetDesktopFolder(IShellFolder **folder)
{
    if (folder != NULL)
    {
        *folder = NULL;
    }
    return E_FAIL;
}

static void WINAPI glue_ILFree(ITEMIDLIST *pidl)
{
    (void)pidl;
}

static HINSTANCE WINAPI glue_ShellExecuteW(HWND hwnd, LPCWSTR verb, LPCWSTR file,
                                           LPCWSTR parameters, LPCWSTR directory, INT show)
{
    (void)hwnd;
    (void)verb;
    (void)file;
    (void)parameters;
    (void)directory;
    (void)show;
    /* <= 32 is the documented failure band (user/wine/programs/cmd/proskrnl_glue.c). */
    return (HINSTANCE)(ULONG_PTR)SE_ERR_ACCESSDENIED;
}

static HRESULT WINAPI glue_StrRetToBufW(STRRET *ret, const ITEMIDLIST *pidl, WCHAR *buffer,
                                        UINT length)
{
    (void)ret;
    (void)pidl;
    if (buffer != NULL && length > 0)
    {
        buffer[0] = 0;
    }
    return E_FAIL;
}

/* ---- wininet/newdev stand-ins (dllimport: __imp_* below) ----------------- */

static HINTERNET WINAPI glue_InternetOpenW(LPCWSTR agent, DWORD accessType, LPCWSTR proxy,
                                           LPCWSTR proxyBypass, DWORD flags)
{
    (void)agent;
    (void)accessType;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    return NULL;
}

static BOOL WINAPI glue_InternetCloseHandle(HINTERNET internet)
{
    (void)internet;
    return FALSE;
}

BOOL WINAPI UpdateDriverForPlugAndPlayDevicesA(HWND parent, const char *hardwareId,
                                               const char *infPath, DWORD flags,
                                               BOOL *rebootRequired)
{
    (void)parent;
    (void)hardwareId;
    (void)infPath;
    (void)flags;
    if (rebootRequired != NULL)
    {
        *rebootRequired = FALSE;
    }
    return FALSE;
}

/* ---- ws2_32 stand-ins (dllimport: __imp_* below) ------------------------- */

/* create_computer_name_keys reads the machine's name through gethostname
 * and seeds ComputerName/ActiveComputerName (+ the Tcpip Hostname keys)
 * from it. CUI-3 needs those keys populated: rpcrt4's ncacn_np server
 * handoff fails hard when GetComputerNameA cannot answer
 * (dlls/rpcrt4/rpc_transport.c rpcrt4_ncacn_np_handoff -> the SCM's RPC
 * server loop exits), and kernelbase reads the name from the registry keys
 * wineboot writes. There is no hostname source below this boundary, so the
 * glue answers a FIXED name — configuration, not NT contract (docs/03
 * "CUI-3 SCM notes"). ws2_32.dll itself stays unloadable until its unixlib
 * seam lands (Net-1); wineboot must not import it. */
int WINAPI gethostname(char *name, int namelen)
{
    static const char fixed[] = "proskrnl";
    if (name == NULL || namelen < (int)sizeof(fixed))
    {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    memcpy(name, fixed, sizeof(fixed));
    return 0;
}

int WINAPI getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                       struct addrinfo **result)
{
    (void)node;
    (void)service;
    (void)hints;
    if (result != NULL)
    {
        *result = NULL;
    }
    return EAI_FAIL;
}

void WINAPI freeaddrinfo(struct addrinfo *info)
{
    (void)info;
}

/* ---- dllimport indirection ----------------------------------------------- */

/* These headers declare their functions dllimport, so wineboot.c's calls go
 * through __imp_* pointers (user/wine/programs/cmd/proskrnl_glue.c precedent). */
HRESULT(WINAPI *__imp_SHGetFolderPathW)(HWND, int, HANDLE, DWORD, WCHAR *) = glue_SHGetFolderPathW;
BOOL(WINAPI *__imp_SHGetSpecialFolderPathW)
(HWND, WCHAR *, int, BOOL) = glue_SHGetSpecialFolderPathW;
HRESULT(WINAPI *__imp_SHGetSpecialFolderLocation)
(HWND, int, ITEMIDLIST **) = glue_SHGetSpecialFolderLocation;
HRESULT(WINAPI *__imp_SHGetDesktopFolder)(IShellFolder **) = glue_SHGetDesktopFolder;
void(WINAPI *__imp_ILFree)(ITEMIDLIST *) = glue_ILFree;
HINSTANCE(WINAPI *__imp_ShellExecuteW)
(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT) = glue_ShellExecuteW;
HRESULT(WINAPI *__imp_StrRetToBufW)
(STRRET *, const ITEMIDLIST *, WCHAR *, UINT) = glue_StrRetToBufW;
HINTERNET(WINAPI *__imp_InternetOpenW)
(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = glue_InternetOpenW;
BOOL(WINAPI *__imp_InternetCloseHandle)(HINTERNET) = glue_InternetCloseHandle;
/* These four are referenced as PLAIN symbols by wineboot.c (wine's
 * ws2tcpip.h/newdev.h carry no dllimport under __WINESRC__), so they are
 * defined above under their real names; the __imp_ aliases cover any
 * dllimport-compiled reference too. */
BOOL(WINAPI *__imp_UpdateDriverForPlugAndPlayDevicesA)
(HWND, const char *, const char *, DWORD, BOOL *) = UpdateDriverForPlugAndPlayDevicesA;
int(WINAPI *__imp_gethostname)(char *, int) = gethostname;
int(WINAPI *__imp_getaddrinfo)(const char *, const char *, const struct addrinfo *,
                               struct addrinfo **) = getaddrinfo;
void(WINAPI *__imp_freeaddrinfo)(struct addrinfo *) = freeaddrinfo;
