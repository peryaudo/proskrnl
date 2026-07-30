/*
 * input.c - \Device\Input0 and \Device\Input1 into win32u's message queues.
 *
 * The devices hand out raw evdev events, untranslated (drivers/hidproto.h
 * -- translation was explicitly deferred to user32, which is this).
 *
 * Keyboard: turning events into Win32 input needs two steps and neither of
 * them is a keyboard layout:
 *
 *   evdev keycode -> AT set-1 scancode, which is a fixed table;
 *   scancode -> vkey, which win32u does itself before the message is
 *   queued (dlls/win32u/message.c, map_scan_to_kbd_vkey), using its
 *   built-in kbdus tables because this driver exports no
 *   pKbdLayerDescriptor.
 *
 * So the driver only owes the first step. Wayland keys ARE evdev keycodes,
 * so Wine already has that table: key2scan in
 * dlls/winewayland.drv/wayland_keyboard.c. The subset below is the base
 * range plus the extended keys winemine can be driven with; anything else
 * takes the same made-up extended scancode Wine's own fallback produces,
 * which is wrong in the same way on both and therefore comparable.
 *
 * Pointer (GUI-4): the tablet's absolute axes scale to screen pixels --
 * the range comes from the device itself (IOCTL_PRSHID_GET_ABS_INFO), the
 * screen from the scanout mode, so no QEMU constant is baked here -- and
 * inject as MOUSEEVENTF_ABSOLUTE hardware input the way winewayland's
 * pointer does (dlls/winewayland.drv/wayland_pointer.c,
 * pointer_handle_motion_internal): screen pixels go to the server
 * verbatim, which routes by capture and coordinate
 * (server/queue.c find_hardware_message_window). hwnd 0 on purpose: this
 * reader serves the whole desktop, not one window, and the server needs
 * no window hint to hit-test. MOUSEEVENTF_MOVE_NOCOALESCE keeps win32u
 * from holding motion back (dlls/win32u/input.c accum_mouse_motion) --
 * QEMU already coalesced whatever needed coalescing.
 *
 * The read loops are the one tests/gui/gui_smoke.c proved at GUI-1:
 * exclusive open, blocking NtReadFile, whole 8-byte events. Each runs on
 * its own thread because the devices have no async path (HACK-002: no
 * IRQ, the driver polls inside the blocking read).
 */

#include "winefb.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

#include "drivers/hidproto.h"

/* evdev keycodes, from Linux's input-event-codes.h -- the numbers virtio's
 * spec points at for EV_KEY (virtio 1.2 cs01 sec. 5.8.6, which defers to
 * the Linux input protocol). Only the ones this table names are used. */
#define KEY_KPDOT       83
#define KEY_F11         87
#define KEY_F12         88
#define KEY_KPENTER     96
#define KEY_RIGHTCTRL   97
#define KEY_KPSLASH     98
#define KEY_SYSRQ       99
#define KEY_RIGHTALT    100
#define KEY_HOME        102
#define KEY_UP          103
#define KEY_PAGEUP      104
#define KEY_LEFT        105
#define KEY_RIGHT       106
#define KEY_END         107
#define KEY_DOWN        108
#define KEY_PAGEDOWN    109
#define KEY_INSERT      110
#define KEY_DELETE      111
#define KEY_PAUSE       119
#define KEY_LEFTMETA    125
#define KEY_RIGHTMETA   126
#define KEY_MENU        127

/* evdev keycode -> AT set-1 scancode. Values as in Wine's own key2scan
 * (dlls/winewayland.drv/wayland_keyboard.c), where 0x1xx means the 0xE0
 * prefix and 0x2xx the 0xE1 one. */
static WORD key_to_scan( UINT key )
{
    if (key <= KEY_KPDOT) return key;   /* the base range maps one to one */

    switch (key)
    {
    case KEY_SYSRQ:     return 0x0054;
    case KEY_F11:       return 0x0057;
    case KEY_F12:       return 0x0058;
    case KEY_KPENTER:   return 0x011c;
    case KEY_RIGHTCTRL: return 0x011d;
    case KEY_KPSLASH:   return 0x0135;
    case KEY_RIGHTALT:  return 0x0138;
    case KEY_HOME:      return 0x0147;
    case KEY_UP:        return 0x0148;
    case KEY_PAGEUP:    return 0x0149;
    case KEY_LEFT:      return 0x014b;
    case KEY_RIGHT:     return 0x014d;
    case KEY_END:       return 0x014f;
    case KEY_DOWN:      return 0x0150;
    case KEY_PAGEDOWN:  return 0x0151;
    case KEY_INSERT:    return 0x0152;
    case KEY_DELETE:    return 0x0153;
    case KEY_LEFTMETA:  return 0x015b;
    case KEY_RIGHTMETA: return 0x015c;
    case KEY_MENU:      return 0x015d;
    case KEY_PAUSE:     return 0x021d;
    }
    return 0x200 | (key & 0x7f);
}

static void inject_key( const HID_INPUT_EVENT *event )
{
    WORD scan = key_to_scan( event->code );
    INPUT input = { 0 };

    input.type = INPUT_KEYBOARD;
    input.ki.wScan = (scan & 0x300) ? scan + 0xdf00 : scan;
    input.ki.dwFlags = KEYEVENTF_SCANCODE;
    if (scan & ~0xff) input.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    /* evdev value 2 is auto-repeat, which Win32 spells as another press. */
    if (!event->value) input.ki.dwFlags |= KEYEVENTF_KEYUP;

    NtUserSendHardwareInput( NtUserGetForegroundWindow(), 0, &input, 0 );
}

static DWORD WINAPI input_thread( void *arg )
{
    static const WCHAR input0[] =
        {'\\','D','e','v','i','c','e','\\','I','n','p','u','t','0',0};
    HID_INPUT_EVENT events[32];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE device;
    NTSTATUS status;

    RtlInitUnicodeString( &name, input0 );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    /* Exclusive by contract (drivers/hidproto.h): sharing 0. */
    status = NtCreateFile( &device, FILE_GENERIC_READ | SYNCHRONIZE, &attr, &io, NULL,
                           FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
                           NULL, 0 );
    if (status == STATUS_SHARING_VIOLATION)
    {
        /* Another GUI process won the exclusive open and is the reader.
         * Losing that race is the designed outcome for every process but
         * one (each of them tries, the server routes globally), so it is
         * not reported as an absence. */
        TRACE( "input0 already has its reader\n" );
        return 0;
    }
    if (status)
    {
        /* No keyboard: the display half stands alone, so say so once and
         * stop rather than spinning on a device that is not there. */
        winefb_report( "[KTEST] gui2 input ABSENT\n" );
        return 0;
    }

    winefb_report( "[KTEST] gui2 input READY\n" );
    for (;;)
    {
        ULONG count, i;

        if (NtReadFile( device, NULL, NULL, NULL, &io, events, sizeof(events), NULL, NULL )) break;
        count = io.Information / sizeof(events[0]);
        for (i = 0; i < count; i++)
        {
            if (events[i].type != HID_EV_KEY) continue;   /* EV_SYN and the rest */
            inject_key( &events[i] );
        }
    }
    NtClose( device );
    return 0;
}

/* --- the pointer (GUI-4) ------------------------------------------------- */

/* One report's worth of button/wheel INPUTs; QEMU's tablet sends at most a
 * couple of button transitions between SYNs. */
#define POINTER_MAX_CLICKS 8

struct pointer_report
{
    UINT last_x, last_y; /* raw device values; persist across reports */
    BOOL moved;          /* an axis changed since the last SYN */
    UINT buttons;        /* bit 0/1/2 = left/right/middle, for the marker */
    INPUT clicks[POINTER_MAX_CLICKS];
    UINT click_count;
    int screen_x, screen_y; /* last injected position */
};

static void inject_pointer( INPUT *input )
{
    input->type = INPUT_MOUSE;
    NtUserSendHardwareInput( 0, SEND_HWMSG_RAWINPUT, input, 0 );
}

/* Device range -> screen pixels. Both ends inclusive; 64-bit intermediate
 * because 32767 * 32767 does not care, but 32767 * a future 4K width
 * might. */
static int scale_axis( UINT value, UINT min, UINT max, UINT screen )
{
    if (max <= min || screen == 0) return 0;
    if (value <= min) return 0;
    if (value >= max) return (int)screen - 1;
    return (int)(((ULONGLONG)(value - min) * (screen - 1)) / (max - min));
}

static void pointer_flush_report( struct pointer_report *report, const HID_ABS_INFO *abs )
{
    UINT i;

    /* Motion first: a button in the same report belongs at the report's
     * position, and the server stamps buttons with the cursor position it
     * already has (server/queue.c queue_mouse_message). */
    if (report->moved)
    {
        INPUT input = { 0 };

        report->screen_x = scale_axis( report->last_x, abs->minX, abs->maxX,
                                       winefb_scanout.mode.width );
        report->screen_y = scale_axis( report->last_y, abs->minY, abs->maxY,
                                       winefb_scanout.mode.height );
        input.mi.dx = report->screen_x;
        input.mi.dy = report->screen_y;
        input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE_NOCOALESCE;
        inject_pointer( &input );
        report->moved = FALSE;
    }
    for (i = 0; i < report->click_count; i++) inject_pointer( &report->clicks[i] );
    report->click_count = 0;
}

static void pointer_add_click( struct pointer_report *report, DWORD flags, DWORD data )
{
    INPUT *input;

    if (report->click_count >= POINTER_MAX_CLICKS) return;
    input = &report->clicks[report->click_count++];
    memset( input, 0, sizeof(*input) );
    input->mi.dwFlags = flags;
    input->mi.mouseData = data;
}

static DWORD WINAPI pointer_thread( void *arg )
{
    static const WCHAR input1[] =
        {'\\','D','e','v','i','c','e','\\','I','n','p','u','t','1',0};
    HID_INPUT_EVENT events[32];
    struct pointer_report report = { 0 };
    HID_ABS_INFO abs;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE device;
    NTSTATUS status;

    RtlInitUnicodeString( &name, input1 );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    /* Exclusive by contract (drivers/hidproto.h): sharing 0. */
    status = NtCreateFile( &device, FILE_GENERIC_READ | SYNCHRONIZE, &attr, &io, NULL,
                           FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
                           NULL, 0 );
    if (status == STATUS_SHARING_VIOLATION)
    {
        /* Losing the open still answers the question the cursor asks: a
         * pointer device EXISTS, and this process must therefore draw the
         * arrow into its own flushes from the shared position (cursor.c).
         * The device's exclusivity is the signal -- no protocol needed. */
        winefb_pointer_present = TRUE;
        TRACE( "input1 already has its reader\n" );
        return 0;
    }
    if (status)
    {
        /* No pointer: keyboard-only images say so once and stand alone.
         * winefb_pointer_present stays FALSE, so no process draws a
         * cursor. */
        winefb_report( "[KTEST] gui4 mouse ABSENT\n" );
        return 0;
    }
    winefb_pointer_present = TRUE;

    /* The device's own range, once; scaling with a stale range would be
     * wrong forever, and the range cannot change (the device model fixes
     * it before DRIVER_OK). */
    if (NtDeviceIoControlFile( device, NULL, NULL, NULL, &io, IOCTL_PRSHID_GET_ABS_INFO, NULL, 0,
                               &abs, sizeof(abs) ) || io.Information != sizeof(abs))
    {
        ERR( "IOCTL_PRSHID_GET_ABS_INFO failed\n" );
        winefb_report( "[KTEST] gui4 mouse FAULT absinfo\n" );
        NtClose( device );
        return 0;
    }

    winefb_report( "[KTEST] gui4 mouse READY abs=%u..%u,%u..%u\n", (unsigned)abs.minX,
                   (unsigned)abs.maxX, (unsigned)abs.minY, (unsigned)abs.maxY );
    for (;;)
    {
        ULONG count, i;
        BOOL flushed = FALSE;

        if (NtReadFile( device, NULL, NULL, NULL, &io, events, sizeof(events), NULL, NULL )) break;
        count = io.Information / sizeof(events[0]);
        for (i = 0; i < count; i++)
        {
            const HID_INPUT_EVENT *event = &events[i];

            switch (event->type)
            {
            case HID_EV_ABS:
                if (event->code == HID_ABS_X) { report.last_x = event->value; report.moved = TRUE; }
                else if (event->code == HID_ABS_Y) { report.last_y = event->value; report.moved = TRUE; }
                break;
            case HID_EV_KEY:
                switch (event->code)
                {
                case HID_BTN_LEFT:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_LEFTDOWN
                                                             : MOUSEEVENTF_LEFTUP, 0 );
                    report.buttons = event->value ? report.buttons | 1 : report.buttons & ~1u;
                    break;
                case HID_BTN_RIGHT:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_RIGHTDOWN
                                                             : MOUSEEVENTF_RIGHTUP, 0 );
                    report.buttons = event->value ? report.buttons | 2 : report.buttons & ~2u;
                    break;
                case HID_BTN_MIDDLE:
                    pointer_add_click( &report, event->value ? MOUSEEVENTF_MIDDLEDOWN
                                                             : MOUSEEVENTF_MIDDLEUP, 0 );
                    report.buttons = event->value ? report.buttons | 4 : report.buttons & ~4u;
                    break;
                }
                break;
            case HID_EV_REL:
                /* The wheel is a detent count; Win32 spells one detent
                 * WHEEL_DELTA, same sign (up/away positive). */
                if (event->code == HID_REL_WHEEL)
                    pointer_add_click( &report, MOUSEEVENTF_WHEEL,
                                       (DWORD)((int)event->value * WHEEL_DELTA) );
                break;
            case HID_EV_SYN:
                if (report.moved || report.click_count)
                {
                    pointer_flush_report( &report, &abs );
                    flushed = TRUE;
                }
                break;
            }
        }
        /* One line per drained batch, not per report: the harness gates on
         * position/buttons after it stops injecting, and a batch is the
         * natural coalescing unit under a fast host pointer. The cursor
         * follows the batch's final position (cursor.c; this thread is the
         * only one that MOVES it, though every process draws it). */
        if (flushed)
        {
            winefb_cursor_update();
            winefb_report( "[KTEST] gui4 ptr x=%d y=%d btn=%x\n", report.screen_x,
                           report.screen_y, (unsigned)report.buttons );
        }
    }
    NtClose( device );
    return 0;
}

/* Idempotent: every GUI process calls this from every hook that proves the
 * process is alive and off the loader lock (display enumeration, first
 * window surface), and exactly one attempt is made per process. The
 * devices open exclusively, so across processes exactly one reader wins;
 * the rest lose the race quietly above. Residual (docs/03 GUI-4 notes): if
 * the winning process dies, input is orphaned until a process that has not
 * yet attempted creates its first window surface. */
void winefb_start_input(void)
{
    static LONG started;
    HANDLE thread;

    if (InterlockedExchange( &started, 1 )) return;

    /* The cast is Wine's own idiom for handing a DWORD-returning routine to
     * NtCreateThreadEx (dlls/kernelbase/thread.c, CreateRemoteThreadEx): the
     * declared PRTL_THREAD_START_ROUTINE returns void, but the return value
     * is what becomes the thread's exit status. */
    if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                          (PRTL_THREAD_START_ROUTINE)input_thread, NULL,
                          0, 0, 0, 0, NULL ))
    {
        ERR( "cannot start the input thread\n" );
        return;
    }
    NtClose( thread );

    if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(),
                          (PRTL_THREAD_START_ROUTINE)pointer_thread,
                          NULL, 0, 0, 0, 0, NULL ))
    {
        ERR( "cannot start the pointer thread\n" );
        return;
    }
    NtClose( thread );
}
