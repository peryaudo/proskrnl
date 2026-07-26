/*
 * input.c - \Device\Input0 into win32u's message queues.
 *
 * The device hands out raw evdev events, untranslated (drivers/hidproto.h
 * -- scancode translation was explicitly deferred to user32, which is
 * this). Turning them into Win32 input needs two steps and neither of them
 * is a keyboard layout:
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
 * The read loop is the one tests/gui/gui_smoke.c proved at GUI-1: exclusive
 * open, blocking NtReadFile, whole 8-byte events. It runs on its own thread
 * because the device has no async path (HACK-002: no IRQ, the driver polls
 * inside the blocking read).
 */

#include "winefb.h"
#include "wine/debug.h"

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

    RtlInitUnicodeString( &name, input0 );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    /* Exclusive by contract (drivers/hidproto.h): sharing 0. */
    if (NtCreateFile( &device, FILE_GENERIC_READ | SYNCHRONIZE, &attr, &io, NULL,
                      FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0 ))
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

void winefb_start_input(void)
{
    HANDLE thread;

    if (NtCreateThreadEx( &thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), input_thread, NULL,
                          0, 0, 0, 0, NULL ))
    {
        ERR( "cannot start the input thread\n" );
        return;
    }
    NtClose( thread );
}
