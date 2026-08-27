/*
 * inputmap.h - rawinput.c's event translation, kept apart so the numbers
 * are auditable in one screenful.
 *
 * \Device\Input0/1 hand out raw evdev events (drivers/hidproto.h), and
 * turning them into Win32 input needs two fixed pieces of arithmetic: the
 * evdev-keycode -> AT-set-1-scancode table, and the absolute-axis ->
 * screen-pixel scaling. The pump is the only reader of the devices
 * (clients never open them -- docs/03 "GUI-4 notes"), but the scaling is
 * still a cross-tree contract: the gui4/gui6/coldinput harness inverts
 * the formula exactly (tests/run/run.sh move_px) to predict the pixel a
 * synthetic tablet move lands on.
 */
#ifndef PRSK_INPUTMAP_H
#define PRSK_INPUTMAP_H

/* evdev keycodes, from Linux's input-event-codes.h -- the numbers virtio's
 * spec points at for EV_KEY (virtio 1.2 cs01 sec. 5.8.6, which defers to
 * the Linux input protocol). Only the ones the table names are used. */
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
static inline WORD prsk_key_to_scan( UINT key )
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

/* Device range -> screen pixels. Both ends inclusive; 64-bit intermediate
 * because 32767 * 32767 does not care, but 32767 * a future 4K width
 * might. The harness inverts this exactly (tests/run/run.sh move_px), so
 * a second copy that rounded differently would fail the gui4 echo. */
static inline int prsk_scale_axis( UINT value, UINT min, UINT max, UINT screen )
{
    if (max <= min || screen == 0) return 0;
    if (value <= min) return 0;
    if (value >= max) return (int)screen - 1;
    return (int)(((ULONGLONG)(value - min) * (screen - 1)) / (max - min));
}

#endif /* PRSK_INPUTMAP_H */
