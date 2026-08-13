/*
 * winefb_unit.h - the plain-integer seam between the two header worlds of
 * the compositor unit test (docs/08).
 *
 * winefb_mocks.c compiles in wine-header land (the driver's own flags);
 * winefb_unit.c compiles in ntapi-harness land (system mingw headers). This
 * header is the only thing both include, so it speaks C integers and
 * nothing else. Windows are named by their handle VALUE; rects are
 * left,top,right,bottom in screen pixels; colors are 0xRRGGBB, which on the
 * 32bpp BGRX scanout the mock configures is also the packed pixel value.
 */
#ifndef PRSK_WINEFB_UNIT_H
#define PRSK_WINEFB_UNIT_H

#define UNIT_MAX_WINDOWS 80 /* enough to overflow WINEFB_MAX_TOPLEVELS (64) */
#define UNIT_MAX_REDRAWS 128

/* fixture: the desktop the mock server answers with. unit_add_window order
 * is topmost first, the get_window_list contract. */
void unit_reset(unsigned int width, unsigned int height);
void unit_add_window(unsigned int hwnd, int left, int top, int right, int bottom, int clientLeft,
                     int clientTop, int clientRight, int clientBottom, int visible);
void unit_set_desktop(unsigned int hwnd);
void unit_set_visible(unsigned int hwnd, int visible);

/* the driver under test */
int unit_create_surface(unsigned int hwnd, int left, int top, int right, int bottom);
void unit_release_surface(unsigned int hwnd);
void unit_surface_fill(unsigned int hwnd, unsigned int argb);
void unit_pos_changed(unsigned int hwnd, unsigned int insert_after, unsigned int swp_flags,
                      int left, int top, int right, int bottom, int with_surface);
void unit_flush_dirty(unsigned int hwnd, int left, int top, int right, int bottom);
void unit_set_clip(unsigned int hwnd, const int *rects, unsigned int count);
void unit_flush_shaped(unsigned int hwnd, const unsigned char *shape, int stride, int topdown);
void unit_repaint_rect(int left, int top, int right, int bottom, unsigned int exclude);
void unit_activate(unsigned int hwnd, unsigned int previous);

/* observation */
unsigned int unit_pixel(int x, int y);
unsigned int unit_bg(void);
unsigned int unit_redraw_count(void);
unsigned int unit_report_count(void);
unsigned int unit_redraw_hwnd(unsigned int i);
int unit_redraw_whole(unsigned int i);             /* 1 = whole window + frame */
void unit_redraw_rect(unsigned int i, int out[4]); /* client-relative */
unsigned int unit_raise_count(void);
unsigned int unit_raise_hwnd(unsigned int i);
unsigned int unit_raise_after(unsigned int i); /* 0 = HWND_TOP */
unsigned int unit_raise_flags(unsigned int i);

#endif /* PRSK_WINEFB_UNIT_H */
