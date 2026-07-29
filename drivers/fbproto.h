/* drivers/fbproto.h — the \Device\Fb0 contract (GUI-1, HACK-001).
 *
 * The kernel <-> user protocol for the framebuffer device, shared by
 * drivers/fb.c and everything that opens \Device\Fb0 (tests/gui, and
 * user/wine/dlls/winefb.drv/display.c from GUI-2). The condrvproto.h precedent:
 * this is a proskrnl-internal contract, so it lives outside abi/ — there is
 * nothing in Wine's headers to generate it from (Art. 4 governs values that
 * exist in the NT contract; this device does not exist in NT at all).
 *
 * \Device\Fb0 is HACK-001 (docs/10): NT owns the framebuffer behind a
 * display driver below win32k, and route (a) (docs/07) has no such thing,
 * so win32u's backend needs somewhere to blit. The device sits at the
 * OUTSIDE of the boundary — no Nt* call learns about it, nothing in
 * kernel/ or abi/ changes shape (Art. 2's GUI exception).
 *
 * The device is used the ordinary NT way, which is the whole point of
 * shaping it like this:
 *
 *   NtOpenFile(\Device\Fb0, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
 *   NtDeviceIoControlFile(IOCTL_PRSFB_GET_MODE)  -> FB_MODE_INFO
 *   NtCreateSection(PAGE_READWRITE, SEC_COMMIT, fbHandle)
 *   NtMapViewOfSection                            -> the scanout, mapped
 *
 * i.e. exactly MapViewOfFile(CreateFileMapping(hDevice)) at the Win32
 * level. Writes through the view land in the scanout with no flush.
 */
#ifndef PROSKRNL_DRIVERS_FBPROTO_H
#define PROSKRNL_DRIVERS_FBPROTO_H

#include <stdint.h>

/* CTL_CODE / METHOD_BUFFERED / FILE_READ_ACCESS / FILE_DEVICE_VIDEO. Both
 * sides of this contract get them from their own view of the same Microsoft
 * definitions: the kernel from abi/ntioapi.h (generated from the pinned
 * Wine winioctl.h, Art. 4), a PE client from mingw's winioctl.h. The values
 * agree -- FILE_DEVICE_VIDEO is 0x23 in both -- which is the point of
 * generating rather than retyping them. */
#ifdef _WIN32
#include <winioctl.h>
#else
#include "abi/ntioapi.h"
#endif

/* Function code 0x800: 0x000-0x7FF are reserved to Microsoft, custom codes
 * start at 0x800 (MS docs, "Defining I/O Control Codes"). */
#define IOCTL_PRSFB_GET_MODE CTL_CODE(FILE_DEVICE_VIDEO, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

/* The mode the bootloader set, reported verbatim — the kernel never picks
 * or changes a mode (there is no mode-set path; GUI-1 takes what Limine
 * hands it). The mask fields describe pixel layout the same way the Limine
 * boot protocol does, so a client composes colours without assuming BGRA:
 * channel value << shift, `size` bits wide. */
typedef struct FB_MODE_INFO
{
    uint32_t width;  /* pixels */
    uint32_t height; /* pixels */
    uint32_t pitch;  /* BYTES per scanline; may exceed width * bytesPerPixel */
    uint32_t bpp;    /* bits per pixel; 32 is all GUI-1 publishes */
    uint8_t redMaskSize;
    uint8_t redMaskShift;
    uint8_t greenMaskSize;
    uint8_t greenMaskShift;
    uint8_t blueMaskSize;
    uint8_t blueMaskShift;
    uint8_t memoryModel; /* FB_MEMORY_MODEL_RGB */
    uint8_t reserved;
    uint64_t size; /* mappable bytes = pitch * height; the section's size */
} FB_MODE_INFO;
/* Both sides are x86-64 with the same alignment rules, but the contract is
 * a byte layout, so pin it rather than trusting two compilers to agree. */
_Static_assert(sizeof(FB_MODE_INFO) == 32, "FB_MODE_INFO layout is the \\Device\\Fb0 contract");

/* The only memory model GUI-1 publishes; the value is Limine's
 * LIMINE_FRAMEBUFFER_RGB (third_party/limine-protocol/include/limine.h),
 * passed through rather than retyped. */
#define FB_MEMORY_MODEL_RGB 1

#endif /* PROSKRNL_DRIVERS_FBPROTO_H */
