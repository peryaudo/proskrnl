/* drivers/fb.c — \Device\Fb0 over the Limine framebuffer (GUI-1, HACK-001).
 *
 * The kernel half of the GUI path's display: publish the linear framebuffer
 * the bootloader already set, and let a user process map it. That is the
 * entire job — there is no mode set, no drawing, no cursor, no acceleration
 * and no display-driver model. Everything above the scanout belongs to
 * win32u's backend in user mode (docs/07, route (a)); everything below it
 * belongs to the bootloader.
 *
 * HACK-001 (docs/10): NT has no such device — it owns the framebuffer
 * behind a display driver below win32k — so this sits at the OUTSIDE of the
 * boundary, a new device and nothing else. No Nt* call learns about it and
 * no abi/ layout changes (Art. 2's GUI exception). Deleting drivers/fb.*,
 * drivers/fbproto.h, the Makefile line and the FbInitialize() call restores
 * the pre-GUI kernel exactly (Art. 7).
 *
 * The mapping mechanism is the interesting part, and it is deliberately not
 * new machinery: the device implements the ordinary GetCache vfs op
 * (kernel/io/vfs.h) and hands back a page cache whose frames ARE the
 * scanout's physical pages. NtCreateSection over the handle then works
 * through IopBuildSectionBacking and MiMapViewOfSection unchanged, so a
 * client maps the framebuffer with exactly the calls it would use to map a
 * file, and kernel/mm gains nothing at all (G10/Art. 11: no second mapping
 * path). NtReadFile/NtWriteFile on the handle fall out of the same seam.
 *
 * The framebuffer itself is not this file's to find: kernel/init/bootvid.c
 * declares the one Limine framebuffer request in the image, because the boot
 * console consumes it far earlier than the first kernel thread runs. We take
 * the same response through KiGetBootFramebuffer (G10 — one authority) and
 * shut the console down before publishing, so the scanout never has two
 * owners (Art. 11).
 */
#include "drivers/fb.h"
#include "drivers/fbproto.h"
#include "kernel/io/io.h"
#include "kernel/io/vfs.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/pagecache.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/init/bootvid.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"

#include <limine.h>

/* fbproto.h states the memory model to its clients without dragging the
 * Limine header into a PE build, so pin the two together here — the one
 * place both are visible — rather than trusting a copied 1 to stay right. */
_Static_assert(FB_MEMORY_MODEL_RGB == LIMINE_FRAMEBUFFER_RGB,
               "the \\Device\\Fb0 memory model is Limine's, passed through");

/* --- driver state ------------------------------------------------------------ */

static FB_MODE_INFO FbMode;
static IO_FCB FbFcb;

/* The scanout's pages, in the shape the Mm section path already understands
 * (kernel/mm/pagecache.h). These frames are NOT owned by the frame
 * allocator: the framebuffer sits outside the Limine memmap's usable
 * entries, so kernel/mm/phys.c never had them to hand out, and nothing here
 * ever frees them. */
static MI_PAGE_CACHE FbCache;

/* --- the device ops (see kernel/io/vfs.h) ------------------------------------ */

static NTSTATUS FbCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                         PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                         ULONG fileAttributes, ULONG disposition, ULONG options,
                         ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }
    file->fsContext = &FbFcb;
    file->fcb = &FbFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void FbCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void FbClose(PFILE_OBJECT file)
{
    (void)file;
}

/* The seam that makes NtCreateSection + NtMapViewOfSection work: the
 * "cache" backing this stream is the scanout itself. */
static NTSTATUS FbGetCache(PFILE_OBJECT file, PMI_PAGE_CACHE *cache)
{
    (void)file;
    *cache = &FbCache;
    return STATUS_SUCCESS;
}

/* Nothing to write back: a store through a mapped view (or a cached write
 * from kernel/io/rw.c) has already landed in the scanout — there is no
 * farther copy of these bytes anywhere. Present because rw.c calls it
 * unconditionally on the write path, and succeeding is the truth here. */
static NTSTATUS FbWritebackRange(PFILE_OBJECT file, uint64_t offset, uint64_t length)
{
    (void)file;
    (void)offset;
    (void)length;
    return STATUS_SUCCESS;
}

static NTSTATUS FbGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    info->fileAttributes = FILE_ATTRIBUTE_NORMAL;
    info->endOfFile = FbCache.fileSize;
    info->allocationSize = FbCache.fileSize;
    return STATUS_SUCCESS;
}

static NTSTATUS FbQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity, ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Fb0");
    ULONG full = sizeof(name) - sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

static NTSTATUS FbDeviceControl(PFILE_OBJECT file, ULONG code, const void *input, ULONG inputLength,
                                void *output, ULONG outputLength, ULONG_PTR *infoOut,
                                IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)input;
    (void)inputLength;
    (void)request;

    if (code == IOCTL_PRSFB_GET_MODE)
    {
        if (outputLength < sizeof(FB_MODE_INFO))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }
        memcpy(output, &FbMode, sizeof(FbMode));
        *infoOut = sizeof(FbMode);
        return STATUS_SUCCESS;
    }

    /* Art. 12: name the refusal on serial and return the refusal status —
     * never a no-op success for a verb this device does not have. */
    DbgPrint("fb: unimplemented ioctl %#lx\n", (unsigned long)code);
    return STATUS_NOT_IMPLEMENTED;
}

static const IO_VFS_OPS FbOps = {
    .Create = FbCreate,
    .Cleanup = FbCleanup,
    .Close = FbClose,
    .GetCache = FbGetCache,
    .WritebackRange = FbWritebackRange,
    .GetInfo = FbGetInfo,
    .QueryName = FbQueryName,
    .DeviceControl = FbDeviceControl,
};

/* --- initialization ---------------------------------------------------------- */

void FbInitialize(void)
{
    struct limine_framebuffer *fb = KiGetBootFramebuffer();
    if (fb == 0)
    {
        DbgPrint("fb: no Limine framebuffer; \\Device\\Fb0 not published\n");
        return;
    }

    /* Publish only what GUI-1 actually supports. Anything else refuses by
     * being absent rather than by being published and lying about itself. */
    if (fb->memory_model != LIMINE_FRAMEBUFFER_RGB || fb->bpp != 32)
    {
        DbgPrint("fb: unsupported mode (model %u, %u bpp); \\Device\\Fb0 not published\n",
                 (unsigned)fb->memory_model, (unsigned)fb->bpp);
        return;
    }

    /* Recover the physical base: Limine's pointer is the HHDM alias, and
     * MiPhysicalToVirtual(0) is that same window's base. */
    uint64_t hhdmBase = (uint64_t)(uintptr_t)MiPhysicalToVirtual(0);
    uint64_t physicalBase = (uint64_t)(uintptr_t)fb->address - hhdmBase;
    if ((physicalBase & (PAGE_SIZE - 1)) != 0)
    {
        DbgPrint("fb: framebuffer at %#lx is not page-aligned; \\Device\\Fb0 not published\n",
                 (unsigned long)physicalBase);
        return;
    }

    uint64_t size = fb->pitch * fb->height;
    ULONG pageCount = (ULONG)((size + PAGE_SIZE - 1) / PAGE_SIZE);
    uint64_t *frames = MiAllocatePool(pageCount * sizeof(uint64_t));
    if (frames == 0)
    {
        KiPanic("FbInitialize: cannot allocate the framebuffer frame list");
    }
    for (ULONG i = 0; i < pageCount; i++)
    {
        frames[i] = physicalBase + (uint64_t)i * PAGE_SIZE;
    }

    /* A page cache the Mm section path can map, built by hand because these
     * frames are the device's, not the allocator's (MiInitializePageCache
     * would start an empty, owned one). */
    FbCache.fileSize = size;
    FbCache.pageCount = pageCount;
    FbCache.capacity = pageCount;
    FbCache.frames = frames;

    FbMode.width = (uint32_t)fb->width;
    FbMode.height = (uint32_t)fb->height;
    FbMode.pitch = (uint32_t)fb->pitch;
    FbMode.bpp = fb->bpp;
    FbMode.redMaskSize = fb->red_mask_size;
    FbMode.redMaskShift = fb->red_mask_shift;
    FbMode.greenMaskSize = fb->green_mask_size;
    FbMode.greenMaskShift = fb->green_mask_shift;
    FbMode.blueMaskSize = fb->blue_mask_size;
    FbMode.blueMaskShift = fb->blue_mask_shift;
    FbMode.memoryModel = fb->memory_model;
    FbMode.reserved = 0;
    FbMode.size = size;

    /* The hand-off. From the instant \Device\Fb0 exists a client can map the
     * scanout and blit, so the boot console stops here — one owner of these
     * pixels at a time (Art. 11). It is deliberately the LAST thing before
     * publishing and not one line earlier: every failure path above leaves
     * the console alive, because nothing can take the framebuffer when the
     * device was never published. */
    KiBootVideoShutdown();

    IopInitializeFcb(&FbFcb);
    IoPublishDevice(WSTR("\\Device\\Fb0"), &FbOps, 0, FILE_DEVICE_VIDEO);
    DbgPrint("fb: \\Device\\Fb0 %ux%u %ubpp pitch %u at %#lx (%lu KiB)\n", FbMode.width,
             FbMode.height, FbMode.bpp, FbMode.pitch, (unsigned long)physicalBase,
             (unsigned long)(size / 1024));
}
