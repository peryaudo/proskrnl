/* kernel/init/bootvid.c — the kernel log on the framebuffer (Art. 9).
 *
 * The serial port is the machine channel and stays exactly what it was: every
 * byte still goes out COM1 first, and this file cannot change one of them.
 * What it adds is a second, human channel — the same log drawn on whatever
 * framebuffer the bootloader set, so a box with no serial wire (and a GUI
 * boot watched on screen) shows what went wrong before the GUI comes up.
 *
 * Glyph rendering is Flanterm's (third_party/flanterm, BSD-2-Clause, pinned
 * and unmodified — docs/11 "Third-party code inside the kernel image"). We
 * call its public API and nothing else. Two properties of its framebuffer
 * backend are what let this run as the second thing the kernel ever does:
 * with both allocator callbacks null it allocates out of a static pool, so
 * no MiAllocatePool is needed, and it draws through the plain HHDM pointer
 * Limine hands us, which the bootloader's page tables already map and
 * MiInitializeVirtualMemory re-maps at the same address (arch/x86_64/mmu.c
 * maps EVERY memmap entry, the framebuffer region included) — so the console
 * survives the CR3 switch without knowing it happened.
 *
 * The console owns the scanout until FbInitialize publishes \Device\Fb0, and
 * not one instruction longer: KiBootVideoShutdown is the hand-off, and after
 * it those pixels have exactly one owner again (Art. 11).
 */
#include "kernel/init/bootvid.h"
#include "kernel/lib/dbgprint.h"

#include <stddef.h>
#include <stdint.h>

#include <limine.h>

#include <flanterm.h>
#include <flanterm_backends/fb.h>

/* Limine hands the framebuffer's address as an HHDM VIRTUAL pointer with the
 * offset already added, and LIMINE_FRAMEBUFFER_RGB names the channel-mask
 * layout (limine PROTOCOL.md "Framebuffer feature" and the pointer
 * convention; third_party/limine-protocol/include/limine.h). This is the
 * image's only framebuffer request — drivers/fb.c reads the same response
 * through KiGetBootFramebuffer (G10). The linker script collects
 * .limine_requests from any object (arch/x86_64/linker.ld), so it does not
 * matter which one declares it. */
__attribute__((used, section(".limine_requests"))) static volatile struct limine_framebuffer_request
    KiFramebufferRequest = {.id = LIMINE_FRAMEBUFFER_REQUEST_ID, .revision = 0, .response = 0};

static struct flanterm_context *KiBootVideoTerminal;

/* Cleared by the hand-off. Checked on every character, so keep it a load. */
static int KiBootVideoActive;

/* DbgPrint is called from interrupt context (the clock tick, the panic path),
 * and a trap landing in the middle of flanterm_write would re-enter the
 * terminal's parser on its own half-updated state. Uniprocessor with no
 * kernel preemption (Art. 3), so a plain flag is the whole exclusion: a
 * re-entrant character is dropped from the screen — never from serial, which
 * dbgprint.c has already written by the time we are called. */
static int KiBootVideoInWrite;

struct limine_framebuffer *KiGetBootFramebuffer(void)
{
    volatile struct limine_framebuffer_response *response = KiFramebufferRequest.response;
    if (response == 0 || response->framebuffer_count == 0)
    {
        return 0;
    }
    return response->framebuffers[0];
}

void KiInitializeBootVideo(void)
{
    struct limine_framebuffer *framebuffer = KiGetBootFramebuffer();
    if (framebuffer == 0)
    {
        DbgPrint("bootvid: no Limine framebuffer; the boot log is serial only\n");
        return;
    }
    if (framebuffer->memory_model != LIMINE_FRAMEBUFFER_RGB || framebuffer->bpp != 32)
    {
        DbgPrint("bootvid: unsupported mode (model %u, %u bpp); the boot log is serial only\n",
                 (unsigned)framebuffer->memory_model, (unsigned)framebuffer->bpp);
        return;
    }

    /* Null allocator callbacks select the backend's static pool (no memory
     * manager yet); null canvas, colours and font select its defaults; the
     * two zero scales let it pick a font scale from the resolution. */
    KiBootVideoTerminal = flanterm_fb_init(
        0, 0, (uint32_t *)framebuffer->address, framebuffer->width, framebuffer->height,
        framebuffer->pitch, framebuffer->red_mask_size, framebuffer->red_mask_shift,
        framebuffer->green_mask_size, framebuffer->green_mask_shift, framebuffer->blue_mask_size,
        framebuffer->blue_mask_shift, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        FLANTERM_FB_ROTATE_0);
    if (KiBootVideoTerminal == 0)
    {
        DbgPrint("bootvid: terminal init failed; the boot log is serial only\n");
        return;
    }

    /* Draw per line rather than per character: the queue the backend keeps
     * turns a scrolling log from one VRAM pass per glyph into one per flush,
     * and a line is the unit a reader waits for anyway. The panic path ends
     * its lines like everything else, so nothing is left unflushed. */
    flanterm_set_autoflush(KiBootVideoTerminal, false);
    KiBootVideoActive = 1;
}

int KiTestBootVideo(void)
{
    struct limine_framebuffer *framebuffer = KiGetBootFramebuffer();
    if (!KiBootVideoActive)
    {
        DbgPrint("[KTEST] bootvid ABSENT\n");
        return 1;
    }

    size_t columns = 0;
    size_t rows = 0;
    flanterm_get_dimensions(KiBootVideoTerminal, &columns, &rows);
    DbgPrint("[KTEST] bootvid PASS %ux%u chars on %ux%u\n", (unsigned)columns, (unsigned)rows,
             (unsigned)framebuffer->width, (unsigned)framebuffer->height);

    /* The line above is on the wire; the point of this check is that it is
     * also on the glass. A console that initializes and then draws nothing
     * (wrong pointer, wrong pitch, a backend that quietly refused) is the one
     * failure the serial log cannot show, so read the scanout back: the text
     * just drawn must have lit at least one pixel in the top band. */
    const volatile uint32_t *scanout = (const volatile uint32_t *)framebuffer->address;
    uint64_t stride = framebuffer->pitch / sizeof(uint32_t);
    uint64_t band = framebuffer->height < 64 ? framebuffer->height : 64;
    for (uint64_t y = 0; y < band; y++)
    {
        for (uint64_t x = 0; x < framebuffer->width; x++)
        {
            if (scanout[y * stride + x] != 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

void KiBootVideoPutChar(char c)
{
    if (!KiBootVideoActive || KiBootVideoInWrite)
    {
        return;
    }
    KiBootVideoInWrite = 1;
    flanterm_write(KiBootVideoTerminal, &c, 1);
    if (c == '\n')
    {
        flanterm_flush(KiBootVideoTerminal);
    }
    KiBootVideoInWrite = 0;
}

void KiBootVideoShutdown(void)
{
    if (!KiBootVideoActive)
    {
        return;
    }
    flanterm_flush(KiBootVideoTerminal);
    KiBootVideoActive = 0;

    /* Deliberately not flanterm_deinit: the static pool cannot be returned
     * anyway, and leaving the context intact means a later panic finds no
     * freed state. It is inert either way — KiBootVideoPutChar is now a
     * no-op, and nothing else in the kernel touches those pixels again. */
}
