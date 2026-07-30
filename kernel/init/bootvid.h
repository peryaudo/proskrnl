/* kernel/init/bootvid.h — the boot console: the kernel log, on the screen.
 *
 * Debug output is infrastructure (Art. 9), and a serial wire is not always
 * there to carry it. Everything DbgPrint writes — and everything a user-mode
 * NtDisplayString writes — is mirrored onto the framebuffer the bootloader
 * already set, from the second line of boot until the GUI takes the scanout.
 * Serial is unaffected and is always written first: this mirror can never
 * change what a verdict grep sees (docs/08).
 *
 * Nothing here is observable from an unprivileged .exe, so nothing here is
 * boundary behaviour (Art. 1) and no Nt* call learns about it. NT's own
 * boot-time equivalent is bootvid.sys / InbvDisplayString; we reproduce
 * neither its interface nor its internals, hence the internal Ki name
 * (docs/15).
 */
#ifndef PROSKRNL_KERNEL_INIT_BOOTVID_H
#define PROSKRNL_KERNEL_INIT_BOOTVID_H

struct limine_framebuffer;

/* The one Limine framebuffer request in the image. It lives here, not in
 * drivers/fb.c, because this is its earliest consumer: the boot console runs
 * before the memory manager, the GUI device runs on the first kernel thread.
 * One declaration = one authority (G10/Art. 11), and the dependency points
 * the right way for Art. 7 — the subtractable GUI driver leans on core debug
 * infrastructure, never the reverse. Null when the bootloader reported no
 * framebuffer. */
struct limine_framebuffer *KiGetBootFramebuffer(void);

/* Bring the console up. Called from KiSystemStartup as soon as the base
 * revision is known, before the memory manager exists: the terminal needs no
 * allocator (its backend has a static pool) and Limine's framebuffer pointer
 * is already mapped, both by the bootloader's tables and by ours. A
 * framebuffer in any shape the backend does not take means no console — the
 * boot log then goes to serial alone, exactly as before. */
void KiInitializeBootVideo(void);

/* Report the console's verdict on serial ([KTEST] bootvid PASS/ABSENT) and
 * confirm it is really drawing: the scanout is read back, because a console
 * that comes up and then paints nothing is precisely the failure the serial
 * log cannot show. Returns 0 only for that case — no framebuffer at all is
 * ABSENT, not a failure. */
int KiTestBootVideo(void);

/* Draw one character. A no-op before KiInitializeBootVideo and after
 * KiBootVideoShutdown. Called for every byte DbgPrint emits, so the inactive
 * path is deliberately a load and a branch. */
void KiBootVideoPutChar(char c);

/* Give the scanout up, for good: after this the console draws nothing and
 * the framebuffer belongs to whoever \Device\Fb0 hands it to. Exactly one
 * owner of those pixels at any instant (Art. 11). */
void KiBootVideoShutdown(void);

#endif /* PROSKRNL_KERNEL_INIT_BOOTVID_H */
