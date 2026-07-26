/* drivers/fb.h — \Device\Fb0, the Limine framebuffer (GUI-1, HACK-001).
 * The wire contract is drivers/fbproto.h. */
#ifndef PROSKRNL_DRIVERS_FB_H
#define PROSKRNL_DRIVERS_FB_H

/* Publish \Device\Fb0 over whatever framebuffer the bootloader set. Needs a
 * handle table (IoPublishDevice), so it runs on the first kernel thread. No
 * framebuffer, or one in a shape GUI-1 does not publish, means no device:
 * an open then fails STATUS_OBJECT_NAME_NOT_FOUND, which is the honest
 * answer rather than a device that pretends (Art. 12). */
void FbInitialize(void);

#endif /* PROSKRNL_DRIVERS_FB_H */
