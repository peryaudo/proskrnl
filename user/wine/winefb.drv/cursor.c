/*
 * cursor.c - nothing yet, on purpose.
 *
 * docs/04 reserves this file for the driver's cursor half, and docs/07
 * describes the backend as one that "draws the cursor". It cannot: GUI-1
 * shipped a keyboard and no mouse (HACK-002 configures virtio-input's
 * eventq only, and QEMU is given a virtio-keyboard), so there is no pointer
 * to follow and no motion to erase behind. Drawing one anyway would be a
 * fixed picture of a lie.
 *
 * The driver therefore leaves pSetCursor, pGetCursorPos, pSetCursorPos and
 * pClipCursor unset, and __wine_set_user_driver's nulldrv_* defaults answer
 * them the way Wine answers on a driver with no pointer device. The cursor
 * arrives with the mouse, in GUI-4 (docs/02).
 *
 * Kept as a file rather than as a note so the layout docs/04 promises is
 * the layout on disk, and so the next milestone has an obvious place to
 * start.
 */
