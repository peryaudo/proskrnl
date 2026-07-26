/*
 * poll.h — the two declarations wineserver's object.h reaches for.
 *
 * GUI-2 compiles the pinned wineserver's GUI state machine as PE code inside
 * the GUI process (user/wine/server/). Nothing in that subset ever polls: the
 * fd layer is stubbed out (user/wine/server/shim.c), and waiting is a kernel
 * event, not a descriptor. Only the type has to exist so `struct object_ops`
 * can name it.
 */
#ifndef PRSK_POLL_H
#define PRSK_POLL_H

struct pollfd
{
    int fd;
    short events;
    short revents;
};

#define POLLIN   0x001
#define POLLPRI  0x002
#define POLLOUT  0x004
#define POLLERR  0x008
#define POLLHUP  0x010
#define POLLNVAL 0x020

#endif /* PRSK_POLL_H */
