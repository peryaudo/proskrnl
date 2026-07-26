/*
 * shim.h - what user/wine/server/shim.c publishes to the rest of the build.
 *
 * The GUI process compiles the pinned wineserver's GUI object model
 * (server/{object,handle,user,atom,class,winstation,window,queue,region,
 * clipboard,hook}.c, unmodified) and reaches it through an in-process
 * wine_server_call. This header is the seam between that code and the parts
 * of wineserver that are NOT compiled here - the unix event loop, the fd
 * layer, the security engine, the process/thread model.
 */
#ifndef PRSK_SERVER_SHIM_H
#define PRSK_SERVER_SHIM_H

/* Bring up the one process/thread pair, the session mapping and the timeout
 * service thread. Idempotent; called from wine_server_call. */
extern int prsk_server_init(void);

/* The kernel event that mirrors a message queue's wake predicate. win32u
 * waits on it inside NtUserMsgWaitForMultipleObjectsEx, exactly as it waits
 * on wineserver's queue handle (dlls/win32u/message.c, wait_message). */
extern void *prsk_queue_event( struct msg_queue *queue );

/* Recompute every queue's event from its shared wake/changed bits. Called
 * after any handler that could have changed them, with the server lock
 * still held. */
extern void prsk_wake_queues(void);

#endif /* PRSK_SERVER_SHIM_H */
