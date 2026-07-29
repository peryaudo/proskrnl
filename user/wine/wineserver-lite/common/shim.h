/*
 * shim.h - what user/wine/wineserver-lite/common/shim.c publishes to the rest of the build.
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

/* Bring up the client list, the session mapping and the timeout service
 * thread. Idempotent; called from the first wine_server_call in the
 * in-process build, and from the server process's own start-up. */
extern int prsk_server_init(void);

/* One client == one process talking to this server. Opaque outside shim.c;
 * the transport only ever holds pointers to them. */
struct prsk_client;

/* The process this library is linked into, as a client. In the in-process
 * build it is the only one. */
extern struct prsk_client *prsk_local_client(void);

/* Register / retire a client that reached the server over the transport.
 * create takes the client's pid and an NT process handle the server keeps
 * (and closes on reap); reap runs the wineserver teardown for every thread
 * record the client still owns, then drops the client. */
extern struct prsk_client *prsk_attach_client( unsigned int pid, void *processHandle );
extern void prsk_reap_client( struct prsk_client *client );
extern void prsk_reap_thread( struct prsk_client *client, unsigned int tid );
extern void *prsk_client_process_handle( struct prsk_client *client );

/* The server half of one request: bind the calling thread's record, run the
 * handler, apply the reply fix-ups. Both modes go through it. */
extern unsigned int prsk_server_dispatch( struct prsk_client *client, unsigned int tid,
                                          struct __server_request_info *info );

/* NOTE: queue wake-ups are NOT declared here. They are reached through the
 * queue object's own get_sync op (server/queue.c) and duplicated out to the
 * client by the get_msg_queue_handle fix-up in shim.c, so no separate entry
 * point is needed. Two such declarations lived here unimplemented until
 * GUI-3 removed them.
 */

#endif /* PRSK_SERVER_SHIM_H */
