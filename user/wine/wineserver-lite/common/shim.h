/*
 * shim.h - what user/wine/wineserver-lite/common/shim.c publishes to the rest of the build.
 *
 * wineserver-lite.exe compiles the pinned wineserver's GUI object model
 * (server/{object,handle,user,atom,class,winstation,window,queue,region,
 * clipboard,hook}.c, unmodified) and reaches it from its transport loop.
 * This header is the seam between that code and the parts of wineserver
 * that are NOT compiled here - the unix event loop, the fd layer, the
 * security engine, the process/thread model.
 */
#ifndef PRSK_SERVER_SHIM_H
#define PRSK_SERVER_SHIM_H

/* Bring up the client list, the session mapping and the timeout service
 * thread. Idempotent; called from the server process's own start-up. */
extern int prsk_server_init(void);

/* One client == one process talking to this server. Opaque outside shim.c;
 * the transport only ever holds pointers to them. */
struct prsk_client;

/* Register / retire a client that reached the server over the transport.
 * create takes the client's pid and an NT process handle the server keeps
 * (and closes on reap); reap runs the wineserver teardown for every thread
 * record the client still owns, then drops the client. */
extern struct prsk_client *prsk_attach_client( unsigned int pid, void *processHandle );
extern void prsk_reap_client( struct prsk_client *client );
extern void prsk_reap_thread( struct prsk_client *client, unsigned int tid );
extern void *prsk_client_process_handle( struct prsk_client *client );

/* The server half of one request: bind the calling thread's record, run the
 * handler, apply the reply fix-ups. Every request goes through it. */
extern unsigned int prsk_server_dispatch( struct prsk_client *client, unsigned int tid,
                                          struct __server_request_info *info );

/* One request from a thread INSIDE the server process -- the raw-input pump
 * (server/rawinput.c), which is this build's RIT: it reads \Device\Input0/1
 * and injects through the same pinned handlers a client's request reaches,
 * under the same server lock the transport and timeout threads take. The
 * caller is bound to a synthetic client/thread record for the server's own
 * process, created on first use and never reaped (the server IS the
 * session; its death is the session's). */
extern unsigned int prsk_internal_dispatch( struct __server_request_info *info );

/* The pump's window queries need a desktop named explicitly (the synthetic
 * record has none for the requests' desktop=0 fallback): a handle to the
 * visible winstation's input desktop in the internal process's table, 0 if
 * there is none yet. Close it with prsk_internal_close after the queries
 * it was fetched for -- the input desktop can change across a winstation
 * switch. */
extern unsigned int prsk_internal_input_desktop(void);
extern void prsk_internal_close( unsigned int handle );

/* The published cursor image (dlls/winefb.drv/cursorshape.h): the server
 * owns the section (created at bring-up, before the pump and the transport)
 * and is its only writer. prsk_cursor_publish is PRSK_OP_SET_CURSOR's
 * server half -- `data` is the slot payload, one struct prsk_cursor_publish;
 * it refuses a publish for a window the pointer has since left
 * (STATUS_INVALID_HANDLE, the expected race) and a malformed one loudly.
 * prsk_cursor_shared is the pump's read side. prsk_cursor_reassert_default
 * puts the desktop's arrow back when the window under the pointer has no
 * thread to answer WM_WINE_SETCURSOR (the explorerless fixture's forced
 * desktop); returns nonzero when it changed the image. */
struct prsk_cursor_image;
extern const volatile struct prsk_cursor_image *prsk_cursor_shared(void);
extern unsigned int prsk_cursor_publish( const void *data, unsigned int size );
extern int prsk_cursor_reassert_default(void);

/* Start the pump's reader threads (server/rawinput.c). Called once from
 * the server's own start-up, BEFORE the transport is published: the
 * session's input devices are claimed before any client can exist, the
 * way the RIT owns the hardware before any Win32 process runs. Clients
 * never open \Device\Input0/1 (docs/03 "GUI-4 notes"). */
extern void prsk_rawinput_start(void);

/* NOTE: queue wake-ups are NOT declared here. They are reached through the
 * queue object's own get_sync op (server/queue.c) and duplicated out to the
 * client by the get_msg_queue_handle fix-up in shim.c, so no separate entry
 * point is needed. Two such declarations lived here unimplemented until
 * GUI-3 removed them.
 */

#endif /* PRSK_SERVER_SHIM_H */
