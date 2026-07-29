/*
 * prsk_request_table.h - the shape of the generated dispatch table.
 *
 * Filled in by tools/gen_server_table.py from the pinned tree's
 * request_handlers.h; a NULL slot is a request whose handler is not linked
 * into this build, and the dispatcher names it on serial and refuses.
 */
#ifndef PRSK_REQUEST_TABLE_H
#define PRSK_REQUEST_TABLE_H

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef void (*prsk_req_handler)( const void *req, void *reply );

extern const prsk_req_handler prsk_req_handlers[];
extern const char * const prsk_req_names[];
extern const unsigned int prsk_req_count;

#endif /* PRSK_REQUEST_TABLE_H */
