/*
 * proskrnl_glue.h - the proskrnl seam for the ported Wine conhost (M9).
 *
 * conhost.c is the pinned Wine tree's programs/conhost/conhost.c with its
 * two wineserver call sites (get_next_console_request) redirected to the
 * kernel ConDrv server transport declared here (drivers/condrvproto.h).
 * proskrnl_glue.c also carries the process entry (opens the Server and the
 * serial tty handles the kernel provides), the tiny CRT surface conhost.c
 * uses, and no-op stands-ins for the user32/window.c symbols the headless
 * build references but never executes.
 */
#ifndef PROSKRNL_CONHOST_GLUE_H
#define PROSKRNL_CONHOST_GLUE_H

#include <stdarg.h>
#include <stddef.h>
#include <windef.h>
#include <winternl.h>

/* Reply the previous request's result (unless none is outstanding) and
 * fetch the next one into `buffer`. STATUS_PENDING = nothing queued; wait
 * on the server handle. Mirrors wineserver's get_next_console_request. */
NTSTATUS proskrnl_next_console_request( HANDLE server, NTSTATUS status, int signal,
                                        const void *reply_data, size_t reply_size,
                                        void *buffer, size_t buffer_capacity,
                                        unsigned int *code, int *output,
                                        size_t *out_size, size_t *in_size );

/* Complete the oldest delivered blocking read (read_complete's
 * get_next_console_request(read=1) form); data1 is the optional
 * READ_CONSOLE_CONTROL key-state prefix. */
NTSTATUS proskrnl_console_read_complete( HANDLE server, NTSTATUS status, int signal,
                                         const void *data1, size_t size1,
                                         const void *data2, size_t size2 );

#endif /* PROSKRNL_CONHOST_GLUE_H */
