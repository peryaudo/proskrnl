/* drivers/net/port/stdio.h — hosted-header shim for the pinned lwIP's
 * `#include <stdio.h>` (see string.h in this directory). mem.c includes it
 * for snprintf, whose only uses sit behind MEM_SANITY_REGION_* (off);
 * declared so the include parses, undefined so a use appearing would fail
 * the link loudly rather than acquire a silent stub (Art. 12's shape).
 */
#ifndef PROSKRNL_DRIVERS_NET_PORT_STDIO_H
#define PROSKRNL_DRIVERS_NET_PORT_STDIO_H

#include <stddef.h>

int snprintf(char *buffer, size_t size, const char *format, ...);

#endif /* PROSKRNL_DRIVERS_NET_PORT_STDIO_H */
