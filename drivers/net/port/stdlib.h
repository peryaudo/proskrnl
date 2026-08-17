/* drivers/net/port/stdlib.h — hosted-header shim for the pinned lwIP's
 * `#include <stdlib.h>` (see string.h in this directory). netif.c calls
 * atoi (netif_name_to_index); sys_arch.c defines it. malloc/free stay
 * undeclared on purpose: MEM_LIBC_MALLOC=0 (lwipopts.h), so a reference
 * appearing would be a config regression and must fail the build loudly.
 */
#ifndef PROSKRNL_DRIVERS_NET_PORT_STDLIB_H
#define PROSKRNL_DRIVERS_NET_PORT_STDLIB_H

int atoi(const char *s);

#endif /* PROSKRNL_DRIVERS_NET_PORT_STDLIB_H */
