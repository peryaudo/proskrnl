/* drivers/net/port/string.h — hosted-header shim for the pinned lwIP's
 * `#include <string.h>` (Net-1, docs/24 §4b). Environment furniture of the
 * port layer, not a patch: the freestanding kernel has no libc headers, so
 * this directory serves the three lwIP includes (string/stdio/stdlib) over
 * kernel primitives. The mem* four are kernel/lib/string.c's; the str*
 * three lwIP's core files call are defined in sys_arch.c.
 */
#ifndef PROSKRNL_DRIVERS_NET_PORT_STRING_H
#define PROSKRNL_DRIVERS_NET_PORT_STRING_H

#include <stddef.h>

void *memset(void *destination, int value, size_t length);
void *memcpy(void *destination, const void *source, size_t length);
void *memmove(void *destination, const void *source, size_t length);
int memcmp(const void *left, const void *right, size_t length);

size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t length);

#endif /* PROSKRNL_DRIVERS_NET_PORT_STRING_H */
