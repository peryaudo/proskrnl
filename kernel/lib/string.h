/* kernel/lib/string.h — freestanding memory intrinsics (M2). See string.c. */
#ifndef PROSKRNL_KERNEL_LIB_STRING_H
#define PROSKRNL_KERNEL_LIB_STRING_H

#include <stddef.h>

/* Compiler-mandated names: clang emits calls to these under -ffreestanding,
 * so the docs/15 naming rules are waived for them. */
/* NOLINTBEGIN(readability-identifier-naming) */
void *memset(void *destination, int value, size_t length);
void *memcpy(void *destination, const void *source, size_t length);
void *memmove(void *destination, const void *source, size_t length);
int memcmp(const void *left, const void *right, size_t length);
/* NOLINTEND(readability-identifier-naming) */

#endif /* PROSKRNL_KERNEL_LIB_STRING_H */
