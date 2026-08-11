/* kernel/lib/crc32.h — CRC-32 over a byte range. See crc32.c for which
 * CRC-32 this is and where to re-verify it. */
#ifndef PROSKRNL_KERNEL_LIB_CRC32_H
#define PROSKRNL_KERNEL_LIB_CRC32_H

#include <stddef.h>
#include <stdint.h>

/* CRC-32/ISO-HDLC of `length` bytes at `data`. */
uint32_t KiCrc32(const void *data, size_t length);

/* Recompute the algorithm's published check value and ASSERT it. Called once
 * at boot so a miscompiled or mis-edited CRC names itself immediately rather
 * than as an unreadable hive three reboots later. */
void KiCrc32SelfTest(void);

#endif /* PROSKRNL_KERNEL_LIB_CRC32_H */
