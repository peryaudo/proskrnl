/* kernel/lib/le.h — unaligned little-endian field accessors.
 *
 * On-disk and on-wire structures (the FAT32 BPB and directory slots, our
 * registry hive records) are little-endian and packed, so a field can sit at
 * any offset. x86-64 is little-endian too, so no byte swapping is needed —
 * but a direct pointer cast to a wider type is unaligned access, which is
 * undefined behavior and which UBSan reports. memcpy through a local is the
 * portable spelling clang compiles to the single load/store anyway.
 *
 * These were three identical private copies (fs/fat32/fat.c, fs/fat32/dir.c,
 * kernel/cm/hive.c) before they landed here; Art. 11 wants one authority.
 * Pinned by tests/kmt/lib.c.
 */
#ifndef PROSKRNL_KERNEL_LIB_LE_H
#define PROSKRNL_KERNEL_LIB_LE_H

#include "kernel/lib/string.h"
#include <stdint.h>

static inline uint16_t KiReadLe16(const void *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint32_t KiReadLe32(const void *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline uint64_t KiReadLe64(const void *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void KiWriteLe16(void *p, uint16_t v)
{
    memcpy(p, &v, sizeof(v));
}

static inline void KiWriteLe32(void *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static inline void KiWriteLe64(void *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

#endif /* PROSKRNL_KERNEL_LIB_LE_H */
