/* arch/x86_64/fwcfg.h — QEMU's firmware configuration device (fw_cfg), the
 * channel a `-fw_cfg name=opt/...,string=...` on the QEMU command line
 * reaches the guest through.
 *
 * Like SMBIOS next door, this is firmware data an OS reads for itself, not a
 * boundary contract: nothing here is NT-shaped. The one consumer is
 * kernel/cm/registry.c, which publishes the named items it knows about as
 * values under the volatile \Registry\Machine\Hardware\qemu key.
 *
 * The device is absent on real hardware and on non-QEMU hypervisors, which
 * KiFwCfgPresent answers for — every caller must handle that. */
#ifndef PROSKRNL_ARCH_X86_64_FWCFG_H
#define PROSKRNL_ARCH_X86_64_FWCFG_H

#include <stdint.h>

#include "abi/ntdef.h"

/* TRUE when the fw_cfg selector/data registers answered the signature probe,
 * i.e. we are running under QEMU. Probes once and caches. */
BOOLEAN KiFwCfgPresent(void);

/* Read the named fw_cfg item ("opt/org.proskrnl/interactive", …) into
 * `buffer`, at most `bufferSize` bytes. FALSE when the device is absent, the
 * name is not in the file directory, or the item does not fit — *bytesRead is
 * meaningful only on TRUE.
 *
 * The blob carries no terminator of its own: QEMU sizes a `-fw_cfg
 * ...,string=` item at strlen() with the NUL excluded (pinned tree
 * system/vl.c parse_fw_cfg). */
BOOLEAN KiFwCfgReadItem(const char *name, void *buffer, uint32_t bufferSize, uint32_t *bytesRead);

#endif /* PROSKRNL_ARCH_X86_64_FWCFG_H */
