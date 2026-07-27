/* arch/x86_64/smbios.h — the firmware's SMBIOS structure table, located once
 * at boot (CUI/GUI: the SystemFirmwareTableInformation RSMB provider).
 *
 * This is firmware data an OS reads for itself, not a boundary contract: the
 * NT-shaped answer (the RawSMBIOSData prologue) is assembled in
 * kernel/ps/query.c, and this header hands it only the raw facts. */
#ifndef PROSKRNL_ARCH_X86_64_SMBIOS_H
#define PROSKRNL_ARCH_X86_64_SMBIOS_H

#include <stdint.h>

#include "abi/ntdef.h"

typedef struct
{
    const uint8_t *tableData; /* the structure table, through the HHDM */
    uint32_t tableLength;     /* bytes, up to and including the type-127 end */
    uint8_t majorVersion;     /* entry point's SMBIOS version */
    uint8_t minorVersion;
    uint8_t docRevision; /* 3.x DocRev; 0 from a 2.x entry point */
} KI_SMBIOS_TABLE;

/* Parse the entry point Limine reported (physical addresses under base
 * revision 3; either may be 0). Safe to call with both 0 — the table simply
 * stays absent, which every caller must handle: firmware need not publish
 * SMBIOS at all. */
void KiSmbiosInitialize(uint64_t entryPoint32Physical, uint64_t entryPoint64Physical);

/* The located table, or 0 when firmware published none / it did not parse. */
const KI_SMBIOS_TABLE *KiSmbiosGetTable(void);

#endif /* PROSKRNL_ARCH_X86_64_SMBIOS_H */
