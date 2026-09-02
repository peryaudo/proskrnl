/* arch/x86_64/acpi.h — the firmware's ACPI tables, located and bounded once
 * at boot: RSDP -> RSDT/XSDT -> FADT (the fixed-hardware register blocks),
 * DSDT (only the \_S5 sleep package is read out of it), MADT (the local
 * APIC address and the interrupt-controller census).
 *
 * Like SMBIOS next door, this is firmware data an OS reads for itself, not a
 * boundary contract: nothing here is NT-shaped, and nothing here is
 * observable from an unprivileged .exe (Art. 1). There is no AML
 * interpreter and no PnP/power model (docs/03 "WDM / PnP / power" dropped):
 * the one consumer with a machine-level effect is arch/x86_64/power.c, which
 * turns the FADT's PM1 control block plus the \_S5 sleep type into a
 * power-off, so that the same kernel image ends a session on bare metal the
 * way it ends one on QEMU. The facts are raw; nothing is invented: a table
 * that fails validation is reported absent (Art. 12), never guessed.
 *
 * Every offset and value is the ACPI Specification 6.5 (UEFI Forum), cited
 * per constant below and in acpi.c; the pinned QEMU tree (the firmware-table
 * generator the tests boot against) is the runtime cross-check, named at
 * each site as well. */
#ifndef PROSKRNL_ARCH_X86_64_ACPI_H
#define PROSKRNL_ARCH_X86_64_ACPI_H

#include <stdint.h>

#include "abi/ntdef.h"

/* Generic Address Structure address-space ids (ACPI 6.5 §5.2.3.2 Table 5.1
 * "Address Space ID": 0x00 System Memory, 0x01 System I/O; pinned QEMU
 * include/hw/acpi/aml-build.h AML_AS_SYSTEM_MEMORY / AML_AS_SYSTEM_IO). */
#define KI_ACPI_GAS_SYSTEM_MEMORY 0x00
#define KI_ACPI_GAS_SYSTEM_IO     0x01

/* FADT fixed-feature flag HW_REDUCED_ACPI (ACPI 6.5 §5.2.9 Table 5.10, bit
 * 20; pinned QEMU include/hw/acpi/acpi-defs.h ACPI_FADT_F_HW_REDUCED_ACPI,
 * the 21st enumerator). A hardware-reduced platform has no PM1 blocks at
 * all, so power.c refuses it rather than poke an address that is not there. */
#define KI_ACPI_FADT_FLAG_HW_REDUCED_ACPI (1u << 20)

/* A register block as the FADT describes it: the address-space id and the
 * register width from a Generic Address Structure (ACPI 6.5 §5.2.3.2), or the
 * same two facts synthesized from the ACPI 1.0 32-bit fields when the FADT
 * predates the X_ form. address 0 means "no such block". */
typedef struct
{
    uint8_t addressSpaceId;
    uint8_t bitWidth;
    uint64_t address;
} KI_ACPI_GAS;

typedef struct
{
    /* The root pointer and the root table it named. */
    const uint8_t *rsdp;      /* through the HHDM */
    uint8_t rsdpRevision;     /* 0 = ACPI 1.0 (RSDT only), >= 2 = XSDT present */
    BOOLEAN xsdtUsed;         /* which root table `rootTable` is */
    const uint8_t *rootTable; /* the RSDT or XSDT, header-validated */
    uint32_t tableCount;      /* entries in it */

    /* FADT (signature "FACP", ACPI 6.5 §5.2.9). */
    const uint8_t *fadt; /* 0 when absent or refused */
    uint32_t fadtLength;
    uint8_t fadtRevision;
    uint32_t fadtFlags;
    uint16_t sciInterrupt;
    uint32_t smiCommandPort; /* 0 = no SMI command port (ACPI mode is fixed on) */
    uint8_t acpiEnableValue;
    uint8_t acpiDisableValue;
    KI_ACPI_GAS pm1aControl; /* address 0 = absent */
    KI_ACPI_GAS pm1bControl; /* address 0 = absent (the usual case) */
    uint8_t pm1ControlLength;

    /* DSDT (ACPI 6.5 §5.2.11.1) and the one object read out of it. */
    const uint8_t *dsdt; /* 0 when absent or refused */
    uint32_t dsdtLength;
    BOOLEAN s5Present; /* a \_S5 package of integer constants was found */
    uint8_t s5SleepTypeA;
    uint8_t s5SleepTypeB;

    /* MADT (signature "APIC", ACPI 6.5 §5.2.12). */
    const uint8_t *madt; /* 0 when absent or refused */
    uint64_t localApicAddress;
    uint32_t enabledLocalApicCount; /* Processor Local APIC / x2APIC entries flagged Enabled */
    uint32_t ioApicCount;
} KI_ACPI_INFO;

/* Parse the tables from the RSDP Limine reported (a physical address under
 * base revision 3; 0 when the firmware published none). Safe to call with 0
 * — the info simply stays absent, which every caller must handle: firmware
 * need not publish ACPI at all, and a table that fails validation is treated
 * exactly like one that was never published. */
void KiAcpiInitialize(uint64_t rsdpPhysical);

/* The located tables, or 0 when the RSDP was absent / did not parse. */
const KI_ACPI_INFO *KiAcpiGetInfo(void);

/* The (nth+1)-th table in the root table carrying this 4-byte signature,
 * header-validated (length bounded, checksum zero), or 0 when there is no
 * such table. *lengthOut (optional) receives the table's Length. This is the
 * read-only accessor a SystemFirmwareTableInformation "ACPI" provider would
 * be built on; today's consumers are the parser itself and the kmt suite. */
const uint8_t *KiAcpiFindTable(const char *signature, uint32_t nth, uint32_t *lengthOut);

#endif /* PROSKRNL_ARCH_X86_64_ACPI_H */
