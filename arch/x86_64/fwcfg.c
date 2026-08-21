/* arch/x86_64/fwcfg.c — read named blobs out of QEMU's fw_cfg device.
 *
 * The traditional (non-DMA) interface only: select an item by writing its key
 * to the selector register, then read the item's bytes one at a time from the
 * data register, which auto-advances. Named items live at selector keys
 * 0x0020 and up and are found through the file directory at key 0x0019 — a
 * big-endian count followed by fixed 64-byte entries. Reads are sequential
 * with no seek, so finding a name means walking the directory from its start.
 *
 * Every register number, key number and structure layout below is from the
 * pinned QEMU tree's docs/specs/fw_cfg.rst; re-verify against that document.
 * Nothing here is an NT contract.
 */
#include "arch/x86_64/fwcfg.h"

#include "arch/x86_64/io.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"

/* fw_cfg.rst "Register Locations", x86/x86_64. The selector is 16-bit and
 * little-endian on an IOport, which is what a plain outw writes. */
#define KI_FWCFG_PORT_SELECTOR 0x510
#define KI_FWCFG_PORT_DATA     0x511

/* fw_cfg.rst "Signature (Key 0x0000)" and "File Directory (Key 0x0019)". */
#define KI_FWCFG_KEY_SIGNATURE 0x0000
#define KI_FWCFG_KEY_FILE_DIR  0x0019

/* fw_cfg.rst "File Directory": struct FWCfgFile is 64 bytes — big-endian
 * size, big-endian selector, 2 reserved bytes, then a 56-byte NUL-terminated
 * ASCII name. */
#define KI_FWCFG_NAME_LENGTH     56
#define KI_FWCFG_RESERVED_LENGTH 2

/* fw_cfg.rst "Ranges": at most 0x4000 generic items exist, so a larger
 * directory count is a device that is not answering sanely — bound the walk
 * rather than trust it. */
#define KI_FWCFG_MAX_FILES 0x4000

/* 0 = not probed yet, 1 = present, 2 = absent. */
static int KiFwCfgProbeState;

static void KiFwCfgSelect(uint16_t key)
{
    KiOutWord(KI_FWCFG_PORT_SELECTOR, key);
}

/* Read `bytes` bytes of the selected item at the current offset. Past the
 * item's end the device returns 0x00 forever (fw_cfg.rst "Data Register"), so
 * an over-long read is harmless rather than a hang. */
static void KiFwCfgReadBytes(void *buffer, uint32_t bytes)
{
    uint8_t *out = (uint8_t *)buffer;
    for (uint32_t i = 0; i < bytes; i++)
    {
        out[i] = KiInByte(KI_FWCFG_PORT_DATA);
    }
}

static void KiFwCfgSkipBytes(uint32_t bytes)
{
    for (uint32_t i = 0; i < bytes; i++)
    {
        (void)KiInByte(KI_FWCFG_PORT_DATA);
    }
}

/* The directory's scalars are big-endian; the individual reads are sequenced
 * through locals because the order of two KiInByte calls inside one
 * expression would be unspecified. */
static uint16_t KiFwCfgReadBigEndian16(void)
{
    uint8_t high = KiInByte(KI_FWCFG_PORT_DATA);
    uint8_t low = KiInByte(KI_FWCFG_PORT_DATA);
    return (uint16_t)(((uint16_t)high << 8) | low);
}

static uint32_t KiFwCfgReadBigEndian32(void)
{
    uint16_t high = KiFwCfgReadBigEndian16();
    uint16_t low = KiFwCfgReadBigEndian16();
    return ((uint32_t)high << 16) | low;
}

/* Compare a directory entry's fixed 56-byte name field against a C string.
 * fw_cfg item names are case-sensitive. */
static BOOLEAN KiFwCfgNameMatches(const char *entryName, const char *wanted)
{
    uint32_t i = 0;
    while (i < KI_FWCFG_NAME_LENGTH)
    {
        if (entryName[i] != wanted[i])
        {
            return FALSE;
        }
        if (wanted[i] == 0)
        {
            return TRUE;
        }
        i++;
    }
    return wanted[i] == 0; /* a name filling the field entirely */
}

BOOLEAN KiFwCfgPresent(void)
{
    if (KiFwCfgProbeState == 0)
    {
        /* fw_cfg.rst "Signature (Key 0x0000)": four bytes reading "QEMU".
         * The probe is a write to an IOport nothing else claims, which is how
         * every firmware finds this device; on hardware without it the reads
         * come back as floating 0xff and the comparison simply fails. */
        char signature[4];
        KiFwCfgSelect(KI_FWCFG_KEY_SIGNATURE);
        KiFwCfgReadBytes(signature, sizeof(signature));
        BOOLEAN present = signature[0] == 'Q' && signature[1] == 'E' && signature[2] == 'M' &&
                          signature[3] == 'U';
        KiFwCfgProbeState = present ? 1 : 2;
        DbgPrint("fwcfg: QEMU firmware configuration device %s\n", present ? "present" : "absent");
    }
    return KiFwCfgProbeState == 1;
}

BOOLEAN KiFwCfgReadItem(const char *name, void *buffer, uint32_t bufferSize, uint32_t *bytesRead)
{
    if (!KiFwCfgPresent())
    {
        return FALSE;
    }

    KiFwCfgSelect(KI_FWCFG_KEY_FILE_DIR);
    uint32_t count = KiFwCfgReadBigEndian32();
    if (count > KI_FWCFG_MAX_FILES)
    {
        return FALSE;
    }
    for (uint32_t i = 0; i < count; i++)
    {
        uint32_t size = KiFwCfgReadBigEndian32();
        uint16_t selector = KiFwCfgReadBigEndian16();
        KiFwCfgSkipBytes(KI_FWCFG_RESERVED_LENGTH);
        char entryName[KI_FWCFG_NAME_LENGTH];
        KiFwCfgReadBytes(entryName, sizeof(entryName));
        if (!KiFwCfgNameMatches(entryName, name))
        {
            continue;
        }
        if (size > bufferSize)
        {
            /* FATAL, not a refusal the caller can shrug off. An item that
             * exists but does not fit is a command-line mistake, and every
             * way of reporting it in the return value reads as ABSENT — which
             * is indistinguishable from never having passed it, so the caller
             * applies its "unspecified" default and the boot runs something
             * other than what it was told to. That is exactly what happened:
             * the winetest gate's pair list was 1270 bytes against a 256-byte
             * cap, this printed its line, and the guest swept EVERY pair
             * because an empty filter means no filter (Art. 12 — a refusal
             * must not become a plausible answer downstream). Callers size
             * their buffer for the value they expect; none probes for a size,
             * and there is no return value that could tell one from the
             * other. */
            DbgPrint("fwcfg: %s is %u bytes, too big for the caller's %u\n", name,
                     (unsigned int)size, (unsigned int)bufferSize);
            KiPanic("fw_cfg item too big for its caller");
        }
        /* Selecting resets the data offset to zero (fw_cfg.rst "Selector
         * Register"), which is what abandons the directory walk here. */
        KiFwCfgSelect(selector);
        KiFwCfgReadBytes(buffer, size);
        *bytesRead = size;
        return TRUE;
    }
    return FALSE;
}
