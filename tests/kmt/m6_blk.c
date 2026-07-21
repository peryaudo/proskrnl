/* tests/kmt/m6_blk.c — virtio-blk driver units, folded into the M6 suite
 * (tests/kmt/m6_io.c kmt_run_m6).
 *
 * The driver bounces every transfer through one page and splits multi-sector
 * calls into 8-sector requests (drivers/virtio/blk.c VioBlkTransfer), so the
 * boundaries worth crossing are multiples of 8. Write tests use a scratch
 * region in the unpartitioned GPT slack — see the layout note below — and a
 * pattern that is a function of the ABSOLUTE LBA, so a chunk sequenced to
 * the wrong sector is caught, not masked.
 *
 * A driver-level write-verify knob was considered and rejected: a readback
 * through the same bounce frame verifies the device echo, not the address —
 * it would pass with a wrong-LBA bug present on both legs. The neighbor
 * checks in test_blk_write_read_verify convict that class instead.
 */
#include "tests/kmt/kmt.h"
#include "drivers/virtio/blk.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"

#include "abi/ntstatus.h"

/* Scratch region: tools/mkimage.sh lays out GPT entries at LBA 2..33
 * (sgdisk default: 128 entries of 128 bytes, UEFI 2.10 §5.3.3) and creates
 * p1 (the Limine BIOS-boot stage) at LBA 2048 (`sgdisk -n 1:2048:+1M`), so
 * LBA 34..2047 is unpartitioned slack nothing owns. We use the upper half,
 * far from the GPT structures. test_blk_scratch_guard re-derives the layout
 * from the on-disk GPT at run time and gates every write test on it. */
#define KMT_BLK_SCRATCH_LBA     1024
#define KMT_BLK_SCRATCH_SECTORS 1024

#define SECTOR 512

static int blk_scratch_ok; /* set by test_blk_scratch_guard */

/* Pattern byte for absolute (lba, offset-within-sector): a splitmix64-style
 * mix so neighboring sectors never share bytes. */
static unsigned char blk_pattern(uint64_t lba, uint32_t i, uint32_t generation)
{
    uint64_t x = (lba << 20) ^ i ^ ((uint64_t)generation << 56);
    x *= 0x9E3779B97F4A7C15ull;
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 32;
    return (unsigned char)x;
}

static void blk_fill(unsigned char *buffer, uint64_t lba, uint32_t sectors, uint32_t generation)
{
    for (uint32_t s = 0; s < sectors; s++)
        for (uint32_t i = 0; i < SECTOR; i++)
            buffer[s * SECTOR + i] = blk_pattern(lba + s, i, generation);
}

/* First mismatching byte index against the pattern, or -1. */
static int blk_verify(const unsigned char *buffer, uint64_t lba, uint32_t sectors,
                      uint32_t generation)
{
    for (uint32_t s = 0; s < sectors; s++)
        for (uint32_t i = 0; i < SECTOR; i++)
            if (buffer[s * SECTOR + i] != blk_pattern(lba + s, i, generation))
                return (int)(s * SECTOR + i);
    return -1;
}

static uint64_t read64(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

/* Layout guard: parse the on-disk GPT (UEFI 2.10 §5.3.2 header, §5.3.3
 * entries) and require every partition to start at/after LBA 2048, so the
 * scratch region can never overlap a real partition. All write tests gate
 * on this — a future mkimage.sh layout change flips the suite to FAIL
 * instead of corrupting the boot volume. */
static void test_blk_scratch_guard(void)
{
    unsigned char sector[SECTOR];
    blk_scratch_ok = 0;
    ok(VioBlkReadSectors(1, 1, sector) == STATUS_SUCCESS, "read GPT header");
    if (memcmp(sector, "EFI PART", 8) != 0)
    {
        ok(0, "no GPT header signature");
        return;
    }
    /* AlternateLBA (offset 32) is the backup header at the last sector —
     * a free cross-check of the device capacity (UEFI 2.10 Table 5.5). */
    uint64_t alternate = read64(sector + 32);
    ok(alternate == VioBlkSectorCount() - 1, "backup header LBA %lu vs capacity %lu",
       (unsigned long)alternate, (unsigned long)VioBlkSectorCount());
    uint64_t entryArrayLba = read64(sector + 72);
    uint32_t entryCount, entrySize;
    memcpy(&entryCount, sector + 80, 4);
    memcpy(&entrySize, sector + 84, 4);
    ok(entrySize >= 128 && entrySize <= SECTOR, "entry size %u", entrySize);

    static const unsigned char zeroGuid[16] = {0};
    uint32_t perSector = SECTOR / entrySize;
    unsigned char entries[SECTOR];
    int violations = 0;
    for (uint32_t index = 0; index < entryCount; index++)
    {
        if (index % perSector == 0 &&
            VioBlkReadSectors(entryArrayLba + index / perSector, 1, entries) != STATUS_SUCCESS)
        {
            ok(0, "read GPT entries");
            return;
        }
        const unsigned char *entry = entries + (index % perSector) * entrySize;
        if (memcmp(entry, zeroGuid, 16) == 0)
            continue;
        uint64_t start = read64(entry + 32); /* StartingLBA (UEFI Table 5.6) */
        if (start < KMT_BLK_SCRATCH_LBA + KMT_BLK_SCRATCH_SECTORS)
            violations++;
    }
    ok(violations == 0, "%d partition(s) overlap the scratch region", violations);
    /* The entry array itself must end below the scratch too. */
    uint64_t arrayEnd = entryArrayLba + (entryCount * entrySize + SECTOR - 1) / SECTOR;
    ok(arrayEnd <= KMT_BLK_SCRATCH_LBA, "GPT entry array reaches LBA %lu", (unsigned long)arrayEnd);
    if (violations == 0 && arrayEnd <= KMT_BLK_SCRATCH_LBA)
        blk_scratch_ok = 1;
}

static void test_blk_last_sector(void)
{
    unsigned char sector[2 * SECTOR];
    uint64_t last = VioBlkSectorCount() - 1;
    /* The backup GPT header sits AT the last LBA (UEFI 2.10 §5.3.2). */
    ok(VioBlkReadSectors(last, 1, sector) == STATUS_SUCCESS, "read last sector");
    ok(memcmp(sector, "EFI PART", 8) == 0, "backup GPT header signature at the last LBA");
    /* A 2-sector read ending exactly at the capacity boundary. */
    memset(sector, 0, sizeof(sector));
    ok(VioBlkReadSectors(last - 1, 2, sector) == STATUS_SUCCESS, "read spanning to the end");
    ok(memcmp(sector + SECTOR, "EFI PART", 8) == 0, "second sector is the backup header");
}

static void test_blk_out_of_range(void)
{
    uint64_t cap = VioBlkSectorCount();
    unsigned char *buffer = MiAllocatePool(9 * SECTOR);
    unsigned char reference[8 * SECTOR];
    ok(buffer != 0, "pool");
    if (buffer == 0)
        return;

    ok(VioBlkReadSectors(cap, 1, buffer) == STATUS_IO_DEVICE_ERROR, "read at capacity");
    ok(VioBlkReadSectors(cap - 1, 2, buffer) == STATUS_IO_DEVICE_ERROR,
       "read spanning past the end");
    ok(VioBlkWriteSectors(cap, 1, buffer) == STATUS_IO_DEVICE_ERROR, "write at capacity");

    /* A multi-chunk transfer failing on the SECOND chunk: the in-range
     * prefix IS transferred before the failure (the chunked loop's
     * documented contract — the caller sees an error but a modified
     * buffer prefix). */
    memset(buffer, 0xCC, 9 * SECTOR);
    ok(VioBlkReadSectors(cap - 8, 9, buffer) == STATUS_IO_DEVICE_ERROR,
       "9-sector read starting 8 short of the end");
    ok(VioBlkReadSectors(cap - 8, 8, reference) == STATUS_SUCCESS, "reference read");
    ok(memcmp(buffer, reference, 8 * SECTOR) == 0, "in-range prefix was transferred");
    int poisoned = 1;
    for (uint32_t i = 8 * SECTOR; i < 9 * SECTOR; i++)
        if (buffer[i] != 0xCC)
            poisoned = 0;
    ok(poisoned, "out-of-range tail untouched");

    /* lba = UINT64_MAX, count 2: the driver's own bounds check wraps
     * (sectorLba + count overflows to 1), so the request reaches the device,
     * which range-checks and fails it with VIRTIO_BLK_S_IOERR — the only
     * reachable exercise of the status-byte error path (pinned QEMU
     * hw/block/virtio-blk.c virtio_blk_sect_range_ok). */
    ok(VioBlkReadSectors(~0ULL, 2, buffer) == STATUS_IO_DEVICE_ERROR,
       "read at UINT64_MAX exercises the device IOERR path");

    MiFreePool(buffer);
}

/* Write-then-readback at sizes crossing the driver's 8-sector chunking:
 * sub-chunk, exact, chunk+1, multi-chunk straddles. Each size gets its own
 * base LBA so a stray write from one case cannot fix up another; readback
 * uses a different call split than the write so the seams cross differently. */
static void test_blk_chunk_boundaries(void)
{
    static const uint32_t sizes[] = {1, 2, 7, 8, 9, 15, 16, 17, 64, 65};
    if (!blk_scratch_ok)
        return;
    unsigned char *buffer = MiAllocatePool(65 * SECTOR);
    ok(buffer != 0, "pool");
    if (buffer == 0)
        return;

    uint64_t base = KMT_BLK_SCRATCH_LBA;
    for (unsigned c = 0; c < sizeof(sizes) / sizeof(sizes[0]); c++)
    {
        uint32_t count = sizes[c];
        blk_fill(buffer, base, count, 1);
        ok(VioBlkWriteSectors(base, count, buffer) == STATUS_SUCCESS, "write %u at %lu", count,
           (unsigned long)base);

        /* Readback as one call. */
        memset(buffer, 0, (uint64_t)count * SECTOR);
        ok(VioBlkReadSectors(base, count, buffer) == STATUS_SUCCESS, "read %u", count);
        ok(blk_verify(buffer, base, count, 1) == -1, "%u-sector readback mismatch", count);

        /* Readback split at a different seam (first sector, then the rest). */
        if (count > 1)
        {
            memset(buffer, 0, (uint64_t)count * SECTOR);
            ok(VioBlkReadSectors(base, 1, buffer) == STATUS_SUCCESS, "split read head");
            ok(VioBlkReadSectors(base + 1, count - 1, buffer + SECTOR) == STATUS_SUCCESS,
               "split read tail");
            ok(blk_verify(buffer, base, count, 1) == -1, "%u-sector split readback mismatch",
               count);
        }
        base += count;
    }
    MiFreePool(buffer);
}

/* The wrong-LBA conviction: fill a region, overwrite a window in the middle,
 * and verify the NEIGHBORS still carry generation-1 bytes — a write landing
 * at the wrong LBA reads back consistently wrong, which per-write readback
 * verification can never see. */
static void test_blk_write_read_verify(void)
{
    enum
    {
        REGION = 128,
        WINDOW_AT = 60,
        WINDOW = 3
    };
    if (!blk_scratch_ok)
        return;
    uint64_t base = KMT_BLK_SCRATCH_LBA + 512; /* clear of test_blk_chunk_boundaries */
    unsigned char *buffer = MiAllocatePool(REGION * SECTOR);
    ok(buffer != 0, "pool");
    if (buffer == 0)
        return;

    blk_fill(buffer, base, REGION, 1);
    ok(VioBlkWriteSectors(base, REGION, buffer) == STATUS_SUCCESS, "write region");

    /* Sector-at-a-time readback (the FatReadSector shape). */
    int bad = 0;
    for (uint32_t s = 0; s < REGION; s++)
    {
        unsigned char one[SECTOR];
        if (VioBlkReadSectors(base + s, 1, one) != STATUS_SUCCESS ||
            blk_verify(one, base + s, 1, 1) != -1)
            bad++;
    }
    ok(bad == 0, "%d bad sectors in per-sector readback", bad);

    blk_fill(buffer, base + WINDOW_AT, WINDOW, 2);
    ok(VioBlkWriteSectors(base + WINDOW_AT, WINDOW, buffer) == STATUS_SUCCESS, "window write");

    memset(buffer, 0, REGION * SECTOR);
    ok(VioBlkReadSectors(base, REGION, buffer) == STATUS_SUCCESS, "read region");
    ok(blk_verify(buffer, base, WINDOW_AT, 1) == -1, "sectors before the window changed");
    ok(blk_verify(buffer + WINDOW_AT * SECTOR, base + WINDOW_AT, WINDOW, 2) == -1,
       "window content wrong");
    ok(blk_verify(buffer + (WINDOW_AT + WINDOW) * SECTOR, base + WINDOW_AT + WINDOW,
                  REGION - WINDOW_AT - WINDOW, 1) == -1,
       "sectors after the window changed");
    MiFreePool(buffer);
}

/* Caller-buffer alignment: the bounce buffer makes alignment and physical
 * contiguity of the caller's buffer irrelevant (blk.c "One-page bounce
 * buffers"). This is a tripwire for a future direct-DMA rewrite. */
static void test_blk_unaligned_buffers(void)
{
    if (!blk_scratch_ok)
        return;
    uint64_t base = KMT_BLK_SCRATCH_LBA + 512 + 200;
    unsigned char *pool = MiAllocatePool(9 * SECTOR + 3);
    ok(pool != 0, "pool");
    if (pool == 0)
        return;
    unsigned char *odd = pool + 1; /* deliberately misaligned VA */

    blk_fill(odd, base, 9, 3);
    ok(VioBlkWriteSectors(base, 9, odd) == STATUS_SUCCESS, "write from odd VA");
    memset(odd, 0, 9 * SECTOR);
    ok(VioBlkReadSectors(base, 9, odd) == STATUS_SUCCESS, "read to odd VA");
    ok(blk_verify(odd, base, 9, 3) == -1, "odd-VA readback mismatch");
    MiFreePool(pool);
}

int kmt_run_m6_blk(void)
{
    int before = kmt_failures;
    DbgPrint("kmt: M6 blk suite\n");
    KMT_RUN(test_blk_scratch_guard);
    KMT_RUN(test_blk_last_sector);
    KMT_RUN(test_blk_out_of_range);
    KMT_RUN(test_blk_chunk_boundaries);
    KMT_RUN(test_blk_write_read_verify);
    KMT_RUN(test_blk_unaligned_buffers);
    return kmt_failures - before;
}
