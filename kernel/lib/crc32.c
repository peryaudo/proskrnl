/* kernel/lib/crc32.c — CRC-32/ISO-HDLC, the checksum the hive log frames its
 * records with.
 *
 * WHICH CRC-32 (gate G8 — these constants are fixed by an external contract,
 * so here is where to re-verify them): CRC-32/ISO-HDLC, a.k.a. CRC-32/ADCCP,
 * PKZIP's and Ethernet's. Reflected input and output, polynomial 0x04C11DB7
 * used in its reversed form 0xEDB88320, init 0xFFFFFFFF, final xor
 * 0xFFFFFFFF. Defined by ITU-T Recommendation V.42 (03/2002) section
 * 8.1.1.6.2 and by IEEE 802.3 clause 3.2.9 (the frame check sequence); both
 * are the normative sources, and the parameters are catalogued as
 * "CRC-32/ISO-HDLC" in the CRC RevEng catalogue. Its PUBLISHED CHECK VALUE
 * -- the CRC of the nine ASCII bytes "123456789" -- is 0xCBF43926, which
 * KiCrc32SelfTest recomputes at boot. That check value is the whole point of
 * citing a named algorithm rather than "a CRC": it converts every constant
 * above into something a reader can verify without trusting this comment.
 *
 * NOT the SSE4.2 `crc32` instruction: the kernel is built -mno-sse
 * (Makefile), and that instruction computes CRC-32C (Castagnoli, polynomial
 * 0x1EDC6F41), which is a DIFFERENT checksum -- it would not reproduce the
 * check value above.
 *
 * Bit-at-a-time rather than a 256-entry table (Art. 3, stupidly correct): the
 * whole hive is at most a few hundred KiB per boot, so eight shifts per byte
 * costs microseconds against the milliseconds of disk I/O the checksum
 * exists to protect. A table is the obvious change if this ever measures.
 */
#include "kernel/lib/crc32.h"

#include "kernel/init/panic.h"

#define KI_CRC32_REVERSED_POLYNOMIAL 0xEDB88320u
#define KI_CRC32_INITIAL             0xFFFFFFFFu
#define KI_CRC32_FINAL_XOR           0xFFFFFFFFu

/* The algorithm's published check value: CRC of the ASCII bytes "123456789". */
#define KI_CRC32_CHECK_VALUE 0xCBF43926u

uint32_t KiCrc32(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    uint32_t crc = KI_CRC32_INITIAL;

    for (size_t i = 0; i < length; i++)
    {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; bit++)
        {
            /* Reflected form: shift right, and fold the polynomial back in
             * whenever the bit shifted out was set. */
            uint32_t lowBitSet = crc & 1u;
            crc >>= 1;
            if (lowBitSet != 0)
            {
                crc ^= KI_CRC32_REVERSED_POLYNOMIAL;
            }
        }
    }
    return crc ^ KI_CRC32_FINAL_XOR;
}

void KiCrc32SelfTest(void)
{
    static const uint8_t check[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    ASSERT(KiCrc32(check, sizeof(check)) == KI_CRC32_CHECK_VALUE);
    /* The empty range is the identity the framing code relies on for a
     * zero-length tail: init xor final == 0. */
    ASSERT(KiCrc32(check, 0) == 0);
}
