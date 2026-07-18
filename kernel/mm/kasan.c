/* kernel/mm/kasan.c — minimal KASAN (M3). See kasan.h for scope.
 *
 * Shadow encoding (the standard ASan scheme, 1 shadow byte per 8-byte
 * granule): 0 = whole granule addressable; 1..7 = only the first N bytes;
 * 0xFC = red zone (block header / allocation tail); 0xFB = freed memory.
 *
 * The compiler emits outline calls (__asan_loadN_noabort/__asan_storeN_
 * noabort) for every load/store in instrumented code; the hook range-checks
 * against the pool and walks the shadow byte-wise — stupidly correct over
 * clever (Art. 3). This file itself is compiled uninstrumented (Makefile)
 * and must stay self-contained enough not to recurse into the pool.
 */
#include "kernel/mm/kasan.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/phys.h"
#include "arch/x86_64/mmu.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

#define MI_KASAN_SHADOW_BASE 0xFFFFB00000000000ULL
#define MI_KASAN_GRANULE     8

#define MI_KASAN_FREE    0xFB
#define MI_KASAN_REDZONE 0xFC

static int MiKasanReady;
static uint64_t MiKasanPoolEnd;      /* pool bytes with shadow behind them */
static uint64_t MiKasanShadowMapped; /* first unmapped shadow byte */
static int *MiKasanReportCounter;    /* tests/kmt hook; 0 = reports are fatal */

static unsigned char *MiKasanShadowFor(uint64_t address)
{
    return (unsigned char *)(uintptr_t)(MI_KASAN_SHADOW_BASE +
                                        ((address - MI_POOL_BASE) / MI_KASAN_GRANULE));
}

void MiKasanInitialize(void)
{
    MiKasanReady = 1;
    MiKasanPoolEnd = MI_POOL_BASE;
    MiKasanShadowMapped = MI_KASAN_SHADOW_BASE;
    MiKasanReportCounter = 0;
}

void MiKasanCoverPool(uint64_t poolEnd)
{
    if (!MiKasanReady)
    {
        return;
    }
    uint64_t shadowEnd = (uint64_t)(uintptr_t)MiKasanShadowFor(poolEnd);
    while (MiKasanShadowMapped < shadowEnd)
    {
        uint64_t frame = MiAllocatePage();
        if (frame == 0)
        {
            KiPanic("MiKasanCoverPool: out of physical memory for shadow");
        }
        MiMapPage(MiKasanShadowMapped, frame, 1);
        /* Fresh shadow covers not-yet-allocated heap: poison as freed. */
        memset((void *)(uintptr_t)MiKasanShadowMapped, MI_KASAN_FREE, PAGE_SIZE);
        MiKasanShadowMapped += PAGE_SIZE;
    }
    MiKasanPoolEnd = poolEnd;
}

/* Poison [address, address+size) — both granule-aligned — with `value`. */
static void MiKasanPoisonRange(uint64_t address, uint64_t size, unsigned char value)
{
    ASSERT((address % MI_KASAN_GRANULE) == 0 && (size % MI_KASAN_GRANULE) == 0);
    memset(MiKasanShadowFor(address), value, size / MI_KASAN_GRANULE);
}

void MiKasanMarkAllocated(void *data, uint64_t requestedBytes, uint64_t blockBytes)
{
    if (!MiKasanReady)
    {
        return;
    }
    uint64_t dataAddress = (uint64_t)(uintptr_t)data;

    /* The 16-byte header before the data is red zone for everyone but
     * pool.c (which is uninstrumented). */
    MiKasanPoisonRange(dataAddress - 16, 16, MI_KASAN_REDZONE);

    /* The data: whole granules addressable, a trailing partial granule gets
     * its byte count, everything after is red zone up to the block end. */
    uint64_t wholeGranules = requestedBytes / MI_KASAN_GRANULE;
    uint64_t remainder = requestedBytes % MI_KASAN_GRANULE;
    unsigned char *shadow = MiKasanShadowFor(dataAddress);
    memset(shadow, 0, wholeGranules);
    uint64_t poisonedGranules = wholeGranules;
    if (remainder != 0)
    {
        shadow[wholeGranules] = (unsigned char)remainder;
        poisonedGranules++;
    }
    uint64_t dataGranules = (blockBytes - 16) / MI_KASAN_GRANULE;
    ASSERT(poisonedGranules <= dataGranules);
    memset(shadow + poisonedGranules, MI_KASAN_REDZONE, dataGranules - poisonedGranules);
}

void MiKasanMarkFreed(void *block, uint64_t blockBytes)
{
    if (!MiKasanReady)
    {
        return;
    }
    MiKasanPoisonRange((uint64_t)(uintptr_t)block, blockBytes, MI_KASAN_FREE);
}

void MiKasanSetReportCounter(int *counter)
{
    MiKasanReportCounter = counter;
}

static void MiKasanReport(uint64_t address, uint64_t size, int isWrite, void *caller)
{
    if (MiKasanReportCounter != 0)
    {
        (*MiKasanReportCounter)++;
        return;
    }
    /* Mid-panic the dump code deliberately reads best-effort (e.g. the RBP
     * walk of an overflowed stack crosses redzones); re-panicking here would
     * trip the recursion latch and truncate the one dump that matters
     * (Art. 9). The first report wins; stay quiet during it. */
    if (KiPanicInProgress)
    {
        return;
    }
    unsigned char shadowValue = *MiKasanShadowFor(address);
    DbgPrint("[KASAN] invalid %s of %lu bytes at %p (shadow %02x, caller %p)\n",
             isWrite ? "write" : "read", (unsigned long)size, (void *)(uintptr_t)address,
             shadowValue, caller);
    KiPanic(shadowValue == MI_KASAN_FREE ? "KASAN: use after free"
                                         : "KASAN: out-of-bounds pool access");
}

/* One byte addressable? (the standard shadow decode) */
static int MiKasanByteOk(uint64_t address)
{
    unsigned char shadow = *MiKasanShadowFor(address);
    if (shadow == 0)
    {
        return 1;
    }
    if (shadow >= MI_KASAN_GRANULE)
    {
        return 0; /* red zone / freed */
    }
    return (address % MI_KASAN_GRANULE) < shadow;
}

static void MiKasanCheck(uint64_t address, uint64_t size, int isWrite, void *caller)
{
    if (!MiKasanReady || size == 0)
    {
        return;
    }
    /* Only the pool is shadowed; everything else (image, stacks handed out
     * by Limine, HHDM) is out of scope by design (kasan.h). */
    if (address < MI_POOL_BASE || address + size > MiKasanPoolEnd || address + size < address)
    {
        return;
    }
    for (uint64_t probe = address; probe < address + size; probe++)
    {
        if (!MiKasanByteOk(probe))
        {
            MiKasanReport(probe, size, isWrite, caller);
            return;
        }
    }
}

void MiKasanCheckRange(void *address, uint64_t size, int isWrite, void *caller)
{
    MiKasanCheck((uint64_t)(uintptr_t)address, size, isWrite, caller);
}

/* --- the compiler ABI ------------------------------------------------------ */
/* NOLINTBEGIN(bugprone-reserved-identifier,readability-identifier-naming) —
 * these exact names are what -fsanitize=kernel-address emits calls to. */

#define MI_KASAN_HOOK(size)                                                                        \
    void __asan_load##size##_noabort(uint64_t address);                                            \
    void __asan_load##size##_noabort(uint64_t address)                                             \
    {                                                                                              \
        MiKasanCheck(address, size, 0, __builtin_return_address(0));                               \
    }                                                                                              \
    void __asan_store##size##_noabort(uint64_t address);                                           \
    void __asan_store##size##_noabort(uint64_t address)                                            \
    {                                                                                              \
        MiKasanCheck(address, size, 1, __builtin_return_address(0));                               \
    }

MI_KASAN_HOOK(1)
MI_KASAN_HOOK(2)
MI_KASAN_HOOK(4)
MI_KASAN_HOOK(8)
MI_KASAN_HOOK(16)

void __asan_loadN_noabort(uint64_t address, uint64_t size);
void __asan_loadN_noabort(uint64_t address, uint64_t size)
{
    MiKasanCheck(address, size, 0, __builtin_return_address(0));
}

void __asan_storeN_noabort(uint64_t address, uint64_t size);
void __asan_storeN_noabort(uint64_t address, uint64_t size)
{
    MiKasanCheck(address, size, 1, __builtin_return_address(0));
}

void __asan_handle_no_return(void);
void __asan_handle_no_return(void)
{
    /* Stack poisoning is disabled; nothing to unwind. */
}

/* NOLINTEND(bugprone-reserved-identifier,readability-identifier-naming) */
