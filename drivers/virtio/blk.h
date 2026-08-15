/* drivers/virtio/blk.h — virtio-blk: the M6 boot disk (docs/02, docs/04).
 *
 * Synchronous sector I/O over one polled virtqueue. The disk the FAT32
 * volume (fs/fat32) mounts is QEMU's `-drive if=virtio` boot image
 * (tools/qemu.sh).
 */
#ifndef PROSKRNL_DRIVERS_VIRTIO_BLK_H
#define PROSKRNL_DRIVERS_VIRTIO_BLK_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "kernel/ke/ke.h" /* CUI-8: the per-request completion event */

/* virtio-blk always speaks 512-byte sectors regardless of blk_size
 * (virtio 1.2 cs01 §5.2.5: "does not affect the units used in the
 * protocol (always 512 bytes)"). */
#define VIO_BLK_SECTOR_SIZE 512

/* Requests that may be in flight at once (CUI-8, docs/19 §5a). An internal
 * capacity choice, not a spec value: it sizes the control-slot frame and is
 * comfortably under the ring's 256-descriptor budget at 3 descriptors per
 * request. */
#define VIO_BLK_MAX_INFLIGHT 16

/* One block request, CALLER-embedded (stack or batch array — never pool
 * owned by the driver): the issuer's frame owns the request from submit to
 * observed completion and never unwinds past it (docs/20 R4). Every field
 * is the driver's from submit until the await returns. */
typedef struct VIO_BLK_REQUEST
{
    uint32_t type; /* driver-internal VIO_BLK_T_* */
    uint64_t sectorLba;
    uint32_t sectorCount;
    uint64_t dataPhysical; /* one physically contiguous run */
    KEVENT done;           /* set by the drain; the issuer's park (docs/19 §5c) */
    volatile BOOLEAN completed;
    NTSTATUS result;
    uint16_t descHead;
    uint8_t controlSlot;
} VIO_BLK_REQUEST;

/* Submit one direct-DMA transfer without waiting (up to
 * VIO_BLK_MAX_INFLIGHT in flight — the docs/19 §5a depth) and collect it
 * later: VioBlkAwait completes the common QEMU-fast request in a bounded
 * drain-spin, else parks the issuer on the request's event until a drain
 * point completes it — other threads run while the device works. A refused
 * submit (out-of-range LBA) leaves nothing in flight. The await never
 * abandons: it returns only once the device is done with the request's
 * memory (docs/20 R4), polling home when the caller's park is refused (a
 * terminating thread). At most a page per request. */
NTSTATUS VioBlkSubmitRead(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                          uint64_t physical);
NTSTATUS VioBlkSubmitWrite(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                           uint64_t physical);
NTSTATUS VioBlkAwait(VIO_BLK_REQUEST *request);

/* Batch shape (docs/19 §11d.7): stage parameters into caller-owned
 * requests with the Prepare pair (no device interaction), then put the
 * whole batch in flight under ONE dispatcher-lock hold with SubmitBatch —
 * atomic against every asynchronous harvest, so the observed in-flight
 * depth is the issuer's, not the harvest timing's. Stops at the first
 * refusal: *submittedOut requests (a prefix) are in flight and MUST each
 * be awaited (docs/20 R4); the refused one and the rest are untouched.
 * count is capped at VIO_BLK_MAX_INFLIGHT. */
void VioBlkPrepareRead(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                       uint64_t physical);
void VioBlkPrepareWrite(VIO_BLK_REQUEST *request, uint64_t sectorLba, uint32_t sectorCount,
                        uint64_t physical);
NTSTATUS VioBlkSubmitBatch(VIO_BLK_REQUEST *requests, ULONG count, ULONG *submittedOut);

/* Harvest every published completion. THE single harvest authority
 * (Art. 11); every drain point funnels here. Call with the dispatcher lock
 * held (the completion ISR holds it by arriving; thread context acquires
 * it) — preferably through Io's IoDrainDeviceCompletions, which brackets
 * the docs/20 R2 allocator prohibition. */
void VioBlkDrain(void);

/* Requests currently in flight (submitted, not yet harvested). */
ULONG VioBlkInFlightCount(void);

/* The docs/19 §8.4 depth verdict's raw numbers: the maximum in-flight
 * depth observed and the mean sampled at each submit (x100), since the
 * last reset. */
void VioBlkQueryDepthStats(ULONG *maxDepthOut, ULONG *meanDepthTimes100Out);
void VioBlkResetDepthStats(void);

/* Test/stress instrumentation (docs/19 §8.1's aggressiveness knob): bound
 * the await's pre-park drain-spin. 0 forces every await to park — the kmt
 * CUI-8 suite holds the in-flight window open with it so progress and
 * cancellation are verdicts, not races. Returns the PREVIOUS bound: a
 * test must restore THAT, never the compile-time VIO_BLK_AWAIT_SPINS — a
 * stress boot (kernel/init/main.c cui8_stress.flag) configures 0 at boot,
 * and a test restoring the default silently de-stressed every later test
 * on the image built to park on every await. Nothing outside tests and
 * the boot-time stress arm may touch this. */
#define VIO_BLK_AWAIT_SPINS 4096
ULONG VioBlkSetAwaitSpinBound(ULONG spins);

/* Test/stress instrumentation, same knob class (docs/19 §8.1): while held,
 * VioBlkDrain defers harvesting, so a parked issuer PROVABLY stays parked —
 * the in-flight window is a controlled state again, which the completion
 * ISR otherwise closes at device speed (a cancel test that rode the old
 * tick-drain latency became a race, docs/19 §11e). The driver's own
 * forward-progress paths (submit-side retries, the terminating thread's
 * poll-home) bypass the hold, so it can never wedge the driver — and
 * releasing it harvests inline, because no further MSI is owed for entries
 * published while held. VioBlkPumpCompletions is the watcher's manual
 * harvest for advancing an issuer through pre-window I/O while the hold is
 * up. Nothing outside tests may touch either. */
void VioBlkSetCompletionHold(BOOLEAN hold);
void VioBlkPumpCompletions(void);

/* Probe PCI bus 0, bring the device up per the virtio 1.2 cs01 §3.1.1
 * initialization sequence, and set up the request queue. Returns TRUE when
 * a disk is ready; FALSE when no virtio-blk function exists. */
BOOLEAN VioBlkInitialize(void);

BOOLEAN VioBlkIsPresent(void);
uint64_t VioBlkSectorCount(void);

/* Synchronous sector I/O through an internal bounce frame (buffers may be
 * physically discontiguous pool/cache memory). */
NTSTATUS VioBlkReadSectors(uint64_t sectorLba, uint32_t sectorCount, void *buffer);
NTSTATUS VioBlkWriteSectors(uint64_t sectorLba, uint32_t sectorCount, const void *buffer);

/* Synchronous direct-DMA sector I/O: the device reads/writes the caller's
 * physically contiguous buffer itself — no bounce, no copy (CUI-8, docs/19
 * §5a; the page cache's frames are single 4 KiB frames, so page-granularity
 * transfers describe them to the device directly). At most one page per
 * call. */
NTSTATUS VioBlkReadSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);
NTSTATUS VioBlkWriteSectorsPhysical(uint64_t sectorLba, uint32_t sectorCount, uint64_t physical);

#endif /* PROSKRNL_DRIVERS_VIRTIO_BLK_H */
