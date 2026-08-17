/* drivers/virtio/snd.h — virtio-snd: the PCM transport behind \Device\Snd*
 * (AUD-1, HACK-007; docs/23).
 *
 * controlq + txq only: the render path. eventq is left unpopulated (nothing
 * consumes jack/xrun events — no buffers are posted, no verb pretends to
 * deliver them) and rxq is AUD-3's (docs/23 §3, Art. 12). No MSI-X vector:
 * harvest joins IoDrainDeviceCompletions and rides the tick tail's 1 ms
 * bound against a 10 ms period — docs/19 §11f is the controlling precedent
 * (poll-and-nap stays until a consumer convicts it).
 */
#ifndef PROSKRNL_DRIVERS_VIRTIO_SND_H
#define PROSKRNL_DRIVERS_VIRTIO_SND_H

#include <stdint.h>

#include "abi/ntdef.h"
#include "drivers/sndproto.h" /* SND_PCM_INFO / SND_PCM_SET_PARAMS / SND_MAX_PERIODS */

/* Streams the driver will carry (\Device\Snd0..3). An internal capacity
 * choice, not a spec value: QEMU's default is 2 and its property maximum is
 * 10 (pinned tree hw/audio/virtio-snd.c realize check); a fifth stream has
 * no consumer. The device's own count decides how many are real. */
#define VIO_SND_MAX_STREAMS 4

/* Probe PCI bus 0, bring the device up per the virtio 1.2 cs01 §3.1.1
 * initialization sequence, set up controlq + txq, and cache every stream's
 * PCM_INFO (the device's own claim). Returns TRUE when a sound device is
 * ready; FALSE (loudly, on serial) when none exists. */
BOOLEAN VioSndInitialize(void);

BOOLEAN VioSndIsPresent(void);
uint32_t VioSndStreamCount(void);

/* Stream `streamId`'s virtio_snd_pcm_info, cached at init and relayed
 * verbatim (never touches MMIO). streamId < VioSndStreamCount(). */
const SND_PCM_INFO *VioSndStreamInfo(uint32_t streamId);

/* The control verbs (virtio 1.2 cs01 §5.14.6.1), one call per ioctl, each
 * a synchronous controlq round trip: submit under the dispatcher lock,
 * bounded drain-spin, then park on the request's event with the blk-shaped
 * 10 s wedge panic (QEMU serves the controlq synchronously at the notify).
 * The returned NTSTATUS is the device's own answer mapped per sndproto.h.
 * SET_PARAMS additionally (re)sizes the stream's period slots and PREPARE
 * zeroes the position counter. */
NTSTATUS VioSndSetParams(uint32_t streamId, const SND_PCM_SET_PARAMS *params);
NTSTATUS VioSndPrepare(uint32_t streamId);
NTSTATUS VioSndStart(uint32_t streamId);
NTSTATUS VioSndStop(uint32_t streamId);
NTSTATUS VioSndRelease(uint32_t streamId);

/* TRUE once a SET_PARAMS has succeeded for the stream; *periodBytesOut
 * then reports the negotiated period. A write cannot be sized before
 * this (sndproto.h: STATUS_INVALID_DEVICE_STATE). */
BOOLEAN VioSndStreamParams(uint32_t streamId, uint32_t *periodBytesOut);

/* Blocking write of EXACTLY one period (docs/23 §4a): copies the pool
 * bounce into a driver-owned DMA frame, submits one txq chain
 * (virtio_snd_pcm_xfer header + frames + status footer, §5.14.6.8), and
 * returns without waiting for the device to consume it. When every period
 * slot is in flight the caller PARKS on the stream's space event until the
 * drain harvests a completion — THE new blocking point G14 declares. A
 * non-SUCCESS wait (a terminating thread) returns that status; the
 * in-flight periods live in driver frames, so the caller owes nothing
 * (docs/20 R4 is satisfied by ownership, not by awaiting). */
NTSTATUS VioSndWritePeriod(uint32_t streamId, const void *buffer, ULONG length);

/* Total payload bytes completed (consumed by the device) since the last
 * successful PREPARE, counted at tx harvest. */
uint64_t VioSndPosition(uint32_t streamId);

/* Harvest every published controlq/txq completion: status stores, position
 * accounting, event sets — nothing else (docs/20 R2). THE snd harvest arm
 * of the one drain authority (Art. 11); call with the dispatcher lock held,
 * preferably through IoDrainDeviceCompletions. */
void VioSndDrain(void);

/* Requests in flight (control + tx periods, submitted, not yet harvested). */
ULONG VioSndInFlightCount(void);
ULONG VioSndTxInFlightCount(uint32_t streamId);

/* Test instrumentation, the VioBlkSetCompletionHold knob class (docs/19
 * §8.1): while held, VioSndDrain defers the TX harvest so a parked writer
 * provably stays parked; controlq harvest and the driver's own
 * forward-progress paths bypass it. Releasing harvests inline. Nothing
 * outside tests may touch either. */
void VioSndSetCompletionHold(BOOLEAN hold);
void VioSndPumpCompletions(void);

#endif /* PROSKRNL_DRIVERS_VIRTIO_SND_H */
