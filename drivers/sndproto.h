/* drivers/sndproto.h — the \Device\Snd<n> contract (AUD-1, HACK-007).
 *
 * The kernel <-> user protocol for the PCM stream devices, shared by
 * drivers/snd.c and everything that opens them (tests/audio, and
 * user/wine/dlls/winevsnd.drv from AUD-2). Outside abi/ for the same reason
 * as drivers/fbproto.h: NT has no such devices, so there is nothing in
 * Wine's headers to generate the contract from (Art. 4 governs values that
 * exist in the NT contract; these devices do not exist in NT at all).
 *
 * The devices are HACK-007 (docs/10): on NT the audio surface an
 * unprivileged .exe sees is entirely user-mode API (mmdevapi/WASAPI) over
 * audiodg and the kernel-streaming stack, and no Nt* call carries PCM.
 * mmdevapi's unixlib seam still needs a transport below it (docs/23 §1),
 * so like \Device\Fb0 these sit at the OUTSIDE of the boundary (Art. 2's
 * audio exception) and are reached through the existing NtCreateFile /
 * NtDeviceIoControlFile / NtWriteFile surface.
 *
 * One device node per PCM stream the virtio-snd device reports:
 * \Device\Snd0, \Device\Snd1, ... — each node's direction is the stream's
 * own PCM_INFO answer relayed verbatim, never instance order (the HACK-002
 * "the device's claim, not PCI enumeration" rule). The ioctls mirror the
 * virtio control verbs one-to-one; the payloads relay the virtio encodings
 * untranslated. NO format translation, no resampling, no mixing, no volume
 * in the kernel, ever: all of that is policy, and policy lives above the
 * boundary (the keyboard-layout argument from HACK-002, applied to PCM).
 *
 * Contract, per render (direction OUTPUT) stream:
 *
 *   NtCreateFile(\Device\SndN, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
 *                share = 0)                       exclusive per stream
 *   IOCTL_PRSSND_INFO        -> SND_PCM_INFO      the device's own claim
 *   IOCTL_PRSSND_SET_PARAMS  <- SND_PCM_SET_PARAMS
 *   IOCTL_PRSSND_PREPARE / START / STOP / RELEASE
 *   NtWriteFile(buffer, period_bytes)             EXACTLY one period per
 *                                                 call; blocks while the
 *                                                 device's buffer is full
 *   IOCTL_PRSSND_POSITION    -> SND_POSITION      bytes the device consumed
 *
 * Writes BLOCK: up to buffer_bytes / period_bytes periods ride in flight,
 * and when the ring is full the writer parks until the device returns a
 * buffer — the pacing clock emerges from tx completion, no timer invented
 * (docs/23 §4a). A write whose length is not exactly the SET_PARAMS
 * period_bytes is an error rather than a silent short write, and a write
 * before any successful SET_PARAMS is STATUS_INVALID_DEVICE_STATE (the
 * driver cannot know the period). Each stream opens EXCLUSIVELY: a second
 * open gets STATUS_SHARING_VIOLATION (the Io share engine, no private
 * flag — G10/Art. 11).
 *
 * Verb statuses relay the device's own answer as a real NT failure, fixed
 * here so both sides agree: VIRTIO_SND_S_OK -> STATUS_SUCCESS, S_BAD_MSG ->
 * STATUS_INVALID_PARAMETER, S_NOT_SUPP -> STATUS_INVALID_DEVICE_REQUEST,
 * S_IO_ERR -> STATUS_IO_DEVICE_ERROR. Unbuilt verbs refuse loudly with
 * STATUS_NOT_IMPLEMENTED and name themselves on serial (Art. 12).
 *
 * AUD-1 scope: render only (controlq + txq). A capture (direction INPUT)
 * stream's node answers INFO and the control verbs, but has no Read op
 * until AUD-3 builds the rxq path — the missing op makes the Io layer
 * refuse with its own status rather than fabricate silence (Art. 12).
 *
 * Transport capacity, stated rather than discovered: the kernel driver
 * carries one period per DMA frame and at most SND_MAX_PERIODS periods in
 * flight, so SET_PARAMS with period_bytes > 4096 or with
 * buffer_bytes / period_bytes > SND_MAX_PERIODS is refused
 * STATUS_INVALID_PARAMETER before reaching the device. QEMU's defaults
 * (buffer 8192 / period 2048) sit well inside both bounds.
 */
#ifndef PROSKRNL_DRIVERS_SNDPROTO_H
#define PROSKRNL_DRIVERS_SNDPROTO_H

#include <stdint.h>

/* CTL_CODE / METHOD_BUFFERED / FILE_READ_ACCESS / FILE_DEVICE_SOUND. Both
 * sides of this contract get them from their own view of the same Microsoft
 * definitions: the kernel from abi/ntioapi.h (generated from the pinned
 * Wine winioctl.h, Art. 4), a PE client from mingw's winioctl.h. */
#ifdef _WIN32
#include <winioctl.h>
#else
#include "abi/ntioapi.h"
#endif

/* Periods the kernel transport can keep in flight per stream (one DMA
 * frame each). An internal capacity choice, not a spec value — the
 * VIO_BLK_MAX_INFLIGHT precedent. */
#define SND_MAX_PERIODS 8

/* Function codes 0x800-0x806: 0x000-0x7FF are reserved to Microsoft, custom
 * codes start at 0x800 (MS docs, "Defining I/O Control Codes"). One ioctl
 * per virtio PCM control verb (virtio 1.2 cs01 §5.14.6.1), plus POSITION —
 * the one query the wire needs and virtio answers implicitly (bytes counted
 * at tx-completion harvest, docs/23 §4a). */
#define IOCTL_PRSSND_INFO CTL_CODE(FILE_DEVICE_SOUND, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_SET_PARAMS                                                                    \
    CTL_CODE(FILE_DEVICE_SOUND, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_PREPARE  CTL_CODE(FILE_DEVICE_SOUND, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_START    CTL_CODE(FILE_DEVICE_SOUND, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_STOP     CTL_CODE(FILE_DEVICE_SOUND, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_RELEASE  CTL_CODE(FILE_DEVICE_SOUND, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_PRSSND_POSITION CTL_CODE(FILE_DEVICE_SOUND, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)

/* The stream's virtio_snd_pcm_info, relayed verbatim (virtio 1.2 cs01
 * §5.14.6.6.2 struct virtio_snd_pcm_info; cross-check third_party/qemu
 * include/standard-headers/linux/virtio_snd.h). formats/rates are bitmaps
 * of (1 << SND_PCM_FMT_*) / (1 << SND_PCM_RATE_*); direction is SND_D_*.
 * Reported untranslated so neither side bakes in a QEMU constant — the
 * hidproto ABS_INFO precedent. */
typedef struct SND_PCM_INFO
{
    uint32_t hdaFnNid; /* HDA function group node id; QEMU reports 0 */
    uint32_t features; /* (1 << virtio VIRTIO_SND_PCM_F_*) bitmap */
    uint64_t formats;  /* (1 << SND_PCM_FMT_*) bitmap */
    uint64_t rates;    /* (1 << SND_PCM_RATE_*) bitmap */
    uint8_t direction; /* SND_D_OUTPUT / SND_D_INPUT — the device's claim */
    uint8_t channelsMin;
    uint8_t channelsMax;
    uint8_t reserved[5];
} SND_PCM_INFO;
_Static_assert(sizeof(SND_PCM_INFO) == 32,
               "virtio_snd_pcm_info is 32 bytes (virtio 1.2 cs01 §5.14.6.6.2)");

/* The virtio_snd_pcm_set_params payload minus its stream header — the
 * stream is the device node (virtio 1.2 cs01 §5.14.6.6.3; cross-check
 * virtio_snd.h struct virtio_snd_pcm_set_params). Forwarded verbatim; the
 * device's own status decides, except the two transport-capacity bounds in
 * the header comment. */
typedef struct SND_PCM_SET_PARAMS
{
    uint32_t bufferBytes; /* size of the hardware buffer */
    uint32_t periodBytes; /* size of one period = one NtWriteFile */
    uint32_t features;    /* (1 << virtio VIRTIO_SND_PCM_F_*); 0 at AUD-1 */
    uint8_t channels;
    uint8_t format; /* SND_PCM_FMT_* */
    uint8_t rate;   /* SND_PCM_RATE_* */
    uint8_t reserved;
} SND_PCM_SET_PARAMS;
_Static_assert(sizeof(SND_PCM_SET_PARAMS) == 16,
               "SND_PCM_SET_PARAMS layout is the \\Device\\Snd* contract");

/* Total bytes of this stream's payload the device has consumed, counted at
 * tx-completion harvest; reset to 0 by a successful PREPARE. 0 before START
 * is a fact about the device, not a fabricated answer (docs/23 §4a). */
typedef struct SND_POSITION
{
    uint64_t bytesConsumed;
} SND_POSITION;
_Static_assert(sizeof(SND_POSITION) == 8, "SND_POSITION layout is the \\Device\\Snd* contract");

/* Dataflow directions (virtio 1.2 cs01 §5.14.6.6.2 VIRTIO_SND_D_*;
 * cross-check virtio_snd.h). */
#define SND_D_OUTPUT 0
#define SND_D_INPUT  1

/* Sample-format bit positions (virtio 1.2 cs01 §5.14.6.6.3
 * VIRTIO_SND_PCM_FMT_*; cross-check virtio_snd.h). Only the ones a
 * consumer exists for (the hidproto rule): S16 is the AUD-1 verdict
 * format end-to-end — QEMU's wav audiodev refuses float and 32-bit
 * (pinned tree audio/wavaudio.c wav_init_out), docs/23 §6a. */
#define SND_PCM_FMT_S16 5

/* Frame-rate bit positions (virtio 1.2 cs01 §5.14.6.6.3
 * VIRTIO_SND_PCM_RATE_*; cross-check virtio_snd.h). */
#define SND_PCM_RATE_44100 6
#define SND_PCM_RATE_48000 7

#endif /* PROSKRNL_DRIVERS_SNDPROTO_H */
