/*
 * winevsnd stream — endpoints, render + capture streams, the clocks, the
 * feeder and the capture thread (AUD-2 render, AUD-3 capture; docs/23 §4b).
 *
 * One render device per process: \Device\Snd<n> opens EXCLUSIVE (the Io
 * share engine, drivers/sndproto.h), so in-process concurrency is real —
 * the feeder mixes all of this process's shared-mode streams in float,
 * applies the session volumes in software (QEMU's device has no mixer),
 * converts to the negotiated device format (S16 48 kHz stereo under QEMU),
 * and blocking-writes one period per cycle: the parked NtWriteFile IS the
 * period clock (docs/23 §4a — the pacing emerges from tx completion, no
 * timer invented). A second process's open answers STATUS_SHARING_VIOLATION,
 * surfaced as AUDCLNT_E_DEVICE_IN_USE — the recorded docs/03 deviation
 * whose named exit is audiodg-lite (HACK-008, reserved).
 *
 * Capture (AUD-3) is the mirror: one capture device per process, a capture
 * thread whose blocking NtReadFile of one device period IS the capture
 * clock, depositing into every started capture stream's ring at the
 * stream's own rate/format (the feeder's decode/resample inverted) with
 * held_frames saturating at the buffer — data the client does not fetch is
 * dropped, the oracle drivers' own overrun posture (winealsa alsa_read_data
 * caps at bufsize; mmdevapi/tests/capture.c pins pad == buffer after a
 * sleep). The get/release_capture_buffer protocol is winealsa's, which the
 * capture pairs pin: one mmdevapi period per GetBuffer or BUFFER_EMPTY,
 * devpos = frames the client consumed, position = consumed + held.
 *
 * On underrun the feeder mixes what it has and leaves silence for the rest,
 * so the stream clock keeps advancing through the glitch — WASAPI's
 * observable contract — and the miss is COUNTED: the underrun total is the
 * number the [KTEST] audio verdict line reports (docs/19 §8.4's rule — a
 * number, never an inference).
 *
 * The ring/clock arithmetic (get/release_render_buffer, padding, position)
 * follows the oracle's own drivers — winealsa's alsa.c ring and winepulse's
 * error shapes — because the winetest render pairs pin exactly those.
 * Position advances in period-granularity steps; that is legal WASAPI, and
 * QPC interpolation (docs/22) is the named refinement if a pair ever
 * convicts the staircase.
 */
#include <stdio.h>

/* initguid BEFORE any header that DEFINE_GUIDs, so the KSDATAFORMAT_SUBTYPE_*
 * comparisons below have definitions in this module (nothing else links a
 * uuid library into a -nostdlib DLL). audioclient.h drags ksmedia.h in, so
 * the order must be pinned here, ahead of winevsnd.h. */
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "initguid.h"
#include "ks.h"
#include "ksmedia.h"

#include "winevsnd.h"

#include "drivers/sndproto.h"

/* The device format winevsnd negotiates with QEMU's virtio-snd: S16 48 kHz
 * stereo — the AUD-1 verdict format end-to-end (QEMU's wav audiodev refuses
 * float, docs/23 §6a), and within every stream the pinned model advertises.
 * The device's own INFO answer is still checked before SET_PARAMS. */
#define VSND_DEV_RATE          48000
#define VSND_DEV_CHANNELS      2
#define VSND_DEV_BLOCK         4                        /* bytes per S16 stereo frame */
#define VSND_DEV_PERIOD_FRAMES 480                      /* 10 ms */
#define VSND_DEV_PERIOD_BYTES  (VSND_DEV_PERIOD_FRAMES * VSND_DEV_BLOCK)
#define VSND_DEV_PERIODS       4                        /* ring depth: 40 ms of slack */

/* The mmdevapi periods this driver reports (get_device_period): the same
 * defaults the oracle's drivers use (dlls/winealsa.drv/alsa.c def_period /
 * min_period), and 10 ms at 48 kHz lands one period at 1920 bytes — inside
 * the transport's 4096-byte period bound (drivers/sndproto.h). */
#define VSND_DEF_PERIOD 100000
#define VSND_MIN_PERIOD  50000

enum sample_kind { KIND_U8, KIND_S16, KIND_S24, KIND_S32, KIND_F32 };

struct vsnd_stream
{
    struct vsnd_stream *next;
    EDataFlow flow;
    AUDCLNT_SHAREMODE share;
    DWORD flags;
    enum sample_kind kind;
    UINT32 rate, channels, block_align;
    UINT32 bufsize_frames;   /* the client-visible buffer (duration) */
    UINT32 period_frames;    /* the mmdevapi period, in CLIENT frames */
    BYTE *local_buffer;      /* the ring */
    BYTE *tmp_buffer;        /* wrap-around GetBuffer staging */
    UINT32 tmp_buffer_frames;
    int getbuf_last;         /* alsa's protocol state: <0 = tmp buffer */
    UINT32 wri_offs;         /* ring write index, frames */
    UINT32 lcl_offs;         /* ring read index, frames */
    UINT32 held_frames;      /* GetCurrentPadding */
    UINT64 written_frames;   /* total released by the client */
    UINT64 last_pos;         /* monotonic clamp for GetPosition */
    double src_frac;         /* feeder resampler position, [0,1) */
    float vols[2];
    BOOL started;
    BOOL ever_started;       /* event pacing begins at first Start and never
                              * stops again (render.c: "Still receiving
                              * events!" after Stop/Reset -- the winepulse
                              * timer-loop shape) */
    HANDLE event;
};

static RTL_CRITICAL_SECTION vsnd_lock;
static BOOL vsnd_lock_ready;

static struct vsnd_stream *streams;
static HANDLE dev_handle;
static int dev_node = -1, cap_node = -1;
static BOOL nodes_probed;
static int dev_streams;
static BOOL dev_started;
static HANDLE feeder_thread;
static BOOL feeder_quit;
static BOOL feeder_stopping;
static UINT64 underrun_count;

/* The capture mirror of the dev_* and feeder_* set (AUD-3). cap_prepared
 * tracks whether the capture device is PREPAREd (reads may flow): raised
 * by cap_acquire, lowered by capture_stop's RELEASE — which goes out
 * BEFORE the join because its flush is what unparks a reader blocked in
 * NtReadFile — and by cap_release. */
static HANDLE cap_handle;
static int cap_streams;
static BOOL cap_started;
static BOOL cap_prepared;
static HANDLE capture_thread;
static BOOL capture_quit;
static BOOL capture_stopping;

/* The AUD-2 verdict channel: the WASAPI half of tests/run/run.sh audio reads
 * this after playback and prints the count on its [KTEST] line. */
DECLSPEC_EXPORT UINT64 winevsnd_diag_underruns(void)
{
    return underrun_count;
}

static void vsnd_take_lock(void)
{
    if (!vsnd_lock_ready)
    {
        /* First touch is single-threaded (load_driver under mmdevapi's
         * INIT_ONCE); the feeder does not exist yet. */
        RtlInitializeCriticalSection(&vsnd_lock);
        vsnd_lock_ready = TRUE;
    }
    RtlEnterCriticalSection(&vsnd_lock);
}

static void vsnd_drop_lock(void)
{
    RtlLeaveCriticalSection(&vsnd_lock);
}

static NTSTATUS unlock_result(HRESULT *result, HRESULT value)
{
    *result = value;
    vsnd_drop_lock();
    return STATUS_SUCCESS;
}

static void *vsnd_alloc(SIZE_T size)
{
    return RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, size);
}

static void vsnd_free(void *ptr)
{
    if (ptr) RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, ptr);
}

static struct vsnd_stream *handle_get_stream(stream_handle h)
{
    return (struct vsnd_stream *)(UINT_PTR)h;
}

static UINT32 muldiv_u32(UINT64 a, UINT64 b, UINT64 c)
{
    return (UINT32)(a * b / c);
}

/* ---- the device ---------------------------------------------------------- */

static NTSTATUS open_node(int node, HANDLE *handle)
{
    WCHAR path[32];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    char narrow[32];
    int i, len;

    len = _snprintf(narrow, sizeof(narrow), "\\Device\\Snd%u", node);
    for (i = 0; i <= len; i++) path[i] = (unsigned char)narrow[i];
    name.Buffer = path;
    name.Length = len * sizeof(WCHAR);
    name.MaximumLength = name.Length + sizeof(WCHAR);
    InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &attr,
                        &io, NULL, FILE_ATTRIBUTE_NORMAL, 0 /* exclusive */, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
}

static NTSTATUS dev_ioctl(HANDLE handle, ULONG code, void *in_buf, ULONG in_len,
                          void *out_buf, ULONG out_len)
{
    IO_STATUS_BLOCK io;

    return NtDeviceIoControlFile(handle, NULL, NULL, NULL, &io, code,
                                 in_buf, in_len, out_buf, out_len);
}

/* One probe per process: which nodes exist, and each node's OWN direction
 * claim (never instance order — the HACK-002 rule the kernel driver already
 * follows; this side just relays the relay). A node someone else holds open
 * answers STATUS_SHARING_VIOLATION: it exists, but with no handle there is
 * no INFO to relay, so it is skipped with its name on serial rather than
 * listed under a fabricated direction (Art. 12). */
static void probe_nodes(void)
{
    int node;

    if (nodes_probed) return;
    for (node = 0; node < 4; node++)
    {
        SND_PCM_INFO info;
        HANDLE handle;
        NTSTATUS status;

        status = open_node(node, &handle);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
            break;
        if (status == STATUS_SHARING_VIOLATION)
        {
            vsnd_report("winevsnd: \\Device\\Snd%u is held elsewhere - not enumerated\n", node);
            continue;
        }
        if (status)
        {
            /* Loud, named: a node that exists but refuses the probe for an
             * unexpected reason must not silently shrink the endpoint list
             * (Art. 12). */
            vsnd_report("winevsnd: \\Device\\Snd%u probe open failed (%08x)\n", node, (UINT)status);
            continue;
        }
        status = dev_ioctl(handle, IOCTL_PRSSND_INFO, NULL, 0, &info, sizeof(info));
        if (!status)
        {
            if (info.direction == SND_D_OUTPUT && dev_node < 0) dev_node = node;
            if (info.direction == SND_D_INPUT && cap_node < 0) cap_node = node;
        }
        else
            vsnd_report("winevsnd: \\Device\\Snd%u INFO refused (%08x)\n", node, (UINT)status);
        NtClose(handle);
    }
    nodes_probed = TRUE;
}

/* Open + configure the render device for the fixed device format. Called
 * with the lock held, by the first render stream. */
static HRESULT dev_acquire(void)
{
    SND_PCM_INFO info;
    SND_PCM_SET_PARAMS params;
    NTSTATUS status;

    if (dev_handle) return S_OK;

    probe_nodes();
    if (dev_node < 0)
    {
        vsnd_report("winevsnd: no render node - endpoint creation refused\n");
        return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
    }

    status = open_node(dev_node, &dev_handle);
    if (status == STATUS_SHARING_VIOLATION)
    {
        /* Another process holds the one render stream. A real WASAPI status
         * in circumstances Windows would not produce it (shared mode admits
         * N processes): the recorded docs/03 deviation, docs/23 §4d;
         * audiodg-lite (HACK-008) is its named, unbuilt exit. */
        vsnd_report("winevsnd: \\Device\\Snd%u busy - AUDCLNT_E_DEVICE_IN_USE (docs/03)\n",
                    dev_node);
        dev_handle = NULL;
        return AUDCLNT_E_DEVICE_IN_USE;
    }
    if (status)
    {
        vsnd_report("winevsnd: \\Device\\Snd%u open failed (%08x)\n", dev_node, (UINT)status);
        dev_handle = NULL;
        return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
    }

    /* The device's own claim gates the format, never this driver's habit. */
    if (dev_ioctl(dev_handle, IOCTL_PRSSND_INFO, NULL, 0, &info, sizeof(info)) ||
        !(info.formats & (1ull << SND_PCM_FMT_S16)) ||
        !(info.rates & (1ull << SND_PCM_RATE_48000)) ||
        info.channelsMin > VSND_DEV_CHANNELS || info.channelsMax < VSND_DEV_CHANNELS)
    {
        vsnd_report("winevsnd: \\Device\\Snd%u does not claim S16/48k/stereo - refused\n",
                    dev_node);
        goto fail;
    }

    params.bufferBytes = VSND_DEV_PERIOD_BYTES * VSND_DEV_PERIODS;
    params.periodBytes = VSND_DEV_PERIOD_BYTES;
    params.features = 0;
    params.channels = VSND_DEV_CHANNELS;
    params.format = SND_PCM_FMT_S16;
    params.rate = SND_PCM_RATE_48000;
    params.reserved = 0;
    if (dev_ioctl(dev_handle, IOCTL_PRSSND_SET_PARAMS, &params, sizeof(params), NULL, 0))
    {
        vsnd_report("winevsnd: SET_PARAMS refused by \\Device\\Snd%u\n", dev_node);
        goto fail;
    }
    if (dev_ioctl(dev_handle, IOCTL_PRSSND_PREPARE, NULL, 0, NULL, 0))
    {
        vsnd_report("winevsnd: PREPARE refused by \\Device\\Snd%u\n", dev_node);
        goto fail;
    }
    return S_OK;

fail:
    NtClose(dev_handle);
    dev_handle = NULL;
    return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
}

/* Called with the lock held, after the feeder is gone. */
static void dev_release(void)
{
    if (!dev_handle) return;
    if (dev_started) dev_ioctl(dev_handle, IOCTL_PRSSND_STOP, NULL, 0, NULL, 0);
    dev_ioctl(dev_handle, IOCTL_PRSSND_RELEASE, NULL, 0, NULL, 0);
    NtClose(dev_handle);
    dev_handle = NULL;
    dev_started = FALSE;
}

/* The capture device, dev_acquire mirrored: same geometry, same format
 * gate, same AUDCLNT_E_DEVICE_IN_USE deviation for a foreign holder
 * (docs/03 "AUD-2 notes", extended to capture). Called with the lock held,
 * by the first capture stream. */
static HRESULT cap_acquire(void)
{
    SND_PCM_INFO info;
    SND_PCM_SET_PARAMS params;
    NTSTATUS status;

    if (cap_handle) return S_OK;

    probe_nodes();
    if (cap_node < 0)
    {
        vsnd_report("winevsnd: no capture node - endpoint creation refused\n");
        return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
    }

    status = open_node(cap_node, &cap_handle);
    if (status == STATUS_SHARING_VIOLATION)
    {
        vsnd_report("winevsnd: \\Device\\Snd%u busy - AUDCLNT_E_DEVICE_IN_USE (docs/03)\n",
                    cap_node);
        cap_handle = NULL;
        return AUDCLNT_E_DEVICE_IN_USE;
    }
    if (status)
    {
        vsnd_report("winevsnd: \\Device\\Snd%u open failed (%08x)\n", cap_node, (UINT)status);
        cap_handle = NULL;
        return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
    }

    /* The device's own claim gates the format, never this driver's habit. */
    if (dev_ioctl(cap_handle, IOCTL_PRSSND_INFO, NULL, 0, &info, sizeof(info)) ||
        !(info.formats & (1ull << SND_PCM_FMT_S16)) ||
        !(info.rates & (1ull << SND_PCM_RATE_48000)) ||
        info.channelsMin > VSND_DEV_CHANNELS || info.channelsMax < VSND_DEV_CHANNELS)
    {
        vsnd_report("winevsnd: \\Device\\Snd%u does not claim S16/48k/stereo - refused\n",
                    cap_node);
        goto fail;
    }

    params.bufferBytes = VSND_DEV_PERIOD_BYTES * VSND_DEV_PERIODS;
    params.periodBytes = VSND_DEV_PERIOD_BYTES;
    params.features = 0;
    params.channels = VSND_DEV_CHANNELS;
    params.format = SND_PCM_FMT_S16;
    params.rate = SND_PCM_RATE_48000;
    params.reserved = 0;
    if (dev_ioctl(cap_handle, IOCTL_PRSSND_SET_PARAMS, &params, sizeof(params), NULL, 0))
    {
        vsnd_report("winevsnd: SET_PARAMS refused by \\Device\\Snd%u\n", cap_node);
        goto fail;
    }
    if (dev_ioctl(cap_handle, IOCTL_PRSSND_PREPARE, NULL, 0, NULL, 0))
    {
        vsnd_report("winevsnd: PREPARE refused by \\Device\\Snd%u\n", cap_node);
        goto fail;
    }
    cap_prepared = TRUE;
    return S_OK;

fail:
    NtClose(cap_handle);
    cap_handle = NULL;
    return AUDCLNT_E_ENDPOINT_CREATE_FAILED;
}

/* Called with the lock held, after the capture thread is gone (or was
 * never started). RELEASE also unparks a reader still blocked in
 * NtReadFile: the kernel relays the device's flush as a short success
 * (drivers/sndproto.h). */
static void cap_release(void)
{
    if (!cap_handle) return;
    if (cap_started) dev_ioctl(cap_handle, IOCTL_PRSSND_STOP, NULL, 0, NULL, 0);
    if (cap_prepared) dev_ioctl(cap_handle, IOCTL_PRSSND_RELEASE, NULL, 0, NULL, 0);
    NtClose(cap_handle);
    cap_handle = NULL;
    cap_started = FALSE;
    cap_prepared = FALSE;
}

/* ---- the feeder ---------------------------------------------------------- */

static float decode_sample(const struct vsnd_stream *s, UINT32 frame, UINT ch)
{
    UINT32 idx = (s->lcl_offs + frame) % s->bufsize_frames;
    const BYTE *p = s->local_buffer + (SIZE_T)idx * s->block_align;

    if (s->channels == 1) ch = 0;
    switch (s->kind)
    {
    case KIND_U8:
        return ((int)p[ch] - 128) / 128.0f;
    case KIND_S16:
        return ((const short *)p)[ch] / 32768.0f;
    case KIND_S24:
    {
        const BYTE *b = p + ch * 3;
        int v = (b[0] << 8) | (b[1] << 16) | ((int)(signed char)b[2] << 24);
        return v / 2147483648.0f;
    }
    case KIND_S32:
        return ((const int *)p)[ch] / 2147483648.0f;
    case KIND_F32:
        return ((const float *)p)[ch];
    }
    return 0.0f;
}

/* Mix up to one device period of this stream into acc, consuming from its
 * ring at the stream's own rate (nearest-sample resampling — the simplest
 * thing that passes the boundary tests; docs/23 §5's no-policy-in-kernel
 * rule puts all of this above the boundary, and it is). Returns TRUE if the
 * stream ran short (an underrun for a started stream). */
static BOOL mix_stream(struct vsnd_stream *s, float *acc)
{
    double step = (double)s->rate / VSND_DEV_RATE;
    double pos = s->src_frac;
    UINT32 avail = s->held_frames, consumed;
    BOOL ran_short = FALSE;
    UINT32 i;

    for (i = 0; i < VSND_DEV_PERIOD_FRAMES; i++)
    {
        UINT32 idx = (UINT32)pos;

        if (idx >= avail)
        {
            ran_short = TRUE;
            break;
        }
        acc[i * 2 + 0] += decode_sample(s, idx, 0) * s->vols[0];
        acc[i * 2 + 1] += decode_sample(s, idx, 1) * s->vols[1];
        pos += step;
    }

    consumed = (UINT32)pos;
    if (consumed > avail) consumed = avail;
    s->held_frames -= consumed;
    s->lcl_offs = (s->lcl_offs + consumed) % s->bufsize_frames;
    s->src_frac = ran_short ? 0.0 : pos - consumed;
    return ran_short;
}

/* ---- the capture thread (AUD-3) ------------------------------------------- */

/* Encode one float sample into a client frame — decode_sample's inverse,
 * kind by kind (S16 uses the symmetric 1/32768 scaling for the same
 * bit-exact round-trip the render path documents). */
static void encode_sample(enum sample_kind kind, float v, BYTE *p, UINT ch)
{
    switch (kind)
    {
    case KIND_U8:
    {
        int iv = (int)(v * 128.0f) + 128;

        if (iv < 0) iv = 0;
        if (iv > 255) iv = 255;
        p[ch] = (BYTE)iv;
        break;
    }
    case KIND_S16:
    {
        float scaled = v * 32768.0f;

        if (scaled > 32767.0f) scaled = 32767.0f;
        if (scaled < -32768.0f) scaled = -32768.0f;
        ((short *)p)[ch] = (short)scaled;
        break;
    }
    case KIND_S24:
    case KIND_S32:
    {
        float scaled = v * 2147483648.0f;
        int iv;

        if (scaled >= 2147483520.0f) iv = 0x7fffff80; /* largest float < 2^31 */
        else if (scaled < -2147483648.0f) iv = (int)0x80000000;
        else iv = (int)scaled;
        if (kind == KIND_S32)
            ((int *)p)[ch] = iv;
        else
        {
            BYTE *b = p + ch * 3;

            b[0] = (BYTE)(iv >> 8);
            b[1] = (BYTE)(iv >> 16);
            b[2] = (BYTE)(iv >> 24);
        }
        break;
    }
    case KIND_F32:
        ((float *)p)[ch] = v;
        break;
    }
}

/* Deposit one device period into a capture stream's ring at the stream's
 * own rate and format — the feeder's decode/resample inverted (nearest
 * sample, the same policy-above-the-boundary). Frames the ring cannot hold
 * are DROPPED, held_frames saturating at the buffer: the oracle drivers'
 * overrun posture (winealsa alsa_read_data stops reading at bufsize),
 * pinned by mmdevapi/tests/capture.c (pad == buffer_size after a sleep
 * with nothing released). Called with the lock held. */
static void deposit_stream(struct vsnd_stream *s, const short *in, UINT32 in_frames)
{
    double step = (double)VSND_DEV_RATE / s->rate; /* device frames per client frame */
    double pos = s->src_frac;

    while ((UINT32)pos < in_frames)
    {
        UINT32 idx = (UINT32)pos;

        if (s->held_frames < s->bufsize_frames)
        {
            BYTE *frame = s->local_buffer + (SIZE_T)s->wri_offs * s->block_align;
            UINT ch;

            for (ch = 0; ch < s->channels; ch++)
            {
                float v = 0.0f;

                /* The front pair carries the device's stereo; further
                 * channels get silence — the render downmix mirrored. A
                 * mono client takes the device's left. */
                if (ch < 2)
                {
                    UINT dev_ch = s->channels == 1 ? 0 : ch;

                    v = in[idx * 2 + dev_ch] / 32768.0f * s->vols[ch];
                }
                encode_sample(s->kind, v, frame, ch);
            }
            s->wri_offs = (s->wri_offs + 1) % s->bufsize_frames;
            s->held_frames++;
        }
        pos += step;
    }
    s->src_frac = pos - in_frames;
}

static NTSTATUS WINAPI capture_proc(void *arg)
{
    short in[VSND_DEV_PERIOD_FRAMES * 2];
    IO_STATUS_BLOCK io;
    struct vsnd_stream *s;
    LARGE_INTEGER delay;
    NTSTATUS status;
    BOOL starve;

    for (;;)
    {
        vsnd_take_lock();
        if (capture_quit)
        {
            vsnd_drop_lock();
            break;
        }

        if (!cap_started)
        {
            /* Idle tick: nothing is captured, but the event cadence keeps
             * running for every capture stream that has ever started (the
             * feeder's ever_started rule, capture's half). */
            for (s = streams; s; s = s->next)
                if (s->flow == eCapture && s->ever_started && s->event)
                    NtSetEvent(s->event, NULL);
            vsnd_drop_lock();
            delay.QuadPart = -(LONGLONG)VSND_DEF_PERIOD;   /* one period */
            NtDelayExecution(FALSE, &delay);
            continue;
        }
        /* Once the device is STARTed the thread keeps reading even while
         * no client stream is started, depositing into none — captured
         * data a stopped client misses is dropped AT PACE, the oracle
         * drivers' own shape (winealsa's timer keeps the ALSA ring
         * draining through a client Stop). Stopping the reads instead
         * lets the backend's rate controller accumulate the whole stopped
         * stretch as un-granted budget (pinned tree audio/audio.c
         * audio_rate_peek_bytes: granted = elapsed * rate - sent, up to
         * 65536 frames) and dump it as an instant burst at the next
         * Start — which floods the ring and fails
         * mmdevapi/tests/capture.c's padding <= 2 * period assertion
         * (measured: padding 11520 after 10 reads). */
        vsnd_drop_lock();

        /* The capture clock: parks in the kernel until the device completes
         * a captured period (docs/23 §4a — the mirror). Never under the
         * lock — a parked reader must not stall the client's GetBuffer. */
        io.Information = 0;
        status = NtReadFile(cap_handle, NULL, NULL, NULL, &io, in, VSND_DEV_PERIOD_BYTES,
                            NULL, NULL);
        starve = status || io.Information != VSND_DEV_PERIOD_BYTES;

        vsnd_take_lock();
        if (!starve)
            for (s = streams; s; s = s->next)
                if (s->flow == eCapture && s->started)
                    deposit_stream(s, in, VSND_DEV_PERIOD_FRAMES);
        for (s = streams; s; s = s->next)
            if (s->flow == eCapture && s->ever_started && s->event)
                NtSetEvent(s->event, NULL);
        vsnd_drop_lock();

        if (starve)
        {
            /* A short or refused read is the stop/release flush (teardown
             * in flight — capture_quit decides above) — nap one period
             * rather than hot-spin on the released device. */
            delay.QuadPart = -(LONGLONG)VSND_DEF_PERIOD;
            NtDelayExecution(FALSE, &delay);
        }
    }
    return STATUS_SUCCESS;
}

/* Called with the lock held (feeder_start's twin). */
static void capture_start(void)
{
    LONG priority = THREAD_PRIORITY_TIME_CRITICAL;

    if (capture_thread || capture_stopping) return;
    capture_quit = FALSE;
    if (RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0,
                            (PRTL_THREAD_START_ROUTINE)capture_proc, NULL, &capture_thread, NULL))
    {
        vsnd_report("winevsnd: capture thread creation failed\n");
        capture_thread = NULL;
        return;
    }
    NtSetInformationThread(capture_thread, ThreadBasePriority, &priority, sizeof(priority));
}

/* Called with the lock held; drops it to join the capture thread. The
 * unpark ORDER is the point: STOP + RELEASE go out BEFORE the join,
 * because the RELEASE flush is what returns a parked NtReadFile
 * (drivers/sndproto.h); the handle closes later, in cap_release, once no
 * reader can be inside it. */
static void capture_stop(void)
{
    HANDLE thread = capture_thread;

    if (!thread) return;
    capture_quit = TRUE;
    capture_stopping = TRUE;
    capture_thread = NULL;
    if (cap_handle)
    {
        if (cap_started) dev_ioctl(cap_handle, IOCTL_PRSSND_STOP, NULL, 0, NULL, 0);
        dev_ioctl(cap_handle, IOCTL_PRSSND_RELEASE, NULL, 0, NULL, 0);
        cap_started = FALSE;
        cap_prepared = FALSE;
    }
    vsnd_drop_lock();
    NtWaitForSingleObject(thread, FALSE, NULL);
    NtClose(thread);
    vsnd_take_lock();
    capture_stopping = FALSE;
    /* A create_stream that landed while the lock was dropped found
     * capture_start refused and the device released; re-arm both for it
     * (the feeder_stop rationale, plus the RELEASE -> PREPARE cycle the
     * device contract allows). The re-PREPARE must happen HERE, after the
     * join — re-preparing while the old reader was still parked would
     * discard its flush completions and park it forever. */
    if (cap_streams > 0)
    {
        struct vsnd_stream *s;

        if (cap_handle && !cap_prepared &&
            !dev_ioctl(cap_handle, IOCTL_PRSSND_PREPARE, NULL, 0, NULL, 0))
            cap_prepared = TRUE;
        /* A raced stream may have Started against the released device
         * (vsnd_start marks it and defers the device START to here). */
        for (s = streams; s; s = s->next)
            if (s->flow == eCapture && s->started && cap_handle && cap_prepared &&
                !cap_started && !dev_ioctl(cap_handle, IOCTL_PRSSND_START, NULL, 0, NULL, 0))
                cap_started = TRUE;
        capture_start();
    }
}

static NTSTATUS WINAPI feeder_proc(void *arg)
{
    float acc[VSND_DEV_PERIOD_FRAMES * 2];
    short out[VSND_DEV_PERIOD_FRAMES * 2];
    IO_STATUS_BLOCK io;
    struct vsnd_stream *s;
    LARGE_INTEGER delay;
    BOOL any;
    UINT32 i;

    for (;;)
    {
        vsnd_take_lock();
        if (feeder_quit)
        {
            vsnd_drop_lock();
            break;
        }

        any = FALSE;
        for (s = streams; s; s = s->next)
            if (s->started && s->flow == eRender) any = TRUE;

        if (!any || !dev_started)
        {
            /* Idle tick: no mixing, but the event cadence keeps running for
             * every RENDER stream that has ever started (see ever_started;
             * capture streams are the capture thread's to signal). */
            for (s = streams; s; s = s->next)
                if (s->flow == eRender && s->ever_started && s->event)
                    NtSetEvent(s->event, NULL);
            vsnd_drop_lock();
            delay.QuadPart = -(LONGLONG)VSND_DEF_PERIOD;   /* one period */
            NtDelayExecution(FALSE, &delay);
            continue;
        }

        memset(acc, 0, sizeof(acc));
        for (s = streams; s; s = s->next)
        {
            if (!s->started || s->flow != eRender) continue;
            if (mix_stream(s, acc))
                underrun_count++;   /* silence fills the gap; the clock advances */
        }
        for (i = 0; i < VSND_DEV_PERIOD_FRAMES * 2; i++)
        {
            /* Symmetric 1/32768 scaling, the decode's inverse: an S16
             * client's samples round-trip BIT-EXACTLY through the float mix
             * (both scalings are powers of two), which is what lets the
             * audio leg's WASAPI half assert the same sample-exact span the
             * AUD-1 half does (docs/23 §6a). */
            float v = acc[i] * 32768.0f;

            if (v > 32767.0f) v = 32767.0f;
            if (v < -32768.0f) v = -32768.0f;
            out[i] = (short)v;
        }
        vsnd_drop_lock();

        /* The period clock: parks in the kernel until the device returns a
         * buffer (the CUI-8 engine; drivers/virtio/snd.c). Never under the
         * lock — a parked feeder must not stall the client's GetBuffer. */
        NtWriteFile(dev_handle, NULL, NULL, NULL, &io, out, VSND_DEV_PERIOD_BYTES, NULL, NULL);

        vsnd_take_lock();
        for (s = streams; s; s = s->next)
            if (s->flow == eRender && s->ever_started && s->event)
                NtSetEvent(s->event, NULL);
        vsnd_drop_lock();
    }
    return STATUS_SUCCESS;
}

/* Called with the lock held. */
static void feeder_start(void)
{
    LONG priority = THREAD_PRIORITY_TIME_CRITICAL;

    /* Refused while a stop is joining the old feeder: resetting feeder_quit
     * here would resurrect it and wedge the joiner (the release path
     * restarts the feeder after the join if streams arrived meanwhile). */
    if (feeder_thread || feeder_stopping) return;
    feeder_quit = FALSE;
    if (RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0,
                            (PRTL_THREAD_START_ROUTINE)feeder_proc, NULL, &feeder_thread, NULL))
    {
        vsnd_report("winevsnd: feeder thread creation failed\n");
        feeder_thread = NULL;
        return;
    }
    /* The priority mmdevapi's own helper uses (dlls/mmdevapi/unixlib.h
     * create_unix_thread) — the deadline argument is docs/23 §7. */
    NtSetInformationThread(feeder_thread, ThreadBasePriority, &priority, sizeof(priority));
}

/* Called with the lock held; drops it to join the feeder. */
static void feeder_stop(void)
{
    HANDLE thread = feeder_thread;

    if (!thread) return;
    feeder_quit = TRUE;
    feeder_stopping = TRUE;
    feeder_thread = NULL;
    vsnd_drop_lock();
    NtWaitForSingleObject(thread, FALSE, NULL);
    NtClose(thread);
    vsnd_take_lock();
    feeder_stopping = FALSE;
    /* A create_stream that landed while the lock was dropped found
     * feeder_start refused; it left dev_streams > 0 -- start its feeder. */
    if (dev_streams > 0) feeder_start();
}

/* ---- the entries --------------------------------------------------------- */

NTSTATUS vsnd_process_detach(void *args)
{
    struct vsnd_stream *s, *next;

    vsnd_take_lock();
    feeder_stop();
    capture_stop();
    for (s = streams; s; s = next)
    {
        next = s->next;
        vsnd_free(s->local_buffer);
        vsnd_free(s->tmp_buffer);
        vsnd_free(s);
    }
    streams = NULL;
    dev_streams = 0;
    cap_streams = 0;
    dev_release();
    cap_release();
    vsnd_drop_lock();
    if (underrun_count)
        vsnd_report("winevsnd: process detach, underruns=%u\n", (UINT)underrun_count);
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_get_endpoint_ids(void *args)
{
    struct get_endpoint_ids_params *params = args;
    static const WCHAR out_name[] = {'O','u','t',' ','(','S','n','d','0',')',0};
    static const WCHAR in_name[] = {'I','n',' ','(','S','n','d','1',')',0};
    struct
    {
        const WCHAR *name;
        char device[8];
    } found[1];
    unsigned int num = 0, i, needed, offset;
    struct endpoint *endpoint = params->endpoints;
    int node;

    vsnd_take_lock();
    probe_nodes();
    /* One endpoint per flow, each from the node's OWN direction claim
     * (probe_nodes): the render node for eRender, the capture node for
     * eCapture (AUD-3 — the withhold that stood here while capture was
     * unbuilt is gone with the reason for it). */
    node = params->flow == eRender ? dev_node : cap_node;
    vsnd_drop_lock();

    if (node >= 0)
    {
        found[0].name = params->flow == eRender ? out_name : in_name;
        _snprintf(found[0].device, sizeof(found[0].device), "Snd%u", node);
        num = 1;
    }

    /* The two-pass byte-offset packing load_driver_devices expects — the
     * winealsa shape (dlls/winealsa.drv/alsa.c alsa_get_endpoint_ids). */
    offset = needed = num * sizeof(*params->endpoints);
    for (i = 0; i < num; i++)
    {
        unsigned int name_len = wcslen(found[i].name) + 1;
        unsigned int device_len = strlen(found[i].device) + 1;

        needed += name_len * sizeof(WCHAR) + ((device_len + 1) & ~1u);
        if (needed <= params->size)
        {
            endpoint->name = offset;
            memcpy((char *)params->endpoints + offset, found[i].name, name_len * sizeof(WCHAR));
            offset += name_len * sizeof(WCHAR);
            endpoint->device = offset;
            memcpy((char *)params->endpoints + offset, found[i].device, device_len);
            offset += (device_len + 1) & ~1u;
            endpoint++;
        }
    }
    params->num = num;
    params->default_idx = 0;
    if (needed > params->size)
    {
        params->size = needed;
        params->result = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    else params->result = S_OK;
    return STATUS_SUCCESS;
}

/* The format set the feeder can decode — winepulse's acceptance set
 * (dlls/winepulse.drv/pulse.c pulse_spec_from_waveformat), which is what
 * the oracle's answers pin. Rate is free (the feeder resamples), channels
 * are 1..2 (the device is stereo; no downmix policy exists yet). */
static HRESULT parse_format(const WAVEFORMATEX *fmt, enum sample_kind *kind)
{
    if (!fmt) return E_POINTER;
    /* Up to 32 channels, PulseAudio's own ceiling (PA_CHANNELS_MAX) and so
     * the winepulse acceptance set the oracle pins: the winmm wave pair
     * opens 4- and 8-channel extensible formats, and mmdevapi's spatial
     * stream multiplexes its 12 static objects as a 12-channel float
     * stream. The feeder mixes the FRONT PAIR and drops the rest -- a
     * downmix policy above the boundary, stated here rather than hidden
     * (docs/23 s5). */
    if (!fmt->nChannels || fmt->nChannels > 32 || !fmt->nSamplesPerSec)
        return AUDCLNT_E_UNSUPPORTED_FORMAT;

    switch (fmt->wFormatTag)
    {
    case WAVE_FORMAT_PCM:
        if (fmt->wBitsPerSample == 8) { *kind = KIND_U8; return S_OK; }
        if (fmt->wBitsPerSample == 16) { *kind = KIND_S16; return S_OK; }
        if (fmt->wBitsPerSample == 24) { *kind = KIND_S24; return S_OK; }
        if (fmt->wBitsPerSample == 32) { *kind = KIND_S32; return S_OK; }
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    case WAVE_FORMAT_IEEE_FLOAT:
        if (fmt->wBitsPerSample == 32) { *kind = KIND_F32; return S_OK; }
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    case WAVE_FORMAT_EXTENSIBLE:
    {
        const WAVEFORMATEXTENSIBLE *ext = (const WAVEFORMATEXTENSIBLE *)fmt;
        WORD valid;

        if (fmt->cbSize < sizeof(*ext) - sizeof(*fmt))
            return AUDCLNT_E_UNSUPPORTED_FORMAT;
        valid = ext->Samples.wValidBitsPerSample;
        if (!valid) valid = fmt->wBitsPerSample;
        if (IsEqualGUID(&ext->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT))
        {
            if (fmt->wBitsPerSample == 32 && valid == 32) { *kind = KIND_F32; return S_OK; }
            return AUDCLNT_E_UNSUPPORTED_FORMAT;
        }
        if (IsEqualGUID(&ext->SubFormat, &KSDATAFORMAT_SUBTYPE_PCM))
        {
            if (valid != fmt->wBitsPerSample) return AUDCLNT_E_UNSUPPORTED_FORMAT;
            if (fmt->wBitsPerSample == 8) { *kind = KIND_U8; return S_OK; }
            if (fmt->wBitsPerSample == 16) { *kind = KIND_S16; return S_OK; }
            if (fmt->wBitsPerSample == 24) { *kind = KIND_S24; return S_OK; }
            if (fmt->wBitsPerSample == 32) { *kind = KIND_S32; return S_OK; }
        }
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    }
    default:
        return AUDCLNT_E_UNSUPPORTED_FORMAT;
    }
}

NTSTATUS vsnd_create_stream(void *args)
{
    struct create_stream_params *params = args;
    struct vsnd_stream *stream;
    enum sample_kind kind;
    HRESULT hr;

    if (params->share == AUDCLNT_SHAREMODE_EXCLUSIVE)
    {
        /* docs/23 §5: no exclusive mode — the oracle's driver shape
         * (winepulse pulse_create_stream). */
        params->result = AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED;
        return STATUS_SUCCESS;
    }
    if (FAILED(hr = parse_format(params->fmt, &kind)))
    {
        params->result = hr;
        return STATUS_SUCCESS;
    }

    vsnd_take_lock();
    if (FAILED(hr = params->flow == eRender ? dev_acquire() : cap_acquire()))
        return unlock_result(&params->result, hr);

    if (!(stream = vsnd_alloc(sizeof(*stream))))
        goto oom;
    stream->flow = params->flow;
    stream->share = params->share;
    stream->flags = params->flags;
    stream->kind = kind;
    stream->rate = params->fmt->nSamplesPerSec;
    stream->channels = params->fmt->nChannels;
    stream->block_align = params->fmt->nBlockAlign;
    stream->period_frames = muldiv_u32(params->fmt->nSamplesPerSec, params->period, 10000000);
    stream->bufsize_frames = muldiv_u32(params->fmt->nSamplesPerSec, params->duration, 10000000);
    if (!stream->period_frames || !stream->bufsize_frames)
    {
        vsnd_free(stream);
        return unlock_result(&params->result, E_INVALIDARG);
    }
    if (!(stream->local_buffer = vsnd_alloc((SIZE_T)stream->bufsize_frames * stream->block_align)))
    {
        vsnd_free(stream);
        goto oom;
    }
    if (kind == KIND_U8)
        memset(stream->local_buffer, 0x80, (SIZE_T)stream->bufsize_frames * stream->block_align);
    stream->vols[0] = stream->vols[1] = 1.0f;

    stream->next = streams;
    streams = stream;
    if (params->flow == eRender)
    {
        dev_streams++;
        feeder_start();
    }
    else
    {
        cap_streams++;
        capture_start();
    }

    *params->channel_count = params->fmt->nChannels;
    *params->stream = (stream_handle)(UINT_PTR)stream;
    return unlock_result(&params->result, S_OK);

oom:
    if (params->flow == eRender && !dev_streams) dev_release();
    if (params->flow == eCapture && !cap_streams) cap_release();
    return unlock_result(&params->result, E_OUTOFMEMORY);
}

NTSTATUS vsnd_release_stream(void *args)
{
    struct release_stream_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    struct vsnd_stream **link;

    vsnd_take_lock();
    for (link = &streams; *link; link = &(*link)->next)
        if (*link == stream) break;
    if (*link) *link = stream->next;
    if (stream->flow == eRender)
    {
        dev_streams--;
        if (!dev_streams)
        {
            feeder_stop();
            /* Re-checked after the join dropped the lock: a concurrent
             * create_stream may hold the device again. */
            if (!dev_streams) dev_release();
        }
    }
    else
    {
        cap_streams--;
        if (!cap_streams)
        {
            capture_stop();
            if (!cap_streams) cap_release();
        }
    }
    vsnd_drop_lock();

    vsnd_free(stream->local_buffer);
    vsnd_free(stream->tmp_buffer);
    vsnd_free(stream);
    params->result = S_OK;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_start(void *args)
{
    struct start_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    if ((stream->flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) && !stream->event)
        return unlock_result(&params->result, AUDCLNT_E_EVENTHANDLE_NOT_SET);
    if (stream->started)
        return unlock_result(&params->result, AUDCLNT_E_NOT_STOPPED);
    if (stream->flow == eRender)
    {
        if (!dev_started)
        {
            if (dev_ioctl(dev_handle, IOCTL_PRSSND_START, NULL, 0, NULL, 0))
            {
                vsnd_report("winevsnd: START refused by the device\n");
                return unlock_result(&params->result, AUDCLNT_E_DEVICE_INVALIDATED);
            }
            dev_started = TRUE;
        }
    }
    else if (!cap_started && cap_prepared)
    {
        /* The mirror; when a capture_stop join has the device released
         * (cap_prepared FALSE), the mark below stands and capture_stop's
         * re-arm issues the device START. */
        if (dev_ioctl(cap_handle, IOCTL_PRSSND_START, NULL, 0, NULL, 0))
        {
            vsnd_report("winevsnd: capture START refused by the device\n");
            return unlock_result(&params->result, AUDCLNT_E_DEVICE_INVALIDATED);
        }
        cap_started = TRUE;
    }
    stream->started = TRUE;
    stream->ever_started = TRUE;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_stop(void *args)
{
    struct stop_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    if (!stream->started)
        return unlock_result(&params->result, S_FALSE);
    stream->started = FALSE;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_reset(void *args)
{
    struct reset_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    if (stream->started)
        return unlock_result(&params->result, AUDCLNT_E_NOT_STOPPED);
    if (stream->getbuf_last)
        return unlock_result(&params->result, AUDCLNT_E_BUFFER_OPERATION_PENDING);
    if (stream->flow == eRender)
    {
        stream->written_frames = 0;
        stream->last_pos = 0;
    }
    else
    {
        /* Reset drops the held frames but the capture clock counts them
         * as consumed (winealsa alsa_reset: written += held) — position
         * is monotonic through a Reset. */
        stream->written_frames += stream->held_frames;
    }
    stream->held_frames = 0;
    stream->lcl_offs = 0;
    stream->wri_offs = 0;
    stream->src_frac = 0.0;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_render_buffer(void *args)
{
    struct get_render_buffer_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT32 write_pos, frames = params->frames;

    vsnd_take_lock();
    if (stream->getbuf_last)
        return unlock_result(&params->result, AUDCLNT_E_OUT_OF_ORDER);
    if (!frames)
        return unlock_result(&params->result, S_OK);
    if (stream->held_frames + frames > stream->bufsize_frames)
        return unlock_result(&params->result, AUDCLNT_E_BUFFER_TOO_LARGE);

    write_pos = stream->wri_offs;
    if (write_pos + frames > stream->bufsize_frames)
    {
        if (stream->tmp_buffer_frames < frames)
        {
            vsnd_free(stream->tmp_buffer);
            stream->tmp_buffer = vsnd_alloc((SIZE_T)frames * stream->block_align);
            if (!stream->tmp_buffer)
            {
                stream->tmp_buffer_frames = 0;
                return unlock_result(&params->result, E_OUTOFMEMORY);
            }
            stream->tmp_buffer_frames = frames;
        }
        *params->data = stream->tmp_buffer;
        stream->getbuf_last = -(int)frames;
    }
    else
    {
        *params->data = stream->local_buffer + (SIZE_T)write_pos * stream->block_align;
        stream->getbuf_last = frames;
    }
    memset(*params->data, stream->kind == KIND_U8 ? 0x80 : 0,
           (SIZE_T)frames * stream->block_align);
    return unlock_result(&params->result, S_OK);
}

static void wrap_buffer(struct vsnd_stream *stream, const BYTE *buffer, UINT32 written_frames)
{
    UINT32 write_offs_bytes = stream->wri_offs * stream->block_align;
    UINT32 chunk_bytes = (stream->bufsize_frames - stream->wri_offs) * stream->block_align;
    UINT32 written_bytes = written_frames * stream->block_align;

    if (written_bytes <= chunk_bytes)
        memcpy(stream->local_buffer + write_offs_bytes, buffer, written_bytes);
    else
    {
        memcpy(stream->local_buffer + write_offs_bytes, buffer, chunk_bytes);
        memcpy(stream->local_buffer, buffer + chunk_bytes, written_bytes - chunk_bytes);
    }
}

NTSTATUS vsnd_release_render_buffer(void *args)
{
    struct release_render_buffer_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT32 written_frames = params->written_frames;
    BYTE *buffer;

    vsnd_take_lock();
    if (!written_frames)
    {
        stream->getbuf_last = 0;
        return unlock_result(&params->result, S_OK);
    }
    if (!stream->getbuf_last)
        return unlock_result(&params->result, AUDCLNT_E_OUT_OF_ORDER);
    if (written_frames > (UINT32)(stream->getbuf_last >= 0 ? stream->getbuf_last
                                                          : -stream->getbuf_last))
        return unlock_result(&params->result, AUDCLNT_E_INVALID_SIZE);

    if (stream->getbuf_last >= 0)
        buffer = stream->local_buffer + (SIZE_T)stream->wri_offs * stream->block_align;
    else
        buffer = stream->tmp_buffer;

    if (params->flags & AUDCLNT_BUFFERFLAGS_SILENT)
        memset(buffer, stream->kind == KIND_U8 ? 0x80 : 0,
               (SIZE_T)written_frames * stream->block_align);

    if (stream->getbuf_last < 0)
        wrap_buffer(stream, buffer, written_frames);

    stream->wri_offs = (stream->wri_offs + written_frames) % stream->bufsize_frames;
    stream->held_frames += written_frames;
    stream->written_frames += written_frames;
    stream->getbuf_last = 0;
    return unlock_result(&params->result, S_OK);
}

/* The get/release_capture_buffer protocol, winealsa's exactly — the shape
 * the capture pairs pin (mmdevapi/tests/capture.c): one mmdevapi period
 * per GetBuffer or BUFFER_EMPTY under that, identical answers on repeat
 * until the release, flags always 0 (discontinuity reporting is todo_wine
 * in the pair — a FIXME the oracle's own drivers share), devpos = frames
 * the client has consumed so far. */
NTSTATUS vsnd_get_capture_buffer(void *args)
{
    struct get_capture_buffer_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT32 frames;

    vsnd_take_lock();
    if (stream->getbuf_last)
        return unlock_result(&params->result, AUDCLNT_E_OUT_OF_ORDER);
    if (stream->held_frames < stream->period_frames)
    {
        *params->frames = 0;
        return unlock_result(&params->result, AUDCLNT_S_BUFFER_EMPTY);
    }
    frames = stream->period_frames;

    if (stream->lcl_offs + frames > stream->bufsize_frames)
    {
        UINT32 chunk_bytes = (stream->bufsize_frames - stream->lcl_offs) * stream->block_align;

        if (stream->tmp_buffer_frames < frames)
        {
            vsnd_free(stream->tmp_buffer);
            stream->tmp_buffer = vsnd_alloc((SIZE_T)frames * stream->block_align);
            if (!stream->tmp_buffer)
            {
                stream->tmp_buffer_frames = 0;
                return unlock_result(&params->result, E_OUTOFMEMORY);
            }
            stream->tmp_buffer_frames = frames;
        }
        memcpy(stream->tmp_buffer, stream->local_buffer + (SIZE_T)stream->lcl_offs * stream->block_align,
               chunk_bytes);
        memcpy(stream->tmp_buffer + chunk_bytes, stream->local_buffer,
               (SIZE_T)frames * stream->block_align - chunk_bytes);
        *params->data = stream->tmp_buffer;
    }
    else
        *params->data = stream->local_buffer + (SIZE_T)stream->lcl_offs * stream->block_align;

    stream->getbuf_last = frames;
    *params->frames = frames;
    *params->flags = 0;
    if (params->devpos)
        *params->devpos = stream->written_frames;
    if (params->qpcpos)
    {
        LARGE_INTEGER stamp, freq;

        NtQueryPerformanceCounter(&stamp, &freq);
        *params->qpcpos = stamp.QuadPart * (INT64)10000000 / freq.QuadPart;
    }
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_release_capture_buffer(void *args)
{
    struct release_capture_buffer_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT32 done = params->done;

    vsnd_take_lock();
    if (!done)
    {
        stream->getbuf_last = 0;
        return unlock_result(&params->result, S_OK);
    }
    if (!stream->getbuf_last)
        return unlock_result(&params->result, AUDCLNT_E_OUT_OF_ORDER);
    if ((UINT32)stream->getbuf_last != done)
        return unlock_result(&params->result, AUDCLNT_E_INVALID_SIZE);

    stream->written_frames += done;
    stream->held_frames -= done;
    stream->lcl_offs = (stream->lcl_offs + done) % stream->bufsize_frames;
    stream->getbuf_last = 0;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_next_packet_size(void *args)
{
    struct get_next_packet_size_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    *params->frames = stream->held_frames < stream->period_frames ? 0 : stream->period_frames;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_is_format_supported(void *args)
{
    struct is_format_supported_params *params = args;
    enum sample_kind kind;

    if (params->share == AUDCLNT_SHAREMODE_EXCLUSIVE)
    {
        /* docs/23 §5: no exclusive mode, the oracle's shape. */
        params->result = AUDCLNT_E_EXCLUSIVE_MODE_NOT_ALLOWED;
        return STATUS_SUCCESS;
    }
    params->result = parse_format(params->fmt_in, &kind);
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_get_mix_format(void *args)
{
    struct get_mix_format_params *params = args;
    WAVEFORMATEXTENSIBLE *fmt = params->fmt;

    /* The Windows-typical mix format (docs/23 §4b): float32 48 kHz stereo,
     * derived from the fixed device negotiation above; the feeder converts
     * to the device's S16. */
    fmt->Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    fmt->Format.nChannels = VSND_DEV_CHANNELS;
    fmt->Format.nSamplesPerSec = VSND_DEV_RATE;
    fmt->Format.wBitsPerSample = 32;
    fmt->Format.nBlockAlign = VSND_DEV_CHANNELS * 4;
    fmt->Format.nAvgBytesPerSec = VSND_DEV_RATE * VSND_DEV_CHANNELS * 4;
    fmt->Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    fmt->Samples.wValidBitsPerSample = 32;
    fmt->dwChannelMask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
    fmt->SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
    params->result = S_OK;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_get_device_period(void *args)
{
    struct get_device_period_params *params = args;

    if (params->def_period) *params->def_period = VSND_DEF_PERIOD;
    if (params->min_period) *params->min_period = VSND_MIN_PERIOD;
    params->result = S_OK;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_get_buffer_size(void *args)
{
    struct get_buffer_size_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    *params->frames = stream->bufsize_frames;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_latency(void *args)
{
    struct get_latency_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    /* The device ring (4 periods of schedule slack, docs/23 §7) plus one
     * mmdevapi period — the winealsa hidden-frames shape. */
    *params->latency = (REFERENCE_TIME)10000000 * (VSND_DEV_PERIODS + 1) *
                       VSND_DEV_PERIOD_FRAMES / VSND_DEV_RATE +
                       (REFERENCE_TIME)10000000 * stream->period_frames / stream->rate;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_current_padding(void *args)
{
    struct get_current_padding_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    *params->padding = stream->held_frames;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_frequency(void *args)
{
    struct get_frequency_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    if (stream->share == AUDCLNT_SHAREMODE_SHARED)
        *params->freq = (UINT64)stream->rate * stream->block_align;
    else
        *params->freq = stream->rate;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_get_position(void *args)
{
    struct get_position_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT64 position;

    if (params->device)
    {
        /* The oracle's own drivers refuse device position (winealsa
         * alsa_get_position); matching that shape is the contract. */
        vsnd_report("winevsnd: device-relative get_position refused (unbuilt)\n");
        params->result = E_NOTIMPL;
        return STATUS_SUCCESS;
    }

    vsnd_take_lock();
    /* Render: what the feeder has consumed from the ring. Capture: what
     * the client consumed plus what waits in the ring (winealsa's
     * written + held — deposits advance the clock whether or not the
     * client fetches them). Period-granularity: the legal staircase
     * (docs/23 §4b); monotonic by clamping, the winealsa shape. The
     * render clock advances through an underrun because the feeder
     * consumes silence at device pace either way. */
    if (stream->flow == eRender)
        position = stream->written_frames - stream->held_frames;
    else
        position = stream->written_frames + stream->held_frames;
    if (position < stream->last_pos)
        position = stream->last_pos;
    else
        stream->last_pos = position;

    if (stream->share == AUDCLNT_SHAREMODE_SHARED)
        *params->pos = position * stream->block_align;
    else
        *params->pos = position;

    if (params->qpctime)
    {
        LARGE_INTEGER stamp, freq;

        NtQueryPerformanceCounter(&stamp, &freq);
        *params->qpctime = stamp.QuadPart * (INT64)10000000 / freq.QuadPart;
    }
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_set_volumes(void *args)
{
    struct set_volumes_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);
    UINT32 i;

    vsnd_take_lock();
    for (i = 0; i < stream->channels && i < 2; i++)
        stream->vols[i] = params->volumes[i] * params->session_volumes[i] *
                          params->master_volume;
    vsnd_drop_lock();
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_set_event_handle(void *args)
{
    struct set_event_handle_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    if (!(stream->flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK))
        return unlock_result(&params->result, AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED);
    if (stream->event)
        return unlock_result(&params->result, HRESULT_FROM_WIN32(ERROR_INVALID_NAME));
    stream->event = params->event;
    return unlock_result(&params->result, S_OK);
}

NTSTATUS vsnd_test_connect(void *args)
{
    struct test_connect_params *params = args;

    vsnd_take_lock();
    probe_nodes();
    params->priority = dev_node >= 0 || cap_node >= 0 ? Priority_Preferred
                                                      : Priority_Unavailable;
    vsnd_drop_lock();
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_is_started(void *args)
{
    struct is_started_params *params = args;
    struct vsnd_stream *stream = handle_get_stream(params->stream);

    vsnd_take_lock();
    return unlock_result(&params->result, stream->started ? S_OK : S_FALSE);
}

NTSTATUS vsnd_get_prop_value(void *args)
{
    struct get_prop_value_params *params = args;

    /* No driver-specific properties exist for a virtio stream node; the
     * winealsa default shape for everything it does not serve. mmdevapi
     * itself stores the load-bearing keys (FriendlyName, DeviceFormat) in
     * the registry from the endpoint list and mix format above. */
    params->result = E_NOTIMPL;
    return STATUS_SUCCESS;
}
