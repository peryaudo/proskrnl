/* tests/kmt/snd.c — the \Device\Snd* device-contract smoke (AUD-1 render,
 * AUD-3 capture; HACK-007; docs/23 §6e).
 *
 * The device contract (drivers/sndproto.h) is NT-absent, so no differential
 * oracle exists for it — like Fb0, its verdicts are kmt tests (control-verb
 * round trips, a written period completing, the park actually parking) plus
 * the run.sh audio leg's WAV artifact. Runs only when a virtio-snd device
 * exists (the audio leg's image); silently absent everywhere else — the
 * FATINTEROP precedent, so `make test` and kmtcheck.sh stay untouched and
 * the audio leg greps the [KTEST] SND verdict itself.
 *
 * Every parameter asserted is the DEVICE'S claim (direction, format/rate
 * bits), never a QEMU constant like the stream count — the HACK-002 rule.
 * No test asserts completion latency: the wav backend consumes on host
 * timers (docs/19 §11c), so completion waits are generously bounded and
 * position is polled, never timed.
 *
 * The pattern this suite plays (a constant 0x11 fill) is deliberately
 * DIFFERENT from tests/audio/aud_smoke.c's reference sequence: both land in
 * the same recorded WAV on the audio leg, and the harness must be able to
 * find the client's span without tripping over this one.
 */
#include "tests/kmt/kmt.h"
#include "kernel/ke/ke.h"
#include "kernel/io/io.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "drivers/sndproto.h"
#include "drivers/virtio/snd.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

/* The QEMU-default geometry the tests negotiate (buffer 8192 / period 2048,
 * S16 stereo 48 kHz). SET_PARAMS forwards it and the device's own status
 * decides — a refusal fails the suite loudly rather than skipping. */
#define SND_TEST_BUFFER_BYTES 8192u
#define SND_TEST_PERIOD_BYTES 2048u
#define SND_TEST_PERIODS      (SND_TEST_BUFFER_BYTES / SND_TEST_PERIOD_BYTES)

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    attr->Length = sizeof(*attr);
    attr->RootDirectory = 0;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static NTSTATUS snd_open(const WCHAR *path, ACCESS_MASK access, ULONG share, HANDLE *handleOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_attr(&attr, &name, path);
    return NtCreateFile(handleOut, access, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL, share, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
}

static NTSTATUS snd_ioctl(HANDLE handle, ULONG code, const void *input, ULONG inputLength,
                          void *output, ULONG outputLength)
{
    IO_STATUS_BLOCK iosb;
    return NtDeviceIoControlFile(handle, 0, 0, 0, &iosb, code, (void *)(uintptr_t)input,
                                 inputLength, output, outputLength);
}

static NTSTATUS snd_write(HANDLE handle, const void *buffer, ULONG length)
{
    IO_STATUS_BLOCK iosb;
    return NtWriteFile(handle, 0, 0, 0, &iosb, (void *)(uintptr_t)buffer, length, 0, 0);
}

static NTSTATUS snd_set_default_params(HANDLE handle)
{
    SND_PCM_SET_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.bufferBytes = SND_TEST_BUFFER_BYTES;
    params.periodBytes = SND_TEST_PERIOD_BYTES;
    params.channels = 2;
    params.format = SND_PCM_FMT_S16;
    params.rate = SND_PCM_RATE_48000;
    return snd_ioctl(handle, IOCTL_PRSSND_SET_PARAMS, &params, sizeof(params), 0, 0);
}

static uint64_t snd_position(HANDLE handle)
{
    SND_POSITION position = {0};
    NTSTATUS status = snd_ioctl(handle, IOCTL_PRSSND_POSITION, 0, 0, &position, sizeof(position));
    ok(status == STATUS_SUCCESS, "position %#x", (unsigned)status);
    return position.bytesConsumed;
}

/* Poll POSITION until it reaches `target` bytes. Generously bounded (10 s
 * of 1 ms naps): the wav backend consumes on host timers, so nothing here
 * asserts HOW FAST — only that consumption happens (docs/19 §11c). */
static int snd_await_position(HANDLE handle, uint64_t target)
{
    for (int naps = 0; naps < 10000; naps++)
    {
        if (snd_position(handle) >= target)
        {
            return 1;
        }
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    return 0;
}

/* --- the device's own claims ----------------------------------------------- */

static void test_snd_probe(void)
{
    ok(VioSndStreamCount() >= 1, "at least one PCM stream (%lu)",
       (unsigned long)VioSndStreamCount());

    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open Snd0 %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    SND_PCM_INFO info;
    memset(&info, 0, sizeof(info));
    status = snd_ioctl(handle, IOCTL_PRSSND_INFO, 0, 0, &info, sizeof(info));
    ok(status == STATUS_SUCCESS, "INFO %#x", (unsigned)status);
    /* The claims the AUD-1 verdict path depends on: stream 0 renders and
     * speaks S16 at 44.1/48 kHz. Each is the device's own PCM_INFO answer;
     * nothing asserts the stream COUNT or the full format set. */
    ok(info.direction == SND_D_OUTPUT, "stream 0 direction %u", info.direction);
    ok((info.formats >> SND_PCM_FMT_S16) & 1, "S16 supported (formats %#llx)",
       (unsigned long long)info.formats);
    ok((info.rates >> SND_PCM_RATE_44100) & 1, "44.1 kHz supported (rates %#llx)",
       (unsigned long long)info.rates);
    ok((info.rates >> SND_PCM_RATE_48000) & 1, "48 kHz supported (rates %#llx)",
       (unsigned long long)info.rates);
    ok(info.channelsMin <= 2 && info.channelsMax >= 2, "stereo within [%u, %u]", info.channelsMin,
       info.channelsMax);
    NtClose(handle);
}

/* --- refusals (before any SET_PARAMS, while the stream is pristine) -------- */

static void test_snd_refusals(void)
{
    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open Snd0 %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    /* Exclusive open (sndproto.h): the share engine, not a private flag. */
    HANDLE second = 0;
    status = snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &second);
    ok(status == STATUS_SHARING_VIOLATION, "second open -> %#x", (unsigned)status);
    if (NT_SUCCESS(status))
        NtClose(second);

    /* A write before any SET_PARAMS has no period to size against. */
    static char period[SND_TEST_PERIOD_BYTES];
    status = snd_write(handle, period, sizeof(period));
    ok(status == STATUS_INVALID_DEVICE_STATE, "write before SET_PARAMS -> %#x", (unsigned)status);

    /* No Read op on a render stream (wrong direction): the Io layer's own
     * refusal, never a fabricated zero-length success (Art. 12). */
    IO_STATUS_BLOCK iosb;
    status = NtReadFile(handle, 0, 0, 0, &iosb, period, sizeof(period), 0, 0);
    ok(status == STATUS_INVALID_DEVICE_REQUEST, "read on render stream -> %#x", (unsigned)status);

    /* SET_PARAMS past the kernel transport's stated bounds (sndproto.h):
     * refused before the device sees it. */
    SND_PCM_SET_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.bufferBytes = 65536;
    params.periodBytes = 8192; /* > one DMA frame */
    params.channels = 2;
    params.format = SND_PCM_FMT_S16;
    params.rate = SND_PCM_RATE_48000;
    status = snd_ioctl(handle, IOCTL_PRSSND_SET_PARAMS, &params, sizeof(params), 0, 0);
    ok(status == STATUS_INVALID_PARAMETER, "oversized period -> %#x", (unsigned)status);

    NtClose(handle);

    /* The capture stream (Snd1 under QEMU's default two-stream shape) has
     * no Write op: wrong direction, refused by the Io layer. Gated on the
     * DEVICE's claim, not on QEMU's default count. */
    if (VioSndStreamCount() >= 2 && VioSndStreamInfo(1)->direction == SND_D_INPUT)
    {
        HANDLE capture = 0;
        status =
            snd_open(WSTR("\\Device\\Snd1"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &capture);
        ok(status == STATUS_SUCCESS, "open Snd1 %#x", (unsigned)status);
        if (status == STATUS_SUCCESS)
        {
            status = snd_write(capture, period, sizeof(period));
            ok(status == STATUS_INVALID_DEVICE_REQUEST, "write on capture stream -> %#x",
               (unsigned)status);
            NtClose(capture);
        }
    }
}

/* --- control-verb round trips ---------------------------------------------- */

static void test_snd_verb_roundtrip(void)
{
    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open Snd0 %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    /* An unsupported format is the DEVICE's refusal, relayed: the pinned
     * model's supported_formats excludes IMA_ADPCM (format 0), so the
     * answer is S_NOT_SUPP -> STATUS_INVALID_DEVICE_REQUEST. */
    SND_PCM_SET_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.bufferBytes = SND_TEST_BUFFER_BYTES;
    params.periodBytes = SND_TEST_PERIOD_BYTES;
    params.channels = 2;
    params.format = 0; /* VIRTIO_SND_PCM_FMT_IMA_ADPCM: not in the model's set */
    params.rate = SND_PCM_RATE_48000;
    status = snd_ioctl(handle, IOCTL_PRSSND_SET_PARAMS, &params, sizeof(params), 0, 0);
    ok(status == STATUS_INVALID_DEVICE_REQUEST, "unsupported format -> %#x", (unsigned)status);

    status = snd_set_default_params(handle);
    ok(status == STATUS_SUCCESS, "SET_PARAMS %#x", (unsigned)status);
    status = snd_ioctl(handle, IOCTL_PRSSND_PREPARE, 0, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "PREPARE %#x", (unsigned)status);

    /* 0 before START is the device's fact, not a fabricated answer
     * (sndproto.h). */
    ok(snd_position(handle) == 0, "position before START");

    status = snd_ioctl(handle, IOCTL_PRSSND_START, 0, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "START %#x", (unsigned)status);
    status = snd_ioctl(handle, IOCTL_PRSSND_STOP, 0, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "STOP %#x", (unsigned)status);
    status = snd_ioctl(handle, IOCTL_PRSSND_RELEASE, 0, 0, 0, 0);
    ok(status == STATUS_SUCCESS, "RELEASE %#x", (unsigned)status);
    NtClose(handle);
}

/* --- a written period completes -------------------------------------------- */

static void test_snd_period_completes(void)
{
    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open Snd0 %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    ok(snd_set_default_params(handle) == STATUS_SUCCESS, "SET_PARAMS");
    ok(snd_ioctl(handle, IOCTL_PRSSND_PREPARE, 0, 0, 0, 0) == STATUS_SUCCESS, "PREPARE");
    ok(snd_ioctl(handle, IOCTL_PRSSND_START, 0, 0, 0, 0) == STATUS_SUCCESS, "START");

    /* One period, whole-period-or-refused: a short write first. */
    static char period[SND_TEST_PERIOD_BYTES];
    memset(period, 0x11, sizeof(period));
    status = snd_write(handle, period, SND_TEST_PERIOD_BYTES / 2);
    ok(status == STATUS_INVALID_PARAMETER, "half-period write -> %#x", (unsigned)status);

    status = snd_write(handle, period, sizeof(period));
    ok(status == STATUS_SUCCESS, "period write %#x", (unsigned)status);

    /* The device consumes it and the harvest counts it — the tick-tail
     * drain path, no manual pump. */
    ok(snd_await_position(handle, SND_TEST_PERIOD_BYTES), "period consumed (position %llu)",
       (unsigned long long)snd_position(handle));

    ok(snd_ioctl(handle, IOCTL_PRSSND_STOP, 0, 0, 0, 0) == STATUS_SUCCESS, "STOP");
    ok(snd_ioctl(handle, IOCTL_PRSSND_RELEASE, 0, 0, 0, 0) == STATUS_SUCCESS, "RELEASE");
    NtClose(handle);
}

/* --- the park actually parks (G14's blocking point) ------------------------ */

static volatile NTSTATUS snd_park_status;
static HANDLE snd_park_handle;

static void snd_park_writer(void *context)
{
    (void)context;
    static char period[SND_TEST_PERIOD_BYTES];
    memset(period, 0x11, sizeof(period));
    snd_park_status = snd_write(snd_park_handle, period, sizeof(period));
}

static void test_snd_park_parks(void)
{
    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(WSTR("\\Device\\Snd0"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open Snd0 %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    ok(snd_set_default_params(handle) == STATUS_SUCCESS, "SET_PARAMS");
    ok(snd_ioctl(handle, IOCTL_PRSSND_PREPARE, 0, 0, 0, 0) == STATUS_SUCCESS, "PREPARE");

    /* Deliberately NOT started: the device queues tx buffers but consumes
     * nothing before START (pinned model: consumption is the audio
     * backend's, armed at START), so "the ring is full and the writer is
     * parked" is a controlled state, not a race against host timers —
     * the cui8 determinism discipline without needing the hold. */
    static char period[SND_TEST_PERIOD_BYTES];
    memset(period, 0x11, sizeof(period));
    for (unsigned fill = 0; fill < SND_TEST_PERIODS; fill++)
    {
        status = snd_write(handle, period, sizeof(period));
        ok(status == STATUS_SUCCESS, "fill write %u %#x", fill, (unsigned)status);
    }
    ok(VioSndTxInFlightCount(0) == SND_TEST_PERIODS, "buffer full (%lu in flight)",
       (unsigned long)VioSndTxInFlightCount(0));

    /* The one-past-full write must park. */
    snd_park_status = STATUS_PENDING;
    snd_park_handle = handle;
    PKTHREAD writer = KiCreateThread(8, snd_park_writer, 0);
    ok(writer != 0, "writer thread");
    if (writer == 0)
    {
        NtClose(handle);
        return; /* the FAIL is recorded; don't turn it into a NULL deref */
    }

    /* The writer stays parked while nothing completes: this thread keeps
     * running (the machine property) and the write keeps not returning.
     * 50 ms of naps is observation time, not a latency assertion. */
    for (int naps = 0; naps < 50; naps++)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    ok(snd_park_status == STATUS_PENDING, "writer parked while the buffer is full (%#x)",
       (unsigned)snd_park_status);
    ok(VioSndTxInFlightCount(0) == SND_TEST_PERIODS, "still full while parked");

    /* START releases the flow: the device consumes, the tick-tail drain
     * harvests, the space wake un-parks the writer. */
    ok(snd_ioctl(handle, IOCTL_PRSSND_START, 0, 0, 0, 0) == STATUS_SUCCESS, "START");
    NTSTATUS join = KeWaitForSingleObject(writer, Executive, 0, FALSE, 0);
    ok(join == STATUS_SUCCESS, "join %#x", (unsigned)join);
    KiDeleteThread(writer);
    ok(snd_park_status == STATUS_SUCCESS, "parked write completed %#x", (unsigned)snd_park_status);

    /* Everything queued drains through. */
    ok(snd_await_position(handle, (uint64_t)(SND_TEST_PERIODS + 1) * SND_TEST_PERIOD_BYTES),
       "queued periods consumed (position %llu)", (unsigned long long)snd_position(handle));

    ok(snd_ioctl(handle, IOCTL_PRSSND_STOP, 0, 0, 0, 0) == STATUS_SUCCESS, "STOP");
    ok(snd_ioctl(handle, IOCTL_PRSSND_RELEASE, 0, 0, 0, 0) == STATUS_SUCCESS, "RELEASE");
    NtClose(handle);
}

/* --- capture (AUD-3) --------------------------------------------------------
 *
 * Every case below stays inside the both-backend-deterministic envelope:
 * before START the device holds every posted rx buffer (the voice is armed
 * only at START), and RELEASE flushes them all back — true under the wav
 * backend (which has NO input side: pinned tree audio/wavaudio.c has no
 * in-voice, so rx buffers ONLY return at the RELEASE flush) and under the
 * none backend alike. No case here waits for a STARTED capture period to
 * fill — on a wav boot that would hang forever; the started-capture verdict
 * is the run.sh audio capture leg's, on a none-backend boot (docs/23 §6a,
 * §7 as corrected by AUD-3). */

/* The capture stream, by the DEVICE's own direction claim — never "Snd1"
 * (the HACK-002 rule). */
static int snd_find_capture(uint32_t *idOut)
{
    for (uint32_t id = 0; id < VioSndStreamCount() && id < VIO_SND_MAX_STREAMS; id++)
    {
        if (VioSndStreamInfo(id)->direction == SND_D_INPUT)
        {
            *idOut = id;
            return 1;
        }
    }
    return 0;
}

static const WCHAR *snd_device_path(uint32_t id)
{
    static const WCHAR paths[VIO_SND_MAX_STREAMS][14] = {
        WSTR("\\Device\\Snd0"),
        WSTR("\\Device\\Snd1"),
        WSTR("\\Device\\Snd2"),
        WSTR("\\Device\\Snd3"),
    };
    return paths[id];
}

static NTSTATUS snd_read(HANDLE handle, void *buffer, ULONG length, ULONG *bytesOut)
{
    IO_STATUS_BLOCK iosb;
    iosb.Information = 0;
    NTSTATUS status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, length, 0, 0);
    if (bytesOut != 0)
    {
        *bytesOut = (ULONG)iosb.Information;
    }
    return status;
}

static void test_snd_capture_refusals(void)
{
    uint32_t id;
    if (!snd_find_capture(&id))
    {
        return; /* the device claims no capture stream; nothing to assert */
    }

    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(snd_device_path(id), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open capture %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    static char period[SND_TEST_PERIOD_BYTES];

    /* A read before any SET_PARAMS has no period to size against. */
    status = snd_read(handle, period, sizeof(period), 0);
    ok(status == STATUS_INVALID_DEVICE_STATE, "read before SET_PARAMS -> %#x", (unsigned)status);

    ok(snd_set_default_params(handle) == STATUS_SUCCESS, "SET_PARAMS");

    /* Whole-period-or-refused, the write rule mirrored. */
    status = snd_read(handle, period, SND_TEST_PERIOD_BYTES / 2, 0);
    ok(status == STATUS_INVALID_PARAMETER, "half-period read -> %#x", (unsigned)status);

    /* Sized but not prepared: nothing is posted, nothing will complete. */
    status = snd_read(handle, period, sizeof(period), 0);
    ok(status == STATUS_INVALID_DEVICE_STATE, "read before PREPARE -> %#x", (unsigned)status);

    NtClose(handle);
}

/* --- the reader's park parks, and RELEASE's flush unparks it ---------------- */

static volatile NTSTATUS snd_capture_status;
static volatile ULONG snd_capture_bytes;
static HANDLE snd_capture_handle;

static void snd_capture_reader(void *context)
{
    (void)context;
    static char period[SND_TEST_PERIOD_BYTES];
    ULONG bytes = 0;
    NTSTATUS status = snd_read(snd_capture_handle, period, sizeof(period), &bytes);
    snd_capture_bytes = bytes;
    snd_capture_status = status;
}

static void test_snd_capture_park_and_flush(void)
{
    uint32_t id;
    if (!snd_find_capture(&id))
    {
        return;
    }

    HANDLE handle = 0;
    NTSTATUS status =
        snd_open(snd_device_path(id), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, &handle);
    ok(status == STATUS_SUCCESS, "open capture %#x", (unsigned)status);
    if (status != STATUS_SUCCESS)
        return;

    ok(snd_set_default_params(handle) == STATUS_SUCCESS, "SET_PARAMS");
    ok(snd_ioctl(handle, IOCTL_PRSSND_PREPARE, 0, 0, 0, 0) == STATUS_SUCCESS, "PREPARE");

    /* PREPARE posted the whole buffer as rx chains. */
    ok(VioSndRxInFlightCount(id) == SND_TEST_PERIODS, "rx posted (%lu in flight)",
       (unsigned long)VioSndRxInFlightCount(id));

    /* Deliberately NOT started: the device holds every rx buffer until
     * START arms the voice (both backends), so "nothing has completed and
     * the reader is parked" is a controlled state, not a race against
     * host timers — the render park test's discipline mirrored. */
    snd_capture_status = STATUS_PENDING;
    snd_capture_bytes = 0xffffffff;
    snd_capture_handle = handle;
    PKTHREAD reader = KiCreateThread(8, snd_capture_reader, 0);
    ok(reader != 0, "reader thread");
    if (reader == 0)
    {
        NtClose(handle);
        return;
    }

    /* 50 ms of naps is observation time, not a latency assertion. */
    for (int naps = 0; naps < 50; naps++)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    ok(snd_capture_status == STATUS_PENDING, "reader parked while nothing completes (%#x)",
       (unsigned)snd_capture_status);
    ok(VioSndRxInFlightCount(id) == SND_TEST_PERIODS, "still all in flight while parked");

    /* RELEASE flushes every posted period back (§5.14.6.6.5.1); the
     * tick-tail drain harvests, the space wake un-parks the reader, and
     * the completion is honest: SUCCESS with the 0 bytes the device
     * captured — never fabricated silence. */
    ok(snd_ioctl(handle, IOCTL_PRSSND_RELEASE, 0, 0, 0, 0) == STATUS_SUCCESS, "RELEASE");
    NTSTATUS join = KeWaitForSingleObject(reader, Executive, 0, FALSE, 0);
    ok(join == STATUS_SUCCESS, "join %#x", (unsigned)join);
    KiDeleteThread(reader);
    ok(snd_capture_status == STATUS_SUCCESS, "parked read completed %#x",
       (unsigned)snd_capture_status);
    ok(snd_capture_bytes == 0, "flushed period is empty (%lu bytes)",
       (unsigned long)snd_capture_bytes);

    /* Position: nothing was captured, and the flush adds nothing. */
    ok(snd_position(handle) == 0, "position after flush (%llu)",
       (unsigned long long)snd_position(handle));

    /* The remaining flushed completions still deliver (the device's final
     * answers), then the released stream refuses — never a forever park
     * (sndproto.h). */
    static char period[SND_TEST_PERIOD_BYTES];
    for (unsigned drain = 0; drain < SND_TEST_PERIODS - 1; drain++)
    {
        ULONG bytes = 0xffffffff;
        status = snd_read(handle, period, sizeof(period), &bytes);
        ok(status == STATUS_SUCCESS && bytes == 0, "flush drain %u -> %#x, %lu bytes", drain,
           (unsigned)status, (unsigned long)bytes);
    }
    status = snd_read(handle, period, sizeof(period), 0);
    ok(status == STATUS_INVALID_DEVICE_STATE, "read after flush drained -> %#x", (unsigned)status);
    ok(VioSndRxInFlightCount(id) == 0, "nothing in flight after RELEASE (%lu)",
       (unsigned long)VioSndRxInFlightCount(id));

    NtClose(handle);
}

int kmt_run_snd(void)
{
    if (!VioSndIsPresent())
    {
        return 0; /* not an audio-leg run (the FATINTEROP precedent) */
    }
    int before = kmt_failures;
    DbgPrint("kmt: SND suite\n");
    KMT_RUN(test_snd_probe);
    KMT_RUN(test_snd_refusals);
    KMT_RUN(test_snd_verb_roundtrip);
    KMT_RUN(test_snd_period_completes);
    KMT_RUN(test_snd_park_parks);
    KMT_RUN(test_snd_capture_refusals);
    KMT_RUN(test_snd_capture_park_and_flush);
    int failures = kmt_failures - before;
    DbgPrint(failures == 0 ? "[KTEST] SND PASS\n" : "[KTEST] SND FAIL failures=%d\n", failures);
    return failures;
}
