/* tests/audio/aud_smoke.c — the AUD-1 acceptance client (docs/02, docs/23
 * §6a).
 *
 * "Done when: tests/run/run.sh audio is green — a guest client plays a
 * deterministic S16 pattern and the harness finds it sample-exact in the
 * WAV that QEMU's -audiodev wav recorded."
 *
 * The shape is gui_smoke.c's, transposed: open \Device\Snd0, check the
 * device's own claims, negotiate S16 stereo 48 kHz, and play a seeded
 * pseudo-random S16 sequence through blocking period writes. The verdict
 * line carries every generation parameter (seed, period count, geometry) so
 * the host checker (tests/audio/check_audio.py) regenerates the reference
 * from the guest's own report and never hardcodes a QEMU constant — the
 * check_rect.py rule.
 *
 * No oracle leg exists and cannot: \Device\Snd0 is HACK-007 (docs/10), a
 * device NT does not have. What stands in for the oracle is QEMU: the WAV
 * is written by its audio backend from what its device model consumed,
 * neither of which the kernel controls (Art. 6).
 *
 * A freestanding PE against ntdll only -- no CRT, no Win32. User clients
 * follow the test-code conventions (Wine style, docs/15 exemption).
 */
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "drivers/sndproto.h"

/* The negotiated geometry. S16 end-to-end because the wav backend refuses
 * float and 32-bit formats (audio/wavaudio.c; docs/23 §6a). The whole
 * pattern fits the device buffer and is queued IN FULL before START: a
 * pattern streamed while playing depends on the guest resubmitting within
 * the ring's slack, and a TCG guest missing that once makes the device
 * insert silence MID-SPAN — the recording then contains every sample but
 * never contiguously, which is a host-scheduling artifact, precisely the
 * docs/19 §11c class the verdict must not depend on (measured: the
 * streamed form of this client flaked at 32/64 KiB). Pre-queued, the
 * device drains one full ring contiguously and the span's integrity
 * depends only on the device model. The ring-full PARK is not exercised
 * here and does not need to be: tests/kmt/snd.c holds it deterministically. */
#define AUD_BUFFER_BYTES 32768 /* sndproto.h SND_MAX_PERIODS slots of one frame each */
#define AUD_PERIOD_BYTES 4096
#define AUD_PERIODS      8
#define AUD_SEED         0x41554431u /* 'AUD1'; printed, never assumed by the host */

/* Silence appended AFTER the pattern (streamed once START frees slots; a
 * trailer underrun would insert exactly what the trailer is, so streaming
 * is safe here). The wav backend loses its unflushed tail when the guest
 * is ended — measured at a few hundred bytes — and without a trailer that
 * tail is the PATTERN's last samples: the recording then contains every
 * sample but not the last few, which reads as a truncated span. With the
 * trailer, whatever the teardown drops is silence. */
#define AUD_TRAILER_PERIODS 2

NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);

/* --- serial output (no CRT; gui_smoke.c's say()) ---------------------------- */

static void say(const char *ascii)
{
    WCHAR wide[160];
    USHORT n = 0;
    UNICODE_STRING string;

    while (ascii[n] != '\0' && n < 159)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

static char *append_text(char *out, const char *text)
{
    while (*text)
        *out++ = *text++;
    return out;
}

static char *append_number(char *out, ULONGLONG value, unsigned int base, unsigned int pad)
{
    char digits[24];
    unsigned int n = 0;

    do
    {
        unsigned int digit = (unsigned int)(value % base);
        digits[n++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value /= base;
    } while (value != 0);

    while (n < pad)
        digits[n++] = '0';
    while (n--)
        *out++ = digits[n];
    return out;
}

static void fail(const char *what, NTSTATUS status)
{
    char line[160];
    char *out = line;

    out = append_text(out, "[KTEST] audio FAIL (");
    out = append_text(out, what);
    out = append_text(out, ", ");
    out = append_number(out, (ULONGLONG)(ULONG)status, 16, 8);
    out = append_text(out, ")\r\n");
    *out = '\0';
    say(line);
}

static void park_forever(void)
{
    /* Never exit (the gui_smoke rule): the host owns QEMU's lifetime and
     * ends the guest over QMP once the verdict and the WAV are in; a
     * process teardown here would race the recording's tail. */
    for (;;)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; /* 1 s, relative */
        NtDelayExecution(FALSE, &interval);
    }
}

/* --- the deterministic pattern --------------------------------------------- */

/* One shared LCG definition with check_audio.py: state' = state * 6364136223846793005
 * + 1442695040558665139 (mod 2^64), sample = (int16)(state' >> 48). The
 * constants are Knuth's MMIX line; what matters is only that both sides
 * compute the identical sequence from the printed seed. */
static ULONGLONG aud_state;

static SHORT aud_next_sample(void)
{
    aud_state = aud_state * 6364136223846793005ULL + 1442695040558665139ULL;
    return (SHORT)(aud_state >> 48);
}

/* --- the play path ---------------------------------------------------------- */

void aud_start(void *peb)
{
    (void)peb;

    HANDLE snd = NULL;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;

    {
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attributes;
        RtlInitUnicodeString(&name, L"\\Device\\Snd0");
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = NtCreateFile(&snd, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
                              &attributes, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0 /* exclusive */,
                              FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    }
    if (!NT_SUCCESS(status))
    {
        fail("open", status);
        park_forever();
    }

    /* The device's own claims, checked before anything is negotiated: the
     * verdict path needs an S16-capable 48 kHz render stream, and a device
     * that lacks one must say so here rather than fail mid-play. */
    SND_PCM_INFO info;
    status = NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_INFO, NULL, 0, &info,
                                   sizeof(info));
    if (!NT_SUCCESS(status))
    {
        fail("info", status);
        park_forever();
    }
    if (info.direction != SND_D_OUTPUT || !((info.formats >> SND_PCM_FMT_S16) & 1) ||
        !((info.rates >> SND_PCM_RATE_48000) & 1) || info.channelsMin > 2 || info.channelsMax < 2)
    {
        fail("caps", STATUS_NOT_SUPPORTED);
        park_forever();
    }

    SND_PCM_SET_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.bufferBytes = AUD_BUFFER_BYTES;
    params.periodBytes = AUD_PERIOD_BYTES;
    params.channels = 2;
    params.format = SND_PCM_FMT_S16;
    params.rate = SND_PCM_RATE_48000;
    status = NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_SET_PARAMS, &params,
                                   sizeof(params), NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("set_params", status);
        park_forever();
    }
    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_PREPARE, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("prepare", status);
        park_forever();
    }

    /* The generation parameters, printed BEFORE playing so the host can
     * regenerate the reference even from a run that dies mid-play. */
    {
        char line[160];
        char *out = line;
        out = append_text(out, "[KTEST] audio playing seed=");
        out = append_number(out, AUD_SEED, 16, 8);
        out = append_text(out, " periods=");
        out = append_number(out, AUD_PERIODS, 10, 0);
        out = append_text(out, " period_bytes=");
        out = append_number(out, AUD_PERIOD_BYTES, 10, 0);
        out = append_text(out, " rate=48000 ch=2 fmt=s16\r\n");
        *out = '\0';
        say(line);
    }

    /* Queue the WHOLE pattern before START (see the geometry comment): the
     * device consumes nothing yet, so all AUD_PERIODS writes seat in the
     * ring without parking and the later drain is one contiguous span. */
    aud_state = AUD_SEED;
    static SHORT period[AUD_PERIOD_BYTES / sizeof(SHORT)];
    for (unsigned p = 0; p < AUD_PERIODS; p++)
    {
        for (unsigned s = 0; s < AUD_PERIOD_BYTES / sizeof(SHORT); s++)
            period[s] = aud_next_sample();
        status = NtWriteFile(snd, NULL, NULL, NULL, &iosb, period, AUD_PERIOD_BYTES, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            fail("write", status);
            park_forever();
        }
    }

    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_START, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("start", status);
        park_forever();
    }

    /* The silence trailer (see AUD_TRAILER_PERIODS): these writes PARK
     * until the draining pattern frees a slot — the blocking contract in
     * ordinary use, incidentally exercised from ring 3 here. */
    for (unsigned s = 0; s < AUD_PERIOD_BYTES / sizeof(SHORT); s++)
        period[s] = 0;
    for (unsigned p = 0; p < AUD_TRAILER_PERIODS; p++)
    {
        status = NtWriteFile(snd, NULL, NULL, NULL, &iosb, period, AUD_PERIOD_BYTES, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            fail("trailer", status);
            park_forever();
        }
    }

    /* Wait for the device to consume everything queued: POSITION counts tx
     * completions, so this is the guest-side proof the samples reached the
     * device model. Polled, generously bounded, never timed (the wav
     * backend consumes on host timers — docs/19 §11c). */
    {
        int consumed = 0;
        for (int naps = 0; naps < 3000; naps++)
        {
            SND_POSITION position;
            status = NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_POSITION,
                                           NULL, 0, &position, sizeof(position));
            if (!NT_SUCCESS(status))
            {
                fail("position", status);
                park_forever();
            }
            if (position.bytesConsumed >=
                (ULONGLONG)(AUD_PERIODS + AUD_TRAILER_PERIODS) * AUD_PERIOD_BYTES)
            {
                consumed = 1;
                break;
            }
            LARGE_INTEGER interval;
            interval.QuadPart = -100000LL; /* 10 ms, relative */
            NtDelayExecution(FALSE, &interval);
        }
        if (!consumed)
        {
            fail("consume", STATUS_TIMEOUT);
            park_forever();
        }
    }

    /* Half a second of settle before the verdict: POSITION counts device
     * completions, and the wav file trails them by the backend's buffering.
     * The PASS line is what makes the host end the guest, so it must not
     * outrun the recording. Generosity, not an assertion (docs/19 §11c). */
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -5000000LL; /* 500 ms, relative */
        NtDelayExecution(FALSE, &interval);
    }

    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_STOP, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("stop", status);
        park_forever();
    }

    say("[KTEST] audio PASS\r\n");
    park_forever();
}
