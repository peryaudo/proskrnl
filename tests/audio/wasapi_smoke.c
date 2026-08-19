/* tests/audio/wasapi_smoke.c — the AUD-2 acceptance client (docs/02, docs/23
 * §6c).
 *
 * aud_smoke.c one layer up: the SAME deterministic S16 pattern (same LCG,
 * same printed generation parameters, so tests/audio/check_audio.py
 * regenerates the reference unchanged), but played through the whole PE
 * audio stack — CoCreateInstance(MMDeviceEnumerator) → IAudioClient →
 * IAudioRenderClient over mmdevapi + winevsnd.drv + \Device\Snd0 — instead
 * of driving the device ioctls directly. Green here is the first
 * end-to-end proof that the seam loads the driver, the driver negotiates
 * the device, and the feeder's mix/convert path is sample-exact (the
 * symmetric 1/32768 scaling makes S16 → float mix → S16 the identity).
 *
 * The verdict line carries the underrun COUNT read back from the driver's
 * winevsnd_diag_underruns export — a number, never an inference (docs/19
 * §8.4; docs/23 §7's measured-cost rule). The client keeps the WASAPI
 * buffer topped up with silence until the pattern has played, so on an
 * unloaded host the count is 0 and on a starved TCG runner it is the
 * measured glitch count — reported either way.
 *
 * Freestanding PE (no CRT): ntdll + ole32 imports only; COM does not need
 * a CRT in the caller. Verdicts go through NtDisplayString (say()) — this
 * client runs as a GUI_LEG foreground with no console. User clients follow
 * the test-code conventions (Wine style, docs/15 exemption).
 */
#define COBJMACROS
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include <initguid.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

/* The same generation parameters as aud_smoke.c, printed before playing so
 * the host regenerates the reference from the guest's own report. */
#define AUD_PERIOD_BYTES   4096
#define AUD_PERIODS        8
#define AUD_SEED           0x41554431u /* 'AUD1' */
#define AUD_FRAME_BYTES    4           /* S16 stereo */
#define AUD_PATTERN_FRAMES (AUD_PERIODS * AUD_PERIOD_BYTES / AUD_FRAME_BYTES)

NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);
/* mingw's winternl.h omits the Ldr family; prototypes per the pinned
 * wine/include/winternl.h. */
NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(PWSTR, ULONG, UNICODE_STRING *, void **);
NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(void *, ANSI_STRING *, ULONG, void **);
NTSYSAPI void NTAPI RtlInitAnsiString(ANSI_STRING *, const char *);

/* --- serial output (aud_smoke.c's say()) ----------------------------------- */

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

static void fail(const char *what, ULONG code)
{
    char line[160];
    char *out = line;

    out = append_text(out, "[KTEST] audio FAIL (");
    out = append_text(out, what);
    out = append_text(out, ", ");
    out = append_number(out, code, 16, 8);
    out = append_text(out, ")\r\n");
    *out = '\0';
    say(line);
}

static void park_forever(void)
{
    /* Never exit (the aud_smoke rule): the host owns QEMU's lifetime and a
     * teardown here would race the recording's tail. */
    for (;;)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; /* 1 s, relative */
        NtDelayExecution(FALSE, &interval);
    }
}

static void nap(LONGLONG hundred_ns)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -hundred_ns;
    NtDelayExecution(FALSE, &interval);
}

/* --- the deterministic pattern (one definition with check_audio.py) -------- */

static ULONGLONG aud_state;

static SHORT aud_next_sample(void)
{
    aud_state = aud_state * 6364136223846793005ULL + 1442695040558665139ULL;
    return (SHORT)(aud_state >> 48);
}

/* --- the play path ---------------------------------------------------------- */

void wasapi_start(void *peb)
{
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDevice *device = NULL;
    IAudioClient *client = NULL;
    IAudioRenderClient *render = NULL;
    WAVEFORMATEX fmt;
    UINT32 buffer_frames = 0, done_frames = 0;
    HRESULT hr;

    (void)peb;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr != S_OK)
    {
        fail("coinit", (ULONG)hr);
        park_forever();
    }
    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IMMDeviceEnumerator, (void **)&enumerator);
    if (hr != S_OK)
    {
        fail("enumerator", (ULONG)hr);
        park_forever();
    }
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eRender, eMultimedia, &device);
    if (hr != S_OK)
    {
        fail("endpoint", (ULONG)hr);
        park_forever();
    }
    hr =
        IMMDevice_Activate(device, &IID_IAudioClient, CLSCTX_INPROC_SERVER, NULL, (void **)&client);
    if (hr != S_OK)
    {
        fail("activate", (ULONG)hr);
        park_forever();
    }

    /* S16 48 kHz stereo — the AUD-1 verdict format, end to end: the feeder's
     * symmetric scaling makes this the bit-exact path (stream.c). */
    fmt.wFormatTag = WAVE_FORMAT_PCM;
    fmt.nChannels = 2;
    fmt.nSamplesPerSec = 48000;
    fmt.wBitsPerSample = 16;
    fmt.nBlockAlign = AUD_FRAME_BYTES;
    fmt.nAvgBytesPerSec = 48000 * AUD_FRAME_BYTES;
    fmt.cbSize = 0;
    hr = IAudioClient_Initialize(client, AUDCLNT_SHAREMODE_SHARED, 0, 10000000 /* 1 s */, 0, &fmt,
                                 NULL);
    if (hr != S_OK)
    {
        fail("initialize", (ULONG)hr);
        park_forever();
    }
    hr = IAudioClient_GetBufferSize(client, &buffer_frames);
    if (hr != S_OK || buffer_frames < AUD_PATTERN_FRAMES)
    {
        fail("buffer_size", hr != S_OK ? (ULONG)hr : buffer_frames);
        park_forever();
    }
    hr = IAudioClient_GetService(client, &IID_IAudioRenderClient, (void **)&render);
    if (hr != S_OK)
    {
        fail("render_client", (ULONG)hr);
        park_forever();
    }

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

    /* The whole pattern in one GetBuffer, before Start — the aud_smoke
     * pre-queue rule (docs/19 §11c): a streamed pattern depends on the
     * guest's scheduling and flakes under TCG; pre-queued, the span's
     * integrity depends only on the stack under test. */
    {
        BYTE *data = NULL;
        SHORT *samples;
        UINT32 s;

        hr = IAudioRenderClient_GetBuffer(render, AUD_PATTERN_FRAMES, &data);
        if (hr != S_OK)
        {
            fail("get_buffer", (ULONG)hr);
            park_forever();
        }
        samples = (SHORT *)data;
        aud_state = AUD_SEED;
        for (s = 0; s < AUD_PATTERN_FRAMES * 2; s++)
            samples[s] = aud_next_sample();
        hr = IAudioRenderClient_ReleaseBuffer(render, AUD_PATTERN_FRAMES, 0);
        if (hr != S_OK)
        {
            fail("release_buffer", (ULONG)hr);
            park_forever();
        }
    }

    hr = IAudioClient_Start(client);
    if (hr != S_OK)
    {
        fail("start", (ULONG)hr);
        park_forever();
    }

    /* Keep the buffer topped up with SILENCE until the pattern has played:
     * position advances period by period, and a ring that never runs dry
     * makes 0 the expected underrun count on an unloaded host — what the
     * counter then measures is the feeder missing ITS deadline, the docs/23
     * §7 number. Polled, generously bounded, never timed. */
    {
        int played = 0, naps;

        for (naps = 0; naps < 3000; naps++)
        {
            UINT32 padding = 0;

            hr = IAudioClient_GetCurrentPadding(client, &padding);
            if (hr != S_OK)
            {
                fail("padding", (ULONG)hr);
                park_forever();
            }
            done_frames = buffer_frames; /* anything above the refill bar */
            if (padding + done_frames / 4 < buffer_frames)
            {
                BYTE *data = NULL;
                UINT32 chunk = buffer_frames - padding;

                if (IAudioRenderClient_GetBuffer(render, chunk, &data) == S_OK)
                    IAudioRenderClient_ReleaseBuffer(render, chunk, AUDCLNT_BUFFERFLAGS_SILENT);
            }
            {
                UINT64 pos = 0, qpc = 0;
                IAudioClock *clock = NULL;

                if (IAudioClient_GetService(client, &IID_IAudioClock, (void **)&clock) == S_OK)
                {
                    IAudioClock_GetPosition(clock, &pos, &qpc);
                    IAudioClock_Release(clock);
                }
                /* Shared-mode position is in BYTES (freq = rate * block). */
                if (pos >= (UINT64)AUD_PATTERN_FRAMES * AUD_FRAME_BYTES)
                {
                    played = 1;
                    break;
                }
            }
            nap(100000); /* 10 ms */
        }
        if (!played)
        {
            fail("consume", STATUS_TIMEOUT);
            park_forever();
        }
    }

    /* Settle before the verdict (the aud_smoke rule): the WAV trails the
     * device by the backend's buffering. */
    nap(5000000); /* 500 ms */
    IAudioClient_Stop(client);

    /* The underrun count, read from the driver the seam loaded into THIS
     * process — the [KTEST] number the leg greps (docs/23 §6c). ntdll-only
     * resolution: this client links no kernel32. */
    {
        ULONGLONG underruns = ~0ull;
        UNICODE_STRING dll_name;
        ANSI_STRING func_name;
        void *module = NULL;
        ULONGLONG (*diag)(void) = NULL;

        RtlInitUnicodeString(&dll_name, L"winevsnd.drv");
        if (!LdrGetDllHandle(NULL, 0, &dll_name, &module))
        {
            RtlInitAnsiString(&func_name, "winevsnd_diag_underruns");
            if (!LdrGetProcedureAddress(module, &func_name, 0, (void **)&diag) && diag)
                underruns = diag();
        }
        if (underruns == ~0ull)
        {
            fail("diag", STATUS_ENTRYPOINT_NOT_FOUND);
            park_forever();
        }

        {
            char line[160];
            char *out = line;
            out = append_text(out, "[KTEST] audio PASS underruns=");
            out = append_number(out, underruns, 10, 0);
            /* The client's own bitness, so a leg can tell WHICH build of
             * this one source produced the verdict: the i386 build runs as
             * a WOW64 guest, loads syswow64's mmdevapi and winevsnd.drv,
             * and is the only thing that makes bits=32 appear here. An
             * inference from which .exe the image carries would not be a
             * measurement (docs/19 §8.4). */
            out = append_text(out, " bits=");
            out = append_number(out, sizeof(void *) * 8, 10, 0);
            out = append_text(out, "\r\n");
            *out = '\0';
            say(line);
        }
    }
    park_forever();
}
