/* tests/audio/wasapi_cap_smoke.c — the AUD-3 WASAPI capture client
 * (docs/02 "AUD-3 — capture"; docs/23 §6c).
 *
 * cap_smoke.c one layer up, and wasapi_smoke.c pointed the other way: an
 * event-driven shared-mode capture stream through the whole PE audio stack
 * — CoCreateInstance(MMDeviceEnumerator) → IAudioClient(eCapture) →
 * IAudioCaptureClient over mmdevapi + winevsnd.drv + the capture node.
 * Green here is the end-to-end proof that the seam enumerates the capture
 * endpoint, the capture thread's blocking NtReadFile paces the deposits,
 * and the get/release_capture_buffer protocol delivers.
 *
 * Runs on the `none`-audiodev boot (the one backend with an input side —
 * see cap_smoke.c's header for why wav cannot carry capture). What is
 * honestly assertable: packets FLOW (the event fires and packets of
 * exactly one period arrive), their content is SILENCE (the none backend's
 * only product), and the packet count on the verdict line is a NUMBER
 * (docs/19 §8.4's rule). Nothing asserts how fast (docs/19 §11c) — the
 * waits are generously bounded, never timed.
 *
 * Freestanding PE (no CRT): ntdll + ole32 imports only. User clients
 * follow the test-code conventions (Wine style, docs/15 exemption).
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

#define CAP_TARGET_PACKETS 16 /* packets read before the verdict (~160 ms) */

NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);
/* mingw's winternl.h subset omits NtCreateEvent and EVENT_TYPE; prototype
 * per the pinned wine/include/winternl.h, EVENT_TYPE values per the
 * pinned wine/include/ntdef.h (SynchronizationEvent = 1). */
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, int, BOOLEAN);
#define CAP_SYNCHRONIZATION_EVENT 1
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, LARGE_INTEGER *);

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

    out = append_text(out, "[KTEST] audio capture FAIL (");
    out = append_text(out, what);
    out = append_text(out, ", ");
    out = append_number(out, code, 16, 8);
    out = append_text(out, ")\r\n");
    *out = '\0';
    say(line);
}

static void park_forever(void)
{
    /* Never exit (the aud_smoke rule): the host owns QEMU's lifetime. */
    for (;;)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; /* 1 s, relative */
        NtDelayExecution(FALSE, &interval);
    }
}

/* --- the capture path -------------------------------------------------------- */

void wasapi_cap_start(void *peb)
{
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDevice *device = NULL;
    IAudioClient *client = NULL;
    IAudioCaptureClient *capture = NULL;
    WAVEFORMATEX fmt;
    HANDLE event = NULL;
    UINT32 buffer_frames = 0, packets = 0;
    UINT64 silent_frames = 0;
    HRESULT hr;
    NTSTATUS status;

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
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eCapture, eMultimedia, &device);
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

    /* S16 48 kHz stereo — the device format, so the deposit path's encode
     * is the identity and "silence in, zeros out" is exact. */
    fmt.wFormatTag = WAVE_FORMAT_PCM;
    fmt.nChannels = 2;
    fmt.nSamplesPerSec = 48000;
    fmt.wBitsPerSample = 16;
    fmt.nBlockAlign = 4;
    fmt.nAvgBytesPerSec = 48000 * 4;
    fmt.cbSize = 0;
    hr =
        IAudioClient_Initialize(client, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                                10000000 /* 1 s */, 0, &fmt, NULL);
    if (hr != S_OK)
    {
        fail("initialize", (ULONG)hr);
        park_forever();
    }
    hr = IAudioClient_GetBufferSize(client, &buffer_frames);
    if (hr != S_OK || !buffer_frames)
    {
        fail("buffer_size", hr != S_OK ? (ULONG)hr : buffer_frames);
        park_forever();
    }
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, CAP_SYNCHRONIZATION_EVENT, FALSE);
    if (status)
    {
        fail("event", (ULONG)status);
        park_forever();
    }
    hr = IAudioClient_SetEventHandle(client, event);
    if (hr != S_OK)
    {
        fail("set_event", (ULONG)hr);
        park_forever();
    }
    hr = IAudioClient_GetService(client, &IID_IAudioCaptureClient, (void **)&capture);
    if (hr != S_OK)
    {
        fail("capture_client", (ULONG)hr);
        park_forever();
    }

    hr = IAudioClient_Start(client);
    if (hr != S_OK)
    {
        fail("start", (ULONG)hr);
        park_forever();
    }

    /* Event-paced: wait, drain every ready packet, repeat. Bounded by wait
     * COUNT (generosity, not a latency assertion — docs/19 §11c). */
    {
        int waits;

        for (waits = 0; waits < 3000 && packets < CAP_TARGET_PACKETS; waits++)
        {
            LARGE_INTEGER timeout;

            timeout.QuadPart = -1000000LL; /* 100 ms, relative */
            NtWaitForSingleObject(event, FALSE, &timeout);

            for (;;)
            {
                UINT32 next = 0, frames = 0, i;
                DWORD flags = 0;
                UINT64 devpos = 0, qpcpos = 0;
                BYTE *data = NULL;

                hr = IAudioCaptureClient_GetNextPacketSize(capture, &next);
                if (hr != S_OK)
                {
                    fail("next_packet", (ULONG)hr);
                    park_forever();
                }
                if (!next)
                    break;
                hr = IAudioCaptureClient_GetBuffer(capture, &data, &frames, &flags, &devpos,
                                                   &qpcpos);
                if (hr != S_OK)
                {
                    fail("get_buffer", (ULONG)hr);
                    park_forever();
                }
                if (frames != next)
                {
                    fail("packet_size", frames);
                    park_forever();
                }
                /* The none backend's product is silence; anything else is
                 * a deposit-path defect (docs/23 §7's honest content). */
                for (i = 0; i < frames * 4; i++)
                {
                    if (data[i] != 0)
                    {
                        fail("not_silence", i);
                        park_forever();
                    }
                }
                silent_frames += frames;
                hr = IAudioCaptureClient_ReleaseBuffer(capture, frames);
                if (hr != S_OK)
                {
                    fail("release_buffer", (ULONG)hr);
                    park_forever();
                }
                packets++;
            }
        }
        if (packets < CAP_TARGET_PACKETS)
        {
            fail("packets", packets);
            park_forever();
        }
    }

    /* The clock moved with the packets: position (bytes, shared mode) must
     * cover what was released — accounting, not timing. */
    {
        UINT64 pos = 0, qpc = 0;
        IAudioClock *clock = NULL;

        if (IAudioClient_GetService(client, &IID_IAudioClock, (void **)&clock) == S_OK)
        {
            IAudioClock_GetPosition(clock, &pos, &qpc);
            IAudioClock_Release(clock);
        }
        if (pos < silent_frames * 4)
        {
            fail("position", (ULONG)pos);
            park_forever();
        }
    }

    IAudioClient_Stop(client);

    {
        char line[160];
        char *out = line;
        out = append_text(out, "[KTEST] audio capture PASS packets=");
        out = append_number(out, packets, 10, 0);
        out = append_text(out, " frames=");
        out = append_number(out, silent_frames, 10, 0);
        out = append_text(out, "\r\n");
        *out = '\0';
        say(line);
    }
    park_forever();
}
