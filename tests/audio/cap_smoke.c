/* tests/audio/cap_smoke.c — the AUD-3 device-contract capture client
 * (docs/02 "AUD-3 — capture"; docs/23 §6e).
 *
 * aud_smoke.c's shape pointed the other way: find the capture node by its
 * OWN direction claim (never "Snd1" — the HACK-002 rule), negotiate S16
 * stereo 48 kHz at the QEMU-default geometry, and blocking-read a fixed
 * number of periods. Runs on a boot whose audiodev is `none` — the one
 * backend with an input side, which supplies SILENCE at the correct
 * cadence (pinned tree audio/noaudio.c no_read: audio_rate_get_bytes +
 * audio_pcm_info_clear_buf). The wav backend has NO input voices
 * (audio/wavaudio.c: max_voices_in = 0), so on a wav boot rx buffers only
 * ever return at the RELEASE flush — which is why this client gets its own
 * boot and why no kmt case waits for a started capture period.
 *
 * What is honestly assertable (docs/23 §7): every read completes as a FULL
 * period of ZEROS (the none backend's silence — the only content QEMU can
 * supply; a content-asserting capture test with real input is the named
 * gap), and POSITION counts exactly what was read. Nothing asserts HOW
 * FAST anything completed (docs/19 §11c) — the blocking read IS the
 * cadence, however the host schedules it.
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

/* The QEMU-default geometry (buffer 8192 / period 2048): 4 periods in
 * flight, ~10.6 ms per period at S16 stereo 48 kHz. The device's own
 * status decides — a refusal fails loudly rather than skipping. */
#define CAP_BUFFER_BYTES 8192
#define CAP_PERIOD_BYTES 2048
#define CAP_PERIODS      8 /* periods read before the verdict */

NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, IO_STATUS_BLOCK *, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);

/* --- serial output (no CRT; aud_smoke.c's say()) ---------------------------- */

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

    out = append_text(out, "[KTEST] audio capture FAIL (");
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
     * ends the guest over QMP once the verdict is in. */
    for (;;)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; /* 1 s, relative */
        NtDelayExecution(FALSE, &interval);
    }
}

/* --- the capture path -------------------------------------------------------- */

static NTSTATUS open_node(unsigned node, HANDLE *handle, IO_STATUS_BLOCK *iosb)
{
    WCHAR path[16];
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    static const WCHAR stem[] = L"\\Device\\Snd";
    unsigned i;

    for (i = 0; stem[i]; i++)
        path[i] = stem[i];
    path[i++] = (WCHAR)('0' + node);
    path[i] = 0;
    name.Buffer = path;
    name.Length = (USHORT)(i * sizeof(WCHAR));
    name.MaximumLength = name.Length + sizeof(WCHAR);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE, &attributes,
                        iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0 /* exclusive */, FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

void cap_start(void *peb)
{
    (void)peb;

    HANDLE snd = NULL;
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    IO_STATUS_BLOCK iosb;
    SND_PCM_INFO info;
    unsigned node;

    /* The capture node is whichever stream CLAIMS direction INPUT — probe
     * every node and ask, never assume instance order (the HACK-002 rule). */
    for (node = 0; node < 4; node++)
    {
        HANDLE handle = NULL;
        status = open_node(node, &handle, &iosb);
        if (!NT_SUCCESS(status))
            continue;
        status = NtDeviceIoControlFile(handle, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_INFO, NULL, 0,
                                       &info, sizeof(info));
        if (NT_SUCCESS(status) && info.direction == SND_D_INPUT)
        {
            snd = handle;
            break;
        }
        NtClose(handle);
    }
    if (snd == NULL)
    {
        fail("no capture node", status);
        park_forever();
    }

    /* The device's own claims, checked before anything is negotiated. */
    if (!((info.formats >> SND_PCM_FMT_S16) & 1) || !((info.rates >> SND_PCM_RATE_48000) & 1) ||
        info.channelsMin > 2 || info.channelsMax < 2)
    {
        fail("caps", STATUS_NOT_SUPPORTED);
        park_forever();
    }

    SND_PCM_SET_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.bufferBytes = CAP_BUFFER_BYTES;
    params.periodBytes = CAP_PERIOD_BYTES;
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
    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_START, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("start", status);
        park_forever();
    }

    /* Blocking-read the periods; the park in the kernel is the cadence.
     * Each must complete FULL (a short period would be a stop/flush this
     * client never issued) and as ZEROS (the none backend's silence — the
     * only content QEMU can supply; docs/23 §7). */
    static char period[CAP_PERIOD_BYTES];
    for (unsigned p = 0; p < CAP_PERIODS; p++)
    {
        memset(period, 0x5a, sizeof(period)); /* poisoned so silence is proven, not leftover */
        status = NtReadFile(snd, NULL, NULL, NULL, &iosb, period, CAP_PERIOD_BYTES, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            fail("read", status);
            park_forever();
        }
        if (iosb.Information != CAP_PERIOD_BYTES)
        {
            fail("short period", STATUS_UNSUCCESSFUL);
            park_forever();
        }
        for (unsigned i = 0; i < CAP_PERIOD_BYTES; i++)
        {
            if (period[i] != 0)
            {
                fail("not silence", STATUS_UNSUCCESSFUL);
                park_forever();
            }
        }
    }

    /* POSITION counts rx completions at harvest, so everything read is
     * already counted — an exact accounting check, not a race. */
    SND_POSITION position;
    status = NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_POSITION, NULL, 0,
                                   &position, sizeof(position));
    if (!NT_SUCCESS(status))
    {
        fail("position", status);
        park_forever();
    }
    if (position.bytesConsumed < (ULONGLONG)CAP_PERIODS * CAP_PERIOD_BYTES)
    {
        fail("position short", STATUS_UNSUCCESSFUL);
        park_forever();
    }

    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_STOP, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("stop", status);
        park_forever();
    }
    status =
        NtDeviceIoControlFile(snd, NULL, NULL, NULL, &iosb, IOCTL_PRSSND_RELEASE, NULL, 0, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        fail("release", status);
        park_forever();
    }

    {
        char line[160];
        char *out = line;
        out = append_text(out, "[KTEST] audio capture PASS periods=");
        out = append_number(out, CAP_PERIODS, 10, 0);
        out = append_text(out, " pos=");
        out = append_number(out, position.bytesConsumed, 10, 0);
        out = append_text(out, "\r\n");
        *out = '\0';
        say(line);
    }
    park_forever();
}
