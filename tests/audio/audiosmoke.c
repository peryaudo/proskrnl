/*
 * audiosmoke.c — the audio oracle actually has an audio backend.
 *
 * ORACLE-ONLY, deliberately — the fontsmoke recipe applied to sound
 * (docs/23 §6b, the third instance of the docs/06 trap). It lives outside
 * tests/ntapi/ so the harness's all_tests() sweep never picks it up: it
 * links ole32, which the proskrnl ntapi image does not carry, and it asks
 * nothing about the KERNEL. It is a check on the test *equipment*, not on
 * proskrnl (docs/14).
 *
 * Why it exists: the pinned Wine is configured --with-pulse, but
 * winepulse.drv is dlopen'd and FAIL-SOFT — with no reachable PulseAudio
 * server mmdevapi loads no driver and does not fail: it enumerates ZERO
 * endpoints, waveOutGetNumDevs() answers 0, and every audio winetest pair
 * SKIPS, which counts as green. An oracle that skips is not an oracle. So:
 * ask it for a render endpoint and check it answers. The pair discipline
 * (docs/21) can then trust that a green audio pair exercised real code.
 */
#define COBJMACROS
#include "ntapi.h"

/* initguid.h turns the DEFINE_GUID()s in the headers below into definitions
 * in this translation unit, so no uuid library is linked (the build is
 * -nostdlib, like every ntapi-harness exe). */
#include <initguid.h>
#include <mmdeviceapi.h>

START_TEST(audiosmoke)
{
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDeviceCollection *devices = NULL;
    UINT count = 0;
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "CoInitializeEx returned %#x", (unsigned)hr);
    if (hr != S_OK)
        return;

    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IMMDeviceEnumerator, (void **)&enumerator);
    ok(hr == S_OK, "CoCreateInstance(MMDeviceEnumerator) returned %#x", (unsigned)hr);

    if (enumerator)
    {
        hr = IMMDeviceEnumerator_EnumAudioEndpoints(enumerator, eRender, DEVICE_STATE_ACTIVE,
                                                    &devices);
        ok(hr == S_OK, "EnumAudioEndpoints(eRender) returned %#x", (unsigned)hr);
        if (devices)
        {
            hr = IMMDeviceCollection_GetCount(devices, &count);
            ok(hr == S_OK, "GetCount returned %#x", (unsigned)hr);
            ok(count >= 1, "the oracle enumerates no active render endpoint — the audio "
                           "backend is missing (check --with-pulse and the runner's "
                           "start_pulse daemon)");
            IMMDeviceCollection_Release(devices);
        }
        IMMDeviceEnumerator_Release(enumerator);
    }

    CoUninitialize();
}
