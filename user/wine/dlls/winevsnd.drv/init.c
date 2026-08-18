/*
 * winevsnd init — the exported entry table and the serial report channel.
 *
 * mmdevapi's seam resolves ONE export, __wine_unix_call_funcs, and indexes
 * it by enum unix_funcs (dlls/mmdevapi/unixlib.h). The table below is that
 * enum written out in order; the C_ASSERT pins the count so a wine pin bump
 * that grows the surface fails this build instead of dispatching off the
 * table's end.
 *
 * Every entry returns STATUS_SUCCESS at the NTSTATUS layer and carries its
 * verdict in params->result: mmdevapi's wine_unix_call asserts the NTSTATUS
 * is zero (mmdevapi_private.h), so a non-success here aborts the calling
 * process — the same discipline the oracle's own drivers follow (winealsa's
 * alsa_not_implemented returns STATUS_SUCCESS).
 */
#include <stdio.h>

#include "winevsnd.h"

void vsnd_report(const char *format, ...)
{
    char text[256];
    WCHAR wide[256];
    UNICODE_STRING str;
    va_list args;
    int len, i;

    va_start(args, format);
    len = _vsnprintf(text, sizeof(text) - 1, format, args);
    va_end(args);
    if (len < 0) return;
    if (len > (int)sizeof(text) - 1) len = (int)sizeof(text) - 1;

    for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
    str.Buffer = wide;
    str.Length = len * sizeof(WCHAR);
    str.MaximumLength = str.Length;
    NtDisplayString(&str);
}

static NTSTATUS vsnd_process_attach(void *args)
{
    return STATUS_SUCCESS;
}

/* The feeder starts with the first stream (stream.c), not from a main loop:
 * a no-op success is the oracle's own shape for these (winealsa runs every
 * one of process_attach/main_loop_start/main_loop_stop through
 * alsa_not_implemented, which returns STATUS_SUCCESS). */
static NTSTATUS vsnd_main_loop_start(void *args)
{
    return STATUS_SUCCESS;
}

static NTSTATUS vsnd_main_loop_stop(void *args)
{
    return STATUS_SUCCESS;
}

/* The deliberately-unbuilt surface (docs/23 §5). Loud, named, and shaped
 * as the REAL refusal the caller's contract knows — never
 * STATUS_NOT_IMPLEMENTED through a path that asserts success. (The capture
 * legs that stood here until AUD-3 live in stream.c now.)
 *
 * The oracle's own driverless path answers E_NOTIMPL for loopback capture
 * (mmdevapi client.c get_loopback_capture_device FIXME), and winepulse
 * answers E_NOTIMPL for set_sample_rate — matching the oracle's shape IS
 * the contract here (docs/23 §5: no loopback, no rate adjustment). */
static NTSTATUS vsnd_get_loopback_capture_device(void *args)
{
    struct get_loopback_capture_device_params *params = args;

    vsnd_report("winevsnd: get_loopback_capture_device refused (unbuilt, docs/23 s5)\n");
    params->result = E_NOTIMPL;
    return STATUS_SUCCESS;
}

static NTSTATUS vsnd_set_sample_rate(void *args)
{
    struct set_sample_rate_params *params = args;

    vsnd_report("winevsnd: set_sample_rate refused (unbuilt, docs/23 s5)\n");
    params->result = E_NOTIMPL;
    return STATUS_SUCCESS;
}

/* enum unix_funcs, in order (dlls/mmdevapi/unixlib.h:322). */
DECLSPEC_EXPORT const vsnd_entry __wine_unix_call_funcs[] =
{
    vsnd_process_attach,            /* process_attach */
    vsnd_process_detach,            /* process_detach */
    vsnd_main_loop_start,           /* main_loop_start */
    vsnd_main_loop_stop,            /* main_loop_stop */
    vsnd_get_endpoint_ids,          /* get_endpoint_ids */
    vsnd_create_stream,             /* create_stream */
    vsnd_release_stream,            /* release_stream */
    vsnd_start,                     /* start */
    vsnd_stop,                      /* stop */
    vsnd_reset,                     /* reset */
    vsnd_get_render_buffer,         /* get_render_buffer */
    vsnd_release_render_buffer,     /* release_render_buffer */
    vsnd_get_capture_buffer,        /* get_capture_buffer */
    vsnd_release_capture_buffer,    /* release_capture_buffer */
    vsnd_is_format_supported,       /* is_format_supported */
    vsnd_get_loopback_capture_device, /* get_loopback_capture_device */
    vsnd_get_mix_format,            /* get_mix_format */
    vsnd_get_device_period,         /* get_device_period */
    vsnd_get_buffer_size,           /* get_buffer_size */
    vsnd_get_latency,               /* get_latency */
    vsnd_get_current_padding,       /* get_current_padding */
    vsnd_get_next_packet_size,      /* get_next_packet_size */
    vsnd_get_frequency,             /* get_frequency */
    vsnd_get_position,              /* get_position */
    vsnd_set_volumes,               /* set_volumes */
    vsnd_set_event_handle,          /* set_event_handle */
    vsnd_set_sample_rate,           /* set_sample_rate */
    vsnd_test_connect,              /* test_connect */
    vsnd_is_started,                /* is_started */
    vsnd_get_prop_value,            /* get_prop_value */
    vsnd_midi_get_driver,           /* midi_get_driver */
    vsnd_midi_init,                 /* midi_init */
    vsnd_midi_release,              /* midi_release */
    vsnd_midi_out_message,          /* midi_out_message */
    vsnd_midi_in_message,           /* midi_in_message */
    vsnd_midi_notify_wait,          /* midi_notify_wait */
    vsnd_aux_message,               /* aux_message */
};

C_ASSERT(ARRAY_SIZE(__wine_unix_call_funcs) == funcs_count);

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    /* ntdll's spelling: this module imports nothing above ntdll. */
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll(instance);
    return TRUE;
}
