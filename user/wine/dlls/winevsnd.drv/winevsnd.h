/*
 * winevsnd.h — the PE mmdevapi driver over \Device\Snd* (AUD-2, docs/23 §4b).
 *
 * The winefb.drv recipe applied to sound: superproject PE code, zero fork
 * lines, additive by construction — the oracle never executes a byte of it.
 * mmdevapi loads this module as an ordinary PE DLL (the seam's proskrnl leg
 * in third_party/wine dlls/mmdevapi/main.c load_driver) and dispatches
 * through the __wine_unix_call_funcs table main.c exports; the entries are
 * mmdevapi's unixlib surface (dlls/mmdevapi/unixlib.h, 37 entries)
 * implemented as ordinary PE code over Nt* calls against the HACK-007
 * device nodes (drivers/sndproto.h).
 */
#ifndef PRSK_WINEVSND_H
#define PRSK_WINEVSND_H

#include <stdarg.h>
#include <stddef.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#include "audioclient.h"
#include "mmdeviceapi.h"
#include "mmddk.h"

#include "unixlib.h"           /* third_party/wine dlls/mmdevapi — the contract */

/* PE-side the wine/unixlib.h entry typedef is unix-only; the table this
 * module exports is plain PE function pointers, same signature. */
typedef NTSTATUS (*vsnd_entry)(void *args);

/* init.c */
extern void vsnd_report(const char *format, ...);

/* stream.c — the device, the streams, the feeder */
extern NTSTATUS vsnd_process_detach(void *args);
extern NTSTATUS vsnd_get_endpoint_ids(void *args);
extern NTSTATUS vsnd_create_stream(void *args);
extern NTSTATUS vsnd_release_stream(void *args);
extern NTSTATUS vsnd_start(void *args);
extern NTSTATUS vsnd_stop(void *args);
extern NTSTATUS vsnd_reset(void *args);
extern NTSTATUS vsnd_get_render_buffer(void *args);
extern NTSTATUS vsnd_release_render_buffer(void *args);
extern NTSTATUS vsnd_is_format_supported(void *args);
extern NTSTATUS vsnd_get_mix_format(void *args);
extern NTSTATUS vsnd_get_device_period(void *args);
extern NTSTATUS vsnd_get_buffer_size(void *args);
extern NTSTATUS vsnd_get_latency(void *args);
extern NTSTATUS vsnd_get_current_padding(void *args);
extern NTSTATUS vsnd_get_frequency(void *args);
extern NTSTATUS vsnd_get_position(void *args);
extern NTSTATUS vsnd_set_volumes(void *args);
extern NTSTATUS vsnd_set_event_handle(void *args);
extern NTSTATUS vsnd_test_connect(void *args);
extern NTSTATUS vsnd_is_started(void *args);
extern NTSTATUS vsnd_get_prop_value(void *args);

/* midi.c — the zero-device MIDI driver (docs/23 §4b: zero is the TRUE count
 * for hardware that does not exist, not an Art. 12 fabrication) */
extern NTSTATUS vsnd_midi_get_driver(void *args);
extern NTSTATUS vsnd_midi_init(void *args);
extern NTSTATUS vsnd_midi_release(void *args);
extern NTSTATUS vsnd_midi_out_message(void *args);
extern NTSTATUS vsnd_midi_in_message(void *args);
extern NTSTATUS vsnd_midi_notify_wait(void *args);
extern NTSTATUS vsnd_aux_message(void *args);

#endif /* PRSK_WINEVSND_H */
