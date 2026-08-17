/*
 * winevsnd midi — the zero-device MIDI and AUX driver (docs/23 §4b).
 *
 * midi_get_driver answers the empty string, so mmdevapi routes MIDI to this
 * driver itself (dlls/mmdevapi/main.c init_driver); midi_init then reports
 * success with ZERO devices — the true count for hardware that does not
 * exist (virtio-snd carries no MIDI), not an Art. 12 fabrication. Every
 * per-device message answers MMSYSERR_BADDEVICEID, which is what any
 * dev_id is when the device count is zero (the winealsa dispatch shape,
 * dlls/winealsa.drv/alsamidi.c midi_out_message).
 *
 * midi_notify_wait must BLOCK: mmdevapi's notify thread loops on it
 * (main.c notify_thread) and treats a return only as "a notification or
 * quit" — a non-blocking return would spin that thread. With zero devices
 * the only notification that can ever arrive is quit, raised by
 * midi_release; a kernel event carries it.
 */
#include "winevsnd.h"

static HANDLE midi_quit_event;
static BOOL midi_quit;

static NTSTATUS create_quit_event(void)
{
    OBJECT_ATTRIBUTES attr;

    if (midi_quit_event) return STATUS_SUCCESS;
    InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);
    return NtCreateEvent(&midi_quit_event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
}

NTSTATUS vsnd_midi_get_driver(void *args)
{
    WCHAR *name = args;

    /* Empty: mmdevapi then uses THIS driver's midi entries (main.c:182). */
    name[0] = 0;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_midi_init(void *args)
{
    struct midi_init_params *params = args;

    midi_quit = FALSE;
    if (create_quit_event())
    {
        vsnd_report("winevsnd: midi_init could not create its quit event\n");
        *params->err = MMSYSERR_ERROR;
        return STATUS_SUCCESS;
    }
    /* Zero MIDI devices exist; success with nothing to enumerate. */
    *params->err = NOERROR;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_midi_release(void *args)
{
    midi_quit = TRUE;
    if (midi_quit_event) NtSetEvent(midi_quit_event, NULL);
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_midi_out_message(void *args)
{
    struct midi_out_message_params *params = args;

    params->notify->send_notify = FALSE;
    switch (params->msg)
    {
    case DRVM_INIT:
    case DRVM_EXIT:
    case DRVM_ENABLE:
    case DRVM_DISABLE:
        *params->err = MMSYSERR_NOERROR;
        break;
    case MODM_GETNUMDEVS:
        *params->err = 0;
        break;
    default:
        /* Zero devices: every dev_id is out of range. */
        *params->err = MMSYSERR_BADDEVICEID;
        break;
    }
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_midi_in_message(void *args)
{
    struct midi_in_message_params *params = args;

    params->notify->send_notify = FALSE;
    switch (params->msg)
    {
    case DRVM_INIT:
    case DRVM_EXIT:
    case DRVM_ENABLE:
    case DRVM_DISABLE:
        *params->err = MMSYSERR_NOERROR;
        break;
    case MIDM_GETNUMDEVS:
        *params->err = 0;
        break;
    default:
        *params->err = MMSYSERR_BADDEVICEID;
        break;
    }
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_midi_notify_wait(void *args)
{
    struct midi_notify_wait_params *params = args;

    params->notify->send_notify = FALSE;
    if (midi_quit_event) NtWaitForSingleObject(midi_quit_event, FALSE, NULL);
    *params->quit = midi_quit;
    return STATUS_SUCCESS;
}

NTSTATUS vsnd_aux_message(void *args)
{
    struct aux_message_params *params = args;

    switch (params->msg)
    {
    case AUXDM_GETNUMDEVS:
        *params->err = 0;
        break;
    default:
        *params->err = MMSYSERR_BADDEVICEID;
        break;
    }
    return STATUS_SUCCESS;
}
