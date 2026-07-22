/*
 * tests/cui/svcdemo.c — the CUI-3 acceptance service (docs/02 "a real
 * service installs, starts, and survives reboot, all driven from ring 3").
 *
 * Like hello_crt.c, built with the PLAIN mingw toolchain and its full CRT
 * (imports advapi32 + msvcrt + kernel32; no Wine import libraries): a
 * third-party service binary against the baked Wine userland. The console
 * acceptance installs it with `sc create SvcDemo binpath= C:\svcdemo.exe
 * start= auto`, starts it with `sc start SvcDemo`, and reads its proof; the
 * scm leg reboots and asserts the SCM auto-started it from the persisted
 * registry with no further input.
 *
 * The service body appends one line to C:\svcdemo.log per start (the file
 * is the ring-3-observable proof a service process really ran under
 * services.exe — one line after boot 1, two after the reboot), reports
 * RUNNING, and parks until SERVICE_CONTROL_STOP.
 */
#include <windows.h>

static SERVICE_STATUS_HANDLE status_handle;
static HANDLE stop_event;

static void report_state(DWORD state)
{
    SERVICE_STATUS status;

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &status);
}

static DWORD WINAPI control_handler(DWORD control, DWORD event_type, void *event_data,
                                    void *context)
{
    (void)event_type;
    (void)event_data;
    (void)context;
    switch (control)
    {
    case SERVICE_CONTROL_STOP:
        report_state(SERVICE_STOP_PENDING);
        SetEvent(stop_event);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void append_proof(void)
{
    HANDLE file = CreateFileW(L"C:\\svcdemo.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;
    static const char line[] = "svcdemo: service ran\r\n";
    DWORD written;
    WriteFile(file, line, sizeof(line) - 1, &written, NULL);
    CloseHandle(file);
}

static void WINAPI service_main(DWORD argc, WCHAR **argv)
{
    (void)argc;
    (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(L"SvcDemo", control_handler, NULL);
    if (!status_handle)
        return;
    report_state(SERVICE_START_PENDING);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    append_proof();
    report_state(SERVICE_RUNNING);
    WaitForSingleObject(stop_event, INFINITE);
    report_state(SERVICE_STOPPED);
}

int main(void)
{
    static const SERVICE_TABLE_ENTRYW table[] = {
        {(WCHAR *)L"SvcDemo", service_main},
        {NULL, NULL},
    };
    /* Blocks dispatching until the service stops; fails fast when run from
     * a console instead of the SCM (the honest off-the-shelf behaviour). */
    StartServiceCtrlDispatcherW(table);
    return 0;
}
