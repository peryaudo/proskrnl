/*
 * sem_ps/terminate_siblings.c — NtTerminateProcess(NULL, status) terminates
 * every OTHER thread of the calling process, and does not return until they
 * are gone.
 *
 * This is what RtlExitUserProcess relies on to drain siblings before it runs
 * DLL detach. proskrnl returned STATUS_SUCCESS having terminated nothing, so
 * detach routines ran against threads still executing inside the DLLs being
 * detached.
 *
 * The sibling here parks in an infinite wait, so "it ended" cannot be
 * confused with "it finished on its own": only the terminate can end it.
 */
#include "../ntapi.h"

#include <windows.h>

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(HANDLE, LONG);

static HANDLE sibling_ready;

static DWORD WINAPI park_forever(void *arg)
{
    (void)arg;
    SetEvent(sibling_ready);
    for (;;)
        Sleep(60000);
}

START_TEST(terminate_siblings)
{
    HANDLE thread;
    DWORD exitCode = 0;
    NTSTATUS status;

    sibling_ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(sibling_ready != NULL, "ready event");
    if (sibling_ready == NULL)
        return;

    thread = CreateThread(NULL, 0, park_forever, NULL, 0, NULL);
    ok(thread != NULL, "spawn the sibling");
    if (thread == NULL)
        return;
    ok(WaitForSingleObject(sibling_ready, 10000) == WAIT_OBJECT_0, "the sibling started");

    /* It is parked in a 60-second sleep, so it cannot end by itself. */
    ok(WaitForSingleObject(thread, 0) == WAIT_TIMEOUT, "the sibling is still running");

    status = NtTerminateProcess(NULL, 0x1234);
    ok(status == STATUS_SUCCESS, "NtTerminateProcess(NULL) -> %08lx", (unsigned long)status);

    /* The contract is that it has ALREADY happened when the call returns --
     * a zero-timeout wait, not a generous one. */
    ok(WaitForSingleObject(thread, 0) == WAIT_OBJECT_0,
       "the sibling is still alive after NtTerminateProcess(NULL) returned");
    ok(GetExitCodeThread(thread, &exitCode) && exitCode != STILL_ACTIVE,
       "the sibling's exit code is still STILL_ACTIVE");

    CloseHandle(thread);
    CloseHandle(sibling_ready);
}
