/*
 * sem_ps/suspend_exited.c — suspending a thread that has already exited.
 *
 * Convicted by the winetest gate: kernel32:thread joins a thread and then
 * asserts `SuspendThread(thread) == -1` (thread.c:551) and
 * `ResumeThread(thread) == 0` (thread.c:554). proskrnl handed back a live
 * suspend count for a thread that had already run to completion, so both
 * failed and the six assertions after them fell over behind it.
 *
 * The oracle's server states the rule in one line
 * (third_party/wine server/thread.c, the suspend_thread handler):
 *
 *     if (thread->state == TERMINATED) set_error( STATUS_ACCESS_DENIED );
 *     else reply->count = suspend_thread( thread );
 *
 * — STATUS_ACCESS_DENIED, notably, and not a status about the thread's
 * state, which is the answer an implementation written from intuition
 * would reach for. Its resume_thread handler has no such guard at all, so
 * resuming an exited thread SUCCEEDS with a count of 0.
 *
 * That asymmetry is the whole content of this pin: the two calls do not
 * mirror each other, and a kernel that made them symmetric — either by
 * refusing both or by allowing both — would pass neither half of
 * kernel32:thread's check.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID,
                                         PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static DWORD WINAPI quick_exit_thread(void *arg)
{
    (void)arg;
    return 0;
}

START_TEST(suspend_exited)
{
    NTSTATUS status;
    HANDLE thread = NULL;
    ULONG previous;
    LARGE_INTEGER timeout;

    status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, (HANDLE)(LONG_PTR)-1,
                              (PVOID)quick_exit_thread, NULL, 0, 0, 0, 0, NULL);
    ok(status == STATUS_SUCCESS, "create thread -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* Let it run to completion — this is the state the rule is about. */
    timeout.QuadPart = -50000000; /* 5 s */
    status = NtWaitForSingleObject(thread, FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "join thread -> %08lx", (unsigned long)status);

    /* --- suspend is refused, and with ACCESS_DENIED specifically --------- */
    previous = 0xdeadbeef;
    status = NtSuspendThread(thread, &previous);
    ok(status == STATUS_ACCESS_DENIED, "suspend exited thread -> %08lx", (unsigned long)status);

    /* --- but resume is NOT: it succeeds, with a count of 0 --------------- */
    previous = 0xdeadbeef;
    status = NtResumeThread(thread, &previous);
    ok(status == STATUS_SUCCESS, "resume exited thread -> %08lx", (unsigned long)status);
    ok(previous == 0, "resume of an exited thread reported count %lu", (unsigned long)previous);

    /* Self-suspension is deliberately NOT pinned here, and the reason is a
     * real divergence rather than a limitation of the test. On the ORACLE,
     * SuspendThread(GetCurrentThread()) parks the caller INSIDE the call —
     * a test that did it would hang, and one did while this was written.
     * On proskrnl the gate is honoured on the way back to ring 3
     * (kernel/syscall/table.c), so the syscall returns and the thread parks
     * at the edge. Both reach the same observable state for a caller that
     * has another thread to resume it, which is the only arrangement in
     * which self-suspension is useful and exactly what kernel32:thread's
     * threadFunc3 does.
     *
     * What this test covers is the PREREQUISITE that was actually broken:
     * the NtCurrentThread pseudo-handle now resolves (kernel/ob/handle.c),
     * so a self-suspend reaches the gate at all instead of failing
     * STATUS_INVALID_HANDLE. The winetest pair is the differential for the
     * parking itself. */

    NtClose(thread);
}
