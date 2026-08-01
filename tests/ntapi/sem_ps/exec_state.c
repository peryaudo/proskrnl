/*
 * sem_ps/exec_state.c — NtFlushProcessWriteBuffers,
 * NtGetCurrentProcessorNumber and NtSetThreadExecutionState (CUI-6).
 *
 * The three no-power ids kernel32/kernelbase forward straight to ntdll
 * (FlushProcessWriteBuffers / GetCurrentProcessorNumber .spec forwards;
 * SetThreadExecutionState). Oracle behaviour pinned from the pinned tree:
 * flush always succeeds (dlls/ntdll/unix/virtual.c NtFlushProcessWriteBuffers
 * — the membarrier wrapper never fails); the processor number is a real CPU
 * id below the machine's processor count (dlls/ntdll/unix/thread.c
 * NtGetCurrentProcessorNumber — on uniprocessor proskrnl that count is 1, so
 * the same bound pins 0 there); the execution state is a per-process latch
 * (dlls/ntdll/unix/system.c NtSetThreadExecutionState: *old_state = current;
 * current is replaced unless it holds ES_CONTINUOUS and the new state does
 * not).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtFlushProcessWriteBuffers(void);
NTSYSAPI ULONG NTAPI NtGetCurrentProcessorNumber(void);
NTSYSAPI NTSTATUS NTAPI NtSetThreadExecutionState(EXECUTION_STATE, EXECUTION_STATE *);

START_TEST(exec_state)
{
    NTSTATUS status;
    SYSTEM_BASIC_INFORMATION sbi;
    ULONG len = 0;
    ULONG cpu;
    EXECUTION_STATE old;

    /* --- NtFlushProcessWriteBuffers: always succeeds --------------------- */
    status = NtFlushProcessWriteBuffers();
    ok(status == STATUS_SUCCESS, "flush write buffers -> %08lx", (unsigned long)status);

    /* --- NtGetCurrentProcessorNumber: a CPU id below the machine count --- */
    memset(&sbi, 0, sizeof(sbi));
    status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), &len);
    ok(status == STATUS_SUCCESS, "SystemBasicInformation -> %08lx", (unsigned long)status);
    cpu = NtGetCurrentProcessorNumber();
    ok(cpu < sbi.NumberOfProcessors, "processor number %lu of %u", (unsigned long)cpu,
       (unsigned)sbi.NumberOfProcessors);

    /* --- NtSetThreadExecutionState: the per-process latch ---------------- */
    /* Fresh process: the initial state is the awake triple (system + display
     * required, user present) and no ES_CONTINUOUS. */
    old = 0;
    status = NtSetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED, &old);
    ok(status == STATUS_SUCCESS, "set exec state -> %08lx", (unsigned long)status);
    ok(old == (ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT), "initial state %08lx",
       (unsigned long)old);

    /* The continuous state latched: a non-continuous pulse reports it but
     * does NOT replace it... */
    old = 0;
    status = NtSetThreadExecutionState(ES_DISPLAY_REQUIRED, &old);
    ok(status == STATUS_SUCCESS, "pulse -> %08lx", (unsigned long)status);
    ok(old == (ES_CONTINUOUS | ES_SYSTEM_REQUIRED), "latched state survives pulse, old %08lx",
       (unsigned long)old);
    old = 0;
    status = NtSetThreadExecutionState(ES_USER_PRESENT, &old);
    ok(status == STATUS_SUCCESS, "pulse again -> %08lx", (unsigned long)status);
    ok(old == (ES_CONTINUOUS | ES_SYSTEM_REQUIRED), "pulse did not stick, old %08lx",
       (unsigned long)old);

    /* ...while a continuous set replaces it. */
    old = 0;
    status = NtSetThreadExecutionState(ES_CONTINUOUS, &old);
    ok(status == STATUS_SUCCESS, "clear continuous -> %08lx", (unsigned long)status);
    ok(old == (ES_CONTINUOUS | ES_SYSTEM_REQUIRED), "old before clear %08lx", (unsigned long)old);
    old = 0;
    status = NtSetThreadExecutionState(ES_CONTINUOUS, &old);
    ok(status == STATUS_SUCCESS, "read back -> %08lx", (unsigned long)status);
    ok(old == ES_CONTINUOUS, "bare continuous latched, old %08lx", (unsigned long)old);

    /* A bare-continuous latch does NOT hold: any set now replaces it (the
     * current state carries ES_CONTINUOUS, so the gate is open only for new
     * states that also carry it — a plain pulse reports without replacing). */
    old = 0;
    status = NtSetThreadExecutionState(ES_SYSTEM_REQUIRED, &old);
    ok(status == STATUS_SUCCESS, "pulse on bare continuous -> %08lx", (unsigned long)status);
    ok(old == ES_CONTINUOUS, "bare continuous survives pulse, old %08lx", (unsigned long)old);

    /* Restore the boot state for any later test in the same process image. */
    status = NtSetThreadExecutionState(
        ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT, &old);
    ok(status == STATUS_SUCCESS, "restore -> %08lx", (unsigned long)status);
}
