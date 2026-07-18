/*
 * sem_file/apc_completion.c — APC completion of NtReadFile/NtWriteFile (M6
 * spec, oracle-only until M7).
 *
 * The APC leg of the async-completion protocol (docs/03: "IOSB timing,
 * APC/event/port" is a kept contract): a read carrying an ApcRoutine queues a
 * user APC on completion; the APC is delivered at the next alertable wait,
 * receives the ApcContext and the very IOSB the caller passed, and the IOSB
 * is written BEFORE the routine runs. Delivering a user APC needs the M7
 * KiUserApcDispatcher return protocol, so this test stays out of the
 * proskrnl manifest until then — on the oracle it is the executable spec
 * that M7 will be held to (Art. 5).
 */
#include "util.h"

static int apc_calls;
static void *apc_seen_context;
static IO_STATUS_BLOCK *apc_seen_iosb;
static ULONG apc_seen_information;
static NTSTATUS apc_seen_status;

static void NTAPI completion_apc(PVOID context, PIO_STATUS_BLOCK iosb, ULONG reserved)
{
    apc_calls++;
    apc_seen_context = context;
    apc_seen_iosb = iosb;
    apc_seen_status = iosb->Status;
    apc_seen_information = (ULONG)iosb->Information;
    (void)reserved;
}

START_TEST(apc_completion)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, h;
    LARGE_INTEGER offset, timeout;
    char buffer[16];
    int marker;

    dir = open_test_dir(W("\\??\\C:\\prstest\\apc"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("apc.bin"));

    status = open_file(&h, dir, W("apc.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0,
                       FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create apc.bin -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, NULL, NULL, &iosb, "0123456789", 10, &offset, NULL);
    ok(status == STATUS_SUCCESS, "fill -> %08lx", (unsigned long)status);

    /* --- read with an APC routine: no delivery before an alertable wait. --- */
    apc_calls = 0;
    poison_iosb(&iosb);
    offset.QuadPart = 2;
    status = NtReadFile(h, NULL, completion_apc, &marker, &iosb, buffer, 5, &offset, NULL);
    ok(status == STATUS_SUCCESS, "read with APC -> %08lx", (unsigned long)status);
    ok(apc_calls == 0, "APC not delivered before an alertable wait (%d)", apc_calls);

    /* A non-alertable delay does not deliver it either. */
    timeout.QuadPart = -100000; /* 10 ms, relative */
    status = NtDelayExecution(FALSE, &timeout);
    ok(status == STATUS_SUCCESS, "non-alertable delay -> %08lx", (unsigned long)status);
    ok(apc_calls == 0, "APC still pending after non-alertable wait (%d)", apc_calls);

    /* An alertable wait delivers it and returns STATUS_USER_APC. */
    timeout.QuadPart = -10000000; /* 1 s: the APC must cut this short */
    status = NtDelayExecution(TRUE, &timeout);
    ok(status == STATUS_USER_APC, "alertable delay -> %08lx", (unsigned long)status);
    ok(apc_calls == 1, "APC delivered once (%d)", apc_calls);
    ok(apc_seen_context == &marker, "APC context %p (want %p)", apc_seen_context, (void *)&marker);
    ok(apc_seen_iosb == &iosb, "APC iosb %p (want %p)", (void *)apc_seen_iosb, (void *)&iosb);
    ok(apc_seen_status == STATUS_SUCCESS && apc_seen_information == 5,
       "iosb written before the APC ran: %08lx/%lu", (unsigned long)apc_seen_status,
       (unsigned long)apc_seen_information);
    ok(memcmp(buffer, "23456", 5) == 0, "APC read data");

    /* --- second delivery does not repeat. ---------------------------------- */
    timeout.QuadPart = -100000;
    status = NtDelayExecution(TRUE, &timeout);
    ok(status == STATUS_SUCCESS, "drained alertable delay -> %08lx", (unsigned long)status);
    ok(apc_calls == 1, "APC not delivered twice (%d)", apc_calls);

    /* --- write completion also queues the APC. ----------------------------- */
    poison_iosb(&iosb);
    offset.QuadPart = 0;
    status = NtWriteFile(h, NULL, completion_apc, &marker, &iosb, "AB", 2, &offset, NULL);
    ok(status == STATUS_SUCCESS, "write with APC -> %08lx", (unsigned long)status);
    timeout.QuadPart = -10000000;
    status = NtDelayExecution(TRUE, &timeout);
    ok(status == STATUS_USER_APC, "alertable delay after write -> %08lx", (unsigned long)status);
    ok(apc_calls == 2 && apc_seen_information == 2, "write APC delivered (%d, %lu)", apc_calls,
       (unsigned long)apc_seen_information);

    NtClose(h);
    scrub_file(dir, W("apc.bin"));
    NtClose(dir);
}
