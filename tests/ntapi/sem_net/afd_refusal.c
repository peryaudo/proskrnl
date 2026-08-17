/*
 * sem_net/afd_refusal.c — the unknown-code shape (G12's oracle-pinned
 * refusal), and IOCTL_AFD_WINE_COMPLETE_ASYNC.
 *
 * Measured at the raw boundary (docs/24 §1b — first drafts guessed the
 * WSAIoctl-level pend-then-complete shape and the oracle corrected
 * them): an ioctl \Device\Afd does not know refuses INLINE with
 * STATUS_NOT_SUPPORTED, the IOSB untouched, the event and every other
 * completion leg unfired. ws2_32's own WSAIoctl never even forwards an
 * unknown code — its default arm FABRICATES the overlapped
 * pend-then-STATUS_NOT_SUPPORTED completion PE-side by issuing
 * IOCTL_AFD_WINE_COMPLETE_ASYNC with that status (socket.c's default
 * arm), which is also why COMPLETE_ASYNC is pinned here: it completes
 * its own call through the ordinary async legs with the caller-supplied
 * status, and doubles as ws2_32's is-this-a-socket probe
 * (is_valid_socket).
 *
 * proskrnl's default arm answers this same inline shape for every
 * UNBUILT verb too (each named loudly on serial — the KI_SYSCALL_MISSING
 * pattern at device level); that divergence-by-tail is recorded in
 * docs/03, and no case here (or anywhere — G12) asserts
 * STATUS_NOT_IMPLEMENTED.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(HANDLE, PULONG_PTR, PULONG_PTR, PIO_STATUS_BLOCK,
                                             PLARGE_INTEGER);

typedef struct
{
    HANDLE CompletionPort;
    ULONG_PTR CompletionKey;
} SEM_NET_COMPLETION_INFORMATION;

#ifndef FileCompletionInformation
#define FileCompletionInformation 30
#endif

#define TEST_KEY ((ULONG_PTR)0xafd0afd0)

static const ULONG unknown_codes[] = {
    0xdeadbeef, 0x8004667d, /* FIOASYNC — winsock's own, unimplemented everywhere */
    0x667e, 0x28000004,     /* SIO_FLUSH */
};

static void test_unknown_code_shape(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL, event;
    unsigned i;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < sizeof(unknown_codes) / sizeof(unknown_codes[0]); i++)
    {
        status = afd_tcp(&s, FALSE);
        ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

        ResetEvent(event);
        poison_iosb(&iosb);
        status =
            NtDeviceIoControlFile(s, event, NULL, NULL, &iosb, unknown_codes[i], NULL, 0, NULL, 0);
        ok(status == STATUS_NOT_SUPPORTED, "code %08lx -> %08lx", (unsigned long)unknown_codes[i],
           (unsigned long)status);
        ok(iosb.Status == IOSB_POISON_STATUS, "code %08lx wrote the IOSB: %08lx",
           (unsigned long)unknown_codes[i], (unsigned long)iosb.Status);
        ok(!is_signaled(event), "code %08lx fired the event", (unsigned long)unknown_codes[i]);
        NtClose(s);
    }
    CloseHandle(event);
}

/* COMPLETE_ASYNC's probe face: input STATUS_SUCCESS, no async legs —
 * STATUS_SUCCESS straight back (is_valid_socket's whole test). */
static void test_complete_async_probe(void)
{
    IO_STATUS_BLOCK iosb;
    HANDLE s = NULL;
    NTSTATUS input = STATUS_SUCCESS;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_COMPLETE_ASYNC,
                                   &input, sizeof(input), NULL, 0);
    ok(status == STATUS_SUCCESS, "complete-async probe -> %08lx", (unsigned long)status);
    NtClose(s);
}

/* COMPLETE_ASYNC's fabrication face: the packet leg. ws2_32's WSAIoctl
 * hands an unsupported overlapped ioctl this verb with
 * STATUS_NOT_SUPPORTED and its test (ws2_32:sock
 * test_unsupported_ioctls) then observes the completion packet carrying
 * that status — so the packet must arrive here too, with the caller's
 * ApcContext as the value. */
static void test_complete_async_posts_packet(void)
{
    SEM_NET_COMPLETION_INFORMATION completion;
    IO_STATUS_BLOCK iosb, packetIosb, setIosb;
    LARGE_INTEGER timeout;
    ULONG_PTR key = 0, value = 0;
    HANDLE s = NULL, port = NULL;
    NTSTATUS input = STATUS_NOT_SUPPORTED;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);
    status = NtCreateIoCompletion(&port, IO_COMPLETION_ALL_ACCESS, NULL, 0);
    ok(status == STATUS_SUCCESS, "port -> %08lx", (unsigned long)status);
    completion.CompletionPort = port;
    completion.CompletionKey = TEST_KEY;
    status = NtSetInformationFile(s, &setIosb, &completion, sizeof(completion),
                                  (FILE_INFORMATION_CLASS)FileCompletionInformation);
    ok(status == STATUS_SUCCESS, "attach -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, NULL, (void *)0xdead0001, &iosb,
                                   IOCTL_AFD_WINE_COMPLETE_ASYNC, &input, sizeof(input), NULL, 0);
    ok(status == STATUS_NOT_SUPPORTED, "complete-async -> %08lx", (unsigned long)status);

    timeout.QuadPart = -30LL * 10000000;
    poison_iosb(&packetIosb);
    status = NtRemoveIoCompletion(port, &key, &value, &packetIosb, &timeout);
    ok(status == STATUS_SUCCESS, "remove -> %08lx", (unsigned long)status);
    ok(key == TEST_KEY, "key %lx", (unsigned long)key);
    ok(value == 0xdead0001, "value %lx", (unsigned long)value);
    ok(packetIosb.Status == STATUS_NOT_SUPPORTED, "packet status %08lx",
       (unsigned long)packetIosb.Status);
    ok(packetIosb.Information == 0, "packet information %lx",
       (unsigned long)packetIosb.Information);

    NtClose(port);
    NtClose(s);
}

static unsigned apc_hits;
static NTSTATUS apc_status;
static void WINAPI refusal_apc(void *context, IO_STATUS_BLOCK *iosb, ULONG reserved)
{
    (void)context;
    (void)reserved;
    apc_hits++;
    apc_status = iosb->Status;
}

/* COMPLETE_ASYNC's APC leg: WSAIoctl's completion-routine case rides it
 * (ws2_32:sock test_unsupported_ioctls observes the routine called with
 * WSAEOPNOTSUPP), so the raw APC must fire at the next alertable wait
 * with the fabricated status in the IOSB. */
static void test_complete_async_fires_apc(void)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER zero;
    HANDLE s = NULL;
    NTSTATUS input = STATUS_NOT_SUPPORTED;
    NTSTATUS status;

    status = afd_tcp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "create -> %08lx", (unsigned long)status);

    apc_hits = 0;
    apc_status = IOSB_POISON_STATUS;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, NULL, refusal_apc, NULL, &iosb, IOCTL_AFD_WINE_COMPLETE_ASYNC,
                                   &input, sizeof(input), NULL, 0);
    ok(status == STATUS_NOT_SUPPORTED, "complete-async apc -> %08lx", (unsigned long)status);

    zero.QuadPart = 0;
    status = NtDelayExecution(TRUE, &zero);
    ok(status == STATUS_USER_APC, "alertable delay -> %08lx", (unsigned long)status);
    ok(apc_hits == 1, "apc ran %u times", apc_hits);
    ok(apc_status == STATUS_NOT_SUPPORTED, "apc saw %08lx", (unsigned long)apc_status);

    NtClose(s);
}

START_TEST(afd_refusal)
{
    test_unknown_code_shape();
    test_complete_async_probe();
    test_complete_async_posts_packet();
    test_complete_async_fires_apc();
}
