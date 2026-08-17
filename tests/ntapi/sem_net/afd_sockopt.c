/*
 * sem_net/afd_sockopt.c — the sockopt ioctl family Net-2 carries: one
 * get/set roundtrip per option in the get-as-output/set-as-input
 * convention (io.Information is the optlen), SO_ERROR's no-error answer,
 * SO_CONNECT_TIME's connected/unconnected split, and the SO_LINGER
 * abort-on-close path (the RST that test_get_events_reset's RESET bit
 * rides on).
 */
#include "util.h"

#define IOCTL_AFD_WINE_GET_SO_BROADCAST        WINE_AFD_IOC(220)
#define IOCTL_AFD_WINE_SET_SO_BROADCAST        WINE_AFD_IOC(221)
#define IOCTL_AFD_WINE_GET_SO_KEEPALIVE        WINE_AFD_IOC(223)
#define IOCTL_AFD_WINE_SET_SO_KEEPALIVE        WINE_AFD_IOC(224)
#define IOCTL_AFD_WINE_GET_SO_LINGER           WINE_AFD_IOC(225)
#define IOCTL_AFD_WINE_SET_SO_LINGER           WINE_AFD_IOC(226)
#define IOCTL_AFD_WINE_GET_SO_OOBINLINE        WINE_AFD_IOC(227)
#define IOCTL_AFD_WINE_SET_SO_OOBINLINE        WINE_AFD_IOC(228)
#define IOCTL_AFD_WINE_SET_SO_RCVBUF           WINE_AFD_IOC(229)
#define IOCTL_AFD_WINE_GET_SO_RCVBUF           WINE_AFD_IOC(230)
#define IOCTL_AFD_WINE_SET_SO_RCVTIMEO         WINE_AFD_IOC(231)
#define IOCTL_AFD_WINE_GET_SO_RCVTIMEO         WINE_AFD_IOC(232)
#define IOCTL_AFD_WINE_GET_SO_REUSEADDR        WINE_AFD_IOC(233)
#define IOCTL_AFD_WINE_SET_SO_REUSEADDR        WINE_AFD_IOC(234)
#define IOCTL_AFD_WINE_SET_SO_SNDBUF           WINE_AFD_IOC(235)
#define IOCTL_AFD_WINE_GET_SO_SNDBUF           WINE_AFD_IOC(236)
#define IOCTL_AFD_WINE_GET_SO_SNDTIMEO         WINE_AFD_IOC(237)
#define IOCTL_AFD_WINE_SET_SO_SNDTIMEO         WINE_AFD_IOC(238)
#define IOCTL_AFD_WINE_GET_TCP_NODELAY         WINE_AFD_IOC(284)
#define IOCTL_AFD_WINE_SET_TCP_NODELAY         WINE_AFD_IOC(285)
#define IOCTL_AFD_WINE_GET_SO_CONNECT_TIME     WINE_AFD_IOC(292)
#define IOCTL_AFD_WINE_GET_SO_EXCLUSIVEADDRUSE WINE_AFD_IOC(297)
#define IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE WINE_AFD_IOC(298)

struct afd_event_select_params
{
    HANDLE event;
    int mask;
};

struct afd_get_events_params
{
    int flags;
    int status[13];
};

typedef struct
{
    unsigned short onoff;
    unsigned short linger;
} WS_LINGER;

static NTSTATUS sockopt_set(HANDLE s, ULONG code, const void *value, ULONG length)
{
    IO_STATUS_BLOCK iosb;
    poison_iosb(&iosb);
    return NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, code, (void *)(ULONG_PTR)value, length,
                                 NULL, 0);
}

static NTSTATUS sockopt_get(HANDLE s, ULONG code, void *value, ULONG length, ULONG_PTR *lenOut)
{
    IO_STATUS_BLOCK iosb;
    poison_iosb(&iosb);
    NTSTATUS status =
        NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, code, NULL, 0, value, length);
    if (lenOut != NULL)
        *lenOut = iosb.Information;
    return status;
}

/* One int-valued option's set(1)/get roundtrip. */
static void roundtrip_int(HANDLE s, ULONG getCode, ULONG setCode, int line)
{
    int value = 1;
    ULONG_PTR length = 0;
    NTSTATUS status = sockopt_set(s, setCode, &value, sizeof(value));
    ntapi_okv(status == STATUS_SUCCESS, __FILE__, line, "set -> %08lx", (unsigned long)status);
    value = 0xcc;
    status = sockopt_get(s, getCode, &value, sizeof(value), &length);
    ntapi_okv(status == STATUS_SUCCESS, __FILE__, line, "get -> %08lx", (unsigned long)status);
    ntapi_okv(value != 0 && value != 0xcc, __FILE__, line, "roundtrip value %d", value);
    ntapi_okv(length == sizeof(value), __FILE__, line, "optlen %lu", (unsigned long)length);
}
#define ROUNDTRIP_INT(s, get, set) roundtrip_int(s, get, set, __LINE__)

static void test_bool_options(void)
{
    HANDLE client = NULL, server = NULL;

    if (!tcp_pair(&client, &server))
        return;
    ROUNDTRIP_INT(client, IOCTL_AFD_WINE_GET_SO_KEEPALIVE, IOCTL_AFD_WINE_SET_SO_KEEPALIVE);
    ROUNDTRIP_INT(client, IOCTL_AFD_WINE_GET_SO_OOBINLINE, IOCTL_AFD_WINE_SET_SO_OOBINLINE);
    ROUNDTRIP_INT(client, IOCTL_AFD_WINE_GET_SO_REUSEADDR, IOCTL_AFD_WINE_SET_SO_REUSEADDR);
    ROUNDTRIP_INT(client, IOCTL_AFD_WINE_GET_TCP_NODELAY, IOCTL_AFD_WINE_SET_TCP_NODELAY);
    /* REUSEADDR and EXCLUSIVEADDRUSE are mutually exclusive: with
     * REUSEADDR set above, the exclusive set refuses (measured — the
     * Windows contract); on a fresh socket it roundtrips. */
    {
        int one = 1;
        NTSTATUS status =
            sockopt_set(client, IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE, &one, sizeof(one));
        ok(status == STATUS_INVALID_PARAMETER, "exclusive-over-reuse -> %08lx",
           (unsigned long)status);
    }
    ROUNDTRIP_INT(server, IOCTL_AFD_WINE_GET_SO_EXCLUSIVEADDRUSE,
                  IOCTL_AFD_WINE_SET_SO_EXCLUSIVEADDRUSE);
    NtClose(client);
    NtClose(server);
}

static void test_udp_broadcast(void)
{
    HANDLE s = NULL;
    NTSTATUS status = afd_udp(&s, FALSE);
    ok(status == STATUS_SUCCESS, "udp -> %08lx", (unsigned long)status);
    ROUNDTRIP_INT(s, IOCTL_AFD_WINE_GET_SO_BROADCAST, IOCTL_AFD_WINE_SET_SO_BROADCAST);
    NtClose(s);
}

static void test_buffer_and_timeout_options(void)
{
    HANDLE client = NULL, server = NULL;
    int value;
    ULONG_PTR length;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    value = 12345;
    status = sockopt_set(client, IOCTL_AFD_WINE_SET_SO_RCVBUF, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "set rcvbuf -> %08lx", (unsigned long)status);
    value = 0;
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_RCVBUF, &value, sizeof(value), &length);
    ok(status == STATUS_SUCCESS, "get rcvbuf -> %08lx", (unsigned long)status);
    ok(value == 12345, "rcvbuf %d", value);

    value = 23456;
    status = sockopt_set(client, IOCTL_AFD_WINE_SET_SO_SNDBUF, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "set sndbuf -> %08lx", (unsigned long)status);
    value = 0;
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_SNDBUF, &value, sizeof(value), &length);
    ok(status == STATUS_SUCCESS, "get sndbuf -> %08lx", (unsigned long)status);
    ok(value == 23456, "sndbuf %d", value);

    value = 1500; /* ms */
    status = sockopt_set(client, IOCTL_AFD_WINE_SET_SO_RCVTIMEO, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "set rcvtimeo -> %08lx", (unsigned long)status);
    value = 0;
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_RCVTIMEO, &value, sizeof(value), &length);
    ok(status == STATUS_SUCCESS, "get rcvtimeo -> %08lx", (unsigned long)status);
    ok(value == 1500, "rcvtimeo %d", value);

    value = 2500;
    status = sockopt_set(client, IOCTL_AFD_WINE_SET_SO_SNDTIMEO, &value, sizeof(value));
    ok(status == STATUS_SUCCESS, "set sndtimeo -> %08lx", (unsigned long)status);
    value = 0;
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_SNDTIMEO, &value, sizeof(value), &length);
    ok(status == STATUS_SUCCESS, "get sndtimeo -> %08lx", (unsigned long)status);
    ok(value == 2500, "sndtimeo %d", value);

    NtClose(client);
    NtClose(server);
}

static void test_linger_and_error(void)
{
    WS_LINGER linger;
    HANDLE client = NULL, server = NULL;
    int value;
    ULONG_PTR length;
    NTSTATUS status;

    if (!tcp_pair(&client, &server))
        return;

    linger.onoff = 1;
    linger.linger = 7;
    status = sockopt_set(client, IOCTL_AFD_WINE_SET_SO_LINGER, &linger, sizeof(linger));
    ok(status == STATUS_SUCCESS, "set linger -> %08lx", (unsigned long)status);
    memset(&linger, 0xcc, sizeof(linger));
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_LINGER, &linger, sizeof(linger), &length);
    ok(status == STATUS_SUCCESS, "get linger -> %08lx", (unsigned long)status);
    ok(linger.onoff == 1 && linger.linger == 7, "linger {%u,%u}", linger.onoff, linger.linger);

    value = 0xcc;
    status = sockopt_get(client, IOCTL_AFD_WINE_GET_SO_ERROR, &value, sizeof(value), &length);
    ok(status == STATUS_SUCCESS, "get so_error -> %08lx", (unsigned long)status);
    ok(value == 0, "so_error %d", value);

    NtClose(client);
    NtClose(server);
}

static void test_connect_time(void)
{
    HANDLE client = NULL, server = NULL, fresh = NULL;
    unsigned int seconds;
    ULONG_PTR length;
    NTSTATUS status;

    status = afd_tcp(&fresh, FALSE);
    ok(status == STATUS_SUCCESS, "fresh -> %08lx", (unsigned long)status);
    seconds = 0;
    status =
        sockopt_get(fresh, IOCTL_AFD_WINE_GET_SO_CONNECT_TIME, &seconds, sizeof(seconds), &length);
    ok(status == STATUS_SUCCESS, "unconnected connect-time -> %08lx", (unsigned long)status);
    ok(seconds == 0xffffffff, "unconnected connect-time %u", seconds);
    NtClose(fresh);

    if (!tcp_pair(&client, &server))
        return;
    seconds = 0xcccccccc;
    status =
        sockopt_get(client, IOCTL_AFD_WINE_GET_SO_CONNECT_TIME, &seconds, sizeof(seconds), &length);
    ok(status == STATUS_SUCCESS, "connected connect-time -> %08lx", (unsigned long)status);
    ok(seconds < 60, "connected connect-time %u", seconds);
    NtClose(client);
    NtClose(server);
}

/* The linger-zero close aborts (RST) — and the peer's armed event mask
 * reports it as AFD_POLL_RESET (ws2_32:afd test_get_events_reset's
 * close_with_rst shape, both halves in one deterministic case). */
static void test_rst_reports_reset(void)
{
    struct afd_event_select_params select;
    struct afd_get_events_params events;
    WS_LINGER linger;
    IO_STATUS_BLOCK iosb;
    HANDLE client = NULL, server = NULL, event;
    unsigned i;
    NTSTATUS status;

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!tcp_pair(&client, &server))
        return;

    select.event = event;
    select.mask = AFD_POLL_ACCEPT | AFD_POLL_CLOSE | AFD_POLL_OOB | AFD_POLL_READ | AFD_POLL_RESET |
                  AFD_POLL_HUP;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_EVENT_SELECT, &select,
                                   sizeof(select), NULL, 0);
    ok(status == STATUS_SUCCESS, "select -> %08lx", (unsigned long)status);

    linger.onoff = 1;
    linger.linger = 0;
    status = sockopt_set(server, IOCTL_AFD_WINE_SET_SO_LINGER, &linger, sizeof(linger));
    ok(status == STATUS_SUCCESS, "set linger-zero -> %08lx", (unsigned long)status);
    NtClose(server); /* the abortive close: RST on the wire */

    ok(wait_done(event), "the RST never fired the event");
    memset(&events, 0xcc, sizeof(events));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(client, NULL, NULL, NULL, &iosb, IOCTL_AFD_GET_EVENTS, NULL, 0,
                                   &events, sizeof(events));
    ok(status == STATUS_SUCCESS, "get-events -> %08lx", (unsigned long)status);
    ok(events.flags == AFD_POLL_RESET, "flags %#x", events.flags);
    for (i = 0; i < 13; i++)
        ok(events.status[i] == 0, "status[%u] %#x", i, events.status[i]);

    NtClose(client);
    CloseHandle(event);
}

START_TEST(afd_sockopt)
{
    test_bool_options();
    test_udp_broadcast();
    test_buffer_and_timeout_options();
    test_linger_and_error();
    test_connect_time();
    test_rst_reports_reset();
}
