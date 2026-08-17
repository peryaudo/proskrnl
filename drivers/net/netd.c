/* drivers/net/netd.c — the lwIP stack and its one thread (Net-1, docs/24
 * §4b; see netd.h, drivers/net/port/, drivers/virtio/net.c).
 *
 * The pinned lwIP (third_party/lwip, docs/11's second admission) runs in
 * NO_SYS mainloop mode — Article 3's machine (docs/24 §3c) — driven by the
 * netd kernel thread below: park on the driver's work event with a timeout
 * derived from lwIP's next-due timer; on wake, feed staged receive frames
 * to netif->input (pbuf allocation happens HERE, in thread context, from
 * lwIP's static pools — never in the drain), service the loopback queue,
 * run sys_check_timeouts, and let transmissions flow out through
 * linkoutput. netd's park is a declared blocking point:
 * tools/blocking_frontier.txt carries NetdThreadMain (G14), and docs/20
 * §8.4's re-check for it is recorded there.
 *
 * THE SINGLE-THREADING INVARIANT (docs/24 §4b, stated once and asserted):
 * lwIP is entered from exactly two contexts — netd, and kernel-thread
 * "syscall context" callers (today the kmt echo; Net-2's AFD verbs take
 * that seat) — and never from the drain or any interrupt path; no code
 * path blocks while inside lwIP. Under Article 3's machine (no kernel
 * preemption, uniprocessor) those two contexts therefore never interleave
 * inside the stack: atomic under the no-preemption model. The
 * NetdInsideLwip flag is asserted at every entry seam below. CUI-10's
 * giant lock preserves the invariant verbatim — a thread holds the lock
 * for its whole kernel visit — and this paragraph is the row docs/18 §5's
 * audit re-checks when that day comes.
 */
#include "drivers/net/netd.h"
#include "drivers/afd.h" /* Net-2: the parked-poll deadline + expiry tick */
#include "drivers/virtio/net.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE */
#include "kernel/cm/cm.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "abi/ntstatus.h"
#include "abi/ntregapi.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/timeouts.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/stats.h"
#include "netif/ethernet.h"

static struct netif NetdNetif;
static BOOLEAN NetdUp;
static BOOLEAN NetdStaticConfig;
static BOOLEAN NetdDhcpBoundOnce;
static volatile BOOLEAN NetdLeaseDirty;
static ULONG NetdRxPbufDrops; /* pbuf pool exhausted at input: loud, counted */

/* The mainloop's park target — netd's own (Net-2): the drain wakes it
 * through VioNetSetWakeEvent when a NIC exists, and any syscall-context
 * lwIP caller wakes it through NetdWake so queued output (loopback frames
 * included) gets serviced promptly on an image with no NIC at all. */
static KEVENT NetdWorkEvent;

void NetdWake(void)
{
    KeSetEvent(&NetdWorkEvent, 0, FALSE);
}

/* The invariant flag (header comment). volatile: read/written across the
 * two entry contexts. Non-static since Net-2: the AFD device is the
 * second syscall-context entry seam and asserts through these. */
static volatile BOOLEAN NetdInsideLwip;

void NetdEnterLwip(void)
{
    ASSERT(!NetdInsideLwip);
    NetdInsideLwip = TRUE;
}

void NetdLeaveLwip(void)
{
    ASSERT(NetdInsideLwip);
    NetdInsideLwip = FALSE;
}

/* --- the wire (drivers/virtio/net.c below, lwIP above) --------------------- */

static err_t NetdLinkOutput(struct netif *netif, struct pbuf *p)
{
    (void)netif;
    unsigned char frame[VIO_NET_MAX_FRAME];
    if (p->tot_len > sizeof(frame))
    {
        return ERR_IF;
    }
    pbuf_copy_partial(p, frame, p->tot_len, 0);
    /* A refused transmit (every bounce slot in flight) is the driver's
     * loud counted drop; ERR_IF lets the stack's own retransmission
     * machinery own the recovery — never a wait (docs/24 §4a/§4b). */
    return VioNetTransmitFrame(frame, p->tot_len) ? ERR_OK : ERR_IF;
}

static err_t NetdNetifInit(struct netif *netif)
{
    netif->name[0] = 'e';
    netif->name[1] = 'n';
    netif->mtu = 1500; /* untagged Ethernet; no VIRTIO_NET_F_MTU is negotiated */
    netif->hwaddr_len = VIO_NET_MAC_BYTES;
    memcpy(netif->hwaddr, VioNetMacAddress(), VIO_NET_MAC_BYTES);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    netif->output = etharp_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = NetdLinkOutput;
    return ERR_OK;
}

/* The lease latch (docs/24 §4b): the callback runs INSIDE lwIP on netd, so
 * it only marks state dirty — the registry write (file I/O, a park)
 * happens back in the mainloop, outside the stack. */
static void NetdStatusCallback(struct netif *netif)
{
    (void)netif;
    NetdLeaseDirty = TRUE;
}

/* --- the DHCP lease, surfaced the NT way (docs/24 §4b) --------------------- */

/* The adapter key: real Windows mints a random setup-time GUID per
 * adapter; this kernel derives one deterministically from the device's
 * MAC (the node field carries it, v1-GUID style). Internal decision —
 * the *name* of an adapter key is machine state no oracle pins, only the
 * value names under it are (below). */
static WCHAR NetdAdapterKeyName[40];

static void NetdFormatAdapterKeyName(void)
{
    static const WCHAR hex[] = WSTR("0123456789abcdef");
    const uint8_t *mac = VioNetMacAddress();
    static const WCHAR prefix[] = WSTR("{50524f53-4b52-4e4c-8000-");
    ULONG at = 0;
    for (ULONG i = 0; prefix[i] != 0; i++)
    {
        NetdAdapterKeyName[at++] = prefix[i];
    }
    for (ULONG i = 0; i < VIO_NET_MAC_BYTES; i++)
    {
        NetdAdapterKeyName[at++] = hex[mac[i] >> 4];
        NetdAdapterKeyName[at++] = hex[mac[i] & 0xF];
    }
    NetdAdapterKeyName[at++] = '}';
    NetdAdapterKeyName[at] = 0;
}

PCWSTR NetAdapterKeyName(void)
{
    return NetdAdapterKeyName;
}

/* Dotted-quad formatters for the registry strings and the [KTEST] line.
 * `addr` is the ip4_addr_t word (network byte order). */
static ULONG NetdFormatIp4Char(char out[16], uint32_t addr)
{
    const uint8_t *b = (const uint8_t *)&addr;
    ULONG at = 0;
    for (ULONG i = 0; i < 4; i++)
    {
        uint8_t v = b[i];
        if (v >= 100)
        {
            out[at++] = (char)('0' + v / 100);
        }
        if (v >= 10)
        {
            out[at++] = (char)('0' + (v / 10) % 10);
        }
        out[at++] = (char)('0' + v % 10);
        if (i != 3)
        {
            out[at++] = '.';
        }
    }
    out[at] = 0;
    return at;
}

static ULONG NetdFormatIp4Wide(WCHAR out[16], uint32_t addr)
{
    char narrow[16];
    ULONG length = NetdFormatIp4Char(narrow, addr);
    for (ULONG i = 0; i <= length; i++)
    {
        out[i] = (WCHAR)narrow[i];
    }
    return length;
}

/* One REG value under the adapter key, through the ordinary boundary path
 * (Art. 11: the same NtSetValueKey engine ring 3 uses — hive persistence
 * and change-notify come with it, and no second write path exists to
 * drift). Kernel threads run with the system process's handle table, the
 * CmInitialize hive-load precedent. */
static void NetdSetLeaseValue(HANDLE key, PCWSTR name, ULONG type, const WCHAR *data, ULONG bytes)
{
    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, name);
    NTSTATUS status = NtSetValueKey(key, &valueName, 0, type, data, bytes);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("netd: lease value write failed %08lx\n", (unsigned long)status);
    }
}

/* Write (or rewrite, on renewal) the lease under
 * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<adapter>
 * in the value names real Windows uses — DhcpIPAddress, DhcpSubnetMask
 * (REG_SZ), DhcpDefaultGateway (REG_MULTI_SZ), DhcpNameServer (REG_SZ,
 * space-separated), DhcpServer (REG_SZ) — MS-documented: "TCP/IP and NBT
 * configuration parameters for Windows" (KB 314053), per-interface
 * Dhcp* values under Services\Tcpip\Parameters\Interfaces\<adapter-GUID>
 * (G8). Nothing is baked: under slirp these arrive from the DHCP wire
 * like anywhere else, and Net-3's resolver reads the registry rather
 * than knowing an address. */
static void NetdPublishLease(void)
{
    if (!dhcp_supplied_address(&NetdNetif))
    {
        return; /* the callback also fires for link/addr transitions pre-bind */
    }

    /* Intermediate "Interfaces" first: NtCreateKey creates only the final
     * component (NT semantics; Tcpip\Parameters itself is a seeded
     * skeleton key). */
    static const WCHAR interfacesPath[] =
        WSTR("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
             "\\Interfaces");
    WCHAR adapterPath[sizeof(interfacesPath) / sizeof(WCHAR) + 41];
    ULONG at = 0;
    for (ULONG i = 0; interfacesPath[i] != 0; i++)
    {
        adapterPath[at++] = interfacesPath[i];
    }
    adapterPath[at++] = '\\';
    for (ULONG i = 0; NetdAdapterKeyName[i] != 0; i++)
    {
        adapterPath[at++] = NetdAdapterKeyName[i];
    }
    adapterPath[at] = 0;

    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING path;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &path;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE handle;
    RtlInitUnicodeString(&path, interfacesPath);
    NTSTATUS status = NtCreateKey(&handle, KEY_ALL_ACCESS, &attributes, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("netd: Interfaces key create failed %08lx\n", (unsigned long)status);
        return;
    }
    NtClose(handle);
    RtlInitUnicodeString(&path, adapterPath);
    status = NtCreateKey(&handle, KEY_ALL_ACCESS, &attributes, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("netd: adapter key create failed %08lx\n", (unsigned long)status);
        return;
    }

    WCHAR text[64];
    ULONG length;

    length = NetdFormatIp4Wide(text, ip4_addr_get_u32(netif_ip4_addr(&NetdNetif)));
    NetdSetLeaseValue(handle, WSTR("DhcpIPAddress"), REG_SZ, text, (length + 1) * sizeof(WCHAR));

    length = NetdFormatIp4Wide(text, ip4_addr_get_u32(netif_ip4_netmask(&NetdNetif)));
    NetdSetLeaseValue(handle, WSTR("DhcpSubnetMask"), REG_SZ, text, (length + 1) * sizeof(WCHAR));

    /* MULTI_SZ: the one gateway, then the list terminator. */
    length = NetdFormatIp4Wide(text, ip4_addr_get_u32(netif_ip4_gw(&NetdNetif)));
    text[length + 1] = 0;
    NetdSetLeaseValue(handle, WSTR("DhcpDefaultGateway"), REG_MULTI_SZ, text,
                      (length + 2) * sizeof(WCHAR));

    const struct dhcp *dhcp = netif_dhcp_data(&NetdNetif);
    if (dhcp != 0)
    {
        length = NetdFormatIp4Wide(text, ip4_addr_get_u32(ip_2_ip4(&dhcp->server_ip_addr)));
        NetdSetLeaseValue(handle, WSTR("DhcpServer"), REG_SZ, text, (length + 1) * sizeof(WCHAR));
    }

    /* DHCP option 6 landed in the DNS module's server list (lwipopts.h:
     * LWIP_DNS is compiled for exactly this bookkeeping). Space-separated,
     * the documented DhcpNameServer spelling. */
    at = 0;
    for (u8_t i = 0; i < DNS_MAX_SERVERS; i++)
    {
        const ip_addr_t *server = dns_getserver(i);
        if (ip_addr_isany(server) || !IP_IS_V4(server))
        {
            continue;
        }
        if (at != 0)
        {
            text[at++] = ' ';
        }
        at += NetdFormatIp4Wide(text + at, ip4_addr_get_u32(ip_2_ip4(server)));
    }
    if (at != 0)
    {
        NetdSetLeaseValue(handle, WSTR("DhcpNameServer"), REG_SZ, text, (at + 1) * sizeof(WCHAR));
    }
    NtClose(handle);

    if (!NetdDhcpBoundOnce)
    {
        char address[16];
        NetdFormatIp4Char(address, ip4_addr_get_u32(netif_ip4_addr(&NetdNetif)));
        DbgPrint("[KTEST] net dhcp %s\n", address);
        NetdDhcpBoundOnce = TRUE;
    }
}

BOOLEAN NetDhcpBound(void)
{
    return NetdDhcpBoundOnce;
}

void NetBoundAddressString(char out[16])
{
    ASSERT(NetdUp);
    NetdFormatIp4Char(out, ip4_addr_get_u32(netif_ip4_addr(&NetdNetif)));
}

/* --- the mainloop ----------------------------------------------------------- */

static void NetdThreadMain(void *context)
{
    (void)context;
    for (;;)
    {
        NetdEnterLwip();
        u32_t sleepMs = sys_timeouts_sleeptime();
        NetdLeaveLwip();

        /* Net-2: the nearest parked AFD poll deadline bounds the park
         * too, so an IOCTL_AFD_POLL timeout fires without waiting for
         * unrelated traffic (drivers/afd.c AfdPollTick below). */
        ULONG pollMs = AfdNextPollDelayMs();
        if (pollMs != 0xffffffffu &&
            (sleepMs == SYS_TIMEOUTS_SLEEPTIME_INFINITE || pollMs < sleepMs))
        {
            sleepMs = pollMs;
        }

        /* The park — netd's declared blocking point (G14; the frontier
         * row). Timeout from lwIP's own next-due timer, so protocol time
         * (DHCP retransmits, TCP timers) advances with no work event. */
        if (sleepMs != 0)
        {
            LARGE_INTEGER timeout;
            PLARGE_INTEGER timeoutArg = 0;
            if (sleepMs != SYS_TIMEOUTS_SLEEPTIME_INFINITE)
            {
                timeout.QuadPart = -(LONGLONG)sleepMs * 10000;
                timeoutArg = &timeout;
            }
            KeWaitForSingleObject(&NetdWorkEvent, Executive, KernelMode, FALSE, timeoutArg);
        }
        /* Clear BEFORE consuming: a frame the drain stages after the pop
         * loop below re-sets the event and the next lap sees it. */
        KeClearEvent(&NetdWorkEvent);

        NetdEnterLwip();
        unsigned char frame[VIO_NET_MAX_FRAME];
        uint32_t length;
        while (NetdUp && VioNetPopReceivedFrame(frame, &length))
        {
            /* pbuf allocation happens here, in thread context, from the
             * static pools — the drain allocated nothing (docs/24 §4a).
             * Exhaustion is a loud counted drop, never a kernel OOM
             * (docs/24 §3c). */
            struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_POOL);
            if (p == 0)
            {
                NetdRxPbufDrops++;
                continue;
            }
            pbuf_take(p, frame, (u16_t)length);
            if (NetdNetif.input(p, &NetdNetif) != ERR_OK)
            {
                pbuf_free(p);
            }
        }
        sys_check_timeouts();
        netif_poll_all(); /* the loopback interface's queued frames */
        NetdLeaveLwip();

        /* Outside the stack (completions touch no pcb): expire due AFD
         * polls, then the lease write, which parks (registry/hive I/O) —
         * no code path blocks while inside lwIP. */
        AfdPollTick();
        if (NetdLeaseDirty)
        {
            NetdLeaseDirty = FALSE;
            NetdPublishLease();
        }
    }
}

/* --- bring-up ---------------------------------------------------------------- */

BOOLEAN NetIsUp(void)
{
    return NetdUp;
}

void NetInitialize(void)
{
    /* Net-2: the stack (loopback interface included) comes up on EVERY
     * image — \Device\Afd serves 127.0.0.1 sockets with no NIC at all
     * (docs/24 §5: the boundary is device-free over loopback). Only the
     * ethernet netif, DHCP, and the lease depend on the probed NIC. */
    KeInitializeEvent(&NetdWorkEvent, NotificationEvent, FALSE);

    BOOLEAN wire = VioNetIsPresent();
    NetdEnterLwip();
    lwip_init(); /* LWIP_HAVE_LOOPIF: the 127.0.0.1 loop netif is born here */
    if (wire && netif_add(&NetdNetif, 0, 0, 0, 0, NetdNetifInit, netif_input) == 0)
    {
        DbgPrint("netd: netif_add failed; wire not started\n");
        wire = FALSE;
    }
    if (wire)
    {
        netif_set_default(&NetdNetif);
        netif_set_status_callback(&NetdNetif, NetdStatusCallback);
        /* Dual-stack from day one (docs/24 §5): the v6 link-local address
         * exercises the compiled-in v6 core; the v6 SOCKET surface stays
         * staged until its own pins exist. */
        netif_create_ip6_linklocal_address(&NetdNetif, 1);
        netif_set_up(&NetdNetif);

        /* The static-configuration fallback knob (docs/24 §4b), off by
         * default: a leg that wants no DHCP dependency passes
         * -fw_cfg opt/org.proskrnl/netstatic and gets slirp's own fixed
         * client address — 10.0.2.15/24, gateway 10.0.2.2 (pinned QEMU
         * docs/system/devices/net.rst, "Using the user mode network
         * stack") — with no lease and no Dhcp* registry values. */
        NetdStaticConfig = CmQueryQemuBootFlag(WSTR("NetStatic"), 0) != 0;
        if (NetdStaticConfig)
        {
            ip4_addr_t address, netmask, gateway;
            IP4_ADDR(&address, 10, 0, 2, 15);
            IP4_ADDR(&netmask, 255, 255, 255, 0);
            IP4_ADDR(&gateway, 10, 0, 2, 2);
            netif_set_addr(&NetdNetif, &address, &netmask, &gateway);
            DbgPrint("[KTEST] net static 10.0.2.15\n");
        }
        else
        {
            dhcp_start(&NetdNetif);
        }
    }
    NetdLeaveLwip();

    if (wire)
    {
        NetdFormatAdapterKeyName();
        VioNetSetWakeEvent(&NetdWorkEvent);
        VioNetSetReceiveConsumerLive(TRUE);
        NetdUp = TRUE;
    }
    if (KiCreateThread(8, NetdThreadMain, 0) == 0)
    {
        KiPanic("netd: thread creation failed");
    }
    DbgPrint("netd: stack up (%s)\n",
             !wire ? "loopback only" : (NetdStaticConfig ? "static" : "dhcp"));
}

/* --- the kmt echo (docs/24 §6b) ---------------------------------------------- */

typedef struct
{
    struct tcp_pcb *pcb;
    const void *payload;
    ULONG payloadLength;
    uint8_t *echo;
    ULONG echoCapacity;
    ULONG received;
    NTSTATUS result;
    KEVENT done;
} NETD_ECHO;

static void NetdEchoFinish(NETD_ECHO *echo, NTSTATUS result)
{
    if (echo->pcb != 0)
    {
        tcp_arg(echo->pcb, 0);
        tcp_recv(echo->pcb, 0);
        tcp_err(echo->pcb, 0);
        if (tcp_close(echo->pcb) != ERR_OK)
        {
            tcp_abort(echo->pcb);
        }
        echo->pcb = 0;
    }
    echo->result = result;
    KeSetEvent(&echo->done, 0, FALSE);
}

static err_t NetdEchoConnected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    NETD_ECHO *echo = arg;
    (void)err; /* ERR_OK by contract; failures arrive at the err callback */
    if (tcp_write(pcb, echo->payload, (u16_t)echo->payloadLength, TCP_WRITE_FLAG_COPY) != ERR_OK)
    {
        NetdEchoFinish(echo, STATUS_INSUFFICIENT_RESOURCES);
        return ERR_OK;
    }
    tcp_output(pcb);
    return ERR_OK;
}

static err_t NetdEchoRecv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    NETD_ECHO *echo = arg;
    (void)err;
    if (p == 0)
    {
        /* Remote close before the full echo came back. */
        NetdEchoFinish(echo, STATUS_CONNECTION_RESET);
        return ERR_OK;
    }
    ULONG take = p->tot_len;
    if (take > echo->echoCapacity - echo->received)
    {
        take = echo->echoCapacity - echo->received;
    }
    pbuf_copy_partial(p, echo->echo + echo->received, (u16_t)take, 0);
    echo->received += take;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    if (echo->received >= echo->payloadLength)
    {
        NetdEchoFinish(echo, STATUS_SUCCESS);
    }
    return ERR_OK;
}

static void NetdEchoError(void *arg, err_t err)
{
    NETD_ECHO *echo = arg;
    (void)err;
    echo->pcb = 0; /* lwIP already freed it (tcp_err contract) */
    NetdEchoFinish(echo, STATUS_CONNECTION_REFUSED);
}

NTSTATUS NetEchoSmoke(ULONG hostPort, const void *payload, ULONG payloadLength, void *echoBuffer,
                      ULONG echoCapacity, ULONG *echoedLength)
{
    ASSERT(NetdUp);
    NETD_ECHO echo;
    memset(&echo, 0, sizeof(echo));
    echo.payload = payload;
    echo.payloadLength = payloadLength;
    echo.echo = echoBuffer;
    echo.echoCapacity = echoCapacity;
    echo.result = STATUS_PENDING;
    KeInitializeEvent(&echo.done, NotificationEvent, FALSE);

    /* The second lwIP entry context (the invariant comment above): issue
     * the connect here; every callback completes on netd. */
    NetdEnterLwip();
    echo.pcb = tcp_new();
    err_t err = ERR_MEM;
    if (echo.pcb != 0)
    {
        tcp_arg(echo.pcb, &echo);
        tcp_recv(echo.pcb, NetdEchoRecv);
        tcp_err(echo.pcb, NetdEchoError);
        /* 10.0.2.2: slirp's alias for the host (pinned QEMU
         * docs/system/devices/net.rst, "Using the user mode network
         * stack") — where the harness's echo server listens. */
        ip_addr_t host;
        IP_ADDR4(&host, 10, 0, 2, 2);
        err = tcp_connect(echo.pcb, &host, (u16_t)hostPort, NetdEchoConnected);
        if (err != ERR_OK)
        {
            tcp_abort(echo.pcb);
            echo.pcb = 0;
        }
    }
    NetdLeaveLwip();
    if (err != ERR_OK)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Generous and guest-clocked — the verdict is the echoed content,
     * never timing (docs/19 §11c). */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30LL * 10000000; /* 30 s relative */
    NTSTATUS wait = KeWaitForSingleObject(&echo.done, Executive, KernelMode, FALSE, &timeout);
    if (wait == STATUS_TIMEOUT)
    {
        NetdEnterLwip();
        NetdEchoFinish(&echo, STATUS_IO_TIMEOUT);
        NetdLeaveLwip();
        KeWaitForSingleObject(&echo.done, Executive, KernelMode, FALSE, 0);
        *echoedLength = echo.received;
        return STATUS_IO_TIMEOUT;
    }
    *echoedLength = echo.received;
    return echo.result;
}

void NetPrintKtestStats(void)
{
    VIO_NET_STATS stats;
    VioNetQueryStats(&stats);
    ULONG pended = 0;
    ULONG syncParks = 0;
    ULONG refused = 0;
    AfdQueryStats(&pended, &syncParks, &refused);
    /* The docs/24 §6e discipline: the win is a verdict — counters as
     * numbers, floors where they make sense (the net leg asserts
     * rx/tx > 0, excluding a loopback-only implementation; the proskrnl
     * ntapi leg asserts pended > 0, excluding an inline-only one — both
     * inert shapes pass every semantic test), recorded facts where they
     * do not (drops, retransmits, high-water marks). rexmit is lwIP's
     * own MIB2 count (lwipopts.h MIB2_STATS). */
    DbgPrint("[KTEST] net stats rx=%lu tx=%lu rxdrops=%lu txdrops=%lu staged_hw=%lu "
             "pbufdrops=%lu heap_hw=%lu pbufpool_hw=%lu pended=%lu syncparks=%lu refused=%lu "
             "rexmit=%lu\n",
             (unsigned long)stats.rxFrames, (unsigned long)stats.txFrames,
             (unsigned long)stats.rxStagedDrops, (unsigned long)stats.txSlotDrops,
             (unsigned long)stats.rxStagedHighWater, (unsigned long)NetdRxPbufDrops,
             (unsigned long)lwip_stats.mem.max, (unsigned long)lwip_stats.memp[MEMP_PBUF_POOL]->max,
             (unsigned long)pended, (unsigned long)syncParks, (unsigned long)refused,
             (unsigned long)lwip_stats.mib2.tcpretranssegs);
}
