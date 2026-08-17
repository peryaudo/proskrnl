/* tests/kmt/net_smoke.c — the Net-1 device verdicts (docs/24 §6b/§6g).
 *
 * The driver's internals have no oracle (like Fb0, like snd): the wire is
 * the verdict, and the run.sh net leg reads it from the filter-dump pcap
 * QEMU's own device model writes — never from the kernel's account of
 * itself (Art. 6). This suite's job is the kernel half of that
 * cross-check: report the device's MAC on serial ([KTEST] net mac) so the
 * harness can assert the same address appears as the Ethernet source in
 * the pcap, and put one distinctive frame on the wire so the pcap has
 * content to find.
 *
 * Runs only when a NIC exists (the net leg's image); silently absent
 * everywhere else — the fat_interop shape, so no other leg's [KTEST]
 * stream moves.
 */
#include "tests/kmt/kmt.h"
#include "drivers/virtio/net.h"
#include "drivers/net/netd.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE for the delay park */
#include "kernel/cm/cm.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "abi/ntstatus.h"
#include "abi/ntregapi.h"

/* One hand-built broadcast frame: IEEE 802 local-experimental ethertype
 * 0x88B5 (IEEE 802 registry, reserved for private experiments — nothing
 * on a slirp segment speaks it), a payload the pcap assertion greps for
 * bytewise. */
#define NET_SMOKE_ETHERTYPE_HI 0x88
#define NET_SMOKE_ETHERTYPE_LO 0xB5
static const char net_smoke_payload[] = "proskrnl-net-smoke";

static void test_net_mac_and_transmit(void)
{
    const uint8_t *mac = VioNetMacAddress();
    /* The harness's serial<->wire cross-check anchor. */
    DbgPrint("[KTEST] net mac %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3],
             mac[4], mac[5]);

    unsigned char frame[14 + sizeof(net_smoke_payload)];
    memset(frame, 0xFF, 6); /* broadcast destination */
    memcpy(frame + 6, mac, 6);
    frame[12] = NET_SMOKE_ETHERTYPE_HI;
    frame[13] = NET_SMOKE_ETHERTYPE_LO;
    memcpy(frame + 14, net_smoke_payload, sizeof(net_smoke_payload));

    ok(VioNetTransmitFrame(frame, sizeof(frame)) == 1, "smoke frame refused a transmit slot");

    /* The completion round trip: the tick-tail drain (1 ms bound, docs/19
     * §11f) harvests the transmit and counts it. Guest-clocked and
     * generous — content, never timing (docs/19 §11c). */
    VIO_NET_STATS stats;
    for (int spins = 0; spins < 1000; spins++)
    {
        VioNetQueryStats(&stats);
        if (stats.txFrames >= 1)
        {
            break;
        }
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms relative */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    VioNetQueryStats(&stats);
    ok(stats.txFrames >= 1, "smoke frame never completed (txFrames=%u)", (unsigned)stats.txFrames);
    ok(stats.txSlotDrops == 0, "transmit dropped (txSlotDrops=%u)", (unsigned)stats.txSlotDrops);
}

static void delay_ms(int ms)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)ms * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/* DHCP binds against slirp's built-in server; the lease lands in the
 * Windows registry values; the in-kernel echo round-trips the harness's
 * server on the host alias. Bounds are guest-clocked and generous — every
 * verdict below is content (docs/19 §11c). */
static void test_net_dhcp_echo_lease(void)
{
    /* Up to 60 s of guest time for the DHCP exchange (typically well
     * under a second against slirp; TCG on a loaded runner is why the
     * bound is generous). */
    for (int spins = 0; spins < 600 && !NetDhcpBound(); spins++)
    {
        delay_ms(100);
    }
    ok(NetDhcpBound(), "dhcp never bound");
    if (!NetDhcpBound())
    {
        return;
    }

    char bound[16];
    NetBoundAddressString(bound);

    /* The lease check: the registry answer through the ordinary boundary
     * read path must match the stack's own idea of the address. */
    static const WCHAR interfaces[] =
        WSTR("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
             "\\Interfaces");
    WCHAR adapterPath[sizeof(interfaces) / sizeof(WCHAR) + 41];
    ULONG at = 0;
    for (ULONG i = 0; interfaces[i] != 0; i++)
    {
        adapterPath[at++] = interfaces[i];
    }
    adapterPath[at++] = '\\';
    PCWSTR keyName = NetAdapterKeyName();
    for (ULONG i = 0; keyName[i] != 0; i++)
    {
        adapterPath[at++] = keyName[i];
    }
    adapterPath[at] = 0;

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, adapterPath);
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &path;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE key = 0;
    NTSTATUS status = NtOpenKey(&key, KEY_QUERY_VALUE, &attributes);
    ok(status == STATUS_SUCCESS, "adapter lease key open failed %08x", (unsigned)status);
    if (status == STATUS_SUCCESS)
    {
        UNICODE_STRING valueName;
        RtlInitUnicodeString(&valueName, WSTR("DhcpIPAddress"));
        unsigned char buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 32 * sizeof(WCHAR)];
        DWORD resultLength = 0;
        status = NtQueryValueKey(key, &valueName, KeyValuePartialInformation, buffer,
                                 sizeof(buffer), &resultLength);
        ok(status == STATUS_SUCCESS, "DhcpIPAddress query failed %08x", (unsigned)status);
        if (status == STATUS_SUCCESS)
        {
            const KEY_VALUE_PARTIAL_INFORMATION *info = (const void *)buffer;
            ok(info->Type == REG_SZ, "DhcpIPAddress type %u", (unsigned)info->Type);
            const WCHAR *value = (const WCHAR *)info->Data;
            int match = 1;
            ULONG i = 0;
            for (; bound[i] != 0; i++)
            {
                if (value[i] != (WCHAR)bound[i])
                {
                    match = 0;
                    break;
                }
            }
            if (match && value[i] != 0)
            {
                match = 0;
            }
            ok(match, "DhcpIPAddress does not match the bound address %s", bound);
            if (match)
            {
                DbgPrint("[KTEST] net lease PASS\n");
            }
        }
        NtClose(key);
    }

    /* The echo (docs/24 §6b): only when the leg said where the server
     * listens. Its absence is a decision the boot flag records, not a
     * silent skip — the run.sh net leg always passes the port. */
    ULONG port = CmQueryQemuBootFlag(WSTR("NetEchoPort"), 0);
    if (port == 0)
    {
        DbgPrint("kmt: net echo skipped (no NetEchoPort boot flag)\n");
    }
    else
    {
        static const char payload[] = "proskrnl-net-echo-payload-0123456789";
        char echoed[sizeof(payload)];
        ULONG echoedLength = 0;
        status =
            NetEchoSmoke(port, payload, sizeof(payload) - 1, echoed, sizeof(echoed), &echoedLength);
        ok(status == STATUS_SUCCESS, "echo failed %08x", (unsigned)status);
        ok(echoedLength == sizeof(payload) - 1, "echo length %u", (unsigned)echoedLength);
        ok(echoedLength == sizeof(payload) - 1 && memcmp(echoed, payload, echoedLength) == 0,
           "echo payload mismatch");
        if (status == STATUS_SUCCESS && echoedLength == sizeof(payload) - 1 &&
            memcmp(echoed, payload, echoedLength) == 0)
        {
            DbgPrint("[KTEST] net echo PASS\n");
        }
    }
}

int kmt_run_net(void)
{
    if (!VioNetIsPresent())
    {
        return 0; /* not a net image (the fat_interop precedent) */
    }
    int before = kmt_failures;
    KMT_RUN(test_net_mac_and_transmit);
    if (NetIsUp())
    {
        KMT_RUN(test_net_dhcp_echo_lease);
    }
    NetPrintKtestStats();
    return kmt_failures - before;
}
