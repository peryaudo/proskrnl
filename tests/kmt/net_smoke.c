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
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h" /* KPROCESSOR_MODE for the delay park */
#include "kernel/lib/string.h"

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

int kmt_run_net(void)
{
    if (!VioNetIsPresent())
    {
        return 0; /* not a net image (the fat_interop precedent) */
    }
    int before = kmt_failures;
    KMT_RUN(test_net_mac_and_transmit);
    return kmt_failures - before;
}
