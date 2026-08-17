/* drivers/net/netd.h — the lwIP stack's bring-up and its one mainloop
 * thread (Net-1, docs/24 §4b; see netd.c).
 *
 * The public surface deliberately carries no lwIP types: everything above
 * this header is NT-styled kernel code, and the raw API stays inside
 * drivers/net/ until Net-2's AFD device consumes it there.
 */
#ifndef PROSKRNL_DRIVERS_NET_NETD_H
#define PROSKRNL_DRIVERS_NET_NETD_H

#include "abi/ntdef.h"

/* Bring-up (kernel/init/main.c, after CmInitialize and the boot-volume
 * mount — deliberately later than the pre-freeze device probe, docs/24
 * §4b): lwip_init, the ethernet netif over drivers/virtio/net.c, DHCP
 * (or the static fallback knob), and the netd thread. Quietly does
 * nothing when no NIC exists — every image but the net leg's. */
void NetInitialize(void);
BOOLEAN NetIsUp(void);

/* TRUE once a DHCP lease is bound (and its registry values written). */
BOOLEAN NetDhcpBound(void);

/* The bound IPv4 address as a dotted quad (the [KTEST] net dhcp line's
 * spelling); out must hold 16 chars. Valid once NetDhcpBound(). */
void NetBoundAddressString(char out[16]);

/* The adapter's registry key below
 * \Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces,
 * for the kmt lease check. Valid once NetIsUp(). */
PCWSTR NetAdapterKeyName(void);

/* The Net-1 in-kernel TCP echo (docs/24 §6b): connect to the harness's
 * echo server on slirp's host alias, send `payload`, wait for it to come
 * back. Returns STATUS_SUCCESS with the echoed bytes in `echo`
 * (*echoedLength set), STATUS_IO_TIMEOUT when the exchange never
 * completes inside the generous guest-clocked bound, or an error. kmt
 * only — nothing ring-3 reaches this (the boundary arrives at Net-2). */
NTSTATUS NetEchoSmoke(ULONG hostPort, const void *payload, ULONG payloadLength, void *echo,
                      ULONG echoCapacity, ULONG *echoedLength);

/* The docs/24 §6e verdict numbers: one [KTEST] net stats line with frame
 * counts, the loud-drop counters, and the pool high-water marks. */
void NetPrintKtestStats(void);

#endif /* PROSKRNL_DRIVERS_NET_NETD_H */
