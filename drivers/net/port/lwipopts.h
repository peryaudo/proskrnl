/* drivers/net/port/lwipopts.h — the pinned lwIP's configuration (Net-1,
 * docs/24 §3c/§4b).
 *
 * This file is lwIP's own documented user-supplied configuration surface —
 * a port, not a patch (docs/11; the submodule carries zero local commits).
 * Port files follow lwIP's naming conventions, exempt from docs/15 the way
 * tests are.
 *
 * The posture is docs/24 §3c: NO_SYS mainloop mode is Article 3's machine
 * (uniprocessor, one dispatcher lock, no kernel preemption — the
 * single-threading invariant is stated and asserted in drivers/net/netd.c),
 * configuration is as much about what is turned OFF, every pool is static
 * and sized here as a recorded fact with its rationale (docs/24 §7: the
 * cliff is loud — exhaustion is a counted drop or an ERR_MEM, never a
 * kernel OOM — and re-sizing on conviction is a one-line change, never a
 * dynamic allocator), and every checksum is computed and verified in
 * software because no offload is negotiated (drivers/virtio/net.c leaves
 * the whole family unnegotiated, so the CHECKSUM_GEN and CHECKSUM_CHECK
 * defaults — all software — are left exactly as they are).
 */
#ifndef PROSKRNL_DRIVERS_NET_PORT_LWIPOPTS_H
#define PROSKRNL_DRIVERS_NET_PORT_LWIPOPTS_H

/* --- the machine (docs/24 §3c) -------------------------------------------- */

/* Raw callback API driven from one mainloop; no OS abstraction, no
 * threads, no mailboxes. */
#define NO_SYS 1

/* The sockets and netconn APIs are NOT COMPILED — the AFD layer (Net-2)
 * is written against the raw API and the oracle, never against lwIP's own
 * socket emulation. */
#define LWIP_SOCKET  0
#define LWIP_NETCONN 0

/* Single-threaded by the kernel's own construction: lwIP is entered from
 * exactly two contexts that can never interleave inside the stack
 * (drivers/net/netd.c states and asserts the invariant), so there is
 * nothing for a protection layer to protect. */
#define SYS_LIGHTWEIGHT_PROT 0

/* No libc heap anywhere: mem.c serves PBUF_RAM/tcp segments from the
 * static MEM_SIZE region in kernel .bss below, memp.c serves every other
 * pool statically — networking never enters MiAllocatePool on the data
 * path, so the drain-context allocator prohibition (docs/20 R2) is
 * untouched by construction. */
#define MEM_LIBC_MALLOC 0
#define MEMP_MEM_MALLOC 0

/* --- the surface ----------------------------------------------------------- */

#define LWIP_DHCP 1
/* No address-conflict probe before binding: the only wire this kernel
 * sees is a QEMU slirp segment with exactly one DHCP server and no
 * second host to conflict with, and the ACD probe costs seconds of
 * bind latency per boot on every net leg. (This also keeps acd.c out
 * of the build — absence of negotiation is absence of code.) */
#define LWIP_DHCP_DOES_ACD_CHECK 0
#define LWIP_AUTOIP              0

/* The DNS client module is compiled for its server-list bookkeeping —
 * DHCP option 6 lands in dns_setserver() and the lease writer reads it
 * back for the DhcpNameServer registry value (docs/24 §4b). Nothing
 * kernel-side ever issues a query: resolution is ring-3 wsresolv's
 * (Net-3, docs/24 §4f). */
#define LWIP_DNS 1

/* Dual-stack compiled from day one (docs/24 §5: re-sizing pools twice is
 * the expensive path); the v6 SOCKET surface stays staged until its own
 * sem_net pins exist. v4 is the acceptance path. */
#define LWIP_IPV6       1
#define LWIP_IPV6_DHCP6 0
/* x86_64: the v6 reassembly helper holds pointers, so it outgrows the
 * in-place fragment header on LP64 — lwIP's own assert names this knob
 * as the required setting there (src/core/ipv6/ip6_frag.c). */
#define IPV6_FRAG_COPYHEADER 1

/* The loopback interface: 127.0.0.1 exists from bring-up — Net-2's
 * sem_net runs against it kernel-only, no device, no slirp (docs/24
 * §6a). Queued frames are drained by the netd mainloop's netif_poll_all
 * pass, bounded below. */
#define LWIP_NETIF_LOOPBACK 1

/* The lease latch (drivers/net/netd.c): the status callback only sets a
 * flag — no registry, no disk, nothing that can block inside lwIP. */
#define LWIP_NETIF_STATUS_CALLBACK 1

/* Natural alignment for x86_64: every heap/pool object lwIP hands out
 * (pbuf structs and payloads included) is 8-byte aligned. The default
 * (1) is unaligned-access UB the kernel's UBSan traps on the first ARP
 * frame. */
#define MEM_ALIGNMENT 8

/* --- static sizing (recorded facts, each with its rationale; the
 *     high-water marks ride the [KTEST] net stats line) ------------------- */

/* The mem.c heap: PBUF_RAM allocations (transmit pbufs, DHCP/ARP
 * scratch) and TCP segments' payload copies. 64 KiB ≈ four full send
 * buffers plus slack — the acceptance path is one connection. */
#define MEM_SIZE (64 * 1024)

/* Receive-side pbufs (PBUF_POOL): 32 buffers covers a full staged ring's
 * worth of frames (drivers/virtio/net.c stages at most 64, the mainloop
 * feeds them through one at a time) plus reassembly headroom. */
#define PBUF_POOL_SIZE 32

/* Ethernet MTU 1500 minus the 40-byte IPv4+TCP headers. */
#define TCP_MSS 1460

/* Window and send buffer: 8 segments each — plenty for an echo and a
 * fetch, small enough that the whole TCP footprint stays a few tens of
 * KiB. TCP_SND_QUEUELEN follows as its default (4x) and
 * MEMP_NUM_TCP_SEG below covers it. */
#define TCP_WND     (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)

/* Connection counts: Net-1 needs one TCP connection (the echo) and two
 * UDP flows (DHCP, and mld6's internal use); Net-2's AFD serves real
 * consumers whose concurrency is bounded by these same numbers — the
 * refusal is a loud WSAENOBUFS-shaped error there, and the resize is
 * one line here. */
#define MEMP_NUM_TCP_PCB        16
#define MEMP_NUM_TCP_PCB_LISTEN 8
#define MEMP_NUM_UDP_PCB        8
#define MEMP_NUM_RAW_PCB        4
#define MEMP_NUM_TCP_SEG        48

/* Loopback queue bound: frames parked between mainloop passes. */
#define LWIP_LOOPBACK_MAX_PBUFS 16

/* --- diagnostics ----------------------------------------------------------- */

/* LWIP_STATS stays at its default (on): lwip_stats is where the pool
 * high-water marks the [KTEST] net stats line reports come from
 * (docs/24 §6e). LWIP_ASSERT stays active — it lands in KiPanic
 * (arch/cc.h), loud beats wrong (Art. 12). LWIP_DEBUG stays off. */

/* Net-2: the MIB2 counter block is the RETRANSMIT source —
 * lwip_stats.mib2.tcpretranssegs feeds the [KTEST] net stats rexmit
 * number (docs/24 §6e: the win is a verdict, and a loopback-only
 * implementation shows its hand in the drop/retransmit counters). */
#define MIB2_STATS 1

#endif /* PROSKRNL_DRIVERS_NET_PORT_LWIPOPTS_H */
