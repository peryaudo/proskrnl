/* drivers/nsi.c — \Device\Nsi: the network-store surface nsi.dll opens as
 * \\.\Nsi and iphlpapi's GetAdaptersAddresses reads (Net-3, docs/24 §4e;
 * milestone docs/02 "Net-3").
 *
 * Minimal and consumer-scoped: the three table verbs (enumerate-all,
 * get-all-parameters, get-parameter) over exactly the tables the pinned
 * GetAdaptersAddresses reads — the NDIS ifinfo table, the IP unicast
 * tables, and the IP forward tables (dlls/iphlpapi/iphlpapi_main.c reads
 * the forward table unconditionally in gateway_and_prefix_addresses_alloc,
 * and get-parameter is its ConvertInterfaceLuidToGuid read — the measured
 * conviction docs/24 §4e's "grows by conviction" clause asks for).
 * Everything else refuses loudly (G12): icmp-echo and change-notification
 * answer STATUS_NOT_SUPPORTED and name themselves on serial — a recorded
 * divergence from the oracle, which serves both (docs/03 "Net-3 notes") —
 * and unknown modules/tables answer the oracle's own
 * STATUS_INVALID_PARAMETER.
 *
 * ONE interface authority (Art. 11): every row is a per-request view of
 * lwIP netif state, read under the NetdEnterLwip bracket — no second
 * interface database exists to drift. Row identity is minted once:
 * if_index is the lwIP netif index, the luid packs the IANA type with
 * that index, and the ethernet if_guid is NetAdapterGuid — the SAME
 * MAC-derived value that names the adapter's registry key
 * (drivers/net/netd.c), so a consumer joining AdapterName against
 * Tcpip\Parameters\Interfaces lands on one key.
 *
 * Every verb answers inline — no parks, no pends — so the device adds no
 * blocking point (G14: no frontier entry) and no cancel path.
 *
 * The dialect is pinned by tests/ntapi/sem_nsi/ against the oracle
 * measured from OUTSIDE (docs/24 §1b — wine/dlls/nsiproxy.sys is never
 * read): the count probe, capacity-spaced arrays behind the leading
 * DWORD, STATUS_BUFFER_OVERFLOW with rows-written on short capacity,
 * exact-or-zero strides, and the refusal statuses above.
 */
#include "drivers/nsi.h"
#include "drivers/net/netd.h"
#include "kernel/io/io.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

#include "abi/nsi.h"
#include "abi/ntstatus.h"

#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/dhcp.h"

/* --- externally fixed row constants (G8) ----------------------------------- *
 * IANA ifType values (wine/include/ipifcons.h): */
#define NSIP_IF_TYPE_ETHERNET_CSMACD   6
#define NSIP_IF_TYPE_SOFTWARE_LOOPBACK 24
/* wine/include/ifdef.h IF_OPER_STATUS: */
#define NSIP_OPER_STATUS_UP   1
#define NSIP_OPER_STATUS_DOWN 2
/* wine/include/ifdef.h NET_IF_ACCESS_TYPE / NET_IF_CONNECTION_TYPE: */
#define NSIP_ACCESS_LOOPBACK      1
#define NSIP_ACCESS_BROADCAST     2
#define NSIP_CONNECTION_DEDICATED 1
/* wine/include/nldef.h NL_PREFIX_ORIGIN / NL_SUFFIX_ORIGIN / NL_DAD_STATE: */
#define NSIP_ORIGIN_MANUAL 1
#define NSIP_ORIGIN_DHCP   3
#define NSIP_DAD_PREFERRED 4
/* wine/include/nldef.h NL_ROUTE_PROTOCOL (MAKE_ROUTE_PROTOCOL): */
#define NSIP_PROTO_LOCAL   2
#define NSIP_PROTO_NETMGMT 3

static PIO_DEVICE NsiDevice;
static IO_FCB NsiFcb;

/* --- the row snapshot ------------------------------------------------------ *
 * Rows are built per request from netif state into these scratch arrays —
 * tiny tables (two netifs bound the counts), and safe as statics because
 * no path below parks: under Article 3's machine a DeviceControl runs to
 * completion before any other kernel visitor can enter (the greppable
 * "atomic under the no-preemption model" sentence, drivers/afd.c's
 * instance). */
#define NSIP_MAX_ROWS 8

union NSIP_KEY
{
    NET_LUID luid;
    struct nsi_ipv4_unicast_key v4Unicast;
    struct nsi_ipv6_unicast_key v6Unicast;
    struct nsi_ipv4_forward_key v4Forward;
    struct nsi_ipv6_forward_key v6Forward;
};

union NSIP_RW
{
    struct nsi_ndis_ifinfo_rw ifinfo;
    struct nsi_ip_unicast_rw unicast;
    struct nsi_ip_forward_rw forward;
};

union NSIP_DYNAMIC
{
    struct nsi_ndis_ifinfo_dynamic ifinfo;
    struct nsi_ip_unicast_dynamic unicast;
    struct nsi_ipv4_forward_dynamic v4Forward;
    struct nsi_ipv6_forward_dynamic v6Forward;
};

union NSIP_STATIC
{
    struct nsi_ndis_ifinfo_static ifinfo;
    struct nsi_ip_unicast_static unicast;
    struct nsi_ip_forward_static forward;
};

static union NSIP_KEY NsipKeys[NSIP_MAX_ROWS];
static union NSIP_RW NsipRw[NSIP_MAX_ROWS];
static union NSIP_DYNAMIC NsipDynamic[NSIP_MAX_ROWS];
static union NSIP_STATIC NsipStatic[NSIP_MAX_ROWS];

/* --- interface identity (one authority; header comment) -------------------- */

static BOOLEAN NsipIsLoopback(const struct netif *netif)
{
    return netif->name[0] == 'l' && netif->name[1] == 'o';
}

static ULONG NsipIfType(const struct netif *netif)
{
    return NsipIsLoopback(netif) ? NSIP_IF_TYPE_SOFTWARE_LOOPBACK : NSIP_IF_TYPE_ETHERNET_CSMACD;
}

static NET_LUID NsipLuid(const struct netif *netif)
{
    NET_LUID luid;
    luid.Value = 0;
    luid.Info.IfType = NsipIfType(netif);
    luid.Info.NetLuidIndex = netif_get_index((struct netif *)netif);
    return luid;
}

static void NsipGuid(const struct netif *netif, GUID *out)
{
    if (!NsipIsLoopback(netif))
    {
        NetAdapterGuid(out); /* the registry key's identity, minted once */
        return;
    }
    /* The loopback adapter never appears in the registry; its GUID only
     * needs to be stable and distinct — same PROS-KR-NL shape, netif
     * index in the node field. */
    memset(out, 0, sizeof(*out));
    out->Data1 = 0x50524f53;
    out->Data2 = 0x4b52;
    out->Data3 = 0x4e4c;
    out->Data4[0] = 0x80;
    out->Data4[7] = (UCHAR)netif_get_index((struct netif *)netif);
}

static void NsipSetCountedString(IF_COUNTED_STRING *out, const char *text)
{
    ULONG i = 0;
    while (text[i] != 0 && i < IF_MAX_STRING_SIZE)
    {
        out->String[i] = (WCHAR)text[i];
        i++;
    }
    out->String[i] = 0;
    out->Length = (USHORT)(i * sizeof(WCHAR));
}

static ULONG NsipPrefixLength(uint32_t netmask) /* network byte order */
{
    ULONG bits = 0;
    uint32_t host = lwip_ntohl(netmask);
    while (host & 0x80000000u)
    {
        bits++;
        host <<= 1;
    }
    return bits;
}

/* --- the table builders ---------------------------------------------------- *
 * Each fills the snapshot arrays (one union slot per row) and returns the
 * row count. Callers hold the NetdEnterLwip bracket. */

static ULONG NsipBuildIfinfo(void)
{
    struct netif *netif;
    ULONG count = 0;
    NETIF_FOREACH(netif)
    {
        if (count == NSIP_MAX_ROWS)
        {
            break;
        }
        BOOLEAN loop = NsipIsLoopback(netif);
        BOOLEAN up = loop || (netif_is_up(netif) && netif_is_link_up(netif));
        union NSIP_KEY *key = &NsipKeys[count];
        struct nsi_ndis_ifinfo_rw *rw = &NsipRw[count].ifinfo;
        struct nsi_ndis_ifinfo_dynamic *dyn = &NsipDynamic[count].ifinfo;
        struct nsi_ndis_ifinfo_static *stat = &NsipStatic[count].ifinfo;

        memset(key, 0, sizeof(*key));
        memset(rw, 0, sizeof(*rw));
        memset(dyn, 0, sizeof(*dyn));
        memset(stat, 0, sizeof(*stat));

        key->luid = NsipLuid(netif);

        NsipGuid(netif, &rw->network_guid);
        rw->admin_status = NSIP_OPER_STATUS_UP;
        NsipSetCountedString(&rw->alias, loop ? "Loopback" : "Ethernet");
        rw->phys_addr.Length = netif->hwaddr_len;
        memcpy(rw->phys_addr.Address, netif->hwaddr, netif->hwaddr_len);

        dyn->oper_status = up ? NSIP_OPER_STATUS_UP : NSIP_OPER_STATUS_DOWN;
        dyn->flags.not_media_conn = up ? 0 : 1;
        dyn->media_conn_state = up ? 1 : 0;
        /* lwIP's loop netif carries no MTU; the answer a consumer can use
         * is the loopback's effectively unbounded frame (the value real
         * loopback adapters report). */
        dyn->mtu = netif->mtu != 0 ? netif->mtu : 65536;

        stat->if_index = netif_get_index(netif);
        NsipSetCountedString(&stat->descr,
                             loop ? "Software Loopback Interface" : "proskrnl virtio-net");
        stat->type = NsipIfType(netif);
        stat->access_type = loop ? NSIP_ACCESS_LOOPBACK : NSIP_ACCESS_BROADCAST;
        stat->conn_type = NSIP_CONNECTION_DEDICATED;
        NsipGuid(netif, &stat->if_guid);
        stat->conn_present = loop ? 0 : 1;
        stat->perm_phys_addr = rw->phys_addr;
        stat->flags.hw = loop ? 0 : 1;
        count++;
    }
    return count;
}

static ULONG NsipBuildV4Unicast(void)
{
    struct netif *netif;
    ULONG count = 0;
    NETIF_FOREACH(netif)
    {
        if (count == NSIP_MAX_ROWS)
        {
            break;
        }
        const ip4_addr_t *addr = netif_ip4_addr(netif);
        if (ip4_addr_isany(addr))
        {
            continue;
        }
        BOOLEAN loop = NsipIsLoopback(netif);
        BOOLEAN viaDhcp = !loop && dhcp_supplied_address(netif);
        struct nsi_ipv4_unicast_key *key = &NsipKeys[count].v4Unicast;
        struct nsi_ip_unicast_rw *rw = &NsipRw[count].unicast;
        struct nsi_ip_unicast_dynamic *dyn = &NsipDynamic[count].unicast;
        struct nsi_ip_unicast_static *stat = &NsipStatic[count].unicast;

        memset(&NsipKeys[count], 0, sizeof(NsipKeys[count]));
        memset(rw, 0, sizeof(*rw));
        memset(dyn, 0, sizeof(*dyn));
        memset(stat, 0, sizeof(*stat));

        key->luid = NsipLuid(netif);
        key->addr.S_un.S_addr = ip4_addr_get_u32(addr);

        rw->preferred_lifetime = 0xffffffffu; /* infinite — no lease clock here */
        rw->valid_lifetime = 0xffffffffu;
        rw->prefix_origin = viaDhcp ? NSIP_ORIGIN_DHCP : NSIP_ORIGIN_MANUAL;
        rw->suffix_origin = viaDhcp ? NSIP_ORIGIN_DHCP : NSIP_ORIGIN_MANUAL;
        rw->on_link_prefix = NsipPrefixLength(ip4_addr_get_u32(netif_ip4_netmask(netif)));

        dyn->scope_id = 0;
        dyn->dad_state = NSIP_DAD_PREFERRED;
        count++;
    }
    return count;
}

static ULONG NsipBuildV6Unicast(void)
{
    struct netif *netif;
    ULONG count = 0;
    NETIF_FOREACH(netif)
    {
        for (int slot = 0; slot < LWIP_IPV6_NUM_ADDRESSES; slot++)
        {
            if (count == NSIP_MAX_ROWS)
            {
                break;
            }
            if (!ip6_addr_isvalid(netif_ip6_addr_state(netif, slot)))
            {
                continue;
            }
            const ip6_addr_t *addr = netif_ip6_addr(netif, slot);
            struct nsi_ipv6_unicast_key *key = &NsipKeys[count].v6Unicast;
            struct nsi_ip_unicast_rw *rw = &NsipRw[count].unicast;
            struct nsi_ip_unicast_dynamic *dyn = &NsipDynamic[count].unicast;
            struct nsi_ip_unicast_static *stat = &NsipStatic[count].unicast;

            memset(&NsipKeys[count], 0, sizeof(NsipKeys[count]));
            memset(rw, 0, sizeof(*rw));
            memset(dyn, 0, sizeof(*dyn));
            memset(stat, 0, sizeof(*stat));

            key->luid = NsipLuid(netif);
            memcpy(key->addr.u.Byte, addr->addr, 16);

            rw->preferred_lifetime = 0xffffffffu;
            rw->valid_lifetime = 0xffffffffu;
            rw->prefix_origin = NSIP_ORIGIN_MANUAL;
            rw->suffix_origin = NSIP_ORIGIN_MANUAL;
            rw->on_link_prefix = ip6_addr_islinklocal(addr) ? 64 : 128;

            dyn->scope_id = ip6_addr_islinklocal(addr) ? netif_get_index(netif) : 0;
            dyn->dad_state = NSIP_DAD_PREFERRED;
            count++;
        }
    }
    return count;
}

static void NsipFillV4ForwardRow(ULONG at, const struct netif *netif, uint32_t prefix,
                                 UCHAR prefixLength, uint32_t nextHop, ULONG protocol,
                                 BOOLEAN loopbackRoute)
{
    struct nsi_ipv4_forward_key *key = &NsipKeys[at].v4Forward;
    struct nsi_ip_forward_rw *rw = &NsipRw[at].forward;
    struct nsi_ipv4_forward_dynamic *dyn = &NsipDynamic[at].v4Forward;
    struct nsi_ip_forward_static *stat = &NsipStatic[at].forward;

    memset(&NsipKeys[at], 0, sizeof(NsipKeys[at]));
    memset(rw, 0, sizeof(*rw));
    memset(dyn, 0, sizeof(*dyn));
    memset(stat, 0, sizeof(*stat));

    key->prefix.S_un.S_addr = prefix;
    key->prefix_len = prefixLength;
    key->luid = NsipLuid(netif);
    key->luid2 = key->luid;
    key->next_hop.S_un.S_addr = nextHop;

    rw->protocol = protocol;
    rw->loopback = loopbackRoute ? 1 : 0;
    rw->immortal = 1;

    dyn->addr2 = key->prefix;
    stat->if_index = netif_get_index((struct netif *)netif);
}

static ULONG NsipBuildV4Forward(void)
{
    struct netif *netif;
    ULONG count = 0;
    NETIF_FOREACH(netif)
    {
        if (count + 3 > NSIP_MAX_ROWS)
        {
            break;
        }
        const ip4_addr_t *addr = netif_ip4_addr(netif);
        if (ip4_addr_isany(addr))
        {
            continue;
        }
        uint32_t address = ip4_addr_get_u32(addr);
        uint32_t netmask = ip4_addr_get_u32(netif_ip4_netmask(netif));
        BOOLEAN loop = NsipIsLoopback(netif);

        /* The on-link net route (the GAA prefix row). */
        NsipFillV4ForwardRow(count++, netif, address & netmask, (UCHAR)NsipPrefixLength(netmask), 0,
                             NSIP_PROTO_LOCAL, loop);

        /* The gateway's default route (the GAA gateway row). */
        uint32_t gateway = ip4_addr_get_u32(netif_ip4_gw(netif));
        if (!loop && gateway != 0)
        {
            NsipFillV4ForwardRow(count++, netif, 0, 0, gateway, NSIP_PROTO_NETMGMT, FALSE);
        }
    }
    return count;
}

static ULONG NsipBuildV6Forward(void)
{
    /* The v6 surface is staged (docs/24 §5, docs/03 "Net-2 staged
     * AF_INET6"): the table exists and answers honestly — no routes are
     * held for it, so it holds no rows. */
    return 0;
}

/* --- the table directory --------------------------------------------------- */

typedef struct
{
    const NPI_MODULEID *module;
    ULONG table;
    ULONG keySize;
    ULONG rwSize;
    ULONG dynamicSize;
    ULONG staticSize;
    ULONG (*build)(void);
} NSIP_TABLE;

static const NPI_MODULEID NsipNdisModule = NPI_MS_NDIS_MODULEID_INIT;
static const NPI_MODULEID NsipIpv4Module = NPI_MS_IPV4_MODULEID_INIT;
static const NPI_MODULEID NsipIpv6Module = NPI_MS_IPV6_MODULEID_INIT;

static const NSIP_TABLE NsipTables[] = {
    {&NsipNdisModule, NSI_NDIS_IFINFO_TABLE, sizeof(NET_LUID), sizeof(struct nsi_ndis_ifinfo_rw),
     sizeof(struct nsi_ndis_ifinfo_dynamic), sizeof(struct nsi_ndis_ifinfo_static),
     NsipBuildIfinfo},
    {&NsipIpv4Module, NSI_IP_UNICAST_TABLE, sizeof(struct nsi_ipv4_unicast_key),
     sizeof(struct nsi_ip_unicast_rw), sizeof(struct nsi_ip_unicast_dynamic),
     sizeof(struct nsi_ip_unicast_static), NsipBuildV4Unicast},
    {&NsipIpv6Module, NSI_IP_UNICAST_TABLE, sizeof(struct nsi_ipv6_unicast_key),
     sizeof(struct nsi_ip_unicast_rw), sizeof(struct nsi_ip_unicast_dynamic),
     sizeof(struct nsi_ip_unicast_static), NsipBuildV6Unicast},
    {&NsipIpv4Module, NSI_IP_FORWARD_TABLE, sizeof(struct nsi_ipv4_forward_key),
     sizeof(struct nsi_ip_forward_rw), sizeof(struct nsi_ipv4_forward_dynamic),
     sizeof(struct nsi_ip_forward_static), NsipBuildV4Forward},
    {&NsipIpv6Module, NSI_IP_FORWARD_TABLE, sizeof(struct nsi_ipv6_forward_key),
     sizeof(struct nsi_ip_forward_rw), sizeof(struct nsi_ipv6_forward_dynamic),
     sizeof(struct nsi_ip_forward_static), NsipBuildV6Forward},
};

static BOOLEAN NsipModuleEqual(const NPI_MODULEID *a, const NPI_MODULEID *b)
{
    /* Type + Guid, the NmrIsEqualNpiModuleId recipe (netiodef.h) — never
     * a whole-struct memcmp across the header's padding. */
    return a->Type == b->Type && memcmp(&a->Guid, &b->Guid, sizeof(a->Guid)) == 0;
}

static const NSIP_TABLE *NsipFindTable(const NPI_MODULEID *module, ULONG table)
{
    for (ULONG i = 0; i < sizeof(NsipTables) / sizeof(NsipTables[0]); i++)
    {
        if (NsipTables[i].table == table && NsipModuleEqual(NsipTables[i].module, module))
        {
            return &NsipTables[i];
        }
    }
    return 0;
}

/* Exact-or-zero: a stride must name the table's row size or opt out —
 * the oracle refuses a wrong nonzero stride STATUS_INVALID_PARAMETER
 * (measured; how a caller with a drifted header fails loudly instead of
 * shearing rows). */
static BOOLEAN NsipStridesValid(const NSIP_TABLE *table, ULONG keySize, ULONG rwSize,
                                ULONG dynamicSize, ULONG staticSize)
{
    return (keySize == 0 || keySize == table->keySize) &&
           (rwSize == 0 || rwSize == table->rwSize) &&
           (dynamicSize == 0 || dynamicSize == table->dynamicSize) &&
           (staticSize == 0 || staticSize == table->staticSize);
}

static ULONG NsipBuildSnapshot(const NSIP_TABLE *table)
{
    NetdEnterLwip();
    ULONG count = table->build();
    NetdLeaveLwip();
    return count;
}

static LONG NsipFindRow(const NSIP_TABLE *table, ULONG count, const void *key)
{
    for (ULONG i = 0; i < count; i++)
    {
        if (memcmp(&NsipKeys[i], key, table->keySize) == 0)
        {
            return (LONG)i;
        }
    }
    return -1;
}

/* --- the verbs ------------------------------------------------------------- */

static NTSTATUS NsipEnumerateAll(const void *input, ULONG inputLength, void *output,
                                 ULONG outputLength, ULONG_PTR *infoOut)
{
    if (inputLength < sizeof(struct nsiproxy_enumerate_all))
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct nsiproxy_enumerate_all *in = input;
    ULONG strideSum = in->key_size + in->rw_size + in->dynamic_size + in->static_size;
    if (outputLength < sizeof(DWORD) + strideSum * (ULONGLONG)in->count)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const NSIP_TABLE *table = NsipFindTable(&in->module, in->table);
    if (table == 0)
    {
        DbgPrint("nsi: unbuilt table %lu/%08lx refused\n", (unsigned long)in->table,
                 (unsigned long)in->module.Guid.Data1);
        return STATUS_INVALID_PARAMETER;
    }
    if (!NsipStridesValid(table, in->key_size, in->rw_size, in->dynamic_size, in->static_size))
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG total = NsipBuildSnapshot(table);
    ULONG written = total < in->count ? total : in->count;
    BOOLEAN probeOnly = strideSum == 0;

    memset(output, 0, outputLength);
    /* The leading DWORD: rows written — except the pure count probe
     * (every stride zero), which answers the TOTAL (the
     * NsiAllocateAndGetTable resize loop's contract, measured). */
    *(DWORD *)output = probeOnly ? total : written;

    UCHAR *cursor = (UCHAR *)output + sizeof(DWORD);
    for (ULONG i = 0; i < written; i++)
    {
        if (in->key_size != 0)
        {
            memcpy(cursor + (ULONGLONG)in->key_size * i, &NsipKeys[i], table->keySize);
        }
    }
    cursor += (ULONGLONG)in->key_size * in->count;
    for (ULONG i = 0; i < written; i++)
    {
        if (in->rw_size != 0)
        {
            memcpy(cursor + (ULONGLONG)in->rw_size * i, &NsipRw[i], table->rwSize);
        }
    }
    cursor += (ULONGLONG)in->rw_size * in->count;
    for (ULONG i = 0; i < written; i++)
    {
        if (in->dynamic_size != 0)
        {
            memcpy(cursor + (ULONGLONG)in->dynamic_size * i, &NsipDynamic[i], table->dynamicSize);
        }
    }
    cursor += (ULONGLONG)in->dynamic_size * in->count;
    for (ULONG i = 0; i < written; i++)
    {
        if (in->static_size != 0)
        {
            memcpy(cursor + (ULONGLONG)in->static_size * i, &NsipStatic[i], table->staticSize);
        }
    }

    *infoOut = sizeof(DWORD) + strideSum * (ULONGLONG)in->count;
    return (!probeOnly && total > in->count) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

static NTSTATUS NsipGetAllParameters(const void *input, ULONG inputLength, void *output,
                                     ULONG outputLength, ULONG_PTR *infoOut)
{
    ULONG header = offsetof(struct nsiproxy_get_all_parameters, key);
    if (inputLength < header)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct nsiproxy_get_all_parameters *in = input;
    if (inputLength < header + in->key_size)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const NSIP_TABLE *table = NsipFindTable(&in->module, in->table);
    if (table == 0)
    {
        DbgPrint("nsi: unbuilt table %lu/%08lx refused\n", (unsigned long)in->table,
                 (unsigned long)in->module.Guid.Data1);
        return STATUS_INVALID_PARAMETER;
    }
    if (in->key_size != table->keySize ||
        !NsipStridesValid(table, 0, in->rw_size, in->dynamic_size, in->static_size))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputLength < in->rw_size + in->dynamic_size + in->static_size)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG count = NsipBuildSnapshot(table);
    LONG row = NsipFindRow(table, count, in->key);
    if (row < 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    UCHAR *cursor = output;
    if (in->rw_size != 0)
    {
        memcpy(cursor, &NsipRw[row], table->rwSize);
    }
    cursor += in->rw_size;
    if (in->dynamic_size != 0)
    {
        memcpy(cursor, &NsipDynamic[row], table->dynamicSize);
    }
    cursor += in->dynamic_size;
    if (in->static_size != 0)
    {
        memcpy(cursor, &NsipStatic[row], table->staticSize);
    }
    *infoOut = in->rw_size + in->dynamic_size + in->static_size;
    return STATUS_SUCCESS;
}

static NTSTATUS NsipGetParameter(const void *input, ULONG inputLength, void *output,
                                 ULONG outputLength, ULONG_PTR *infoOut)
{
    ULONG header = offsetof(struct nsiproxy_get_parameter, key);
    if (inputLength < header)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const struct nsiproxy_get_parameter *in = input;
    if (inputLength < header + in->key_size)
    {
        return STATUS_INVALID_PARAMETER;
    }
    const NSIP_TABLE *table = NsipFindTable(&in->module, in->table);
    if (table == 0)
    {
        DbgPrint("nsi: unbuilt table %lu/%08lx refused\n", (unsigned long)in->table,
                 (unsigned long)in->module.Guid.Data1);
        return STATUS_INVALID_PARAMETER;
    }
    if (in->key_size != table->keySize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    const void *arrays[] = {NsipRw, NsipDynamic, NsipStatic};
    ULONG arrayStrides[] = {sizeof(union NSIP_RW), sizeof(union NSIP_DYNAMIC),
                            sizeof(union NSIP_STATIC)};
    ULONG rowSizes[] = {table->rwSize, table->dynamicSize, table->staticSize};
    if (in->param_type > NSI_PARAM_TYPE_STATIC)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ULONG rowSize = rowSizes[in->param_type];
    if (in->data_offset > rowSize || outputLength > rowSize - in->data_offset)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG count = NsipBuildSnapshot(table);
    LONG row = NsipFindRow(table, count, in->key);
    if (row < 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    const UCHAR *source =
        (const UCHAR *)arrays[in->param_type] + arrayStrides[in->param_type] * (ULONG)row;
    memcpy(output, source + in->data_offset, outputLength);
    *infoOut = outputLength;
    return STATUS_SUCCESS;
}

/* --- the device ------------------------------------------------------------ */

static NTSTATUS NsiVfsCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                             PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess, ULONG shareAccess,
                             ULONG fileAttributes, ULONG disposition, ULONG options,
                             ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    /* The bare name and a trailing backslash open; a trailing NAME
     * refuses — the pinned shape (sem_nsi/nsi_open.c), unlike
     * \Device\Afd's swallow-anything. */
    if (path->Length > sizeof(WCHAR) || (path->Length == sizeof(WCHAR) && path->Buffer[0] != '\\'))
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    file->fsContext = &NsiFcb;
    file->fcb = &NsiFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void NsiVfsCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void NsiVfsClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS NsiVfsGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS NsiDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                 ULONG inputLength, void *output, ULONG outputLength,
                                 ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)request; /* every verb answers inline — no pends, no parks */
    switch (code)
    {
    case IOCTL_NSIPROXY_WINE_ENUMERATE_ALL:
        return NsipEnumerateAll(input, inputLength, output, outputLength, infoOut);
    case IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS:
        return NsipGetAllParameters(input, inputLength, output, outputLength, infoOut);
    case IOCTL_NSIPROXY_WINE_GET_PARAMETER:
        return NsipGetParameter(input, inputLength, output, outputLength, infoOut);
    default:
        break;
    }
    /* icmp-echo and change-notification land here DELIBERATELY (docs/24
     * §5; the docs/03 "Net-3 notes" divergence — the oracle serves both),
     * beside genuinely unknown codes: the oracle's own unknown-code
     * answer (STATUS_NOT_SUPPORTED, pinned sem_nsi/nsi_refusal.c), named
     * on serial. Never STATUS_NOT_IMPLEMENTED (G12 — the armed panic). */
    DbgPrint("nsi: unimplemented ioctl %08lx\n", (unsigned long)code);
    return STATUS_NOT_SUPPORTED;
}

static const IO_VFS_OPS NsiOps = {
    .Create = NsiVfsCreate,
    .Cleanup = NsiVfsCleanup,
    .Close = NsiVfsClose,
    .GetInfo = NsiVfsGetInfo,
    .DeviceControl = NsiDeviceControl,
};

void NsiInitialize(void)
{
    IopInitializeFcb(&NsiFcb);
    NsiDevice = IoPublishDevice(WSTR("\\Device\\Nsi"), &NsiOps, 0, FILE_DEVICE_NETWORK);
    if (NsiDevice == 0)
    {
        KiPanic("nsi: device publication failed");
    }

    /* \??\Nsi — the name nsi.dll's CreateFileW(L"\\\\.\\Nsi") resolves
     * (the kernel/io/null.c \??\NUL recipe). */
    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_PERMANENT;
    UNICODE_STRING linkName, target;
    RtlInitUnicodeString(&linkName, WSTR("\\??\\Nsi"));
    RtlInitUnicodeString(&target, WSTR("\\Device\\Nsi"));
    attributes.ObjectName = &linkName;
    NTSTATUS status =
        NtCreateSymbolicLinkObject(&handle, SYMBOLIC_LINK_ALL_ACCESS, &attributes, &target);
    if (!NT_SUCCESS(status))
    {
        KiPanic("nsi: cannot create \\??\\Nsi");
    }
    NtClose(handle);
    DbgPrint("nsi: \\Device\\Nsi up\n");
}
