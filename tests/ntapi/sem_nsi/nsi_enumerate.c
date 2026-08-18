/*
 * sem_nsi/nsi_enumerate.c — IOCTL_NSIPROXY_WINE_ENUMERATE_ALL: the
 * count probe, the row arrays, the short-capacity shape, and the
 * cross-table loopback identity.
 *
 * The wire contract is nsi.dll's (dlls/nsi/nsi.c
 * NsiEnumerateObjectsAllParametersEx): input carries the four per-array
 * strides and a row CAPACITY; output is a leading DWORD row count
 * followed by the key/rw/dynamic/static arrays, each laid out at
 * CAPACITY spacing (nsi.dll advances by size * in.count, not by the
 * answered count). Capacity smaller than the table answers
 * STATUS_BUFFER_OVERFLOW with the DWORD = rows actually written — that
 * is how NsiAllocateAndGetTable's probe-and-resize loop reads it.
 *
 * Verdicts are properties, never host values: the one row both runners
 * own is the software loopback (IF_TYPE_SOFTWARE_LOOPBACK, 127.0.0.1),
 * and everything else is counted, bounded or cross-referenced.
 */
#include "util.h"

static HANDLE h;

static void test_count_probe(void)
{
    UINT count = 0;
    NTSTATUS status;

    /* All strides zero: the DWORD answers the table's total row count
     * and nothing else is written. */
    status = nsi_count(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &count);
    ok(status == STATUS_SUCCESS, "ifinfo count probe -> %08lx", (unsigned long)status);
    ok(count >= 1, "ifinfo count %u", count);
}

static void test_ifinfo_rows(void)
{
    NET_LUID keys[16];
    static struct nsi_ndis_ifinfo_rw rw[16];
    static struct nsi_ndis_ifinfo_dynamic dyn[16];
    static struct nsi_ndis_ifinfo_static stat[16];
    UINT count = 0, probed = 0, i, j, loopbacks = 0;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = nsi_count(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &probed);
    ok(status == STATUS_SUCCESS, "count probe -> %08lx", (unsigned long)status);

    status =
        nsi_enumerate(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, keys, sizeof(keys[0]), rw,
                      sizeof(rw[0]), dyn, sizeof(dyn[0]), stat, sizeof(stat[0]), 16, &count, &iosb);
    ok(status == STATUS_SUCCESS, "enumerate -> %08lx", (unsigned long)status);
    ok(count == probed, "count %u != probe %u", count, probed);
    ok(count >= 1 && count <= 16, "count %u", count);
    ok(iosb.Status == STATUS_SUCCESS, "iosb.Status %08lx", (unsigned long)iosb.Status);
    /* Information covers the DWORD plus the arrays at CAPACITY spacing. */
    ok(iosb.Information == sizeof(DWORD) + 16ul * (sizeof(keys[0]) + sizeof(rw[0]) +
                                                   sizeof(dyn[0]) + sizeof(stat[0])),
       "info %lu", (unsigned long)iosb.Information);

    for (i = 0; i < count; i++)
    {
        ok(stat[i].if_index != 0, "row %u: if_index 0", i);
        ok(keys[i].Info.IfType == stat[i].type, "row %u: luid type %u != %u", i,
           (UINT)keys[i].Info.IfType, stat[i].type);
        ok(rw[i].alias.Length < sizeof(rw[i].alias.String), "row %u: alias len %u", i,
           rw[i].alias.Length);
        ok(stat[i].descr.Length < sizeof(stat[i].descr.String), "row %u: descr len %u", i,
           stat[i].descr.Length);
        ok(rw[i].phys_addr.Length <= 32, "row %u: phys len %u", i, rw[i].phys_addr.Length);
        for (j = i + 1; j < count; j++)
        {
            ok(keys[i].Value != keys[j].Value, "rows %u/%u share a luid", i, j);
            ok(stat[i].if_index != stat[j].if_index, "rows %u/%u share if_index", i, j);
        }
        if (stat[i].type == NSI_IF_TYPE_SOFTWARE_LOOPBACK)
        {
            loopbacks++;
            ok(dyn[i].oper_status == 1 /* IfOperStatusUp */, "loopback oper %u",
               dyn[i].oper_status);
            ok(dyn[i].mtu != 0, "loopback mtu 0");
            ok(rw[i].alias.Length > 0, "loopback alias empty");
        }
    }
    ok(loopbacks == 1, "%u loopback rows", loopbacks);
}

static void test_short_capacity(void)
{
    NET_LUID keys[2];
    static struct nsi_ndis_ifinfo_rw rw[2];
    static struct nsi_ndis_ifinfo_dynamic dyn[2];
    static struct nsi_ndis_ifinfo_static stat[2];
    UINT total = 0, answered = 0;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    status = nsi_count(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &total);
    ok(status == STATUS_SUCCESS, "count probe -> %08lx", (unsigned long)status);

    /* Capacity 0 with nonzero strides: overflow, zero rows written. */
    status = nsi_enumerate(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, NULL, sizeof(keys[0]), NULL,
                           sizeof(rw[0]), NULL, sizeof(dyn[0]), NULL, sizeof(stat[0]), 0, &answered,
                           &iosb);
    ok(status == STATUS_BUFFER_OVERFLOW, "capacity 0 -> %08lx", (unsigned long)status);
    ok(answered == 0, "capacity 0 wrote %u", answered);
    ok(iosb.Status == STATUS_BUFFER_OVERFLOW, "capacity 0 iosb %08lx", (unsigned long)iosb.Status);

    /* Capacity 1 under a bigger table: overflow, exactly one row written
     * and it is a valid row. */
    if (total > 1)
    {
        status = nsi_enumerate(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, keys, sizeof(keys[0]), rw,
                               sizeof(rw[0]), dyn, sizeof(dyn[0]), stat, sizeof(stat[0]), 1,
                               &answered, &iosb);
        ok(status == STATUS_BUFFER_OVERFLOW, "capacity 1 -> %08lx", (unsigned long)status);
        ok(answered == 1, "capacity 1 wrote %u", answered);
        ok(stat[0].if_index != 0, "capacity 1 row: if_index 0");
    }
    else
        skip("one-interface machine: the partial-write leg needs two rows");
}

static void test_key_subset_and_first_arg(void)
{
    NET_LUID keys[16];
    UINT count = 0;
    struct nsiproxy_enumerate_all in;
    BYTE out[sizeof(DWORD) + 16 * sizeof(NET_LUID)];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    /* Keys-only (the ConvertGuidToLuid sweep shape): zero strides for
     * the row arrays are legal per-array. */
    status = nsi_enumerate(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, keys, sizeof(keys[0]), NULL, 0,
                           NULL, 0, NULL, 0, 16, &count, NULL);
    ok(status == STATUS_SUCCESS, "keys only -> %08lx", (unsigned long)status);
    ok(count >= 1, "keys only count %u", count);

    /* first_arg 0 answers the same as the 1 iphlpapi passes. */
    memset(&in, 0, sizeof(in));
    in.module = npi_ms_ndis;
    in.first_arg = 0;
    in.table = NSI_NDIS_IFINFO_TABLE;
    in.key_size = sizeof(NET_LUID);
    in.count = 16;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_ENUMERATE_ALL,
                                   &in, sizeof(in), out, sizeof(out));
    ok(status == STATUS_SUCCESS, "first_arg 0 -> %08lx", (unsigned long)status);
    ok(*(DWORD *)out == count, "first_arg 0 count %lu != %u", (unsigned long)*(DWORD *)out, count);
}

static void test_unicast(void)
{
    static struct nsi_ipv4_unicast_key keys[64];
    static struct nsi_ip_unicast_rw rw[64];
    static struct nsi_ip_unicast_dynamic dyn[64];
    static struct nsi_ip_unicast_static stat[64];
    NET_LUID loop_luid;
    UINT count = 0, i, loop_row = ~0u;
    NTSTATUS status;

    if (!nsi_find_loopback(h, &loop_luid, NULL, NULL, NULL))
    {
        ok(0, "no loopback ifinfo row");
        return;
    }

    status =
        nsi_enumerate(h, &npi_ms_ipv4, NSI_IP_UNICAST_TABLE, keys, sizeof(keys[0]), rw,
                      sizeof(rw[0]), dyn, sizeof(dyn[0]), stat, sizeof(stat[0]), 64, &count, NULL);
    ok(status == STATUS_SUCCESS, "v4 unicast -> %08lx", (unsigned long)status);
    ok(count >= 1 && count <= 64, "v4 unicast count %u", count);

    for (i = 0; i < count; i++)
        if (keys[i].addr.S_un.S_addr == LOOPBACK_BE)
            loop_row = i;
    ok(loop_row != ~0u, "no 127.0.0.1 row");
    if (loop_row != ~0u)
    {
        /* The unicast row's luid is the ifinfo table's loopback luid —
         * one interface identity across modules (the iphlpapi join). */
        ok(keys[loop_row].luid.Value == loop_luid.Value, "127.0.0.1 luid %016llx != %016llx",
           (unsigned long long)keys[loop_row].luid.Value, (unsigned long long)loop_luid.Value);
        ok(rw[loop_row].on_link_prefix == 8, "127.0.0.1 prefix %u", rw[loop_row].on_link_prefix);
        ok(rw[loop_row].prefix_origin == 1 /* IpPrefixOriginManual */, "127.0.0.1 prefix origin %u",
           rw[loop_row].prefix_origin);
        ok(rw[loop_row].suffix_origin == 1 /* IpSuffixOriginManual */, "127.0.0.1 suffix origin %u",
           rw[loop_row].suffix_origin);
        ok(dyn[loop_row].dad_state == 4 /* IpDadStatePreferred */, "127.0.0.1 dad %u",
           dyn[loop_row].dad_state);
        ok(dyn[loop_row].scope_id == 0, "127.0.0.1 scope %u", dyn[loop_row].scope_id);
    }

    /* The v6 table answers the dialect even when it holds no rows (a
     * v6-less host and staged-v6 proskrnl both answer an honest count). */
    status = nsi_enumerate(h, &npi_ms_ipv6, NSI_IP_UNICAST_TABLE, NULL,
                           sizeof(struct nsi_ipv6_unicast_key), NULL, sizeof(rw[0]), NULL,
                           sizeof(dyn[0]), NULL, sizeof(stat[0]), 0, &count, NULL);
    ok(status == STATUS_SUCCESS || status == STATUS_BUFFER_OVERFLOW, "v6 unicast count -> %08lx",
       (unsigned long)status);
}

static void test_forward(void)
{
    static struct nsi_ipv4_forward_key keys[64];
    static struct nsi_ip_forward_rw rw[64];
    NET_LUID loop_luid;
    UINT count = 0, i, loop_net = ~0u;
    NTSTATUS status;

    if (!nsi_find_loopback(h, &loop_luid, NULL, NULL, NULL))
    {
        ok(0, "no loopback ifinfo row");
        return;
    }

    /* The route table GetAdaptersAddresses reads unconditionally
     * (gateway_and_prefix_addresses_alloc): key + rw arrays only. */
    status = nsi_enumerate(h, &npi_ms_ipv4, NSI_IP_FORWARD_TABLE, keys, sizeof(keys[0]), rw,
                           sizeof(rw[0]), NULL, 0, NULL, 0, 64, &count, NULL);
    ok(status == STATUS_SUCCESS, "v4 forward -> %08lx", (unsigned long)status);
    ok(count >= 1 && count <= 64, "v4 forward count %u", count);

    for (i = 0; i < count; i++)
    {
        /* On-link routes carry next_hop 0.0.0.0; gateway routes a
         * nonzero next_hop — both never at once (the GAA split). */
        if (keys[i].luid.Value == loop_luid.Value &&
            keys[i].prefix.S_un.S_addr == 0x0000007f /* 127.0.0.0 */ && keys[i].prefix_len == 8)
        {
            loop_net = i;
            ok(keys[i].next_hop.S_un.S_addr == 0, "loopback net route has a gateway");
            ok(rw[i].loopback == 1, "loopback net route loopback flag %u", rw[i].loopback);
        }
    }
    ok(loop_net != ~0u, "no 127.0.0.0/8 route");
}

START_TEST(nsi_enumerate)
{
    NTSTATUS status = nsi_open(&h);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    test_count_probe();
    test_ifinfo_rows();
    test_short_capacity();
    test_key_subset_and_first_arg();
    test_unicast();
    test_forward();
    NtClose(h);
}
