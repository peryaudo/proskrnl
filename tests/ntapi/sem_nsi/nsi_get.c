/*
 * sem_nsi/nsi_get.c — the keyed verbs: IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS
 * (whole row by key) and IOCTL_NSIPROXY_WINE_GET_PARAMETER (one field by
 * param_type + byte offset — the ConvertInterfaceLuidToGuid shape,
 * dlls/iphlpapi/iphlpapi_main.c).
 *
 * The keyed answers must agree with the enumerated rows — one table
 * authority behind both verbs, convicted by cross-checking, never by
 * naming host values.
 */
#include "util.h"

static HANDLE h;

static void test_get_all(void)
{
    NET_LUID luid, bogus;
    static struct nsi_ndis_ifinfo_rw enum_rw, rw;
    static struct nsi_ndis_ifinfo_dynamic enum_dyn, dyn;
    static struct nsi_ndis_ifinfo_static enum_stat, stat;
    NTSTATUS status;

    if (!nsi_find_loopback(h, &luid, &enum_stat, &enum_dyn, &enum_rw))
    {
        ok(0, "no loopback ifinfo row");
        return;
    }

    memset(&stat, 0, sizeof(stat));
    memset(&rw, 0, sizeof(rw));
    status = nsi_get_all(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid), &rw,
                         sizeof(rw), &dyn, sizeof(dyn), &stat, sizeof(stat));
    ok(status == STATUS_SUCCESS, "get_all -> %08lx", (unsigned long)status);
    ok(stat.if_index == enum_stat.if_index, "if_index %u != %u", stat.if_index, enum_stat.if_index);
    ok(stat.type == NSI_IF_TYPE_SOFTWARE_LOOPBACK, "type %u", stat.type);
    ok(memcmp(&stat.if_guid, &enum_stat.if_guid, sizeof(GUID)) == 0, "if_guid differs");
    ok(rw.alias.Length == enum_rw.alias.Length, "alias length %u != %u", rw.alias.Length,
       enum_rw.alias.Length);

    /* A single-array subset is legal: rw only. */
    memset(&rw, 0, sizeof(rw));
    status = nsi_get_all(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid), &rw,
                         sizeof(rw), NULL, 0, NULL, 0);
    ok(status == STATUS_SUCCESS, "get_all rw only -> %08lx", (unsigned long)status);
    ok(rw.alias.Length == enum_rw.alias.Length, "rw-only alias length %u", rw.alias.Length);

    /* An unknown key refuses by name. */
    bogus.Value = ~0ULL;
    status = nsi_get_all(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &bogus, sizeof(bogus), &rw,
                         sizeof(rw), &dyn, sizeof(dyn), &stat, sizeof(stat));
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "get_all bogus key -> %08lx", (unsigned long)status);
}

static void test_get_param(void)
{
    NET_LUID luid, bogus;
    static struct nsi_ndis_ifinfo_static enum_stat;
    GUID guid;
    UINT if_index = 0;
    NTSTATUS status;

    if (!nsi_find_loopback(h, &luid, &enum_stat, NULL, NULL))
    {
        ok(0, "no loopback ifinfo row");
        return;
    }

    /* The ConvertInterfaceLuidToGuid read: static array, if_guid offset. */
    memset(&guid, 0, sizeof(guid));
    status = nsi_get_param(
        h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid), NSI_PARAM_TYPE_STATIC,
        FIELD_OFFSET(struct nsi_ndis_ifinfo_static, if_guid), &guid, sizeof(guid));
    ok(status == STATUS_SUCCESS, "get_param if_guid -> %08lx", (unsigned long)status);
    ok(memcmp(&guid, &enum_stat.if_guid, sizeof(guid)) == 0, "if_guid differs from the row");

    /* The ConvertInterfaceLuidToIndex read: static offset 0. */
    status = nsi_get_param(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid),
                           NSI_PARAM_TYPE_STATIC, 0, &if_index, sizeof(if_index));
    ok(status == STATUS_SUCCESS, "get_param if_index -> %08lx", (unsigned long)status);
    ok(if_index == enum_stat.if_index, "if_index %u != %u", if_index, enum_stat.if_index);

    /* Refusal shapes: unknown key, an offset beyond the row, a
     * param_type that names no array. */
    bogus.Value = ~0ULL;
    status = nsi_get_param(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &bogus, sizeof(bogus),
                           NSI_PARAM_TYPE_STATIC, 0, &if_index, sizeof(if_index));
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "get_param bogus key -> %08lx",
       (unsigned long)status);

    status = nsi_get_param(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid),
                           NSI_PARAM_TYPE_STATIC, 100000, &if_index, sizeof(if_index));
    ok(status == STATUS_INVALID_PARAMETER, "get_param huge offset -> %08lx", (unsigned long)status);

    status = nsi_get_param(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, &luid, sizeof(luid), 7, 0,
                           &if_index, sizeof(if_index));
    ok(status == STATUS_INVALID_PARAMETER, "get_param bad type -> %08lx", (unsigned long)status);
}

static void test_get_all_unicast(void)
{
    static struct nsi_ipv4_unicast_key keys[64];
    static struct nsi_ip_unicast_rw enum_rw[64], rw;
    static struct nsi_ip_unicast_dynamic dyn;
    static struct nsi_ip_unicast_static stat;
    UINT count = 0, i, loop_row = ~0u;
    NTSTATUS status;

    status = nsi_enumerate(h, &npi_ms_ipv4, NSI_IP_UNICAST_TABLE, keys, sizeof(keys[0]), enum_rw,
                           sizeof(enum_rw[0]), NULL, 0, NULL, 0, 64, &count, NULL);
    ok(status == STATUS_SUCCESS, "v4 unicast enumerate -> %08lx", (unsigned long)status);
    for (i = 0; i < count && i < 64; i++)
        if (keys[i].addr.S_un.S_addr == LOOPBACK_BE)
            loop_row = i;
    if (loop_row == ~0u)
    {
        ok(0, "no 127.0.0.1 row");
        return;
    }

    memset(&rw, 0, sizeof(rw));
    status =
        nsi_get_all(h, &npi_ms_ipv4, NSI_IP_UNICAST_TABLE, &keys[loop_row], sizeof(keys[loop_row]),
                    &rw, sizeof(rw), &dyn, sizeof(dyn), &stat, sizeof(stat));
    ok(status == STATUS_SUCCESS, "unicast get_all -> %08lx", (unsigned long)status);
    ok(rw.on_link_prefix == enum_rw[loop_row].on_link_prefix, "unicast prefix %u != %u",
       rw.on_link_prefix, enum_rw[loop_row].on_link_prefix);
}

START_TEST(nsi_get)
{
    NTSTATUS status = nsi_open(&h);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    test_get_all();
    test_get_param();
    test_get_all_unicast();
    NtClose(h);
}
