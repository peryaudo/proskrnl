/*
 * sem_nsi/nsi_refusal.c — the refusal shapes: unknown ioctl codes,
 * unknown modules/tables, short buffers on every verb, and the two
 * verbs the minimal proskrnl device deliberately refuses.
 *
 * The default arm is oracle-shaped, exactly like sem_net's
 * test_unsupported_ioctls: an unknown code answers STATUS_NOT_SUPPORTED
 * (wine's nsiproxy fixme arm), an unknown module or table answers
 * STATUS_INVALID_PARAMETER, and a short input or output buffer answers
 * STATUS_INVALID_PARAMETER before any table is consulted. None of these
 * is ever STATUS_NOT_IMPLEMENTED (Art. 12 — that status is a ring-3
 * panic, not an answer).
 *
 * icmp-echo and change-notification are served by the oracle but are
 * deliberately unbuilt on proskrnl (docs/24 §5, the docs/03 "Net-3
 * notes" divergence): there they answer the same STATUS_NOT_SUPPORTED
 * as an unknown code, pinned per-runner below.
 */
#include "util.h"

static HANDLE h;

static void test_unknown_codes(void)
{
    BYTE in[64], out[64];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    static const ULONG codes[] = {NSI_IOC(0x3ff), NSI_IOC(0x405), NSI_IOC(0x480)};
    unsigned i;

    memset(in, 0, sizeof(in));
    for (i = 0; i < 3; i++)
    {
        poison_iosb(&iosb);
        status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, codes[i], in, sizeof(in), out,
                                       sizeof(out));
        ok(status == STATUS_NOT_SUPPORTED, "code %u -> %08lx", i, (unsigned long)status);
    }
}

static void test_unknown_module_table(void)
{
    static const NPI_MODULEID bogus = {
        sizeof(NPI_MODULEID), MIT_GUID, {{0xdeadbeef, 0x1234, 0x5678, {1, 2, 3, 4, 5, 6, 7, 8}}}};
    NET_LUID luid;
    struct nsi_ndis_ifinfo_rw rw;
    UINT count = 0, if_index = 0;
    NTSTATUS status;

    /* Unknown table under a known module — all three verbs. */
    status = nsi_count(h, &npi_ms_ndis, 0x7f, &count);
    ok(status == STATUS_INVALID_PARAMETER, "enumerate unknown table -> %08lx",
       (unsigned long)status);

    luid.Value = 0;
    status =
        nsi_get_all(h, &npi_ms_ndis, 0x7f, &luid, sizeof(luid), &rw, sizeof(rw), NULL, 0, NULL, 0);
    ok(status == STATUS_INVALID_PARAMETER, "get_all unknown table -> %08lx", (unsigned long)status);

    status = nsi_get_param(h, &npi_ms_ndis, 0x7f, &luid, sizeof(luid), NSI_PARAM_TYPE_STATIC, 0,
                           &if_index, sizeof(if_index));
    ok(status == STATUS_INVALID_PARAMETER, "get_param unknown table -> %08lx",
       (unsigned long)status);

    /* Unknown module. */
    status = nsi_count(h, &bogus, 0, &count);
    ok(status == STATUS_INVALID_PARAMETER, "enumerate unknown module -> %08lx",
       (unsigned long)status);
}

static void test_short_buffers(void)
{
    struct nsiproxy_enumerate_all in;
    struct nsiproxy_get_all_parameters hdr;
    BYTE out[64];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    memset(&in, 0, sizeof(in));
    in.module = npi_ms_ndis;
    in.table = NSI_NDIS_IFINFO_TABLE;
    in.key_size = sizeof(NET_LUID);
    in.count = 4;

    /* Input below the fixed header. */
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_ENUMERATE_ALL,
                                   &in, sizeof(in) - 4, out, sizeof(out));
    ok(status == STATUS_INVALID_PARAMETER, "enumerate short in -> %08lx", (unsigned long)status);

    /* Output below the leading DWORD + the promised arrays. */
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_ENUMERATE_ALL,
                                   &in, sizeof(in), out, 2);
    ok(status == STATUS_INVALID_PARAMETER, "enumerate tiny out -> %08lx", (unsigned long)status);

    /* get_all: a header that stops before its own key, and an output
     * smaller than the promised arrays. */
    memset(&hdr, 0, sizeof(hdr));
    hdr.module = npi_ms_ndis;
    hdr.table = NSI_NDIS_IFINFO_TABLE;
    hdr.key_size = sizeof(NET_LUID);
    hdr.rw_size = sizeof(struct nsi_ndis_ifinfo_rw);

    poison_iosb(&iosb);
    status =
        NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS,
                              &hdr, 8, out, sizeof(out));
    ok(status == STATUS_INVALID_PARAMETER, "get_all short in -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(
        h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS, &hdr,
        FIELD_OFFSET(struct nsiproxy_get_all_parameters, key), out, sizeof(out));
    ok(status == STATUS_INVALID_PARAMETER, "get_all keyless in -> %08lx", (unsigned long)status);

    {
        struct
        {
            struct nsiproxy_get_all_parameters hdr;
            BYTE key_space[8];
        } in2;
        memset(&in2, 0, sizeof(in2));
        in2.hdr.module = npi_ms_ndis;
        in2.hdr.table = NSI_NDIS_IFINFO_TABLE;
        in2.hdr.key_size = sizeof(NET_LUID);
        in2.hdr.rw_size = sizeof(struct nsi_ndis_ifinfo_rw);
        poison_iosb(&iosb);
        status = NtDeviceIoControlFile(
            h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS, &in2,
            FIELD_OFFSET(struct nsiproxy_get_all_parameters, key[8]), out, sizeof(out));
        ok(status == STATUS_INVALID_PARAMETER, "get_all short out -> %08lx", (unsigned long)status);
    }
}

static void test_unbuilt_verbs(void)
{
    BYTE in[128], out[64];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    if (!ntapi_ctx.on_proskrnl)
    {
        /* The oracle SERVES icmp-echo and change-notification; proskrnl's
         * minimal device refuses both until a consumer convicts them —
         * the recorded docs/03 "Net-3 notes" divergence. Exercising the
         * oracle's implementations here would put a live ICMP probe and
         * a never-completing notification into a semantics suite, so the
         * oracle side is not measured beyond that record. */
        skip("icmp-echo/change-notification: oracle serves them; the refusal is proskrnl's");
        return;
    }

    memset(in, 0, sizeof(in));
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_ICMP_ECHO, in,
                                   sizeof(in), out, sizeof(out));
    ok(status == STATUS_NOT_SUPPORTED, "icmp echo -> %08lx", (unsigned long)status);

    poison_iosb(&iosb);
    status =
        NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_CHANGE_NOTIFICATION,
                              in, sizeof(struct nsiproxy_request_notification), NULL, 0);
    ok(status == STATUS_NOT_SUPPORTED, "change notification -> %08lx", (unsigned long)status);
}

START_TEST(nsi_refusal)
{
    NTSTATUS status = nsi_open(&h);
    ok(status == STATUS_SUCCESS, "open -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;
    test_unknown_codes();
    test_unknown_module_table();
    test_short_buffers();
    test_unbuilt_verbs();
    NtClose(h);
}
