/*
 * tests/resolv/resolv_unit.c — the wsresolv unit corpus (Net-3).
 *
 * The DNS wire code is ~500 lines of parser no boundary test can reach
 * hermetically (a live query's reply is the network's, not the suite's),
 * so this drives dns.c through its dns_transport seam with a canned and
 * adversarial corpus — truncation, compression loops, CNAME chains,
 * malformed counts — plus the literal parsers and the registry-free
 * packing paths of the unixlib entries (numeric getaddrinfo/getnameinfo,
 * localhost), asserted byte-exactly against the shapes the PE consumer
 * (dlls/ws2_32/protocol.c) walks.
 *
 * Built by the `resolvunit` leg (tests/run/run.sh) against the real
 * wsresolv sources and run under the pinned wine; it is a unit verdict
 * on OUR code, not an oracle differential — ws2_32:protocol is the
 * boundary judge (the winefb_unit precedent).
 */
#include "../../user/wine/dlls/wsresolv/wsresolv.h"

/* A self-contained ok() harness (ntapi.h's mingw headers cannot share a
 * TU with the wine headers wsresolv.h stands on): assertions print
 * [ASSERT] lines to stdout, the verdict is one [KTEST] line, the exit
 * code is the failure count clamped to 1. */
static int resolv_unit_failures;
static HANDLE resolv_unit_stdout;

static void unit_out(const char *text)
{
    IO_STATUS_BLOCK iosb;
    unsigned int len = (unsigned int)strlen(text);

    if (resolv_unit_stdout &&
        !NtWriteFile(resolv_unit_stdout, 0, NULL, NULL, &iosb, (void *)text, len, NULL, NULL))
        return;
    /* no console: the serial fallback (the ntapi.c shape) */
    {
        WCHAR wide[256];
        UNICODE_STRING str;
        unsigned int i;
        if (len > 255) len = 255;
        for (i = 0; i < len; i++) wide[i] = (unsigned char)text[i];
        str.Buffer = wide;
        str.Length = len * sizeof(WCHAR);
        str.MaximumLength = str.Length;
        NtDisplayString(&str);
    }
}

static void unit_okv(int cond, int line, const char *fmt, ...)
{
    char text[512];
    va_list args;
    int len;

    if (cond) return;
    resolv_unit_failures++;
    len = _snprintf(text, sizeof(text) - 2, "[ASSERT] resolv_unit.c:%d: ", line);
    va_start(args, fmt);
    len += _vsnprintf(text + len, sizeof(text) - 2 - len, fmt, args);
    va_end(args);
    if (len < 0) len = (int)strlen(text);
    text[len] = '\n';
    text[len + 1] = 0;
    unit_out(text);
}

#define ok(cond, ...) unit_okv((cond) != 0, __LINE__, __VA_ARGS__)

/* ---- literal parsers ------------------------------------------------------ */

static void test_parsers(void)
{
    unsigned char b4[4], b16[16];
    static const unsigned char loop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const unsigned char mixed[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                            0,    0,    0,    0,    1, 2, 3, 4};

    ok(resolv_parse_ipv4("1.2.3.4", b4), "1.2.3.4 refused");
    ok(b4[0] == 1 && b4[1] == 2 && b4[2] == 3 && b4[3] == 4, "1.2.3.4 bytes");
    ok(resolv_parse_ipv4("255.255.255.255", b4), "broadcast refused");
    ok(!resolv_parse_ipv4("1.2.3", b4), "three parts accepted");
    ok(!resolv_parse_ipv4("1.2.3.256", b4), "octet 256 accepted");
    ok(!resolv_parse_ipv4("1.2.3.4.5", b4), "five parts accepted");
    ok(!resolv_parse_ipv4("a.b.c.d", b4), "letters accepted");
    ok(!resolv_parse_ipv4("", b4), "empty accepted");

    ok(resolv_parse_ipv6("::1", b16), "::1 refused");
    ok(memcmp(b16, loop6, 16) == 0, "::1 bytes");
    ok(resolv_parse_ipv6("2001:db8::102:304", b16), "2001:db8 refused");
    ok(memcmp(b16, mixed, 16) == 0, "2001:db8 bytes");
    ok(resolv_parse_ipv6("2001:db8::1.2.3.4", b16), "embedded v4 refused");
    ok(memcmp(b16, mixed, 16) == 0, "embedded v4 bytes");
    ok(resolv_parse_ipv6("1:2:3:4:5:6:7:8", b16), "full groups refused");
    ok(!resolv_parse_ipv6("1:2:3:4:5:6:7:8:9", b16), "nine groups accepted");
    ok(!resolv_parse_ipv6("1::2::3", b16), "double gap accepted");
    ok(!resolv_parse_ipv6("12345::1", b16), "five hex digits accepted");
    ok(!resolv_parse_ipv6("localhost", b16), "name accepted as v6");
}

/* ---- the query builder ---------------------------------------------------- */

static void test_build_query(void)
{
    unsigned char buffer[512];
    static const unsigned char expected[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7,    'e', 'x',
        'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',  0,    0x00, 0x01, 0x00, 0x01};
    unsigned int len;
    char longname[300];
    unsigned int i;

    len = dns_build_query(buffer, sizeof(buffer), "example.com", 1, 0x1234);
    ok(len == sizeof(expected), "query length %u", len);
    ok(len == sizeof(expected) && memcmp(buffer, expected, len) == 0, "query bytes");

    /* One trailing dot is legal and encodes identically. */
    len = dns_build_query(buffer, sizeof(buffer), "example.com.", 1, 0x1234);
    ok(len == sizeof(expected) && memcmp(buffer, expected, len) == 0, "trailing dot");

    ok(dns_build_query(buffer, sizeof(buffer), "", 1, 1) == 0, "empty name encoded");
    ok(dns_build_query(buffer, sizeof(buffer), "a..b", 1, 1) == 0, "empty label encoded");
    for (i = 0; i < 70; i++)
        longname[i] = 'a';
    longname[70] = 0;
    ok(dns_build_query(buffer, sizeof(buffer), longname, 1, 1) == 0, "64-char label encoded");
}

/* ---- the reply parser ----------------------------------------------------- */

/* Assemble a reply: header + echoed question + raw answer bytes. */
static unsigned int make_reply(unsigned char *out, unsigned short id, unsigned char flags2,
                               unsigned char rcode, unsigned short ancount,
                               const unsigned char *answers, unsigned int answers_len)
{
    static const unsigned char question[] = {7,   'e', 'x', 'a', 'm', 'p', 'l', 'e', 3,
                                             'c', 'o', 'm', 0,   0,   1,   0,   1};
    unsigned int at = 0;

    out[0] = id >> 8;
    out[1] = id & 0xff;
    out[2] = 0x80 | flags2; /* QR */
    out[3] = rcode;
    out[4] = 0;
    out[5] = 1; /* QDCOUNT */
    out[6] = ancount >> 8;
    out[7] = ancount & 0xff;
    memset(out + 8, 0, 4);
    at = 12;
    memcpy(out + at, question, sizeof(question));
    at += sizeof(question);
    memcpy(out + at, answers, answers_len);
    return at + answers_len;
}

static void test_parse_reply(void)
{
    unsigned char reply[512];
    unsigned int len;
    struct resolv_result result;
    int ret;

    /* One A answer, owner compressed to the question name (0xc00c). */
    static const unsigned char one_a[] = {0xc0, 0x0c, 0, 1, 0,  1,   0,   0,
                                          0,    60,   0, 4, 93, 184, 216, 34};
    memset(&result, 0, sizeof(result));
    len = make_reply(reply, 0x0101, 0, 0, 1, one_a, sizeof(one_a));
    ret = dns_parse_reply(reply, len, 0x0101, "example.com", 1, &result);
    ok(ret == 0, "one A -> %d", ret);
    ok(result.count == 1, "one A count %u", result.count);
    ok(result.count == 1 && result.addrs[0].family == AF_INET && result.addrs[0].bytes[0] == 93 &&
           result.addrs[0].bytes[3] == 34,
       "one A bytes");
    ok(_stricmp(result.canonname, "example.com") == 0, "one A canonname '%s'", result.canonname);

    /* Wrong id refuses. */
    memset(&result, 0, sizeof(result));
    ret = dns_parse_reply(reply, len, 0x0202, "example.com", 1, &result);
    ok(ret == WSANO_RECOVERY, "wrong id -> %d", ret);

    /* A query (not a response) refuses. */
    memset(&result, 0, sizeof(result));
    reply[2] &= 0x7f;
    ret = dns_parse_reply(reply, len, 0x0101, "example.com", 1, &result);
    ok(ret == WSANO_RECOVERY, "not a response -> %d", ret);
    reply[2] |= 0x80;

    /* Truncation answers try-again (the UDP-only scope's loud edge). */
    memset(&result, 0, sizeof(result));
    len = make_reply(reply, 3, 0x02, 0, 0, one_a, 0);
    ret = dns_parse_reply(reply, len, 3, "example.com", 1, &result);
    ok(ret == WSATRY_AGAIN, "TC -> %d", ret);

    /* NXDOMAIN / SERVFAIL. */
    len = make_reply(reply, 4, 0, 3, 0, one_a, 0);
    ret = dns_parse_reply(reply, len, 4, "example.com", 1, &result);
    ok(ret == WSAHOST_NOT_FOUND, "NXDOMAIN -> %d", ret);
    len = make_reply(reply, 5, 0, 2, 0, one_a, 0);
    ret = dns_parse_reply(reply, len, 5, "example.com", 1, &result);
    ok(ret == WSATRY_AGAIN, "SERVFAIL -> %d", ret);

    /* CNAME chain: example.com -> alias.example.com carrying the A. */
    {
        static const unsigned char cname_chain[] = {
            /* example.com CNAME alias.example.com (compressed tail) */
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8, 5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x0c,
            /* alias.example.com A 10.0.0.5 */
            5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 5};
        memset(&result, 0, sizeof(result));
        len = make_reply(reply, 6, 0, 0, 2, cname_chain, sizeof(cname_chain));
        ret = dns_parse_reply(reply, len, 6, "example.com", 1, &result);
        ok(ret == 0, "cname chain -> %d", ret);
        ok(result.count == 1 && result.addrs[0].bytes[0] == 10, "cname chain address");
        ok(_stricmp(result.canonname, "alias.example.com") == 0, "cname canonname '%s'",
           result.canonname);
    }

    /* An answer owned by an UNRELATED name is ignored. */
    {
        static const unsigned char stray[] = {5, 'o', 't', 'h', 'e', 'r', 0xc0, 0x0c, 0, 1, 0,
                                              1, 0,   0,   0,   60,  0,   4,    9,    9, 9, 9};
        memset(&result, 0, sizeof(result));
        len = make_reply(reply, 7, 0, 0, 1, stray, sizeof(stray));
        ret = dns_parse_reply(reply, len, 7, "example.com", 1, &result);
        ok(ret == 0, "stray owner -> %d", ret);
        ok(result.count == 0, "stray owner collected");
    }

    /* A compression pointer loop is malformed, never a hang. */
    {
        static const unsigned char loop[] = {0xc0, 0x1d, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4};
        memset(&result, 0, sizeof(result));
        len = make_reply(reply, 8, 0, 0, 1, loop, sizeof(loop));
        /* 0x1d = offset of this answer's own name: points at itself. */
        ret = dns_parse_reply(reply, len, 8, "example.com", 1, &result);
        ok(ret == WSANO_RECOVERY, "pointer loop -> %d", ret);
    }

    /* rdlength past the end of the packet is malformed. */
    {
        static const unsigned char overflow[] = {0xc0, 0x0c, 0, 1,   0, 1, 0, 0,
                                                 0,    60,   0, 200, 1, 2, 3, 4};
        memset(&result, 0, sizeof(result));
        len = make_reply(reply, 9, 0, 0, 1, overflow, sizeof(overflow));
        ret = dns_parse_reply(reply, len, 9, "example.com", 1, &result);
        ok(ret == WSANO_RECOVERY, "rdlength overflow -> %d", ret);
    }

    /* AAAA. */
    {
        static const unsigned char one_aaaa[] = {0xc0, 0x0c, 0,    28,   0,    1,    0, 0, 0, 60,
                                                 0,    16,   0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                                 0,    0,    0,    0,    0,    0,    0, 1};
        memset(&result, 0, sizeof(result));
        len = make_reply(reply, 10, 0, 0, 1, one_aaaa, sizeof(one_aaaa));
        ret = dns_parse_reply(reply, len, 10, "example.com", 28, &result);
        ok(ret == 0, "one AAAA -> %d", ret);
        ok(result.count == 1 && result.addrs[0].family == AF_INET6 &&
               result.addrs[0].bytes[15] == 1,
           "one AAAA bytes");
    }
}

/* ---- dns_resolve through the transport seam ------------------------------- */

struct mock_transport_state
{
    int calls;
    int fail_first; /* answer this error on the first exchange */
};

static int mock_exchange(void *context, const unsigned char *query, unsigned int query_len,
                         unsigned char *reply, unsigned int reply_cap, unsigned int *reply_len)
{
    struct mock_transport_state *state = context;
    unsigned short id = (unsigned short)((query[0] << 8) | query[1]);
    unsigned short qtype = (unsigned short)((query[query_len - 4] << 8) | query[query_len - 3]);
    static const unsigned char one_a[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7};

    (void)reply_cap;
    state->calls++;
    if (state->fail_first && state->calls == 1)
        return state->fail_first;
    if (qtype == 28)
    {
        /* no AAAA: clean empty answer */
        *reply_len = make_reply(reply, id, 0, 0, 0, one_a, 0);
        return 0;
    }
    *reply_len = make_reply(reply, id, 0, 0, 1, one_a, sizeof(one_a));
    return 0;
}

static void test_dns_resolve(void)
{
    struct mock_transport_state state = {0, 0};
    struct dns_transport transport = {mock_exchange, &state};
    struct resolv_result result;
    int ret;

    memset(&result, 0, sizeof(result));
    ret = dns_resolve("example.com", TRUE, TRUE, &transport, &result);
    ok(ret == 0, "resolve -> %d", ret);
    ok(result.count == 1 && result.addrs[0].family == AF_INET && result.addrs[0].bytes[0] == 192 &&
           result.addrs[0].bytes[3] == 7,
       "resolve address");
    ok(state.calls == 2, "resolve exchanges %d", state.calls); /* AAAA then A */

    /* A transport failure on one family still surfaces the other's answer. */
    state.calls = 0;
    state.fail_first = WSATRY_AGAIN;
    memset(&result, 0, sizeof(result));
    ret = dns_resolve("example.com", TRUE, TRUE, &transport, &result);
    ok(ret == 0, "half-failed resolve -> %d", ret);
    ok(result.count == 1, "half-failed count %u", result.count);
}

/* ---- registry-free unixlib entries ---------------------------------------- */

static void test_getaddrinfo_numeric(void)
{
    char buffer[1024];
    struct addrinfo hints;
    struct getaddrinfo_params params;
    unsigned int size;
    NTSTATUS ret;
    struct addrinfo *info = (struct addrinfo *)buffer;
    const struct sockaddr_in *sin;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* The grow-and-retry contract: an 8-byte buffer reports the need. */
    size = 8;
    params.node = "192.0.2.55";
    params.service = "443";
    params.hints = &hints;
    params.info = info;
    params.size = &size;
    ret = resolv_getaddrinfo(&params);
    ok(ret == ERROR_INSUFFICIENT_BUFFER, "small buffer -> %d", (int)ret);
    ok(size > 8 && size <= sizeof(buffer), "needed %u", size);

    memset(buffer, 0xcc, sizeof(buffer));
    ret = resolv_getaddrinfo(&params);
    ok(ret == 0, "numeric -> %d", (int)ret);
    ok(info->ai_family == AF_INET, "family %d", info->ai_family);
    ok(info->ai_socktype == SOCK_STREAM, "socktype %d", info->ai_socktype);
    ok(info->ai_protocol == IPPROTO_TCP, "protocol %d", info->ai_protocol);
    ok(info->ai_addrlen == sizeof(struct sockaddr_in), "addrlen %d", (int)info->ai_addrlen);
    ok(info->ai_next == NULL, "next %p", info->ai_next);
    ok(info->ai_canonname == NULL, "canonname %p", info->ai_canonname);
    sin = (const struct sockaddr_in *)info->ai_addr;
    ok(sin->sin_family == AF_INET, "sin family %d", sin->sin_family);
    ok(sin->sin_port == 0xbb01, "sin port %04x", sin->sin_port); /* 443 BE */
    ok(sin->sin_addr.S_un.S_un_b.s_b1 == 192 && sin->sin_addr.S_un.S_un_b.s_b4 == 55, "sin addr");

    /* AI_NUMERICHOST refuses a name without touching any backend. */
    size = sizeof(buffer);
    hints.ai_flags = AI_NUMERICHOST;
    params.node = "not-a-literal.example";
    ret = resolv_getaddrinfo(&params);
    ok(ret == WSAHOST_NOT_FOUND, "AI_NUMERICHOST name -> %d", (int)ret);
    hints.ai_flags = 0;

    /* A v4 literal under AF_INET6 refuses. */
    hints.ai_family = AF_INET6;
    params.node = "192.0.2.55";
    ret = resolv_getaddrinfo(&params);
    ok(ret == WSAHOST_NOT_FOUND, "v4 literal under v6 -> %d", (int)ret);

    /* localhost under AF_UNSPEC: ::1 then 127.0.0.1 (the Windows order). */
    size = sizeof(buffer);
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    params.node = "localhost";
    ret = resolv_getaddrinfo(&params);
    ok(ret == 0, "localhost -> %d", (int)ret);
    ok(info->ai_family == AF_INET6, "localhost first family %d", info->ai_family);
    ok(info->ai_next != NULL && info->ai_next->ai_family == AF_INET, "localhost second family");
    ok(info->ai_canonname != NULL && _stricmp(info->ai_canonname, "localhost") == 0,
       "localhost canonname");

    /* NULL node: loopback without AI_PASSIVE, wildcard with. */
    hints.ai_flags = 0;
    hints.ai_family = AF_INET;
    params.node = NULL;
    ret = resolv_getaddrinfo(&params);
    ok(ret == 0, "null node -> %d", (int)ret);
    sin = (const struct sockaddr_in *)info->ai_addr;
    ok(sin->sin_addr.S_un.S_addr == 0x0100007f, "null node addr %08x",
       (unsigned int)sin->sin_addr.S_un.S_addr);
    hints.ai_flags = AI_PASSIVE;
    ret = resolv_getaddrinfo(&params);
    ok(ret == 0, "passive null node -> %d", (int)ret);
    sin = (const struct sockaddr_in *)info->ai_addr;
    ok(sin->sin_addr.S_un.S_addr == 0, "passive addr %08x",
       (unsigned int)sin->sin_addr.S_un.S_addr);
}

static void test_getnameinfo_numeric(void)
{
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct getnameinfo_params params;
    char host[64], serv[32];
    NTSTATUS ret;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0x5000;                 /* 80 BE */
    sin.sin_addr.S_un.S_addr = 0x0700a8c0; /* 192.168.0.7 */

    params.addr = (const struct sockaddr *)&sin;
    params.addr_len = sizeof(sin);
    params.host = host;
    params.host_len = sizeof(host);
    params.serv = serv;
    params.serv_len = sizeof(serv);
    params.flags = NI_NUMERICHOST | NI_NUMERICSERV;
    ret = resolv_getnameinfo(&params);
    ok(ret == 0, "numeric v4 -> %d", (int)ret);
    ok(strcmp(host, "192.168.0.7") == 0, "numeric v4 host '%s'", host);
    ok(strcmp(serv, "80") == 0, "numeric v4 serv '%s'", serv);

    /* A too-small host buffer refuses WSAEFAULT. */
    params.host_len = 4;
    ret = resolv_getnameinfo(&params);
    ok(ret == WSAEFAULT, "short host buffer -> %d", (int)ret);
    params.host_len = sizeof(host);

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr.u.Byte[0] = 0x20;
    sin6.sin6_addr.u.Byte[1] = 0x01;
    sin6.sin6_addr.u.Byte[3] = 0xb8;
    sin6.sin6_addr.u.Byte[2] = 0x0d;
    sin6.sin6_addr.u.Byte[15] = 1;
    params.addr = (const struct sockaddr *)&sin6;
    params.addr_len = sizeof(sin6);
    params.flags = NI_NUMERICHOST | NI_NUMERICSERV;
    ret = resolv_getnameinfo(&params);
    ok(ret == 0, "numeric v6 -> %d", (int)ret);
    ok(strcmp(host, "2001:db8::1") == 0, "numeric v6 host '%s'", host);
}

void __stdcall resolv_unit_start(void *peb)
{
    (void)peb;
    resolv_unit_stdout = NtCurrentTeb()->Peb->ProcessParameters->hStdOutput;

    test_parsers();
    test_build_query();
    test_parse_reply();
    test_dns_resolve();
    test_getaddrinfo_numeric();
    test_getnameinfo_numeric();

    unit_out(resolv_unit_failures ? "[KTEST] resolvunit FAIL\n" : "[KTEST] resolvunit PASS\n");
    NtTerminateProcess(NtCurrentProcess(), resolv_unit_failures ? 1 : 0);
}
