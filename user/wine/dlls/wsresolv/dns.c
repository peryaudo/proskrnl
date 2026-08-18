/*
 * wsresolv dns — a minimal DNS client (A/AAAA/CNAME) over ws2_32's own
 * public UDP socket surface (see wsresolv.h).
 *
 * Wire format per RFC 1035 (and RFC 3596 for AAAA) — public spec, the
 * G8 source for every constant here. Recursion is safe by construction:
 * the socket path (socket/sendto/recvfrom/select) never re-enters the
 * resolver (docs/24 §4f).
 *
 * Deliberate scope (docs/03 "Net-3 notes"): UDP only — a truncated (TC)
 * reply answers WSATRY_AGAIN loudly instead of retrying over TCP; no
 * PTR; no search-list suffixing (the name goes to the wire as given).
 * The parser is convicted by the tests/resolv corpus (malformed counts,
 * compression loops, CNAME chains, truncation) — hermetic through the
 * dns_transport seam — and the wire leg by the acceptance run's pcap.
 */
#include "wsresolv.h"

#define DNS_TYPE_A_RR 1
#define DNS_TYPE_CNAME_RR 5
#define DNS_TYPE_AAAA_RR 28
#define DNS_CLASS_IN 1

#define DNS_MAX_SERVERS 4
#define DNS_UDP_MAX 512
#define DNS_TIMEOUT_SECONDS 3
#define DNS_ROUNDS 2

static unsigned short read16( const unsigned char *p )
{
    return (unsigned short)((p[0] << 8) | p[1]);
}

static void write16( unsigned char *p, unsigned short v )
{
    p[0] = v >> 8;
    p[1] = v & 0xff;
}

/* ---- query build ---------------------------------------------------------- */

unsigned int dns_build_query( unsigned char *buffer, unsigned int capacity, const char *name,
                              unsigned short qtype, unsigned short id )
{
    unsigned int at = 12, label_start;
    unsigned int i = 0;

    if (capacity < 18) return 0;
    memset( buffer, 0, 12 );
    write16( buffer, id );
    buffer[2] = 0x01; /* RD */
    write16( buffer + 4, 1 ); /* QDCOUNT */

    for (;;)
    {
        unsigned int label_len = 0;
        label_start = at++;
        while (name[i] && name[i] != '.')
        {
            if (label_len == 63 || at + 5 > capacity) return 0;
            buffer[at++] = (unsigned char)name[i++];
            label_len++;
        }
        if (label_len == 0) return 0; /* empty label ("", ".." or trailing '.') */
        buffer[label_start] = (unsigned char)label_len;
        if (name[i] == '.')
        {
            i++;
            if (!name[i]) break; /* one trailing dot is legal */
        }
        else break;
    }
    if (at + 5 > capacity || at > 12 + 255 ) return 0;
    buffer[at++] = 0;
    write16( buffer + at, qtype );
    at += 2;
    write16( buffer + at, DNS_CLASS_IN );
    at += 2;
    return at;
}

/* ---- reply parse ---------------------------------------------------------- */

/* Decode a (possibly compressed) name at `at` into dotted text; returns
 * the offset just past its in-place representation, or 0 on malformed
 * input. Bounded against pointer loops by a total-jump budget. */
static unsigned int decode_name( const unsigned char *reply, unsigned int length, unsigned int at,
                                 char *out, unsigned int out_capacity )
{
    unsigned int out_at = 0, jumps = 0, after = 0;

    for (;;)
    {
        unsigned char tag;
        if (at >= length) return 0;
        tag = reply[at];
        if (tag == 0)
        {
            if (!after) after = at + 1;
            break;
        }
        if ((tag & 0xc0) == 0xc0)
        {
            unsigned int target;
            if (at + 2 > length) return 0;
            target = ((tag & 0x3f) << 8) | reply[at + 1];
            if (!after) after = at + 2;
            if (++jumps > 32 || target >= length) return 0;
            at = target;
            continue;
        }
        if (tag & 0xc0) return 0;
        if (at + 1 + tag > length) return 0;
        if (out_at + tag + 2 > out_capacity) return 0;
        if (out_at) out[out_at++] = '.';
        memcpy( out + out_at, reply + at + 1, tag );
        out_at += tag;
        at += 1 + tag;
    }
    out[out_at] = 0;
    return after;
}

static int name_equal( const char *a, const char *b )
{
    return _stricmp( a, b ) == 0;
}

int dns_parse_reply( const unsigned char *reply, unsigned int length, unsigned short id,
                     const char *name, unsigned short qtype, struct resolv_result *result )
{
    unsigned int at = 12, i;
    unsigned int qdcount, ancount;
    unsigned char rcode;
    char chain[RESOLV_NAME_MAX];
    unsigned int chain_at = 0;

    if (length < 12) return WSANO_RECOVERY;
    if (read16( reply ) != id) return WSANO_RECOVERY;
    if (!(reply[2] & 0x80)) return WSANO_RECOVERY; /* not a response */
    if (reply[2] & 0x02)
    {
        /* TC: the UDP-only scope's loud edge (header comment). */
        resolv_report( "wsresolv: dns reply truncated; no TCP retry built\n" );
        return WSATRY_AGAIN;
    }
    rcode = reply[3] & 0x0f;
    if (rcode == 3) return WSAHOST_NOT_FOUND; /* NXDOMAIN */
    if (rcode != 0) return WSATRY_AGAIN;      /* SERVFAIL and kin */

    qdcount = read16( reply + 4 );
    ancount = read16( reply + 6 );
    if (qdcount > 8 || ancount > 64) return WSANO_RECOVERY;

    for (i = 0; i < qdcount; i++)
    {
        char qname[RESOLV_NAME_MAX];
        at = decode_name( reply, length, at, qname, sizeof(qname) );
        if (!at || at + 4 > length) return WSANO_RECOVERY;
        at += 4;
    }

    /* The owner chain starts at the queried name; CNAMEs move it. */
    while (name[chain_at] && chain_at < sizeof(chain) - 1)
    {
        chain[chain_at] = name[chain_at];
        chain_at++;
    }
    chain[chain_at] = 0;
    if (chain_at && chain[chain_at - 1] == '.') chain[chain_at - 1] = 0;

    for (i = 0; i < ancount; i++)
    {
        char owner[RESOLV_NAME_MAX];
        unsigned short rtype, rclass, rdlength;

        at = decode_name( reply, length, at, owner, sizeof(owner) );
        if (!at || at + 10 > length) return WSANO_RECOVERY;
        rtype = read16( reply + at );
        rclass = read16( reply + at + 2 );
        rdlength = read16( reply + at + 8 );
        at += 10;
        if (at + rdlength > length) return WSANO_RECOVERY;

        if (rclass == DNS_CLASS_IN && name_equal( owner, chain ))
        {
            if (rtype == DNS_TYPE_CNAME_RR)
            {
                if (!decode_name( reply, length, at, chain, sizeof(chain) ))
                    return WSANO_RECOVERY;
            }
            else if (rtype == qtype && rtype == DNS_TYPE_A_RR && rdlength == 4)
            {
                resolv_result_add( result, AF_INET, reply + at );
                if (!result->canonname[0]) memcpy( result->canonname, chain, strlen( chain ) + 1 );
            }
            else if (rtype == qtype && rtype == DNS_TYPE_AAAA_RR && rdlength == 16)
            {
                resolv_result_add( result, AF_INET6, reply + at );
                if (!result->canonname[0]) memcpy( result->canonname, chain, strlen( chain ) + 1 );
            }
        }
        at += rdlength;
    }
    return 0;
}

/* ---- the real transport: UDP against the lease's servers ------------------ */

struct dns_servers
{
    unsigned int count;
    unsigned char addrs[DNS_MAX_SERVERS][4];
};

static void add_server_list( struct dns_servers *servers, const char *list )
{
    unsigned int i = 0;

    while (list[i] && servers->count < DNS_MAX_SERVERS)
    {
        char one[64];
        unsigned int at = 0;
        unsigned char bytes[4];

        while (list[i] == ' ' || list[i] == ',') i++;
        while (list[i] && list[i] != ' ' && list[i] != ',' && at < sizeof(one) - 1)
            one[at++] = list[i++];
        one[at] = 0;
        if (at && resolv_parse_ipv4( one, bytes ))
        {
            unsigned int j, seen = 0;
            for (j = 0; j < servers->count; j++)
                if (memcmp( servers->addrs[j], bytes, 4 ) == 0) seen = 1;
            if (!seen) memcpy( servers->addrs[servers->count++], bytes, 4 );
        }
    }
}

static void sink_server_value( const WCHAR *text, void *cookie )
{
    char narrow_text[256];
    unsigned int i = 0;

    while (text[i] && i < sizeof(narrow_text) - 1)
    {
        narrow_text[i] = (char)text[i];
        i++;
    }
    narrow_text[i] = 0;
    add_server_list( cookie, narrow_text );
}

static void get_dns_servers( struct dns_servers *servers )
{
    WCHAR text[256];

    servers->count = 0;
    /* A static NameServer overrides; the lease's DhcpNameServer values
     * (drivers/net/netd.c NetdPublishLease, the MS KB 314053 names)
     * otherwise. */
    if (resolv_read_hklm_string(
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            L"NameServer", text, ARRAY_SIZE(text) ) && text[0])
        sink_server_value( text, servers );
    if (!servers->count)
        resolv_collect_interface_values( L"DhcpNameServer", sink_server_value, servers );
}

static int udp_exchange( void *context, const unsigned char *query, unsigned int query_len,
                         unsigned char *reply, unsigned int reply_cap, unsigned int *reply_len )
{
    struct dns_servers *servers = context;
    unsigned int round, i;
    WSADATA wsa_data;

    if (!servers->count) return WSATRY_AGAIN;
    WSAStartup( MAKEWORD(2, 2), &wsa_data ); /* refcounted; the caller may not have */

    for (round = 0; round < DNS_ROUNDS; round++)
    {
        for (i = 0; i < servers->count; i++)
        {
            SOCKET s;
            struct sockaddr_in server;
            TIMEVAL timeout;
            fd_set readers;
            int got;

            s = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
            if (s == INVALID_SOCKET) continue;
            memset( &server, 0, sizeof(server) );
            server.sin_family = AF_INET;
            server.sin_port = (unsigned short)((53 << 8) | (53 >> 8)); /* htons(53) */
            memcpy( &server.sin_addr, servers->addrs[i], 4 );
            if (sendto( s, (const char *)query, (int)query_len, 0, (struct sockaddr *)&server,
                        sizeof(server) ) != (int)query_len)
            {
                closesocket( s );
                continue;
            }
            readers.fd_count = 1;
            readers.fd_array[0] = s;
            timeout.tv_sec = DNS_TIMEOUT_SECONDS;
            timeout.tv_usec = 0;
            if (select( 0, &readers, NULL, NULL, &timeout ) != 1)
            {
                closesocket( s );
                continue;
            }
            got = recvfrom( s, (char *)reply, (int)reply_cap, 0, NULL, NULL );
            closesocket( s );
            if (got <= 0) continue;
            *reply_len = (unsigned int)got;
            WSACleanup();
            return 0;
        }
    }
    WSACleanup();
    return WSATRY_AGAIN;
}

/* ---- the resolver entry point --------------------------------------------- */

static unsigned short next_query_id( void )
{
    static ULONG seed;
    LARGE_INTEGER now;

    if (!seed)
    {
        NtQuerySystemTime( &now );
        seed = now.LowPart | 1;
    }
    return (unsigned short)(RtlRandom( &seed ) & 0xffff);
}

static int query_one( const struct dns_transport *transport, const char *name,
                      unsigned short qtype, struct resolv_result *result )
{
    unsigned char query[DNS_UDP_MAX], reply[DNS_UDP_MAX];
    unsigned int query_len, reply_len = 0;
    unsigned short id = next_query_id();
    int ret;

    query_len = dns_build_query( query, sizeof(query), name, qtype, id );
    if (!query_len) return WSAHOST_NOT_FOUND; /* unencodable name */
    if ((ret = transport->exchange( transport->context, query, query_len, reply, sizeof(reply),
                                    &reply_len )))
        return ret;
    return dns_parse_reply( reply, reply_len, id, name, qtype, result );
}

int dns_resolve( const char *name, BOOL want_v4, BOOL want_v6, const struct dns_transport *transport,
                 struct resolv_result *result )
{
    struct dns_servers servers;
    struct dns_transport udp_transport;
    int ret_v4 = 0, ret_v6 = 0;
    unsigned int before = result->count;

    if (!transport)
    {
        get_dns_servers( &servers );
        if (!servers.count)
        {
            resolv_report( "wsresolv: no DNS servers configured (no lease, no NameServer)\n" );
            return WSATRY_AGAIN;
        }
        udp_transport.exchange = udp_exchange;
        udp_transport.context = &servers;
        transport = &udp_transport;
    }

    if (want_v6) ret_v6 = query_one( transport, name, DNS_TYPE_AAAA_RR, result );
    if (want_v4) ret_v4 = query_one( transport, name, DNS_TYPE_A_RR, result );

    if (result->count > before) return 0;
    if (want_v4 && ret_v4) return ret_v4;
    if (want_v6 && ret_v6) return ret_v6;
    return WSAHOST_NOT_FOUND; /* clean replies, no usable records */
}
