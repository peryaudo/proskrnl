/*
 * wsresolv resolv — the five unixlib entries and the resolution engine
 * (see wsresolv.h).
 *
 * Resolution order (the Windows shape the ws2_32:protocol pair judges):
 * numeric literals, localhost, the machine's own names (registry
 * Hostname/Domain/ComputerName), the drivers\etc\hosts file, then DNS
 * (dns.c) against the servers the Net-1 lease wrote. getnameinfo serves
 * the numeric direction plus hosts/local reverse matches; wire PTR stays
 * unbuilt and refuses loudly (docs/03 "Net-3 notes").
 *
 * Buffer contract (the PE consumer's shape, dlls/ws2_32/protocol.c):
 * getaddrinfo/gethostbyname/gethostbyaddr pack their whole result into
 * the caller's buffer of *size bytes — internal pointers point inside it
 * — or set *size to the requirement and answer ERROR_INSUFFICIENT_BUFFER
 * for the caller's grow-and-retry loop.
 */
#include "wsresolv.h"

/* ---- small string/byte helpers (ntdll's CRT exports only) ----------------- */

static int resolv_strieq( const char *a, const char *b )
{
    return _stricmp( a, b ) == 0;
}

static unsigned short swap16( unsigned short v )
{
    return (unsigned short)((v << 8) | (v >> 8));
}

/* ---- registry helpers ----------------------------------------------------- */

static const WCHAR tcpip_params_key[] =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters";
static const WCHAR interfaces_key[] =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";

static NTSTATUS open_key( const WCHAR *path, HANDLE *handle )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    RtlInitUnicodeString( &name, path );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, 0, NULL );
    return NtOpenKey( handle, KEY_READ, &attr );
}

static unsigned int query_value_string( HANDLE key, const WCHAR *value, WCHAR *buffer,
                                        unsigned int capacity )
{
    char raw[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 512 * sizeof(WCHAR)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)raw;
    UNICODE_STRING value_name;
    ULONG length = 0;
    unsigned int chars;

    RtlInitUnicodeString( &value_name, value );
    if (NtQueryValueKey( key, &value_name, KeyValuePartialInformation, raw, sizeof(raw), &length ))
        return 0;
    if (info->Type != REG_SZ && info->Type != REG_EXPAND_SZ && info->Type != REG_MULTI_SZ)
        return 0;
    chars = info->DataLength / sizeof(WCHAR);
    while (chars && ((const WCHAR *)info->Data)[chars - 1] == 0) chars--;
    if (chars + 1 > capacity) return 0;
    memcpy( buffer, info->Data, chars * sizeof(WCHAR) );
    buffer[chars] = 0;
    return chars;
}

unsigned int resolv_read_hklm_string( const WCHAR *key_path, const WCHAR *value, WCHAR *buffer,
                                      unsigned int capacity )
{
    HANDLE key;
    unsigned int chars;

    if (open_key( key_path, &key )) return 0;
    chars = query_value_string( key, value, buffer, capacity );
    NtClose( key );
    return chars;
}

/* Walk the lease keys under Interfaces, handing each named REG_SZ value
 * to `sink` (dotted quads / space-separated server lists). */
void resolv_collect_interface_values( const WCHAR *value,
                                      void (*sink)( const WCHAR *text, void *cookie ),
                                      void *cookie )
{
    HANDLE root;
    ULONG index;

    if (open_key( interfaces_key, &root )) return;
    for (index = 0;; index++)
    {
        char raw[sizeof(KEY_BASIC_INFORMATION) + 128 * sizeof(WCHAR)];
        KEY_BASIC_INFORMATION *info = (KEY_BASIC_INFORMATION *)raw;
        ULONG length = 0;
        WCHAR name[130];
        WCHAR text[256];
        UNICODE_STRING sub_name;
        OBJECT_ATTRIBUTES attr;
        HANDLE sub;

        if (NtEnumerateKey( root, index, KeyBasicInformation, raw, sizeof(raw), &length )) break;
        if (info->NameLength / sizeof(WCHAR) >= ARRAY_SIZE(name)) continue;
        memcpy( name, info->Name, info->NameLength );
        name[info->NameLength / sizeof(WCHAR)] = 0;

        RtlInitUnicodeString( &sub_name, name );
        InitializeObjectAttributes( &attr, &sub_name, OBJ_CASE_INSENSITIVE, root, NULL );
        if (NtOpenKey( &sub, KEY_READ, &attr )) continue;
        if (query_value_string( sub, value, text, ARRAY_SIZE(text) )) sink( text, cookie );
        NtClose( sub );
    }
    NtClose( root );
}

/* ---- files ---------------------------------------------------------------- */

char *resolv_read_file( const WCHAR *nt_path )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION std_info;
    HANDLE handle;
    char *data;
    ULONG size;

    RtlInitUnicodeString( &name, nt_path );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, 0, NULL );
    if (NtCreateFile( &handle, GENERIC_READ | SYNCHRONIZE, &attr, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0 ))
        return NULL;
    if (NtQueryInformationFile( handle, &iosb, &std_info, sizeof(std_info),
                                FileStandardInformation ) ||
        std_info.EndOfFile.QuadPart > 1024 * 1024)
    {
        NtClose( handle );
        return NULL;
    }
    size = (ULONG)std_info.EndOfFile.QuadPart;
    if (!(data = resolv_alloc( size + 1 )))
    {
        NtClose( handle );
        return NULL;
    }
    if (NtReadFile( handle, 0, NULL, NULL, &iosb, data, size, NULL, NULL ))
    {
        resolv_free( data );
        NtClose( handle );
        return NULL;
    }
    data[iosb.Information] = 0;
    NtClose( handle );
    return data;
}

BOOL resolv_etc_prefix( WCHAR *buffer, unsigned int capacity )
{
    WCHAR path[300];
    static const WCHAR nt_prefix[] = L"\\??\\";
    static const WCHAR sysroot[] = L"%SystemRoot%";
    static const WCHAR windir[] = L"C:\\windows";
    unsigned int chars, at = 0, i = 0;

    chars = resolv_read_hklm_string( tcpip_params_key, L"DataBasePath", path, ARRAY_SIZE(path) );
    if (!chars) return FALSE;

    for (i = 0; nt_prefix[i]; i++)
    {
        if (at + 1 >= capacity) return FALSE;
        buffer[at++] = nt_prefix[i];
    }
    i = 0;
    /* wine.inf stores the expanded %12% path, but tolerate a literal
     * %SystemRoot% prefix the way kernelbase would expand it. */
    if (!_wcsnicmp( path, sysroot, ARRAY_SIZE(sysroot) - 1 ))
    {
        unsigned int j;
        for (j = 0; windir[j]; j++)
        {
            if (at + 1 >= capacity) return FALSE;
            buffer[at++] = windir[j];
        }
        i = ARRAY_SIZE(sysroot) - 1;
    }
    for (; path[i]; i++)
    {
        if (at + 1 >= capacity) return FALSE;
        buffer[at++] = path[i];
    }
    if (at && buffer[at - 1] != '\\')
    {
        if (at + 1 >= capacity) return FALSE;
        buffer[at++] = '\\';
    }
    buffer[at] = 0;
    return TRUE;
}

static char *read_etc_file( const WCHAR *name )
{
    WCHAR path[340];
    unsigned int at, i;

    if (!resolv_etc_prefix( path, ARRAY_SIZE(path) )) return NULL;
    at = wcslen( path );
    for (i = 0; name[i]; i++)
    {
        if (at + 1 >= ARRAY_SIZE(path)) return NULL;
        path[at++] = name[i];
    }
    path[at] = 0;
    return resolv_read_file( path );
}

/* ---- literals ------------------------------------------------------------- */

BOOL resolv_parse_ipv4( const char *text, unsigned char out[4] )
{
    unsigned int part = 0, value = 0, digits = 0;
    unsigned int i;

    for (i = 0;; i++)
    {
        char c = text[i];
        if (c >= '0' && c <= '9')
        {
            value = value * 10 + (c - '0');
            digits++;
            if (value > 255 || digits > 3) return FALSE;
        }
        else if (c == '.' || c == 0)
        {
            if (!digits || part >= 4) return FALSE;
            out[part++] = (unsigned char)value;
            value = 0;
            digits = 0;
            if (c == 0) break;
        }
        else return FALSE;
    }
    return part == 4;
}

static int hex_value( char c )
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

BOOL resolv_parse_ipv6( const char *text, unsigned char out[16] )
{
    unsigned short groups[8];
    int group_count = 0, gap_at = -1;
    unsigned int i = 0;
    int j;

    if (text[0] == ':' && text[1] == ':')
    {
        gap_at = 0;
        i = 2;
        if (!text[i]) goto done;
    }
    for (;;)
    {
        unsigned int value = 0, digits = 0;
        unsigned int start = i;
        /* An embedded v4 tail takes the last two groups. */
        {
            unsigned int k = i;
            BOOL sees_dot = FALSE;
            while (text[k] && text[k] != ':')
            {
                if (text[k] == '.') sees_dot = TRUE;
                k++;
            }
            if (sees_dot && text[k] == 0)
            {
                unsigned char v4[4];
                if (!resolv_parse_ipv4( text + i, v4 ) || group_count > 6) return FALSE;
                groups[group_count++] = (unsigned short)((v4[0] << 8) | v4[1]);
                groups[group_count++] = (unsigned short)((v4[2] << 8) | v4[3]);
                goto done;
            }
        }
        while (hex_value( text[i] ) >= 0)
        {
            value = (value << 4) | hex_value( text[i] );
            digits++;
            i++;
            if (digits > 4) return FALSE;
        }
        if (!digits) return FALSE;
        if (group_count >= 8) return FALSE;
        groups[group_count++] = (unsigned short)value;
        (void)start;
        if (text[i] == 0) break;
        if (text[i] != ':') return FALSE;
        i++;
        if (text[i] == ':')
        {
            if (gap_at >= 0) return FALSE;
            gap_at = group_count;
            i++;
            if (!text[i]) break;
        }
    }
done:
    if (gap_at < 0 && group_count != 8) return FALSE;
    if (gap_at >= 0 && group_count >= 8) return FALSE;
    memset( out, 0, 16 );
    for (j = 0; j < (gap_at < 0 ? group_count : gap_at); j++)
    {
        out[j * 2] = groups[j] >> 8;
        out[j * 2 + 1] = groups[j] & 0xff;
    }
    if (gap_at >= 0)
    {
        int tail = group_count - gap_at;
        for (j = 0; j < tail; j++)
        {
            int group = gap_at + j, slot = 8 - tail + j;
            out[slot * 2] = groups[group] >> 8;
            out[slot * 2 + 1] = groups[group] & 0xff;
        }
    }
    return TRUE;
}

static unsigned int format_ipv4( const unsigned char *bytes, char *out )
{
    return sprintf( out, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3] );
}

static unsigned int format_ipv6( const unsigned char *bytes, char *out )
{
    /* Grouped hex with the longest zero run compressed (RFC 5952 enough
     * for the numeric direction). */
    unsigned short groups[8];
    int best_at = -1, best_len = 0, run_at = -1, run_len = 0, i;
    char *p = out;

    for (i = 0; i < 8; i++) groups[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
    for (i = 0; i < 8; i++)
    {
        if (groups[i] == 0)
        {
            if (run_at < 0) run_at = i;
            run_len = i - run_at + 1;
            if (run_len > best_len)
            {
                best_len = run_len;
                best_at = run_at;
            }
        }
        else run_at = -1;
    }
    if (best_len < 2) best_at = -1;
    for (i = 0; i < 8; i++)
    {
        if (best_at >= 0 && i == best_at)
        {
            *p++ = ':';
            if (i == 0) *p++ = ':';
            i += best_len - 1;
            if (i == 7) *p++ = ':';
            continue;
        }
        p += sprintf( p, "%x", groups[i] );
        if (i != 7) *p++ = ':';
    }
    *p = 0;
    return (unsigned int)(p - out);
}

/* ---- the result set ------------------------------------------------------- */

void resolv_result_add( struct resolv_result *result, int family, const void *bytes )
{
    unsigned int length = family == AF_INET ? 4 : 16;
    unsigned int i;

    for (i = 0; i < result->count; i++)
    {
        if (result->addrs[i].family == family &&
            memcmp( result->addrs[i].bytes, bytes, length ) == 0)
            return;
    }
    if (result->count == RESOLV_MAX_ADDRS) return;
    result->addrs[result->count].family = family;
    memset( result->addrs[result->count].bytes, 0, 16 );
    memcpy( result->addrs[result->count].bytes, bytes, length );
    result->count++;
}

static void set_canonname( struct resolv_result *result, const char *name )
{
    unsigned int i = 0;
    while (name[i] && i < RESOLV_NAME_MAX - 1)
    {
        result->canonname[i] = name[i];
        i++;
    }
    result->canonname[i] = 0;
}

/* ---- the machine's own names and addresses -------------------------------- */

static void narrow( const WCHAR *wide, char *out, unsigned int capacity )
{
    unsigned int i = 0;
    while (wide[i] && i < capacity - 1)
    {
        out[i] = (char)wide[i];
        i++;
    }
    out[i] = 0;
}

static void get_local_names( char *hostname, unsigned int hostname_cap, char *fqdn,
                             unsigned int fqdn_cap )
{
    WCHAR host_w[128], domain_w[128];
    char domain[128];

    hostname[0] = 0;
    fqdn[0] = 0;
    if (!resolv_read_hklm_string( tcpip_params_key, L"Hostname", host_w, ARRAY_SIZE(host_w) ))
        return;
    narrow( host_w, hostname, hostname_cap );
    if (resolv_read_hklm_string( tcpip_params_key, L"Domain", domain_w, ARRAY_SIZE(domain_w) ) &&
        domain_w[0])
    {
        narrow( domain_w, domain, sizeof(domain) );
        _snprintf( fqdn, fqdn_cap - 1, "%s.%s", hostname, domain );
        fqdn[fqdn_cap - 1] = 0;
    }
}

static BOOL is_local_name( const char *node, char *fqdn_out, unsigned int fqdn_cap )
{
    char hostname[128], fqdn[256];
    WCHAR computer_w[64];
    char computer[64];

    get_local_names( hostname, sizeof(hostname), fqdn, sizeof(fqdn) );
    if (fqdn_out)
    {
        if (fqdn[0]) { unsigned int i = 0; while (fqdn[i] && i < fqdn_cap - 1) { fqdn_out[i] = fqdn[i]; i++; } fqdn_out[i] = 0; }
        else { unsigned int i = 0; while (hostname[i] && i < fqdn_cap - 1) { fqdn_out[i] = hostname[i]; i++; } fqdn_out[i] = 0; }
    }
    if (hostname[0] && resolv_strieq( node, hostname )) return TRUE;
    if (fqdn[0] && resolv_strieq( node, fqdn )) return TRUE;
    if (resolv_read_hklm_string(
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ComputerName"
            L"\\ActiveComputerName",
            L"ComputerName", computer_w, ARRAY_SIZE(computer_w) ))
    {
        narrow( computer_w, computer, sizeof(computer) );
        if (computer[0] && resolv_strieq( node, computer )) return TRUE;
    }
    return FALSE;
}

static void add_lease_address( const WCHAR *text, void *cookie )
{
    struct resolv_result *result = cookie;
    char narrow_text[64];
    unsigned char v4[4];

    narrow( text, narrow_text, sizeof(narrow_text) );
    if (resolv_parse_ipv4( narrow_text, v4 )) resolv_result_add( result, AF_INET, v4 );
}

static void get_local_addresses( struct resolv_result *result, BOOL want_v4, BOOL want_v6 )
{
    static const unsigned char loopback4[4] = {127, 0, 0, 1};

    if (want_v4)
    {
        resolv_collect_interface_values( L"DhcpIPAddress", add_lease_address, result );
        resolv_result_add( result, AF_INET, loopback4 );
    }
    (void)want_v6; /* the machine holds no global v6 address (staged v6) */
}

/* ---- the hosts file ------------------------------------------------------- */

/* Tokenize `line` in place; returns token count. */
static unsigned int split_line( char *line, char *tokens[], unsigned int capacity )
{
    unsigned int count = 0;
    char *p = line;

    for (;;)
    {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == 0 || *p == '#') break;
        if (count == capacity) break;
        tokens[count++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
        else break;
    }
    return count;
}

/* Walk hosts lines: `visit` gets the parsed address and the name tokens,
 * returns TRUE to stop. */
struct hosts_row
{
    int family;
    unsigned char bytes[16];
    char **names;
    unsigned int name_count;
};

static void for_each_hosts_row( BOOL (*visit)( const struct hosts_row *row, void *cookie ),
                                void *cookie )
{
    char *data = read_etc_file( L"hosts" );
    char *line, *next;

    if (!data) return;
    for (line = data; line; line = next)
    {
        char *tokens[16];
        unsigned int count;
        struct hosts_row row;

        next = strchr( line, '\n' );
        if (next)
        {
            *next = 0;
            next++;
        }
        count = split_line( line, tokens, ARRAY_SIZE(tokens) );
        if (count < 2) continue;
        if (resolv_parse_ipv4( tokens[0], row.bytes )) row.family = AF_INET;
        else if (resolv_parse_ipv6( tokens[0], row.bytes )) row.family = AF_INET6;
        else continue;
        row.names = tokens + 1;
        row.name_count = count - 1;
        if (visit( &row, cookie )) break;
    }
    resolv_free( data );
}

struct hosts_lookup
{
    const char *node;
    BOOL want_v4, want_v6;
    struct resolv_result *result;
};

static BOOL hosts_lookup_visit( const struct hosts_row *row, void *cookie )
{
    struct hosts_lookup *lookup = cookie;
    unsigned int i;

    if (row->family == AF_INET && !lookup->want_v4) return FALSE;
    if (row->family == AF_INET6 && !lookup->want_v6) return FALSE;
    for (i = 0; i < row->name_count; i++)
    {
        if (resolv_strieq( row->names[i], lookup->node ))
        {
            if (!lookup->result->count) set_canonname( lookup->result, row->names[0] );
            resolv_result_add( lookup->result, row->family, row->bytes );
            return FALSE; /* keep walking: more rows may carry the name */
        }
    }
    return FALSE;
}

struct hosts_reverse
{
    int family;
    const unsigned char *bytes;
    char name[RESOLV_NAME_MAX];
};

static BOOL hosts_reverse_visit( const struct hosts_row *row, void *cookie )
{
    struct hosts_reverse *reverse = cookie;
    unsigned int length = row->family == AF_INET ? 4 : 16;
    unsigned int i = 0;

    if (row->family != reverse->family || memcmp( row->bytes, reverse->bytes, length ) != 0)
        return FALSE;
    while (row->names[0][i] && i < RESOLV_NAME_MAX - 1)
    {
        reverse->name[i] = row->names[0][i];
        i++;
    }
    reverse->name[i] = 0;
    return TRUE;
}

/* ---- services ------------------------------------------------------------- */

static BOOL numeric_port( const char *text, unsigned int *port )
{
    unsigned int value = 0, i;

    if (!text[0]) return FALSE;
    for (i = 0; text[i]; i++)
    {
        if (text[i] < '0' || text[i] > '9') return FALSE;
        value = value * 10 + (text[i] - '0');
        if (value > 65535) return FALSE;
    }
    *port = value;
    return TRUE;
}

/* Look `service` up in drivers\etc\services filtered by socktype
 * (0 = either); answers the port in HOST order or -1. */
static int service_port( const char *service, int socktype )
{
    char *data = read_etc_file( L"services" );
    char *line, *next;
    int port = -1;

    if (!data) return -1;
    for (line = data; line && port < 0; line = next)
    {
        char *tokens[16];
        unsigned int count, i, value;
        char *slash;

        next = strchr( line, '\n' );
        if (next)
        {
            *next = 0;
            next++;
        }
        count = split_line( line, tokens, ARRAY_SIZE(tokens) );
        if (count < 2) continue;
        slash = strchr( tokens[1], '/' );
        if (!slash) continue;
        *slash = 0;
        if (!numeric_port( tokens[1], &value )) continue;
        if (socktype == SOCK_STREAM && _stricmp( slash + 1, "tcp" )) continue;
        if (socktype == SOCK_DGRAM && _stricmp( slash + 1, "udp" )) continue;
        for (i = 0; i < count && port < 0; i++)
        {
            if (i == 1) continue;
            if (resolv_strieq( tokens[i], service )) port = (int)value;
        }
    }
    resolv_free( data );
    return port;
}

/* The reverse direction for getnameinfo. */
static BOOL service_name( unsigned int port, BOOL datagram, char *out, unsigned int capacity )
{
    char *data = read_etc_file( L"services" );
    char *line, *next;
    BOOL found = FALSE;

    if (!data) return FALSE;
    for (line = data; line && !found; line = next)
    {
        char *tokens[16];
        unsigned int count, value, i;
        char *slash;

        next = strchr( line, '\n' );
        if (next)
        {
            *next = 0;
            next++;
        }
        count = split_line( line, tokens, ARRAY_SIZE(tokens) );
        if (count < 2) continue;
        slash = strchr( tokens[1], '/' );
        if (!slash) continue;
        *slash = 0;
        if (!numeric_port( tokens[1], &value ) || value != port) continue;
        if (_stricmp( slash + 1, datagram ? "udp" : "tcp" )) continue;
        i = 0;
        while (tokens[0][i] && i < capacity - 1)
        {
            out[i] = tokens[0][i];
            i++;
        }
        out[i] = 0;
        found = TRUE;
    }
    resolv_free( data );
    return found;
}

/* ---- the shared name-resolution engine ------------------------------------ */

static int resolve_node( const char *node, int family, int flags, struct resolv_result *result )
{
    BOOL want_v4 = family != AF_INET6;
    BOOL want_v6 = family != AF_INET;
    static const unsigned char loopback4[4] = {127, 0, 0, 1};
    static const unsigned char loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const unsigned char any4[4] = {0, 0, 0, 0};
    static const unsigned char any6[16] = {0};
    unsigned char bytes[16];
    char fqdn[RESOLV_NAME_MAX];

    memset( result, 0, sizeof(*result) );

    if (!node)
    {
        if (flags & AI_PASSIVE)
        {
            if (want_v6) resolv_result_add( result, AF_INET6, any6 );
            if (want_v4) resolv_result_add( result, AF_INET, any4 );
        }
        else
        {
            if (want_v6) resolv_result_add( result, AF_INET6, loopback6 );
            if (want_v4) resolv_result_add( result, AF_INET, loopback4 );
        }
        return result->count ? 0 : WSAHOST_NOT_FOUND;
    }

    if (resolv_parse_ipv4( node, bytes ))
    {
        if (!want_v4) return WSAHOST_NOT_FOUND;
        resolv_result_add( result, AF_INET, bytes );
        set_canonname( result, node );
        return 0;
    }
    if (resolv_parse_ipv6( node, bytes ))
    {
        if (!want_v6) return WSAHOST_NOT_FOUND;
        resolv_result_add( result, AF_INET6, bytes );
        set_canonname( result, node );
        return 0;
    }
    if (flags & AI_NUMERICHOST) return WSAHOST_NOT_FOUND;

    if (resolv_strieq( node, "localhost" ) || resolv_strieq( node, "localhost.localdomain" ))
    {
        if (want_v6) resolv_result_add( result, AF_INET6, loopback6 );
        if (want_v4) resolv_result_add( result, AF_INET, loopback4 );
        set_canonname( result, "localhost" );
        return result->count ? 0 : WSAHOST_NOT_FOUND;
    }

    if (is_local_name( node, fqdn, sizeof(fqdn) ))
    {
        get_local_addresses( result, want_v4, want_v6 );
        set_canonname( result, fqdn );
        return result->count ? 0 : WSAHOST_NOT_FOUND;
    }

    {
        struct hosts_lookup lookup = {node, want_v4, want_v6, result};
        for_each_hosts_row( hosts_lookup_visit, &lookup );
        if (result->count) return 0;
    }

    return dns_resolve( node, want_v4, want_v6, NULL, result );
}

/* ---- getaddrinfo ---------------------------------------------------------- */

NTSTATUS resolv_getaddrinfo( void *args )
{
    struct getaddrinfo_params *params = args;
    const struct addrinfo *hints = params->hints;
    int family = hints ? hints->ai_family : AF_UNSPEC;
    int flags = hints ? hints->ai_flags : 0;
    int socktype = hints ? hints->ai_socktype : 0;
    int protocol = hints ? hints->ai_protocol : 0;
    unsigned int port = 0;
    struct resolv_result result;
    unsigned int needed, canon_len = 0, i;
    char *cursor;
    struct addrinfo *previous = NULL;
    int ret;

    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6)
    {
        resolv_report( "wsresolv: getaddrinfo family %d refused\n", family );
        return WSAEAFNOSUPPORT;
    }

    if (params->service && params->service[0])
    {
        if (!numeric_port( params->service, &port ))
        {
            int found = service_port( params->service, socktype );
            if (found < 0) return WSATYPE_NOT_FOUND; /* EAI_SERVICE */
            port = (unsigned int)found;
        }
    }

    if ((ret = resolve_node( params->node, family, flags, &result ))) return ret;
    if (!result.count) return WSAHOST_NOT_FOUND;

    if ((flags & AI_CANONNAME) && result.canonname[0])
        canon_len = (unsigned int)strlen( result.canonname ) + 1;
    needed = result.count * (sizeof(struct addrinfo) + sizeof(SOCKADDR_STORAGE)) + canon_len;
    if (needed > *params->size)
    {
        *params->size = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset( params->info, 0, needed );
    cursor = (char *)params->info;
    for (i = 0; i < result.count; i++)
    {
        struct addrinfo *info = (struct addrinfo *)cursor;
        SOCKADDR_STORAGE *storage = (SOCKADDR_STORAGE *)(cursor + sizeof(struct addrinfo));

        info->ai_flags = 0;
        info->ai_family = result.addrs[i].family;
        info->ai_socktype = socktype;
        info->ai_protocol = protocol;
        info->ai_addr = (struct sockaddr *)storage;
        if (result.addrs[i].family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)storage;
            sin->sin_family = AF_INET;
            sin->sin_port = swap16( (unsigned short)port );
            memcpy( &sin->sin_addr, result.addrs[i].bytes, 4 );
            info->ai_addrlen = sizeof(*sin);
        }
        else
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)storage;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = swap16( (unsigned short)port );
            memcpy( &sin6->sin6_addr, result.addrs[i].bytes, 16 );
            info->ai_addrlen = sizeof(*sin6);
        }
        if (previous) previous->ai_next = info;
        previous = info;
        cursor += sizeof(struct addrinfo) + sizeof(SOCKADDR_STORAGE);
    }
    if (canon_len)
    {
        memcpy( cursor, result.canonname, canon_len );
        params->info->ai_canonname = cursor;
    }
    return 0;
}

/* ---- hostent packing (gethostbyname / gethostbyaddr) ---------------------- */

static NTSTATUS pack_hostent( struct hostent *host, unsigned int *size, const char *name,
                              const struct resolv_result *result )
{
    unsigned int v4_count = 0, i, needed;
    char *cursor;
    unsigned int name_len = (unsigned int)strlen( name ) + 1;

    for (i = 0; i < result->count; i++)
        if (result->addrs[i].family == AF_INET) v4_count++;
    if (!v4_count) return WSAHOST_NOT_FOUND;

    needed = sizeof(struct hostent) + sizeof(char *) /* aliases: the NULL */
             + (v4_count + 1) * sizeof(char *) + v4_count * 4 + name_len;
    if (needed > *size)
    {
        *size = needed;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memset( host, 0, needed );
    cursor = (char *)(host + 1);
    host->h_aliases = (char **)cursor;
    cursor += sizeof(char *); /* one NULL */
    host->h_addr_list = (char **)cursor;
    cursor += (v4_count + 1) * sizeof(char *);
    v4_count = 0;
    for (i = 0; i < result->count; i++)
    {
        if (result->addrs[i].family != AF_INET) continue;
        host->h_addr_list[v4_count] = cursor;
        memcpy( cursor, result->addrs[i].bytes, 4 );
        cursor += 4;
        v4_count++;
    }
    host->h_name = cursor;
    memcpy( cursor, name, name_len );
    host->h_addrtype = AF_INET;
    host->h_length = 4;
    return 0;
}

NTSTATUS resolv_gethostbyname( void *args )
{
    struct gethostbyname_params *params = args;
    struct resolv_result result;
    int ret;

    if ((ret = resolve_node( params->name, AF_INET, 0, &result ))) return ret;
    return pack_hostent( params->host, params->size,
                         result.canonname[0] ? result.canonname : params->name, &result );
}

NTSTATUS resolv_gethostbyaddr( void *args )
{
    struct gethostbyaddr_params *params = args;
    struct resolv_result result;
    struct hosts_reverse reverse;
    static const unsigned char loopback4[4] = {127, 0, 0, 1};

    if (params->family != AF_INET || params->len < 4) return WSAEAFNOSUPPORT;

    memset( &result, 0, sizeof(result) );
    resolv_result_add( &result, AF_INET, params->addr );

    reverse.family = AF_INET;
    reverse.bytes = params->addr;
    reverse.name[0] = 0;
    for_each_hosts_row( hosts_reverse_visit, &reverse );
    if (!reverse.name[0])
    {
        if (memcmp( params->addr, loopback4, 4 ) == 0)
        {
            static const char localhost[] = "localhost";
            memcpy( reverse.name, localhost, sizeof(localhost) );
        }
        else
        {
            struct resolv_result locals;
            unsigned int i;
            memset( &locals, 0, sizeof(locals) );
            get_local_addresses( &locals, TRUE, FALSE );
            for (i = 0; i < locals.count; i++)
            {
                if (memcmp( locals.addrs[i].bytes, params->addr, 4 ) == 0)
                {
                    char hostname[128], fqdn[RESOLV_NAME_MAX];
                    get_local_names( hostname, sizeof(hostname), fqdn, sizeof(fqdn) );
                    if (hostname[0])
                        memcpy( reverse.name, hostname, strlen( hostname ) + 1 );
                    break;
                }
            }
        }
    }
    if (!reverse.name[0])
    {
        /* Wire PTR stays unbuilt (docs/03 "Net-3 notes"): loud, specific. */
        resolv_report( "wsresolv: gethostbyaddr beyond hosts/local refused (PTR unbuilt)\n" );
        return WSAHOST_NOT_FOUND;
    }
    return pack_hostent( params->host, params->size, reverse.name, &result );
}

/* ---- gethostname / getnameinfo -------------------------------------------- */

NTSTATUS resolv_gethostname( void *args )
{
    struct gethostname_params *params = args;
    char hostname[128], fqdn[RESOLV_NAME_MAX];
    unsigned int length;

    get_local_names( hostname, sizeof(hostname), fqdn, sizeof(fqdn) );
    if (!hostname[0]) return WSAENETDOWN;
    length = (unsigned int)strlen( hostname );
    if (length + 1 > params->size) return WSAEFAULT;
    memcpy( params->name, hostname, length + 1 );
    return 0;
}

NTSTATUS resolv_getnameinfo( void *args )
{
    struct getnameinfo_params *params = args;
    const struct sockaddr *addr = params->addr;
    int family;
    const unsigned char *bytes;
    unsigned int port;

    if (!addr || params->addr_len < (int)sizeof(struct sockaddr_in)) return WSAEFAULT;
    family = addr->sa_family;
    if (family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        bytes = (const unsigned char *)&sin->sin_addr;
        port = swap16( sin->sin_port );
    }
    else if (family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        if (params->addr_len < (int)sizeof(struct sockaddr_in6)) return WSAEFAULT;
        bytes = (const unsigned char *)&sin6->sin6_addr;
        port = swap16( sin6->sin6_port );
    }
    else return WSAEAFNOSUPPORT;

    if (params->host && params->host_len)
    {
        char text[RESOLV_NAME_MAX];
        unsigned int length;

        text[0] = 0;
        if (!(params->flags & NI_NUMERICHOST))
        {
            struct hosts_reverse reverse;
            reverse.family = family;
            reverse.bytes = bytes;
            reverse.name[0] = 0;
            for_each_hosts_row( hosts_reverse_visit, &reverse );
            if (reverse.name[0]) memcpy( text, reverse.name, strlen( reverse.name ) + 1 );
            else if (family == AF_INET)
            {
                static const unsigned char loopback4[4] = {127, 0, 0, 1};
                if (memcmp( bytes, loopback4, 4 ) == 0)
                    memcpy( text, "localhost", sizeof("localhost") );
            }
            if (!text[0] && (params->flags & NI_NAMEREQD))
            {
                /* Wire PTR stays unbuilt: loud, specific (docs/03). */
                resolv_report( "wsresolv: getnameinfo NI_NAMEREQD beyond hosts refused (PTR unbuilt)\n" );
                return WSAHOST_NOT_FOUND;
            }
        }
        if (!text[0])
        {
            if (family == AF_INET) format_ipv4( bytes, text );
            else format_ipv6( bytes, text );
        }
        length = (unsigned int)strlen( text );
        if (length + 1 > params->host_len) return WSAEFAULT;
        memcpy( params->host, text, length + 1 );
    }

    if (params->serv && params->serv_len)
    {
        char text[64];
        unsigned int length;

        text[0] = 0;
        if (!(params->flags & NI_NUMERICSERV))
            service_name( port, (params->flags & NI_DGRAM) != 0, text, sizeof(text) );
        if (!text[0]) sprintf( text, "%u", port );
        length = (unsigned int)strlen( text );
        if (length + 1 > params->serv_len) return WSAEFAULT;
        memcpy( params->serv, text, length + 1 );
    }
    return 0;
}
