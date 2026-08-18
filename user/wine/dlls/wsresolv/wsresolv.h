/*
 * wsresolv — the PE resolver behind ws2_32's WS_CALL seam (Net-3,
 * docs/24 §4f).
 *
 * ws2_32's five resolver entries are its own unixlib
 * (dlls/ws2_32/ws2_32_private.h: the param structs and enum this header
 * pulls in — the CONTRACT, the same way winevsnd.drv includes mmdevapi's
 * unixlib.h). On proskrnl the fork's WS_CALL leg LdrLoadDll's this DLL
 * and dispatches through the one exported __wine_unix_call_funcs table
 * (main.c), indexed by enum ws_unix_funcs; the C_ASSERT in main.c pins
 * the count against a pin-bump growing the surface silently.
 *
 * The engine (resolv.c): numeric fast paths, localhost and the machine's
 * own names, the drivers\etc\hosts file, then a minimal DNS client
 * (dns.c) speaking over ws2_32's OWN public UDP socket surface — the
 * recursion is safe because the socket path never re-enters the resolver
 * — against the servers the Net-1 lease wrote to the registry.
 *
 * Linked above ntdll + ws2_32 only (no kernel32 — the winevsnd rule):
 * files and the registry are reached through Nt*, allocation through
 * RtlAllocateHeap on the PEB heap.
 */
#ifndef __WSRESOLV_H
#define __WSRESOLV_H

#include <stdarg.h>

#include "ws2_32_private.h"

/* ---- plumbing (main.c) --------------------------------------------------- */

void resolv_report( const char *format, ... );

void *resolv_alloc( unsigned int size );
void resolv_free( void *ptr );

/* ---- registry / file helpers (resolv.c) ---------------------------------- */

/* Read a REG_SZ under HKLM; returns length in WCHARs (0 = absent/too big). */
unsigned int resolv_read_hklm_string( const WCHAR *key_path, const WCHAR *value,
                                      WCHAR *buffer, unsigned int capacity );

/* Read a whole file by NT path into a heap buffer (NUL-terminated);
 * returns NULL when absent. Caller resolv_free()s. */
char *resolv_read_file( const WCHAR *nt_path );

/* The drivers\etc directory (DataBasePath), as an NT path prefix ending
 * in '\\'; FALSE when the registry carries none. */
BOOL resolv_etc_prefix( WCHAR *buffer, unsigned int capacity );

/* Hand each Tcpip\Parameters\Interfaces\<adapter> value named `value`
 * (REG_SZ) to `sink` — the lease values netd wrote. */
void resolv_collect_interface_values( const WCHAR *value,
                                      void (*sink)( const WCHAR *text, void *cookie ),
                                      void *cookie );

/* Strict dotted-quad parse (network-order bytes out). */
BOOL resolv_parse_ipv4( const char *text, unsigned char out[4] );

/* IPv6 literal parse ('::' compression, embedded v4 tail). */
BOOL resolv_parse_ipv6( const char *text, unsigned char out[16] );

/* ---- the resolved-address set (resolv.c) --------------------------------- */

#define RESOLV_MAX_ADDRS 16
#define RESOLV_NAME_MAX 256

struct resolv_address
{
    int family;                 /* AF_INET / AF_INET6 */
    unsigned char bytes[16];    /* 4 or 16 bytes, network order */
};

struct resolv_result
{
    unsigned int count;
    struct resolv_address addrs[RESOLV_MAX_ADDRS];
    char canonname[RESOLV_NAME_MAX];
};

void resolv_result_add( struct resolv_result *result, int family, const void *bytes );

/* ---- the DNS client (dns.c) ---------------------------------------------- */

/* The wire exchange, swappable so tests/resolv can drive the parser with
 * a canned corpus: send `query` (query_len bytes), land the reply in
 * `reply` (up to reply_cap), 0 on success with *reply_len set. */
struct dns_transport
{
    int (*exchange)( void *context, const unsigned char *query, unsigned int query_len,
                     unsigned char *reply, unsigned int reply_cap, unsigned int *reply_len );
    void *context;
};

/* Resolve `name` via DNS over `transport` (NULL = the real UDP transport
 * against the registry's server list). Appends to `result`; answers 0,
 * WSAHOST_NOT_FOUND, WSATRY_AGAIN or WSANO_RECOVERY. */
int dns_resolve( const char *name, BOOL want_v4, BOOL want_v6, const struct dns_transport *transport,
                 struct resolv_result *result );

/* The query builder / reply parser, exported for the unit corpus. */
unsigned int dns_build_query( unsigned char *buffer, unsigned int capacity, const char *name,
                              unsigned short qtype, unsigned short id );
int dns_parse_reply( const unsigned char *reply, unsigned int length, unsigned short id,
                     const char *name, unsigned short qtype, struct resolv_result *result );

#endif /* __WSRESOLV_H */
