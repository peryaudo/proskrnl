/*
 * user/conhost/wine/debug.h - a silent stand-in for Wine's debug channels.
 *
 * Shadows wine/include/wine/debug.h through include-path order. The ported
 * conhost's TRACE/WARN/ERR/FIXME lines become no-ops: proskrnl's debugging
 * surface is the kernel's serial DbgPrint, and conhost's own chatter would
 * interleave with the console bytes on the same wire (docs/08).
 */
#ifndef __WINE_WINE_DEBUG_H
#define __WINE_WINE_DEBUG_H

#include <windef.h>

#define WINE_DEFAULT_DEBUG_CHANNEL(ch) /* nothing */
#define WINE_DECLARE_DEBUG_CHANNEL(ch) /* nothing */

#define __WINE_DBG_NOOP(...)  do { if (0) { __wine_dbg_sink( "" __VA_ARGS__ ); } } while (0)
static inline void __wine_dbg_sink( const char *fmt, ... ) { (void)fmt; }

#define TRACE(...)    __WINE_DBG_NOOP(__VA_ARGS__)
#define WARN(...)     __WINE_DBG_NOOP(__VA_ARGS__)
#define ERR(...)      __WINE_DBG_NOOP(__VA_ARGS__)
#define FIXME(...)    __WINE_DBG_NOOP(__VA_ARGS__)
#define TRACE_ON(ch)  0
#define WARN_ON(ch)   0
#define ERR_ON(ch)    0
#define FIXME_ON(ch)  0

static inline const char *wine_dbgstr_w( const WCHAR *s )      { (void)s; return ""; }
static inline const char *wine_dbgstr_wn( const WCHAR *s, int n ) { (void)s; (void)n; return ""; }
static inline const char *wine_dbgstr_an( const char *s, int n )  { (void)s; (void)n; return ""; }
static inline const char *wine_dbgstr_rect( const RECT *r )    { (void)r; return ""; }
#define debugstr_w(s)     wine_dbgstr_w(s)
#define debugstr_wn(s, n) wine_dbgstr_wn((s), (n))
#define debugstr_an(s, n) wine_dbgstr_an((s), (n))
#define debugstr_a(s)     wine_dbgstr_an((s), -1)

#endif /* __WINE_WINE_DEBUG_H */
