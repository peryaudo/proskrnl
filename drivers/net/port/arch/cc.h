/* drivers/net/port/arch/cc.h — lwIP's compiler/platform glue over kernel
 * primitives (Net-1, docs/24 §4b). Part of the port layer: lwIP's own
 * documented user-supplied surface, not a patch (docs/11).
 */
#ifndef PROSKRNL_DRIVERS_NET_PORT_ARCH_CC_H
#define PROSKRNL_DRIVERS_NET_PORT_ARCH_CC_H

#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"

/* Diagnostics land on serial; a failed LWIP_ASSERT is fatal through the
 * one panic path (Art. 9/12: the panic dump is the debugger, and loud
 * beats wrong). */
#define LWIP_PLATFORM_DIAG(x)                                                                      \
    do                                                                                             \
    {                                                                                              \
        DbgPrint x;                                                                                \
    } while (0)
#define LWIP_PLATFORM_ASSERT(x) KiPanic("lwip assert: " x)

/* Freestanding kernel: clang's builtin stdint/stddef/limits serve lwIP's
 * type needs; ctype and inttypes are hosted and stay out (lwIP supplies
 * its own fallbacks under these knobs, and the format macros below feed
 * its diag strings). */
#define LWIP_NO_CTYPE_H    1
#define LWIP_NO_INTTYPES_H 1
#define X8_F               "02x"
#define U16_F              "u"
#define S16_F              "d"
#define X16_F              "x"
#define U32_F              "u"
#define S32_F              "d"
#define X32_F              "x"
#define SZT_F              "lu"

/* Randomness for protocol identifiers (DHCP xid, IPv6 DAD delays):
 * drivers/net/port/sys_arch.c over the TSC. Quality is not a goal —
 * nothing cryptographic rides this. */
/* lwIP-style name, deliberately: the port layer follows lwIP's own naming
 * (docs/24 §4b, exempt from docs/15 the way tests are). */
unsigned int net_port_rand(void); /* NOLINT(readability-identifier-naming) */
#define LWIP_RAND() ((unsigned int)net_port_rand())

#endif /* PROSKRNL_DRIVERS_NET_PORT_ARCH_CC_H */
