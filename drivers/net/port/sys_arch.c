/* drivers/net/port/sys_arch.c — lwIP's two environment entry points
 * (Net-1, docs/24 §4b). Part of the port layer (docs/11).
 */
#include "lwip/opt.h"
#include "lwip/sys.h"
#include "kernel/ke/ke.h"

/* Milliseconds since boot: KeTickCount is the 1 kHz tick the timekeeping
 * work calibrated (docs/22; sys_now rides the same tick). lwIP handles
 * the u32 wrap itself. */
u32_t sys_now(void)
{
    return (u32_t)KeTickCount;
}

/* TSC low word: cheap non-cryptographic entropy for DHCP xids and kin
 * (arch/cc.h LWIP_RAND). */
unsigned int net_port_rand(void)
{
    uint32_t low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return low ^ high;
}

/* The three str* calls lwIP's core files make (def.c lwip_strnstr, dns.c's
 * "localhost" check, netif.c name handling) and netif.c's atoi, defined
 * here because the kernel's own string surface is the Ki* inline family
 * (kernel/lib/string.h) and grows no libc names without a consumer. The
 * mem* four come from kernel/lib/string.c. */
size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0')
    {
        n++;
    }
    return n;
}

int strcmp(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b)
    {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        if (a[i] != b[i] || a[i] == '\0')
        {
            return (unsigned char)a[i] - (unsigned char)b[i];
        }
    }
    return 0;
}

int atoi(const char *s)
{
    int value = 0;
    int negative = (*s == '-');
    if (*s == '-' || *s == '+')
    {
        s++;
    }
    while (*s >= '0' && *s <= '9')
    {
        value = value * 10 + (*s - '0');
        s++;
    }
    return negative ? -value : value;
}
