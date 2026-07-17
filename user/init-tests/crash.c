/* user/init-tests/crash.c — the M4 crash-containment client (docs/02):
 * "a user crash is contained as process termination, not a kernel fault."
 *
 * Deliberately dereferences an unmapped user address. The kernel's trap path
 * must contain this as process termination with STATUS_ACCESS_VIOLATION (its
 * boot-module string is expect=av) — and, crucially, the kernel must keep
 * running so the next module still executes. main() never returns.
 */
#include "abi/ntdef.h"
#include "abi/ntpsapi.h"

int main(void)
{
    /* An address inside the canonical user half but never mapped. */
    volatile unsigned char *bad = (volatile unsigned char *)0x123000;
    unsigned char sink = *bad;
    (void)sink;
    return 0; /* unreachable: the read above faults */
}
