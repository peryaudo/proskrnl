/* drivers/afd.h — \Device\Afd, the socket boundary Wine's ws2_32 issues
 * (Net-2; see drivers/afd.c). */
#ifndef PROSKRNL_DRIVERS_AFD_H
#define PROSKRNL_DRIVERS_AFD_H

#include "abi/ntdef.h"

/* Publish \Device\Afd (kernel/init/main.c, after NetInitialize — the
 * device serves loopback sockets over the always-on lwIP stack, NIC or
 * not). Boot-time panic on failure, the IoPublishDevice rule. */
void AfdInitialize(void);

/* The thread-exit sweep (kernel/ps/thread.c): cancel-complete
 * (STATUS_CANCELLED) every parked socket request `thread` issued. AFD
 * only — npfs deliberately keeps its don't-sweep behavior (docs/03
 * "CUI-3 SCM notes"); the pinned contract is per-device. Safe before
 * AfdInitialize (no-op). */
struct KTHREAD;
void AfdCancelThreadIo(struct KTHREAD *thread);

/* The parked-poll expiry (drivers/net/netd.c's mainloop): AfdPollTick
 * completes every poll whose deadline passed (STATUS_TIMEOUT);
 * AfdNextPollDelayMs is the milliseconds until the nearest deadline
 * (0 = due now, 0xffffffff = none), folded into netd's park timeout so
 * an expiry never waits for unrelated traffic. Both safe before
 * AfdInitialize (no-ops). */
void AfdPollTick(void);
ULONG AfdNextPollDelayMs(void);

/* The docs/24 §6e verdict numbers for the [KTEST] net stats line
 * (drivers/net/netd.c NetPrintKtestStats): requests that genuinely
 * parked, synchronous-handle park laps, and default-arm refusals. */
void AfdQueryStats(ULONG *pendedOut, ULONG *syncParksOut, ULONG *refusedOut);

/* Is this Ob body a FILE_OBJECT open on \Device\Afd? — for the one
 * oracle-parity shim in NtQueryObject (socket handles report their
 * attributes without OBJ_INHERIT there; inheritance itself is intact). */
BOOLEAN AfdIsSocketFile(PVOID body);

#endif /* PROSKRNL_DRIVERS_AFD_H */
