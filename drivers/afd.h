/* drivers/afd.h — \Device\Afd, the socket boundary Wine's ws2_32 issues
 * (Net-2; see drivers/afd.c). */
#ifndef PROSKRNL_DRIVERS_AFD_H
#define PROSKRNL_DRIVERS_AFD_H

/* Publish \Device\Afd (kernel/init/main.c, after NetInitialize — the
 * device serves loopback sockets over the always-on lwIP stack, NIC or
 * not). Boot-time panic on failure, the IoPublishDevice rule. */
void AfdInitialize(void);

#endif /* PROSKRNL_DRIVERS_AFD_H */
