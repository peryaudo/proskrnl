/* drivers/nsi.h — \Device\Nsi, the network-store surface nsi.dll and
 * iphlpapi read (Net-3; see drivers/nsi.c). */
#ifndef PROSKRNL_DRIVERS_NSI_H
#define PROSKRNL_DRIVERS_NSI_H

/* Publish \Device\Nsi and its \??\Nsi link (kernel/init/main.c, after
 * NetInitialize — the tables are views of lwIP netif state). Boot-time
 * panic on failure, the IoPublishDevice rule. */
void NsiInitialize(void);

#endif /* PROSKRNL_DRIVERS_NSI_H */
