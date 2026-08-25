/* drivers/condrv.h — the console driver (M9, docs/02) and its serial
 * transport (HACK-004, docs/10). */
#ifndef PROSKRNL_DRIVERS_CONDRV_H
#define PROSKRNL_DRIVERS_CONDRV_H

#include "abi/ntdef.h"

struct EPROCESS;

/* Publish the console-side devices. Needs the Ob namespace and a thread
 * with a handle table; no disk dependency. */
void CondrvInitialize(void);

/* Process-delete fallback: release a console binding the exit-path handle
 * sweep did not (a connection handle duplicated into another process
 * outlives the binder's sweep). Idempotent; called by PspDeleteProcess. */
void CondrvProcessDelete(struct EPROCESS *process);

#endif /* PROSKRNL_DRIVERS_CONDRV_H */
