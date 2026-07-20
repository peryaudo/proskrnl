/* drivers/condrv.h — the console driver (M9, docs/02) and its serial
 * transport (HACK-004, docs/10). */
#ifndef PROSKRNL_DRIVERS_CONDRV_H
#define PROSKRNL_DRIVERS_CONDRV_H

#include "abi/ntdef.h"

/* Publish the console-side devices. Needs the Ob namespace and a thread
 * with a handle table; no disk dependency. */
void CondrvInitialize(void);

/* Block until conhost has opened \Device\ConDrv\Server, up to
 * `timeoutMilliseconds`. TRUE = a console server is live. The boot runner
 * gates console-using test processes on this so a slow conhost start can
 * never turn into a nondeterministic FAIL (docs/08). */
BOOLEAN CondrvWaitForServer(ULONG timeoutMilliseconds);

/* Seed one process's console plumbing (M9): a Reference open for
 * RTL_USER_PROCESS_PARAMETERS.ConsoleHandle, an Input open for hStdInput,
 * and ONE Output open behind both hStdOutput and hStdError — the same
 * shape kernelbase's init_console_std_handles builds for itself. Handles
 * are created in `process`'s own table. */
struct EPROCESS;
NTSTATUS CondrvCreateProcessHandles(struct EPROCESS *process, HANDLE *consoleOut, HANDLE *inOut,
                                    HANDLE *outOut, HANDLE *errOut);

#endif /* PROSKRNL_DRIVERS_CONDRV_H */
