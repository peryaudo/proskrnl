/* drivers/condrvproto.h — the kernel <-> conhost server transport (M9).
 *
 * A proskrnl-INTERNAL contract, deliberately outside abi/: real NT's
 * condrv <-> conhost protocol is undocumented and absent from Wine's
 * headers (Wine pumps conhost through wineserver requests instead), so
 * there is nothing to generate from (G4 applies to the CLIENT surface,
 * which is fully generated — abi/ntcondrv.h). Both sides of this header
 * are in this tree: drivers/condrv.c and user/conhost/.
 *
 * Shape: conhost reads one CONDRV_SERVER_MSG (+ its input payload) per
 * NtReadFile on its \Device\ConDrv\Server handle — STATUS_PENDING means
 * "no request queued; wait on the handle" (the server file object is
 * signaled while requests are pending). It answers with one
 * CONDRV_SERVER_REPLY (+ output payload) per NtWriteFile, matched by id.
 * Reads must offer exactly CONDRV_SERVER_BUFFER_SIZE bytes; the kernel
 * caps every forwarded payload to fit (large client writes are chunked
 * by the kernel before forwarding).
 */
#ifndef PROSKRNL_DRIVERS_CONDRVPROTO_H
#define PROSKRNL_DRIVERS_CONDRVPROTO_H

#include <stdint.h>

#define CONDRV_SERVER_BUFFER_SIZE 65536u

typedef struct CONDRV_SERVER_MSG
{
    uint64_t id;          /* request id, echoed in the reply */
    uint32_t code;        /* IOCTL_CONDRV_* */
    uint32_t output;      /* screen-buffer id; 0 = the input object */
    uint32_t inSize;      /* payload bytes following this header */
    uint32_t outCapacity; /* most payload bytes the reply may carry */
} CONDRV_SERVER_MSG;

typedef struct CONDRV_SERVER_REPLY
{
    uint64_t id;      /* the request this answers */
    int32_t status;   /* NTSTATUS for the client's ioctl */
    uint32_t outSize; /* payload bytes following this header */
} CONDRV_SERVER_REPLY;

#define CONDRV_SERVER_MAX_PAYLOAD (CONDRV_SERVER_BUFFER_SIZE - sizeof(CONDRV_SERVER_MSG))

#endif /* PROSKRNL_DRIVERS_CONDRVPROTO_H */
