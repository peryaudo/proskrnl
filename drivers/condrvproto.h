/* drivers/condrvproto.h — the kernel <-> conhost server transport (M9).
 *
 * A proskrnl-INTERNAL contract, deliberately outside abi/: real NT's
 * condrv <-> conhost protocol is undocumented and absent from Wine's
 * headers (Wine pumps conhost through wineserver requests instead), so
 * there is nothing to generate from (G4 applies to the CLIENT surface,
 * which is fully generated — abi/ntcondrv.h). The conhost side lives in
 * the pinned fork as programs/conhost/proskrnl.h (the runtime-dormant
 * seam commit, Art. 10) — the two struct sets are both proskrnl-authored
 * and MUST stay byte-identical; the run.sh console echo test exercises
 * the wire end to end.
 *
 * The shape mirrors wineserver's get_next_console_request semantics
 * (third_party/wine server/console.c), so conhost's logic ports without
 * behavioural change:
 *
 *  - conhost reads one CONDRV_SERVER_MSG (+ input payload) per NtReadFile
 *    on its \Device\ConDrv\Server handle. STATUS_PENDING = nothing queued;
 *    wait on the handle (it is signaled while requests are deliverable).
 *    Reads must offer the full CONDRV_SERVER_BUFFER_SIZE; the kernel caps
 *    forwarded payloads to fit (large client writes are chunked first).
 *  - A delivered BLOCKING-READ verb (READ_INPUT/READ_CONSOLE[_CONTROL]/
 *    READ_FILE) parks kernel-side at delivery: its client stays blocked
 *    and the next plain reply is ignored, exactly like wineserver's
 *    read_queue. It completes only through a reply with read = 1
 *    (conhost's read_complete), which finishes the OLDEST delivered read.
 *    read = 1 with no delivered read answers STATUS_INVALID_HANDLE (the
 *    signal-only read_complete conhost issues; it tolerates that status).
 *  - Any other delivered verb is "busy": the next reply with read = 0 and
 *    the matching id completes it. STATUS_PENDING in a reply becomes
 *    STATUS_INVALID_PARAMETER (wineserver's conversion).
 */
#ifndef PROSKRNL_DRIVERS_CONDRVPROTO_H
#define PROSKRNL_DRIVERS_CONDRVPROTO_H

#include <stdint.h>

#define CONDRV_SERVER_BUFFER_SIZE 65536u

typedef struct CONDRV_SERVER_MSG
{
    uint64_t id;          /* request id, echoed in the plain reply */
    uint32_t code;        /* IOCTL_CONDRV_* */
    uint32_t output;      /* screen-buffer id; 0 = the input object */
    uint32_t inSize;      /* payload bytes following this header */
    uint32_t outCapacity; /* most payload bytes the reply may carry */
} CONDRV_SERVER_MSG;

typedef struct CONDRV_SERVER_REPLY
{
    uint64_t id;      /* the busy request this answers (read == 0) */
    int32_t status;   /* NTSTATUS for the client's ioctl */
    uint32_t read;    /* 1 = complete the oldest delivered blocking read */
    uint32_t outSize; /* payload bytes following this header */
    uint32_t pad;
} CONDRV_SERVER_REPLY;

#define CONDRV_SERVER_MAX_PAYLOAD (CONDRV_SERVER_BUFFER_SIZE - sizeof(CONDRV_SERVER_MSG))

#endif /* PROSKRNL_DRIVERS_CONDRVPROTO_H */
