/* drivers/condrv.c — the console driver (M9) + its serial transport.
 *
 * Two devices live here:
 *
 * \Device\ConDrv — the real-NT/Wine console architecture (adopted, not
 * invented — docs/10 "Non-hacks"): clients open Connection/Reference/
 * Input/Output/ScreenBuffer by name (exactly the set the pinned
 * kernelbase's console.c opens) and issue IOCTL_CONDRV_* through
 * NtDeviceIoControlFile; plain Read/Write on console handles forward as
 * IOCTL_CONDRV_READ_FILE/WRITE_FILE. The kernel is a message queue, not a
 * console: every client verb is packaged as a CONDRV_SERVER_MSG and pumped
 * to conhost through its \Device\ConDrv\Server handle (Read = next
 * request, Write = id-matched reply — drivers/condrvproto.h), which is the
 * proskrnl seam standing in for Wine's get_next_console_request wineserver
 * call. One global console; the server file object is signaled while
 * requests are queued so conhost's WaitForMultipleObjects works unchanged.
 * A dead or absent conhost fails requests fast — boot never hangs on it.
 *
 * \Device\Serial0 — the COM1 UART published as a plain stream device, both
 * directions. That transport is HACK-004 (docs/10) — a COM port is never
 * real NT's interactive-console backend; it is subtracted when the M11+
 * input/display path exists. The RX side polls: the blocking Read drains
 * the FIFO or naps 1 ms and retries (no IRQ4 routing exists, and the clock
 * already ticks at 1 kHz — Art. 3 simplest-correct; 16-byte FIFO at 1 kHz
 * sustains ~16 KB/s, far past interactive typing).
 *
 * The TX side is raw — no '\n' -> '\r\n' mangling here: conhost owns the
 * console's line discipline. DbgPrint keeps its own KiSerialPutString path
 * untouched; the two interleave on the wire, which the headless test loop
 * tolerates by grepping unique markers (docs/08).
 */
#include "drivers/condrv.h"
#include "drivers/condrvproto.h"
#include "kernel/io/io.h"
#include "kernel/ke/ke.h"
#include "kernel/ps/ps.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/lib/list.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/serial.h"

#include "abi/ntcondrv.h"

/* --- \Device\Serial0 --------------------------------------------------------- */

/* One global open context: the device is stateless per-open (conhost is the
 * only intended opener) but the Io close hooks key off a non-NULL fsContext
 * and a valid IO_FCB (kernel/io/file.c). */
static IO_FCB CondrvSerialFcb;

static NTSTATUS CondrvSerialCreate(PIO_DEVICE device, PFILE_OBJECT file, const UNICODE_STRING *path,
                                   PFILE_OBJECT relativeTo, ACCESS_MASK grantedAccess,
                                   ULONG shareAccess, ULONG fileAttributes, ULONG disposition,
                                   ULONG options, ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition;
    (void)options;
    if (path->Length != 0)
    {
        return STATUS_OBJECT_NAME_NOT_FOUND; /* the device has no namespace */
    }
    file->fsContext = &CondrvSerialFcb;
    file->fcb = &CondrvSerialFcb;
    file->isDirectory = FALSE;
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void CondrvSerialCleanup(PFILE_OBJECT file)
{
    (void)file;
}

static void CondrvSerialClose(PFILE_OBJECT file)
{
    (void)file;
}

static NTSTATUS CondrvSerialGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS CondrvSerialQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
                                      ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Serial0");
    ULONG full = sizeof(name) - sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

/* Blocking tty-style read: returns as soon as at least one byte exists,
 * with whatever else the FIFO already holds (conhost's input thread feeds
 * single keystrokes through exactly this shape). */
static NTSTATUS CondrvSerialRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    (void)file;
    if (length == 0)
    {
        *infoOut = 0;
        return STATUS_SUCCESS;
    }
    unsigned char *out = buffer;
    for (;;)
    {
        ULONG got = 0;
        int ch;
        while (got < length && (ch = KiSerialTryGetChar()) >= 0)
        {
            out[got++] = (unsigned char)ch;
        }
        if (got != 0)
        {
            *infoOut = got;
            return STATUS_SUCCESS;
        }
        /* Nap one clock tick between polls (relative 100 ns units). */
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

static NTSTATUS CondrvSerialWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                                  ULONG_PTR *infoOut)
{
    (void)file;
    const unsigned char *in = buffer;
    for (ULONG i = 0; i < length; i++)
    {
        KiSerialPutChar((char)in[i]);
    }
    *infoOut = length;
    return STATUS_SUCCESS;
}

static const IO_VFS_OPS CondrvSerialOps = {
    .Create = CondrvSerialCreate,
    .Cleanup = CondrvSerialCleanup,
    .Close = CondrvSerialClose,
    .GetInfo = CondrvSerialGetInfo,
    .QueryName = CondrvSerialQueryName,
    .Read = CondrvSerialRead,
    .Write = CondrvSerialWrite,
};

/* --- \Device\ConDrv: the console object -------------------------------------- */

typedef enum
{
    CondrvOpenServer,
    CondrvOpenConnection, /* also Reference: both name the console itself */
    CondrvOpenInput,
    CondrvOpenOutput,
} CONDRV_OPEN_KIND;

typedef struct CONDRV_OPEN
{
    CONDRV_OPEN_KIND kind;
    ULONG outputId; /* screen-buffer id (kind == Output); 1 = conhost's
                     * pre-created default buffer */
} CONDRV_OPEN, *PCONDRV_OPEN;

/* One in-flight client verb. Lives on the REQUESTER's kernel stack — the
 * requester blocks on `done` for the whole round trip. */
typedef struct CONDRV_REQUEST
{
    LIST_ENTRY listEntry;
    uint64_t id;
    ULONG code;
    ULONG output;
    const void *input;
    ULONG inputLength;
    void *outputBuffer;
    ULONG outputCapacity;
    NTSTATUS status;       /* reply */
    ULONG_PTR information; /* reply payload bytes */
    KEVENT done;
} CONDRV_REQUEST, *PCONDRV_REQUEST;

/* The verbs conhost completes out-of-band through read_complete — the
 * wineserver read_queue class (third_party/wine server/console.c
 * is_blocking_read_ioctl). */
static BOOLEAN CondrvIsBlockingReadCode(ULONG code)
{
    return code == IOCTL_CONDRV_READ_INPUT || code == IOCTL_CONDRV_READ_CONSOLE ||
           code == IOCTL_CONDRV_READ_CONSOLE_CONTROL || code == IOCTL_CONDRV_READ_FILE;
}

static struct
{
    PFILE_OBJECT serverFile; /* conhost's Server open; 0 = no console */
    LIST_ENTRY requestQueue; /* queued, not yet fetched by conhost */
    LIST_ENTRY readQueue;    /* head = the delivered blocking read awaiting
                              * read_complete; tail = reads deferred behind
                              * it (wineserver's read_queue shape) */
    PCONDRV_REQUEST current; /* delivered non-read verb, awaiting its reply */
    uint64_t nextRequestId;
    ULONG nextOutputId;   /* fresh screen-buffer ids (2+) */
    KEVENT serverPresent; /* notification: a conhost attached */
} CondrvConsole;

static IO_FCB CondrvConsoleFcb;

/* The server file object doubles as conhost's wait handle: signaled while
 * requests are queued (its DISPATCHER_HEADER is event-shaped — io.h). */
static void CondrvSignalServer(BOOLEAN pending)
{
    if (CondrvConsole.serverFile == 0)
    {
        return;
    }
    PKEVENT event = (PKEVENT)&CondrvConsole.serverFile->header;
    if (pending)
    {
        KeSetEvent(event, 0, FALSE);
    }
    else
    {
        KeClearEvent(event);
    }
}

/* Package one client verb, queue it, wake conhost, park until the reply. */
static NTSTATUS CondrvForward(ULONG code, ULONG output, const void *input, ULONG inputLength,
                              void *outputBuffer, ULONG outputCapacity, ULONG_PTR *infoOut)
{
    if (CondrvConsole.serverFile == 0)
    {
        return STATUS_INVALID_DEVICE_STATE; /* no conhost: fail fast, never hang */
    }
    if (inputLength > CONDRV_SERVER_MAX_PAYLOAD)
    {
        return STATUS_INVALID_BUFFER_SIZE; /* protocol cap (condrvproto.h) */
    }
    if (outputCapacity > CONDRV_SERVER_MAX_PAYLOAD)
    {
        outputCapacity = CONDRV_SERVER_MAX_PAYLOAD; /* clamp: shorter reads */
    }

    CONDRV_REQUEST request;
    request.id = ++CondrvConsole.nextRequestId;
    request.code = code;
    request.output = output;
    request.input = input;
    request.inputLength = inputLength;
    request.outputBuffer = outputBuffer;
    request.outputCapacity = outputCapacity;
    request.status = STATUS_INVALID_DEVICE_STATE;
    request.information = 0;
    KeInitializeEvent(&request.done, NotificationEvent, FALSE);

    InsertTailList(&CondrvConsole.requestQueue, &request.listEntry);
    CondrvSignalServer(TRUE);
    NTSTATUS waitStatus = KeWaitForSingleObject(&request.done, Executive, KernelMode, FALSE, 0);
    ASSERT(waitStatus == STATUS_SUCCESS);

    *infoOut = request.information;
    return request.status;
}

/* Complete one request back to its parked client. */
static void CondrvCompleteRequest(PCONDRV_REQUEST request, NTSTATUS status, const void *data,
                                  ULONG dataLength)
{
    ULONG copy = dataLength;
    if (copy > request->outputCapacity)
    {
        copy = request->outputCapacity;
    }
    if (copy != 0)
    {
        memcpy(request->outputBuffer, data, copy);
    }
    /* WRITE_FILE reports the bytes CONSUMED, not the reply payload
     * (wineserver get_next_console_request's result choice). */
    request->information = request->code == IOCTL_CONDRV_WRITE_FILE ? request->inputLength : copy;
    request->status = status;
    KeSetEvent(&request->done, 0, FALSE);
}

/* conhost's request fetch: one CONDRV_SERVER_MSG (+ payload) per read;
 * STATUS_PENDING = nothing deliverable (wait on the handle). Mirrors
 * wineserver: a fetched blocking read parks on readQueue (completed only
 * by read_complete); later reads defer behind it; other verbs are "busy"
 * until the plain reply. */
static NTSTATUS CondrvServerRead(void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    if (CondrvConsole.current != 0)
    {
        return STATUS_INVALID_DEVICE_STATE; /* reply before fetching again */
    }

    /* wineserver's move-aside: while a read is outstanding, queued reads
     * shift to the read queue (order kept) so non-reads can flow. */
    if (!IsListEmpty(&CondrvConsole.readQueue) && !IsListEmpty(&CondrvConsole.requestQueue))
    {
        PCONDRV_REQUEST head =
            CONTAINING_RECORD(CondrvConsole.requestQueue.Flink, CONDRV_REQUEST, listEntry);
        if (CondrvIsBlockingReadCode(head->code))
        {
            PLIST_ENTRY entry = CondrvConsole.requestQueue.Flink;
            while (entry != &CondrvConsole.requestQueue)
            {
                PLIST_ENTRY next = entry->Flink;
                PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
                if (CondrvIsBlockingReadCode(request->code))
                {
                    RemoveEntryList(entry);
                    InsertTailList(&CondrvConsole.readQueue, entry);
                }
                entry = next;
            }
        }
    }

    if (IsListEmpty(&CondrvConsole.requestQueue))
    {
        CondrvSignalServer(FALSE);
        return STATUS_PENDING;
    }
    PLIST_ENTRY entry = RemoveHeadList(&CondrvConsole.requestQueue);
    PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
    if (IsListEmpty(&CondrvConsole.requestQueue))
    {
        CondrvSignalServer(FALSE);
    }

    ULONG total = (ULONG)sizeof(CONDRV_SERVER_MSG) + request->inputLength;
    if (length < total)
    {
        /* The glue always offers the full protocol buffer; re-queue and
         * refuse rather than truncating. */
        InsertHeadList(&CondrvConsole.requestQueue, entry);
        CondrvSignalServer(TRUE);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (CondrvIsBlockingReadCode(request->code))
    {
        ASSERT(IsListEmpty(&CondrvConsole.readQueue));
        InsertTailList(&CondrvConsole.readQueue, entry);
    }
    else
    {
        CondrvConsole.current = request;
    }

    CONDRV_SERVER_MSG *message = buffer;
    message->id = request->id;
    message->code = request->code;
    message->output = request->output;
    message->inSize = request->inputLength;
    message->outCapacity = request->outputCapacity;
    if (request->inputLength != 0)
    {
        memcpy(message + 1, request->input, request->inputLength);
    }
    *infoOut = total;
    return STATUS_SUCCESS;
}

/* conhost's reply. read == 1 completes the oldest delivered blocking read
 * (read_complete); read == 0 completes the busy verb — and is silently
 * ignored when there is none, exactly like wineserver ignores the loop
 * reply that follows a read delivery. */
static NTSTATUS CondrvServerWrite(const void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    if (length < sizeof(CONDRV_SERVER_REPLY))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    const CONDRV_SERVER_REPLY *reply = buffer;
    if (length < sizeof(*reply) + reply->outSize)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = reply->status;
    if (status == STATUS_PENDING)
    {
        status = STATUS_INVALID_PARAMETER; /* wineserver's conversion */
    }

    if (reply->read != 0)
    {
        if (IsListEmpty(&CondrvConsole.readQueue))
        {
            /* conhost's signal-only read_complete; it tolerates exactly
             * this status (wineserver answers the same). */
            return STATUS_INVALID_HANDLE;
        }
        PLIST_ENTRY entry = RemoveHeadList(&CondrvConsole.readQueue);
        PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
        CondrvCompleteRequest(request, status, reply + 1, reply->outSize);
        /* Deferred reads become deliverable again (wineserver moves the
         * read queue back after a completion). */
        while (!IsListEmpty(&CondrvConsole.readQueue))
        {
            InsertTailList(&CondrvConsole.requestQueue, RemoveHeadList(&CondrvConsole.readQueue));
        }
        if (!IsListEmpty(&CondrvConsole.requestQueue))
        {
            CondrvSignalServer(TRUE);
        }
        *infoOut = length;
        return STATUS_SUCCESS;
    }

    PCONDRV_REQUEST request = CondrvConsole.current;
    if (request != 0)
    {
        if (request->id != reply->id)
        {
            return STATUS_INVALID_PARAMETER;
        }
        CondrvConsole.current = 0;
        CondrvCompleteRequest(request, status, reply + 1, reply->outSize);
    }
    *infoOut = length;
    return STATUS_SUCCESS;
}

/* Server teardown: every queued, busy, and parked-read request fails — a
 * dead conhost degrades the console, it never deadlocks a client. */
static void CondrvServerGone(void)
{
    CondrvConsole.serverFile = 0;
    KeClearEvent(&CondrvConsole.serverPresent);
    if (CondrvConsole.current != 0)
    {
        CondrvCompleteRequest(CondrvConsole.current, STATUS_INVALID_DEVICE_STATE, 0, 0);
        CondrvConsole.current = 0;
    }
    while (!IsListEmpty(&CondrvConsole.readQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&CondrvConsole.readQueue);
        CondrvCompleteRequest(CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry),
                              STATUS_INVALID_DEVICE_STATE, 0, 0);
    }
    while (!IsListEmpty(&CondrvConsole.requestQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&CondrvConsole.requestQueue);
        CondrvCompleteRequest(CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry),
                              STATUS_INVALID_DEVICE_STATE, 0, 0);
    }
}

/* --- ConDrv vfs ops ---------------------------------------------------------- */

static NTSTATUS CondrvConsoleCreate(PIO_DEVICE device, PFILE_OBJECT file,
                                    const UNICODE_STRING *path, PFILE_OBJECT relativeTo,
                                    ACCESS_MASK grantedAccess, ULONG shareAccess,
                                    ULONG fileAttributes, ULONG disposition, ULONG options,
                                    ULONG_PTR *information)
{
    (void)device;
    (void)relativeTo; /* a relative open (root = any console handle) names
                       * the same single console */
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition; /* kernelbase opens Input/Output with FILE_CREATE */
    (void)options;

    UNICODE_STRING name;
    CONDRV_OPEN_KIND kind;
    BOOLEAN isScreenBuffer = FALSE;
    RtlInitUnicodeString(&name, WSTR("Server"));
    if (RtlEqualUnicodeString(path, &name, TRUE))
    {
        kind = CondrvOpenServer;
    }
    else if ((RtlInitUnicodeString(&name, WSTR("Connection")),
              RtlEqualUnicodeString(path, &name, TRUE)) ||
             (RtlInitUnicodeString(&name, WSTR("Reference")),
              RtlEqualUnicodeString(path, &name, TRUE)))
    {
        kind = CondrvOpenConnection;
    }
    else if ((RtlInitUnicodeString(&name, WSTR("Input")), RtlEqualUnicodeString(path, &name, TRUE)))
    {
        kind = CondrvOpenInput;
    }
    else if ((RtlInitUnicodeString(&name, WSTR("Output")),
              RtlEqualUnicodeString(path, &name, TRUE)))
    {
        kind = CondrvOpenOutput;
    }
    else if ((RtlInitUnicodeString(&name, WSTR("ScreenBuffer")),
              RtlEqualUnicodeString(path, &name, TRUE)))
    {
        kind = CondrvOpenOutput;
        isScreenBuffer = TRUE;
    }
    else
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    if (kind == CondrvOpenServer && CondrvConsole.serverFile != 0)
    {
        return STATUS_ACCESS_DENIED; /* one console server */
    }

    PCONDRV_OPEN open = MiAllocatePool(sizeof(CONDRV_OPEN));
    if (open == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    open->kind = kind;
    open->outputId = kind == CondrvOpenOutput ? 1 : 0;

    if (isScreenBuffer)
    {
        /* A fresh screen buffer: allocate an id and have conhost create it
         * (its INIT_OUTPUT path) before the open returns. */
        open->outputId = ++CondrvConsole.nextOutputId;
        ULONG_PTR ignored = 0;
        NTSTATUS status =
            CondrvForward(IOCTL_CONDRV_INIT_OUTPUT, open->outputId, 0, 0, 0, 0, &ignored);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(open);
            return status;
        }
    }

    file->fsContext = open;
    file->fcb = &CondrvConsoleFcb;
    file->isDirectory = FALSE;
    if (kind == CondrvOpenServer)
    {
        CondrvConsole.serverFile = file;
        /* Born signaled (io.h); the server handle signals "requests
         * pending", so start clear. */
        KeClearEvent((PKEVENT)&file->header);
        KeSetEvent(&CondrvConsole.serverPresent, 0, FALSE);
        DbgPrint("condrv: console server attached\n");
    }
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void CondrvConsoleCleanup(PFILE_OBJECT file)
{
    PCONDRV_OPEN open = file->fsContext;
    if (open->kind == CondrvOpenServer && CondrvConsole.serverFile == file)
    {
        CondrvServerGone();
    }
    else if (open->kind == CondrvOpenOutput && open->outputId > 1 && CondrvConsole.serverFile != 0)
    {
        ULONG_PTR ignored = 0;
        CondrvForward(IOCTL_CONDRV_CLOSE_OUTPUT, open->outputId, 0, 0, 0, 0, &ignored);
    }
}

static void CondrvConsoleClose(PFILE_OBJECT file)
{
    MiFreePool(file->fsContext);
}

static NTSTATUS CondrvConsoleGetInfo(PFILE_OBJECT file, IO_FILE_INFO *info)
{
    (void)file;
    memset(info, 0, sizeof(*info));
    return STATUS_SUCCESS;
}

static NTSTATUS CondrvConsoleQueryName(PFILE_OBJECT file, WCHAR *buffer, ULONG capacity,
                                       ULONG *lengthOut)
{
    (void)file;
    static const WCHAR name[] = WSTR("\\Reference");
    ULONG full = sizeof(name) - sizeof(WCHAR);
    *lengthOut = full;
    ULONG copy = full <= capacity ? full : capacity;
    memcpy(buffer, name, copy);
    return full <= capacity ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
}

static NTSTATUS CondrvConsoleRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut)
{
    PCONDRV_OPEN open = file->fsContext;
    switch (open->kind)
    {
    case CondrvOpenServer:
        return CondrvServerRead(buffer, length, infoOut);
    case CondrvOpenInput:
        /* ReadFile on a console handle: kernelbase's fallback path — the
         * same cooked read the console server implements as READ_FILE. */
        return CondrvForward(IOCTL_CONDRV_READ_FILE, 0, 0, 0, buffer, length, infoOut);
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS CondrvConsoleWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                                   ULONG_PTR *infoOut)
{
    PCONDRV_OPEN open = file->fsContext;
    switch (open->kind)
    {
    case CondrvOpenServer:
        return CondrvServerWrite(buffer, length, infoOut);
    case CondrvOpenOutput:
    {
        /* WriteFile on a console handle -> WRITE_FILE, chunked under the
         * protocol payload cap so any write size succeeds. */
        ULONG written = 0;
        while (written < length || length == 0)
        {
            ULONG chunk = length - written;
            if (chunk > CONDRV_SERVER_MAX_PAYLOAD)
            {
                chunk = (ULONG)CONDRV_SERVER_MAX_PAYLOAD;
            }
            ULONG_PTR ignored = 0;
            NTSTATUS status =
                CondrvForward(IOCTL_CONDRV_WRITE_FILE, open->outputId,
                              (const unsigned char *)buffer + written, chunk, 0, 0, &ignored);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            written += chunk;
            if (length == 0)
            {
                break;
            }
        }
        *infoOut = written;
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS CondrvConsoleDeviceControl(PFILE_OBJECT file, ULONG code, const void *input,
                                           ULONG inputLength, void *output, ULONG outputLength,
                                           ULONG_PTR *infoOut)
{
    PCONDRV_OPEN open = file->fsContext;
    if (open->kind == CondrvOpenServer)
    {
        /* conhost's own verbs on its server handle: input-thread setup and
         * ctrl-event fanout. No client to deliver to yet — accept. */
        if (code == IOCTL_CONDRV_SETUP_INPUT || code == IOCTL_CONDRV_CTRL_EVENT)
        {
            *infoOut = 0;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (code == IOCTL_CONDRV_BIND_PID)
    {
        /* Wine's wineserver-side bookkeeping; one global console here. */
        *infoOut = 0;
        return STATUS_SUCCESS;
    }
    return CondrvForward(code, open->kind == CondrvOpenOutput ? open->outputId : 0, input,
                         inputLength, output, outputLength, infoOut);
}

static const IO_VFS_OPS CondrvConsoleOps = {
    .Create = CondrvConsoleCreate,
    .Cleanup = CondrvConsoleCleanup,
    .Close = CondrvConsoleClose,
    .GetInfo = CondrvConsoleGetInfo,
    .QueryName = CondrvConsoleQueryName,
    .Read = CondrvConsoleRead,
    .Write = CondrvConsoleWrite,
    .DeviceControl = CondrvConsoleDeviceControl,
};

static PIO_DEVICE CondrvConsoleDevice;

/* --- process console plumbing (kernel/ps seam) ------------------------------- */

BOOLEAN CondrvWaitForServer(ULONG timeoutMilliseconds)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)timeoutMilliseconds * 10000;
    return KeWaitForSingleObject(&CondrvConsole.serverPresent, Executive, KernelMode, FALSE,
                                 &timeout) == STATUS_SUCCESS;
}

/* Build one ConDrv FILE_OBJECT of `kind` outside the NtCreateFile path (no
 * name walk — the creator seeds a child that cannot open anything yet). */
static NTSTATUS CondrvBuildOpen(CONDRV_OPEN_KIND kind, ULONG outputId, PFILE_OBJECT *fileOut)
{
    PCONDRV_OPEN open = MiAllocatePool(sizeof(CONDRV_OPEN));
    if (open == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    open->kind = kind;
    open->outputId = outputId;

    PVOID body;
    NTSTATUS status = ObpAllocateObject(&IoFileObjectType, sizeof(FILE_OBJECT), &body);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(open);
        return status;
    }
    PFILE_OBJECT file = body;
    KiInitializeDispatcherHeader(&file->header, KI_OBJECT_NOTIFICATION_EVENT, 1);
    ObfReferenceObject(CondrvConsoleDevice);
    file->device = CondrvConsoleDevice;
    file->fsContext = open;
    file->fcb = &CondrvConsoleFcb;
    file->synchronousIo = TRUE;
    file->grantedAccess = FILE_ALL_ACCESS;
    file->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    *fileOut = file;
    return STATUS_SUCCESS;
}

NTSTATUS CondrvCreateProcessHandles(struct EPROCESS *process, HANDLE *consoleOut, HANDLE *inOut,
                                    HANDLE *outOut, HANDLE *errOut)
{
    if (CondrvConsoleDevice == 0)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    PFILE_OBJECT reference = 0;
    PFILE_OBJECT input = 0;
    PFILE_OBJECT output = 0;
    NTSTATUS status = CondrvBuildOpen(CondrvOpenConnection, 0, &reference);
    if (NT_SUCCESS(status))
    {
        status = CondrvBuildOpen(CondrvOpenInput, 0, &input);
    }
    if (NT_SUCCESS(status))
    {
        status = CondrvBuildOpen(CondrvOpenOutput, 1, &output);
    }
    POBP_HANDLE_TABLE table = &process->handleTable;
    if (NT_SUCCESS(status))
    {
        status = ObpCreateHandleInTable(table, reference, FILE_ALL_ACCESS, 0, consoleOut);
    }
    if (NT_SUCCESS(status))
    {
        /* Std handles are born inheritable, as NT console handles are —
         * cmd's pipe children receive them through the M10 inherit-all
         * copy at the same values (sem_ps/inherit semantics). */
        status = ObpCreateHandleInTable(table, input, FILE_ALL_ACCESS, OBJ_INHERIT, inOut);
    }
    if (NT_SUCCESS(status))
    {
        /* hStdOutput and hStdError share ONE output open — the shape
         * kernelbase's own std-handle setup produces (DuplicateHandle). */
        status = ObpCreateHandleInTable(table, output, FILE_ALL_ACCESS, OBJ_INHERIT, outOut);
    }
    if (NT_SUCCESS(status))
    {
        status = ObpCreateHandleInTable(table, output, FILE_ALL_ACCESS, OBJ_INHERIT, errOut);
    }
    /* The handles hold their own references (or nothing does: on failure
     * the creator references drop everything, and ObpCloseAllHandles at
     * process exit releases the seeded ones). */
    if (reference != 0)
    {
        ObDereferenceObject(reference);
    }
    if (input != 0)
    {
        ObDereferenceObject(input);
    }
    if (output != 0)
    {
        ObDereferenceObject(output);
    }
    return status;
}

/* --- initialization ---------------------------------------------------------- */

static PIO_DEVICE CondrvPublishDevice(const WCHAR *name, const IO_VFS_OPS *ops, ULONG deviceType)
{
    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES attributes;
    RtlInitUnicodeString(&deviceName, name);
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &deviceName;
    attributes.Attributes = OBJ_PERMANENT;

    PVOID body;
    HANDLE handle;
    NTSTATUS status = ObpCreateObjectWithHandle(&IoDeviceType, sizeof(IO_DEVICE), &attributes,
                                                FILE_ALL_ACCESS, &body, &handle);
    if (status != STATUS_SUCCESS)
    {
        KiPanic("CondrvInitialize: cannot create a console device");
    }
    PIO_DEVICE device = body;
    device->ops = ops;
    device->context = 0;
    device->deviceType = deviceType;
    NtClose(handle);
    return device;
}

void CondrvInitialize(void)
{
    IopInitializeFcb(&CondrvSerialFcb);
    IopInitializeFcb(&CondrvConsoleFcb);
    InitializeListHead(&CondrvConsole.requestQueue);
    InitializeListHead(&CondrvConsole.readQueue);
    CondrvConsole.nextOutputId = 1; /* id 1 = conhost's pre-created buffer */
    KeInitializeEvent(&CondrvConsole.serverPresent, NotificationEvent, FALSE);
    /* GetFileType maps FILE_DEVICE_SERIAL_PORT and FILE_DEVICE_CONSOLE to
     * FILE_TYPE_CHAR (Wine dlls/kernelbase/file.c); the console value is
     * what wineserver's console objects report (server/console.c
     * console_get_volume_info). */
    CondrvPublishDevice(WSTR("\\Device\\Serial0"), &CondrvSerialOps, FILE_DEVICE_SERIAL_PORT);
    CondrvConsoleDevice =
        CondrvPublishDevice(WSTR("\\Device\\ConDrv"), &CondrvConsoleOps, FILE_DEVICE_CONSOLE);
}
