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

/* ASCII ETX — what a terminal sends for Ctrl+C (the byte a Unix tty's VINTR
 * defaults to). CUI-4 treats it as a signal on the RX path; see
 * CondrvSerialRead. Routed to the console whose conhost is doing this tty
 * read (defined with the console machinery below). */
#define CONDRV_SERIAL_INTR 0x03
static void CondrvSerialInterrupt(void);

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
static NTSTATUS CondrvSerialRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                                 IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)request; /* the console reads block rather than pend (docs/03 CUI-5) */
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
        BOOLEAN interrupt = FALSE;
        while (got < length && (ch = KiSerialTryGetChar()) >= 0)
        {
            if (ch == CONDRV_SERIAL_INTR)
            {
                /* ^C is a SIGNAL, not input (CUI-4). Under HACK-004 the UART
                 * RX path IS this milestone's keyboard driver (docs/02 M9),
                 * so it is also the line discipline: like a Unix tty's ISIG,
                 * the byte is consumed here and becomes a console control
                 * event rather than a keystroke. Delivered after the read
                 * returns, so the fanout never runs under conhost's read. */
                interrupt = TRUE;
                continue;
            }
            out[got++] = (unsigned char)ch;
        }
        if (interrupt)
        {
            CondrvSerialInterrupt();
        }
        if (got != 0)
        {
            *infoOut = got;
            return STATUS_SUCCESS;
        }
        if (interrupt)
        {
            /* Nothing but the ^C: report a zero-length read rather than
             * blocking, so conhost's input thread loops promptly. */
            *infoOut = 0;
            return STATUS_SUCCESS;
        }
        /* Nap one clock tick between polls (relative 100 ns units). */
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; /* 1 ms */
        NTSTATUS napStatus = KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (napStatus != STATUS_SUCCESS)
        {
            /* CUI-4: a foreign terminate broke the nap — stop polling and let
             * the thread unwind to its reaping edge instead of re-napping. */
            *infoOut = 0;
            return napStatus;
        }
    }
}

static NTSTATUS CondrvSerialWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                                  ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    (void)file;
    (void)request;
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

/* --- \Device\ConDrv: per-client consoles -------------------------------------- */

/* The object model is wineserver's (third_party/wine server/console.c), one
 * struct per console rather than one static: a Server open MINTS a console
 * server; "Reference" relative to it mints THE console, once
 * (console_server_lookup_name); "Connection" relative to the console BINDS
 * the opening process (console_lookup_name); Input/Output opens and their
 * I/O resolve the CALLER's binding at call time, never a captured pointer
 * (console_input_ioctl and friends read current->process->console). The
 * binding itself lives on the EPROCESS (`process->console`, the wineserver
 * field of the same name) so the Ctrl+C fanout and the create-path fixups
 * see the same authority (Art. 11). Pinned by tests/ntapi/sem_console/. */

typedef enum
{
    CondrvOpenServer,
    CondrvOpenConsole, /* "Reference": the console object itself */
    CondrvOpenConnection,
    CondrvOpenInput,
    CondrvOpenOutput, /* Output; also ScreenBuffer (outputId > 1) */
} CONDRV_OPEN_KIND;

typedef struct CONDRV_CONSOLE CONDRV_CONSOLE, *PCONDRV_CONSOLE;

typedef struct CONDRV_OPEN
{
    CONDRV_OPEN_KIND kind;
    ULONG outputId;          /* screen-buffer id (kind == Output); 1 = conhost's
                              * pre-created default buffer */
    PCONDRV_CONSOLE console; /* counted. Server: the minted console;
                              * Console: the referenced console;
                              * ScreenBuffer: the console the id was minted
                              * on (its CLOSE_OUTPUT must reach that conhost
                              * even after the closer unbinds). Input/Output/
                              * Connection carry NONE — their routing is the
                              * caller's binding, resolved per call. */
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

struct CONDRV_CONSOLE
{
    LIST_ENTRY listEntry; /* CondrvConsoleList (serial-^C routing) */
    /* G11 ownership audit — who holds refCount: the Server open, every
     * Console-kind open (Reference handles, the create-fixup duplicates
     * included — they share the FILE_OBJECT), every ScreenBuffer open, and
     * every bound EPROCESS. clientCount is the subset that means "someone
     * is still using this console": everything above except the Server
     * open itself. In-flight CONDRV_REQUESTs hold neither — each lives on
     * its requester's stack, and the requester's own open or binding pins
     * the console for the duration of CondrvForward. */
    LONG refCount;
    LONG clientCount;
    BOOLEAN referenceMinted; /* one console per server (wineserver
                              * console_server_lookup_name's INVALID_HANDLE) */
    PFILE_OBJECT serverFile; /* conhost's Server open; 0 = conhost gone */
    PEPROCESS serverProcess; /* the process last PUMPING the server (its
                              * conhost — the opener may be smss, whose
                              * child inherited the handle; refreshed at
                              * every server read). Serial-^C routing keys
                              * off it. Weak, cleared with serverFile. */
    LIST_ENTRY requestQueue; /* queued, not yet fetched by conhost */
    LIST_ENTRY readQueue;    /* head = the delivered blocking read awaiting
                              * read_complete; tail = reads deferred behind
                              * it (wineserver's read_queue shape) */
    PCONDRV_REQUEST current; /* delivered non-read verb, awaiting its reply */
    uint64_t nextRequestId;
    ULONG nextOutputId; /* fresh screen-buffer ids (2+) */
};

static LIST_ENTRY CondrvConsoleList;

static IO_FCB CondrvConsoleFcb;

static void CondrvReferenceConsole(PCONDRV_CONSOLE console)
{
    console->refCount++;
}

static void CondrvReleaseConsole(PCONDRV_CONSOLE console)
{
    ASSERT(console->refCount > 0);
    if (--console->refCount != 0)
    {
        return;
    }
    ASSERT(console->clientCount == 0);
    ASSERT(console->current == 0);
    ASSERT(IsListEmpty(&console->requestQueue));
    ASSERT(IsListEmpty(&console->readQueue));
    RemoveEntryList(&console->listEntry);
    MiFreePool(console);
}

/* The caller's console binding — wineserver's `current->process->console`,
 * which every Input/Output open and I/O resolves at CALL time. */
static PCONDRV_CONSOLE CondrvCallerConsole(void)
{
    return KeGetCurrentThread()->process->console;
}

/* A ^C on the serial wire (HACK-004) belongs to the console whose conhost
 * is doing this tty read: the reading thread IS that conhost's input
 * thread, so its process names the console without scanning any handle
 * table. No match (a stray ^C with no serial conhost) is dropped loudly
 * (Art. 12). */
static void CondrvSerialInterrupt(void)
{
    PEPROCESS reader = KeGetCurrentThread()->process;
    for (PLIST_ENTRY entry = CondrvConsoleList.Flink; entry != &CondrvConsoleList;
         entry = entry->Flink)
    {
        PCONDRV_CONSOLE console = CONTAINING_RECORD(entry, CONDRV_CONSOLE, listEntry);
        if (console->serverProcess == reader)
        {
            PsPropagateConsoleCtrlEvent(console, CTRL_C_EVENT, 0);
            return;
        }
    }
    DbgPrint("condrv: serial ^C with no console server reading the tty; dropped\n");
}

/* The server file object doubles as conhost's wait handle: signaled while
 * requests are queued (its DISPATCHER_HEADER is event-shaped — io.h). */
static void CondrvSignalServer(PCONDRV_CONSOLE console, BOOLEAN pending)
{
    if (console->serverFile == 0)
    {
        return;
    }
    PKEVENT event = (PKEVENT)&console->serverFile->header;
    if (pending)
    {
        KeSetEvent(event, 0, FALSE);
    }
    else
    {
        KeClearEvent(event);
    }
}

/* One client (a Console/ScreenBuffer open, or a process binding) is gone.
 * When the LAST one goes, wake conhost: its next Server read answers
 * STATUS_INVALID_HANDLE (wineserver's get_next_console_request answer once
 * the console is gone), which is how conhost learns to exit — the boot
 * conhost never sees it because smss holds its Reference handle forever. */
static void CondrvClientGone(PCONDRV_CONSOLE console)
{
    ASSERT(console->clientCount > 0);
    if (--console->clientCount == 0)
    {
        CondrvSignalServer(console, TRUE);
    }
    CondrvReleaseConsole(console);
}

/* Bind `process` to `console` — the ONE writer of process->console
 * (wineserver console_lookup_name / console_connection_ioctl; Art. 11).
 * The caller has checked the process is unbound. */
static void CondrvBindProcess(PEPROCESS process, PCONDRV_CONSOLE console)
{
    ASSERT(process->console == 0);
    CondrvReferenceConsole(console);
    console->clientCount++;
    process->console = console;
}

/* Unbind `process` from whatever console it is bound to (wineserver
 * console_connection_close_handle; idempotent — the process-delete fallback
 * runs after the handle sweep already unbound through the connection's
 * Cleanup). */
static void CondrvUnbindProcess(PEPROCESS process)
{
    PCONDRV_CONSOLE console = process->console;
    if (console == 0)
    {
        return;
    }
    process->console = 0;
    CondrvClientGone(console);
}

/* The process-delete fallback (kernel/ps/process.c PspDeleteProcess): a
 * binding normally drops at the connection handle's Cleanup during the
 * exit sweep, but a connection handle duplicated into another process
 * outlives the binder's sweep — this keeps the EPROCESS reference audit
 * balanced regardless. */
void CondrvProcessDelete(PEPROCESS process)
{
    CondrvUnbindProcess(process);
}

/* Package one client verb, queue it, wake conhost, park until the reply. */
static NTSTATUS CondrvForward(PCONDRV_CONSOLE console, ULONG code, ULONG output, const void *input,
                              ULONG inputLength, void *outputBuffer, ULONG outputCapacity,
                              ULONG_PTR *infoOut)
{
    if (console->serverFile == 0)
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
    request.id = ++console->nextRequestId;
    request.code = code;
    request.output = output;
    request.input = input;
    request.inputLength = inputLength;
    request.outputBuffer = outputBuffer;
    request.outputCapacity = outputCapacity;
    request.status = STATUS_INVALID_DEVICE_STATE;
    request.information = 0;
    KeInitializeEvent(&request.done, NotificationEvent, FALSE);

    InsertTailList(&console->requestQueue, &request.listEntry);
    CondrvSignalServer(console, TRUE);
    NTSTATUS waitStatus = KeWaitForSingleObject(&request.done, Executive, KernelMode, FALSE, 0);
    if (waitStatus != STATUS_SUCCESS)
    {
        /* CUI-4: the client thread is being terminated. Our `request` lives on
         * this (now-unwinding) kernel stack, so nothing conhost still owns may
         * point at it. THREE states are reachable here, not two: the abort
         * (KiAbortThreadWait) readies this thread without touching the console
         * queues, and on the uniprocessor this thread does not run again until
         * conhost parks — so conhost can fetch the request AND complete it in
         * that window.
         *
         *   completed  `done` is signalled. CondrvCompleteRequest is its only
         *              setter and always runs after the request has left both
         *              queues and `current`, so there is nothing to unlink —
         *              unlinking anyway is a double-remove, which is the list
         *              assert the GUI-5 msg run tripped in
         *              test_WaitForInputIdle (docs/03 "GUI-5 winetest notes").
         *   delivered  a fetched non-read verb conhost has yet to answer:
         *              `current`, already off both queues.
         *   queued     still on requestQueue, or parked/deferred on readQueue.
         *
         * A vanished read completes on conhost's side as STATUS_INVALID_HANDLE,
         * which it already tolerates. */
        uint64_t f = KiAcquireDispatcherLock();
        if (KeReadStateEvent(&request.done) != 0)
        {
            /* completed: unlinked and unowned already */
        }
        else if (console->current == &request)
        {
            console->current = 0;
        }
        else
        {
            RemoveEntryList(&request.listEntry);
        }
        KiReleaseDispatcherLock(f);
        return waitStatus;
    }

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
static NTSTATUS CondrvServerRead(PCONDRV_CONSOLE console, void *buffer, ULONG length,
                                 ULONG_PTR *infoOut)
{
    if (console->current != 0)
    {
        return STATUS_INVALID_DEVICE_STATE; /* reply before fetching again */
    }
    /* Whoever pumps the server IS this console's conhost — the opener may
     * have been smss, whose spawned child inherited the handle. */
    console->serverProcess = KeGetCurrentThread()->process;

    /* The console's last client is gone: answer the fetch the way
     * wineserver's get_next_console_request answers a server whose console
     * has been destroyed — conhost's process_console_ioctls returns on it
     * and conhost exits. Queued work cannot exist here (every request is
     * pinned by a live client). */
    if (console->referenceMinted && console->clientCount == 0)
    {
        return STATUS_INVALID_HANDLE;
    }

    /* wineserver's move-aside: while a read is outstanding, queued reads
     * shift to the read queue (order kept) so non-reads can flow. */
    if (!IsListEmpty(&console->readQueue) && !IsListEmpty(&console->requestQueue))
    {
        PCONDRV_REQUEST head =
            CONTAINING_RECORD(console->requestQueue.Flink, CONDRV_REQUEST, listEntry);
        if (CondrvIsBlockingReadCode(head->code))
        {
            PLIST_ENTRY entry = console->requestQueue.Flink;
            while (entry != &console->requestQueue)
            {
                PLIST_ENTRY next = entry->Flink;
                PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
                if (CondrvIsBlockingReadCode(request->code))
                {
                    RemoveEntryList(entry);
                    InsertTailList(&console->readQueue, entry);
                }
                entry = next;
            }
        }
    }

    if (IsListEmpty(&console->requestQueue))
    {
        CondrvSignalServer(console, FALSE);
        return STATUS_PENDING;
    }
    PLIST_ENTRY entry = RemoveHeadList(&console->requestQueue);
    PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
    if (IsListEmpty(&console->requestQueue))
    {
        CondrvSignalServer(console, FALSE);
    }

    ULONG total = (ULONG)sizeof(CONDRV_SERVER_MSG) + request->inputLength;
    if (length < total)
    {
        /* The glue always offers the full protocol buffer; re-queue and
         * refuse rather than truncating. */
        InsertHeadList(&console->requestQueue, entry);
        CondrvSignalServer(console, TRUE);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (CondrvIsBlockingReadCode(request->code))
    {
        ASSERT(IsListEmpty(&console->readQueue));
        InsertTailList(&console->readQueue, entry);
    }
    else
    {
        console->current = request;
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
static NTSTATUS CondrvServerWrite(PCONDRV_CONSOLE console, const void *buffer, ULONG length,
                                  ULONG_PTR *infoOut)
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
        if (IsListEmpty(&console->readQueue))
        {
            /* conhost's signal-only read_complete; it tolerates exactly
             * this status (wineserver answers the same). */
            return STATUS_INVALID_HANDLE;
        }
        PLIST_ENTRY entry = RemoveHeadList(&console->readQueue);
        PCONDRV_REQUEST request = CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry);
        CondrvCompleteRequest(request, status, reply + 1, reply->outSize);
        /* Deferred reads become deliverable again (wineserver moves the
         * read queue back after a completion). */
        while (!IsListEmpty(&console->readQueue))
        {
            InsertTailList(&console->requestQueue, RemoveHeadList(&console->readQueue));
        }
        if (!IsListEmpty(&console->requestQueue))
        {
            CondrvSignalServer(console, TRUE);
        }
        *infoOut = length;
        return STATUS_SUCCESS;
    }

    PCONDRV_REQUEST request = console->current;
    if (request != 0)
    {
        if (request->id != reply->id)
        {
            return STATUS_INVALID_PARAMETER;
        }
        console->current = 0;
        CondrvCompleteRequest(request, status, reply + 1, reply->outSize);
    }
    *infoOut = length;
    return STATUS_SUCCESS;
}

/* Server teardown: every queued, busy, and parked-read request fails — a
 * dead conhost degrades ITS console, it never deadlocks a client. The
 * console object itself lives on while clients hold references; their
 * later verbs fail fast at CondrvForward's serverFile check. */
static void CondrvServerGone(PCONDRV_CONSOLE console)
{
    console->serverFile = 0;
    console->serverProcess = 0;
    if (console->current != 0)
    {
        CondrvCompleteRequest(console->current, STATUS_INVALID_DEVICE_STATE, 0, 0);
        console->current = 0;
    }
    while (!IsListEmpty(&console->readQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&console->readQueue);
        CondrvCompleteRequest(CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry),
                              STATUS_INVALID_DEVICE_STATE, 0, 0);
    }
    while (!IsListEmpty(&console->requestQueue))
    {
        PLIST_ENTRY entry = RemoveHeadList(&console->requestQueue);
        CondrvCompleteRequest(CONTAINING_RECORD(entry, CONDRV_REQUEST, listEntry),
                              STATUS_INVALID_DEVICE_STATE, 0, 0);
    }
}

/* --- ConDrv vfs ops ---------------------------------------------------------- */

/* Name equality against a device-relative component. */
static BOOLEAN CondrvNameIs(const UNICODE_STRING *path, const WCHAR *name)
{
    UNICODE_STRING expected;
    RtlInitUnicodeString(&expected, name);
    return RtlEqualUnicodeString(path, &expected, TRUE);
}

/* The open/binding rules, one arm per wineserver lookup (server/console.c):
 *
 *   \Device\ConDrv\Server              mint a console server
 *   "Reference"  rel. Server           mint THE console, once
 *   "Reference"  rel. Connection       the caller's bound console
 *   "Connection" rel. Console          bind the caller (unbound callers only)
 *   \Device\ConDrv\Connection          connection, no bind (unbound callers only)
 *   \Device\ConDrv\Input|Output        caller must be bound; routed per call
 *   \Device\ConDrv\ScreenBuffer        new buffer on the caller's console
 *
 * Pinned by tests/ntapi/sem_console/ against the real wineserver. */
static NTSTATUS CondrvConsoleCreate(PIO_DEVICE device, PFILE_OBJECT file,
                                    const UNICODE_STRING *path, PFILE_OBJECT relativeTo,
                                    ACCESS_MASK grantedAccess, ULONG shareAccess,
                                    ULONG fileAttributes, ULONG disposition, ULONG options,
                                    ULONG_PTR *information)
{
    (void)device;
    (void)grantedAccess;
    (void)shareAccess;
    (void)fileAttributes;
    (void)disposition; /* kernelbase opens Input/Output with FILE_CREATE */
    (void)options;

    PCONDRV_OPEN rootOpen =
        (relativeTo != 0 && relativeTo->fcb == &CondrvConsoleFcb) ? relativeTo->fsContext : 0;
    PEPROCESS process = KeGetCurrentThread()->process;

    CONDRV_OPEN_KIND kind;
    PCONDRV_CONSOLE console = 0; /* the counted pointer the open will carry */
    PCONDRV_CONSOLE mint = 0;    /* Server open: the console minted below */
    BOOLEAN bindCaller = FALSE;
    ULONG outputId = 0;

    if (rootOpen == 0 && CondrvNameIs(path, WSTR("Server")))
    {
        /* Every Server open mints its own console server (wineserver
         * create_console_server — an unconditional mint; sem_console/
         * server_multi is the pin that retired the one-server refusal). */
        mint = MiAllocatePool(sizeof(CONDRV_CONSOLE));
        if (mint == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memset(mint, 0, sizeof(*mint));
        InitializeListHead(&mint->requestQueue);
        InitializeListHead(&mint->readQueue);
        mint->nextOutputId = 1; /* id 1 = conhost's pre-created buffer */
        mint->refCount = 1;     /* the server open's */
        mint->serverFile = file;
        mint->serverProcess = process;
        InsertTailList(&CondrvConsoleList, &mint->listEntry);
        kind = CondrvOpenServer;
        console = mint;
        /* The request pump is NtReadFile/NtWriteFile HERE (the fork
         * transport, drivers/condrvproto.h) where wineserver serves a
         * get_next_console_request server call — which has no file-access
         * dimension, so kernelbase opens the server handle PROPERTIES-ONLY
         * (dlls/kernelbase/console.c create_console_server:
         * FILE_WRITE_PROPERTIES | FILE_READ_PROPERTIES | SYNCHRONIZE). The
         * data access the pump needs is therefore this device's to grant,
         * not the caller's to request; without it the alloc_console-spawned
         * conhost's first fetch answered STATUS_ACCESS_DENIED and it exited
         * (docs/03 M11 note). */
        file->grantedAccess |= FILE_READ_DATA | FILE_WRITE_DATA;
    }
    else if (rootOpen != 0 && rootOpen->kind == CondrvOpenServer &&
             CondrvNameIs(path, WSTR("Reference")))
    {
        /* Mint THE console for that server, once (console_server_lookup_name:
         * a second Reference answers STATUS_INVALID_HANDLE). Minting is NOT
         * binding — the opener stays unbound. */
        if (rootOpen->console->referenceMinted)
        {
            return STATUS_INVALID_HANDLE;
        }
        rootOpen->console->referenceMinted = TRUE;
        kind = CondrvOpenConsole;
        console = rootOpen->console;
        CondrvReferenceConsole(console);
        console->clientCount++;
    }
    else if (rootOpen != 0 && rootOpen->kind == CondrvOpenConnection &&
             CondrvNameIs(path, WSTR("Reference")))
    {
        /* The caller's bound console (console_connection_lookup_name). */
        if (process->console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        kind = CondrvOpenConsole;
        console = process->console;
        CondrvReferenceConsole(console);
        console->clientCount++;
    }
    else if ((rootOpen == 0 || rootOpen->kind == CondrvOpenConsole) &&
             CondrvNameIs(path, WSTR("Connection")))
    {
        /* A connection: relative to a console it BINDS the caller
         * (console_lookup_name); absolute it binds nothing. Either way an
         * already-bound caller refuses (create_console_connection's
         * ACCESS_DENIED arm). */
        if (process->console != 0)
        {
            return STATUS_ACCESS_DENIED;
        }
        kind = CondrvOpenConnection;
        bindCaller = rootOpen != 0;
    }
    else if (rootOpen == 0 && CondrvNameIs(path, WSTR("Input")))
    {
        /* Caller-bound opens: refuse while unbound
         * (console_device_lookup_name), capture nothing — every read and
         * ioctl re-resolves the binding. */
        if (process->console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        kind = CondrvOpenInput;
    }
    else if (rootOpen == 0 && CondrvNameIs(path, WSTR("Output")))
    {
        if (process->console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        kind = CondrvOpenOutput;
        outputId = 1;
    }
    else if (rootOpen == 0 && CondrvNameIs(path, WSTR("ScreenBuffer")))
    {
        /* A fresh screen buffer on the CALLER's console: mint the id there
         * and have its conhost create it (INIT_OUTPUT) before the open
         * returns. The open keeps a counted console pointer — its
         * CLOSE_OUTPUT at cleanup must reach that conhost even if the
         * closer has since unbound (wineserver's screen_buffer->input). */
        if (process->console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        console = process->console;
        outputId = ++console->nextOutputId;
        ULONG_PTR ignored = 0;
        NTSTATUS status =
            CondrvForward(console, IOCTL_CONDRV_INIT_OUTPUT, outputId, 0, 0, 0, 0, &ignored);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        kind = CondrvOpenOutput;
        CondrvReferenceConsole(console);
        console->clientCount++;
    }
    else
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    PCONDRV_OPEN open = MiAllocatePool(sizeof(CONDRV_OPEN));
    if (open == 0)
    {
        if (mint != 0)
        {
            CondrvReleaseConsole(mint);
        }
        else if (console != 0)
        {
            CondrvClientGone(console);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    open->kind = kind;
    open->outputId = outputId;
    open->console = console;
    if (bindCaller)
    {
        CondrvBindProcess(process, rootOpen->console);
    }

    file->fsContext = open;
    file->fcb = &CondrvConsoleFcb;
    file->isDirectory = FALSE;
    /* This device drives `header` itself, so the Io layer must leave it alone
     * (kernel/io/io.h deviceManagedSignal). The server handle is the reason —
     * it IS conhost's wait handle, and an I/O completion that re-signals it
     * re-arms conhost's park on the very read that drained the queue. The
     * input/output opens are marked too, deliberately: nothing manages their
     * `header` at all today, so leaving them born-signalled is the state this
     * change is not making a claim about. */
    file->deviceManagedSignal = TRUE;
    if (kind == CondrvOpenServer)
    {
        /* Born signaled (io.h); the server handle signals "requests
         * pending", so start clear. */
        KeClearEvent((PKEVENT)&file->header);
        DbgPrint("condrv: console server attached\n");
    }
    *information = FILE_OPENED;
    return STATUS_SUCCESS;
}

static void CondrvConsoleCleanup(PFILE_OBJECT file)
{
    PCONDRV_OPEN open = file->fsContext;
    switch (open->kind)
    {
    case CondrvOpenServer:
        if (open->console->serverFile == file)
        {
            CondrvServerGone(open->console);
        }
        break;
    case CondrvOpenConsole:
        CondrvClientGone(open->console);
        open->console = 0; /* the client count carried the reference */
        break;
    case CondrvOpenConnection:
        /* Closing a connection handle unbinds the CLOSING process from
         * whatever console it is bound to
         * (console_connection_close_handle) — both NtClose and the exit
         * sweep run in the closing process's own context. */
        CondrvUnbindProcess(KeGetCurrentThread()->process);
        break;
    case CondrvOpenOutput:
        if (open->outputId > 1)
        {
            ULONG_PTR ignored = 0;
            CondrvForward(open->console, IOCTL_CONDRV_CLOSE_OUTPUT, open->outputId, 0, 0, 0, 0,
                          &ignored);
            CondrvClientGone(open->console);
            open->console = 0;
        }
        break;
    default:
        break;
    }
}

static void CondrvConsoleClose(PFILE_OBJECT file)
{
    PCONDRV_OPEN open = file->fsContext;
    if (open->console != 0)
    {
        /* The Server open's own reference (client opens dropped theirs at
         * Cleanup, through the client count). */
        CondrvReleaseConsole(open->console);
    }
    MiFreePool(open);
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

static NTSTATUS CondrvConsoleRead(PFILE_OBJECT file, void *buffer, ULONG length, ULONG_PTR *infoOut,
                                  IO_CONTROL_CONTEXT *request)
{
    PCONDRV_OPEN open = file->fsContext;
    (void)request; /* the console reads block rather than pend (docs/03 CUI-5) */
    switch (open->kind)
    {
    case CondrvOpenServer:
        return CondrvServerRead(open->console, buffer, length, infoOut);
    case CondrvOpenInput:
    {
        /* ReadFile on a console handle: kernelbase's fallback path — the
         * same cooked read the console server implements as READ_FILE.
         * Routed through the caller's CURRENT binding, not anything the
         * open captured (wineserver console_input_read). */
        PCONDRV_CONSOLE console = CondrvCallerConsole();
        if (console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        return CondrvForward(console, IOCTL_CONDRV_READ_FILE, 0, 0, 0, buffer, length, infoOut);
    }
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS CondrvConsoleWrite(PFILE_OBJECT file, const void *buffer, ULONG length,
                                   ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    (void)request;
    PCONDRV_OPEN open = file->fsContext;
    switch (open->kind)
    {
    case CondrvOpenServer:
        return CondrvServerWrite(open->console, buffer, length, infoOut);
    case CondrvOpenOutput:
    {
        /* WriteFile on a console handle -> WRITE_FILE, chunked under the
         * protocol payload cap so any write size succeeds. A plain Output
         * open routes through the caller's binding (console_output_write);
         * a ScreenBuffer open writes ITS buffer on ITS console. */
        PCONDRV_CONSOLE console = open->console != 0 ? open->console : CondrvCallerConsole();
        if (console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
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
                CondrvForward(console, IOCTL_CONDRV_WRITE_FILE, open->outputId,
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
                                           ULONG_PTR *infoOut, IO_CONTROL_CONTEXT *request)
{
    (void)request; /* console verbs complete inline (docs/19 §2) */
    PCONDRV_OPEN open = file->fsContext;
    PEPROCESS process = KeGetCurrentThread()->process;
    if (open->kind == CondrvOpenServer)
    {
        if (code == IOCTL_CONDRV_SETUP_INPUT)
        {
            *infoOut = 0; /* conhost's input-thread setup: nothing to do here */
            return STATUS_SUCCESS;
        }
        if (code == IOCTL_CONDRV_CTRL_EVENT)
        {
            /* conhost's ctrl-event fanout (CUI-4): it swallowed a ^C key
             * record and asks the OS to signal ITS console's processes.
             * group_id 0 means every attached process (wineserver's
             * console_server_ioctl -> propagate_console_signal). */
            const struct condrv_ctrl_event *event = input;
            if (inputLength != sizeof(*event))
            {
                return STATUS_INVALID_PARAMETER;
            }
            *infoOut = 0;
            return PsPropagateConsoleCtrlEvent(open->console, (ULONG)event->event, event->group_id);
        }
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (open->kind == CondrvOpenConnection && code == IOCTL_CONDRV_BIND_PID)
    {
        /* AttachConsole's kernel half (wineserver console_connection_ioctl):
         * adopt the target process's console. An already-bound caller
         * refuses; a target with no console refuses; ATTACH_PARENT_PROCESS
         * resolves to the caller's parent. Pinned by sem_console/
         * bind_pid_adopt. */
        if (inputLength != sizeof(unsigned int))
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (process->console != 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        /* ATTACH_PARENT_PROCESS = (DWORD)-1 (third_party/wine
         * include/wincon.h:33; resolved server-side exactly as wineserver's
         * BIND_PID arm resolves it to the caller's parent id). */
        uint64_t pid = *(const unsigned int *)input;
        if (pid == 0xffffffff)
        {
            pid = process->parentProcessId;
        }
        PEPROCESS target = 0;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(uintptr_t)pid, &target);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (target->console == 0)
        {
            ObDereferenceObject(target);
            return STATUS_ACCESS_DENIED;
        }
        CondrvBindProcess(process, target->console);
        ObDereferenceObject(target);
        *infoOut = 0;
        return STATUS_SUCCESS;
    }
    if (code == IOCTL_CONDRV_CTRL_EVENT)
    {
        /* The GenerateConsoleCtrlEvent path (dlls/kernelbase/console.c) on a
         * CLIENT handle. Served kernel-side, never forwarded: this is a
         * wineserver verb, and conhost answers it STATUS_INVALID_HANDLE.
         * Group resolution mirrors server/console.c: an explicit group, else
         * the caller's own; a zero group is a parameter error (unlike the
         * server handle's broadcast). */
        const struct condrv_ctrl_event *event = input;
        if (inputLength != sizeof(*event))
        {
            return STATUS_INVALID_PARAMETER;
        }
        PCONDRV_CONSOLE console =
            open->kind == CondrvOpenConsole ? open->console : process->console;
        if (console == 0)
        {
            return STATUS_INVALID_HANDLE;
        }
        uint64_t group = event->group_id != 0 ? event->group_id : process->processGroupId;
        if (group == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        *infoOut = 0;
        return PsPropagateConsoleCtrlEvent(console, (ULONG)event->event, group);
    }

    /* Data verbs forward to the console's conhost. A Console-kind handle
     * (the ConsoleHandle kernelbase ioctls GET_WINDOW and friends through)
     * targets ITS console (wineserver console_ioctl); Input/Output handles
     * and ScreenBuffer-less opens route through the caller's binding at
     * call time (console_input_ioctl / console_output_ioctl). */
    PCONDRV_CONSOLE console;
    switch (open->kind)
    {
    case CondrvOpenConsole:
        console = open->console;
        break;
    case CondrvOpenOutput:
        console = open->console != 0 ? open->console : CondrvCallerConsole();
        break;
    case CondrvOpenInput:
        console = CondrvCallerConsole();
        break;
    default:
        return STATUS_INVALID_DEVICE_REQUEST; /* other verbs on a connection */
    }
    if (console == 0)
    {
        return STATUS_INVALID_HANDLE;
    }
    return CondrvForward(console, code, open->kind == CondrvOpenOutput ? open->outputId : 0, input,
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

/* --- initialization ---------------------------------------------------------- */

void CondrvInitialize(void)
{
    IopInitializeFcb(&CondrvSerialFcb);
    IopInitializeFcb(&CondrvConsoleFcb);
    InitializeListHead(&CondrvConsoleList);
    /* GetFileType maps FILE_DEVICE_SERIAL_PORT and FILE_DEVICE_CONSOLE to
     * FILE_TYPE_CHAR (Wine dlls/kernelbase/file.c); the console value is
     * what wineserver's console objects report (server/console.c
     * console_get_volume_info). */
    IoPublishDevice(WSTR("\\Device\\Serial0"), &CondrvSerialOps, 0, FILE_DEVICE_SERIAL_PORT);
    CondrvConsoleDevice =
        IoPublishDevice(WSTR("\\Device\\ConDrv"), &CondrvConsoleOps, 0, FILE_DEVICE_CONSOLE);
}
