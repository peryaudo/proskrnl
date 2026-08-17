/*
 * sem_net/util.h — shared helpers for the Net-2 \Device\Afd semantics tests.
 *
 * Same two-mode arrangement as sem_pipe/util.h: the AFD ioctl codes and
 * parameter shapes mingw's headers omit are declared here as
 * wine/include/wine/afd.h spells them — the oracle run itself validates
 * every value, since a wrong code or a wrong layout would answer
 * differently against the real ws2_32/wineserver stack (docs/24 §1b: the
 * oracle is measured from OUTSIDE; wine/server/sock.c is never read).
 * The kernel's own generated copies live in abi/afd.h (G4); tests use the
 * system NT headers plus these local declarations, never abi/ (ntapi.h's
 * header comment).
 *
 * Every case in this bucket is loopback-only and device-free: both
 * sockets live in the same process, 127.0.0.1, ephemeral ports learned by
 * binding port 0 and reading the name back — deterministic on a
 * wineserver against the host loopback and on proskrnl against lwIP's
 * loop interface, with no NIC and no timing in any verdict.
 */
#ifndef NTAPI_SEM_NET_UTIL_H
#define NTAPI_SEM_NET_UTIL_H

/* winsock2.h must precede windows.h's own winsock pull-in; the lean macro
 * keeps ntapi.h's <windows.h> from dragging winsock.h first. Types and
 * constants only — nothing here links against ws2_32 (the whole point is
 * to speak to \Device\Afd raw). */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "../ntapi.h"

#define W(s) u##s

#include <string.h>   /* declarations only: the .exe links no CRT; ntapi.c defines them */
#include <winioctl.h> /* CTL_CODE, FILE_DEVICE_BEEP, FILE_DEVICE_NETWORK */

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID,
                                   ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                    const void *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, PLARGE_INTEGER);

/* --- the AFD boundary, as wine/include/wine/afd.h spells it -------------- */

/* The native-compatible codes (FILE_DEVICE_BEEP-based like real afd.sys). */
#define AFD_CTL(code, method)  CTL_CODE(FILE_DEVICE_BEEP, (code), (method), FILE_ANY_ACCESS)
#define IOCTL_AFD_BIND         AFD_CTL(0x800, METHOD_NEITHER)
#define IOCTL_AFD_LISTEN       AFD_CTL(0x802, METHOD_NEITHER)
#define IOCTL_AFD_RECV         AFD_CTL(0x805, METHOD_NEITHER)
#define IOCTL_AFD_POLL         AFD_CTL(0x809, METHOD_BUFFERED)
#define IOCTL_AFD_GETSOCKNAME  AFD_CTL(0x80b, METHOD_NEITHER)
#define IOCTL_AFD_EVENT_SELECT AFD_CTL(0x821, METHOD_NEITHER)
#define IOCTL_AFD_GET_EVENTS   AFD_CTL(0x822, METHOD_NEITHER)

/* The Wine-private family, function numbers 200..304. */
#define WINE_AFD_IOC(x)                  CTL_CODE(FILE_DEVICE_NETWORK, (x), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AFD_WINE_CREATE            WINE_AFD_IOC(200)
#define IOCTL_AFD_WINE_ACCEPT            WINE_AFD_IOC(201)
#define IOCTL_AFD_WINE_ACCEPT_INTO       WINE_AFD_IOC(202)
#define IOCTL_AFD_WINE_CONNECT           WINE_AFD_IOC(203)
#define IOCTL_AFD_WINE_SHUTDOWN          WINE_AFD_IOC(204)
#define IOCTL_AFD_WINE_RECVMSG           WINE_AFD_IOC(205)
#define IOCTL_AFD_WINE_SENDMSG           WINE_AFD_IOC(206)
#define IOCTL_AFD_WINE_FIONBIO           WINE_AFD_IOC(209)
#define IOCTL_AFD_WINE_COMPLETE_ASYNC    WINE_AFD_IOC(210)
#define IOCTL_AFD_WINE_FIONREAD          WINE_AFD_IOC(211)
#define IOCTL_AFD_WINE_GETPEERNAME       WINE_AFD_IOC(216)
#define IOCTL_AFD_WINE_GET_INFO          WINE_AFD_IOC(218)
#define IOCTL_AFD_WINE_GET_SO_ACCEPTCONN WINE_AFD_IOC(219)
#define IOCTL_AFD_WINE_GET_SO_ERROR      WINE_AFD_IOC(222)

/* The 13-bit readiness word (IOCTL_AFD_GET_EVENTS has space for 13). */
#define AFD_POLL_READ        0x0001
#define AFD_POLL_OOB         0x0002
#define AFD_POLL_WRITE       0x0004
#define AFD_POLL_HUP         0x0008
#define AFD_POLL_RESET       0x0010
#define AFD_POLL_CLOSE       0x0020
#define AFD_POLL_CONNECT     0x0040
#define AFD_POLL_ACCEPT      0x0080
#define AFD_POLL_CONNECT_ERR 0x0100

#define AFD_RECV_FORCE_ASYNC 0x2
#define AFD_MSG_NOT_OOB      0x0020
#define AFD_MSG_OOB          0x0040
#define AFD_MSG_PEEK         0x0080
#define AFD_MSG_WAITALL      0x4000

/* Parameter shapes (wine/include/wine/afd.h, x86_64 layouts). */
struct afd_create_params
{
    int family, type, protocol;
    unsigned int flags;
};

struct afd_bind_params
{
    int unknown;
    struct sockaddr addr; /* variable size */
};

struct afd_listen_params
{
    int unknown1;
    int backlog;
    int unknown2;
};

struct afd_recv_params
{
    const WSABUF *buffers;
    unsigned int count;
    int recv_flags;
    int msg_flags;
};

struct afd_connect_params
{
    int addr_len;
    int synchronous;
    /* followed by the sockaddr bytes, then optional send data */
};

struct afd_accept_into_params
{
    ULONG accept_handle;
    unsigned int recv_len, local_len;
};

struct afd_recvmsg_params
{
    ULONGLONG control_ptr;  /* WSABUF */
    ULONGLONG addr_ptr;     /* struct sockaddr */
    ULONGLONG addr_len_ptr; /* int */
    ULONGLONG ws_flags_ptr; /* unsigned int */
    int force_async;
    unsigned int count;
    ULONGLONG buffers_ptr; /* WSABUF[] */
};

struct afd_sendmsg_params
{
    ULONGLONG addr_ptr; /* const struct sockaddr */
    unsigned int addr_len;
    unsigned int ws_flags;
    int force_async;
    unsigned int count;
    ULONGLONG buffers_ptr; /* const WSABUF[] */
};

struct afd_get_info_params
{
    int family, type, protocol;
};

/* --- plumbing ------------------------------------------------------------- */

static inline void init_ustr(UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    str->Length = (USHORT)(len * 2);
    str->MaximumLength = (USHORT)(len * 2 + 2);
    str->Buffer = (PWSTR)(void *)p;
}

static inline void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name,
                             ULONG flags)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = flags;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

#define IOSB_POISON_STATUS ((NTSTATUS)0x0BADF00D)
static inline void poison_iosb(IO_STATUS_BLOCK *iosb)
{
    iosb->Status = IOSB_POISON_STATUS;
    iosb->Information = (ULONG_PTR)~0ULL;
}

static inline BOOLEAN is_signaled(HANDLE handle)
{
    return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
}

/* Wait for a pended request's completion event with a generous bound; the
 * verdicts are content, never timing (docs/19 §11c). */
static inline BOOLEAN wait_done(HANDLE event)
{
    return WaitForSingleObject(event, 30000) == WAIT_OBJECT_0;
}

/* htons without linking ws2_32 (it is an import there, not a macro). */
static inline unsigned short sw16(unsigned short v)
{
    return (unsigned short)((v << 8) | (v >> 8));
}

#define LOOPBACK_BE 0x0100007f /* 127.0.0.1 in network byte order, as an LE dword */

/* --- socket construction -------------------------------------------------- */

/* Open a raw \Device\Afd handle the way ws2_32's WSASocketW does
 * (dlls/ws2_32/socket.c WSASocketW: GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
 * FILE_SYNCHRONOUS_IO_NONALERT unless overlapped). */
static inline NTSTATUS afd_open(HANDLE *handle, BOOLEAN synchronous)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, W("\\Device\\Afd"));
    init_attr(&attr, NULL, &name, 0);
    *handle = NULL;
    return NtOpenFile(handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &attr, &iosb, 0,
                      synchronous ? FILE_SYNCHRONOUS_IO_NONALERT : 0);
}

/* Open + IOCTL_AFD_WINE_CREATE: a bare socket. `synchronous` picks the
 * handle synchronicity (WSA_FLAG_OVERLAPPED's inverse). */
static inline NTSTATUS afd_create(HANDLE *handle, int family, int type, int protocol,
                                  BOOLEAN synchronous)
{
    struct afd_create_params params;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = afd_open(handle, synchronous);
    if (status != STATUS_SUCCESS)
        return status;
    params.family = family;
    params.type = type;
    params.protocol = protocol;
    params.flags = 0;
    status = NtDeviceIoControlFile(*handle, NULL, NULL, NULL, &iosb, IOCTL_AFD_WINE_CREATE, &params,
                                   sizeof(params), NULL, 0);
    if (status != STATUS_SUCCESS)
    {
        NtClose(*handle);
        *handle = NULL;
    }
    return status;
}

static inline NTSTATUS afd_tcp(HANDLE *handle, BOOLEAN synchronous)
{
    return afd_create(handle, AF_INET, SOCK_STREAM, IPPROTO_TCP, synchronous);
}

static inline NTSTATUS afd_udp(HANDLE *handle, BOOLEAN synchronous)
{
    return afd_create(handle, AF_INET, SOCK_DGRAM, IPPROTO_UDP, synchronous);
}

/* IOCTL_AFD_BIND to 127.0.0.1:port (0 = ephemeral); the bound name comes
 * back in the OUTPUT buffer (ws2_32's bind passes a same-size result
 * buffer and the port materializes there). Returns the ioctl's final
 * status; *bound_out (optional) receives the bound sockaddr_in. On the
 * pinned Wine the verb completes through the event even when the answer
 * is immediate, so a scratch event is part of the shape. */
static inline NTSTATUS afd_bind_loopback(HANDLE s, unsigned short port,
                                         struct sockaddr_in *bound_out)
{
    struct
    {
        struct afd_bind_params params;
        char space[sizeof(struct sockaddr_in)];
    } in;
    struct sockaddr_in bound;
    IO_STATUS_BLOCK iosb;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    struct sockaddr_in *addr = (struct sockaddr_in *)&in.params.addr;
    NTSTATUS status;

    memset(&in, 0, sizeof(in));
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = LOOPBACK_BE;
    addr->sin_port = sw16(port);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, event, NULL, NULL, &iosb, IOCTL_AFD_BIND, &in.params,
                                   sizeof(int) + sizeof(struct sockaddr_in), &bound, sizeof(bound));
    if (status == STATUS_PENDING)
    {
        if (!wait_done(event))
        {
            CloseHandle(event);
            return STATUS_IO_TIMEOUT;
        }
        status = iosb.Status;
    }
    CloseHandle(event);
    if (status == STATUS_SUCCESS && bound_out != NULL)
        *bound_out = bound;
    return status;
}

static inline NTSTATUS afd_listen(HANDLE s, int backlog)
{
    struct afd_listen_params params;
    IO_STATUS_BLOCK iosb;
    memset(&params, 0, sizeof(params));
    params.backlog = backlog;
    return NtDeviceIoControlFile(s, NULL, NULL, NULL, &iosb, IOCTL_AFD_LISTEN, &params,
                                 sizeof(params), NULL, 0);
}

/* IOCTL_AFD_WINE_CONNECT to 127.0.0.1:port, waiting out a pend (the
 * ws2_32 connect() shape: synchronous=TRUE, an event, wait, io.Status). */
static inline NTSTATUS afd_connect_loopback(HANDLE s, unsigned short port)
{
    struct
    {
        struct afd_connect_params params;
        struct sockaddr_in addr;
    } in;
    IO_STATUS_BLOCK iosb;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    NTSTATUS status;

    memset(&in, 0, sizeof(in));
    in.params.addr_len = sizeof(struct sockaddr_in);
    in.params.synchronous = TRUE;
    in.addr.sin_family = AF_INET;
    in.addr.sin_addr.s_addr = LOOPBACK_BE;
    in.addr.sin_port = sw16(port);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_CONNECT, &in,
                                   sizeof(in), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (!wait_done(event))
        {
            CloseHandle(event);
            return STATUS_IO_TIMEOUT;
        }
        status = iosb.Status;
    }
    CloseHandle(event);
    return status;
}

/* A connected loopback TCP pair: *server_out accepts *client_out's
 * connection on an ephemeral port. Both handles asynchronous. Returns
 * FALSE (with its own ok() failures) when construction fails. */
static inline BOOLEAN tcp_pair(HANDLE *client_out, HANDLE *server_out)
{
    HANDLE listener = NULL, client = NULL, server_handle = NULL;
    struct sockaddr_in bound = {0};
    IO_STATUS_BLOCK iosb;
    HANDLE event;
    ULONG accept_handle = 0;
    NTSTATUS status;

    *client_out = *server_out = NULL;
    status = afd_tcp(&listener, FALSE);
    ok(status == STATUS_SUCCESS, "listener create -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return FALSE;
    status = afd_bind_loopback(listener, 0, &bound);
    ok(status == STATUS_SUCCESS, "listener bind -> %08lx", (unsigned long)status);
    status = afd_listen(listener, 1);
    ok(status == STATUS_SUCCESS, "listen -> %08lx", (unsigned long)status);

    status = afd_tcp(&client, FALSE);
    ok(status == STATUS_SUCCESS, "client create -> %08lx", (unsigned long)status);
    status = afd_connect_loopback(client, sw16(bound.sin_port));
    ok(status == STATUS_SUCCESS, "connect -> %08lx", (unsigned long)status);

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(listener, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_ACCEPT, NULL,
                                   0, &accept_handle, sizeof(accept_handle));
    if (status == STATUS_PENDING)
    {
        ok(wait_done(event), "accept never completed");
        status = iosb.Status;
    }
    CloseHandle(event);
    ok(status == STATUS_SUCCESS, "accept -> %08lx", (unsigned long)status);
    NtClose(listener);
    if (status != STATUS_SUCCESS)
    {
        if (client != NULL)
            NtClose(client);
        return FALSE;
    }
    server_handle = (HANDLE)(ULONG_PTR)accept_handle;
    *client_out = client;
    *server_out = server_handle;
    return TRUE;
}

/* One IOCTL_AFD_RECV into a flat buffer, run to its FINAL status through
 * the supplied event (waiting out a pend); *received_out = bytes. */
static inline NTSTATUS afd_recv_wait(HANDLE s, void *buffer, ULONG length, ULONG *received_out)
{
    WSABUF wsabuf;
    struct afd_recv_params params;
    IO_STATUS_BLOCK iosb;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    NTSTATUS status;

    wsabuf.len = length;
    wsabuf.buf = (char *)buffer;
    memset(&params, 0, sizeof(params));
    params.buffers = &wsabuf;
    params.count = 1;
    params.msg_flags = AFD_MSG_NOT_OOB;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, event, NULL, NULL, &iosb, IOCTL_AFD_RECV, &params,
                                   sizeof(params), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (!wait_done(event))
        {
            CloseHandle(event);
            return STATUS_IO_TIMEOUT;
        }
        status = iosb.Status;
    }
    CloseHandle(event);
    if (received_out != NULL)
        *received_out = (ULONG)iosb.Information;
    return status;
}

/* One IOCTL_AFD_WINE_SENDMSG of a flat buffer (no address: connected
 * stream shape), waited to its final status. */
static inline NTSTATUS afd_send_wait(HANDLE s, const void *buffer, ULONG length, ULONG *sent_out)
{
    WSABUF wsabuf;
    struct afd_sendmsg_params params;
    IO_STATUS_BLOCK iosb;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    NTSTATUS status;

    wsabuf.len = length;
    wsabuf.buf = (char *)(ULONG_PTR)buffer;
    memset(&params, 0, sizeof(params));
    params.count = 1;
    params.buffers_ptr = (ULONG_PTR)&wsabuf;
    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(s, event, NULL, NULL, &iosb, IOCTL_AFD_WINE_SENDMSG, &params,
                                   sizeof(params), NULL, 0);
    if (status == STATUS_PENDING)
    {
        if (!wait_done(event))
        {
            CloseHandle(event);
            return STATUS_IO_TIMEOUT;
        }
        status = iosb.Status;
    }
    CloseHandle(event);
    if (sent_out != NULL)
        *sent_out = (ULONG)iosb.Information;
    return status;
}

#endif /* NTAPI_SEM_NET_UTIL_H */
