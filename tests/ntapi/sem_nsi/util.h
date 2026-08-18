/*
 * sem_nsi/util.h — shared helpers for the Net-3 \Device\Nsi semantics tests.
 *
 * Same two-mode arrangement as sem_net/util.h: the NSI ioctl codes,
 * module ids and row shapes mingw's headers omit are declared here as
 * wine/include/wine/nsi.h and wine/include/netiodef.h spell them — the
 * oracle run itself validates every value, since a wrong code or a wrong
 * layout would answer differently against the real nsi.dll/nsiproxy.sys
 * stack (docs/24 §1b: the oracle is measured from OUTSIDE;
 * wine/dlls/nsiproxy.sys is never read). The kernel's own generated
 * copies live in abi/nsi.h (G4); tests use the system NT headers plus
 * these local declarations, never abi/ (ntapi.h's header comment).
 *
 * Every case is table-shape and loopback-property based: the oracle's
 * tables describe the HOST's interfaces and proskrnl's describe lwIP's
 * two netifs, so no verdict may name a host-specific row — the one row
 * both sides own is the software loopback, and everything else is
 * counted, sized, or cross-referenced, never value-golden.
 */
#ifndef NTAPI_SEM_NSI_UTIL_H
#define NTAPI_SEM_NSI_UTIL_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <in6addr.h>
#include <ifdef.h> /* NET_LUID, IF_COUNTED_STRING, IF_PHYSICAL_ADDRESS */
#include "../ntapi.h"

#define W(s) u##s

#include <string.h>   /* declarations only: the .exe links no CRT; ntapi.c defines them */
#include <winioctl.h> /* CTL_CODE, FILE_DEVICE_NETWORK */

/* Prototypes mingw's winternl.h omits (as wine/include/winternl.h). */
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* --- the NSI boundary, as wine/include/{wine/nsi.h,netiodef.h} spell it --- */

/* NPI_MODULEID (netiodef.h; also the MS SDK's netiodef.h — mingw ships no
 * copy, so it is declared here and the oracle validates the layout). */
typedef enum
{
    MIT_GUID = 1,
    MIT_IF_LUID
} NPI_MODULEID_TYPE;

typedef struct
{
    USHORT Length;
    NPI_MODULEID_TYPE Type;
    union
    {
        GUID Guid;
        LUID IfLuid;
    };
} NPI_MODULEID;

/* DEFINE_NPI_MS_MODULEID(name, n): {eb004a00+n, 9b1a, 11d4,
 * {91,23,00,50,04,77,59,bc}} (netiodef.h). */
#define NPI_MS_MODULEID_INIT(n)                                                                    \
    {                                                                                              \
        sizeof(NPI_MODULEID), MIT_GUID,                                                            \
        {                                                                                          \
            {                                                                                      \
                0xeb004a00 + (n), 0x9b1a, 0x11d4,                                                  \
                {                                                                                  \
                    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc                                 \
                }                                                                                  \
            }                                                                                      \
        }                                                                                          \
    }

static const NPI_MODULEID npi_ms_ipv4 = NPI_MS_MODULEID_INIT(0x00);
static const NPI_MODULEID npi_ms_ipv6 = NPI_MS_MODULEID_INIT(0x01);
static const NPI_MODULEID npi_ms_ndis = NPI_MS_MODULEID_INIT(0x11);

/* The five wine-dialect ioctls (wine/nsi.h). */
#define NSI_IOC(x)                              CTL_CODE(FILE_DEVICE_NETWORK, (x), METHOD_BUFFERED, 0)
#define IOCTL_NSIPROXY_WINE_ENUMERATE_ALL       NSI_IOC(0x400)
#define IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS  NSI_IOC(0x401)
#define IOCTL_NSIPROXY_WINE_GET_PARAMETER       NSI_IOC(0x402)
#define IOCTL_NSIPROXY_WINE_ICMP_ECHO           NSI_IOC(0x403)
#define IOCTL_NSIPROXY_WINE_CHANGE_NOTIFICATION NSI_IOC(0x404)

#define NSI_PARAM_TYPE_RW      0
#define NSI_PARAM_TYPE_DYNAMIC 1
#define NSI_PARAM_TYPE_STATIC  2

#define NSI_NDIS_IFINFO_TABLE 0
#define NSI_IP_UNICAST_TABLE  10
#define NSI_IP_FORWARD_TABLE  16

/* IF_TYPE_SOFTWARE_LOOPBACK (ipifcons.h; MS-fixed IANA ifType). */
#define NSI_IF_TYPE_SOFTWARE_LOOPBACK 24

/* Request shapes (wine/nsi.h, x86_64 layouts). */
struct nsiproxy_enumerate_all
{
    NPI_MODULEID module;
    UINT first_arg;
    UINT second_arg;
    UINT table;
    UINT key_size;
    UINT rw_size;
    UINT dynamic_size;
    UINT static_size;
    UINT count;
};

struct nsiproxy_get_all_parameters
{
    NPI_MODULEID module;
    UINT first_arg;
    UINT table;
    UINT key_size;
    UINT rw_size;
    UINT dynamic_size;
    UINT static_size;
    BYTE key[1]; /* key_size */
};

struct nsiproxy_get_parameter
{
    NPI_MODULEID module;
    UINT first_arg;
    UINT table;
    UINT key_size;
    UINT param_type;
    UINT data_offset;
    BYTE key[1]; /* key_size */
};

struct nsiproxy_request_notification
{
    NPI_MODULEID module;
    UINT table;
};

/* Row shapes (wine/nsi.h). */
struct nsi_ndis_ifinfo_rw
{
    GUID network_guid;
    UINT admin_status;
    IF_COUNTED_STRING alias;
    IF_PHYSICAL_ADDRESS phys_addr;
    USHORT pad;
    IF_COUNTED_STRING name2;
    UINT unk;
};

struct nsi_ndis_ifinfo_dynamic
{
    UINT oper_status;
    struct
    {
        UINT unk : 1;
        UINT not_media_conn : 1;
        UINT unk2 : 30;
    } flags;
    UINT media_conn_state;
    UINT unk;
    UINT mtu;
    ULONG64 xmit_speed;
    ULONG64 rcv_speed;
    ULONG64 unk2[3];
    ULONG64 in_discards;
    ULONG64 in_errors;
    ULONG64 in_octets;
    ULONG64 in_ucast_pkts;
    ULONG64 in_mcast_pkts;
    ULONG64 in_bcast_pkts;
    ULONG64 out_octets;
    ULONG64 out_ucast_pkts;
    ULONG64 out_mcast_pkts;
    ULONG64 out_bcast_pkts;
    ULONG64 out_errors;
    ULONG64 out_discards;
    ULONG64 in_ucast_octs;
    ULONG64 in_mcast_octs;
    ULONG64 in_bcast_octs;
    ULONG64 out_ucast_octs;
    ULONG64 out_mcast_octs;
    ULONG64 out_bcast_octs;
    ULONG64 unk4;
};

struct nsi_ndis_ifinfo_static
{
    UINT if_index;
    IF_COUNTED_STRING descr;
    UINT type;
    UINT access_type;
    UINT unk;
    UINT conn_type;
    GUID if_guid;
    USHORT conn_present;
    IF_PHYSICAL_ADDRESS perm_phys_addr;
    struct
    {
        UINT hw : 1;
        UINT filter : 1;
        UINT unk : 30;
    } flags;
    UINT media_type;
    UINT phys_medium_type;
};

struct nsi_ipv4_unicast_key
{
    NET_LUID luid;
    IN_ADDR addr;
    UINT pad;
};

struct nsi_ipv6_unicast_key
{
    NET_LUID luid;
    IN6_ADDR addr;
};

struct nsi_ip_unicast_rw
{
    UINT preferred_lifetime;
    UINT valid_lifetime;
    UINT prefix_origin;
    UINT suffix_origin;
    UINT on_link_prefix;
    UINT unk[2];
};

struct nsi_ip_unicast_dynamic
{
    UINT scope_id;
    UINT dad_state;
};

struct nsi_ip_unicast_static
{
    ULONG64 creation_time;
};

struct nsi_ipv4_forward_key
{
    UINT unk;
    IN_ADDR prefix;
    BYTE prefix_len;
    BYTE unk2[3];
    UINT unk3[3];
    NET_LUID luid;
    NET_LUID luid2;
    IN_ADDR next_hop;
    UINT pad;
};

struct nsi_ip_forward_rw
{
    UINT site_prefix_len;
    UINT valid_lifetime;
    UINT preferred_lifetime;
    UINT metric;
    UINT protocol;
    BYTE loopback;
    BYTE autoconf;
    BYTE publish;
    BYTE immortal;
    BYTE unk[4];
    UINT unk2;
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

#define LOOPBACK_BE 0x0100007f /* 127.0.0.1 in network byte order, as an LE dword */

/* Open \Device\Nsi the way nsi.dll's get_nsi_device does (CreateFileW with
 * dwDesiredAccess 0 — kernelbase maps that to FILE_READ_ATTRIBUTES |
 * SYNCHRONIZE — FILE_SHARE_READ|WRITE, no flags). */
static inline NTSTATUS nsi_open(HANDLE *handle)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    init_ustr(&name, W("\\Device\\Nsi"));
    init_attr(&attr, NULL, &name, 0);
    *handle = NULL;
    return NtOpenFile(handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attr, &iosb,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
}

/* One IOCTL_NSIPROXY_WINE_ENUMERATE_ALL, the nsi.dll shape: input header
 * with per-array strides and a row capacity, output DWORD count then the
 * four arrays back to back at the input strides. Returns the ioctl's
 * status; *answered_out = the leading DWORD (valid on success and on the
 * short-buffer status). */
static inline NTSTATUS nsi_enumerate(HANDLE h, const NPI_MODULEID *module, UINT table, void *key,
                                     UINT key_size, void *rw, UINT rw_size, void *dyn,
                                     UINT dynamic_size, void *stat, UINT static_size, UINT count,
                                     UINT *answered_out, IO_STATUS_BLOCK *iosb_out)
{
    struct nsiproxy_enumerate_all in;
    IO_STATUS_BLOCK iosb;
    ULONG out_size = sizeof(DWORD) + (key_size + rw_size + dynamic_size + static_size) * count;
    BYTE *out = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, out_size);
    NTSTATUS status;
    BYTE *ptr;
    UINT answered;

    memset(&in, 0, sizeof(in));
    in.module = *module;
    in.first_arg = 1; /* what iphlpapi's table readers pass */
    in.second_arg = 0;
    in.table = table;
    in.key_size = key_size;
    in.rw_size = rw_size;
    in.dynamic_size = dynamic_size;
    in.static_size = static_size;
    in.count = count;

    poison_iosb(&iosb);
    status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_ENUMERATE_ALL,
                                   &in, sizeof(in), out, out_size);
    answered = *(DWORD *)out;
    if (answered > count)
        answered = count;
    ptr = out + sizeof(DWORD);
    if (key_size != 0 && key != NULL)
        memcpy(key, ptr, key_size * answered);
    ptr += key_size * count;
    if (rw_size != 0 && rw != NULL)
        memcpy(rw, ptr, rw_size * answered);
    ptr += rw_size * count;
    if (dynamic_size != 0 && dyn != NULL)
        memcpy(dyn, ptr, dynamic_size * answered);
    ptr += dynamic_size * count;
    if (static_size != 0 && stat != NULL)
        memcpy(stat, ptr, static_size * answered);
    if (answered_out != NULL)
        *answered_out = *(DWORD *)out;
    if (iosb_out != NULL)
        *iosb_out = iosb;
    HeapFree(GetProcessHeap(), 0, out);
    return status;
}

/* The count probe: all strides zero — the DWORD answers the table's row
 * count with no row data (the NsiAllocateAndGetTable resize path). */
static inline NTSTATUS nsi_count(HANDLE h, const NPI_MODULEID *module, UINT table, UINT *count_out)
{
    return nsi_enumerate(h, module, table, NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0, count_out, NULL);
}

/* IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS keyed by `key`: rw + dynamic +
 * static back to back in the output. */
static inline NTSTATUS nsi_get_all(HANDLE h, const NPI_MODULEID *module, UINT table,
                                   const void *key, UINT key_size, void *rw, UINT rw_size,
                                   void *dyn, UINT dynamic_size, void *stat, UINT static_size)
{
    struct
    {
        struct nsiproxy_get_all_parameters hdr;
        BYTE key_space[64];
    } in;
    ULONG in_size = FIELD_OFFSET(struct nsiproxy_get_all_parameters, key[key_size]);
    ULONG out_size = rw_size + dynamic_size + static_size;
    BYTE *out = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, out_size);
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    BYTE *ptr;

    memset(&in, 0, sizeof(in));
    in.hdr.module = *module;
    in.hdr.first_arg = 0;
    in.hdr.table = table;
    in.hdr.key_size = key_size;
    in.hdr.rw_size = rw_size;
    in.hdr.dynamic_size = dynamic_size;
    in.hdr.static_size = static_size;
    memcpy(in.hdr.key, key, key_size);

    poison_iosb(&iosb);
    status =
        NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_GET_ALL_PARAMETERS,
                              &in, in_size, out, out_size);
    ptr = out;
    if (rw_size != 0 && rw != NULL)
        memcpy(rw, ptr, rw_size);
    ptr += rw_size;
    if (dynamic_size != 0 && dyn != NULL)
        memcpy(dyn, ptr, dynamic_size);
    ptr += dynamic_size;
    if (static_size != 0 && stat != NULL)
        memcpy(stat, ptr, static_size);
    HeapFree(GetProcessHeap(), 0, out);
    return status;
}

/* IOCTL_NSIPROXY_WINE_GET_PARAMETER: one field of one row, named by
 * param_type + byte offset (the ConvertInterfaceLuidToGuid shape). */
static inline NTSTATUS nsi_get_param(HANDLE h, const NPI_MODULEID *module, UINT table,
                                     const void *key, UINT key_size, UINT param_type,
                                     UINT data_offset, void *data, UINT data_size)
{
    struct
    {
        struct nsiproxy_get_parameter hdr;
        BYTE key_space[64];
    } in;
    ULONG in_size = FIELD_OFFSET(struct nsiproxy_get_parameter, key[key_size]);
    IO_STATUS_BLOCK iosb;

    memset(&in, 0, sizeof(in));
    in.hdr.module = *module;
    in.hdr.first_arg = 1; /* what ConvertInterfaceLuidToGuid passes */
    in.hdr.table = table;
    in.hdr.key_size = key_size;
    in.hdr.param_type = param_type;
    in.hdr.data_offset = data_offset;
    memcpy(in.hdr.key, key, key_size);

    poison_iosb(&iosb);
    return NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_NSIPROXY_WINE_GET_PARAMETER, &in,
                                 in_size, data, data_size);
}

/* Find the software-loopback row of the ndis ifinfo table — the one row
 * both runners own. Returns TRUE and fills the out params on success. */
static inline BOOLEAN nsi_find_loopback(HANDLE h, NET_LUID *luid_out,
                                        struct nsi_ndis_ifinfo_static *stat_out,
                                        struct nsi_ndis_ifinfo_dynamic *dyn_out,
                                        struct nsi_ndis_ifinfo_rw *rw_out)
{
    NET_LUID keys[16];
    static struct nsi_ndis_ifinfo_rw rw[16]; /* 1092 bytes/row: keep off the stack */
    static struct nsi_ndis_ifinfo_dynamic dyn[16];
    static struct nsi_ndis_ifinfo_static stat[16];
    UINT count = 0, i;
    NTSTATUS status;

    status =
        nsi_enumerate(h, &npi_ms_ndis, NSI_NDIS_IFINFO_TABLE, keys, sizeof(keys[0]), rw,
                      sizeof(rw[0]), dyn, sizeof(dyn[0]), stat, sizeof(stat[0]), 16, &count, NULL);
    if (status != STATUS_SUCCESS || count == 0 || count > 16)
        return FALSE;
    for (i = 0; i < count; i++)
    {
        if (stat[i].type == NSI_IF_TYPE_SOFTWARE_LOOPBACK)
        {
            if (luid_out != NULL)
                *luid_out = keys[i];
            if (stat_out != NULL)
                *stat_out = stat[i];
            if (dyn_out != NULL)
                *dyn_out = dyn[i];
            if (rw_out != NULL)
                *rw_out = rw[i];
            return TRUE;
        }
    }
    return FALSE;
}

#endif /* NTAPI_SEM_NSI_UTIL_H */
