/* kernel/io/io.h — the Io department: devices, file objects, the Nt* file
 * surface (M6, docs/02).
 *
 * The forced part (docs/05): the async-completion protocol — final status
 * in the return value, the IO_STATUS_BLOCK written before any completion
 * signal, event/APC completion — and NT file semantics (share modes,
 * case-insensitivity, delete-on-close, byte-range locks), pinned by
 * tests/ntapi/sem_file/ on the Wine oracle. Everything internal is free:
 * no IRP, no device stacks; a device is an Ob object holding a vfs.h op
 * table, and all I/O is synchronous under the hood (Art. 3), completing
 * before the syscall returns.
 *
 * APC completion: accepted at the boundary but deliverable only once M7
 * brings KiUserApcDispatcher; until then a user-mode ApcRoutine is refused
 * loudly (STATUS_NOT_IMPLEMENTED), never dropped silently. The oracle-side
 * spec already exists (sem_file/apc_completion.c, excluded from the
 * proskrnl manifest).
 */
#ifndef PROSKRNL_KERNEL_IO_IO_H
#define PROSKRNL_KERNEL_IO_IO_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntioapi.h"
#include "kernel/ob/ob.h"
#include "kernel/ke/ke.h"
#include "kernel/io/vfs.h"
#include "kernel/mm/pagecache.h"

/* --- Device objects -------------------------------------------------------- */

/* Body of an Ob "Device" object (\Device\HarddiskVolume1). */
typedef struct IO_DEVICE
{
    const IO_VFS_OPS *ops;
    PVOID context; /* the mounted FAT_VOLUME */
} IO_DEVICE, *PIO_DEVICE;

extern OBJECT_TYPE IoDeviceType;
extern OBJECT_TYPE IoFileObjectType;

/* --- File objects ---------------------------------------------------------- */

/* Body of an Ob "File" object: one open of one file. NT's FILE_OBJECT
 * concept; internal layout ours (docs/03). File handles are waitable —
 * NT signals the file object at I/O completion; with every operation
 * completing synchronously (Art. 3) the object is simply born signaled
 * and stays so, which is also what the pinned Wine reports for disk
 * files (fuzzer-pinned). */
typedef struct FILE_OBJECT
{
    DISPATCHER_HEADER header; /* notification-event shape, always signaled */
    PIO_DEVICE device; /* referenced via the Ob device body */
    PIO_FCB fcb;       /* the FS's per-file node (fs/fat32 FAT_FCB) */
    PVOID fsContext;   /* == fcb, typed for the FS's convenience */
    BOOLEAN isDirectory;
    BOOLEAN synchronousIo; /* FILE_SYNCHRONOUS_IO_* at create */
    BOOLEAN deleteOnClose; /* FILE_DELETE_ON_CLOSE at create */
    BOOLEAN shareCounted;  /* this open holds share-access slots */
    ACCESS_MASK grantedAccess;
    ULONG shareAccess; /* this open's FILE_SHARE_* */
    LARGE_INTEGER currentByteOffset;

    /* Directory enumeration state: the mask binds to the handle (pinned
     * Wine: a NULL mask on a later call reuses the previous one). */
    ULONG dirCursor;
    BOOLEAN dirScanStarted; /* first-query state: empty result is
                             * NO_SUCH_FILE only on the first scan */
    UNICODE_STRING dirMask; /* pool copy; Buffer 0 = no mask yet */
} FILE_OBJECT, *PFILE_OBJECT;

/* --- initialization (kernel/io/file.c) ------------------------------------- */

/* Two-phase bring-up. IoInitializeTransport probes virtio-blk and maps its
 * MMIO window — it MUST run before PsInitializeProcessSubsystem (the window
 * may claim a fresh kernel PML4 slot, frozen there). IoMountBootVolume
 * mounts FAT32 and publishes \Device\HarddiskVolume1 + \??\C:; it creates
 * handles, so it runs on the first kernel thread (a process context).
 * Absence of a disk is tolerated. */
void IoInitializeTransport(void);
void IoMountBootVolume(void);

/* --- share-mode accounting (kernel/io/file.c; NT's Io*ShareAccess) --------- */

NTSTATUS IoCheckShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);
void IoSetShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);
void IoRemoveShareAccess(ACCESS_MASK desiredAccess, ULONG shareAccess, PIO_FCB fcb);

/* --- byte-range locks (kernel/io/lock.c) ----------------------------------- */

void IopInitializeFcb(PIO_FCB fcb);
/* Grant/refuse [offset, offset+length) for `owner`. */
NTSTATUS IopLockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length,
                      BOOLEAN exclusive);
NTSTATUS IopUnlockRange(PIO_FCB fcb, PFILE_OBJECT owner, uint64_t offset, uint64_t length);
void IopReleaseAllLocks(PIO_FCB fcb, PFILE_OBJECT owner);

/* --- helpers shared across the io department ------------------------------- */

/* Resolve a file handle with an access check. Caller dereferences. */
NTSTATUS IopReferenceFileByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PFILE_OBJECT *fileOut);

/* Complete one operation: write the IOSB, then signal the optional event —
 * in exactly that order (the docs/08 contract). `eventHandle` may be 0. */
NTSTATUS IopCompleteRequest(IO_STATUS_BLOCK *iosb, HANDLE eventHandle, NTSTATUS status,
                            ULONG_PTR information);

#endif /* PROSKRNL_KERNEL_IO_IO_H */
