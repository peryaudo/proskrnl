/* fs/npfs/npfs.h — the named-pipe filesystem (M9, docs/02).
 *
 * The boundary is the pinned tests/ntapi/sem_pipe/ suite: instance
 * accounting, connect-before-listen, disconnect/broken statuses, byte-mode
 * coalescing, and the message framing rpcrt4 needs. Internals are free
 * (Art. 1): one flat list of pipes on \Device\NamedPipe, each a list of
 * instances whose two ends exchange pooled message buffers; blocking uses
 * plain KEVENTs — no IRP, no MDL. Transfers complete inline (docs/19 §2);
 * the listen verb and the CUI-5 cancellable parks are the exceptions.
 */
#ifndef PROSKRNL_FS_NPFS_NPFS_H
#define PROSKRNL_FS_NPFS_NPFS_H

#include "kernel/io/vfs.h"

extern const IO_VFS_OPS NpfsVfsOps;

/* Publish \Device\NamedPipe (+ the \??\pipe symlink). Needs the Ob
 * namespace and a thread with a handle table; no disk dependency. */
void NpfsInitialize(void);

#endif /* PROSKRNL_FS_NPFS_NPFS_H */
