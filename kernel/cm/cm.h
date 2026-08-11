/* kernel/cm/cm.h — the Cm department: the registry (M8, docs/02).
 *
 * The forced part (docs/05 "Cm — interface only"): the Nt*Key* semantics and
 * information classes Wine's user land exchanges with the kernel, pinned by
 * tests/ntapi/sem_reg/ on the Wine oracle. Everything internal is free and
 * deliberately the dumbest correct thing (Art. 3): the whole registry is a
 * pool-resident tree of key nodes, every key handle is an Ob object pointing
 * at a node (NT's KEY_BODY -> KCB shape), and persistence is a full rewrite
 * of one hive file in our own format on every successful mutation — no cell
 * allocator, no incremental updates, no recovery logging (docs/03 "Cm hive
 * format"; the on-disk layout is documented in hive.c).
 */
#ifndef PROSKRNL_KERNEL_CM_CM_H
#define PROSKRNL_KERNEL_CM_CM_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntregapi.h"
#include "kernel/lib/list.h"
#include "kernel/ob/ob.h"

/* --- the tree ------------------------------------------------------------- */

/* One registry key. Owned by the tree (the parent's subkey list); freed when
 * deleted AND no key body references it any more. NT's KCB concept, layout
 * ours. Names are pool copies; lookup is case-insensitive, case is
 * preserved. */
typedef struct CMP_KEY_NODE
{
    struct CMP_KEY_NODE *parent; /* 0 for the \Registry root */
    LIST_ENTRY siblingEntry;     /* in parent->subkeyListHead */
    LIST_ENTRY subkeyListHead;   /* CMP_KEY_NODE.siblingEntry */
    LIST_ENTRY valueListHead;    /* CMP_VALUE.listEntry */
    LIST_ENTRY notifyListHead;   /* CMP_NOTIFY.entry (notify.c) */
    ULONG subkeyCount;
    ULONG valueCount;
    LARGE_INTEGER lastWriteTime;
    ULONG bodyCount;    /* key bodies bound to this node */
    BOOLEAN deleted;    /* NtDeleteKey ran; node is unlinked */
    BOOLEAN isVolatile; /* REG_OPTION_VOLATILE: never persisted */
    BOOLEAN isLink;     /* REG_OPTION_CREATE_LINK: resolves via SymbolicLinkValue */
    UNICODE_STRING name;
} CMP_KEY_NODE, *PCMP_KEY_NODE;

/* One value under a key. Name and data are pool copies. */
typedef struct CMP_VALUE
{
    LIST_ENTRY listEntry;
    UNICODE_STRING name; /* Length 0 = the default (unnamed) value */
    ULONG type;
    ULONG dataLength;
    PVOID data; /* 0 when dataLength == 0 */
} CMP_VALUE, *PCMP_VALUE;

/* Body of an Ob "Key" object: one open of one key. */
typedef struct CM_KEY_BODY
{
    PCMP_KEY_NODE node;
} CM_KEY_BODY, *PCM_KEY_BODY;

/* One change-notification record: wineserver's `struct notify`, keyed by the
 * arming open (one CM_KEY_BODY per open ≈ the server's (process, hkey) key;
 * a NtDuplicateHandle'd key handle shares its body and therefore its record
 * — docs/03 "CUI-7" notes). Lives on the WATCHED node's notifyListHead; the
 * body pointer is an identity for matching only, never dereferenced. The
 * record can never outlive its body: it is freed when the body's last handle
 * closes (CmpCloseKeyBody) and the body's node reference keeps the node
 * alive until then. */
typedef struct CMP_NOTIFY
{
    LIST_ENTRY entry;        /* on CMP_KEY_NODE.notifyListHead */
    const CM_KEY_BODY *body; /* identity of the arming open */
    BOOLEAN subtree;         /* fixed at the FIRST arm (server semantics) */
    ULONG filter;            /* fixed at the FIRST arm (server semantics) */
    ULONG eventCount;
    PVOID *events; /* referenced event bodies, signalled together */
} CMP_NOTIFY, *PCMP_NOTIFY;

extern OBJECT_TYPE CmpKeyType;

/* The \Registry root node (created by CmInitialize, never deleted). */
extern PCMP_KEY_NODE CmpRootNode;

/* --- registry.c ------------------------------------------------------------ */

/* Bring up the registry: create the \Registry namespace object, the root/
 * Machine/User skeleton, and load the SYSTEM hive from the boot volume (a
 * missing or invalid hive file starts an empty registry — first boot). Runs
 * on the first kernel thread, after IoMountBootVolume. */
void CmInitialize(void);

/* Free one node's values (hive load/parse error unwind + delete paths). */
void CmpFreeValues(PCMP_KEY_NODE node);

/* Allocate a node with a pool copy of `name`, linked under `parent`
 * (parent == 0 for the root). 0 on pool exhaustion. */
/* Maximum key-tree depth, counting the root as level 1. ONE number for
 * three things that must agree: the hive parser's recursion cap, the
 * serializer's (CmpMeasureKey/CmpEmitKey recurse per level on a 16 KiB stack
 * with no guard page), and the create path's -- see CmpAllocateNode for why
 * an asymmetry between them is worse than either limit. */
#define CMP_HIVE_MAX_DEPTH 96u

/* Sanity cap on any hive image the kernel will read or write — the boot hive
 * and every NtLoadKey/NtSaveKey subtree image alike. ONE number: the load
 * paths in NtLoadKey and NtRestoreKey bound a ring-3-supplied file with it
 * before allocating, and the hive writer bounds itself with it. */
#define CMP_HIVE_MAX_BYTES (64u << 20)

/* Depth of `node` counting itself, 0 for the null parent of the root. THE
 * authority for the question. */
ULONG CmpKeyDepth(const CMP_KEY_NODE *node);

/* `node`'s path in WCHARs, writing at most `capacity` of them and returning
 * the BYTES the whole path needs. relativeTo == 0 gives the absolute
 * "\REGISTRY\..." form; a non-null relativeTo stops there (exclusive) and
 * drops the leading separator, which is how the hive log spells a key. */
ULONG CmpBuildPath(const CMP_KEY_NODE *node, const CMP_KEY_NODE *relativeTo, WCHAR *out,
                   ULONG capacity);

/* Resolve a '\'-separated counted path under `start`, optionally creating the
 * components. 0 = a component is missing (when !create) or the pool is
 * exhausted. THE resolver: replay and the boot skeleton share it so a
 * case-variant name folds identically everywhere (Art. 11). */
PCMP_KEY_NODE CmpWalkPathCounted(PCMP_KEY_NODE start, const UNICODE_STRING *path, BOOLEAN create);

/* Returns 0 when the parent is already at CMP_HIVE_MAX_DEPTH, as well as on
 * allocation failure. */
PCMP_KEY_NODE CmpAllocateNode(PCMP_KEY_NODE parent, const UNICODE_STRING *name);

/* Find one named value on `node`, or 0. */
PCMP_VALUE CmpFindValue(PCMP_KEY_NODE node, const UNICODE_STRING *name);

/* Set/replace value `name` on `node` from a kernel-side buffer. */
NTSTATUS CmpSetValue(PCMP_KEY_NODE node, const UNICODE_STRING *name, ULONG type, const void *data,
                     ULONG dataLength);

/* Resolve a key handle for one operation: type check, access check, and the
 * stale-handle STATUS_KEY_DELETED rule (registry.c; wine server/registry.c
 * get_hkey_obj). The caller dereferences *bodyOut on success. */
NTSTATUS CmpReferenceKey(HANDLE handle, ACCESS_MASK desiredAccess, BOOLEAN allowDeleted,
                         PCM_KEY_BODY *bodyOut);

/* --- notify.c ---------------------------------------------------------------- */

/* Fire the change notifications a mutation of `node` owes: every
 * matching-filter record on the node itself, then subtree records up the
 * ancestor chain (wineserver touch_key/check_notify). THE single authority —
 * every mutation site calls this, none signals an event itself. */
void CmpNotifyChange(PCMP_KEY_NODE node, ULONG change);

/* CmpKeyType.closeProcedure: the arming open's last handle closed — fire the
 * body's accumulated events and free its record (wineserver
 * key_close_handle). */
void CmpCloseKeyBody(PVOID bodyPointer);

/* --- hive.c ----------------------------------------------------------------- */

/* Load the hive file into the tree under CmpRootNode (empty tree on a
 * missing/corrupt file), and save the whole tree to the hive file. Save is
 * serialized by an internal mutex and durable on return (immediate
 * writeback, Art. 3); it is a no-op before CmpSetHiveReady (skeleton
 * building during CmInitialize must not trigger writes). */
void CmpInitializeHiveLock(void);
void CmpSetHiveReady(void);
void CmpLoadHive(void);

/* Rewrite the whole log from a fresh snapshot (temp file + rename). The only
 * whole-file writer: boot-time compaction, and the two syscalls whose subtree
 * drop the log's leaf-only DELETE_KEY cannot express (NtUnloadKey on a
 * non-volatile target, NtRestoreKey). */
void CmpRewriteHive(void);

/* Compact once, unconditionally, from CmInitialize -- after the replay and
 * after every seed, immediately before CmpSetHiveReady. */
void CmpCompactHive(void);

/* Append one record for one mutation. No-ops before CmpSetHiveReady. */
void CmpLogCreateKey(const CMP_KEY_NODE *node);
void CmpLogSetValue(const CMP_KEY_NODE *node, const CMP_VALUE *value);
void CmpLogTouchKey(const CMP_KEY_NODE *node);
void CmpLogDeleteValue(const CMP_KEY_NODE *node, const UNICODE_STRING *valueName);

/* Delete and rename move the key before the log is written, so they log a
 * path captured beforehand. A failed capture means SKIP the record rather
 * than log a wrong path. */
BOOLEAN CmpCaptureLogPath(const CMP_KEY_NODE *node, UNICODE_STRING *out);
void CmpReleaseLogPath(UNICODE_STRING *path);
void CmpLogDeleteKey(const UNICODE_STRING *capturedPath, LARGE_INTEGER stamp);
void CmpLogRenameKey(const UNICODE_STRING *capturedPath, const UNICODE_STRING *newName,
                     LARGE_INTEGER stamp);

/* Remove one named value / rename a node in place. Exported because the hive
 * log's replay applies the same two edits the syscalls do, through the same
 * code (Art. 11). */
BOOLEAN CmpRemoveValue(PCMP_KEY_NODE node, const UNICODE_STRING *name);
BOOLEAN CmpRenameNode(PCMP_KEY_NODE node, const UNICODE_STRING *newName);

/* CUI-7 subtree forms of the same engine (one serializer, one parser —
 * Art. 11): a complete PHV2 image of `top` (name stored empty, caller frees
 * *bufferOut), and the inverse — parse a whole image into `top`, unwinding
 * everything on malformation with STATUS_NOT_REGISTRY_FILE (`top` itself
 * stays, as the oracle's failed load leaves its destination). */
NTSTATUS CmpSerializeSubtree(const CMP_KEY_NODE *top, UCHAR **bufferOut, ULONG *totalOut);
NTSTATUS CmpParseSubtreeInto(PCMP_KEY_NODE top, const UCHAR *buffer, ULONGLONG length);

#endif /* PROSKRNL_KERNEL_CM_CM_H */
