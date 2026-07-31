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

/* Depth of `node` counting itself, 0 for the null parent of the root. THE
 * authority for the question. */
ULONG CmpKeyDepth(const CMP_KEY_NODE *node);

/* Returns 0 when the parent is already at CMP_HIVE_MAX_DEPTH, as well as on
 * allocation failure. */
PCMP_KEY_NODE CmpAllocateNode(PCMP_KEY_NODE parent, const UNICODE_STRING *name);

/* Set/replace value `name` on `node` from a kernel-side buffer. */
NTSTATUS CmpSetValue(PCMP_KEY_NODE node, const UNICODE_STRING *name, ULONG type, const void *data,
                     ULONG dataLength);

/* --- hive.c ----------------------------------------------------------------- */

/* Load the hive file into the tree under CmpRootNode (empty tree on a
 * missing/corrupt file), and save the whole tree to the hive file. Save is
 * serialized by an internal mutex and durable on return (immediate
 * writeback, Art. 3); it is a no-op before CmpSetHiveReady (skeleton
 * building during CmInitialize must not trigger writes). */
void CmpInitializeHiveLock(void);
void CmpSetHiveReady(void);
void CmpLoadHive(void);
void CmpSaveHive(void);

#endif /* PROSKRNL_KERNEL_CM_CM_H */
