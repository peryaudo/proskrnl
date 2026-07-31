/* kernel/ob/ob.h — the Ob department: objects, handles, namespace (M3).
 *
 * The forced part is the concept device (docs/05): every kernel object is a
 * refcounted body reachable through handles and through the \-rooted
 * namespace, created/opened via OBJECT_ATTRIBUTES. The implementation is
 * deliberately the simplest thing with those semantics (Art. 3): one growable
 * handle-entry array, directories as plain linked lists, no security beyond
 * the granted-access mask each handle carries.
 *
 * Concurrency: Ob state is touched only from thread context — never from an
 * interrupt — so under Art. 3 (uniprocessor, no kernel preemption) plain code
 * is atomic between blocking points and needs no lock at all. Only the
 * dispatcher state inside object BODIES (signalState, wait lists) is
 * interrupt-visible, and the Ke entry points take the dispatcher lock for it.
 *
 * Exported Ob* names/signatures follow Wine (include/ddk/wdm.h); everything
 * else is Obp-internal (docs/15).
 */
#ifndef PROSKRNL_KERNEL_OB_OB_H
#define PROSKRNL_KERNEL_OB_OB_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntobapi.h"
#include "kernel/lib/list.h"

/* NOLINTBEGIN(readability-identifier-naming) — NT enumerators/members keep NT
 * casing (transcribed verbatim from third_party/wine/include/ddk/wdm.h). */
typedef enum
{
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef struct
{
    ULONG HandleAttributes;
    ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;
/* NOLINTEND(readability-identifier-naming) */

/* --- The type system ------------------------------------------------------ */

typedef struct OBJECT_TYPE
{
    const char *name;                    /* for panic dumps and asserts */
    ACCESS_MASK validAccess;             /* the type's *_ALL_ACCESS mask */
    BOOLEAN waitable;                    /* body begins with a DISPATCHER_HEADER */
    void (*deleteProcedure)(PVOID body); /* last ref dropped; may be 0 */
    void (*closeProcedure)(PVOID body);  /* LAST handle closed (M6: Io cleanup —
                                          * share release, delete-on-close);
                                          * NT's CloseProcedure concept. May be 0. */
    /* Optional NT GENERIC_MAPPING (all four set, or all zero). Zero keeps
     * the documented docs/03 over-grant (a generic wish = validAccess);
     * a type whose generic split is OBSERVABLE (keyed events: GENERIC_READ
     * waits, GENERIC_WRITE wakes — ntdll:sync) carries the real mapping. */
    ACCESS_MASK genericRead;
    ACCESS_MASK genericWrite;
    ACCESS_MASK genericExecute;
    ACCESS_MASK genericAll;
} OBJECT_TYPE, *POBJECT_TYPE;

extern OBJECT_TYPE ObpDirectoryType;
extern OBJECT_TYPE ObpSymbolicLinkType;
extern OBJECT_TYPE ObpEventType;
extern OBJECT_TYPE ObpMutantType;
extern OBJECT_TYPE ObpSemaphoreType;

/* --- The object header ---------------------------------------------------- */

/* Every object is header + body in one pool block; APIs traffic in body
 * pointers (as NT does). pointerCount counts refs (each open handle holds
 * one, a namespace name holds one); handleCount counts open handles so the
 * last close can retire a temporary object's name. */
typedef struct OBJECT_HEADER
{
    LONG pointerCount;
    LONG handleCount;
    POBJECT_TYPE type;
    BOOLEAN permanent;     /* named: never unlinked on last handle close */
    PVOID parentDirectory; /* directory BODY holding our name; 0 = unnamed */
    UNICODE_STRING name;   /* pool copy owned by the header */
    LIST_ENTRY directoryEntry;
    /* CUI-2: the stored security descriptor (a pooled SEP blob, se.h shape;
     * 0 = none — the common case). Ob owns the storage (freed with the
     * object); kernel/se/secobj.c owns the interpretation. */
    PVOID securityDescriptor;
    PVOID sePad; /* keep bodies 16-aligned (assert below) */
} OBJECT_HEADER, *POBJECT_HEADER;

_Static_assert(sizeof(OBJECT_HEADER) % 16 == 0, "object bodies must stay 16-aligned");

static inline POBJECT_HEADER ObpGetHeader(PVOID body)
{
    return (POBJECT_HEADER)body - 1;
}

static inline PVOID ObpGetBody(POBJECT_HEADER header)
{
    return header + 1;
}

/* --- object.c ------------------------------------------------------------- */

/* Set up the object manager and the namespace roots (\, \Device, \??,
 * \BaseNamedObjects). Needs the pool; call before the first Nt*. */
void ObpInitializeObjectManager(void);

/* Allocate an unnamed, unreferenced-by-anyone-else object: pointerCount = 1
 * (the creator's reference), handleCount = 0. Returns the zeroed body. */
NTSTATUS ObpAllocateObject(POBJECT_TYPE type, ULONG bodySize, PVOID *body);

/* Reference / dereference by body pointer (signatures per Wine's wdm.h). */
void ObfReferenceObject(PVOID body);
void ObDereferenceObject(PVOID body);

/* Resolve a handle to a referenced body. type == 0 accepts any type; the
 * entry's granted access must cover desiredAccess. Caller dereferences. */
NTSTATUS ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK desiredAccess, POBJECT_TYPE type,
                                   KPROCESSOR_MODE accessMode, PVOID *body,
                                   POBJECT_HANDLE_INFORMATION handleInformation);

/* --- handle.c ------------------------------------------------------------- */

/* One handle table (M4: per process, embedded in EPROCESS; handle values
 * resolve against the CURRENT thread's process). The entry array layout is
 * private to handle.c. */
typedef struct
{
    PVOID entries; /* OBP_HANDLE_ENTRY[capacity], private to handle.c */
    ULONG capacity;
    ULONG inUse;
} OBP_HANDLE_TABLE, *POBP_HANDLE_TABLE;

void ObpInitializeHandleTable(POBP_HANDLE_TABLE table);
/* Close every live entry (process termination, in thread context). */
void ObpCloseAllHandles(POBP_HANDLE_TABLE table);
/* Free the (already emptied) table storage. */
void ObpDeleteHandleTable(POBP_HANDLE_TABLE table);

/* Create a handle to `body` in the current process's table: bumps
 * handleCount and takes the handle's pointer reference. attributes keeps
 * the OBJ_* bits worth remembering. handleOut is probed for a UserMode
 * caller (every create/open/duplicate path funnels through here). */
NTSTATUS ObpCreateHandle(PVOID body, ACCESS_MASK grantedAccess, ULONG attributes,
                         PHANDLE handleOut);

/* Kernel-internal variant against an EXPLICIT table (M9: seeding a new
 * process's console handles from the creator's context). No user probe. */
NTSTATUS ObpCreateHandleInTable(POBP_HANDLE_TABLE table, PVOID body, ACCESS_MASK grantedAccess,
                                ULONG attributes, PHANDLE handleOut);

/* M10: populate a new process's (empty) table as an inheritance copy of
 * `parent`, mirroring wineserver's copy_handle_table (third_party/wine
 * server/handle.c): with handleList == 0, every OBJ_INHERIT entry is copied
 * AT THE SAME INDEX (handle values are index-derived, so values are
 * preserved); with a list, only the listed handles plus the three std
 * handles — each still requiring OBJ_INHERIT — are copied, same-index.
 * Invalid/non-inheritable handles are skipped silently, as the server
 * skips them. */
NTSTATUS ObpInheritHandles(POBP_HANDLE_TABLE parent, POBP_HANDLE_TABLE child,
                           const HANDLE *handleList, ULONG handleCount, const HANDLE stdHandles[3]);

/* M10: kernel-internal cross-table duplication (the console/std fixups at
 * process creation — wineserver's duplicate_handle(parent, ..., process)
 * sites in server/process.c). Same access; attributes copied only when
 * sameAttributes (DUPLICATE_SAME_ATTRIBUTES). Fails on an invalid source
 * handle — the caller decides what that means. */
NTSTATUS ObpDuplicateIntoTable(POBP_HANDLE_TABLE parent, HANDLE source, POBP_HANDLE_TABLE child,
                               BOOLEAN sameAttributes, PHANDLE handleOut);

/* Consistency-sweep helpers (kernel/init/verify.c orchestrates; dispatcher
 * lock held). ObpVerifyHandleTable asserts one table's internal invariants;
 * ObpHandleTableObjectAt exposes slot occupancy (body or 0) so the sweep can
 * recount handleCount across every table without seeing the entry layout. */
void ObpVerifyHandleTable(POBP_HANDLE_TABLE table);
PVOID ObpHandleTableObjectAt(POBP_HANDLE_TABLE table, ULONG index);

/* Map a caller's desired access onto a type: generic/maximum-allowed bits
 * grant the type's full mask (Se is always-allow, docs/05); specific bits
 * pass through filtered to the type's valid mask. */
ACCESS_MASK ObpMapDesiredAccess(POBJECT_TYPE type, ACCESS_MASK desiredAccess);

/* --- namespace.c ---------------------------------------------------------- */

/* Create-with-name engine shared by every NtCreate*. On STATUS_SUCCESS the
 * caller MUST initialize *body before blocking (cooperative scheduling makes
 * that window private). OBJ_OPENIF turns a name collision into an open of
 * the existing object: *body is the existing object and the status is
 * STATUS_OBJECT_NAME_EXISTS (a success code); the new-object initialization
 * must then be skipped. Unnamed creation is attr == 0 / no ObjectName. */
NTSTATUS ObpCreateObjectWithHandle(POBJECT_TYPE type, ULONG bodySize,
                                   const OBJECT_ATTRIBUTES *attributes, ACCESS_MASK desiredAccess,
                                   PVOID *body, PHANDLE handleOut);

/* Open-by-name engine shared by every NtOpen*. */
NTSTATUS ObpOpenObjectByName(POBJECT_TYPE type, const OBJECT_ATTRIBUTES *attributes,
                             ACCESS_MASK desiredAccess, PHANDLE handleOut);

/* Retire an object's name: unlink from its directory, drop the name's and
 * the directory's references. Idempotent via parentDirectory == 0. */
void ObpUnlinkObjectName(POBJECT_HEADER header);

/* Consistency sweep (kernel/init/verify.c; dispatcher lock held): walk the
 * whole \-rooted tree asserting name/parent/reference agreement for every
 * named object. */
void ObpVerifyNamespace(void);

/* Resolve a path that may cross into a parse object (M6: an Io Device —
 * NT's ParseProcedure concept). On success *parseObject is the referenced
 * object of `parseType` and *remainingName is whatever the walk did not
 * consume (empty when the path named the object itself); it may point into
 * *reparseBuffer, which the caller frees AFTER copying. A path resolving to
 * an object of any other type is STATUS_OBJECT_TYPE_MISMATCH. */
NTSTATUS ObpLookupParseObject(const OBJECT_ATTRIBUTES *attributes, POBJECT_TYPE parseType,
                              PVOID *parseObject, UNICODE_STRING *remainingName,
                              PWSTR *reparseBuffer);

/* Validate a caller-supplied OBJECT_ATTRIBUTES (the block, its ObjectName,
 * and the name buffer) before any of it is read. The Ob create/open engine
 * calls this itself; Io and Cm must call it too, because they parse
 * attributes->ObjectName into their own namespaces without entering the
 * engine. A NULL block succeeds -- callers distinguish "absent" from
 * "present but nameless" themselves. See kernel/ob/namespace.c. */
NTSTATUS ObProbeObjectAttributes(const OBJECT_ATTRIBUTES *attributes);

#endif /* PROSKRNL_KERNEL_OB_OB_H */
