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

/* Resolve a path that may cross into a parse object (M6: an Io Device —
 * NT's ParseProcedure concept). On success *parseObject is the referenced
 * object of `parseType` and *remainingName is whatever the walk did not
 * consume (empty when the path named the object itself); it may point into
 * *reparseBuffer, which the caller frees AFTER copying. A path resolving to
 * an object of any other type is STATUS_OBJECT_TYPE_MISMATCH. */
NTSTATUS ObpLookupParseObject(const OBJECT_ATTRIBUTES *attributes, POBJECT_TYPE parseType,
                              PVOID *parseObject, UNICODE_STRING *remainingName,
                              PWSTR *reparseBuffer);

#endif /* PROSKRNL_KERNEL_OB_OB_H */
