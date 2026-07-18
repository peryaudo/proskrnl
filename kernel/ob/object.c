/* kernel/ob/object.c — object lifetime: allocate, reference, delete (M3).
 *
 * One pool block per object: OBJECT_HEADER followed by the body. The body
 * pointer is the public identity (as in NT); pointerCount keeps the block
 * alive, handleCount decides when a temporary object loses its name. The
 * refcount discipline is stated with ASSERTs throughout — this is the file
 * KASAN and the asserts exist for (docs/05, docs/08).
 */
#include "kernel/ob/ob.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

NTSTATUS ObpAllocateObject(POBJECT_TYPE type, ULONG bodySize, PVOID *body)
{
    ASSERT(type != 0 && bodySize != 0);
    POBJECT_HEADER header = MiAllocatePool(sizeof(OBJECT_HEADER) + bodySize);
    if (header == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* The pool zeroes the block: name/parentDirectory start empty. */
    header->pointerCount = 1; /* the creator's reference */
    header->handleCount = 0;
    header->type = type;
    header->permanent = FALSE;
    InitializeListHead(&header->directoryEntry);
    *body = ObpGetBody(header);
    return STATUS_SUCCESS;
}

void ObfReferenceObject(PVOID body)
{
    POBJECT_HEADER header = ObpGetHeader(body);
    ASSERT(header->pointerCount > 0); /* referencing a dead object */
    header->pointerCount++;
}

void ObDereferenceObject(PVOID body)
{
    POBJECT_HEADER header = ObpGetHeader(body);
    ASSERT(header->pointerCount > 0); /* double dereference */
    header->pointerCount--;
    if (header->pointerCount > 0)
    {
        return;
    }
    /* Last reference: nobody can still reach the object. */
    ASSERT(header->handleCount == 0);
    ASSERT(header->parentDirectory == 0); /* the name holds a reference */
    if (header->type->deleteProcedure != 0)
    {
        header->type->deleteProcedure(body);
    }
    if (header->name.Buffer != 0)
    {
        MiFreePool(header->name.Buffer);
    }
    MiFreePool(header);
}

NTSTATUS NtMakeTemporaryObject(HANDLE handle)
{
    /* Clearing the permanent flag is a delete-class operation: NT requires
     * DELETE access on the handle, so a handle without it is ACCESS_DENIED even
     * though the object is reachable. Matches the pinned third_party/wine
     * (NtMakeTemporaryObject opens with DELETE); docs/09 Art. 6. */
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, DELETE, 0, KernelMode, &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ObpGetHeader(body)->permanent = FALSE;
    ObDereferenceObject(body);
    return STATUS_SUCCESS;
}
