/*
 * sem_ps/sys_handles.c — SystemHandleInformation and
 * SystemModuleInformation (CUI-6).
 *
 * The machine-wide handle table snapshot and the kernel module list.
 * Oracle behaviour pinned from the pinned tree (dlls/ntdll/unix/system.c;
 * server/handle.c enum_handles): a buffer below the header refuses; a
 * successful snapshot carries Count entries — a handle we own appears
 * with our pid, its (USHORT-truncated) handle value, its granted access
 * and its OBJ_INHERIT flag, with ObjectPointer zero-filled. The module
 * list refuses a header-only buffer and its FIRST entry is
 * \SystemRoot\system32\ntoskrnl.exe with NameOffset at the basename,
 * LoadOrderIndex 0 and LoadCount 1 — the invariant subset; the oracle
 * pads the list with two fabricated driver entries and fake bases, which
 * are NOT pinned (proskrnl reports its one real module, docs/03).
 */
#include "util.h"

#define PS_SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)
#define PS_SystemHandleInformation ((SYSTEM_INFORMATION_CLASS)16)

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtSetInformationObject(HANDLE, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
#define OB_HANDLE_FLAG_INFO 4 /* ObjectHandleFlagInformation (sem_ob/handle_flags) */

/* x64 layouts as wine/include/winternl.h (snake_case for local shapes). */
typedef struct
{
    ULONG owner_pid;
    BYTE object_type;
    BYTE handle_flags;
    USHORT handle_value;
    PVOID object_pointer;
    ULONG access_mask;
} ps_handle_entry;

typedef struct
{
    ULONG count;
    ps_handle_entry handle[1];
} ps_handle_info;

typedef struct
{
    PVOID section;
    PVOID mapped_base;
    PVOID image_base;
    ULONG image_size;
    ULONG flags;
    WORD load_order_index;
    WORD init_order_index;
    WORD load_count;
    WORD name_offset;
    BYTE name[256];
} ps_module_entry;

typedef struct
{
    ULONG modules_count;
    ps_module_entry modules[1];
} ps_modules;

static char handle_buffer[512 * 1024];
static char module_buffer[8 * 1024];

START_TEST(sys_handles)
{
    NTSTATUS status;
    ULONG retlen;

    /* --- SystemHandleInformation ------------------------------------------ */
    status = NtQuerySystemInformation(PS_SystemHandleInformation, handle_buffer, 4, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short handle snapshot -> %08lx",
       (unsigned long)status);

    HANDLE event = NULL;
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    {
        struct
        {
            BOOLEAN inherit;
            BOOLEAN protect;
        } flags = {TRUE, FALSE};
        status = NtSetInformationObject(event, OB_HANDLE_FLAG_INFO, &flags, sizeof(flags));
        ok(status == STATUS_SUCCESS, "mark inheritable -> %08lx", (unsigned long)status);
    }

    retlen = 0;
    status = NtQuerySystemInformation(PS_SystemHandleInformation, handle_buffer,
                                      sizeof(handle_buffer), &retlen);
    ok(status == STATUS_SUCCESS, "handle snapshot -> %08lx", (unsigned long)status);
    ps_handle_info *info = (ps_handle_info *)handle_buffer;
    ok(info->count > 0, "snapshot has entries");
    ok(retlen >= sizeof(ULONG) + info->count * sizeof(ps_handle_entry) - sizeof(ps_handle_entry),
       "snapshot length consistent (%lu for %lu entries)", (unsigned long)retlen,
       (unsigned long)info->count);

    ULONG pid = GetCurrentProcessId();
    USHORT wanted = (USHORT)(ULONG_PTR)event;
    int found = 0;
    for (ULONG i = 0; i < info->count; i++)
    {
        ps_handle_entry *entry = &info->handle[i];
        if (entry->owner_pid == pid && entry->handle_value == wanted)
        {
            found = 1;
            ok(entry->access_mask == EVENT_ALL_ACCESS, "event granted access %08lx",
               (unsigned long)entry->access_mask);
            ok((entry->handle_flags & 2) != 0, "inherit flag visible (%02x)",
               entry->handle_flags); /* OBJ_INHERIT, wine/include/winternl.h */
            ok(entry->object_pointer == NULL, "object pointer zero-filled");
        }
    }
    ok(found, "our event handle appears in the snapshot");
    NtClose(event);

    /* --- SystemModuleInformation ------------------------------------------- */
    status = NtQuerySystemInformation(PS_SystemModuleInformation, module_buffer, 8, &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short module list -> %08lx", (unsigned long)status);

    memset(module_buffer, 0, sizeof(module_buffer));
    status = NtQuerySystemInformation(PS_SystemModuleInformation, module_buffer,
                                      sizeof(module_buffer), &retlen);
    ok(status == STATUS_SUCCESS, "module list -> %08lx", (unsigned long)status);
    ps_modules *modules = (ps_modules *)module_buffer;
    ok(modules->modules_count >= 1, "module count %lu", (unsigned long)modules->modules_count);
    {
        static const char kernelName[] = "\\SystemRoot\\system32\\ntoskrnl.exe";
        ps_module_entry *first = &modules->modules[0];
        ok(strcmp((const char *)first->name, kernelName) == 0, "first module '%s'", first->name);
        ok(first->name_offset == sizeof(kernelName) - sizeof("ntoskrnl.exe"),
           "name offset %u points at the basename", first->name_offset);
        ok(strcmp((const char *)first->name + first->name_offset, "ntoskrnl.exe") == 0,
           "basename '%s'", first->name + first->name_offset);
        ok(first->load_order_index == 0, "load order %u", first->load_order_index);
        ok(first->load_count == 1, "load count %u", first->load_count);
        ok(first->image_size > 0, "image size %lu", (unsigned long)first->image_size);
    }
}
