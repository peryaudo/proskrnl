/*
 * sem_ob/query_directory.c — NtQueryDirectoryObject (CUI-5).
 *
 * kernelbase's volume enumeration is the consumer: QueryDosDeviceW's
 * list-all branch and GetLogicalDrives (dlls/kernelbase/volume.c) loop
 * `while (!NtQueryDirectoryObject(handle, info, sizeof(data), 1, 0, &ctx,
 * &len))` over \DosDevices — so the single-entry protocol (SUCCESS per
 * entry, a non-zero status ending the loop, the kernel owning the context
 * cursor) is exactly what must hold. The contract is the pinned Wine's
 * (dlls/ntdll/unix/sync.c NtQueryDirectoryObject + server/directory.c
 * get_directory_entries): entries carry name + type name as NUL-terminated
 * UNICODE_STRINGs pointing into the caller's own buffer (string pool after
 * the entry array, MaximumLength = Length + 2), a zeroed terminator entry
 * follows the used ones, exhaustion is STATUS_NO_MORE_ENTRIES with
 * *ret_size = sizeof(one entry), a single-entry call whose entry cannot
 * fit is STATUS_BUFFER_TOO_SMALL with the required size hinted, and a
 * multi-entry call that fits only part of the directory returns
 * STATUS_MORE_ENTRIES with the cursor advanced past what fit.
 *
 * Entry ORDER is deliberately not pinned (the two sides walk different
 * structures); the loops collect and match by name.
 */
#include "../ntapi.h"

/* char16_t (2-byte) string literal, as Wine's tests spell it. */
#define W(s) u##s

typedef struct _DIRECTORY_BASIC_INFORMATION
{
    UNICODE_STRING ObjectName;
    UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryObject(HANDLE, DIRECTORY_BASIC_INFORMATION *, ULONG,
                                               BOOLEAN, BOOLEAN, PULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE,
                                      BOOLEAN);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001 /* wine/include/ddk/wdm.h */
#endif
#ifndef DIRECTORY_ALL_ACCESS
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF) /* wine/include/ddk/wdm.h */
#endif

static void init_name(UNICODE_STRING *name, OBJECT_ATTRIBUTES *attr, HANDLE root, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    name->Length = (USHORT)(len * 2);
    name->MaximumLength = (USHORT)(len * 2 + 2);
    name->Buffer = (PWSTR)(void *)p;
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = NULL;
    attr->SecurityQualityOfService = NULL;
}

static int ustr_equals(const UNICODE_STRING *str, const void *wide)
{
    const unsigned short *p = (const unsigned short *)wide;
    unsigned len = 0;
    while (p[len])
        len++;
    return str->Length == len * 2 && memcmp(str->Buffer, p, str->Length) == 0;
}

/* One well-formed entry: strings inside the caller buffer, NUL-terminated,
 * MaximumLength = Length + 2. */
static void check_entry_shape(const DIRECTORY_BASIC_INFORMATION *entry, const void *buffer,
                              ULONG size)
{
    const char *base = (const char *)buffer;
    ok((const char *)entry->ObjectName.Buffer > base &&
           (const char *)entry->ObjectName.Buffer < base + size,
       "name buffer inside caller buffer");
    ok(entry->ObjectName.MaximumLength == entry->ObjectName.Length + sizeof(WCHAR),
       "name MaximumLength %u vs %u", entry->ObjectName.MaximumLength, entry->ObjectName.Length);
    ok(entry->ObjectName.Buffer[entry->ObjectName.Length / sizeof(WCHAR)] == 0,
       "name NUL-terminated");
    ok(entry->ObjectTypeName.MaximumLength == entry->ObjectTypeName.Length + sizeof(WCHAR),
       "type MaximumLength %u vs %u", entry->ObjectTypeName.MaximumLength,
       entry->ObjectTypeName.Length);
    ok(entry->ObjectTypeName.Buffer[entry->ObjectTypeName.Length / sizeof(WCHAR)] == 0,
       "type NUL-terminated");
}

START_TEST(query_directory)
{
    NTSTATUS status;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE dir = NULL, opened = NULL;
    HANDLE events[3] = {NULL, NULL, NULL};
    static const void *const event_names[3] = {W("qd_alpha"), W("qd_beta"), W("qd_gamma")};

    /* A private directory with three named events — deterministic content. */
    init_name(&name, &attr, NULL, W("\\BaseNamedObjects\\prs_query_dir"));
    status = NtCreateDirectoryObject(&dir, DIRECTORY_ALL_ACCESS, &attr);
    ok(status == STATUS_SUCCESS, "create directory -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    for (int i = 0; i < 3; i++)
    {
        init_name(&name, &attr, dir, event_names[i]);
        status = NtCreateEvent(&events[i], EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
        ok(status == STATUS_SUCCESS, "create event %d -> %08lx", i, (unsigned long)status);
    }

    init_name(&name, &attr, NULL, W("\\BaseNamedObjects\\prs_query_dir"));
    status = NtOpenDirectoryObject(&opened, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open for query -> %08lx", (unsigned long)status);

    /* --- the QueryDosDeviceW loop shape: single entries to exhaustion ------ */
    {
        char buffer[1024];
        DIRECTORY_BASIC_INFORMATION *info = (DIRECTORY_BASIC_INFORMATION *)buffer;
        ULONG ctx = 0, len = 0;
        int seen[3] = {0, 0, 0};
        int rounds = 0;
        while (!NtQueryDirectoryObject(opened, info, sizeof(buffer), TRUE, FALSE, &ctx, &len))
        {
            check_entry_shape(info, buffer, sizeof(buffer));
            ok(ustr_equals(&info->ObjectTypeName, W("Event")), "entry type (round %d)", rounds);
            for (int i = 0; i < 3; i++)
            {
                if (ustr_equals(&info->ObjectName, event_names[i]))
                    seen[i]++;
            }
            rounds++;
            if (rounds > 8)
                break; /* runaway guard */
        }
        ok(rounds == 3, "single-entry rounds %d", rounds);
        ok(seen[0] == 1 && seen[1] == 1 && seen[2] == 1, "each entry seen once (%d/%d/%d)", seen[0],
           seen[1], seen[2]);
        ok(ctx == 3, "context after loop %lu", (unsigned long)ctx);

        /* The terminating call: NO_MORE_ENTRIES, ret_size = one entry. */
        len = 0;
        status = NtQueryDirectoryObject(opened, info, sizeof(buffer), TRUE, FALSE, &ctx, &len);
        ok(status == STATUS_NO_MORE_ENTRIES, "exhausted -> %08lx", (unsigned long)status);
        ok(len == sizeof(DIRECTORY_BASIC_INFORMATION), "exhausted ret_size %lu",
           (unsigned long)len);

        /* restart=TRUE rewinds regardless of the cursor. */
        status = NtQueryDirectoryObject(opened, info, sizeof(buffer), TRUE, TRUE, &ctx, &len);
        ok(status == STATUS_SUCCESS, "restart -> %08lx", (unsigned long)status);
        ok(ctx == 1, "restart context %lu", (unsigned long)ctx);
    }

    /* --- one multi-entry sweep --------------------------------------------- */
    {
        char buffer[1024];
        DIRECTORY_BASIC_INFORMATION *info = (DIRECTORY_BASIC_INFORMATION *)buffer;
        ULONG ctx = 0, len = 0;
        status = NtQueryDirectoryObject(opened, info, sizeof(buffer), FALSE, TRUE, &ctx, &len);
        ok(status == STATUS_SUCCESS, "multi-entry -> %08lx", (unsigned long)status);
        ok(ctx == 3, "multi-entry context %lu", (unsigned long)ctx);
        int count = 0;
        for (int i = 0; info[i].ObjectName.Buffer != NULL; i++)
        {
            check_entry_shape(&info[i], buffer, sizeof(buffer));
            count++;
        }
        ok(count == 3, "multi-entry count %d", count);
        ok(info[3].ObjectName.Length == 0 && info[3].ObjectName.Buffer == NULL,
           "terminator entry zeroed");
        ok(len > 4 * sizeof(DIRECTORY_BASIC_INFORMATION), "multi-entry ret_size %lu",
           (unsigned long)len);
    }

    /* --- too-small buffers -------------------------------------------------- */
    {
        char buffer[sizeof(DIRECTORY_BASIC_INFORMATION)];
        DIRECTORY_BASIC_INFORMATION *info = (DIRECTORY_BASIC_INFORMATION *)buffer;
        ULONG ctx = 0, len = 0;
        /* Single entry that cannot fit: BUFFER_TOO_SMALL + a size hint that
         * covers the entry, the terminator, and both NULs. */
        status = NtQueryDirectoryObject(opened, info, sizeof(buffer), TRUE, TRUE, &ctx, &len);
        ok(status == STATUS_BUFFER_TOO_SMALL, "tiny single -> %08lx", (unsigned long)status);
        ok(len >= 2 * sizeof(DIRECTORY_BASIC_INFORMATION) + 2 * sizeof(WCHAR),
           "tiny single ret_size %lu", (unsigned long)len);
        ok(ctx == 0, "tiny single context untouched (%lu)", (unsigned long)ctx);
    }
    {
        /* Multi-entry with room for exactly one entry + terminator + one
         * name/type pair: MORE_ENTRIES with the cursor past what fit. */
        char buffer[2 * sizeof(DIRECTORY_BASIC_INFORMATION) + 24 * sizeof(WCHAR)];
        DIRECTORY_BASIC_INFORMATION *info = (DIRECTORY_BASIC_INFORMATION *)buffer;
        ULONG ctx = 0, len = 0;
        status = NtQueryDirectoryObject(opened, info, sizeof(buffer), FALSE, TRUE, &ctx, &len);
        ok(status == STATUS_MORE_ENTRIES, "partial multi -> %08lx", (unsigned long)status);
        ok(ctx == 1, "partial multi context %lu", (unsigned long)ctx);
        check_entry_shape(&info[0], buffer, sizeof(buffer));
    }

    for (int i = 0; i < 3; i++)
    {
        if (events[i] != NULL)
            NtClose(events[i]);
    }
    if (opened != NULL)
        NtClose(opened);
    NtClose(dir);
    /* The remaining unvalidated ring-3 pointers in the Ob/Ke surface, per the
     * 2026-07 review section 1a. Each must be a status, never a kernel fault. */
    {
        void *const BAD = (void *)(ULONG_PTR)0x10000;
        NTSTATUS bs;
        ULONG ctx = 0, rl = 0;
        BYTE b[128];
        HANDLE h = NULL;

        bs = NtQueryDirectoryObject((HANDLE)NULL, b, sizeof(b), TRUE, TRUE, (PULONG)BAD, &rl);
        ok(bs == STATUS_ACCESS_VIOLATION || bs == STATUS_INVALID_HANDLE,
           "QueryDirectoryObject bad context -> %08lx", (unsigned long)bs);

        bs = NtQueryObject((HANDLE)(LONG_PTR)-1, ObjectTypeInformation, b, sizeof(b),
                           (PULONG)BAD);
        ok(bs == STATUS_ACCESS_VIOLATION, "NtQueryObject bad retlen -> %08lx", (unsigned long)bs);

        bs = NtWaitForSingleObject((HANDLE)(LONG_PTR)-1, FALSE, (PLARGE_INTEGER)BAD);
        ok(bs == STATUS_ACCESS_VIOLATION, "wait bad timeout -> %08lx", (unsigned long)bs);

        (void)ctx;
        (void)h;
    }

    /* --- ObjectNameInformation reports the FULL path ----------------------
     *
     * proskrnl returned the leaf component. A caller that gets "prsk_qd_evt"
     * where NT gives "\BaseNamedObjects\prsk_qd_evt" cannot tell two
     * objects with the same leaf name apart; the oracle walks name->parent
     * to the root. */
    {
        static const void *evt_name = W("\\BaseNamedObjects\\prsk_qd_named");
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE evt = NULL;
        NTSTATUS s;
        BYTE raw[512];
        ULONG used = 0;

        init_name(&name, &attr, NULL, evt_name);
        s = NtCreateEvent(&evt, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
        ok(s == STATUS_SUCCESS, "create named event -> %08lx", (unsigned long)s);
        if (NT_SUCCESS(s))
        {
            memset(raw, 0, sizeof(raw));
            s = NtQueryObject(evt, ObjectNameInformation, raw, sizeof(raw), &used);
            ok(s == STATUS_SUCCESS, "ObjectNameInformation -> %08lx", (unsigned long)s);
            if (NT_SUCCESS(s))
            {
                UNICODE_STRING *reported = (UNICODE_STRING *)raw;
                const WCHAR *want = (const WCHAR *)evt_name;
                unsigned want_units = 0, i, same = 1;
                while (want[want_units])
                    want_units++;
                ok(reported->Length == want_units * sizeof(WCHAR),
                   "ObjectNameInformation Length %u, wanted %u (the full path, not the leaf)",
                   (unsigned)reported->Length, (unsigned)(want_units * sizeof(WCHAR)));
                if (reported->Length == want_units * sizeof(WCHAR))
                {
                    for (i = 0; i < want_units; i++)
                    {
                        WCHAR a = reported->Buffer[i], b2 = want[i];
                        if (a >= 'A' && a <= 'Z')
                            a = (WCHAR)(a - 'A' + 'a');
                        if (b2 >= 'A' && b2 <= 'Z')
                            b2 = (WCHAR)(b2 - 'A' + 'a');
                        if (a != b2)
                            same = 0;
                    }
                    ok(same, "ObjectNameInformation spells the whole path");
                }
            }
            NtClose(evt);
        }
    }
}
