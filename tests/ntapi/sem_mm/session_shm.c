/*
 * sem_mm/session_shm.c — the shared-session mapping pattern (GUI-2, docs/07).
 *
 * Wine's win32u reaches its desktop/queue/window state through a named
 * pagefile-backed section, `\KernelObjects\__wine_session`: one writer maps
 * it read-write, every reader opens it BY NAME and maps a read-only view at
 * a granularity-aligned offset (dlls/win32u/winstation.c,
 * map_shared_session_block). GUI-2 puts the writer in-process, so the whole
 * pattern has to hold inside one process.
 *
 * Pinned here because each half is a separate promise: `\KernelObjects` is a
 * namespace directory that must exist and accept a section (Wine's server
 * creates it permanently, server/directory.c), a name must bind ONE section
 * across create and open, two views of it must be the same memory, and a
 * view taken at a non-zero offset must land on the bytes at that offset.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

static const void *kernel_objects = W("\\KernelObjects");
static const void *section_name = W("\\KernelObjects\\prsk_gui2_session");

/* Two allocation granularities, so a view can start at a non-zero aligned
 * offset and still have a whole granule behind it. */
#define GRANULARITY  0x10000
#define SECTION_SIZE (2 * GRANULARITY)

START_TEST(session_shm)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    LARGE_INTEGER size, offset;
    HANDLE dir, writer, reader;
    NTSTATUS status;
    void *write_view = NULL, *read_view = NULL;
    SIZE_T view_size;

    /* `\KernelObjects` exists as a directory in its own right. */
    init_ustr(&name, kernel_objects);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(&dir, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open \\KernelObjects -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(dir);

    /* The writer: a named pagefile-backed section, mapped read-write. */
    size.QuadPart = SECTION_SIZE;
    init_ustr(&name, section_name);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateSection(&writer, SECTION_ALL_ACCESS, &attr, &size, PAGE_READWRITE, SEC_COMMIT,
                             NULL);
    ok(status == STATUS_SUCCESS, "create section in \\KernelObjects -> %08lx",
       (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(writer, NtCurrentProcess(), &write_view, 0, 0, &offset, &view_size,
                                ViewShare, 0, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "map writer view -> %08lx", (unsigned long)status);
    ok(view_size >= SECTION_SIZE, "writer view %lu < section %u", (unsigned long)view_size,
       SECTION_SIZE);

    /* Stamp both granules so the reader's offset view can be told apart from
     * the offset-zero one. */
    ((volatile unsigned int *)write_view)[0] = 0x5e5510u;
    ((volatile unsigned int *)((char *)write_view + GRANULARITY))[0] = 0xb10c01u;

    /* The reader: same name, opened read-only. */
    status = NtOpenSection(&reader, SECTION_MAP_READ, &attr);
    ok(status == STATUS_SUCCESS, "open section by name -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* A read-only view at offset 0 is the SAME memory: the writer's stores
     * are visible through it, and later stores are too (one section, not a
     * snapshot). */
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(reader, NtCurrentProcess(), &read_view, 0, 0, &offset, &view_size,
                                ViewUnmap, 0, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map reader view -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(((volatile unsigned int *)read_view)[0] == 0x5e5510u, "reader saw %08x, expected %08x",
           ((volatile unsigned int *)read_view)[0], 0x5e5510u);
        ((volatile unsigned int *)write_view)[1] = 0x5eec10cu;
        ok(((volatile unsigned int *)read_view)[1] == 0x5eec10cu,
           "reader missed a later store: %08x", ((volatile unsigned int *)read_view)[1]);
        NtUnmapViewOfSection(NtCurrentProcess(), read_view);
    }

    /* A view at a granularity-aligned non-zero offset starts at that offset's
     * bytes — the way win32u reaches an object deep in the mapping. */
    read_view = NULL;
    view_size = 0;
    offset.QuadPart = GRANULARITY;
    status = NtMapViewOfSection(reader, NtCurrentProcess(), &read_view, 0, 0, &offset, &view_size,
                                ViewUnmap, 0, PAGE_READONLY);
    ok(status == STATUS_SUCCESS, "map reader view at offset -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok(((volatile unsigned int *)read_view)[0] == 0xb10c01u,
           "offset view saw %08x, expected %08x", ((volatile unsigned int *)read_view)[0],
           0xb10c01u);
        ok(view_size >= GRANULARITY, "offset view %lu < remaining %u", (unsigned long)view_size,
           GRANULARITY);
        NtUnmapViewOfSection(NtCurrentProcess(), read_view);
    }

    NtClose(reader);
    NtUnmapViewOfSection(NtCurrentProcess(), write_view);
    NtClose(writer);
}
