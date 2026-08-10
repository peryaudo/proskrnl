/*
 * sem_mm/map_image_machine.c — MemExtendedParameterImageMachine bounds the
 * MACHINE of the image a view may be created over.
 *
 * docs/21 W5's tail: `ntdll:virtual:2039` is the last of the three singletons
 * in that pair, and it is the accepted-and-dropped-input shape a sixth time.
 * MiCaptureExtendedParams captured the word into MI_EXTENDED_PARAMS.machine
 * and nothing ever read it, so a request naming IMAGE_FILE_MACHINE_R3000 for
 * an x86-64 DLL mapped it happily and answered STATUS_SUCCESS.
 *
 * The rule is one line in the pinned oracle (third_party/wine
 * dlls/ntdll/unix/virtual.c, map_image_into_view):
 *
 *     if (machine && machine != nt->FileHeader.Machine)
 *     {
 *         status = STATUS_NOT_SUPPORTED;
 *         goto done;
 *     }
 *
 * Five things around it are not guessable from the parameter's name, and each
 * is a way an implementation reaching for the obvious guard answers wrongly:
 *
 *   - ZERO is "no constraint", not "the machine must be zero". The winetest's
 *     own probe (virtual.c:2016) maps with ULong = 0 and expects a success,
 *     and only then decides the parameter is supported at all;
 *   - the word is honoured for an IMAGE section and IGNORED for a DATA one.
 *     The oracle's `machine` reaches map_image_into_view and nothing else —
 *     virtual_map_section's data arm never looks at it — so a guard written
 *     one level up, in the shared parameter parser, refuses a data mapping
 *     the oracle admits. Exactly the position argument sem_mm/map_ex.c makes
 *     for MEM_EXTENDED_PARAMETER_EC_CODE, with the arms the other way round;
 *   - PLACEMENT is decided first. virtual_map_image runs map_image_view
 *     (which places the view) and only THEN map_image_into_view, whose
 *     machine check is its last act before the relocation — so a view that
 *     cannot be placed under the requested limits reports the placement
 *     failure and never reaches the comparison. A wrong machine and an
 *     impossible ceiling together answer the ceiling's status, not
 *     STATUS_NOT_SUPPORTED;
 *   - the parameter ladder is decided before either. A duplicated
 *     ImageMachine entry is STATUS_INVALID_PARAMETER whatever the values are;
 *   - and it holds for a REMOTE target too. Every call in the winetest block
 *     this closes maps into a child process (virtual.c:1796's
 *     create_target_process), and on the oracle that word rides an APC to the
 *     target (`call.map_view_ex.machine = machine`) rather than being applied
 *     by the caller — a different transport for the same rule, so the pin
 *     measures both arms rather than assuming they agree.
 *
 * Oracle-first (G5): every case here is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

NTSYSAPI NTSTATUS NTAPI NtMapViewOfSectionEx(HANDLE, HANDLE, PVOID *, const LARGE_INTEGER *,
                                             SIZE_T *, ULONG, ULONG, PVOID, ULONG);

/* Local MEM_EXTENDED_PARAMETER mirror (as sem_mm/map_ex.c and alloc_ex.c:
 * mingw's headers do not carry it, and the bitfield's low 8 bits are the
 * Type — wine/include/winnt.h MEM_EXTENDED_PARAMETER). */
typedef struct
{
    ULONGLONG type_bits;
    union
    {
        ULONGLONG u64;
        PVOID pointer;
    } u;
} mm_ext_param;

typedef struct
{
    PVOID lowest;
    PVOID highest;
    SIZE_T alignment;
} mm_addr_req;

/* MEM_EXTENDED_PARAMETER_TYPE values (wine/include/winnt.h). */
#define EXT_ADDRESS_REQUIREMENTS 1
#define EXT_IMAGE_MACHINE        6

/* wine/include/winnt.h. R3000 is what the winetest names for "a machine this
 * host is not"; AMD64 is the machine every image on this system declares. */
#define MACHINE_R3000 0x0162
#define MACHINE_R4000 0x0166
#define MACHINE_AMD64 0x8664

/* SECTION_IMAGE_INFORMATION, snake_case, layout as wine/include/winternl.h
 * (x64) — the same local mirror sem_mm/image_section.c carries, for the same
 * reason. Only `machine` is read here. */
typedef struct
{
    PVOID transfer_address;
    ULONG zero_bits;
    SIZE_T maximum_stack_size;
    SIZE_T committed_stack_size;
    ULONG subsystem_type;
    USHORT minor_subsystem_version;
    USHORT major_subsystem_version;
    USHORT major_operating_system_version;
    USHORT minor_operating_system_version;
    USHORT image_characteristics;
    USHORT dll_characteristics;
    USHORT machine;
    BOOLEAN image_contains_code;
    UCHAR image_flags;
    ULONG loader_flags;
    ULONG image_file_size;
    ULONG checksum;
} mm_section_image_info;

/* An image view of a DLL already loaded in this process lands away from its
 * preferred base, so the SUCCESS cases answer STATUS_IMAGE_NOT_AT_BASE. Both
 * are successes and the winetest accepts either (virtual.c:2019). */
static int mapped_ok(NTSTATUS status)
{
    return status == STATUS_SUCCESS || status == (NTSTATUS)STATUS_IMAGE_NOT_AT_BASE;
}

static NTSTATUS map_with_machine(HANDLE section, HANDLE process, ULONG machine, ULONG count,
                                 PVOID *viewOut)
{
    mm_ext_param param[2];
    SIZE_T viewSize = 0;
    NTSTATUS status;

    memset(param, 0, sizeof(param));
    param[0].type_bits = EXT_IMAGE_MACHINE;
    param[0].u.u64 = machine;
    param[1].type_bits = EXT_IMAGE_MACHINE;
    param[1].u.u64 = MACHINE_R4000;

    *viewOut = NULL;
    status = NtMapViewOfSectionEx(section, process, viewOut, NULL, &viewSize, 0, PAGE_READONLY,
                                  param, count);
    if (!mapped_ok(status))
        *viewOut = NULL;
    return status;
}

/* Local wide-string helper: the harness is -nostdlib and links only
 * ntdll/kernel32/kernelbase, so no CRT wcs* (as sem_ps/virtual_memory.c). */
static int wstr_contains(const WCHAR *haystack, const WCHAR *needle)
{
    size_t nlen = 0;
    while (needle[nlen])
        nlen++;
    for (; *haystack; haystack++)
    {
        size_t i = 0;
        while (i < nlen && haystack[i] == needle[i])
            i++;
        if (i == nlen)
            return 1;
    }
    return 0;
}

/* The winetest maps into a CHILD, not into itself. Re-exec ourselves as an
 * idle target and repeat the two decisive cases through its handle: on the
 * oracle the machine word rides an APC into that process, so this is the same
 * rule over a different transport. */
static void test_remote_target(HANDLE section, USHORT machine)
{
    WCHAR self[512], cmdline[600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    const WCHAR *tail = L" --mim-child";
    NTSTATUS status;
    PVOID view;
    int n = 0, i;

    ok(GetModuleFileNameW(NULL, self, 512) != 0, "GetModuleFileNameW");
    cmdline[n++] = L'"';
    for (i = 0; self[i] && n < 560; i++)
        cmdline[n++] = self[i];
    cmdline[n++] = L'"';
    for (i = 0; tail[i]; i++)
        cmdline[n++] = tail[i];
    cmdline[n] = 0;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    ok(CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi),
       "CreateProcessW child");
    if (!pi.hProcess)
        return;

    status = map_with_machine(section, pi.hProcess, 0, 1, &view);
    ok(mapped_ok(status), "remote machine 0 -> %08lx", (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(pi.hProcess, view);

    status = map_with_machine(section, pi.hProcess, MACHINE_R3000, 1, &view);
    ok(status == (NTSTATUS)STATUS_NOT_SUPPORTED, "remote machine R3000 -> %08lx",
       (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(pi.hProcess, view);

    status = map_with_machine(section, pi.hProcess, machine, 1, &view);
    ok(mapped_ok(status), "remote machine AMD64 -> %08lx", (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(pi.hProcess, view);

    WaitForSingleObject(pi.hProcess, 10000);
    NtClose(pi.hProcess);
    NtClose(pi.hThread);
}

/* A DATA section takes the same word and ignores it. The guard cannot live in
 * MiCaptureExtendedParams / get_extended_params, which both arms share. */
static void test_data_section_ignores_it(void)
{
    HANDLE section = NULL;
    LARGE_INTEGER sectionSize;
    NTSTATUS status;
    PVOID view;

    sectionSize.QuadPart = 0x10000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create data section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    status = map_with_machine(section, NtCurrentProcess(), MACHINE_R3000, 1, &view);
    ok(status == STATUS_SUCCESS, "data section + R3000 -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    NtClose(section);
}

START_TEST(map_image_machine)
{
    char path[MAX_PATH];
    HANDLE file, section = NULL;
    mm_section_image_info info;
    mm_ext_param param[2];
    mm_addr_req req;
    SIZE_T retlen = 0, viewSize = 0, imageSize = 0;
    NTSTATUS status;
    PVOID view;

    if (wstr_contains(GetCommandLineW(), L"--mim-child"))
    {
        /* The idle target test_remote_target maps into. Bounded, and the
         * parent joins us. */
        Sleep(3000);
        ExitProcess(0);
    }

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);
    if (file == INVALID_HANDLE_VALUE)
        return;

    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);
    CloseHandle(file);
    if (!NT_SUCCESS(status))
        return;

    /* The pin must not be satisfied by a hardwired AMD64: assert the image
     * really declares it before concluding anything from a machine that
     * matches (docs/21 W5, "the pin had to measure the RULE"). */
    memset(&info, 0, sizeof(info));
    status = NtQuerySection(section, SECTION_IMAGE_INFO_CLASS, &info, sizeof(info), &retlen);
    ok(status == STATUS_SUCCESS, "query image info -> %08lx", (unsigned long)status);
    ok(info.machine == MACHINE_AMD64, "image machine %04x", (unsigned)info.machine);

    /* --- a plain map, to learn the view's extent for the ordering case ------ */
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READONLY, NULL, 0);
    ok(mapped_ok(status), "plain image map -> %08lx", (unsigned long)status);
    if (!mapped_ok(status))
    {
        NtClose(section);
        return;
    }
    imageSize = viewSize;
    ok(imageSize >= 0x20000, "image size %llx", (unsigned long long)imageSize);
    ntapi_printf("map_image_machine: image machine %04x size %llx at %p\n", (unsigned)info.machine,
                 (unsigned long long)imageSize, view);
    NtUnmapViewOfSection(NtCurrentProcess(), view);

    /* --- ZERO is "no constraint" -------------------------------------------- */
    status = map_with_machine(section, NtCurrentProcess(), 0, 1, &view);
    ok(mapped_ok(status), "machine 0 -> %08lx", (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    /* --- the image's OWN machine is accepted -------------------------------- */
    status = map_with_machine(section, NtCurrentProcess(), info.machine, 1, &view);
    ok(mapped_ok(status), "machine AMD64 -> %08lx", (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    /* --- any OTHER machine is STATUS_NOT_SUPPORTED --------------------------- */
    status = map_with_machine(section, NtCurrentProcess(), MACHINE_R3000, 1, &view);
    ok(status == (NTSTATUS)STATUS_NOT_SUPPORTED, "machine R3000 -> %08lx", (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    /* --- the parameter ladder is decided first ------------------------------
     * Two ImageMachine entries refuse on the duplicate whatever they name,
     * including when the FIRST of them would have been accepted. */
    status = map_with_machine(section, NtCurrentProcess(), info.machine, 2, &view);
    ok(status == STATUS_INVALID_PARAMETER, "duplicate ImageMachine -> %08lx",
       (unsigned long)status);
    if (view)
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    /* --- placement is decided before the machine ----------------------------
     * A ceiling that cannot hold the image, together with a machine that
     * cannot be served: map_image_view places the view before
     * map_image_into_view looks at the machine, so the PLACEMENT failure is
     * what is reported. An implementation that guards the machine on the way
     * in answers STATUS_NOT_SUPPORTED here and passes every case above.
     *
     * The ceiling is DERIVED from the image's own measured extent rather than
     * written down: the same ntdll.dll is 0x41a000 on the oracle and 0xba000
     * on proskrnl, so any hard-coded number would have measured one runner
     * and skipped the block on the other. The floor it is measured from is
     * the image arm's own — map_image_view raises limit_low to
     * address_space_start (0x10000, the 64K allocation granularity) before it
     * searches, so a lower base is not reachable anyway. */
    memset(param, 0, sizeof(param));
    memset(&req, 0, sizeof(req));
    req.highest = (PVOID)(ULONG_PTR)(0x10000 + ((imageSize / 2) & ~(SIZE_T)0xfff) - 1);
    param[0].type_bits = EXT_ADDRESS_REQUIREMENTS;
    param[0].u.pointer = &req;
    param[1].type_bits = EXT_IMAGE_MACHINE;
    param[1].u.u64 = MACHINE_R3000;
    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSectionEx(section, NtCurrentProcess(), &view, NULL, &viewSize, 0,
                                  PAGE_READONLY, param, 2);
    ntapi_printf("map_image_machine: ceiling %p for a %llx image\n", req.highest,
                 (unsigned long long)imageSize);
    ok(status == STATUS_NO_MEMORY, "unplaceable + R3000 -> %08lx", (unsigned long)status);
    if (mapped_ok(status))
        NtUnmapViewOfSection(NtCurrentProcess(), view);

    test_remote_target(section, info.machine);

    NtClose(section);

    test_data_section_ignores_it();
    /* --- a CROSS-MACHINE image: the success-class warning ---------------
     * Mapping a 32-bit image into a 64-bit process is not an error — the
     * view IS created — but the caller is told the machine does not match
     * so it can decline to run the code. STATUS_IMAGE_MACHINE_TYPE_MISMATCH
     * is success-class (0x4...), which is exactly why a kernel that returns
     * plain STATUS_SUCCESS looks correct to every NT_SUCCESS() check and is
     * still wrong; ntdll:wow64's test_image_mappings is the caller that
     * notices. Needs the syswow64 payload, so it is skipped where there is
     * none. */
    GetWindowsDirectoryA(path, sizeof(path));
    strcat(path, "\\syswow64\\version.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    if (file == INVALID_HANDLE_VALUE)
    {
        skip("no syswow64 payload to map");
        return;
    }
    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create i386 image section -> %08lx", (unsigned long)status);
    CloseHandle(file);
    if (!NT_SUCCESS(status))
        return;

    memset(&info, 0, sizeof(info));
    status = NtQuerySection(section, SECTION_IMAGE_INFO_CLASS, &info, sizeof(info), &retlen);
    ok(status == STATUS_SUCCESS, "query i386 image info -> %08lx", (unsigned long)status);
    ok(info.machine == 0x014c, "syswow64 image machine %x is not I386", info.machine);

    view = NULL;
    viewSize = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &view, 0, 0, NULL, &viewSize, 1, 0,
                                PAGE_READONLY);
    ok(status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH, "map i386 image -> %08lx",
       (unsigned long)status);
    ok(view != NULL, "the view was not created despite the success-class status");
    if (view != NULL)
        NtUnmapViewOfSection(NtCurrentProcess(), view);
    NtClose(section);
}
