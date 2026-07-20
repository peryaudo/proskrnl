/*
 * sem_mm/image_section.c — SEC_IMAGE sections over a real PE file (M5,
 * docs/02: "NtCreateSection + NtMapViewOfSection maps a PE image").
 *
 * Distilled from Wine's dlls/ntdll/tests/virtual.c test_NtMapViewOfSection
 * (the ntdll.dll image-mapping ok()s) and server/mapping.c get_image_params.
 * ORACLE-ONLY until M6: creating an image section takes a FILE handle, and
 * proskrnl has no NtCreateFile before the I/O manager lands — the kernel side
 * of image mapping is proven at M5 by tests/kmt/m5_section.c and the PE boot
 * module, against this same behaviour. Green on the oracle first (Art. 5).
 */
#include "util.h"

#include <windows.h>
#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* SECTION_IMAGE_INFORMATION with snake_case fields; layout as
 * wine/include/winternl.h (x64), which mingw's winternl.h omits. */
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

START_TEST(image_section)
{
    NTSTATUS status;
    HANDLE file, section;
    LARGE_INTEGER offset;
    SIZE_T view_size, view2_size, retlen;
    char path[MAX_PATH];
    char *view1, *view2;
    mm_section_image_info info;
    mm_section_basic_info sbi;
    MEMORY_BASIC_INFORMATION mbi;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    int i;
    void *addr;

    GetSystemDirectoryA(path, sizeof(path));
    strcat(path, "\\ntdll.dll");
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    ok(file != INVALID_HANDLE_VALUE, "cannot open %s", path);

    /* --- create + query ----------------------------------------------------- */

    section = NULL;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "create image section -> %08lx", (unsigned long)status);

    retlen = 0;
    status = NtQuerySection(section, SECTION_IMAGE_INFO_CLASS, &info, sizeof(info), &retlen);
    ok(status == STATUS_SUCCESS, "query image info -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(info), "image info retlen %lu", (unsigned long)retlen);
    ok(info.machine == IMAGE_FILE_MACHINE_AMD64, "Machine %04x", info.machine);
    ok(info.image_contains_code, "ImageContainsCode not set");
    ok(info.maximum_stack_size != 0, "MaximumStackSize 0");

    status = NtQuerySection(section, SECTION_BASIC_INFO_CLASS, &sbi, sizeof(sbi), NULL);
    ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
    ok((sbi.attributes & SEC_IMAGE) != 0, "Attributes %08lx lack SEC_IMAGE",
       (unsigned long)sbi.attributes);
    ok((sbi.attributes & SEC_FILE) != 0, "Attributes %08lx lack SEC_FILE",
       (unsigned long)sbi.attributes);

    /* --- map two views ------------------------------------------------------ */

    /* ntdll is already loaded at its preferred base, so a fresh view is
     * relocated (Wine's own test pins exactly this). */
    view1 = NULL;
    view_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view1, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map image -> %08lx",
       (unsigned long)status);
    ok(((ULONG_PTR)view1 & 0xFFFF) == 0, "image view %p not 64K aligned", view1);
    ok(view_size != 0, "image view size 0");

    view2 = NULL;
    view2_size = 0;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (void **)&view2, 0, 0, &offset,
                                &view2_size, ViewShare, 0, PAGE_READONLY);
    ok(status == STATUS_IMAGE_NOT_AT_BASE || status == STATUS_SUCCESS, "map image 2 -> %08lx",
       (unsigned long)status);
    ok(view2 != view1, "second image view at the same address");
    ok(view2_size == view_size, "view sizes differ: %lx vs %lx", (unsigned long)view_size,
       (unsigned long)view2_size);

    /* Both views carry the PE image, headers first. */
    dos = (IMAGE_DOS_HEADER *)view1;
    ok(dos->e_magic == IMAGE_DOS_SIGNATURE, "view1 e_magic %04x", dos->e_magic);
    ok(((IMAGE_DOS_HEADER *)view2)->e_magic == IMAGE_DOS_SIGNATURE, "view2 e_magic %04x",
       ((IMAGE_DOS_HEADER *)view2)->e_magic);
    ok(dos->e_lfanew == ((IMAGE_DOS_HEADER *)view2)->e_lfanew, "views disagree on e_lfanew");

    nt = (IMAGE_NT_HEADERS64 *)(view1 + dos->e_lfanew);
    ok(nt->Signature == IMAGE_NT_SIGNATURE, "NT signature %08lx", (unsigned long)nt->Signature);
    ok(view_size >= nt->OptionalHeader.SizeOfImage, "view %lx smaller than SizeOfImage %lx",
       (unsigned long)view_size, (unsigned long)nt->OptionalHeader.SizeOfImage);
    /* (The mapped header's ImageBase after relocation is deliberately NOT
     * pinned: Wine rebases builtin dlls to a server-assigned shared address
     * rather than the view base, so the field's value is oracle-divergent.) */

    /* --- the view is MEM_IMAGE with per-section protection ------------------ */

    status = NtQueryVirtualMemory(NtCurrentProcess(), view1, MEMORY_BASIC_INFO_CLASS, &mbi,
                                  sizeof(mbi), NULL);
    ok(status == STATUS_SUCCESS, "query image view -> %08lx", (unsigned long)status);
    ok(mbi.Type == MEM_IMAGE, "image Type %lx", (unsigned long)mbi.Type);
    ok(mbi.State == MEM_COMMIT, "image State %lx", (unsigned long)mbi.State);
    ok(mbi.AllocationBase == view1, "image AllocationBase %p", mbi.AllocationBase);
    ok(mbi.Protect == PAGE_READONLY, "header Protect %lx", (unsigned long)mbi.Protect);

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            status = NtQueryVirtualMemory(NtCurrentProcess(), view1 + sec[i].VirtualAddress,
                                          MEMORY_BASIC_INFO_CLASS, &mbi, sizeof(mbi), NULL);
            ok(status == STATUS_SUCCESS, "query text -> %08lx", (unsigned long)status);
            ok(mbi.Protect == PAGE_EXECUTE_READ, "text Protect %lx", (unsigned long)mbi.Protect);
            break;
        }
    }

    /* --- an image view is unmapped, never freed ------------------------------ */

    addr = view1;
    view_size = 0;
    status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &view_size, MEM_RELEASE);
    ok(status == STATUS_INVALID_PARAMETER, "free image view -> %08lx", (unsigned long)status);

    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_SUCCESS, "unmap view1 -> %08lx", (unsigned long)status);
    status = NtUnmapViewOfSection(NtCurrentProcess(), view2);
    ok(status == STATUS_SUCCESS, "unmap view2 -> %08lx", (unsigned long)status);
    status = NtUnmapViewOfSection(NtCurrentProcess(), view1);
    ok(status == STATUS_NOT_MAPPED_VIEW, "unmap again -> %08lx", (unsigned long)status);

    NtClose(section);
    CloseHandle(file);

    /* --- a non-PE file is not an image ---------------------------------------- */

    {
        static const char junk[512] = "this is not a PE image";
        char tmp_path[MAX_PATH], tmp_file[MAX_PATH];
        DWORD written;

        GetTempPathA(sizeof(tmp_path), tmp_path);
        GetTempFileNameA(tmp_path, "sec", 0, tmp_file);
        file = CreateFileA(tmp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
        ok(file != INVALID_HANDLE_VALUE, "cannot create temp file");
        WriteFile(file, junk, sizeof(junk), &written, NULL);

        section = NULL;
        status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE,
                                 file);
        ok(status == STATUS_INVALID_IMAGE_NOT_MZ, "junk image -> %08lx", (unsigned long)status);

        CloseHandle(file);
        DeleteFileA(tmp_file);
    }
}
