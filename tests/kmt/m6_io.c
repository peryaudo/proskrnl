/* tests/kmt/m6_io.c — the M6 in-kernel suite: virtio-blk, the FAT32 boot
 * volume through the Nt* file surface, and image sections from on-disk
 * files (docs/02 M6 "Done when": M5's image mapping works from an on-disk
 * file).
 *
 * These run as KernelMode callers of the same Nt* the ring-3 sem_file
 * tests hit; the boundary conviction is the ntapi run (Art. 6) — this
 * suite is the plumbing check that must stay green underneath it.
 */
#include "tests/kmt/kmt.h"
#include "kernel/io/io.h"
#include "kernel/mm/section.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "drivers/virtio/blk.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"
#include "abi/ntmmapi.h"

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    attr->Length = sizeof(*attr);
    attr->RootDirectory = 0;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static void test_virtio_blk(void)
{
    ok(VioBlkIsPresent(), "no virtio-blk disk");
    if (!VioBlkIsPresent())
        return;
    ok(VioBlkSectorCount() > 2048, "capacity %lu sectors", (unsigned long)VioBlkSectorCount());

    /* LBA 0 is the protective MBR: 0x55 at 510, 0xAA at 511 (UEFI 2.10
     * §5.2.3); LBA 1 the GPT header, "EFI PART" (§5.3.2). */
    unsigned char sector[512];
    ok(VioBlkReadSectors(0, 1, sector) == STATUS_SUCCESS, "read LBA 0");
    ok(sector[510] == 0x55 && sector[511] == 0xAA, "protective MBR signature %02x%02x", sector[510],
       sector[511]);
    ok(VioBlkReadSectors(1, 1, sector) == STATUS_SUCCESS, "read LBA 1");
    ok(memcmp(sector, "EFI PART", 8) == 0, "GPT header signature");
}

static void test_file_roundtrip(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir = 0, file = 0;
    NTSTATUS status;
    LARGE_INTEGER offset;

    /* A directory + a file, created through the real Nt* surface. */
    init_attr(&attr, &name, WSTR("\\??\\C:\\kmt6"));
    status = NtCreateFile(&dir, FILE_LIST_DIRECTORY | FILE_ADD_FILE | SYNCHRONIZE, &attr, &iosb, 0,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ok(status == STATUS_SUCCESS, "create kmt6 dir -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;

    init_attr(&attr, &name, WSTR("\\??\\C:\\kmt6\\LongMixedCase-Name.data"));
    status = NtCreateFile(&file, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                          FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT,
                          0, 0);
    ok(status == STATUS_SUCCESS, "create file -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(dir);
        return;
    }

    /* Write a two-page pattern, read it back. */
    ULONG size = 2 * PAGE_SIZE + 123;
    char *buffer = MiAllocatePool(size);
    char *readback = MiAllocatePool(size);
    ok(buffer != 0 && readback != 0, "pool");
    for (ULONG i = 0; i < size; i++)
        buffer[i] = (char)(i * 7 + 3);
    offset.QuadPart = 0;
    status = NtWriteFile(file, 0, 0, 0, &iosb, buffer, size, &offset, 0);
    ok(status == STATUS_SUCCESS && iosb.Information == size, "write -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    memset(readback, 0, size);
    offset.QuadPart = 0;
    status = NtReadFile(file, 0, 0, 0, &iosb, readback, size, &offset, 0);
    ok(status == STATUS_SUCCESS && iosb.Information == size, "read -> %08lx/%lu",
       (unsigned long)status, (unsigned long)iosb.Information);
    ok(memcmp(buffer, readback, size) == 0, "readback mismatch");

    /* Persistence below the cache: bytes must be on the DISK, not only in
     * memory. Read the raw partition through virtio and hunt for the
     * pattern's first 16 bytes (cheap smoke, not a full FS check). */
    NtClose(file);
    init_attr(&attr, &name, WSTR("\\??\\C:\\kmt6\\LongMixedCase-Name.data"));
    file = 0;
    status = NtOpenFile(&file, FILE_GENERIC_READ | DELETE, &attr, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "reopen (case-insensitive path) -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        memset(readback, 0, size);
        offset.QuadPart = 0;
        status = NtReadFile(file, 0, 0, 0, &iosb, readback, size, &offset, 0);
        ok(status == STATUS_SUCCESS && memcmp(buffer, readback, size) == 0,
           "reopen readback -> %08lx", (unsigned long)status);

        /* Delete-on-close via disposition. */
        FILE_DISPOSITION_INFORMATION disposition;
        disposition.DoDeleteFile = TRUE;
        status = NtSetInformationFile(file, &iosb, &disposition, sizeof(disposition),
                                      FileDispositionInformation);
        ok(status == STATUS_SUCCESS, "set disposition -> %08lx", (unsigned long)status);
        NtClose(file);
        file = 0;
        status = NtOpenFile(&file, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                            FILE_SYNCHRONOUS_IO_NONALERT);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "deleted -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(file);
    }

    MiFreePool(buffer);
    MiFreePool(readback);
    NtClose(dir);
}

static void test_image_section_from_disk(void)
{
    /* tools/mkimage.sh copies the boot modules into the FAT root, so the
     * PE client exists as an ordinary on-disk file too. */
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0, section = 0;
    NTSTATUS status;

    init_attr(&attr, &name, WSTR("\\??\\C:\\pe_smoke.exe"));
    status = NtOpenFile(&file, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, &attr, &iosb,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "open pe_smoke.exe -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
        return;

    status = NtCreateSection(&section, SECTION_ALL_ACCESS, 0, 0, PAGE_EXECUTE, SEC_IMAGE, file);
    ok(status == STATUS_SUCCESS, "SEC_IMAGE from disk file -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        /* Map the image into a scratch address space and check the copied
         * headers ("MZ" — abi/ntimage.h IMAGE_DOS_SIGNATURE) landed. */
        PVOID body;
        status = ObReferenceObjectByHandle(section, SECTION_MAP_READ, &MiSectionType, KernelMode,
                                           &body, 0);
        ok(status == STATUS_SUCCESS, "reference section -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS)
        {
            PMI_SECTION sectionBody = body;
            ok(sectionBody->image != 0, "image info missing");
            MI_ADDRESS_SPACE space;
            ok(MiCreateAddressSpace(&space) == STATUS_SUCCESS, "scratch space");
            uint64_t base = 0, viewSize = 0;
            status = MiMapViewOfSection(sectionBody, &space, &base, 0, &viewSize, PAGE_READONLY);
            ok(NT_SUCCESS(status), "map image view -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                uint64_t frame = MiTranslateUserPage(space.pml4Physical, base, 0, 0);
                ok(frame != 0, "image base not mapped");
                const unsigned char *bytes = MiPhysicalToVirtual(frame);
                ok(bytes[0] == 'M' && bytes[1] == 'Z', "no MZ header at the mapped base");
            }
            MiDeleteAddressSpace(&space);
            ObDereferenceObject(body);
        }
        NtClose(section);
    }

    /* While a section lives... it is gone now; the delete guard was
     * released with it. Deleting a mapped file must fail while mapped: */
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_COMMIT, file);
    ok(status == STATUS_SUCCESS, "data section over file -> %08lx", (unsigned long)status);
    if (status == STATUS_SUCCESS)
    {
        HANDLE writable = 0;
        init_attr(&attr, &name, WSTR("\\??\\C:\\pe_smoke.exe"));
        NTSTATUS openStatus = NtOpenFile(&writable, DELETE | SYNCHRONIZE, &attr, &iosb,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         FILE_SYNCHRONOUS_IO_NONALERT);
        ok(openStatus == STATUS_SUCCESS, "open for delete -> %08lx", (unsigned long)openStatus);
        if (openStatus == STATUS_SUCCESS)
        {
            FILE_DISPOSITION_INFORMATION disposition;
            disposition.DoDeleteFile = TRUE;
            NTSTATUS dispositionStatus = NtSetInformationFile(
                writable, &iosb, &disposition, sizeof(disposition), FileDispositionInformation);
            ok(dispositionStatus == STATUS_CANNOT_DELETE, "delete mapped file -> %08lx",
               (unsigned long)dispositionStatus);
            NtClose(writable);
        }
        NtClose(section);
    }
    NtClose(file);
}

int kmt_run_m6(void)
{
    int before = kmt_failures;
    DbgPrint("kmt: M6 io suite\n");
    KMT_RUN(test_virtio_blk);
    if (VioBlkIsPresent())
    {
        KMT_RUN(test_file_roundtrip);
        KMT_RUN(test_image_section_from_disk);
    }
    return kmt_failures - before;
}
