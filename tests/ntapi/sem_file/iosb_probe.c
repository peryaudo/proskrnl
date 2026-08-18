/*
 * sem_file/iosb_probe.c — what the Io layer's IO_STATUS_BLOCK output pointer
 * refuses, and in which ORDER.
 *
 * Every Io service takes a caller-supplied IO_STATUS_BLOCK and writes two
 * pointer-sized fields into it. That invites the reading that the block must
 * be pointer-ALIGNED, the way a kernel that stores through an
 * `IO_STATUS_BLOCK *` needs it to be. It must not: the pinned oracle stores
 * the two fields with a plain assignment through the caller's pointer and
 * checks nothing before it (`io_status->Status = status; io_status->
 * Information = 0;` — dlls/ntdll/unix/file.c NtCancelSynchronousIoFile, and
 * the same shape in NtReadFile / NtQueryInformationFile / NtFlushBuffersFile),
 * so a misaligned but MAPPED block is served, and only an INACCESSIBLE one
 * refuses.
 *
 * The distinction is not academic and it is what convicted this: an
 * alignment test taken BEFORE the accessibility test answers
 * STATUS_DATATYPE_MISALIGNMENT for an address that is neither, where NT
 * answers STATUS_ACCESS_VIOLATION. `third_party/wine`
 * dlls/ntdll/tests/pipe.c:725 asserts exactly that, unguarded, for
 * `(IO_STATUS_BLOCK *)0xdeadbeef` — i.e. it is measured WINDOWS behaviour and
 * not merely the oracle's — and proskrnl answered 0x80000002.
 *
 * §2's misaligned-but-mapped case is the one that separates the two possible
 * fixes, and neither §1 nor the winetest can: dropping the alignment
 * requirement and merely REORDERING the two tests both make 0xdeadbeef
 * answer STATUS_ACCESS_VIOLATION, and they disagree only where the block is
 * writable at a misaligned address. The oracle decides that (Art. 6).
 *
 * The OUTPUT-BUFFER half of this contract is already pinned next door
 * (dir_unaligned_buffer.c, info_unaligned_buffer.c, volume_unaligned.c:
 * "NT treats the buffer as bytes"). This is the same rule for the status
 * block those calls also write, which is the one operand of an Io service
 * that every entry point has.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtCancelSynchronousIoFile(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(HANDLE, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtCancelIoFileEx(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                                     FS_INFORMATION_CLASS);

/* An 8-aligned backing store the misaligned blocks are carved out of, so a
 * delta is a known misalignment rather than whatever the linker gave a
 * `char[]`. `long long` for the base alignment; the deltas are applied to the
 * unsigned char * view. */
static long long alignedStore[8];

static IO_STATUS_BLOCK *block_at(unsigned delta)
{
    unsigned char *base = (unsigned char *)alignedStore + delta;
    memset(alignedStore, 0x5a, sizeof(alignedStore));
    return (IO_STATUS_BLOCK *)(void *)base;
}

/* Read a possibly-misaligned block back the way the kernel wrote it — byte by
 * byte into an aligned local. The test may not itself do the misaligned struct
 * access it is asserting the kernel performs. */
static void read_block(const IO_STATUS_BLOCK *block, IO_STATUS_BLOCK *out)
{
    memcpy(out, (const void *)block, sizeof(*out));
}

static const unsigned deltas[] = {1, 2, 4};

START_TEST(iosb_probe)
{
    IO_STATUS_BLOCK iosb, copy;
    NTSTATUS status;
    HANDLE dir, file = NULL;
    unsigned i;

    dir = open_test_dir(W("\\??\\C:\\prstest\\iosbprobe"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;

    scrub_file(dir, W("probe.dat"));
    status = open_file(&file, dir, W("probe.dat"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create probe.dat -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(dir);
        return;
    }

    /* Two inaccessible-but-well-formed addresses to test against: a RESERVED
     * page (page-aligned, so it is inaccessible WITHOUT being misaligned —
     * the control §1 needs) and a committed read-only one (mapped and
     * aligned, so only the write intent can refuse it). */
    unsigned char *reserved = VirtualAlloc(NULL, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
    unsigned char *readOnly = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY);
    ok(reserved != NULL, "reserve a page");
    ok(readOnly != NULL, "commit a read-only page");

    /* --- §1 an INACCESSIBLE block is STATUS_ACCESS_VIOLATION --------------- */
    /* The winetest's own two cases first (pipe.c:724 and :725). */
    status = NtCancelSynchronousIoFile(GetCurrentThread(), NULL, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync NULL block -> %08lx", (unsigned long)status);
    status = NtCancelSynchronousIoFile(GetCurrentThread(), NULL,
                                       (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef);
    ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync 0xdeadbeef block -> %08lx",
       (unsigned long)status);

    if (reserved != NULL)
    {
        /* Page-ALIGNED and unmapped: the same refusal, which is what says
         * 0xdeadbeef's answer is about accessibility and not about its low
         * bits. */
        status =
            NtCancelSynchronousIoFile(GetCurrentThread(), NULL, (PIO_STATUS_BLOCK)(void *)reserved);
        ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync aligned unmapped block -> %08lx",
           (unsigned long)status);
        /* ... and misaligned AND unmapped, which is 0xdeadbeef's shape. */
        status = NtCancelSynchronousIoFile(GetCurrentThread(), NULL,
                                           (PIO_STATUS_BLOCK)(void *)(reserved + 1));
        ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync misaligned unmapped block -> %08lx",
           (unsigned long)status);
    }
    if (readOnly != NULL)
    {
        /* Mapped, aligned, readable — and still refused, because writing the
         * block is the intent. A probe that only tested presence passes
         * everything above and fails this. */
        status =
            NtCancelSynchronousIoFile(GetCurrentThread(), NULL, (PIO_STATUS_BLOCK)(void *)readOnly);
        ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync read-only block -> %08lx",
           (unsigned long)status);
    }

    /* An inaccessible block outranks a bad HANDLE: the oracle reaches the
     * store either way (it runs the server call first and faults on the way
     * out), so the refusal the caller sees is the block's, not the handle's.
     * pipe.c:722 shows the same handle with a GOOD block answering
     * STATUS_INVALID_HANDLE, so this is a real ordering and not a tautology. */
    status = NtCancelSynchronousIoFile((HANDLE)(ULONG_PTR)0xdeadbeef, NULL,
                                       (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef);
    ok(status == STATUS_ACCESS_VIOLATION, "cancel-sync bad handle + bad block -> %08lx",
       (unsigned long)status);

    /* --- §2 a MISALIGNED but mapped block is SERVED ------------------------ */
    /* The discriminating case. The caller is not parked in synchronous I/O,
     * so the verb's own answer is STATUS_NOT_FOUND — and it must be written
     * through the misaligned pointer, not merely returned. */
    for (i = 0; i < 3; i++)
    {
        IO_STATUS_BLOCK *block = block_at(deltas[i]);
        status = NtCancelSynchronousIoFile(GetCurrentThread(), NULL, block);
        ok(status == STATUS_NOT_FOUND, "cancel-sync block+%u -> %08lx", deltas[i],
           (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Status == STATUS_NOT_FOUND, "cancel-sync block+%u wrote Status %08lx", deltas[i],
           (unsigned long)copy.Status);
        ok(copy.Information == 0, "cancel-sync block+%u wrote Information %llx", deltas[i],
           (unsigned long long)copy.Information);
        /* ... and it wrote the two FIELDS, not the sixteen bytes. The block
         * opens with a union — `union { NTSTATUS Status; PVOID Pointer; }` —
         * so bytes 4..7 are the upper half of the caller's Pointer spelling
         * and nothing on either side writes them. dlls/wow64/file.c fills the
         * whole union (`IO_STATUS_BLOCK io = { .Pointer = &io32 }`) before
         * handing the block down, so this is a live caller's bytes, and an
         * implementation that stages the answer in a local and copies all
         * sixteen out both clobbers them and publishes four uninitialised
         * kernel-stack bytes. Poison is 0x5a (block_at). */
        unsigned char tail[4];
        memcpy(tail, (const unsigned char *)block + 4, sizeof(tail));
        ok(tail[0] == 0x5a && tail[1] == 0x5a && tail[2] == 0x5a && tail[3] == 0x5a,
           "cancel-sync block+%u left union bytes 4..7 as %02x%02x%02x%02x", deltas[i], tail[0],
           tail[1], tail[2], tail[3]);
    }

    /* --- §3 the other two cancel entry points ------------------------------ */
    {
        IO_STATUS_BLOCK *block = block_at(1);
        status = NtCancelIoFile(file, block);
        ok(status == STATUS_SUCCESS, "cancel-io block+1 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Status == STATUS_SUCCESS, "cancel-io block+1 wrote Status %08lx",
           (unsigned long)copy.Status);

        block = block_at(1);
        status = NtCancelIoFileEx(file, NULL, block);
        ok(status == STATUS_NOT_FOUND, "cancel-io-ex block+1 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Status == STATUS_NOT_FOUND, "cancel-io-ex block+1 wrote Status %08lx",
           (unsigned long)copy.Status);

        status = NtCancelIoFile(file, (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef);
        ok(status == STATUS_ACCESS_VIOLATION, "cancel-io bad block -> %08lx",
           (unsigned long)status);
        status = NtCancelIoFileEx(file, NULL, (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef);
        ok(status == STATUS_ACCESS_VIOLATION, "cancel-io-ex bad block -> %08lx",
           (unsigned long)status);
    }

    /* --- §4 the transfer path writes through a misaligned block too -------- */
    {
        static const char payload[] = "iosbprobe";
        LARGE_INTEGER offset;
        char readBack[16];
        IO_STATUS_BLOCK *block = block_at(4);

        offset.QuadPart = 0;
        status =
            NtWriteFile(file, NULL, NULL, NULL, block, payload, sizeof(payload) - 1, &offset, NULL);
        ok(status == STATUS_SUCCESS, "write with block+4 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Information == sizeof(payload) - 1, "write with block+4 wrote Information %llx",
           (unsigned long long)copy.Information);

        block = block_at(2);
        offset.QuadPart = 0;
        memset(readBack, 0, sizeof(readBack));
        status =
            NtReadFile(file, NULL, NULL, NULL, block, readBack, sizeof(payload) - 1, &offset, NULL);
        ok(status == STATUS_SUCCESS, "read with block+2 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Information == sizeof(payload) - 1, "read with block+2 wrote Information %llx",
           (unsigned long long)copy.Information);
        ok(memcmp(readBack, payload, sizeof(payload) - 1) == 0, "read with block+2 bytes");

        offset.QuadPart = 0;
        status = NtReadFile(file, NULL, NULL, NULL, (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef,
                            readBack, sizeof(payload) - 1, &offset, NULL);
        ok(status == STATUS_ACCESS_VIOLATION, "read with bad block -> %08lx",
           (unsigned long)status);

        block = block_at(1);
        status = NtFlushBuffersFile(file, block);
        ok(status == STATUS_SUCCESS, "flush with block+1 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Status == STATUS_SUCCESS, "flush with block+1 wrote Status %08lx",
           (unsigned long)copy.Status);
    }

    /* --- §5 the query paths ------------------------------------------------ */
    {
        FILE_STANDARD_INFORMATION standard;
        IO_STATUS_BLOCK *block = block_at(4);

        status = NtQueryInformationFile(file, block, &standard, sizeof(standard),
                                        FileStandardInformation);
        ok(status == STATUS_SUCCESS, "query-info with block+4 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Information == sizeof(standard), "query-info with block+4 Information %llx",
           (unsigned long long)copy.Information);

        status = NtQueryInformationFile(file, (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef, &standard,
                                        sizeof(standard), FileStandardInformation);
        ok(status == STATUS_ACCESS_VIOLATION, "query-info with bad block -> %08lx",
           (unsigned long)status);

        /* The SET direction has its own probe. A successful set writes the
         * block ... */
        FILE_POSITION_INFORMATION position;
        position.CurrentByteOffset.QuadPart = 0;
        block = block_at(2);
        status =
            NtSetInformationFile(file, block, &position, sizeof(position), FilePositionInformation);
        ok(status == STATUS_SUCCESS, "set-info with block+2 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Status == STATUS_SUCCESS, "set-info with block+2 wrote Status %08lx",
           (unsigned long)copy.Status);

        /* ... and a REFUSED call still owes the caller the refusal it earned,
         * never the alignment one: the block is probed before the class and
         * the length are ever looked at, so a short QUERY buffer reports the
         * length mistake through a misaligned block like any other answer.
         *
         * The query direction, not the set direction, and that is a
         * measurement rather than a preference: the same short buffer on
         * NtSetInformationFile answers STATUS_INVALID_PARAMETER_3 on the
         * oracle (per-class, `else status = STATUS_INVALID_PARAMETER_3;` at
         * dlls/ntdll/unix/file.c:5245) where proskrnl gives
         * INFO_LENGTH_MISMATCH from its shared length gate — a real
         * divergence, but one about which status a class owes and not about
         * the block. Filed as issue #219 rather than pinned here. */
        block = block_at(2);
        status = NtQueryInformationFile(file, block, &standard, sizeof(standard) - 1,
                                        FileStandardInformation);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short query-info with block+2 -> %08lx",
           (unsigned long)status);
    }
    {
        FILE_FS_SIZE_INFORMATION sizeInfo;
        IO_STATUS_BLOCK *block = block_at(1);

        status = NtQueryVolumeInformationFile(dir, block, &sizeInfo, sizeof(sizeInfo),
                                              FileFsSizeInformation);
        ok(status == STATUS_SUCCESS, "query-volume with block+1 -> %08lx", (unsigned long)status);
        read_block(block, &copy);
        ok(copy.Information == sizeof(sizeInfo), "query-volume with block+1 Information %llx",
           (unsigned long long)copy.Information);

        status = NtQueryVolumeInformationFile(dir, (PIO_STATUS_BLOCK)(ULONG_PTR)0xdeadbeef,
                                              &sizeInfo, sizeof(sizeInfo), FileFsSizeInformation);
        ok(status == STATUS_ACCESS_VIOLATION, "query-volume with bad block -> %08lx",
           (unsigned long)status);
    }

    if (reserved != NULL)
        VirtualFree(reserved, 0, MEM_RELEASE);
    if (readOnly != NULL)
        VirtualFree(readOnly, 0, MEM_RELEASE);
    NtClose(file);
    scrub_file(dir, W("probe.dat"));
    NtClose(dir);
}
