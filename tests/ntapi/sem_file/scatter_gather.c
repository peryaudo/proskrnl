/*
 * sem_file/scatter_gather.c — NtReadFileScatter / NtWriteFileGather (CUI-5).
 *
 * kernelbase's ReadFileScatter/WriteFileGather (dlls/kernelbase/file.c)
 * pass these straight through with the OVERLAPPED as the IOSB. The
 * contract (pinned Wine dlls/ntdll/unix/file.c): the handle must be a
 * regular file, opened NON-synchronous and FILE_NO_INTERMEDIATE_BUFFERING
 * — anything else is STATUS_INVALID_PARAMETER; gather additionally refuses
 * a length that is not a page multiple before touching the handle; length
 * counts BYTES (each FILE_SEGMENT_ELEMENT covers one page); the scatter
 * side returns STATUS_PENDING with the IOSB already completed (the gather
 * side returns the final status directly — an oracle asymmetry pinned
 * as-is); a read past EOF completes with STATUS_END_OF_FILE and
 * Information 0.
 */
#include "util.h"

#include <stddef.h>

NTSYSAPI NTSTATUS NTAPI NtReadFileScatter(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                          FILE_SEGMENT_ELEMENT *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtWriteFileGather(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                          FILE_SEGMENT_ELEMENT *, ULONG, PLARGE_INTEGER, PULONG);
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE) ~(ULONG_PTR)0) /* wine/include/winternl.h */
#endif

#define SG_PAGE 4096

static NTSTATUS open_sg(HANDLE *handle, HANDLE root, ACCESS_MASK access, ULONG options,
                        ULONG disposition, IO_STATUS_BLOCK *iosb)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    init_ustr(&name, W("sg.bin"));
    init_attr(&attr, root, &name, OBJ_CASE_INSENSITIVE);
    *handle = NULL;
    return NtCreateFile(handle, access, &attr, iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, disposition, options, NULL, 0);
}

START_TEST(scatter_gather)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HANDLE dir, h;
    LARGE_INTEGER offset;
    FILE_SEGMENT_ELEMENT segments[3];

    dir = open_test_dir(W("\\??\\C:\\prstest\\sg"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("sg.bin"));

    /* Two page-aligned pages with distinct patterns. */
    PVOID pages = NULL;
    SIZE_T region = 2 * SG_PAGE;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &pages, 0, &region,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "allocate pages -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    memset(pages, 0xAB, SG_PAGE);
    memset((char *)pages + SG_PAGE, 0xCD, SG_PAGE);

    /* --- the qualifying handle: non-synchronous + no-intermediate-buffering */
    status = open_sg(&h, dir, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                     FILE_NO_INTERMEDIATE_BUFFERING, FILE_OVERWRITE_IF, &iosb);
    ok(status == STATUS_SUCCESS, "open sg.bin -> %08lx", (unsigned long)status);

    /* Gather two pages at offset 0. */
    segments[0].Buffer = pages;
    segments[1].Buffer = (char *)pages + SG_PAGE;
    segments[2].Alignment = 0;
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtWriteFileGather(h, NULL, NULL, NULL, &iosb, segments, 2 * SG_PAGE, &offset, NULL);
    ok(status == STATUS_SUCCESS, "gather -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "gather iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 2 * SG_PAGE, "gather Information %lu", (unsigned long)iosb.Information);

    /* Scatter them back into fresh pages. */
    PVOID readback = NULL;
    region = 2 * SG_PAGE;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &readback, 0, &region,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS, "allocate readback -> %08lx", (unsigned long)status);
    segments[0].Buffer = readback;
    segments[1].Buffer = (char *)readback + SG_PAGE;
    segments[2].Alignment = 0;
    offset.QuadPart = 0;
    poison_iosb(&iosb);
    status = NtReadFileScatter(h, NULL, NULL, NULL, &iosb, segments, 2 * SG_PAGE, &offset, NULL);
    ok(status == STATUS_PENDING, "scatter -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_SUCCESS, "scatter iosb.Status %08lx", (unsigned long)iosb.Status);
    ok(iosb.Information == 2 * SG_PAGE, "scatter Information %lu", (unsigned long)iosb.Information);
    ok(((unsigned char *)readback)[0] == 0xAB && ((unsigned char *)readback)[SG_PAGE - 1] == 0xAB,
       "page 0 content");
    ok(((unsigned char *)readback)[SG_PAGE] == 0xCD &&
           ((unsigned char *)readback)[2 * SG_PAGE - 1] == 0xCD,
       "page 1 content");

    /* A scatter entirely past EOF completes END_OF_FILE with nothing read. */
    offset.QuadPart = 2 * SG_PAGE;
    poison_iosb(&iosb);
    status = NtReadFileScatter(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE, &offset, NULL);
    ok(status == STATUS_PENDING, "scatter at EOF -> %08lx", (unsigned long)status);
    ok(iosb.Status == STATUS_END_OF_FILE, "scatter at EOF iosb.Status %08lx",
       (unsigned long)iosb.Status);
    ok(iosb.Information == 0, "scatter at EOF Information %lu", (unsigned long)iosb.Information);

    /* Gather refuses a non-page-multiple length before anything else. */
    offset.QuadPart = 0;
    status = NtWriteFileGather(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE / 2, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "gather odd length -> %08lx", (unsigned long)status);
    NtClose(h);

    /* --- disqualified handles refuse INVALID_PARAMETER ---------------------- */
    /* Synchronous handle. */
    status =
        open_sg(&h, dir, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "open sync -> %08lx", (unsigned long)status);
    offset.QuadPart = 0;
    status = NtReadFileScatter(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "scatter on sync handle -> %08lx",
       (unsigned long)status);
    status = NtWriteFileGather(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "gather on sync handle -> %08lx", (unsigned long)status);
    NtClose(h);

    /* Buffered (no FILE_NO_INTERMEDIATE_BUFFERING) handle. */
    status = open_sg(&h, dir, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "open buffered -> %08lx", (unsigned long)status);
    status = NtReadFileScatter(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE, &offset, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "scatter on buffered handle -> %08lx",
       (unsigned long)status);
    NtClose(h);

    /* --- a NEGATIVE ByteOffset is a sentinel or an error, never 0 ---------
     *
     * proskrnl silently kept offset 0 for any negative value, so a gather
     * with FILE_WRITE_TO_END_OF_FILE (-1) overwrote the START of the file
     * instead of appending. Every other negative value is refused, as
     * NtReadFile/NtWriteFile refuse it -- including the -2
     * FILE_USE_FILE_POINTER_POSITION sentinel. */
    status = open_sg(&h, dir, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                     FILE_NO_INTERMEDIATE_BUFFERING, FILE_OPEN, &iosb);
    ok(status == STATUS_SUCCESS, "open for the negative-offset cases -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        offset.QuadPart = -3;
        status = NtWriteFileGather(h, NULL, NULL, NULL, &iosb, segments, SG_PAGE, &offset, NULL);
        ok(status == STATUS_INVALID_PARAMETER, "gather at offset -3 -> %08lx",
           (unsigned long)status);
        /* -2 (FILE_USE_FILE_POINTER_POSITION) is left out: proskrnl refuses
         * it here for the same reason NtReadFile/NtWriteFile do -- an
         * unbuilt sentinel gets a distinguishable status rather than a
         * fabricated position, which is the docs/03 deviation those two
         * already carry -- while the oracle accepts it. Pinning it either
         * way would either certify the divergence or contradict the
         * deviation. The read side is left out too: an asynchronous handle
         * pends there, so the status does not report the offset check. */
        NtClose(h);
    }

    scrub_file(dir, W("sg.bin"));
    NtClose(dir);
}
