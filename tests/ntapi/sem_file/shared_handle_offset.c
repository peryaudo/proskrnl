/*
 * sem_file/shared_handle_offset.c — NT serializes I/O on a synchronous
 * handle (the file-object lock), so two threads writing through ONE shared
 * sync handle with NULL ByteOffset each land at the position the other
 * left: the positions advance atomically per write, the final size is the
 * sum of everything written, and no write's bytes interleave inside a
 * chunk. The oracle gets all three from the shared unix fd; a kernel whose
 * data path can park mid-write must provide them itself (CUI-8 — before
 * the file-object lock, two proskrnl threads both captured offset 0 across
 * a park and overwrote each other's chunks, PR #95 review bug 8).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
                                               FILE_INFORMATION_CLASS);

#define SHO_CHUNK  4096u
#define SHO_CHUNKS 48u /* per thread; 384 KiB total */

static HANDLE sho_handle;
static volatile LONG sho_write_failures;

static DWORD WINAPI sho_writer(void *param)
{
    IO_STATUS_BLOCK iosb;
    char chunk[SHO_CHUNK];
    memset(chunk, (int)(UINT_PTR)param, sizeof(chunk));
    for (unsigned i = 0; i < SHO_CHUNKS; i++)
    {
        NTSTATUS status =
            NtWriteFile(sho_handle, NULL, NULL, NULL, &iosb, chunk, SHO_CHUNK, NULL, NULL);
        if (status != STATUS_SUCCESS || iosb.Information != SHO_CHUNK)
            InterlockedIncrement(&sho_write_failures);
    }
    return 0;
}

START_TEST(shared_handle_offset)
{
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    HANDLE dir, a, b;
    LARGE_INTEGER offset;
    static char block[SHO_CHUNK];

    dir = open_test_dir(W("\\??\\C:\\prstest\\shof"));
    ok(dir != NULL, "test dir");
    if (dir == NULL)
        return;
    scrub_file(dir, W("shared.bin"));

    status = open_file(&sho_handle, dir, W("shared.bin"), FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0, &iosb);
    ok(status == STATUS_SUCCESS, "create shared.bin -> %08lx", (unsigned long)status);
    if (status != STATUS_SUCCESS)
    {
        NtClose(dir);
        return;
    }

    sho_write_failures = 0;
    a = CreateThread(NULL, 0, sho_writer, (void *)(UINT_PTR)0xA5, 0, NULL);
    b = CreateThread(NULL, 0, sho_writer, (void *)(UINT_PTR)0x5A, 0, NULL);
    ok(a != NULL && b != NULL, "writer threads");
    if (a != NULL)
    {
        ok(WaitForSingleObject(a, 60000) == WAIT_OBJECT_0, "writer A returned");
        CloseHandle(a);
    }
    if (b != NULL)
    {
        ok(WaitForSingleObject(b, 60000) == WAIT_OBJECT_0, "writer B returned");
        CloseHandle(b);
    }
    ok(sho_write_failures == 0, "every write succeeded in full (%ld failures)",
       (long)sho_write_failures);

    /* The serialized advance: nothing overwritten, nothing torn. */
    {
        FILE_STANDARD_INFORMATION std;
        status =
            NtQueryInformationFile(sho_handle, &iosb, &std, sizeof(std), FileStandardInformation);
        ok(status == STATUS_SUCCESS, "query size -> %08lx", (unsigned long)status);
        ok(std.EndOfFile.QuadPart == (LONGLONG)(2 * SHO_CHUNKS * SHO_CHUNK),
           "final size is the sum of both writers (%ld vs %lu)", (long)std.EndOfFile.QuadPart,
           (unsigned long)(2 * SHO_CHUNKS * SHO_CHUNK));
    }
    {
        int torn = 0;
        unsigned counts[2] = {0, 0};
        for (unsigned c = 0; c < 2 * SHO_CHUNKS; c++)
        {
            offset.QuadPart = (LONGLONG)c * SHO_CHUNK;
            status =
                NtReadFile(sho_handle, NULL, NULL, NULL, &iosb, block, SHO_CHUNK, &offset, NULL);
            if (status != STATUS_SUCCESS || iosb.Information != SHO_CHUNK)
            {
                torn++;
                continue;
            }
            unsigned char first = (unsigned char)block[0];
            if (first != 0xA5 && first != 0x5A)
            {
                torn++;
                continue;
            }
            for (unsigned i = 1; i < SHO_CHUNK; i++)
            {
                if ((unsigned char)block[i] != first)
                {
                    torn++;
                    break;
                }
            }
            counts[first == 0xA5 ? 0 : 1]++;
        }
        ok(torn == 0, "every chunk is one writer's bytes end to end (%d torn)", torn);
        ok(counts[0] == SHO_CHUNKS && counts[1] == SHO_CHUNKS,
           "each writer's chunks all present (%u/%u)", counts[0], counts[1]);
    }

    NtClose(sho_handle);
    scrub_file(dir, W("shared.bin"));
    NtClose(dir);
}
