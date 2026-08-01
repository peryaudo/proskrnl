/* tests/cui/watchapp.c — the CUI-7 acceptance's VirtualAlloc2/write-watch
 * app (the milestone's "an app on the VirtualAlloc2/write-watch path runs").
 *
 * The GC-runtime shape end to end, through the real kernelbase surface:
 * VirtualAlloc2 with a MEM_ADDRESS_REQUIREMENTS placement (resolved at run
 * time from kernelbase.dll — mingw's import libraries predate it),
 * MEM_WRITE_WATCH, a stride of ring-3 stores read back by GetWriteWatch,
 * ResetWriteWatch, a re-dirty pass, and a ReadFile landing in a watched
 * page to prove kernel-side writes mark too. Markers carry digits the
 * typed command cannot supply.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef PVOID WINAPI VirtualAlloc2_t(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void *, ULONG);

typedef struct
{
    PVOID lowest;
    PVOID highest;
    SIZE_T alignment;
} addr_requirements;

typedef struct
{
    ULONGLONG type_bits;
    union
    {
        ULONGLONG u64;
        PVOID pointer;
    } u;
} ext_param;

#define PAGES 8

int main(void)
{
    unsigned char *base;
    PVOID addresses[PAGES];
    ULONG_PTR count;
    ULONG granularity = 0;
    SIZE_T size = PAGES * 0x1000;

    VirtualAlloc2_t *valloc2 =
        (VirtualAlloc2_t *)(void *)GetProcAddress(LoadLibraryA("kernelbase.dll"), "VirtualAlloc2");
    if (valloc2 == NULL)
    {
        printf("watchapp-no-virtualalloc2\n");
        return 1;
    }

    addr_requirements req;
    ext_param param;
    memset(&req, 0, sizeof(req));
    memset(&param, 0, sizeof(param));
    req.lowest = (PVOID)(ULONG_PTR)0x30000000;
    req.highest = (PVOID)(ULONG_PTR)0x3fffffff;
    req.alignment = 0x20000;
    param.type_bits = 1; /* MemExtendedParameterAddressRequirements */
    param.u.pointer = &req;

    base = valloc2(GetCurrentProcess(), NULL, size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH,
                   PAGE_READWRITE, &param, 1);
    if (base == NULL || (ULONG_PTR)base < 0x30000000 || (ULONG_PTR)base >= 0x40000000 ||
        ((ULONG_PTR)base & 0x1ffff) != 0)
    {
        printf("watchapp-alloc-FAIL (%p, %lu)\n", (void *)base, GetLastError());
        return 1;
    }
    printf("watchapp-alloc-ok\n");

    /* A stride of stores: pages 0, 3 and 6. */
    base[0 * 0x1000] = 1;
    base[3 * 0x1000] = 1;
    base[6 * 0x1000] = 1;
    count = PAGES;
    if (GetWriteWatch(0, base, size, addresses, &count, &granularity) != 0 || count != 3 ||
        addresses[0] != base || addresses[1] != base + 3 * 0x1000 ||
        addresses[2] != base + 6 * 0x1000 || granularity != 0x1000)
    {
        printf("watchapp-watch-FAIL (%lu)\n", (unsigned long)count);
        return 1;
    }
    printf("watchapp-watch-3\n");

    if (ResetWriteWatch(base, size) != 0)
    {
        printf("watchapp-reset-FAIL\n");
        return 1;
    }
    count = PAGES;
    if (GetWriteWatch(0, base, size, addresses, &count, &granularity) != 0 || count != 0)
    {
        printf("watchapp-clean-FAIL (%lu)\n", (unsigned long)count);
        return 1;
    }
    base[5 * 0x1000] = 1;
    count = PAGES;
    if (GetWriteWatch(WRITE_WATCH_FLAG_RESET, base, size, addresses, &count, &granularity) != 0 ||
        count != 1 || addresses[0] != base + 5 * 0x1000)
    {
        printf("watchapp-redirty-FAIL (%lu)\n", (unsigned long)count);
        return 1;
    }
    printf("watchapp-reset-ok\n");

    /* A kernel-side write (ReadFile into a watched page) marks too. */
    {
        HANDLE file = CreateFileA("C:\\watchapp.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD moved = 0;
        static const char payload[] = "watch this";
        if (file == INVALID_HANDLE_VALUE ||
            !WriteFile(file, payload, sizeof(payload), &moved, NULL) ||
            SetFilePointer(file, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
            !ReadFile(file, base + 2 * 0x1000, sizeof(payload), &moved, NULL))
        {
            printf("watchapp-read-setup-FAIL\n");
            return 1;
        }
        CloseHandle(file);
        DeleteFileA("C:\\watchapp.tmp");
        count = PAGES;
        if (GetWriteWatch(0, base, size, addresses, &count, &granularity) != 0 || count != 1 ||
            addresses[0] != base + 2 * 0x1000 ||
            memcmp(base + 2 * 0x1000, payload, sizeof(payload)) != 0)
        {
            printf("watchapp-read-FAIL (%lu)\n", (unsigned long)count);
            return 1;
        }
        printf("watchapp-read-ok\n");
    }

    VirtualFree(base, 0, MEM_RELEASE);
    printf("watchapp-done\n");
    fflush(stdout);
    return 0;
}
