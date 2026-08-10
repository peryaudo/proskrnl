/* tests/cui/hello32.c — the WOW64 milestone's acceptance client (docs/02:
 * "Done when: a 32-bit CUI app runs").
 *
 * An ordinary 32-bit Win32 console program: built by the i686 mingw cross
 * against the SAME Wine import libraries the 64-bit CUI clients use, with a
 * full CRT above them. Nothing here knows it is running under WOW64 — that
 * is the point. It reaches the kernel only the way any Win32 app does, and
 * every syscall it makes has travelled guest -> wow64cpu -> wow64.dll ->
 * the 64-bit ntdll before arriving.
 *
 * It prints one marker line the run.sh leg greps for, then reports what it
 * believes about itself so a WRONG answer is visible rather than silent:
 * IsWow64Process must be true, and the pointer width must be 4.
 *
 * It also checks the one piece of thread furniture only a GUEST can see: the
 * skip flags NtCreateThreadEx records land in the 32-bit TEB, not just in the
 * 64-bit one behind it (sem_ps/thread_skip_flags.c pins the 64-bit half on the
 * oracle; there is no 32-bit ntapi harness, so the guest half is checked here,
 * where the same binary runs under the pinned wine AND under proskrnl —
 * `WINEPREFIX=... third_party/wine/wine build/modules/hello32.exe` is the
 * oracle arm, tests/run/run.sh wow64 the kernel one).
 */
#include <windows.h>
#include <stdio.h>

/* NtCreateThreadEx's flags word and the PsAttributeTebAddress write-back
 * (PsAttributeTebAddress 4 | PS_ATTRIBUTE_THREAD 0x10000) — third_party/wine
 * include/winternl.h, and abi/ntpsapi.h's generated constants. The write-back
 * a GUEST gets is the 32-bit TEB: dlls/wow64/process.c put_ps_attributes hands
 * back `PtrToUlong( *teb ) + 0x2000`. SameTebFlags sits at 0xfca in that TEB
 * (winternl.h `USHORT SameTebFlags; /​* fca/17ee *​/`, abi/ntwow64.h's TEB32),
 * and SkipLoaderInit is bit 14 of it. G8: re-verify in those two headers. */
#define PS_CREATE_SUSPENDED         0x00000001
#define PS_CREATE_SKIP_LOADER_INIT  0x00000020
#define PS_ATTRIBUTE_TEB_ADDRESS_   0x00010004
#define TEB32_SAME_TEB_FLAGS_OFFSET 0x0fca
#define TEB_SKIP_LOADER_INIT        0x4000

typedef struct
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    ULONG_PTR Value;
    SIZE_T *ReturnLength;
} ps_attribute;

typedef struct
{
    SIZE_T TotalLength;
    ps_attribute Attributes[1];
} ps_attribute_list;

typedef LONG(WINAPI *create_thread_ex)(HANDLE *, DWORD, void *, HANDLE, void *, void *, ULONG,
                                       ULONG_PTR, SIZE_T, SIZE_T, void *);

static DWORD WINAPI idle32(LPVOID unused)
{
    (void)unused;
    return 0;
}

/* A suspended thread created with SKIP_LOADER_INIT must carry the bit in the
 * TEB the 32-bit loader will read. Suspended because "before it runs" is the
 * only state in which the flag still means anything. */
static int guest_skip_loader_init(void)
{
    create_thread_ex createThreadEx;
    ps_attribute_list attributes;
    HANDLE thread = NULL;
    void *teb = NULL;
    unsigned short word;
    LONG status;

    createThreadEx =
        (create_thread_ex)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (createThreadEx == NULL)
    {
        printf("hello32: FAIL no NtCreateThreadEx\n");
        return 0;
    }

    memset(&attributes, 0, sizeof(attributes));
    attributes.TotalLength = sizeof(attributes);
    attributes.Attributes[0].Attribute = PS_ATTRIBUTE_TEB_ADDRESS_;
    attributes.Attributes[0].Size = sizeof(teb);
    attributes.Attributes[0].Value = (ULONG_PTR)&teb;
    status =
        createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (void *)idle32, NULL,
                       PS_CREATE_SUSPENDED | PS_CREATE_SKIP_LOADER_INIT, 0, 0, 0, &attributes);
    if (status != 0)
    {
        printf("hello32: FAIL NtCreateThreadEx -> %08lx\n", (unsigned long)status);
        return 0;
    }
    if (teb == NULL)
    {
        printf("hello32: FAIL no TEB address back from NtCreateThreadEx\n");
        TerminateThread(thread, 0);
        CloseHandle(thread);
        return 0;
    }
    word = *(volatile unsigned short *)((char *)teb + TEB32_SAME_TEB_FLAGS_OFFSET);
    TerminateThread(thread, 0);
    CloseHandle(thread);

    printf("hello32: guest SameTebFlags=%04x\n", (unsigned)word);
    if (!(word & TEB_SKIP_LOADER_INIT))
    {
        printf("hello32: FAIL SKIP_LOADER_INIT never reached the 32-bit TEB\n");
        return 0;
    }
    return 1;
}

int main(void)
{
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);

    printf("hello32: pointer=%u wow64=%d\n", (unsigned)sizeof(void *), wow64 ? 1 : 0);
    fflush(stdout);

    if (sizeof(void *) != 4)
    {
        printf("hello32: FAIL not a 32-bit process\n");
        fflush(stdout);
        return 2;
    }
    if (!wow64)
    {
        printf("hello32: FAIL IsWow64Process says no\n");
        fflush(stdout);
        return 3;
    }

    /* A heap round trip and a Win32 call with a real return value, so the
     * marker cannot be printed by a process that died right after entry. */
    char *buffer = HeapAlloc(GetProcessHeap(), 0, 64);
    if (buffer == NULL)
    {
        printf("hello32: FAIL HeapAlloc\n");
        fflush(stdout);
        return 4;
    }
    DWORD length = GetCurrentDirectoryA(64, buffer);
    HeapFree(GetProcessHeap(), 0, buffer);
    if (length == 0)
    {
        printf("hello32: FAIL GetCurrentDirectoryA\n");
        fflush(stdout);
        return 5;
    }

    if (!guest_skip_loader_init())
    {
        fflush(stdout);
        return 6;
    }

    printf("hello32: OK\n");
    fflush(stdout);
    return 0;
}
