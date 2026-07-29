/* tests/boot/alloc_wait.c — the M4 "Done when" client (docs/02):
 * user-mode code allocates memory and waits on an event via syscalls.
 *
 * A flat binary issuing raw Nt* through the generated stubs
 * (tests/ntapi/syscall). Returns 0 on success; any failed step returns a
 * nonzero code the kernel's boot-module runner reports as a FAIL. It also
 * writes a human line through NtDisplayString to prove that path.
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntmmapi.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"

/* NtCurrentProcess() comes from abi/ntdef.h (the pseudo-handle macro is part
 * of the generated contract). */

static void say(const char *ascii)
{
    WCHAR wide[64];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 63)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

int main(void)
{
    /* TEB self-check: gs:[0x30] is NT_TIB.Self (offset pinned by the
     * offsetof(NT_TIB, Self) == 48 static_assert in abi/ntpsapi.h) and must
     * point at the TEB. */
    void *self;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(self));
    if (self == 0)
    {
        return 1;
    }

    /* Reserve+commit a page, then read/write it — a fault here would be a
     * containment failure, not a clean exit. */
    void *base = 0;
    SIZE_T size = 0x2000;
    NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size,
                                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || base == 0)
    {
        return 2;
    }
    volatile unsigned char *p = base;
    if (p[0] != 0 || p[0x1FFF] != 0) /* demand-zeroed */
    {
        return 3;
    }
    p[0] = 0x5a;
    p[0x1FFF] = 0xa5;
    if (p[0] != 0x5a || p[0x1FFF] != 0xa5)
    {
        return 4;
    }

    /* Query the committed region back. */
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T retlen = 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), base, MemoryBasicInformation, &mbi,
                                  sizeof(mbi), &retlen);
    if (status != STATUS_SUCCESS || mbi.State != MEM_COMMIT || retlen != sizeof(mbi))
    {
        return 5;
    }

    /* Create an event, signal it, wait with a zero timeout: the satisfied
     * wait must return immediately (proving the wait syscall path). */
    HANDLE event;
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, 0, SynchronizationEvent, FALSE);
    if (status != STATUS_SUCCESS)
    {
        return 6;
    }
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (NtWaitForSingleObject(event, FALSE, &zero) != STATUS_TIMEOUT)
    {
        return 7; /* unsignalled: must time out */
    }
    if (NtSetEvent(event, 0) != STATUS_SUCCESS)
    {
        return 8;
    }
    if (NtWaitForSingleObject(event, FALSE, &zero) != STATUS_SUCCESS)
    {
        return 9; /* signalled: must succeed */
    }
    NtClose(event);

    /* A bad user pointer to a syscall must come back as a status, not a
     * kernel fault. */
    if (NtSetEvent((HANDLE)0x4, 0) != STATUS_INVALID_HANDLE)
    {
        return 10;
    }
    HANDLE dummy;
    if (NtCreateEvent(&dummy, EVENT_ALL_ACCESS, 0, SynchronizationEvent, FALSE) == STATUS_SUCCESS &&
        NtSetEvent(dummy, (PLONG)0x30000000) != STATUS_ACCESS_VIOLATION)
    {
        return 11; /* aligned but unmapped out-pointer -> STATUS_ACCESS_VIOLATION */
    }

    NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_RELEASE);

    say("[KTEST] user alloc_wait PASS\n");
    return 0;
}
