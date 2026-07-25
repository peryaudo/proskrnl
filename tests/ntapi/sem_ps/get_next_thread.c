/*
 * sem_ps/get_next_thread.c — NtGetNextThread: the loader's TLS walk
 * (dlls/ntdll/loader.c alloc_tls_slot enumerates every running thread when
 * a TLS-bearing DLL is loaded at runtime — hello_crt.exe's msvcrt load
 * convicted its absence). Contract from wineserver's get_next_thread
 * (server/thread.c): flags > 1 -> STATUS_INVALID_PARAMETER; last = 0
 * starts the walk at the head of creation order; each success returns a
 * NEW handle to the process's next thread; the walk ends with
 * STATUS_NO_MORE_ENTRIES. Green on the pinned Wine oracle first (Art. 5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtGetNextThread(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, HANDLE *);

START_TEST(get_next_thread)
{
    NTSTATUS status;
    HANDLE handles[16];
    HANDLE next, last;
    int count = 0;

    /* Only forward (0) and backward (1) walks exist. */
    next = NULL;
    status =
        NtGetNextThread(NtCurrentProcess(), NULL, THREAD_QUERY_LIMITED_INFORMATION, 0, 2, &next);
    ok(status == STATUS_INVALID_PARAMETER, "flags 2 -> %08lx", (unsigned long)status);

    /* Forward walk over the current process: at least this thread, each
     * step a fresh handle, then NO_MORE_ENTRIES. */
    last = NULL;
    for (;;)
    {
        next = NULL;
        status = NtGetNextThread(NtCurrentProcess(), last, THREAD_QUERY_LIMITED_INFORMATION, 0, 0,
                                 &next);
        if (status != STATUS_SUCCESS || count >= 16)
        {
            break;
        }
        ok(next != NULL, "walk step %d returned a null handle", count);
        handles[count++] = next;
        last = next;
    }
    ok(status == STATUS_NO_MORE_ENTRIES, "walk end -> %08lx", (unsigned long)status);
    ok(count >= 1, "no threads enumerated");
    while (count > 0)
    {
        NtClose(handles[--count]);
    }
}
