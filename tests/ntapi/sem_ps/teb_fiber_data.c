/*
 * sem_ps/teb_fiber_data.c — NT_TIB.FiberData reads 0x1e00 on a thread that is
 * not a fiber.
 *
 * The value is furniture, not a pointer: kernelbase gates every fiber entry
 * point on TEB.HasFiberData and only reads FiberData inside that gate
 * (third_party/wine dlls/kernelbase/thread.c), so nothing dereferences the
 * 0x1e00. What makes it a contract anyway is that user mode READS it —
 * kernel32:fiber's test_FiberHandling opens with
 *
 *     ok( !NtCurrentTeb()->HasFiberData, "already a fiber\n" );
 *     ok( NtCurrentTeb()->Tib.FiberData == (void *)0x1e00, "wrong data %p\n", ... );
 *
 * (fiber.c:202-:203) before it creates anything, so a zero here is a wrong
 * answer on a thread that has run no user code at all.
 *
 * WHERE IT COMES FROM IS THE TRANSFERABLE PART. The seed is written by
 * `init_teb` (third_party/wine dlls/ntdll/unix/virtual.c), one line below the
 * ActivationContextStack and StaticUnicodeString furniture — i.e. by the
 * unixlib half proskrnl REPLACES. That is docs/21 W12's rule a third time:
 * replacing a layer means inheriting everything that layer PERFORMED, and the
 * tell is a kernel TEB constructor that mirrors some of `init_teb` and not
 * all of it.
 *
 * The oracle answers this on both a first thread and a created one, so this
 * is an ordinary G5 pin with nothing beyond_oracle in it.
 */
#include "util.h"

#include <windows.h> /* NT_TIB, NtCurrentTeb */

NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

/* The value dlls/ntdll/unix/virtual.c init_teb writes; re-verify there, not
 * from memory (G8). */
#define PS_TIB_FIBER_DATA_SEED ((ULONG_PTR)0x1e00)

static ULONG_PTR childFiberData;
static ULONG_PTR childReady;

static DWORD WINAPI child(LPVOID unused)
{
    (void)unused;
    childFiberData = (ULONG_PTR)((NT_TIB *)NtCurrentTeb())->FiberData;
    childReady = 1;
    return 0;
}

START_TEST(teb_fiber_data)
{
    HANDLE thread;

    ok((ULONG_PTR)((NT_TIB *)NtCurrentTeb())->FiberData == PS_TIB_FIBER_DATA_SEED,
       "main thread: FiberData %llx, wanted %llx",
       (unsigned long long)(ULONG_PTR)((NT_TIB *)NtCurrentTeb())->FiberData,
       (unsigned long long)PS_TIB_FIBER_DATA_SEED);

    /* And on a thread whose TEB was built later, by the same constructor: a
     * seed applied only to the first thread of a process would pass the line
     * above and fail here. */
    childFiberData = 0;
    childReady = 0;
    thread = CreateThread(NULL, 0, child, NULL, 0, NULL);
    ok(thread != NULL, "CreateThread -> %lu", (unsigned long)GetLastError());
    if (thread == NULL)
    {
        return;
    }
    ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "the child did not exit");
    NtClose(thread);
    ok(childReady == 1, "the child never ran");
    ok(childFiberData == PS_TIB_FIBER_DATA_SEED, "created thread: FiberData %llx, wanted %llx",
       (unsigned long long)childFiberData, (unsigned long long)PS_TIB_FIBER_DATA_SEED);
}
