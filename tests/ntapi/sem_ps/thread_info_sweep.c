/*
 * sem_ps/thread_info_sweep.c — the thread info classes a suite SWEEPS.
 *
 * W2a of docs/21. `dlls/kernel32/tests/thread.c` test_thread_info walks
 * every THREADINFOCLASS from 0 upward and tolerates a refusal:
 *
 *     status = pNtQueryInformationThread( thread, i, buf, info_size[i], &ret_len );
 *     if (status == STATUS_NOT_IMPLEMENTED)   continue;
 *     if (status == STATUS_INVALID_INFO_CLASS) continue;
 *     if (status == STATUS_UNSUCCESSFUL)       continue;
 *
 * proskrnl cannot answer the first of those three to anything — the armed
 * boot makes it a panic (Art. 12) — so every class in the sweep has to
 * answer either its value or one of the other two. That is the whole item.
 *
 * Two groups, and they are pinned differently:
 *
 *   ThreadHideFromDebugger is a REAL per-thread flag the oracle implements
 *   (dlls/ntdll/unix/thread.c), so it is pinned normally, including the
 *   documented ordering quirk its own comment describes: the class touches
 *   *ret_len BEFORE any other check, so an unwritable ret_len is
 *   STATUS_ACCESS_VIOLATION even when the length is also wrong. "TP Shell
 *   Service depends on" it, per that comment — it is observable, so it is
 *   the contract.
 *
 *   ThreadPriority, ThreadBasePriority, ThreadImpersonationToken,
 *   ThreadEventPair_Reusable, ThreadZeroTlsCell, ThreadPerformanceCount and
 *   ThreadSetTlsArrayAddress are the set-only/obsolete group the oracle
 *   REFUSES (they share its `FIXME(...); return STATUS_NOT_IMPLEMENTED;`
 *   arm). An oracle answering NOT_IMPLEMENTED is unbuilt, not authoritative
 *   (G12), so those go in a beyond_oracle block: proskrnl answers
 *   STATUS_INVALID_INFO_CLASS, which is what a non-queryable class is, and
 *   which the sweep above accepts by name.
 */
#include "../ntapi.h"

/* THREADINFOCLASS values mingw's winternl.h omits, spelled exactly as the
 * pinned tree spells them (third_party/wine/include/winternl.h, the
 * _THREADINFOCLASS enum) — the same convention sem_port/timers.c uses for
 * TIMER_TYPE. In proskrnl mode abi/ntpsapi.h already defines them, so these
 * only fill the oracle build's gap. */
#ifndef ThreadEventPair_Reusable
#define ThreadEventPair_Reusable  ((THREADINFOCLASS)8)
#endif
#ifndef ThreadZeroTlsCell
#define ThreadZeroTlsCell         ((THREADINFOCLASS)10)
#endif
#ifndef ThreadPerformanceCount
#define ThreadPerformanceCount    ((THREADINFOCLASS)11)
#endif
#ifndef ThreadSetTlsArrayAddress
#define ThreadSetTlsArrayAddress  ((THREADINFOCLASS)15)
#endif
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger    ((THREADINFOCLASS)17)
#endif

/* KERNEL_USER_TIMES with LARGE_INTEGER members, as the pinned tree spells
 * it (third_party/wine/include/winternl.h) — mingw's winternl.h declares
 * the same four fields as FILETIME, which is the same 32 bytes with a less
 * convenient shape. Local so both builds agree. */
typedef struct
{
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} NTAPI_KERNEL_USER_TIMES;

/* THREAD_DESCRIPTOR_INFORMATION, as the pinned tree spells it
 * (third_party/wine/include/winternl.h) — mingw's winternl.h omits it.
 * Only Selector is read here; the LDT_ENTRY tail is padding for the length
 * the class requires. */
typedef struct
{
    DWORD Selector;
    UCHAR Entry[8]; /* sizeof(LDT_ENTRY) */
} NTAPI_THREAD_DESCRIPTOR_INFORMATION;

/* The set-only / obsolete group: queried, never queryable. */
static const struct
{
    THREADINFOCLASS cls;
    const char *name;
} refused[] = {
    {ThreadPriority, "ThreadPriority"},
    {ThreadBasePriority, "ThreadBasePriority"},
    {ThreadImpersonationToken, "ThreadImpersonationToken"},
    {ThreadEventPair_Reusable, "ThreadEventPair_Reusable"},
    {ThreadZeroTlsCell, "ThreadZeroTlsCell"},
    {ThreadPerformanceCount, "ThreadPerformanceCount"},
    {ThreadSetTlsArrayAddress, "ThreadSetTlsArrayAddress"},
};

START_TEST(thread_info_sweep)
{
    NTSTATUS status;
    ULONG returnLength;
    BOOLEAN hidden;
    HANDLE self = (HANDLE)(LONG_PTR)-2; /* NtCurrentThread */

    /* --- ThreadHideFromDebugger: a real flag, and it starts clear -------- */
    returnLength = 0;
    hidden = TRUE;
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden),
                                      &returnLength);
    ok(status == STATUS_SUCCESS, "query hide-from-debugger -> %08lx", (unsigned long)status);
    ok(hidden == FALSE, "thread starts hidden");
    ok(returnLength == sizeof(BOOLEAN), "returned %lu bytes", (unsigned long)returnLength);

    /* A wrong length is a length complaint. */
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden) + 1,
                                      &returnLength);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "wrong length -> %08lx", (unsigned long)status);

    /* ...but an unwritable ret_len beats it, because the class touches
     * ret_len first. Both wrong at once: ACCESS_VIOLATION wins. */
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden) + 1,
                                      (PULONG)(ULONG_PTR)4);
    ok(status == STATUS_ACCESS_VIOLATION, "unwritable ret_len -> %08lx", (unsigned long)status);

    /* --- setting it takes a ZERO length, and the query sees it ----------- */
    status = NtSetInformationThread(self, ThreadHideFromDebugger, NULL, 0);
    ok(status == STATUS_SUCCESS, "set hide-from-debugger -> %08lx", (unsigned long)status);
    hidden = FALSE;
    status = NtQueryInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden),
                                      &returnLength);
    ok(status == STATUS_SUCCESS, "re-query -> %08lx", (unsigned long)status);
    ok(hidden == TRUE, "flag did not stick");

    /* A non-zero length on the SET side is a length complaint. */
    status = NtSetInformationThread(self, ThreadHideFromDebugger, &hidden, sizeof(hidden));
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "set with length -> %08lx", (unsigned long)status);

    /* --- ThreadTimes TRUNCATES; it does not reject a short buffer -------
     * The oracle copies `min(length, sizeof(kusrt))` and reports that same
     * min as the returned length (dlls/ntdll/unix/thread.c), with no
     * INFO_LENGTH_MISMATCH arm at all — so a 8-byte buffer is a SUCCESS
     * carrying only CreateTime. That is unusual enough among the info
     * classes to be worth pinning explicitly. */
    {
        NTAPI_KERNEL_USER_TIMES times;
        memset(&times, 0xcc, sizeof(times));
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadTimes, &times, sizeof(times),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "ThreadTimes -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(times), "ThreadTimes returned %lu bytes",
           (unsigned long)returnLength);
        ok(times.CreateTime.QuadPart != 0, "CreateTime is zero");
        ok(times.ExitTime.QuadPart == 0, "a live thread has an ExitTime");
        ok(times.KernelTime.QuadPart >= 0 && times.UserTime.QuadPart >= 0,
           "negative kernel/user time");

        /* Short buffer: truncated, not refused. */
        LARGE_INTEGER firstOnly;
        firstOnly.QuadPart = 0;
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadTimes, &firstOnly, sizeof(firstOnly),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "ThreadTimes short -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(firstOnly), "ThreadTimes short returned %lu bytes",
           (unsigned long)returnLength);
        ok(firstOnly.QuadPart == times.CreateTime.QuadPart, "short copy is not CreateTime");
    }

    /* --- ThreadAffinityMask: one CPU, so one bit ------------------------
     * Art. 3's uniprocessor mandate makes this answer trivially true rather
     * than approximate — a single-processor machine's affinity mask IS 1,
     * and that is a fact about the machine, not a stub standing in for
     * something richer. The oracle truncates rather than refusing a short
     * buffer here too (`min(length, sizeof(affinity))`, no length gate). */
    {
        ULONG_PTR affinity = 0;
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadAffinityMask, &affinity, sizeof(affinity),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "ThreadAffinityMask -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(affinity), "affinity returned %lu bytes",
           (unsigned long)returnLength);
        ok(affinity != 0, "affinity mask is empty");
    }

    /* --- ThreadDescriptorTableEntry: a GDT selector has no LDT entry ----
     * The sweep passes a ZEROED THREAD_DESCRIPTOR_INFORMATION, so Selector
     * is 0 — and the oracle rejects it before ever touching an LDT:
     * `if (info->Selector >> 16) return STATUS_UNSUCCESSFUL;` then
     * `if (is_gdt_sel( info->Selector )) return STATUS_UNSUCCESSFUL;`,
     * where is_gdt_sel is `!(sel & 4)` (unix_private.h). Selector 0 has the
     * table-indicator bit clear, so it names the GDT, and asking for a GDT
     * selector's LDT entry is STATUS_UNSUCCESSFUL — which the sweep accepts
     * by name.
     *
     * Only that half is pinned. An LDT selector is a 32-bit concept and
     * WOW64 is a later milestone (docs/02), so proskrnl has no LDT to
     * answer from and keeps the loud refusal there rather than inventing an
     * entry (Art. 12). */
    {
        NTAPI_THREAD_DESCRIPTOR_INFORMATION descriptor;
        memset(&descriptor, 0, sizeof(descriptor));
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadDescriptorTableEntry, &descriptor,
                                          sizeof(descriptor), &returnLength);
        ok(status == STATUS_UNSUCCESSFUL, "GDT selector 0 -> %08lx", (unsigned long)status);

        /* A selector above 16 bits is refused first, and the same way. */
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.Selector = 0x10000;
        status = NtQueryInformationThread(self, ThreadDescriptorTableEntry, &descriptor,
                                          sizeof(descriptor), &returnLength);
        ok(status == STATUS_UNSUCCESSFUL, "oversized selector -> %08lx", (unsigned long)status);

        /* ...and a wrong length beats both. */
        status = NtQueryInformationThread(self, ThreadDescriptorTableEntry, &descriptor,
                                          sizeof(descriptor) - 1, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short descriptor -> %08lx",
           (unsigned long)status);
    }

    /* --- the set-only group refuses, and NOT with NOT_IMPLEMENTED -------- */
    beyond_oracle
    {
        for (unsigned i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
        {
            UCHAR buffer[32];
            returnLength = 0;
            status = NtQueryInformationThread(self, refused[i].cls, buffer, sizeof(buffer),
                                              &returnLength);
            ok(status == STATUS_INVALID_INFO_CLASS, "%s query -> %08lx", refused[i].name,
               (unsigned long)status);
        }
    }
}
