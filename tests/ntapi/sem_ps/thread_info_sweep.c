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
#ifndef ThreadGroupInformation
#define ThreadGroupInformation    ((THREADINFOCLASS)30)
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
/* THREAD_BASIC_INFORMATION, as the pinned tree spells it; mingw's omits
 * it from winternl.h. Only ClientId and the size are used here. */
typedef struct
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    struct
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} NTAPI_THREAD_BASIC_INFORMATION;

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

NTSYSAPI NTSTATUS NTAPI NtOpenThread(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *,
                                     const CLIENT_ID *);

START_TEST(thread_info_sweep)
{
    NTSTATUS status;
    ULONG returnLength;
    BOOLEAN hidden;
    HANDLE self = (HANDLE)(LONG_PTR)-2; /* NtCurrentThread */

    /* --- a LIMITED-access handle can still query -------------------------
     * kernel32:thread opens with OpenThread(THREAD_QUERY_LIMITED_INFORMATION)
     * and then sweeps every class through it. NT's thread type grants the
     * limited right to anyone holding the full one and vice-versa for the
     * classes that only need the limited one — the oracle spells the
     * implication out in server/thread.c thread_map_access, and its
     * get_thread_info handler DEFAULTS to the limited right when the caller
     * names none. A kernel that demands the full right refuses the whole
     * sweep with STATUS_ACCESS_DENIED. */
    {
        HANDLE limited = NULL;
        OBJECT_ATTRIBUTES attr;
        CLIENT_ID id;
        memset(&attr, 0, sizeof(attr));
        attr.Length = sizeof(attr);
        NTAPI_THREAD_BASIC_INFORMATION selfBasic;
        memset(&selfBasic, 0, sizeof(selfBasic));
        status = NtQueryInformationThread(self, ThreadBasicInformation, &selfBasic,
                                          sizeof(selfBasic), &returnLength);
        ok(status == STATUS_SUCCESS, "self basic info -> %08lx", (unsigned long)status);
        id.UniqueProcess = NULL;
        id.UniqueThread = selfBasic.ClientId.UniqueThread;
        status = NtOpenThread(&limited, THREAD_QUERY_LIMITED_INFORMATION, &attr, &id);
        ok(status == STATUS_SUCCESS, "open limited thread handle -> %08lx",
           (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NTAPI_KERNEL_USER_TIMES times;
            returnLength = 0;
            status = NtQueryInformationThread(limited, ThreadTimes, &times, sizeof(times),
                                              &returnLength);
            ok(status == STATUS_SUCCESS, "ThreadTimes via limited handle -> %08lx",
               (unsigned long)status);

            NTAPI_THREAD_BASIC_INFORMATION basic;
            status = NtQueryInformationThread(limited, ThreadBasicInformation, &basic,
                                              sizeof(basic), &returnLength);
            ok(status == STATUS_SUCCESS, "ThreadBasicInformation via limited handle -> %08lx",
               (unsigned long)status);

            /* ...but the limited right is NOT a skeleton key. kernel32:thread
             * expects everything outside the small limited-queryable set to
             * be REFUSED through this handle (thread.c's `default:` arm), so
             * a class that answers without checking answers a caller that
             * was never entitled to ask — including the classes whose value
             * needs no thread state at all. */
            ULONG_PTR affinity = 0;
            status = NtQueryInformationThread(limited, ThreadAffinityMask, &affinity,
                                              sizeof(affinity), &returnLength);
            ok(status == STATUS_ACCESS_DENIED, "ThreadAffinityMask via limited handle -> %08lx",
               (unsigned long)status);

            BOOLEAN hiddenLimited = FALSE;
            status = NtQueryInformationThread(limited, ThreadHideFromDebugger, &hiddenLimited,
                                              sizeof(hiddenLimited), &returnLength);
            ok(status == STATUS_ACCESS_DENIED,
               "ThreadHideFromDebugger via limited handle -> %08lx", (unsigned long)status);

            ULONG boostLimited = 0;
            status = NtQueryInformationThread(limited, ThreadPriorityBoost, &boostLimited,
                                              sizeof(boostLimited), &returnLength);
            ok(status == STATUS_SUCCESS, "ThreadPriorityBoost via limited handle -> %08lx",
               (unsigned long)status);
            NtClose(limited);
        }
    }

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

    /* --- ThreadPriorityBoost round-trips ---------------------------------
     * proskrnl does no priority boosting, so nothing acts on this flag —
     * but the query must return what the set stored, or the pair disagrees
     * with itself, which is the silent-plausible answer a stub gives. */
    {
        ULONG disableBoost = 0xdead;
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadPriorityBoost, &disableBoost,
                                          sizeof(disableBoost), &returnLength);
        ok(status == STATUS_SUCCESS, "query boost -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(ULONG), "boost returned %lu bytes",
           (unsigned long)returnLength);
        ok(disableBoost == 0, "boost starts disabled (%lu)", (unsigned long)disableBoost);

        ULONG disable = 1;
        status = NtSetInformationThread(self, ThreadPriorityBoost, &disable, sizeof(disable));
        ok(status == STATUS_SUCCESS, "set boost -> %08lx", (unsigned long)status);
        disableBoost = 0xdead;
        status = NtQueryInformationThread(self, ThreadPriorityBoost, &disableBoost,
                                          sizeof(disableBoost), &returnLength);
        ok(status == STATUS_SUCCESS, "re-query boost -> %08lx", (unsigned long)status);
        ok(disableBoost == 1, "boost flag did not stick (%lu)", (unsigned long)disableBoost);

        status = NtQueryInformationThread(self, ThreadPriorityBoost, &disableBoost, 1,
                                          &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short boost -> %08lx", (unsigned long)status);
    }

    /* --- ThreadIsIoPending: the oracle's own fixed FALSE ------------------
     * The oracle is a declared stub here (FIXME + hardwired FALSE), which
     * is the one case Art. 12 lets a fixed answer stand: it is pinned
     * ORACLE behaviour, so reproducing it is reproducing the boundary. The
     * NULL-buffer status is the detail worth pinning — ACCESS_DENIED, not
     * the ACCESS_VIOLATION most classes give. */
    {
        BOOL pending = TRUE;
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadIsIoPending, &pending, sizeof(pending),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "ThreadIsIoPending -> %08lx", (unsigned long)status);
        ok(pending == FALSE, "ThreadIsIoPending reported pending I/O");
        ok(returnLength == sizeof(BOOL), "returned %lu bytes", (unsigned long)returnLength);

        status = NtQueryInformationThread(self, ThreadIsIoPending, NULL, sizeof(pending),
                                          &returnLength);
        ok(status == STATUS_ACCESS_DENIED, "NULL buffer -> %08lx", (unsigned long)status);

        status = NtQueryInformationThread(self, ThreadIsIoPending, &pending, 1, &returnLength);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short -> %08lx", (unsigned long)status);
    }

    /* --- ThreadGroupInformation: the group form of the same one bit -----
     * Group 0 always — a processor group holds at most 64 processors and
     * this machine has one, which is why the oracle hardcodes the group
     * too. Truncates on a short buffer, like ThreadAffinityMask. */
    {
        struct
        {
            ULONG_PTR Mask;
            USHORT Group;
            USHORT Reserved[3];
        } group;
        memset(&group, 0xcc, sizeof(group));
        returnLength = 0;
        status = NtQueryInformationThread(self, ThreadGroupInformation, &group, sizeof(group),
                                          &returnLength);
        ok(status == STATUS_SUCCESS, "ThreadGroupInformation -> %08lx", (unsigned long)status);
        ok(returnLength == sizeof(group), "group returned %lu bytes",
           (unsigned long)returnLength);
        ok(group.Group == 0, "group %u, expected 0", (unsigned)group.Group);
        ok(group.Mask != 0, "group affinity mask is empty");
    }

    /* --- two classes the ORACLE ITSELF calls invalid ---------------------
     * ThreadIdealProcessor and ThreadEnableAlignmentFaultFixup share an
     * explicit `return STATUS_INVALID_INFO_CLASS;` arm in the oracle,
     * separate from its FIXME/NOT_IMPLEMENTED group
     * (dlls/ntdll/unix/thread.c). Wine draws the same distinction this
     * kernel draws, so these are pinned NORMALLY — no beyond_oracle needed,
     * and they are the evidence that the split is the boundary's own idea
     * and not ours. */
    {
        ULONG value = 0;
        status = NtQueryInformationThread(self, ThreadIdealProcessor, &value, sizeof(value),
                                          &returnLength);
        ok(status == STATUS_INVALID_INFO_CLASS, "ThreadIdealProcessor -> %08lx",
           (unsigned long)status);
        BOOLEAN flag = FALSE;
        status = NtQueryInformationThread(self, ThreadEnableAlignmentFaultFixup, &flag,
                                          sizeof(flag), &returnLength);
        ok(status == STATUS_INVALID_INFO_CLASS, "ThreadEnableAlignmentFaultFixup -> %08lx",
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
