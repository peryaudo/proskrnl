/*
 * sem_ps/proc_classes.c — ProcessPriorityClass, ProcessHandleCount,
 * ProcessImageFileName and ThreadQuerySetWin32StartAddress (CUI-6).
 *
 * The Get/SetPriorityClass, GetProcessHandleCount, process-image-path and
 * Win32StartAddress surfaces. Oracle behaviour pinned from the pinned
 * tree (dlls/ntdll/unix/{process,thread}.c; server/process.c): the
 * priority class wants its 2-byte struct exactly (query refuses other
 * sizes with STATUS_INFO_LENGTH_MISMATCH, set with
 * STATUS_INVALID_PARAMETER), a fresh process is PROCESS_PRIOCLASS_NORMAL
 * with Foreground FALSE, and a set round-trips; the handle count writes
 * its ULONG for size >= 4 but ALSO refuses when size > 4, and a short
 * buffer refuses with length 4 — the oracle fabricates the value 0 under
 * its own FIXME, so the real nonzero count is beyond_oracle
 * (GetProcessHandleCount's documented contract: the number of open
 * handles in the process — learn.microsoft.com GetProcessHandleCount);
 * the image file name is a UNICODE_STRING plus NUL-terminated buffer in
 * NT (\??\...) form with the min-size refusal protocol; the Win32 start
 * address is nonzero for a live thread, its set wants sizeof(PVOID)
 * exactly, and a set round-trips through the query.
 */
#include "util.h"

#ifndef NtCurrentThread
#define NtCurrentThread() ((HANDLE) ~(ULONG_PTR)1)
#endif

#define PS_ProcessPriorityClass            ((PROCESSINFOCLASS)18)
#define PS_ProcessHandleCount              ((PROCESSINFOCLASS)20)
#define PS_ProcessImageFileName            ((PROCESSINFOCLASS)27)
#define PS_ProcessImageFileNameWin32       ((PROCESSINFOCLASS)43)
#define PS_ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)

/* wine/include/winternl.h PROCESS_PRIORITY_CLASS + PROCESS_PRIOCLASS_*. */
typedef struct
{
    BOOLEAN foreground;
    UCHAR priority_class;
} ps_priority_class;
#define PS_PRIOCLASS_NORMAL       2
#define PS_PRIOCLASS_BELOW_NORMAL 5

static int ends_with_insensitive(const WCHAR *haystack, ULONG haystackChars, const WCHAR *needle)
{
    ULONG needleChars = 0;
    while (needle[needleChars])
    {
        needleChars++;
    }
    if (haystackChars < needleChars)
    {
        return 0;
    }
    for (ULONG i = 0; i < needleChars; i++)
    {
        WCHAR a = haystack[haystackChars - needleChars + i];
        WCHAR b = needle[i];
        if (a >= 'A' && a <= 'Z')
        {
            a += 'a' - 'A';
        }
        if (b >= 'A' && b <= 'Z')
        {
            b += 'a' - 'A';
        }
        if (a != b)
        {
            return 0;
        }
    }
    return 1;
}

START_TEST(proc_classes)
{
    NTSTATUS status;
    ULONG retlen;

    /* --- ProcessPriorityClass --------------------------------------------- */
    ps_priority_class prio;
    memset(&prio, 0xcc, sizeof(prio));
    retlen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio,
                                       sizeof(prio), &retlen);
    ok(status == STATUS_SUCCESS, "query priority -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(prio), "priority retlen %lu", (unsigned long)retlen);
    ok(prio.priority_class == PS_PRIOCLASS_NORMAL, "fresh class %u", prio.priority_class);
    ok(prio.foreground == FALSE, "fresh foreground %u", prio.foreground);

    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio,
                                       sizeof(prio) + 2, NULL);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "oversized priority query -> %08lx",
       (unsigned long)status);

    /* Set wants the exact size too — with a different refusal status. */
    prio.foreground = FALSE;
    prio.priority_class = PS_PRIOCLASS_BELOW_NORMAL;
    status = NtSetInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio,
                                     sizeof(prio) + 2);
    ok(status == STATUS_INVALID_PARAMETER, "oversized priority set -> %08lx",
       (unsigned long)status);
    status =
        NtSetInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio, sizeof(prio));
    ok(status == STATUS_SUCCESS, "priority set -> %08lx", (unsigned long)status);
    memset(&prio, 0xcc, sizeof(prio));
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio,
                                       sizeof(prio), NULL);
    ok(status == STATUS_SUCCESS, "priority re-query -> %08lx", (unsigned long)status);
    ok(prio.priority_class == PS_PRIOCLASS_BELOW_NORMAL, "set round-trips %u", prio.priority_class);

    /* Restore for any later test sharing the process image. */
    prio.priority_class = PS_PRIOCLASS_NORMAL;
    NtSetInformationProcess(NtCurrentProcess(), PS_ProcessPriorityClass, &prio, sizeof(prio));

    /* --- ProcessHandleCount ------------------------------------------------ */
    ULONG handleCount = 0xdeadbeef;
    retlen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessHandleCount, &handleCount, 2,
                                       &retlen);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "short handle count -> %08lx", (unsigned long)status);
    ok(retlen == 4, "short handle count retlen %lu", (unsigned long)retlen);
    {
        /* size > 4 writes the value AND refuses. */
        char big[8];
        memset(big, 0xcc, sizeof(big));
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessHandleCount, big,
                                           sizeof(big), &retlen);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "long handle count -> %08lx",
           (unsigned long)status);
    }
    handleCount = 0xdeadbeef;
    retlen = 0;
    status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessHandleCount, &handleCount, 4,
                                       &retlen);
    ok(status == STATUS_SUCCESS, "handle count -> %08lx", (unsigned long)status);
    ok(retlen == 4, "handle count retlen %lu", (unsigned long)retlen);
    beyond_oracle
    {
        /* The oracle memsets 0 under its own FIXME; the documented contract
         * (GetProcessHandleCount, learn.microsoft.com) is the number of open
         * handles in the process — never 0 for a process holding any. */
        ok(handleCount > 0, "handle count %lu", (unsigned long)handleCount);
    }

    /* --- ProcessImageFileName ---------------------------------------------- */
    {
        char raw[sizeof(UNICODE_STRING) + 512 * sizeof(WCHAR)];
        UNICODE_STRING *str = (UNICODE_STRING *)raw;
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageFileName, raw,
                                           sizeof(UNICODE_STRING), &retlen);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short image name -> %08lx",
           (unsigned long)status);
        ok(retlen > sizeof(UNICODE_STRING), "short image name retlen %lu", (unsigned long)retlen);

        memset(raw, 0, sizeof(raw));
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageFileName, raw,
                                           sizeof(raw), &retlen);
        ok(status == STATUS_SUCCESS, "image name -> %08lx", (unsigned long)status);
        ok(str->Length > 0, "image name nonempty");
        ok(str->Buffer == (PWSTR)(str + 1), "buffer embedded after the struct");
        ok(str->MaximumLength == str->Length + sizeof(WCHAR), "max length %u vs %u",
           str->MaximumLength, str->Length);
        ok(str->Buffer[str->Length / sizeof(WCHAR)] == 0, "NUL terminated");
        ok(str->Length >= 4 * sizeof(WCHAR) && str->Buffer[0] == '\\' && str->Buffer[1] == '?' &&
               str->Buffer[2] == '?' && str->Buffer[3] == '\\',
           "NT \\??\\ form");
        ok(ends_with_insensitive(str->Buffer, str->Length / sizeof(WCHAR), L"proc_classes.exe"),
           "path names this image");
    }

    /* --- ProcessImageFileNameWin32 (AUD-2) --------------------------------- */
    /* The class-27 protocol with the NT prefix stripped: the pinned server
     * answers the same name and skips a leading \??\ for the win32 form
     * (dlls/ntdll/unix/process.c ProcessImageFileNameWin32 shares class
     * 27's fill; server/process.c get_process_image_name, req->win32).
     * Consumed by mmdevapi's audio-session machinery, which is how the
     * winetest render pair found it unbuilt (AUD-2 notes). */
    {
        char raw[sizeof(UNICODE_STRING) + 512 * sizeof(WCHAR)];
        char rawNt[sizeof(UNICODE_STRING) + 512 * sizeof(WCHAR)];
        UNICODE_STRING *str = (UNICODE_STRING *)raw;
        UNICODE_STRING *strNt = (UNICODE_STRING *)rawNt;
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageFileNameWin32, raw,
                                           sizeof(UNICODE_STRING), &retlen);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "short win32 image name -> %08lx",
           (unsigned long)status);
        ok(retlen > sizeof(UNICODE_STRING), "short win32 image name retlen %lu",
           (unsigned long)retlen);

        memset(raw, 0, sizeof(raw));
        retlen = 0;
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageFileNameWin32, raw,
                                           sizeof(raw), &retlen);
        ok(status == STATUS_SUCCESS, "win32 image name -> %08lx", (unsigned long)status);
        ok(str->Length > 0, "win32 image name nonempty");
        ok(str->Buffer == (PWSTR)(str + 1), "win32 buffer embedded after the struct");
        ok(str->MaximumLength == str->Length + sizeof(WCHAR), "win32 max length %u vs %u",
           str->MaximumLength, str->Length);
        ok(str->Buffer[str->Length / sizeof(WCHAR)] == 0, "win32 NUL terminated");
        ok(!(str->Length >= 4 * sizeof(WCHAR) && str->Buffer[0] == '\\' &&
             str->Buffer[1] == '?'),
           "win32 form carries no \\??\\ prefix");
        ok(ends_with_insensitive(str->Buffer, str->Length / sizeof(WCHAR), L"proc_classes.exe"),
           "win32 path names this image");

        /* Same name as the NT form, minus exactly its \??\ prefix. */
        memset(rawNt, 0, sizeof(rawNt));
        status = NtQueryInformationProcess(NtCurrentProcess(), PS_ProcessImageFileName, rawNt,
                                           sizeof(rawNt), NULL);
        ok(status == STATUS_SUCCESS, "nt image name re-query -> %08lx", (unsigned long)status);
        if (status == STATUS_SUCCESS && strNt->Length >= 4 * sizeof(WCHAR))
        {
            ok(strNt->Length == str->Length + 4 * sizeof(WCHAR),
               "win32 length %u is nt length %u minus the prefix", str->Length, strNt->Length);
            ok(memcmp(strNt->Buffer + 4, str->Buffer, str->Length) == 0,
               "win32 name is the nt name past the prefix");
        }
    }

    /* --- ThreadQuerySetWin32StartAddress ----------------------------------- */
    {
        PVOID entry = NULL;
        retlen = 0;
        status = NtQueryInformationThread(NtCurrentThread(), PS_ThreadQuerySetWin32StartAddress,
                                          &entry, sizeof(entry), &retlen);
        ok(status == STATUS_SUCCESS, "query start address -> %08lx", (unsigned long)status);
        ok(retlen == sizeof(entry), "start address retlen %lu", (unsigned long)retlen);
        ok(entry != NULL, "start address nonzero");

        PVOID sentinel = (PVOID)(ULONG_PTR)0x1234560;
        status = NtSetInformationThread(NtCurrentThread(), PS_ThreadQuerySetWin32StartAddress,
                                        &sentinel, sizeof(sentinel) - 1);
        ok(status == STATUS_INVALID_PARAMETER, "short start-address set -> %08lx",
           (unsigned long)status);
        status = NtSetInformationThread(NtCurrentThread(), PS_ThreadQuerySetWin32StartAddress,
                                        &sentinel, sizeof(sentinel));
        ok(status == STATUS_SUCCESS, "start-address set -> %08lx", (unsigned long)status);
        entry = NULL;
        status = NtQueryInformationThread(NtCurrentThread(), PS_ThreadQuerySetWin32StartAddress,
                                          &entry, sizeof(entry), NULL);
        ok(status == STATUS_SUCCESS, "start-address re-query -> %08lx", (unsigned long)status);
        ok(entry == sentinel, "start-address round-trips (%p)", entry);
    }
}
