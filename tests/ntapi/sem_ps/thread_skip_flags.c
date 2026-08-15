/*
 * sem_ps/thread_skip_flags.c — NtCreateThreadEx's two "skip" flags land in the
 * new thread's TEB before it runs.
 *
 * ITS ORACLE HALF IS PARKED (tests/run/run.sh ORACLE_PARKED_CASES, which
 * carries the trace and the full triage). Nothing about the case is wrong and
 * nothing about the kernel's half changed: the pinned Wine loses a race in
 * wineserver's receive_fd() when this case's create/terminate/create pattern
 * makes a dying thread's last fd message arrive after its sender is gone, and
 * hands the NEXT request a stale STATUS_INVALID_CID — on a reply that already
 * carries the valid tid and handle of a thread it did create. ~6% per run
 * locally, twice out of two on a hosted CI runner, with or without a display.
 * The proskrnl leg still gates every assertion below; only the oracle sweep
 * skips it, and only until the pin carries a fix.
 *
 * THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH (0x2) and
 * THREAD_CREATE_FLAGS_SKIP_LOADER_INIT (0x20) are not kernel behaviour in
 * themselves: the kernel records each in SameTebFlags and it is the LOADER,
 * in user mode, that reads them back and obeys — `if
 * (NtCurrentTeb()->SkipLoaderInit) return;` is the first line of the pinned
 * tree's loader_init (dlls/ntdll/loader.c), and SkipThreadAttach is what
 * suppresses the DLL_THREAD_ATTACH fan-out beneath it. So the boundary
 * behaviour, and the whole of what a caller can observe, is the TEB bits
 * being set on a thread that has not started yet.
 *
 * That makes it exactly the kind of accepted-and-dropped input a stub is made
 * of: a kernel that parses the flags word, honours CREATE_SUSPENDED, and
 * silently discards these two returns STATUS_SUCCESS and a handle, and every
 * visible thing about the thread is right except that the loader was never
 * told. It cost a WOW64 GUI applet its window: in a WOW64 process EVERY
 * thread is a guest thread unless its creator says otherwise, so a 64-bit
 * helper thread created with SKIP_LOADER_INIT and not honoured is diverted
 * into the 32-bit guest by wow64.dll and jumps to its own 64-bit start
 * routine truncated to 32 bits.
 *
 * Read by offset, like every other TEB field these tests measure (the
 * sem_ps/teb_stack.c and thread_stack_default.c discipline): mingw's
 * winternl.h stops at Reserved[] arrays. 0x17EE is the x64 offset of
 * SameTebFlags in the pinned tree's own header (third_party/wine
 * include/winternl.h, `USHORT SameTebFlags; /​* fca/17ee *​/`), which is where
 * abi/ntpebteb.h's generated layout — and its static_assert — comes from.
 * G8: re-verify there. The first case proves the offset live on the ORACLE
 * (a fresh thread has neither bit and RanProcessInit-class bits do not make
 * the word zero) before anything is concluded from the others.
 *
 * Oracle-first (G5).
 */
#include "util.h"

#include <windows.h>

NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS NTAPI NtTerminateThread(HANDLE, LONG);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* third_party/wine include/winternl.h: the SameTebFlags word and the two bit
 * positions inside it (SkipThreadAttach is bit 3, SkipLoaderInit bit 14 —
 * counting from SafeThunkCall at bit 0, as abi/ntpebteb.h spells out). */
#define PS_TEB_SAME_TEB_FLAGS_OFFSET 0x17EE
#define PS_TEB_SKIP_THREAD_ATTACH    0x0008
#define PS_TEB_SKIP_LOADER_INIT      0x4000

/* PsAttributeTebAddress (4) | PS_ATTRIBUTE_THREAD (0x10000), the write-back
 * NtCreateThreadEx fills with the new thread's TEB — third_party/wine
 * include/winternl.h, and abi/ntpsapi.h's generated PS_ATTRIBUTE_TEB_ADDRESS.
 * Asked for HERE rather than through NtQueryInformationThread because the
 * latter answers a NULL TebBaseAddress for a thread that has not run yet
 * (measured on the oracle), and "before it runs" is the whole state under
 * test. */
#define PS_ATTRIBUTE_TEB_ADDRESS_ 0x00010004

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

#define PS_CREATE_SKIP_THREAD_ATTACH 0x00000002
#define PS_CREATE_SKIP_LOADER_INIT   0x00000020
#define PS_CREATE_SUSPENDED          0x00000001

static ps_create_thread_ex createThreadEx;

static DWORD WINAPI idle_child(LPVOID unused)
{
    (void)unused;
    return 0;
}

/* Create a SUSPENDED thread with `flags` and report its TEB's SameTebFlags.
 * Suspended so the bits are read exactly where the contract puts them —
 * before the thread has run a single instruction, which is also the only
 * state in which SkipLoaderInit could still mean anything. */
static USHORT same_teb_flags(ULONG flags, const char *what)
{
    HANDLE thread = NULL;
    ps_attribute_list attributes;
    void *teb = NULL;
    NTSTATUS status;
    USHORT word = 0;

    memset(&attributes, 0, sizeof(attributes));
    attributes.TotalLength = sizeof(attributes);
    attributes.Attributes[0].Attribute = PS_ATTRIBUTE_TEB_ADDRESS_;
    attributes.Attributes[0].Size = sizeof(teb);
    attributes.Attributes[0].Value = (ULONG_PTR)&teb;
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)idle_child,
                            NULL, flags | PS_CREATE_SUSPENDED, 0, 0, 0, &attributes);
    ok(status == STATUS_SUCCESS, "%s: NtCreateThreadEx -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return 0;
    }
    ok(teb != NULL, "%s: no TEB address", what);
    if (teb != NULL)
    {
        word = *(USHORT *volatile)((char *)teb + PS_TEB_SAME_TEB_FLAGS_OFFSET);
    }
    NtTerminateThread(thread, 0);
    NtClose(thread);
    return word;
}

START_TEST(thread_skip_flags)
{
    USHORT flags;

    createThreadEx = (ps_create_thread_ex)(void *)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                                 "NtCreateThreadEx");
    ok(createThreadEx != NULL, "NtCreateThreadEx");
    if (createThreadEx == NULL)
    {
        return;
    }

    /* Neither flag: neither bit. The offset is proved here — a wrong one
     * would have to read a word that is clear now and sets exactly the right
     * bit in each case below, which no neighbouring field does. */
    flags = same_teb_flags(0, "plain");
    ok((flags & PS_TEB_SKIP_THREAD_ATTACH) == 0, "plain thread: SkipThreadAttach set (%04x)",
       (unsigned)flags);
    ok((flags & PS_TEB_SKIP_LOADER_INIT) == 0, "plain thread: SkipLoaderInit set (%04x)",
       (unsigned)flags);

    flags = same_teb_flags(PS_CREATE_SKIP_THREAD_ATTACH, "skip-thread-attach");
    ok((flags & PS_TEB_SKIP_THREAD_ATTACH) != 0, "SKIP_THREAD_ATTACH -> SameTebFlags %04x",
       (unsigned)flags);
    ok((flags & PS_TEB_SKIP_LOADER_INIT) == 0, "SKIP_THREAD_ATTACH set SkipLoaderInit too (%04x)",
       (unsigned)flags);

    flags = same_teb_flags(PS_CREATE_SKIP_LOADER_INIT, "skip-loader-init");
    ok((flags & PS_TEB_SKIP_LOADER_INIT) != 0, "SKIP_LOADER_INIT -> SameTebFlags %04x",
       (unsigned)flags);
    ok((flags & PS_TEB_SKIP_THREAD_ATTACH) == 0, "SKIP_LOADER_INIT set SkipThreadAttach too (%04x)",
       (unsigned)flags);

    flags = same_teb_flags(PS_CREATE_SKIP_THREAD_ATTACH | PS_CREATE_SKIP_LOADER_INIT, "both");
    ok((flags & (PS_TEB_SKIP_THREAD_ATTACH | PS_TEB_SKIP_LOADER_INIT)) ==
           (PS_TEB_SKIP_THREAD_ATTACH | PS_TEB_SKIP_LOADER_INIT),
       "both flags -> SameTebFlags %04x", (unsigned)flags);
}
