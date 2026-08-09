/* tests/boot/abi_probe.c — the standing ABI-conformance probe.
 *
 * A native PE client run on EVERY boot (boot-module cmdline "abi",
 * kernel/init/main.c KiRunAbiProbe) that asserts ring-3 CONVENTIONS rather
 * than features: entry-stack alignment, the FXSAVE seed values, the mapped
 * PE header claiming its actual base, TEB ids agreeing with what the
 * Nt*Information* surface reports, the process cookie, KUSER_SHARED_DATA
 * ticking, and the absolute-timeout contract. Unlike the milestone smoke
 * clients these checks guard conventions no current consumer may need yet —
 * each one is a documented contract a later Wine DLL will silently depend
 * on, and each earlier convention bug (entry rsp ≡ 0 instead of NT's ≡ 8;
 * the mapped header keeping the preferred base after relocation, so ntdll
 * relocated twice; a TEB id disagreeing with the ETHREAD's; ProcessCookie
 * unserved feeding garbage to RtlEncodePointer; absolute timeouts parked as
 * interrupt-time) stayed latent until one did.
 *
 * Returns 0 on success; a distinct nonzero code per failed check, reported
 * by KiRunAbiProbe as the process exit status.
 *
 * --- conventions this probe does NOT cover yet -----------------------------
 * A ledger of boundary conventions that are real but have no testable
 * consumer or surface today. Each is pinned to the milestone that makes it
 * observable; grow the probe in THAT milestone, before the first consumer:
 *
 *  - KiUserCallbackDispatcher (PEB.KernelCallbackTable): the user-callback
 *    frame/stack contract user32 peer-depends on. Nothing dispatches user
 *    callbacks until the GUI milestone (M12) — add the check with win32k
 *    callouts (frame layout per Wine dlls/ntdll/signal_x86_64.c
 *    KiUserCallbackDispatcher).
 *  - CONTEXT_XSTATE / XSAVE conventions: KUSER_SHARED_DATA.XState
 *    configuration (EnabledFeatures, CompactionEnabled, per-feature
 *    offsets) and the CONTEXT_EX/XSTATE get/set round-trip. Today the
 *    kernel is FXSAVE-only and no baked consumer issues CONTEXT_XSTATE;
 *    add when an AVX-using client or a newer kernelbase appears (layout:
 *    Wine include/winnt.h XSTATE_CONFIGURATION + Intel SDM Vol. 1 XSAVE).
 *  - User CS/SS selector VALUES: today Wine's PE stack reads the selectors
 *    at runtime (dlls/ntdll/unix/signal_x86_64.c cs64_sel), so proskrnl's
 *    own GDT layout (arch/x86_64/gdt.h) is unpinned and this probe
 *    deliberately does not check the values. The WOW64 milestone makes
 *    them load-bearing (heaven's-gate far transfers encode CS) — pin them
 *    there against real NT / MS docs, with the TEB32/PEB32 mirroring and
 *    the 32-bit KUSD fields (TickCountMultiplier consumers included).
 *  - Debugger conventions (DebugPort, first/second-chance routing,
 *    DbgUiRemoteBreakin): no debug surface exists; add with DbgUi/Dbgk.
 *  - Se/token conventions (NtQueryInformationToken shapes ntdll probes at
 *    startup — the boot log's "syscall MISSING 0x21" lines): add when Se
 *    lands; until then the miss itself is the visible marker.
 *
 * Covered elsewhere, deliberately not duplicated here: the SEH/APC
 * dispatcher frame contracts (m7_smoke + hello.exe's SEH leg), PEB process-
 * parameter normalization (smss/wineboot boot legs), syscall-number
 * stability (generated — tools/gen_syscalls.py), and every Nt* semantic the
 * ntapi differential can pin against the oracle (tests/ntapi/).
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntimage.h"
#include "abi/ntioapi.h"
#include "abi/ntkeapi.h"
#include "abi/ntmmapi.h"
#include "abi/ntobapi.h"
#include "abi/ntpebteb.h"
#include "abi/ntpsapi.h"

#define WSTR(s) u##s

/* Captured by the pe_start stub (abi_probe.S) before any C code runs. */
extern ULONG_PTR abi_entry_rsp;
extern ULONG_PTR abi_entry_rflags;
extern ULONG abi_entry_mxcsr;
extern USHORT abi_entry_fcw;

/* Captured by the abi_thread_entry stub for the second thread. */
extern ULONG_PTR abi_thread_rsp;
extern ULONG abi_thread_mxcsr;
extern USHORT abi_thread_fcw;
void abi_thread_entry(void);

static void say(const char *ascii)
{
    WCHAR wide[80];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 79)
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

static void init_ustr(UNICODE_STRING *str, const WCHAR *wide)
{
    USHORT n = 0;
    while (wide[n] != 0)
        n++;
    str->Length = (USHORT)(n * sizeof(WCHAR));
    str->MaximumLength = (USHORT)(str->Length + sizeof(WCHAR));
    str->Buffer = (PWSTR)wide;
}

static void init_attr(OBJECT_ATTRIBUTES *attr, HANDLE root, UNICODE_STRING *name)
{
    attr->Length = sizeof(*attr);
    attr->RootDirectory = root;
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
    attr->SecurityDescriptor = 0;
    attr->SecurityQualityOfService = 0;
}

static volatile TEB *get_teb(void)
{
    void *self;
    /* gs points at the TEB; 0x30 is NT_TIB.Self (abi/ntpsapi.h,
     * _Static_assert(offsetof(NT_TIB, Self) == 48)). */
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(self));
    return (volatile TEB *)self;
}

/* KUSER_SHARED_DATA at its NT-fixed user VA (third_party/wine
 * dlls/ntdll/unix/virtual.c `user_shared_data = (void *)0x7ffe0000`, and
 * include/ddk/wdm.h in the Windows DDK). */
static const volatile KUSER_SHARED_DATA *kusd(void)
{
    return (const volatile KUSER_SHARED_DATA *)(ULONG_PTR)0x7ffe0000;
}

/* The KSYSTEM_TIME coherent-read protocol: the kernel writes High2Time,
 * then Low, then High1Time; a reader retries until the two highs agree
 * (Wine reads it the same way — third_party/wine dlls/ntdll/time.c
 * RtlQueryUnbiasedInterruptTime). */
static ULONGLONG read_ksystem_time(const volatile KSYSTEM_TIME *t)
{
    ULONG low;
    LONG high;
    do
    {
        high = t->High1Time;
        low = t->LowPart;
    } while (high != t->High2Time);
    return ((ULONGLONG)(ULONG)high << 32) | low;
}

/* --- entry conventions: stack alignment + FXSAVE seeds -------------------- */

static int check_entry_state(void)
{
    /* NT enters the thread like a called function: 16-byte alignment minus
     * the pushed return address (MS Learn "x64 stack usage"; Wine's initial
     * frame is StackBase - 0x28 — dlls/ntdll/unix/signal_x86_64.c
     * init_syscall_frame). kernelbase's __TRY frames movdqa off this. */
    if ((abi_entry_rsp & 0xf) != 8)
        return 1;

    /* The seed control words of a fresh thread (MS Learn "x64 calling
     * convention" FPCSR/MXCSR "standard values at the start of program
     * execution"; Wine seeds exactly these — dlls/ntdll/unix/
     * signal_x86_64.c init_syscall_frame FCW 0x27f, MxCsr 0x1f80). */
    if (abi_entry_fcw != 0x27f)
        return 2;
    if (abi_entry_mxcsr != 0x1f80)
        return 3;

    /* DF must be clear at function entry (MS Learn "x64 register usage":
     * the direction flag is clear on entry and on return; bit 10 of RFLAGS
     * per Intel SDM Vol. 1 "EFLAGS Register"). std-then-crash bugs are of
     * the same latent class as the alignment one. */
    if ((abi_entry_rflags & 0x400) != 0)
        return 32;
    return 0;
}

/* --- TEB / PEB / id agreement --------------------------------------------- */

static int check_identity(void)
{
    volatile TEB *teb = get_teb();
    if (teb == 0 || teb->Tib.Self != (struct _NT_TIB *)teb)
        return 4;
    PEB *peb = teb->Peb;
    if (peb == 0)
        return 5;
    if (teb->ClientId.UniqueProcess == 0 || teb->ClientId.UniqueThread == 0)
        return 6;

    /* The entry rsp must lie inside the stack the TEB describes. */
    if (abi_entry_rsp > (ULONG_PTR)teb->Tib.StackBase ||
        abi_entry_rsp <= (ULONG_PTR)teb->Tib.StackLimit)
        return 7;

    /* The TEB's ids and self-pointer must agree with what the query surface
     * reports for the same thread — one thread, one id (a TEB id of N
     * beside an ETHREAD counting N+1 fed RtlSetThreadErrorMode-era Wine
     * wrong ids for every alert). */
    THREAD_BASIC_INFORMATION tbi;
    if (NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), 0) !=
        STATUS_SUCCESS)
        return 8;
    if (tbi.TebBaseAddress != (PVOID)teb)
        return 9;
    if (tbi.ClientId.UniqueProcess != teb->ClientId.UniqueProcess ||
        tbi.ClientId.UniqueThread != teb->ClientId.UniqueThread)
        return 10;

    PROCESS_BASIC_INFORMATION pbi;
    if (NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi),
                                  0) != STATUS_SUCCESS)
        return 11;
    if (pbi.PebBaseAddress != peb)
        return 12;
    if (pbi.UniqueProcessId != (ULONG_PTR)teb->ClientId.UniqueProcess)
        return 13;
    return 0;
}

/* --- the second thread: entry conventions + per-thread stack growth -------- */

static volatile TEB *g_main_teb;
static volatile int g_thread_ran;
static volatile int g_thread_result;

/* Burn stack a KB at a time, far past the initial commit, so the recursion
 * walks through the guard page repeatedly. noinline + volatile stores keep
 * the frames real at -O1. */
static __attribute__((noinline)) int touch_stack(int depth)
{
    volatile unsigned char frame[1024];
    frame[0] = (unsigned char)depth;
    frame[1023] = (unsigned char)(depth >> 1);
    int result = frame[0] + frame[1023];
    if (depth > 0)
        result += touch_stack(depth - 1);
    return result;
}

/* The second thread's C body (entered from abi_thread_entry in abi_probe.S). */
void abi_thread_main(void *arg)
{
    (void)arg;
    g_thread_ran = 1;

    /* Entry conventions hold for every thread the same as for the first
     * (Wine seeds every new-thread CONTEXT identically — third_party/wine
     * dlls/ntdll/unix/signal_x86_64.c init_syscall_frame). */
    if ((abi_thread_rsp & 0xf) != 8)
    {
        g_thread_result = 40;
        return;
    }
    if (abi_thread_fcw != 0x27f || abi_thread_mxcsr != 0x1f80)
    {
        g_thread_result = 41;
        return;
    }

    /* Its own TEB, with its own id, agreeing with the query surface. */
    volatile TEB *teb = get_teb();
    if (teb == 0 || teb == g_main_teb || teb->Tib.Self != (struct _NT_TIB *)teb)
    {
        g_thread_result = 42;
        return;
    }
    if (teb->ClientId.UniqueProcess != g_main_teb->ClientId.UniqueProcess ||
        teb->ClientId.UniqueThread == 0 ||
        teb->ClientId.UniqueThread == g_main_teb->ClientId.UniqueThread)
    {
        g_thread_result = 43;
        return;
    }
    THREAD_BASIC_INFORMATION tbi;
    if (NtQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &tbi, sizeof(tbi), 0) !=
            STATUS_SUCCESS ||
        tbi.TebBaseAddress != (PVOID)teb || tbi.ClientId.UniqueThread != teb->ClientId.UniqueThread)
    {
        g_thread_result = 44;
        return;
    }
    if (abi_thread_rsp > (ULONG_PTR)teb->Tib.StackBase ||
        abi_thread_rsp <= (ULONG_PTR)teb->Tib.StackLimit)
    {
        g_thread_result = 45;
        return;
    }

    /* Guard-page growth keyed on THIS thread's stack, published in THIS
     * thread's TEB: deep recursion past the initial commit must neither
     * fault nor corrupt, and NT lowers NT_TIB.StackLimit to the new commit
     * bottom as it grows (Wine dlls/ntdll/unix/virtual.c grow_thread_stack).
     * Growth keyed on the main thread's bounds is exactly the class that
     * stayed latent until conhost's tty thread recursed deep. */
    PVOID limitBefore = teb->Tib.StackLimit;
    if (touch_stack(288) < 0) /* ~300 KB, far past the 64 KB commit */
    {
        g_thread_result = 46; /* unreachable; defeats value elision */
        return;
    }
    if ((ULONG_PTR)teb->Tib.StackLimit >= (ULONG_PTR)limitBefore)
    {
        g_thread_result = 47;
        return;
    }
    g_thread_result = 0;
}

static int check_thread(void)
{
    g_main_teb = get_teb();
    g_thread_ran = 0;
    g_thread_result = -1;
    HANDLE thread = 0;
    NTSTATUS status =
        NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, 0, NtCurrentProcess(),
                         (PRTL_THREAD_START_ROUTINE)abi_thread_entry, 0, 0, 0, 0, 0, 0);
    if (status != STATUS_SUCCESS || thread == 0)
        return 33;
    if (NtWaitForSingleObject(thread, FALSE, 0) != STATUS_SUCCESS)
        return 34;
    NtClose(thread);
    if (!g_thread_ran || g_thread_result < 0)
        return 35;
    return g_thread_result;
}

/* --- the process cookie ---------------------------------------------------- */

static int check_cookie(void)
{
    /* ntdll feeds ProcessCookie straight into RtlEncodePointer; zero or
     * garbage means every encoded pointer decodes wild (the vectored-
     * handler wild jump). It must be nonzero and stable (Wine
     * dlls/ntdll/unix/process.c NtQueryInformationProcess ProcessCookie). */
    ULONG cookie1 = 0;
    ULONG cookie2 = 0;
    if (NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie, &cookie1, sizeof(cookie1),
                                  0) != STATUS_SUCCESS)
        return 14;
    if (cookie1 == 0)
        return 15;
    if (NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie, &cookie2, sizeof(cookie2),
                                  0) != STATUS_SUCCESS ||
        cookie2 != cookie1)
        return 16;
    return 0;
}

/* --- the mapped PE header claims the actual base --------------------------- */

static int check_own_header(void)
{
    volatile TEB *teb = get_teb();
    PEB *peb = teb->Peb;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)peb->ImageBaseAddress;
    if (dos == 0 || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 17;
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const char *)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 18;
    /* Wherever the image landed, its mapped header must claim THAT base —
     * ntdll's own perform_relocations keys off this field (Wine
     * dlls/ntdll/loader.c), and Wine's mapper rewrites it after relocating
     * (dlls/ntdll/unix/virtual.c map_image_into_view: ImageBase =
     * map_addr). A header still claiming the preferred base makes ntdll
     * relocate every rebased module a second time. */
    if (nt->OptionalHeader.ImageBase != (ULONG_PTR)peb->ImageBaseAddress)
        return 19;
    return 0;
}

/* Force the relocation path: map ntdll.dll twice in this (ntdll-less)
 * process. The second view cannot sit at the first view's base, so it comes
 * back rebased — and an image section is relocated ONCE, so both views must
 * report the SAME stamped ImageBase and hold the same bytes (docs/03 "An
 * image section is relocated once"; the oracle memcmps exactly this at
 * ntdll:virtual:1743, and tests/ntapi/sem_mm/map_image_offset.c pins it).
 *
 * This probe used to require each view's header to claim the base THAT view
 * got, which is the rule docs/17 §6F stated and the oracle refutes. The
 * strong claim survives where it is load-bearing and is checked above: the
 * MAIN image is mapped by the kernel and nothing relocates it afterwards, so
 * ITS header must name its actual base (check_own_header). For a view, the
 * stamp is what ntdll's perform_relocations fixes the residual against, so
 * what matters is that the two agree with each other. */
static const WCHAR ntdll_path[] = WSTR("\\??\\C:\\windows\\system32\\ntdll.dll");

static ULONG_PTR view_stamped_base(void *view, int *codeOut)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        *codeOut = 24;
        return 0;
    }
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const char *)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        *codeOut = 25;
        return 0;
    }
    *codeOut = 0;
    return (ULONG_PTR)nt->OptionalHeader.ImageBase;
}

static int check_rebased_header(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE file = 0;
    init_ustr(&name, ntdll_path);
    init_attr(&attr, 0, &name);
    NTSTATUS status = NtOpenFile(&file, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status))
    {
        /* The ntapi/fuzz images may not bake the windows tree; the check
         * self-skips there rather than failing the whole probe. */
        say("abi_probe: rebase check skipped (no ntdll.dll)\n");
        return 0;
    }

    HANDLE section = 0;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, 0, 0, PAGE_READONLY, SEC_IMAGE, file);
    NtClose(file);
    if (status != STATUS_SUCCESS)
        return 20;

    int code = 0;
    void *view1 = 0;
    void *view2 = 0;
    SIZE_T size1 = 0;
    SIZE_T size2 = 0;
    NTSTATUS status1 = STATUS_SUCCESS;
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &view1, 0, 0, &offset, &size1,
                                ViewShare, 0, PAGE_READONLY);
    status1 = status;
    if (status != STATUS_SUCCESS && status != STATUS_IMAGE_NOT_AT_BASE)
        code = 21;
    if (code == 0)
    {
        offset.QuadPart = 0;
        status = NtMapViewOfSection(section, NtCurrentProcess(), &view2, 0, 0, &offset, &size2,
                                    ViewShare, 0, PAGE_READONLY);
        /* The base is taken: this view MUST come back rebased. */
        if (status != STATUS_IMAGE_NOT_AT_BASE || view2 == view1 || view2 == 0)
            code = 22;
    }
    if (code == 0 && view1 == 0)
        code = 23;
    if (code == 0)
    {
        ULONG_PTR stamp1 = view_stamped_base(view1, &code);
        ULONG_PTR stamp2 = code == 0 ? view_stamped_base(view2, &code) : 0;
        /* Both views name the same copy... */
        if (code == 0 && stamp1 != stamp2)
            code = 26;
        /* ...and when THIS view is the one that got the base — the map
         * answered plain success, so no earlier copy exists elsewhere — the
         * stamp is that base, which is the same claim check_own_header makes
         * of the main image. */
        if (code == 0 && status1 == STATUS_SUCCESS && stamp1 != (ULONG_PTR)view1)
            code = 27;
        /* One copy means one set of bytes: the headers are equal byte for
         * byte, which is what ntdll:virtual:1743 memcmps over the whole
         * image. */
        for (ULONG i = 0; code == 0 && i < 0x40; i++)
        {
            if (((const unsigned char *)view1)[i] != ((const unsigned char *)view2)[i])
                code = 28;
        }
    }

    if (view1 != 0)
        NtUnmapViewOfSection(NtCurrentProcess(), view1);
    if (view2 != 0)
        NtUnmapViewOfSection(NtCurrentProcess(), view2);
    NtClose(section);
    return code;
}

/* --- KUSER_SHARED_DATA ticks; timeouts honor the NT time contract ---------- */

static int check_time(void)
{
    /* SystemTime is 100ns units since 1601 (the NT time contract — Wine
     * dlls/ntdll/unix/sync.c get_absolute_timeout); a zero value means the
     * page was mapped but never written. */
    if (read_ksystem_time(&kusd()->SystemTime) == 0)
        return 27;

    /* The page must TICK: InterruptTime and TickCount both advance across
     * a real delay. Bounded retries absorb a coarse tick period. */
    ULONGLONG interrupt0 = read_ksystem_time(&kusd()->InterruptTime);
    ULONGLONG tick0 = read_ksystem_time(&kusd()->TickCount);
    int advanced = 0;
    for (int i = 0; i < 10 && !advanced; i++)
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -500000; /* 50 ms, relative (negative, 100ns units) */
        if (NtDelayExecution(FALSE, &delay) != STATUS_SUCCESS)
            return 28;
        advanced = read_ksystem_time(&kusd()->InterruptTime) > interrupt0 &&
                   read_ksystem_time(&kusd()->TickCount) > tick0;
    }
    if (!advanced)
        return 29;

    /* An absolute timeout (positive: 100ns since 1601 in SYSTEM time — Wine
     * dlls/ntdll/unix/sync.c get_absolute_timeout) that is already in the
     * past must satisfy immediately. Treating it as interrupt-time parked
     * such waits for ~4 billion seconds. */
    LARGE_INTEGER due;
    due.QuadPart = (LONGLONG)(read_ksystem_time(&kusd()->SystemTime) - 100000000ULL); /* -10 s */
    ULONGLONG before = read_ksystem_time(&kusd()->InterruptTime);
    if (NtDelayExecution(FALSE, &due) != STATUS_SUCCESS)
        return 30;
    ULONGLONG after = read_ksystem_time(&kusd()->InterruptTime);
    if (after - before > 20000000ULL) /* > 2 s: the wait parked */
        return 31;
    return 0;
}

/* The probe body, entered from pe_start (abi_probe.S) after the entry state
 * is captured. Returns the process exit status: 0 = every convention holds. */
int abi_probe_main(void)
{
    int code = check_entry_state();
    if (code == 0)
        code = check_identity();
    if (code == 0)
        code = check_thread();
    if (code == 0)
        code = check_cookie();
    if (code == 0)
        code = check_own_header();
    if (code == 0)
        code = check_rebased_header();
    if (code == 0)
        code = check_time();
    if (code == 0)
        say("[KTEST] user abi_probe PASS\n");
    return code;
}
