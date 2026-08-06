/*
 * sem_ps/zero_tls_cell.c — NtSetInformationThread(ThreadZeroTlsCell) clears
 * a TLS slot; it does not parse an affinity mask.
 *
 * WHY THIS PIN EXISTS. In proskrnl `case ThreadZeroTlsCell:` sat directly
 * above `case ThreadAffinityMask:` and shared its whole body — the
 * sizeof(ULONG_PTR) length rule, the buffer read, the narrowing against the
 * processor mask, the THREAD_SET_INFORMATION check. Nothing in the comment
 * under that case group mentions TLS; the grouping was accidental, and the
 * result was a class answering a caller-plausible status computed from the
 * wrong contract entirely (Art. 12). Nothing convicted it, because the one
 * winetest pair that reaches the class (ntdll:exception) is not active.
 *
 * The class is REACHABLE and live: TlsFree issues it on every call
 * (third_party/wine dlls/kernelbase/thread.c:775,
 * `NtSetInformationThread( GetCurrentThread(), ThreadZeroTlsCell, &index,
 * sizeof(index) )` — and `index` is a DWORD, so the affinity body's 8-byte
 * length rule refused every one of them).
 *
 * THE CONTRACT, from the oracle (third_party/wine
 * dlls/ntdll/unix/thread.c, NtSetInformationThread's first case, and
 * virtual_clear_tls_index in dlls/ntdll/unix/virtual.c):
 *
 *   - the CURRENT thread only. A handle naming any other thread is unbuilt
 *     on the oracle, so this file does not pin it (Art. 12: a case may not
 *     assert STATUS_NOT_IMPLEMENTED, and an unbuilt oracle has nothing to
 *     say about the behaviour anyway).
 *   - a wrong length is STATUS_INVALID_PARAMETER — not the
 *     STATUS_INFO_LENGTH_MISMATCH several of this class's neighbours give.
 *     The two are one `case` label apart in the kernel, which is exactly
 *     how the bug above happened.
 *   - the slot is ZEROED, in every thread. That is the observable effect,
 *     and the only assertion here that a no-op success would fail.
 *   - an index past the expansion range is STATUS_INVALID_PARAMETER.
 *
 * Oracle-first (G5).
 */
#include "../ntapi.h"

NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG);

/* TlsAlloc/TlsSetValue/TlsGetValue come from the headers ntapi.h already
 * pulls in. They are used rather than reaching into the TEB by offset: the
 * slot the boundary must clear is the one TlsSetValue wrote, and letting
 * kernelbase pick it is what keeps this test about the syscall instead of
 * about a struct layout abi/ already asserts.
 *
 * TLS_MINIMUM_AVAILABLE (64) is the TEB's TlsSlots[] count and
 * TlsExpansionBitmapBits is ULONG[32], so 64 + 1024 is the first index no
 * thread can have. Both are the pinned tree's own values
 * (third_party/wine include/winternl.h: TEB.TlsSlots[64],
 * PEB.TlsExpansionBitmapBits[32]; dlls/ntdll/unix/virtual.c:4377 does the
 * `index >= 8 * sizeof(peb->TlsExpansionBitmapBits)` comparison this
 * mirrors). */
#define PRS_TLS_PAST_THE_END (64 + 1024)

START_TEST(zero_tls_cell)
{
    /* -2, spelled out: mingw defines NtCurrentThread only for the Win32
     * GetCurrentThread() spelling. The value is NT's, cited to Microsoft's
     * NtCurrentThread documentation, and is what the oracle's own
     * `handle == GetCurrentThread()` test compares against. */
    HANDLE self = (HANDLE)(LONG_PTR)-2;
    NTSTATUS status;
    DWORD index;
    ULONG cell;
    ULONG_PTR wide;

    index = TlsAlloc();
    ok(index != 0xffffffffu, "TlsAlloc failed");
    if (index == 0xffffffffu)
        return;

    ok(TlsSetValue(index, (LPVOID)(ULONG_PTR)0x5a5a5a5a) != 0, "TlsSetValue failed");
    ok(TlsGetValue(index) == (LPVOID)(ULONG_PTR)0x5a5a5a5a, "the slot did not take the value");

    /* --- a wrong length refuses, and refuses with INVALID_PARAMETER ------
     * sizeof(ULONG_PTR) is the length the affinity body wanted, so this is
     * the assertion that fails the moment the two share a case again. */
    wide = index;
    status = NtSetInformationThread(self, ThreadZeroTlsCell, &wide, sizeof(wide));
    ok(status == STATUS_INVALID_PARAMETER, "an 8-byte ThreadZeroTlsCell -> %08lx",
       (unsigned long)status);
    ok(TlsGetValue(index) == (LPVOID)(ULONG_PTR)0x5a5a5a5a,
       "a refused call cleared the slot anyway");

    /* --- an index past the end of the expansion range refuses ------------ */
    cell = PRS_TLS_PAST_THE_END;
    status = NtSetInformationThread(self, ThreadZeroTlsCell, &cell, sizeof(cell));
    ok(status == STATUS_INVALID_PARAMETER, "an out-of-range TLS index -> %08lx",
       (unsigned long)status);

    /* --- and the real call CLEARS the slot -------------------------------
     * The assertion a no-op success cannot pass, which is the whole reason
     * the class may not be an accept-and-drop stub. */
    cell = index;
    status = NtSetInformationThread(self, ThreadZeroTlsCell, &cell, sizeof(cell));
    ok(status == STATUS_SUCCESS, "ThreadZeroTlsCell -> %08lx", (unsigned long)status);
    ok(TlsGetValue(index) == NULL, "the slot was not cleared: %p", TlsGetValue(index));
}
