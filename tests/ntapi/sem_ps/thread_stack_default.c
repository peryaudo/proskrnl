/*
 * sem_ps/thread_stack_default.c — a thread created with NO reserve gets the
 * MAIN IMAGE's SizeOfStackReserve, not a number the kernel picked.
 *
 * docs/21 W5 (the last small item in the ntdll:virtual thread-stack cluster;
 * virtual.c:1050/:1068, where `CreateThread(NULL, 0x3f00, …, 0, NULL)` names a
 * COMMIT and no reserve and the test then asserts the thread's reserve is the
 * image's). The rule is one line of the pinned oracle
 * (third_party/wine dlls/ntdll/unix/virtual.c virtual_alloc_thread_stack):
 *
 *     if (!reserve_size) reserve_size = main_image_info.MaximumStackSize;
 *     if (!commit_size)  commit_size  = main_image_info.CommittedStackSize;
 *     size = max( reserve_size, commit_size );
 *     if (size < 1024 * 1024) size = 1024 * 1024;
 *     size = ROUND_SIZE( 0, size, granularity_mask );
 *
 * and `main_image_info.MaximumStackSize` is the main image's
 * `SizeOfStackReserve` verbatim (server/mapping.c
 * `mapping->image.stack_size = nt.opt.hdr64.SizeOfStackReserve`, carried into
 * SECTION_IMAGE_INFORMATION by unix/virtual.c virtual_fill_image_information).
 *
 * WHY THIS IS NOT COSMETIC. A hardwired default is a fabricated answer of the
 * quiet kind: every status is right, every TEB field is self-consistent, and
 * the only thing wrong is that the linker's declared stack size — the one
 * number an image gets to state about its threads — was read, retained and
 * then ignored. A program that links with a 2 MiB reserve because its worker
 * threads recurse gets 1 MiB and a stack overflow, and nothing in the failure
 * points back at the kernel. It is docs/21 W5's accepted-and-dropped-input
 * shape with the input coming from the PE header.
 *
 * WHAT THIS FILE MEASURES IS THE RULE, NOT THIS BINARY'S NUMBER. The reserve
 * is read out of the running image's own optional header, so the pin's colour
 * is a property of the contract rather than of what the mingw in the build
 * container defaults to (the sem_ps/shared_machine.c discipline). The one
 * thing it does assert about the number is that it is NOT NT's 1 MiB floor —
 * without that, every case below would be satisfiable by the hardwired
 * default and the file would run green while measuring nothing (docs/21 §4
 * trap 2 in miniature).
 *
 * THE CASE THAT DISCRIMINATES IS THE THIRD ONE. "Use the image's reserve" and
 * "use the LARGER of the image's reserve and the caller's" agree on every
 * default-taking case; they disagree only when a caller explicitly names a
 * reserve BELOW the image's, and NT gives the caller what it asked for. An
 * implementation that folded the image default in with a max() passes cases 1,
 * 2 and 4 and fails only case 3.
 *
 * Oracle-first (G5). Nothing here is beyond_oracle.
 */
#include "util.h"

#include <windows.h> /* NtCurrentTeb, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64 */

NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE);

typedef NTSTATUS(NTAPI *ps_create_thread_ex)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                             PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);

/* TEB.DeallocationStack, reached by offset because mingw's winternl.h stops
 * at four Reserved[] arrays. 0x1478 is the x64 offset the pinned tree's own
 * header states (third_party/wine include/winternl.h, `PVOID
 * DeallocationStack; /​* e0c/1478 *​/`), which is where abi/ntpebteb.h's
 * generated static_assert comes from too. G8: re-verify there. Same constant,
 * same reason, as sem_ps/teb_stack.c and sem_ps/thread_zero_bits.c; proved
 * live on the ORACLE by the first case below before anything is concluded
 * from it. */
#define PS_TEB_DEALLOCATION_STACK_OFFSET 0x1478

/* NT's own floor and the allocation granularity the reserve is rounded to,
 * both transcribed from virtual_alloc_thread_stack's body quoted above. */
#define PS_STACK_FLOOR       0x100000
#define PS_STACK_GRANULARITY 0x10000

static ps_create_thread_ex createThreadEx;

/* The child's own view of its stack, written by the child and read by the
 * creator after it has exited. A child that asserted for itself would make a
 * wrong kernel cost the leg a wedge instead of a failure (docs/21 W10). */
static PVOID childBase;
static PVOID childDealloc;

static DWORD WINAPI child(LPVOID unused)
{
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();

    (void)unused;
    childBase = tib->StackBase;
    childDealloc = *(PVOID *volatile)((char *)NtCurrentTeb() + PS_TEB_DEALLOCATION_STACK_OFFSET);
    return 0;
}

/* The main image's declared stack reserve, read where the winetest reads it
 * (virtual.c test_RtlCreateUserStack: `RtlImageNtHeader(
 * NtCurrentTeb()->Peb->ImageBaseAddress )->OptionalHeader.SizeOfStackReserve`;
 * GetModuleHandleA(NULL) is the same base without the PEB walk). Zero if the
 * headers do not look like a PE64, which the caller reports rather than
 * silently substituting a number. */
static ULONGLONG image_stack_reserve(void)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)GetModuleHandleA(NULL);
    const IMAGE_NT_HEADERS64 *nt;

    if (dos == NULL || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }
    nt = (const IMAGE_NT_HEADERS64 *)((const char *)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return 0;
    }
    return nt->OptionalHeader.SizeOfStackReserve;
}

/* One create with the given (commit, reserve) pair, run to completion; the
 * reserve the thread ended up with is `StackBase - DeallocationStack`, the
 * only pair of TEB fields that can express it (sem_ps/teb_stack.c). */
static void expect_reserve(SIZE_T commit, SIZE_T reserve, ULONGLONG wanted, const char *what)
{
    HANDLE thread = NULL;
    NTSTATUS status;
    ULONGLONG got;

    childBase = NULL;
    childDealloc = NULL;
    status = createThreadEx(&thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PVOID)child,
                            NULL, 0, 0, commit, reserve, NULL);
    ok(status == STATUS_SUCCESS, "%s: NtCreateThreadEx -> %08lx", what, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    ok(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "%s: the child did not exit", what);
    NtClose(thread);

    ok(childDealloc != NULL, "%s: the child reported no DeallocationStack", what);
    if (childDealloc == NULL)
    {
        return;
    }
    got = (ULONGLONG)((char *)childBase - (char *)childDealloc);
    ok(got == wanted, "%s: reserve %llx, wanted %llx", what, got, wanted);
}

START_TEST(thread_stack_default)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    ULONGLONG imageReserve = image_stack_reserve();

    ok(ntdll != NULL, "GetModuleHandleA(ntdll) -> %lu", (unsigned long)GetLastError());
    if (ntdll == NULL)
    {
        return;
    }
    createThreadEx = (ps_create_thread_ex)(void *)GetProcAddress(ntdll, "NtCreateThreadEx");
    ok(createThreadEx != NULL, "NtCreateThreadEx is exported");
    if (createThreadEx == NULL)
    {
        return;
    }

    ntapi_printf("image SizeOfStackReserve %llx\n", imageReserve);
    ok(imageReserve >= PS_STACK_FLOOR, "image SizeOfStackReserve %llx is below NT's floor",
       imageReserve);
    /* Without this the whole file is satisfiable by a hardwired 1 MiB: the
     * image default and the floor would be the same number and no case below
     * could tell "read the header" from "picked a constant". */
    ok(imageReserve != PS_STACK_FLOOR,
       "this image declares NT's floor (%llx) as its reserve, so nothing below discriminates",
       imageReserve);
    ok((imageReserve & (PS_STACK_GRANULARITY - 1)) == 0,
       "image SizeOfStackReserve %llx is not granularity-aligned, so the rounding rule is in play",
       imageReserve);
    if (imageReserve < PS_STACK_FLOOR || (imageReserve & (PS_STACK_GRANULARITY - 1)) != 0)
    {
        return;
    }

    /* 1. Nothing named at all — the pure default. */
    expect_reserve(0, 0, imageReserve, "no reserve, no commit");

    /* 2. A COMMIT named and no reserve: this is ntdll:virtual:1050 exactly
     * (`CreateThread(NULL, 0x3f00, …, 0, NULL)` — dwStackSize is the commit
     * unless STACK_SIZE_PARAM_IS_A_RESERVATION is set, dlls/kernelbase/thread.c
     * CreateRemoteThreadEx). The commit does not displace the default; it is
     * resolved on its own axis. */
    expect_reserve(0x3f00, 0, imageReserve, "commit named, reserve defaulted");

    /* 3. A reserve BELOW the image's, named explicitly. THE DEFAULT IS A
     * DEFAULT, not a minimum: NT gives the caller the smaller number. This is
     * the only case that separates "if (!reserve) reserve = image" from
     * "reserve = max( reserve, image )". */
    expect_reserve(0, PS_STACK_FLOOR, PS_STACK_FLOOR, "explicit reserve below the image's");

    /* 4. A reserve ABOVE the image's, named explicitly — the other side of
     * the same rule, and the one an implementation reaching for max() would
     * also pass. */
    expect_reserve(0, imageReserve + PS_STACK_GRANULARITY, imageReserve + PS_STACK_GRANULARITY,
                   "explicit reserve above the image's");
}
