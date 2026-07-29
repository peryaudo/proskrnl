/* tests/boot/pe_smoke.c — the M5 "Done when" client (docs/02): a real
 * PE image, loaded by the kernel through NtCreateSection+NtMapViewOfSection's
 * engines, exercising the section syscalls and guard-page stack growth from
 * ring 3.
 *
 * Built with x86_64-w64-mingw32-gcc -mabi=sysv (see the Makefile): a PE32+
 * container whose code speaks the SysV calling convention the M4/M5 syscall
 * stubs use. No CRT, no imports — the kernel maps the image and jumps to
 * pe_start with a fresh stack. Returns 0 on success; any failed step returns
 * a distinct nonzero code the kernel's boot-module runner reports as FAIL.
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntmmapi.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntimage.h"

/* An absolute pointer in .data: the one DIR64 base relocation this image is
 * guaranteed to carry, so (a) the linker emits a .reloc directory and (b)
 * the kmt relocation test has a deterministic fixup site. The self-check
 * below only works if the loader relocated it correctly. */
static int reloc_anchor;
static int *volatile reloc_pointer = &reloc_anchor;

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

/* volatile: the KERNEL rewrites NT_TIB.StackLimit behind this code's back as
 * the stack grows; without it the compiler may fold the before/after loads. */
/* gs:[0x30] is NT_TIB.Self — offset pinned by the offsetof(NT_TIB, Self)
 * == 48 static_assert in abi/ntpsapi.h. */
static volatile NT_TIB *get_tib(void)
{
    void *self;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(self));
    return (volatile NT_TIB *)self;
}

/* Deep recursion past the initial stack commit; each frame stays under a
 * page and touches its buffer top-down so the guard page is never skipped
 * (same discipline as sem_mm/stack_growth.c). */
__attribute__((noinline)) static char *recurse(int depth, char *deepest)
{
    volatile char buffer[2048];
    int i;
    for (i = 2048 - 64; i >= 0; i -= 64)
        buffer[i] = (char)depth;
    if ((char *)buffer < deepest)
        deepest = (char *)buffer;
    if (depth > 0)
        deepest = recurse(depth - 1, deepest);
    if (buffer[0] != (char)depth)
        return 0;
    return deepest;
}

static int run_checks(void)
{
    NTSTATUS status;

    /* We ARE a mapped image: the region around our own code is MEM_IMAGE and
     * its AllocationBase carries the PE header we were loaded from. */
    MEMORY_BASIC_INFORMATION mbi;
    status = NtQueryVirtualMemory(NtCurrentProcess(), (void *)(ULONG_PTR)run_checks,
                                  MemoryBasicInformation, &mbi, sizeof(mbi), 0);
    if (status != STATUS_SUCCESS || mbi.Type != MEM_IMAGE || mbi.State != MEM_COMMIT)
        return 1;
    const IMAGE_DOS_HEADER *dos = mbi.AllocationBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 2;
    /* ...and our code pages must not be writable (per-section protection). */
    if (mbi.Protect != PAGE_EXECUTE_READ)
        return 3;
    /* The absolute pointer survived loading (relocated or at base). */
    *reloc_pointer = 42;
    if (reloc_anchor != 42)
        return 18;

    /* The section surface from ring 3: create, double-map, share, query. */
    HANDLE section;
    LARGE_INTEGER max_size;
    max_size.QuadPart = 0x20000;
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, 0, &max_size, PAGE_READWRITE, SEC_COMMIT, 0);
    if (status != STATUS_SUCCESS)
        return 4;

    volatile char *view1 = 0, *view2 = 0;
    SIZE_T view_size = 0;
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (PVOID *)&view1, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || view_size != 0x20000 || view1[0] != 0)
        return 5;
    view_size = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), (PVOID *)&view2, 0, 0, &offset,
                                &view_size, ViewShare, 0, PAGE_READWRITE);
    if (status != STATUS_SUCCESS || view2 == view1)
        return 6;
    view1[0x1FFFF] = 0x5a;
    if (view2[0x1FFFF] != 0x5a)
        return 7; /* views must share pages */

    SECTION_BASIC_INFORMATION sbi;
    SIZE_T retlen = 0;
    status = NtQuerySection(section, SectionBasicInformation, &sbi, sizeof(sbi), &retlen);
    if (status != STATUS_SUCCESS || sbi.Attributes != SEC_COMMIT || sbi.Size.QuadPart != 0x20000 ||
        retlen != sizeof(sbi))
        return 8;

    if (NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)view1) != STATUS_SUCCESS)
        return 9;
    if (view2[0x1FFFF] != 0x5a)
        return 10; /* the section (and view2) outlive view1 */
    if (NtClose(section) != STATUS_SUCCESS)
        return 11;
    if (view2[0x1FFFF] != 0x5a)
        return 12; /* views outlive the handle */
    if (NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)view2) != STATUS_SUCCESS)
        return 13;
    if (NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)view2) != STATUS_NOT_MAPPED_VIEW)
        return 14;

    /* Guard-page stack growth: recurse ~120 KiB past the initial commit
     * (this PE asks for a small SizeOfStackCommit); survival means the
     * kernel grew the stack, and StackLimit tracked it downward. */
    volatile NT_TIB *tib = get_tib();
    char *limit_before = (char *)tib->StackLimit;
    char probe;
    if (limit_before == 0 || (char *)&probe <= limit_before)
        return 15;
    char *deepest = recurse(60, &probe);
    if (deepest == 0)
        return 16;
    char *limit_after = (char *)tib->StackLimit;
    if (limit_after > deepest || limit_after > limit_before)
        return 17;

    say("[KTEST] user pe_smoke PASS\n");
    return 0;
}

/* The PE entry point (AddressOfEntryPoint): no CRT, no arguments. */
__attribute__((used)) void pe_start(void)
{
    NtTerminateProcess(NtCurrentProcess(), run_checks());
    for (;;)
    {
        /* NtTerminateProcess never returns. */
    }
}
