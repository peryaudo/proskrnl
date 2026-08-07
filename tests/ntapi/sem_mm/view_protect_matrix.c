/*
 * sem_mm/view_protect_matrix.c — a view may never be re-protected, or
 * committed over, to an access it was not MAPPED with.
 *
 * The rule is the oracle's set_protection (third_party/wine
 * dlls/ntdll/unix/virtual.c), reached from both NtProtectVirtualMemory and
 * the MEM_COMMIT arm of NtAllocateVirtualMemory:
 *
 *     BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
 *     if ((view->protect & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
 *
 * Three properties of it are each their own way to get this wrong, and each
 * gets its own assertions below:
 *
 *   1. it is a SUBSET test, not equality — a PAGE_EXECUTE_READWRITE view
 *      narrows to anything;
 *   2. WRITECOPY is not one of the compared bits, so PAGE_WRITECOPY needs
 *      only READ and is legal on a read-only view;
 *   3. the ceiling is the VIEW's protection, not the SECTION's — a
 *      PAGE_READWRITE section mapped PAGE_READONLY has a read-only ceiling.
 *
 * And the commit arm has a rule in FRONT of it that changes the answer
 * completely by backing store:
 *
 *     else if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
 *     else ... set_protection(...)
 *
 * so MEM_COMMIT over a FILE-backed view is refused before the protection is
 * even looked at (STATUS_ALREADY_COMMITTED, which kernelbase reports as
 * ERROR_ACCESS_DENIED), while over an ANONYMOUS section view it is allowed
 * and really re-protects.
 *
 * Convicted by kernel32:virtual, which sweeps section x view x requested
 * protection and had ~4100 failures, ~2100 of them the missing subset test
 * (virtual.c:4250/:4251) and ~460 the commit arm answering by the wrong
 * rule (virtual.c:4291).
 *
 * Oracle-first (G5).
 */
#include "util.h"

/* One case of the matrix: map `section` with `viewProtect`, then try to
 * protect the view to `requested`. `expect` is whether NT allows it. */
static void check_protect(HANDLE section, ULONG viewProtect, ULONG requested, int expect,
                          const char *what)
{
    NTSTATUS status;
    PVOID base = NULL;
    SIZE_T size = 0;
    LARGE_INTEGER offset;
    ULONG previous = 0xdeadbeef;
    PVOID protectBase;
    SIZE_T protectSize;

    offset.QuadPart = 0;
    status = NtMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, &offset, &size, ViewShare,
                                0, viewProtect);
    if (!NT_SUCCESS(status))
    {
        /* Not every view protection is mappable off every section; those
         * cases are the section-protection rule's business
         * (sem_mm/section_protect), not this file's. */
        return;
    }

    protectBase = base;
    protectSize = 0x1000;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &protectBase, &protectSize, requested,
                                    &previous);
    if (expect)
    {
        ok(status == STATUS_SUCCESS, "%s: protect -> %08lx, wanted success", what,
           (unsigned long)status);
    }
    else
    {
        ok(status == STATUS_INVALID_PAGE_PROTECTION, "%s: protect -> %08lx, wanted %08lx", what,
           (unsigned long)status, (unsigned long)STATUS_INVALID_PAGE_PROTECTION);
    }

    NtUnmapViewOfSection(NtCurrentProcess(), base);
}

START_TEST(view_protect_matrix)
{
    NTSTATUS status;
    HANDLE section = NULL;
    LARGE_INTEGER sectionSize;

    /* An anonymous PAGE_EXECUTE_READWRITE section: the widest ceiling, so
     * every view protection below is reachable off it and the matrix is
     * about the VIEW, which is the property under test. */
    sectionSize.QuadPart = 0x10000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize,
                             PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create an anonymous section -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    /* --- (1) the subset test ------------------------------------------- */
    check_protect(section, PAGE_READONLY, PAGE_READONLY, 1, "RO view -> RO");
    check_protect(section, PAGE_READONLY, PAGE_READWRITE, 0, "RO view -> RW");
    check_protect(section, PAGE_READONLY, PAGE_EXECUTE_READ, 0, "RO view -> XR");
    check_protect(section, PAGE_READWRITE, PAGE_READONLY, 1, "RW view -> RO (narrowing)");
    check_protect(section, PAGE_READWRITE, PAGE_READWRITE, 1, "RW view -> RW");
    check_protect(section, PAGE_READWRITE, PAGE_EXECUTE_READ, 0, "RW view -> XR");
    check_protect(section, PAGE_EXECUTE_READWRITE, PAGE_READONLY, 1, "XRW view -> RO");
    check_protect(section, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, 1, "XRW view -> RW");
    check_protect(section, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, 1, "XRW view -> XR");
    check_protect(section, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, 1, "XRW view -> XRW");

    /* --- (2) WRITECOPY is not an access bit ----------------------------
     * PAGE_WRITECOPY asks for READ only, so it is legal on a view that
     * grants nothing but read. A kernel that treated writecopy as "write"
     * would refuse this, and it is the single easiest way to get the rule
     * wrong in a way the subset cases above all still pass. */
    check_protect(section, PAGE_READONLY, PAGE_WRITECOPY, 1, "RO view -> WRITECOPY");
    check_protect(section, PAGE_READWRITE, PAGE_WRITECOPY, 1, "RW view -> WRITECOPY");
    check_protect(section, PAGE_READONLY, PAGE_EXECUTE_WRITECOPY, 0,
                  "RO view -> EXECUTE_WRITECOPY");

    NtClose(section);

    /* --- (3) the ceiling is the VIEW's, not the SECTION's ---------------
     * Same section as above would not show it: this one is created
     * PAGE_READWRITE and mapped PAGE_READONLY, so a kernel reading the
     * section's protection instead of the view's would ALLOW the
     * re-protect to PAGE_READWRITE. */
    section = NULL;
    sectionSize.QuadPart = 0x10000;
    status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_READWRITE,
                             SEC_COMMIT, NULL);
    ok(status == STATUS_SUCCESS, "create a PAGE_READWRITE section -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        check_protect(section, PAGE_READONLY, PAGE_READWRITE, 0,
                      "RW section, RO view -> RW (the view is the ceiling)");
        check_protect(section, PAGE_READWRITE, PAGE_READWRITE, 1, "RW section, RW view -> RW");

        /* --- (4) MEM_COMMIT over an ANONYMOUS view ---------------------
         * Allowed, and gated by the same subset rule. Not
         * STATUS_ALREADY_COMMITTED — that answer belongs to file-backed
         * views only. */
        {
            PVOID base = NULL;
            SIZE_T size = 0;
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            status = NtMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, &offset, &size,
                                        ViewShare, 0, PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "map for the commit case -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                PVOID commitBase = base;
                SIZE_T commitSize = 0x1000;
                status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitBase, 0, &commitSize,
                                                 MEM_COMMIT, PAGE_READONLY);
                ok(status == STATUS_SUCCESS,
                   "commit a compatible protection over an anonymous view -> %08lx",
                   (unsigned long)status);

                commitBase = base;
                commitSize = 0x1000;
                status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitBase, 0, &commitSize,
                                                 MEM_COMMIT, PAGE_EXECUTE_READ);
                ok(status == STATUS_INVALID_PAGE_PROTECTION,
                   "commit an incompatible protection over an anonymous view -> %08lx",
                   (unsigned long)status);

                NtUnmapViewOfSection(NtCurrentProcess(), base);
            }
        }
        NtClose(section);
    }

    /* --- (5) MEM_COMMIT over a FILE-backed view -------------------------
     * A different answer, reached BEFORE the protection is considered: the
     * request is refused as already committed however compatible the
     * protection is. Both a compatible and an incompatible protection get
     * the same status, which is the assertion that says the refusal is not
     * the subset rule wearing another name. */
    {
        HANDLE file = NULL;
        WCHAR path[MAX_PATH + 16];
        DWORD pathLen = GetTempPathW(MAX_PATH, path);

        if (pathLen != 0 && pathLen < MAX_PATH)
        {
            lstrcatW(path, L"prskvpm.tmp");
            file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        }
        ok(file != NULL && file != INVALID_HANDLE_VALUE, "create the scratch file -> %lu",
           (unsigned long)GetLastError());
        if (file != NULL && file != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;
            static const char zeros[0x1000];
            WriteFile(file, zeros, sizeof(zeros), &written, NULL);

            section = NULL;
            sectionSize.QuadPart = 0x1000;
            status = NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, &sectionSize,
                                     PAGE_READWRITE, SEC_COMMIT, file);
            ok(status == STATUS_SUCCESS, "create a file-backed section -> %08lx",
               (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                PVOID base = NULL;
                SIZE_T size = 0;
                LARGE_INTEGER offset;
                offset.QuadPart = 0;
                status = NtMapViewOfSection(section, NtCurrentProcess(), &base, 0, 0, &offset,
                                            &size, ViewShare, 0, PAGE_READWRITE);
                ok(status == STATUS_SUCCESS, "map the file-backed view -> %08lx",
                   (unsigned long)status);
                if (NT_SUCCESS(status))
                {
                    PVOID commitBase = base;
                    SIZE_T commitSize = 0x1000;
                    status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitBase, 0,
                                                     &commitSize, MEM_COMMIT, PAGE_READONLY);
                    ok(status == STATUS_ALREADY_COMMITTED,
                       "commit a COMPATIBLE protection over a file view -> %08lx",
                       (unsigned long)status);

                    commitBase = base;
                    commitSize = 0x1000;
                    status = NtAllocateVirtualMemory(NtCurrentProcess(), &commitBase, 0,
                                                     &commitSize, MEM_COMMIT, PAGE_EXECUTE_READ);
                    ok(status == STATUS_ALREADY_COMMITTED,
                       "commit an INCOMPATIBLE protection over a file view -> %08lx",
                       (unsigned long)status);

                    NtUnmapViewOfSection(NtCurrentProcess(), base);
                }
                NtClose(section);
            }
            CloseHandle(file);
            DeleteFileW(path);
        }
    }
}
