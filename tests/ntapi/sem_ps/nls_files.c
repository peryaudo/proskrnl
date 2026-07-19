/*
 * sem_ps/nls_files.c — the NLS data services ntdll's locale_init issues at
 * startup (M7 Wine bring-up; docs/02 "Place the NLS files ntdll reads at
 * startup").
 *
 * NtInitializeNlsFiles maps locale.nls and reports the system LCID;
 * NtGetNlsSectionPtr maps the per-type tables (case table, codepages, the
 * sortkey table kernelbase parses unconditionally at attach). Statuses and
 * type/id validation follow Wine's unix implementation
 * (dlls/ntdll/unix/env.c get_nls_section_name / get_nls_file_path), greened
 * on the pinned Wine oracle first (Art. 5). On proskrnl the files live at
 * C:\windows\system32 (tests/run/run.sh bakes them into the image).
 */
#include "util.h"

START_TEST(nls_files)
{
    NTSTATUS status;
    void *base = NULL;
    LCID lcid = 0;
    LARGE_INTEGER size;
    size.QuadPart = 0;

    /* locale.nls: mapped read-only, a real system LCID. The size argument is
     * left UNTOUCHED (Wine's NtInitializeNlsFiles computes its mapping size
     * into a local and never writes the out parameter — dlls/ntdll/unix/
     * env.c); callers pass a throwaway (locale_init's is named `unused`). */
    size.QuadPart = -1;
    status = NtInitializeNlsFiles(&base, &lcid, &size);
    ok(status == STATUS_SUCCESS, "NtInitializeNlsFiles -> %08lx", (unsigned long)status);
    ok(base != NULL, "locale.nls base %p", base);
    ok(size.QuadPart == -1, "size untouched (%ld)", (long)size.QuadPart);
    ok(lcid != 0, "system lcid %04lx", (unsigned long)lcid);
    if (base)
    {
        /* The mapping is readable (the header's offsets are within it). */
        unsigned int first = *(volatile unsigned int *)base;
        ok(first != 0xdeadbeef, "readable header %08x", first);
    }

    /* The case table (l_intl.nls): type CASEMAP takes id 0 only. */
    void *ptr = NULL;
    SIZE_T mapped = 0;
    status = NtGetNlsSectionPtr(NLS_SECTION_CASEMAP, 0, NULL, &ptr, &mapped);
    ok(status == STATUS_SUCCESS, "casemap -> %08lx", (unsigned long)status);
    ok(ptr != NULL && mapped > 0, "casemap %p size %lu", ptr, (unsigned long)mapped);
    status = NtGetNlsSectionPtr(NLS_SECTION_CASEMAP, 1, NULL, &ptr, &mapped);
    ok(status == STATUS_UNSUCCESSFUL, "casemap id 1 -> %08lx", (unsigned long)status);

    /* Codepage tables: the ANSI/OEM pair locale_init maps for en-US. */
    status = NtGetNlsSectionPtr(NLS_SECTION_CODEPAGE, 1252, NULL, &ptr, &mapped);
    ok(status == STATUS_SUCCESS, "c_1252 -> %08lx", (unsigned long)status);
    ok(ptr != NULL && mapped > 0, "c_1252 %p size %lu", ptr, (unsigned long)mapped);
    status = NtGetNlsSectionPtr(NLS_SECTION_CODEPAGE, 437, NULL, &ptr, &mapped);
    ok(status == STATUS_SUCCESS, "c_437 -> %08lx", (unsigned long)status);

    /* The sortkey table kernelbase's load_sortdefault_nls parses at attach:
     * id must be 0; nonzero is parameter validation, not a lookup miss. */
    status = NtGetNlsSectionPtr(NLS_SECTION_SORTKEYS, 1, NULL, &ptr, &mapped);
    ok(status == STATUS_INVALID_PARAMETER_1, "sortkeys id 1 -> %08lx", (unsigned long)status);
    status = NtGetNlsSectionPtr(NLS_SECTION_SORTKEYS, 0, NULL, &ptr, &mapped);
    ok(status == STATUS_SUCCESS, "sortkeys -> %08lx", (unsigned long)status);
    ok(ptr != NULL && mapped > 0, "sortkeys %p size %lu", ptr, (unsigned long)mapped);

    /* An unknown section type is parameter validation too. */
    status = NtGetNlsSectionPtr(1, 0, NULL, &ptr, &mapped);
    ok(status == STATUS_INVALID_PARAMETER_1, "bad type -> %08lx", (unsigned long)status);
}
