/*
 * sem_ob/out_handle.c — what a handle-producing Nt* call leaves in the
 * caller's slot when it REFUSES.
 *
 * The rule is "cleared before anything can fail": the out-handle is written
 * with 0 at the top of the service, above every validation, so a caller that
 * never initialised its own HANDLE still reads NULL out of a refusal. It is
 * not a nicety — the boundary's own consumers depend on it. kernelbase's
 * CreateFileMappingW (third_party/wine dlls/kernelbase/sync.c) declares
 *
 *     HANDLE ret;
 *     ...
 *     status = NtCreateSection( &ret, ... );
 *     SetLastError( RtlNtStatusToDosError(status) );
 *     return ret;
 *
 * — an uninitialised local, returned on every path including the failing
 * ones. A kernel that refuses correctly and leaves the slot alone therefore
 * hands Win32 a stack-garbage HANDLE for a create that did not happen, which
 * is what kernel32:virtual:1616 sees as "CreateFileMapping unexpectedly
 * succeeded" and :1636/:1638 then see as NtQuerySection failing on it.
 *
 * The pinned oracle states the rule once per entry point, as its own first
 * statement (`*handle = 0;`): dlls/ntdll/unix/sync.c for the sync objects,
 * the namespace objects, the section and the completion port; unix/file.c
 * for NtCreateFile and NtCreateNamedPipeFile (NtOpenFile reaches it by
 * tail-calling NtCreateFile); unix/registry.c for
 * NtCreateKey / NtOpenKeyEx; unix/process.c and unix/thread.c for
 * NtOpenProcess / NtOpenThread; unix/security.c for the token opens; and
 * unix/server.c NtDuplicateObject, which is the one that guards the store
 * (`if (dest) *dest = 0;`) because its out pointer is optional.
 *
 * IT IS NOT UNIVERSAL, AND THAT IS THE HALF A GENERIC IMPLEMENTATION GETS
 * WRONG. Three of the surface's creates deliberately do NOT clear:
 *
 *   - NtCreateThreadEx (unix/thread.c) validates zero_bits and returns
 *     STATUS_INVALID_PARAMETER_3 without ever touching *handle;
 *   - NtCreateUserProcess (unix/process.c) builds into locals and assigns
 *     the caller's two slots only on the success path;
 *   - NtFilterToken (unix/security.c) opens with its flags FIXME.
 *
 * So the three negative controls at the bottom are the point of this file as
 * much as the positives are: a kernel that pre-zeroed in its system-service
 * dispatcher, or inside the shared handle-allocation engine's callers, would
 * pass every assertion above them and fail those three.
 *
 * Oracle-first (G5). Every case here is a call that MUST fail, made with the
 * slot pre-poisoned, so the assertion is about the slot and not about the
 * status — the statuses are asserted too, but only where the refusal's own
 * ladder is what selects which entry point's clear is being measured.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT; ntapi.c defines them */

/* The other departments' entry points, declared here rather than pulled from
 * four bucket headers (sem_mm/reserve_section.c makes the same choice). */
NTSYSAPI NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                        const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtOpenSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                     PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtCreateKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *, ULONG,
                                    const UNICODE_STRING *, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, const OBJECT_ATTRIBUTES *);
NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, const CLIENT_ID *);
NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID,
                                         PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
NTSYSAPI NTSTATUS NTAPI NtFilterToken(HANDLE, ULONG, PVOID, PVOID, PVOID, PHANDLE);
NTSYSAPI NTSTATUS NTAPI NtCreateUserProcess(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
                                            POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG,
                                            PVOID, PVOID, PVOID);

/* value as in wine/include/winnt.h */
#ifndef THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#endif

/* The poison: a value no handle allocator can mint, so "still poison" and
 * "cleared" cannot be confused, and neither can be confused with a real
 * handle. */
#define POISON ((HANDLE)(ULONG_PTR)0xdeadbeef)

static const void *nowhere_ob = W("\\prsk_out_handle_absent");
static const void *nowhere_file = W("\\??\\C:\\prsk_out_handle_absent.tmp");
static const void *nowhere_key = W("\\Registry\\Machine\\Software\\prsk_out_handle_absent");

START_TEST(out_handle)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER size;
    CLIENT_ID cid;
    NTSTATUS status;
    HANDLE handle;

    /* --- the section, which is what convicted the rule ------------------- */

    /* A protection the create switch has no case for: refused above the
     * server call, i.e. by the entry point's own first ladder. */
    handle = POISON;
    size.QuadPart = 0x1000;
    status = NtCreateSection(&handle, SECTION_ALL_ACCESS, NULL, &size, 0x99, SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PAGE_PROTECTION, "NtCreateSection(bad protect) -> %08lx",
       (unsigned long)status);
    ok(handle == NULL, "NtCreateSection(bad protect) left %p", handle);

    /* SEC_RESERVE|SEC_COMMIT — the exact refusal kernel32:virtual's
     * sec_flag_tests sweep makes, and one refused further in (the mapping
     * flags are a whole-word switch: sem_mm/reserve_section.c). Both depths
     * of refusal owe the same cleared slot. */
    handle = POISON;
    size.QuadPart = 0x1000;
    status = NtCreateSection(&handle, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE,
                             SEC_RESERVE | SEC_COMMIT, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "NtCreateSection(RESERVE|COMMIT) -> %08lx",
       (unsigned long)status);
    ok(handle == NULL, "NtCreateSection(RESERVE|COMMIT) left %p", handle);

    /* A named create whose parent directory does not exist: the refusal
     * comes from the name walk, past every argument check. */
    handle = POISON;
    init_ustr(&name, W("\\prsk_out_handle_absent\\sect"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    size.QuadPart = 0x1000;
    status = NtCreateSection(&handle, SECTION_ALL_ACCESS, &attr, &size, PAGE_READWRITE, SEC_COMMIT,
                             NULL);
    ok(!NT_SUCCESS(status), "NtCreateSection(absent parent) -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtCreateSection(absent parent) left %p", handle);

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenSection(&handle, SECTION_QUERY, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtOpenSection -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenSection left %p", handle);

    /* --- the sync objects ------------------------------------------------ */

    handle = POISON;
    init_ustr(&name, W("\\prsk_out_handle_absent\\ev"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&handle, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(!NT_SUCCESS(status), "NtCreateEvent(absent parent) -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtCreateEvent(absent parent) left %p", handle);

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&handle, EVENT_ALL_ACCESS, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtOpenEvent -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenEvent left %p", handle);

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenMutant(&handle, MUTANT_ALL_ACCESS, &attr);
    ok(!NT_SUCCESS(status), "NtOpenMutant -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenMutant left %p", handle);

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenSemaphore(&handle, SEMAPHORE_ALL_ACCESS, &attr);
    ok(!NT_SUCCESS(status), "NtOpenSemaphore -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenSemaphore left %p", handle);

    /* --- the namespace objects ------------------------------------------- */

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(&handle, DIRECTORY_QUERY, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtOpenDirectoryObject -> %08lx",
       (unsigned long)status);
    ok(handle == NULL, "NtOpenDirectoryObject left %p", handle);

    handle = POISON;
    init_ustr(&name, nowhere_ob);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attr);
    ok(!NT_SUCCESS(status), "NtOpenSymbolicLinkObject -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenSymbolicLinkObject left %p", handle);

    /* --- Io: the file surface, and the completion port ------------------- */

    handle = POISON;
    memset(&iosb, 0, sizeof(iosb));
    init_ustr(&name, nowhere_file);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status =
        NtCreateFile(&handle, GENERIC_READ | SYNCHRONIZE, &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtCreateFile -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtCreateFile left %p", handle);

    handle = POISON;
    memset(&iosb, 0, sizeof(iosb));
    init_ustr(&name, nowhere_file);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenFile(&handle, GENERIC_READ | SYNCHRONIZE, &attr, &iosb, FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtOpenFile -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenFile left %p", handle);

    handle = POISON;
    init_ustr(&name, W("\\prsk_out_handle_absent\\port"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateIoCompletion(&handle, IO_COMPLETION_ALL_ACCESS, &attr, 0);
    ok(!NT_SUCCESS(status), "NtCreateIoCompletion(absent parent) -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtCreateIoCompletion(absent parent) left %p", handle);

    /* --- Cm: the registry ------------------------------------------------ */

    handle = POISON;
    init_ustr(&name, nowhere_key);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenKey(&handle, KEY_READ, &attr);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "NtOpenKey -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenKey left %p", handle);

    /* A create whose GRANDparent is absent: NtCreateKey creates only the last
     * component, so this is a refusal from the walk rather than from an
     * argument. */
    handle = POISON;
    init_ustr(&name, W("\\Registry\\Machine\\Software\\prsk_out_handle_absent\\deeper"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateKey(&handle, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(!NT_SUCCESS(status), "NtCreateKey(absent parent) -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtCreateKey(absent parent) left %p", handle);

    /* --- Ps: an open of a process that does not exist -------------------- */

    handle = POISON;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)0x7ffffffc; /* no such pid on either runner */
    cid.UniqueThread = NULL;
    status = NtOpenProcess(&handle, PROCESS_QUERY_INFORMATION, &attr, &cid);
    ok(!NT_SUCCESS(status), "NtOpenProcess -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtOpenProcess left %p", handle);

    /* --- Ob: the duplicate, whose out pointer is OPTIONAL ----------------- */

    handle = POISON;
    status = NtDuplicateObject(NtCurrentProcess(), POISON, NtCurrentProcess(), &handle,
                               EVENT_ALL_ACCESS, 0, 0);
    ok(status == STATUS_INVALID_HANDLE, "NtDuplicateObject -> %08lx", (unsigned long)status);
    ok(handle == NULL, "NtDuplicateObject left %p", handle);

    /* The same refusal with no slot at all must not fault: the store is
     * guarded (`if (dest) *dest = 0;`), which is the one place in the whole
     * surface where it is. */
    status = NtDuplicateObject(NtCurrentProcess(), POISON, NtCurrentProcess(), NULL,
                               EVENT_ALL_ACCESS, 0, 0);
    ok(status == STATUS_INVALID_HANDLE, "NtDuplicateObject(no slot) -> %08lx",
       (unsigned long)status);

    /* --- THE NEGATIVE CONTROL --------------------------------------------
     *
     * NtCreateThreadEx has no clear at all, so an argument refusal leaves
     * the caller's slot exactly as it found it. This is what makes the rule
     * per-entry-point: it cannot live in the dispatcher, and it cannot live
     * in whatever the creates share. The zero_bits band is the cheapest way
     * in — 25 is inside 21 < n < 32, which the oracle refuses before it
     * resolves the process handle (pinned for its own sake by
     * sem_ps/thread_zero_bits.c). */
    handle = POISON;
    status = NtCreateThreadEx(&handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, NULL, 0,
                              25, 0, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER_3, "NtCreateThreadEx(zero_bits 25) -> %08lx",
       (unsigned long)status);
    ok(handle == POISON, "NtCreateThreadEx(zero_bits 25) cleared the slot to %p", handle);

    /* And the second one, from a different department: NtFilterToken opens
     * with its flags FIXME, not with a clear (unix/security.c). An invalid
     * source token is refused before anything is built. */
    handle = POISON;
    status = NtFilterToken(POISON, 0, NULL, NULL, NULL, &handle);
    ok(status == STATUS_INVALID_HANDLE, "NtFilterToken -> %08lx", (unsigned long)status);
    ok(handle == POISON, "NtFilterToken cleared the slot to %p", handle);

    /* And the third, which owes TWO slots and clears neither: it builds into
     * locals and assigns them on the success path only (unix/process.c).
     * THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER is legal on NtCreateThreadEx and
     * invalid here, and it is the oracle's first refusal — but its
     * `attr_count` is computed off ps_attr at declaration and proskrnl probes
     * `createInfo` above the same check, so both structures have to be real
     * for the two runners to reach that refusal by the same route. */
    {
        HANDLE processHandle = POISON, threadHandle = POISON;
        ULONG64 createInfo[32];   /* >= sizeof(PS_CREATE_INFO), 8-aligned */
        ULONG64 attributeList[4]; /* TotalLength only: an empty list */

        memset(createInfo, 0, sizeof(createInfo));
        memset(attributeList, 0, sizeof(attributeList));
        createInfo[0] = sizeof(createInfo);
        attributeList[0] = sizeof(ULONG_PTR);
        status = NtCreateUserProcess(
            &processHandle, &threadHandle, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0,
            THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, NULL, createInfo, attributeList);
        ok(status == STATUS_INVALID_PARAMETER, "NtCreateUserProcess(hide) -> %08lx",
           (unsigned long)status);
        ok(processHandle == POISON, "NtCreateUserProcess cleared the process slot to %p",
           processHandle);
        ok(threadHandle == POISON, "NtCreateUserProcess cleared the thread slot to %p",
           threadHandle);
    }
}
