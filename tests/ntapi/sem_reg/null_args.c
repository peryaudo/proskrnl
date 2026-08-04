/*
 * sem_reg/null_args.c — what NtCreateKey/NtOpenKey do with NULL arguments.
 *
 * Convicted by the winetest gate: ntdll:reg (reg.c:239, 390, 399) expects
 * STATUS_ACCESS_VIOLATION from a NULL OBJECT_ATTRIBUTES and proskrnl
 * answered STATUS_INVALID_PARAMETER — it null-CHECKED an argument the
 * boundary null-DEREFERENCES.
 *
 * That is where the status comes from, and it is worth stating plainly
 * because it is not a style choice. The pinned Wine's NtCreateKey
 * (dlls/ntdll/unix/registry.c:74) opens with
 *
 *     *key = 0;
 *     if (attr->Length != sizeof(OBJECT_ATTRIBUTES)) return STATUS_INVALID_PARAMETER;
 *     if (!attr->ObjectName->Length && !attr->RootDirectory) return STATUS_OBJECT_PATH_SYNTAX_BAD;
 *
 * — three dereferences with no guard, so a NULL `attr` (or a NULL
 * `attr->ObjectName`) is an access violation by construction, and the
 * caller sees STATUS_ACCESS_VIOLATION. A kernel that validates instead of
 * touching returns a different status for the same call, which is a
 * boundary divergence even though it is the "safer" code.
 *
 * The `*key = 0` FIRST also matters: the out handle is cleared before any
 * of the validation runs, so it is cleared even on the failing paths.
 *
 * Oracle-first (G5).
 */
#include "util.h"

START_TEST(null_args)
{
    NTSTATUS status;
    HANDLE key;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* --- NULL OBJECT_ATTRIBUTES with a real out handle ------------------- */
    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtCreateKey(&key, KEY_ALL_ACCESS, NULL, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NtCreateKey(NULL attr) -> %08lx", (unsigned long)status);

    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtCreateKey(&key, 0, NULL, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NtCreateKey(NULL attr, no access) -> %08lx",
       (unsigned long)status);

    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtOpenKey(&key, KEY_READ, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NtOpenKey(NULL attr) -> %08lx", (unsigned long)status);

    /* --- NULL out handle, NULL attributes: either fault is legal --------- */
    status = NtCreateKey(NULL, KEY_ALL_ACCESS, NULL, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_VIOLATION || status == STATUS_INVALID_PARAMETER,
       "NtCreateKey(NULL, NULL attr) -> %08lx", (unsigned long)status);

    /* --- attributes present, ObjectName NULL ----------------------------- */
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    attr.RootDirectory = NULL;
    attr.ObjectName = NULL;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "NtCreateKey(NULL ObjectName) -> %08lx",
       (unsigned long)status);

    /* --- a wrong Length is checked BEFORE ObjectName is touched ---------- */
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr) + 1;
    attr.ObjectName = NULL;
    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "NtCreateKey(bad Length) -> %08lx",
       (unsigned long)status);

    /* --- an empty name with no root is the path-syntax refusal ----------- */
    init_ustr(&name, W(""));
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    key = (HANDLE)(ULONG_PTR)0xdeadbeef;
    status = NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(status == STATUS_OBJECT_PATH_SYNTAX_BAD, "NtCreateKey(empty name, no root) -> %08lx",
       (unsigned long)status);
}
