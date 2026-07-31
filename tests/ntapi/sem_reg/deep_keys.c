/*
 * sem_reg/deep_keys.c — a deeply nested key tree stays consistent.
 *
 * Three walks over the key tree recurse once per level — CmpMeasureKey,
 * CmpEmitKey and CmpFreeSubtree — on a 16 KiB pool-allocated kernel stack
 * with no guard page, and nothing capped depth at create time. ~400 levels
 * of NtCreateKey followed by any mutation ran the stack off its block and
 * corrupted the neighbouring pool headers.
 *
 * Worse than the crash was the asymmetry: create depth was unlimited, the
 * hive PARSER stopped at 96, and CmpLoadHive treats any parse failure as
 * "hive invalid" and discards the whole tree. So a 100-deep key path saved
 * successfully, reported durability, and threw the ENTIRE registry away at
 * the next boot.
 *
 * What this pins, on both legs: creating deeply is either accepted or
 * REFUSED with a status — never accepted-then-lost — and every key that was
 * accepted is still there afterwards. proskrnl's cap (96 levels) is lower
 * than NT's documented 512, which is a docs/03 deviation, so the assertion
 * that all 200 levels are creatable is tagged todo_proskrnl rather than
 * dropped: the oracle must still manage it.
 */
#include "util.h"

#define DEEP_LEVELS 200

static const void *deep_base = W("\\Registry\\Machine\\Software\\prsk_deep");

/* Append "\\lNN" to `path` (in units), returning the new length in units. */
static unsigned append_level(WCHAR *path, unsigned units, unsigned level)
{
    path[units++] = '\\';
    path[units++] = 'l';
    if (level >= 100)
        path[units++] = (WCHAR)('0' + (level / 100) % 10);
    if (level >= 10)
        path[units++] = (WCHAR)('0' + (level / 10) % 10);
    path[units++] = (WCHAR)('0' + level % 10);
    path[units] = 0;
    return units;
}

START_TEST(deep_keys)
{
    static WCHAR path[16 + 6 * DEEP_LEVELS];
    unsigned units = 0;
    unsigned created = 0;
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE key;

    reg_delete_path(deep_base);

    {
        const WCHAR *base = (const WCHAR *)deep_base;
        while (base[units])
        {
            path[units] = base[units];
            units++;
        }
        path[units] = 0;
    }
    status = reg_create_path(path, &key, NULL);
    ok(status == STATUS_SUCCESS, "create deep base -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;
    NtClose(key);

    /* One level at a time, stopping at the first refusal. */
    unsigned lengths[DEEP_LEVELS + 1];
    lengths[0] = units;
    for (unsigned level = 1; level <= DEEP_LEVELS; level++)
    {
        units = append_level(path, units, level);
        lengths[level] = units;
        status = reg_create_path(path, &key, NULL);
        if (!NT_SUCCESS(status))
            break;
        NtClose(key);
        created = level;
    }

    ok(NT_SUCCESS(status) || status == STATUS_INVALID_PARAMETER,
       "deep create stopped at level %u with %08lx, which is neither success nor a refusal",
       created + 1, (unsigned long)status);
    todo_proskrnl
    {
        ok(created == DEEP_LEVELS, "created %u of %u levels", created, DEEP_LEVELS);
    }

    /* Everything that WAS accepted is still openable — no level was taken
     * and then lost, which is the property the asymmetry destroyed. */
    if (created != 0)
    {
        path[lengths[created]] = 0;
        status = reg_open_path(path, &key);
        ok(status == STATUS_SUCCESS, "reopen the deepest accepted level (%u) -> %08lx", created,
           (unsigned long)status);
        if (NT_SUCCESS(status))
            NtClose(key);
    }

    /* Unwind deepest-first: NtDeleteKey refuses a key with subkeys. */
    for (unsigned level = created; level >= 1; level--)
    {
        path[lengths[level]] = 0;
        if (NT_SUCCESS(reg_open_path(path, &key)))
        {
            NtDeleteKey(key);
            NtClose(key);
        }
    }
    path[lengths[0]] = 0;
    if (NT_SUCCESS(reg_open_path(path, &key)))
    {
        NtDeleteKey(key);
        NtClose(key);
    }
}
