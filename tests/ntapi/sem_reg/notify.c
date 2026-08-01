/*
 * sem_reg/notify.c — registry change notification (CUI-7).
 *
 * Oracle behaviour pinned from the pinned tree (wine server/registry.c
 * set_registry_notification / touch_key / check_notify / do_notification /
 * key_close_handle; dlls/ntdll/unix/registry.c NtNotifyChangeMultipleKeys):
 *
 *   - Registration needs KEY_NOTIFY on the key and a real event handle
 *     (SYNCHRONIZE); it RESETS the event and returns STATUS_PENDING. The
 *     kernel never writes the IOSB, never takes the APC/buffer arguments
 *     (count/attr/apc/buffer are FIXME-ignored and the call proceeds).
 *   - Records are keyed (process, key handle): a second registration on the
 *     SAME handle appends its event to the existing record — the original
 *     filter/subtree stick, one change signals every accumulated event, and
 *     the record survives firing (re-arm still PENDING). A different handle
 *     to the same key is an independent record.
 *   - set/delete value fire REG_NOTIFY_CHANGE_LAST_SET on the key;
 *     create/delete subkey fire REG_NOTIFY_CHANGE_NAME on the PARENT;
 *     rename fires REG_NOTIFY_CHANGE_NAME on the renamed key itself.
 *     Ancestors see a change only through subtree=TRUE records.
 *   - Deleting the watched key does NOT signal its own watcher (only the
 *     parent's); the signal arrives when the watching handle closes
 *     (key_close_handle fires-and-frees the record).
 *   - The synchronous form (async=FALSE) blocks until a change and returns
 *     STATUS_SUCCESS (ntdll emulates it with a private event on the oracle;
 *     the kernel-side blocking is observably identical).
 */
#include "util.h"

/* NtNotifyChangeMultipleKeys and NtWaitForSingleObject come from mingw's
 * winternl.h; it omits the single-key form. */
NTSYSAPI NTSTATUS NTAPI NtNotifyChangeKey(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
                                          ULONG, BOOLEAN, PVOID, ULONG, BOOLEAN);

#ifndef REG_NOTIFY_CHANGE_NAME
#define REG_NOTIFY_CHANGE_NAME 0x01
#endif
#ifndef REG_NOTIFY_CHANGE_LAST_SET
#define REG_NOTIFY_CHANGE_LAST_SET 0x04
#endif

static const void *base_path = W("\\Registry\\Machine\\Software\\prsk_m8_notify");
static const void *sub_path = W("\\Registry\\Machine\\Software\\prsk_m8_notify\\sub");
static const void *gc_path = W("\\Registry\\Machine\\Software\\prsk_m8_notify\\sub\\gc");

/* Poll an event: STATUS_SUCCESS = signaled now, STATUS_TIMEOUT = not. */
static NTSTATUS poll_event(HANDLE event)
{
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    return NtWaitForSingleObject(event, FALSE, &zero);
}

/* Wait up to 2 s (bounded so a lost signal still ends the run). */
static NTSTATUS await_event(HANDLE event)
{
    LARGE_INTEGER bound;
    bound.QuadPart = -20000000;
    return NtWaitForSingleObject(event, FALSE, &bound);
}

static HANDLE make_event(BOOLEAN initial)
{
    HANDLE event = NULL;
    NTSTATUS status =
        NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL, 0 /* NotificationEvent */, initial);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);
    return event;
}

static HANDLE sync_target;

static DWORD WINAPI sync_mutator(void *param)
{
    ULONG val = 99;
    (void)param;
    Sleep(100);
    reg_set(sync_target, W("syncv"), REG_DWORD, &val, sizeof(val));
    return 0;
}

START_TEST(notify)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    HANDLE base, sub, gc;
    HANDLE ev1, ev2;
    NTSTATUS status;
    ULONG val = 1;

    reg_ensure_software();
    reg_delete_path(gc_path);
    reg_delete_path(sub_path);
    reg_delete_path(base_path);

    status = reg_create_path(base_path, &base, NULL);
    ok(status == STATUS_SUCCESS, "create base -> %08lx", (unsigned long)status);
    status = reg_create_sub(base, W("sub"), &sub, NULL);
    ok(status == STATUS_SUCCESS, "create sub -> %08lx", (unsigned long)status);
    status = reg_create_sub(sub, W("gc"), &gc, NULL);
    ok(status == STATUS_SUCCESS, "create gc -> %08lx", (unsigned long)status);

    /* --- argument/access ladder ------------------------------------------- */
    status = NtNotifyChangeKey(sub, NULL, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET, FALSE, NULL,
                               0, TRUE);
    ok(status == STATUS_INVALID_HANDLE, "NULL event async -> %08lx", (unsigned long)status);
    {
        HANDLE noNotify;
        init_ustr(&name, W("sub"));
        init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenKey(&noNotify, KEY_QUERY_VALUE, &attr);
        ok(status == STATUS_SUCCESS, "open query-only -> %08lx", (unsigned long)status);
        ev1 = make_event(FALSE);
        status = NtNotifyChangeKey(noNotify, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET,
                                   FALSE, NULL, 0, TRUE);
        ok(status == STATUS_ACCESS_DENIED, "no KEY_NOTIFY -> %08lx", (unsigned long)status);
        NtClose(ev1);
        NtClose(noNotify);
    }

    /* --- registration resets the event, returns PENDING; LAST_SET fires on
     * value set; the record survives firing and re-arms ------------------- */
    ev1 = make_event(TRUE); /* starts SET: registration must reset it */
    status = NtNotifyChangeKey(sub, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET, FALSE, NULL,
                               0, TRUE);
    ok(status == STATUS_PENDING, "arm -> %08lx", (unsigned long)status);
    status = poll_event(ev1);
    ok(status == STATUS_TIMEOUT, "registration reset the event -> %08lx", (unsigned long)status);
    val = 2;
    status = reg_set(sub, W("v"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set v -> %08lx", (unsigned long)status);
    status = await_event(ev1);
    ok(status == STATUS_SUCCESS, "LAST_SET fired -> %08lx", (unsigned long)status);

    /* Re-arm on the same handle: the record survived the firing. */
    status = NtNotifyChangeKey(sub, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET, FALSE, NULL,
                               0, TRUE);
    ok(status == STATUS_PENDING, "re-arm -> %08lx", (unsigned long)status);
    init_ustr(&name, W("v"));
    status = NtDeleteValueKey(sub, &name);
    ok(status == STATUS_SUCCESS, "delete v -> %08lx", (unsigned long)status);
    status = await_event(ev1);
    ok(status == STATUS_SUCCESS, "delete-value fired -> %08lx", (unsigned long)status);

    /* --- the same-handle record keeps its ORIGINAL filter; a second
     * registration only appends its event ---------------------------------- */
    ev2 = make_event(FALSE);
    status = NtNotifyChangeKey(sub, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET, FALSE, NULL,
                               0, TRUE);
    ok(status == STATUS_PENDING, "arm ev1 -> %08lx", (unsigned long)status);
    /* Same handle, DIFFERENT filter: the LAST_SET filter sticks. */
    status =
        NtNotifyChangeKey(sub, ev2, NULL, NULL, NULL, REG_NOTIFY_CHANGE_NAME, FALSE, NULL, 0, TRUE);
    ok(status == STATUS_PENDING, "arm ev2 same handle -> %08lx", (unsigned long)status);
    val = 3;
    status = reg_set(sub, W("v2"), REG_DWORD, &val, sizeof(val));
    ok(status == STATUS_SUCCESS, "set v2 -> %08lx", (unsigned long)status);
    status = await_event(ev1);
    ok(status == STATUS_SUCCESS, "accumulated ev1 fired -> %08lx", (unsigned long)status);
    status = await_event(ev2);
    ok(status == STATUS_SUCCESS, "accumulated ev2 fired under the ORIGINAL filter -> %08lx",
       (unsigned long)status);

    /* --- an independent handle is an independent record -------------------- */
    {
        HANDLE sub2;
        init_ustr(&name, W("sub"));
        init_attr(&attr, base, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenKey(&sub2, KEY_READ, &attr); /* KEY_READ includes KEY_NOTIFY */
        ok(status == STATUS_SUCCESS, "open sub2 -> %08lx", (unsigned long)status);
        /* Registration resets ev1 (pinned above), so no manual reset. */
        status = NtNotifyChangeKey(sub2, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_NAME, FALSE, NULL,
                                   0, TRUE);
        ok(status == STATUS_PENDING, "arm NAME on sub2 -> %08lx", (unsigned long)status);
        val = 4;
        status = reg_set(sub, W("v3"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set v3 -> %08lx", (unsigned long)status);
        status = poll_event(ev1);
        ok(status == STATUS_TIMEOUT, "NAME record missed LAST_SET -> %08lx", (unsigned long)status);
        /* Creating a subkey fires NAME on the parent (sub). */
        {
            HANDLE created;
            status = reg_create_sub(sub, W("kid"), &created, NULL);
            ok(status == STATUS_SUCCESS, "create kid -> %08lx", (unsigned long)status);
            status = await_event(ev1);
            ok(status == STATUS_SUCCESS, "create fired NAME on parent -> %08lx",
               (unsigned long)status);
            /* Deleting it fires NAME on the parent again. */
            status = NtNotifyChangeKey(sub2, ev1, NULL, NULL, NULL, REG_NOTIFY_CHANGE_NAME, FALSE,
                                       NULL, 0, TRUE);
            ok(status == STATUS_PENDING, "re-arm sub2 -> %08lx", (unsigned long)status);
            status = NtDeleteKey(created);
            ok(status == STATUS_SUCCESS, "delete kid -> %08lx", (unsigned long)status);
            NtClose(created);
            status = await_event(ev1);
            ok(status == STATUS_SUCCESS, "delete fired NAME on parent -> %08lx",
               (unsigned long)status);
        }
        NtClose(sub2);
    }

    /* --- subtree semantics -------------------------------------------------- */
    {
        HANDLE baseWatch;
        init_ustr(&name, W("prsk_m8_notify"));
        status = reg_open_path_access(base_path, KEY_NOTIFY, &baseWatch);
        ok(status == STATUS_SUCCESS, "open base watch -> %08lx", (unsigned long)status);
        ev2 = make_event(FALSE);
        status = NtNotifyChangeKey(baseWatch, ev2, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET,
                                   FALSE, NULL, 0, TRUE);
        ok(status == STATUS_PENDING, "arm base no-subtree -> %08lx", (unsigned long)status);
        val = 5;
        status = reg_set(gc, W("deep"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set deep -> %08lx", (unsigned long)status);
        status = poll_event(ev2);
        ok(status == STATUS_TIMEOUT, "no-subtree missed grandchild -> %08lx",
           (unsigned long)status);
        NtClose(baseWatch);
        /* The no-subtree record dies with its handle; a fresh handle armed
         * WITH subtree sees the grandchild. */
        status = reg_open_path_access(base_path, KEY_NOTIFY, &baseWatch);
        ok(status == STATUS_SUCCESS, "reopen base watch -> %08lx", (unsigned long)status);
        status = NtNotifyChangeKey(baseWatch, ev2, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET,
                                   TRUE, NULL, 0, TRUE);
        ok(status == STATUS_PENDING, "arm base subtree -> %08lx", (unsigned long)status);
        val = 6;
        status = reg_set(gc, W("deep"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set deep again -> %08lx", (unsigned long)status);
        status = await_event(ev2);
        ok(status == STATUS_SUCCESS, "subtree saw grandchild -> %08lx", (unsigned long)status);
        NtClose(baseWatch);
        NtClose(ev2);
    }

    /* --- rename fires NAME on the renamed key itself ------------------------ */
    {
        HANDLE gcWatch;
        status = reg_open_path_access(gc_path, KEY_NOTIFY, &gcWatch);
        ok(status == STATUS_SUCCESS, "open gc watch -> %08lx", (unsigned long)status);
        ev2 = make_event(FALSE);
        status = NtNotifyChangeKey(gcWatch, ev2, NULL, NULL, NULL, REG_NOTIFY_CHANGE_NAME, FALSE,
                                   NULL, 0, TRUE);
        ok(status == STATUS_PENDING, "arm gc NAME -> %08lx", (unsigned long)status);
        {
            NTSYSAPI NTSTATUS NTAPI NtRenameKey(HANDLE, UNICODE_STRING *);
            UNICODE_STRING newName;
            init_ustr(&newName, W("gc2"));
            status = NtRenameKey(gc, &newName);
            ok(status == STATUS_SUCCESS, "rename gc -> %08lx", (unsigned long)status);
            status = await_event(ev2);
            ok(status == STATUS_SUCCESS, "rename fired NAME on self -> %08lx",
               (unsigned long)status);
            init_ustr(&newName, W("gc"));
            status = NtRenameKey(gc, &newName);
            ok(status == STATUS_SUCCESS, "rename gc back -> %08lx", (unsigned long)status);
        }
        NtClose(gcWatch);
        NtClose(ev2);
    }

    /* --- deleting the watched key does NOT signal its own watcher; closing
     * the watching handle does --------------------------------------------- */
    {
        HANDLE gcWatch;
        status = reg_open_path_access(gc_path, KEY_NOTIFY, &gcWatch);
        ok(status == STATUS_SUCCESS, "open gc watch 2 -> %08lx", (unsigned long)status);
        ev2 = make_event(FALSE);
        status = NtNotifyChangeKey(gcWatch, ev2, NULL, NULL, NULL,
                                   REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME, FALSE, NULL,
                                   0, TRUE);
        ok(status == STATUS_PENDING, "arm doomed gc -> %08lx", (unsigned long)status);
        status = NtDeleteKey(gc);
        ok(status == STATUS_SUCCESS, "delete gc -> %08lx", (unsigned long)status);
        status = poll_event(ev2);
        ok(status == STATUS_TIMEOUT, "own watcher silent on delete -> %08lx",
           (unsigned long)status);
        NtClose(gcWatch);
        status = await_event(ev2);
        ok(status == STATUS_SUCCESS, "watcher handle close signaled -> %08lx",
           (unsigned long)status);
        NtClose(ev2);
        NtClose(gc);
        gc = NULL;
    }

    /* --- NtNotifyChangeMultipleKeys: the optional parameters are ignored and
     * the call proceeds on the primary key; the IOSB is never written -------- */
    {
        OBJECT_ATTRIBUTES subordinate;
        UNICODE_STRING subordinateName;
        unsigned char iosb[16];
        unsigned i;
        for (i = 0; i < sizeof(iosb); i++)
            iosb[i] = 0xa5;
        init_ustr(&subordinateName, W("\\Registry\\Machine\\Software"));
        init_attr(&subordinate, NULL, &subordinateName, OBJ_CASE_INSENSITIVE);
        /* Registration resets ev1 (pinned above), so no manual reset. */
        status = NtNotifyChangeMultipleKeys(sub, 1, &subordinate, ev1, NULL, NULL,
                                            (PIO_STATUS_BLOCK)(void *)iosb,
                                            REG_NOTIFY_CHANGE_LAST_SET, FALSE, NULL, 0, TRUE);
        ok(status == STATUS_PENDING, "multiple-keys arm -> %08lx", (unsigned long)status);
        val = 7;
        status = reg_set(sub, W("v4"), REG_DWORD, &val, sizeof(val));
        ok(status == STATUS_SUCCESS, "set v4 -> %08lx", (unsigned long)status);
        status = await_event(ev1);
        ok(status == STATUS_SUCCESS, "multiple-keys fired -> %08lx", (unsigned long)status);
        for (i = 0; i < sizeof(iosb); i++)
        {
            if (iosb[i] != 0xa5)
                break;
        }
        ok(i == sizeof(iosb), "IOSB untouched (byte %u)", i);
    }

    /* --- the synchronous form blocks until a change ------------------------- */
    {
        HANDLE mutator;
        sync_target = sub;
        mutator = CreateThread(NULL, 0, sync_mutator, NULL, 0, NULL);
        ok(mutator != NULL, "CreateThread");
        status = NtNotifyChangeKey(sub, NULL, NULL, NULL, NULL, REG_NOTIFY_CHANGE_LAST_SET, FALSE,
                                   NULL, 0, FALSE);
        ok(status == STATUS_SUCCESS, "sync notify -> %08lx", (unsigned long)status);
        if (mutator != NULL)
        {
            WaitForSingleObject(mutator, 5000);
            CloseHandle(mutator);
        }
    }

    /* Cleanup. */
    NtClose(ev1);
    reg_delete_path(gc_path);
    {
        init_ustr(&name, W("syncv"));
        NtDeleteValueKey(sub, &name);
        init_ustr(&name, W("v2"));
        NtDeleteValueKey(sub, &name);
        init_ustr(&name, W("v3"));
        NtDeleteValueKey(sub, &name);
        init_ustr(&name, W("v4"));
        NtDeleteValueKey(sub, &name);
        init_ustr(&name, W("deep"));
        /* deep lived on gc, already deleted */
    }
    status = NtDeleteKey(sub);
    ok(status == STATUS_SUCCESS, "cleanup sub -> %08lx", (unsigned long)status);
    NtClose(sub);
    status = NtDeleteKey(base);
    ok(status == STATUS_SUCCESS, "cleanup base -> %08lx", (unsigned long)status);
    NtClose(base);
}
