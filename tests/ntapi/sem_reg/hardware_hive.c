/*
 * sem_reg/hardware_hive.c — HKLM\HARDWARE exists and is a volatile hive.
 *
 * NT builds HARDWARE at boot from firmware and never persists it:
 *
 *   "HKEY_LOCAL_MACHINE\HARDWARE — ... This key is volatile ... The data is
 *   re-created each time the system is started."
 *   (learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-local-machine; the
 *   "Registry Hives" page lists it with no supporting file.)
 *
 * The oracle agrees, from the other end: `wineboot --init` calls
 * create_hardware_registry_keys (programs/wineboot/wineboot.c — its own
 * comment reads "create the volatile hardware registry keys"), which creates
 * Hardware\Description\System with REG_OPTION_VOLATILE and so brings
 * HKLM\Hardware itself into being as a volatile key. So this is an ORDINARY
 * pinned case, green on Wine before the kernel implements it — no
 * beyond_oracle escape, which would be the wrong tool for behaviour the
 * oracle does implement.
 *
 * Two things are asserted, and the second is the load-bearing one: "the key
 * exists" alone would be satisfied by an ordinary persisted key, which is
 * exactly what must NOT be there. Volatility is observable from ring 3
 * without a reboot, because a stable child of a volatile parent is refused
 * (STATUS_CHILD_MUST_BE_VOLATILE — the general rule sem_reg/delete.c pins).
 * That refusal IS the guarantee that nothing under HARDWARE can reach a hive
 * file.
 *
 * proskrnl seeds the key at CmInitialize rather than waiting for wineboot,
 * because the kernel reads its own boot flags out of it before any user
 * process runs; what it puts UNDER it (HARDWARE\qemu, the QEMU command
 * line's flags — docs/10 HACK-006) is NT-absent and deliberately not
 * asserted here.
 */
#include "util.h"

static const void *hardware_path = W("\\Registry\\Machine\\Hardware");

START_TEST(hardware_hive)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE hardware, child;
    NTSTATUS status;

    init_ustr(&name, hardware_path);
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    hardware = NULL;
    status = NtOpenKey(&hardware, KEY_READ | KEY_CREATE_SUB_KEY, &attr);
    ok(status == STATUS_SUCCESS, "open HKLM\\Hardware -> %08lx", (unsigned long)status);
    if (!NT_SUCCESS(status))
        return;

    /* The hive is volatile, so a stable child is refused. A key seeded as an
     * ordinary persisted one would answer SUCCESS here. */
    init_ustr(&name, W("prsk_hardware_stable"));
    init_attr(&attr, hardware, &name, OBJ_CASE_INSENSITIVE);
    child = NULL;
    status = NtCreateKey(&child, KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL);
    ok(status == STATUS_CHILD_MUST_BE_VOLATILE, "stable child of HKLM\\Hardware -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtDeleteKey(child);
        NtClose(child);
    }

    /* A volatile child is allowed, and is deleted again so the case leaves
     * the hive as it found it. */
    child = NULL;
    status = NtCreateKey(&child, KEY_ALL_ACCESS, &attr, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ok(status == STATUS_SUCCESS, "volatile child of HKLM\\Hardware -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtDeleteKey(child);
        NtClose(child);
    }

    NtClose(hardware);
}
