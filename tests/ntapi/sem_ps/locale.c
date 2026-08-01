/*
 * sem_ps/locale.c — the CUI-7 locale/UI-language services:
 * NtSetDefaultLocale, NtQueryDefaultUILanguage, NtSetDefaultUILanguage,
 * NtQueryInstallUILanguage (+ NtQueryDefaultLocale finally honoring its
 * userProfile argument).
 *
 * Oracle behaviour pinned from the pinned tree (wine
 * dlls/ntdll/unix/env.c:2272-2317): three process-wide slots — user LCID,
 * system LCID, user UI language. NtQueryDefaultLocale(user) reads one or
 * the other; NtSetDefaultLocale writes one or the other;
 * NtQueryDefaultUILanguage / NtSetDefaultUILanguage exchange the UI slot;
 * NtQueryInstallUILanguage has no setter of its own — it DERIVES from the
 * system LCID (LANGIDFROMLCID), so NtSetDefaultLocale(FALSE, x) moves it.
 * No privilege checks anywhere. Absolute initial values are never asserted
 * (the oracle seeds from the host locale); every slot is saved first and
 * restored on exit.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryDefaultLocale(BOOLEAN, LCID *);
NTSYSAPI NTSTATUS NTAPI NtSetDefaultLocale(BOOLEAN, LCID);
NTSYSAPI NTSTATUS NTAPI NtQueryDefaultUILanguage(LANGID *);
NTSYSAPI NTSTATUS NTAPI NtSetDefaultUILanguage(LANGID);
NTSYSAPI NTSTATUS NTAPI NtQueryInstallUILanguage(LANGID *);

START_TEST(locale)
{
    NTSTATUS status;
    LCID userLcid = 0, systemLcid = 0, check = 0;
    LANGID uiLanguage = 0, installLanguage = 0, checkLang = 0;

    /* --- capture the boot state (never asserted absolutely) ----------------- */
    status = NtQueryDefaultLocale(TRUE, &userLcid);
    ok(status == STATUS_SUCCESS, "query user lcid -> %08lx", (unsigned long)status);
    ok(userLcid != 0, "user lcid nonzero");
    status = NtQueryDefaultLocale(FALSE, &systemLcid);
    ok(status == STATUS_SUCCESS, "query system lcid -> %08lx", (unsigned long)status);
    ok(systemLcid != 0, "system lcid nonzero");
    status = NtQueryDefaultUILanguage(&uiLanguage);
    ok(status == STATUS_SUCCESS, "query ui language -> %08lx", (unsigned long)status);
    status = NtQueryInstallUILanguage(&installLanguage);
    ok(status == STATUS_SUCCESS, "query install language -> %08lx", (unsigned long)status);
    ok(installLanguage == LANGIDFROMLCID(systemLcid), "install derives from system (%04x/%04lx)",
       installLanguage, (unsigned long)systemLcid);

    /* --- the user slot round-trips without touching the system slot --------- */
    status = NtSetDefaultLocale(TRUE, 0x0407);
    ok(status == STATUS_SUCCESS, "set user lcid -> %08lx", (unsigned long)status);
    status = NtQueryDefaultLocale(TRUE, &check);
    ok(status == STATUS_SUCCESS && check == 0x0407, "user lcid set (%04lx)", (unsigned long)check);
    status = NtQueryDefaultLocale(FALSE, &check);
    ok(status == STATUS_SUCCESS && check == systemLcid, "system lcid untouched (%04lx)",
       (unsigned long)check);
    status = NtQueryDefaultUILanguage(&checkLang);
    ok(status == STATUS_SUCCESS && checkLang == uiLanguage, "ui language untouched (%04x)",
       checkLang);

    /* --- the system slot moves the install UI language ---------------------- */
    status = NtSetDefaultLocale(FALSE, 0x040c);
    ok(status == STATUS_SUCCESS, "set system lcid -> %08lx", (unsigned long)status);
    status = NtQueryDefaultLocale(FALSE, &check);
    ok(status == STATUS_SUCCESS && check == 0x040c, "system lcid set (%04lx)",
       (unsigned long)check);
    status = NtQueryInstallUILanguage(&checkLang);
    ok(status == STATUS_SUCCESS && checkLang == LANGIDFROMLCID(0x040c),
       "install language follows system (%04x)", checkLang);
    status = NtQueryDefaultLocale(TRUE, &check);
    ok(status == STATUS_SUCCESS && check == 0x0407, "user lcid still set (%04lx)",
       (unsigned long)check);

    /* --- the UI slot is its own -------------------------------------------- */
    status = NtSetDefaultUILanguage(0x0410);
    ok(status == STATUS_SUCCESS, "set ui language -> %08lx", (unsigned long)status);
    status = NtQueryDefaultUILanguage(&checkLang);
    ok(status == STATUS_SUCCESS && checkLang == 0x0410, "ui language set (%04x)", checkLang);
    status = NtQueryDefaultLocale(TRUE, &check);
    ok(status == STATUS_SUCCESS && check == 0x0407, "user lcid unmoved by ui set (%04lx)",
       (unsigned long)check);

    /* --- restore the boot state --------------------------------------------- */
    status = NtSetDefaultLocale(TRUE, userLcid);
    ok(status == STATUS_SUCCESS, "restore user lcid -> %08lx", (unsigned long)status);
    status = NtSetDefaultLocale(FALSE, systemLcid);
    ok(status == STATUS_SUCCESS, "restore system lcid -> %08lx", (unsigned long)status);
    status = NtSetDefaultUILanguage(uiLanguage);
    ok(status == STATUS_SUCCESS, "restore ui language -> %08lx", (unsigned long)status);
    status = NtQueryDefaultLocale(TRUE, &check);
    ok(status == STATUS_SUCCESS && check == userLcid, "user lcid restored");
    status = NtQueryDefaultLocale(FALSE, &check);
    ok(status == STATUS_SUCCESS && check == systemLcid, "system lcid restored");
    status = NtQueryDefaultUILanguage(&checkLang);
    ok(status == STATUS_SUCCESS && checkLang == uiLanguage, "ui language restored");
}
