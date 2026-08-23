/* user/smss/smss.c — the proskrnl session manager: entry point + utilities.
 *
 * Historically (M8) this was a chain proof — verify the registry, spawn one
 * child, exit with its code. It is now the real thing: the kernel launches
 * exactly one user image (kernel/init/main.c KiRunSessionManager), and this
 * process owns everything user-mode that follows, spawning it through the
 * NtCreateUserProcess boundary:
 *
 *   1. prove the registry is up from ring 3 (\Registry\Machine opens);
 *   2. start the system servers — wineserver-lite, then conhost (launch.c);
 *   3. firstboot: wineboot --init applies wine.inf (firstboot.c);
 *   4. an interactive boot (the QEMU command line's interactive flag,
 *      SmssIsInteractiveBoot) hands the console to a
 *      human cmd.exe; otherwise the acceptance flows and test sweeps run
 *      (session.c) and smss exits with the failure count.
 *
 * Verdict lines go out through NtDisplayString — the same serial transport
 * the kernel's [KTEST] lines use (kernel/ps/display.c), so the harness
 * greps are unchanged. A native ntdll-only PE, like hello.exe.
 */
#include "user/smss/smss.h"

#include "abi/ntregapi.h"

#include <stdarg.h>

void SmssSay(const char *ascii)
{
    while (*ascii != '\0')
    {
        WCHAR wide[80];
        USHORT n = 0;
        while (ascii[n] != '\0' && n < 79)
        {
            wide[n] = (WCHAR)(unsigned char)ascii[n];
            n++;
        }
        UNICODE_STRING string;
        string.Length = (USHORT)(n * sizeof(WCHAR));
        string.MaximumLength = string.Length;
        string.Buffer = wide;
        NtDisplayString(&string);
        ascii += n;
    }
}

static void SmssFormatChar(char *buf, unsigned size, unsigned *pos, char c)
{
    if (*pos + 1 < size)
        buf[(*pos)++] = c;
}

static void SmssFormatUnsigned(char *buf, unsigned size, unsigned *pos, unsigned long long value,
                               unsigned base)
{
    char digits[24];
    unsigned n = 0;
    do
    {
        unsigned d = (unsigned)(value % base);
        digits[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        value /= base;
    } while (value != 0);
    while (n != 0)
        SmssFormatChar(buf, size, pos, digits[--n]);
}

/* The analyzer does not model the Windows target's __builtin_ms_va_start, so
 * every va_arg below reads as "uninitialized va_list" under the mingw triple
 * `make format` uses for this PE; the same code is clean under an ELF triple. */
/* NOLINTBEGIN(clang-analyzer-valist.Uninitialized) */
void SmssPrintf(const char *fmt, ...)
{
    char buf[192];
    unsigned pos = 0;
    va_list ap;
    va_start(ap, fmt);
    for (; *fmt != '\0'; fmt++)
    {
        if (*fmt != '%')
        {
            SmssFormatChar(buf, sizeof(buf), &pos, *fmt);
            continue;
        }
        fmt++;
        switch (*fmt)
        {
        case 's':
        {
            const char *s = va_arg(ap, const char *);
            while (*s != '\0')
                SmssFormatChar(buf, sizeof(buf), &pos, *s++);
            break;
        }
        case 'd':
        {
            int v = va_arg(ap, int);
            unsigned long long u = (unsigned long long)v;
            if (v < 0)
            {
                SmssFormatChar(buf, sizeof(buf), &pos, '-');
                u = (unsigned long long)-(long long)v;
            }
            SmssFormatUnsigned(buf, sizeof(buf), &pos, u, 10);
            break;
        }
        case 'u':
            SmssFormatUnsigned(buf, sizeof(buf), &pos, va_arg(ap, unsigned), 10);
            break;
        case 'x':
        {
            /* The kernel DbgPrint %#lx spelling: always 0x-prefixed
             * ("exit=0x0"), so smss verdict lines match the historical ones. */
            SmssFormatChar(buf, sizeof(buf), &pos, '0');
            SmssFormatChar(buf, sizeof(buf), &pos, 'x');
            SmssFormatUnsigned(buf, sizeof(buf), &pos, va_arg(ap, unsigned long long), 16);
            break;
        }
        case '%':
            SmssFormatChar(buf, sizeof(buf), &pos, '%');
            break;
        default:
            SmssFormatChar(buf, sizeof(buf), &pos, '%');
            if (*fmt != '\0')
                SmssFormatChar(buf, sizeof(buf), &pos, *fmt);
            break;
        }
        if (*fmt == '\0')
            break;
    }
    va_end(ap);
    buf[pos] = '\0';
    SmssSay(buf);
}
/* NOLINTEND(clang-analyzer-valist.Uninitialized) */

void SmssInitUnicodeString(UNICODE_STRING *str, const WCHAR *wide)
{
    USHORT n = 0;
    while (wide[n] != 0)
        n++;
    str->Length = (USHORT)(n * sizeof(WCHAR));
    str->MaximumLength = (USHORT)(str->Length + sizeof(WCHAR));
    str->Buffer = (PWSTR)wide;
}

void SmssSleep(ULONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)milliseconds * 10000; /* relative, 100 ns */
    NtDelayExecution(FALSE, &interval);
}

/* --- the QEMU boot flags (HACK-006) ---------------------------------------
 *
 * Read from the same place the kernel reads them: the volatile
 * \Registry\Machine\Hardware\qemu key the kernel published from the QEMU
 * command line's fw_cfg items (kernel/cm/registry.c). No key means no fw_cfg
 * device, i.e. not a QEMU guest — nothing there is scraping a serial log, so
 * each caller's `whenNotQemu` applies. The kernel's KiIsInteractiveBoot
 * states the same rule for its own half of the boot; the two are separate
 * address spaces, not a second authority.
 *
 * Opening the key is factored out because both the DWORD flags and the REG_SZ
 * strings below need it, and a second open site is a second set of rules
 * about what an absent key means (Art. 11).
 */
static NTSTATUS SmssOpenQemuKey(HANDLE *keyOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    SmssInitUnicodeString(&name, WSTR("\\Registry\\Machine\\Hardware\\qemu"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    return NtOpenKey(keyOut, KEY_QUERY_VALUE, &attr);
}

/* TRUE when the open failed because the key is not there — the ONE failure
 * that means "not a QEMU guest". Anything else is a broken registry, which
 * must be said out loud rather than read as a default (Art. 12's spirit). */
static int SmssQemuKeyAbsent(NTSTATUS status)
{
    return status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND;
}

ULONG SmssQemuFlag(const WCHAR *valueName, ULONG whenNotQemu)
{
    HANDLE key;
    NTSTATUS open = SmssOpenQemuKey(&key);
    if (SmssQemuKeyAbsent(open))
        return whenNotQemu;
    if (open != STATUS_SUCCESS)
    {
        SmssPrintf("smss: HKLM\\Hardware\\qemu open failed (%x); reading flags as 0\n",
                   SMSS_HEX(open));
        return 0;
    }

    UNICODE_STRING name;
    SmssInitUnicodeString(&name, valueName);
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    ULONG resultLength = 0;
    NTSTATUS status = NtQueryValueKey(key, &name, KeyValuePartialInformation, buffer,
                                      sizeof(buffer), &resultLength);
    NtClose(key);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return 0; /* the key exists, so QEMU decided: an absent flag is off */
    if (status != STATUS_SUCCESS || info->Type != REG_DWORD || info->DataLength != sizeof(ULONG))
    {
        /* The key is volatile, not read-only, so ring 3 can have overwritten
         * the flag with anything; 0 is the safe reading, but not a silent one
         * (the kernel's CmQueryQemuBootFlag says the same). */
        SmssPrintf("smss: HKLM\\Hardware\\qemu flag is not a REG_DWORD (%x); reading 0\n",
                   SMSS_HEX(status));
        return 0;
    }

    ULONG value;
    for (unsigned int i = 0; i < sizeof(value); i++)
        ((UCHAR *)&value)[i] = info->Data[i];
    return value;
}

void SmssQemuString(const WCHAR *valueName, WCHAR *out, ULONG outChars)
{
    out[0] = 0;
    if (outChars == 0)
        return;

    HANDLE key;
    NTSTATUS open = SmssOpenQemuKey(&key);
    if (open != STATUS_SUCCESS)
    {
        if (!SmssQemuKeyAbsent(open))
            SmssPrintf("smss: HKLM\\Hardware\\qemu open failed (%x); reading strings as \"\"\n",
                       SMSS_HEX(open));
        return; /* not a QEMU guest, or unreadable: the empty string */
    }

    UNICODE_STRING name;
    SmssInitUnicodeString(&name, valueName);
    /* One buffer for the header plus the longest string the kernel publishes
     * (kernel/cm/registry.c CMP_QEMU_STRING_MAX) and its terminator. */
    static UCHAR SmssQemuStringBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                                      (SMSS_QEMU_STRING_MAX + 1) * sizeof(WCHAR)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)SmssQemuStringBuffer;
    ULONG resultLength = 0;
    NTSTATUS status = NtQueryValueKey(key, &name, KeyValuePartialInformation, SmssQemuStringBuffer,
                                      sizeof(SmssQemuStringBuffer), &resultLength);
    NtClose(key);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        /* The key exists, so QEMU decided and an absent string is the empty
         * one — but SAY which value was absent. Silence here reads exactly
         * like a value that was there and empty, and those mean different
         * things: the first is a boot that never asked, the second a boot
         * that asked for nothing. */
        SmssPrintf("smss: HKLM\\Hardware\\qemu has no such value; reading \"\"\n");
        return;
    }
    if (status != STATUS_SUCCESS || info->Type != REG_SZ)
    {
        /* STATUS_BUFFER_OVERFLOW here means the kernel published a string
         * longer than SMSS_QEMU_STRING_MAX, i.e. the two caps have drifted —
         * named separately because reading it as "" means "no filter", which
         * is a DIFFERENT run rather than a missing one. */
        SmssPrintf("smss: HKLM\\Hardware\\qemu %s (%x); reading \"\"\n",
                   status == STATUS_BUFFER_OVERFLOW ? "string is longer than this build's cap"
                                                    : "string is not a REG_SZ",
                   SMSS_HEX(status));
        return;
    }

    /* KEY_VALUE_PARTIAL_INFORMATION.Data is a UCHAR[] carrying REG_SZ's
     * UTF-16, and its alignment is the buffer's rather than the type's, so
     * each character is assembled from its two bytes instead of read through
     * a WCHAR pointer at an address the compiler may not assume aligned. */
    ULONG chars = info->DataLength / sizeof(WCHAR);
    if (chars > outChars - 1)
        chars = outChars - 1;
    ULONG i = 0;
    while (i < chars)
    {
        WCHAR c;
        for (unsigned int b = 0; b < sizeof(c); b++)
            ((UCHAR *)&c)[b] = info->Data[i * sizeof(WCHAR) + b];
        if (c == 0)
            break;
        out[i] = c;
        i++;
    }
    out[i] = 0;
}

/* The interactive boot: unspecified under QEMU means the ordinary scripted
 * session, and no QEMU at all means a human (nothing off-box is scraping a
 * serial log). */
int SmssIsInteractiveBoot(void)
{
    return SmssQemuFlag(WSTR("Interactive"), 1) != 0;
}

/* The windowed console. Defaults ON — including off QEMU — because one image
 * now carries both arrangements and the windowed one over the desktop stack
 * is the product; a boot whose verdict rides the SERIAL console says so on
 * the command line (tools/qemu.sh GUEST_GUI=0). */
int SmssIsGuiBoot(void)
{
    return SmssQemuFlag(WSTR("Gui"), 1) != 0;
}

/* Does this boot have a Windows USERLAND to bring up -- a conhost to start, a
 * prefix for wineboot to initialise? The product image does; a hermetic kernel
 * fixture (tests/fuzz/fuzz.py bakes ntdll/kernel32/kernelbase, the NLS tables,
 * smss and one client) does not.
 *
 * Not probed for, because "the file is absent" is the same bytes for a fixture
 * that never had one and a product bake that LOST one -- and not a flag of its
 * own either. It is DERIVED from the leg name and published beside it by the
 * kernel (kernel/cm/registry.c CmpNoUserlandLegs), which has to know first:
 * the M7 module runner and the ABI probe are kernel-side and run before smss
 * starts. One derivation, published as a value, read here. */
int SmssHasUserland(void)
{
    return SmssQemuFlag(WSTR("Userland"), 1) != 0;
}

/* Does this boot keep its console on the SERIAL transport? A no-op without a
 * desktop (see SmssConsoleWantsWindow). */
int SmssIsSerialBoot(void)
{
    return SmssQemuFlag(WSTR("Serial"), 0) != 0;
}

/* Does explorer own the desktop on this boot?
 *
 * DERIVED, not a flag of its own. A machine a human sits at has a shell, so
 * an INTERACTIVE desktop boot gets one; and GUI-6, whose whole subject is
 * Wine's explorer owning the desktop, asks for one by being that leg
 * (SessionIsShellIntegrationLeg). Every other scripted GUI gate runs a
 * purpose-built client on the server's own desktop fixtures, which is what
 * its golden was measured against.
 *
 * It used to be a flag, and a flag is a thing every caller can forget:
 * defaulting OFF, it meant `make rungui` came up without the shell it had
 * always had. Derived, the answer follows from what the boot already is. */
int SmssIsShellBoot(void)
{
    /* `Serial` is what separates the two interactive desktop boots. A human at
     * the machine reads the console off the screen, so their session is the
     * shell: explorer owns the desktop and IS the launcher. A boot that asks
     * for the console on the SERIAL transport is asking for a console session
     * -- something off-box is driving it and reading its verdicts -- and a
     * shell would leave that driver with no prompt to type at.
     *
     * GUI-6 is not subject to that: its whole milestone is Wine's explorer
     * owning the desktop, photographed against a golden, and it takes its
     * verdict off the serial log like every scripted leg.
     *
     * GUI-5's console-window leg is the one exception in the other direction:
     * it needs the prompt AND the window, which `Serial` cannot express while
     * a boot has just one console (SessionIsWindowedConsoleLeg says why).
     *
     * Two leg names are read here, not one -- gui5con to subtract it and gui6
     * to add it -- and they are the only boot decisions left anywhere that
     * read one. Both retire the same way: give smss a console it can open on
     * the desktop while its own stays on serial, and gui5con becomes an
     * ordinary `Serial`=1 leg; make the shell a thing a leg RUNS rather than a
     * property of the session, and gui6 does too. */
    if (SessionIsWindowedConsoleLeg())
        return 0;
    return SmssIsGuiBoot() &&
           ((SmssIsInteractiveBoot() && !SmssIsSerialBoot()) || SessionIsShellIntegrationLeg());
}

/* Does conhost put up a WINDOW, or stay on the serial transport?
 *
 * A window needs a desktop to put it on, so `Gui`=0 has nowhere to put one
 * and `Serial` is a no-op there. On a boot that HAS a desktop the windowed
 * console is the default -- it is the product -- and a leg whose verdict is
 * a string in the serial log says so with `Serial` (every scripted GUI gate
 * does; gui6 additionally would have a console window in the picture it
 * photographs).
 *
 * Not derived from `Interactive`, though it nearly could be: today every
 * boot wanting the windowed console happens to be interactive, but "is a
 * human here" and "where does the console go" are different questions, and
 * a derivation cannot express a windowed console on a scripted boot.
 *
 * TODO: `Gui`=0 with `Serial`=0 is the third destination -- a framebuffer
 * terminal, conhost drawing the console on the scanout with no desktop under
 * it. Unbuilt: that boot takes the serial transport today, which is why
 * `Serial` reads as a no-op rather than a refusal there. */
int SmssConsoleWantsWindow(void)
{
    return SmssIsGuiBoot() && !SmssIsSerialBoot();
}

/* Publish both derived answers where the PE side reads its boot facts: the
 * volatile HKLM\Hardware\qemu the kernel seeded from fw_cfg. They sit beside
 * those values but are NOT of them -- the kernel publishes what the command
 * line SAID, smss publishes what it MEANS -- and both names differ from the
 * `Shell`/`Gui` a stale reader would look for, so such a reader finds
 * nothing rather than a plausible answer. */
void SmssPublishShellBoot(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key = 0;
    SmssInitUnicodeString(&name, WSTR("\\Registry\\Machine\\Hardware\\qemu"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtOpenKey(&key, KEY_SET_VALUE, &attr);
    if (status != STATUS_SUCCESS)
        return; /* not a QEMU guest: nothing publishes, nothing reads */

    static const struct
    {
        const WCHAR *name;
        int (*answer)(void);
    } derived[] = {
        {WSTR("ShellBoot"), SmssIsShellBoot},
        {WSTR("ConsoleWindow"), SmssConsoleWantsWindow},
    };
    for (unsigned int i = 0; i < sizeof(derived) / sizeof(derived[0]); i++)
    {
        ULONG value = derived[i].answer() ? 1 : 0;
        UNICODE_STRING valueName;
        SmssInitUnicodeString(&valueName, derived[i].name);
        status = NtSetValueKey(key, &valueName, 0, REG_DWORD, &value, sizeof(value));
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] bootderive FAIL (write=%x)\n", SMSS_HEX(status));
            NtClose(key);
            return;
        }
    }
    NtClose(key);
    /* The INPUTS beside the answers: a derived value whose derivation cannot
     * be read off the log is one nobody can check. leg="" here is what sent
     * me chasing a guiwtest boot that had been given GUEST_LEG=guiwtest. */
    SmssPrintf("smss: gui=%u interactive=%u leg=\"%s\" -> shell=%u conwindow=%u\n",
               (unsigned int)(SmssIsGuiBoot() != 0), (unsigned int)(SmssIsInteractiveBoot() != 0),
               SessionLegName(), (unsigned int)(SmssIsShellBoot() != 0),
               (unsigned int)(SmssConsoleWantsWindow() != 0));
}

RTL_USER_PROCESS_PARAMETERS *SmssOwnParams;

/* The kernel passes its pre-session context on the command line
 * (KiRunSessionManager): "abi=<n>" is the ABI conformance probe's failure
 * count, folded into the M9 verdict exactly as the kernel runner folded it
 * (an unconsumed-convention regression must still flip `make test`). */
static int SmssParseAbiFailures(void)
{
    if (SmssOwnParams == 0 || SmssOwnParams->CommandLine.Buffer == 0)
        return 0;
    const WCHAR *cmd = SmssOwnParams->CommandLine.Buffer;
    USHORT len = (USHORT)(SmssOwnParams->CommandLine.Length / sizeof(WCHAR));
    static const WCHAR key[] = WSTR("abi=");
    for (USHORT i = 0; i + 4 < len; i++)
    {
        USHORT k = 0;
        while (k < 4 && cmd[i + k] == key[k])
            k++;
        if (k != 4)
            continue;
        int value = 0;
        for (USHORT j = i + 4; j < len && cmd[j] >= '0' && cmd[j] <= '9'; j++)
            value = value * 10 + (cmd[j] - '0');
        return value;
    }
    return 0;
}

/* 1. The registry the kernel mounted must be reachable from ring 3 — the M8
 * duty, kept as the session's first check. */
static int SmssRegistryReachable(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE machine;
    SmssInitUnicodeString(&name, WSTR("\\Registry\\Machine"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtOpenKey(&machine, KEY_READ, &attr);
    if (status != STATUS_SUCCESS)
    {
        SmssSay("smss: registry not reachable\n");
        return 0;
    }
    NtClose(machine);
    return 1;
}

/* CUI-1 firstboot: run `wineboot --init` (firstboot.c) so wine.inf's
 * machine-state registry payload is applied before anything else uses the
 * hive. A boot with no Windows userland at all -- the hermetic kernel
 * fixtures -- skips it, and says so with `Userland` rather than being probed
 * for (SmssHasUserland). wineboot's own .update-timestamp freshness check
 * makes non-first boots near-instant. */
static int SmssRunFirstboot(void)
{
    /* No probe: the PRODUCT image carries wineboot.exe on every boot, so a
     * missing one is a broken bake and must fail loudly rather than yield a
     * machine with no registry population and no explanation. A hermetic
     * kernel fixture has no prefix to initialise, and the boot says so by
     * naming a fixture leg (`Userland`, derived) -- a boot fact, not something
     * the volume can be asked. */
    if (!SmssHasUserland())
    {
        SmssSay("smss: no Windows userland on this boot; firstboot skipped\n");
        return 0;
    }
    NTSTATUS exitStatus = FirstbootRun();
    if (exitStatus != 0)
    {
        SmssPrintf("[KTEST] firstboot FAIL (exit=%x)\n", SMSS_HEX(exitStatus));
        return 1;
    }
    SmssSay("[KTEST] firstboot PASS\n");
    return 0;
}

/* GUI-6, and the interactive shell session `make rungui` gives a human:
 * route every GUI client onto explorer's desktop by machine state rather
 * than plumbing. Two values -- HKCU\Software\Wine\Explorer
 * "Desktop"="shell" and Explorer\Desktops "shell"="1280x800", the
 * configuration a Wine user sets for a virtual desktop -- make win32u's
 * get_default_desktop (dlls/win32u/winstation.c) land every self-creating
 * client (the windowed conhost, cmd's applet children) on desktop "shell",
 * and the first client's get_desktop_window auto-launches explorer onto
 * it, taskbar and all (the magic name;
 * programs/explorer/desktop.c get_default_enable_shell). 1280x800 is the
 * scanout (one mode, HACK-001).
 *
 * Written by smss itself, native Nt* calls, BEFORE the windowed conhost
 * starts: a client picks its desktop at win32u attach, so the routing must
 * already be in the hive when the first client connects -- and the writer
 * must not itself be a GUI process. The first cut ran the values in
 * through rundll32/setupapi (an .inf), and that was the defect: rundll32
 * is a GUI client, its stub window forced a desktop into existence BEFORE
 * the values it was carrying were written, so the boot grew a transient
 * registry-less desktop with its own auto-launched explorer, and the real
 * session's windows sat beside a dead sibling arrangement that click
 * activation then tripped over.
 *
 * Gated on the boot's flags, not on explorer's presence: the gui6 leg (same
 * shell payload, no interactive flag) launches explorer explicitly with
 * /desktop=shell,WxH and needs no routing values -- and writing them there
 * would hand firstboot's transient rundll32 children a desktop auto-launch
 * of their own, changing what its golden pinned. */
/* Write one REG_SZ under \Registry\User\<sid> -- the fixed Se identity
 * (kernel/se/token.c); the skeleton root exists from boot
 * (kernel/cm/registry.c). NtCreateKey creates one level, so the subkey path
 * is walked and each component created -- the parents may not exist on a
 * virgin hive. Shared by the shell desktop routing and the audio driver
 * seed below (one spelling, Art. 11). Returns the failing status or 0. */
static NTSTATUS SmssWriteUserValue(const WCHAR *subkey, const WCHAR *valueNameStr,
                                   const WCHAR *value)
{
    WCHAR path[128];
    unsigned int n = 0;
    const WCHAR *prefix = WSTR("\\Registry\\User\\S-1-5-21-0-0-0-1000\\");
    while (prefix[n] != 0)
    {
        path[n] = prefix[n];
        n++;
    }
    for (unsigned int j = 0;; j++)
    {
        WCHAR c = subkey[j];
        if (c != 0 && c != '\\')
        {
            path[n++] = c;
            continue;
        }
        path[n] = 0;

        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        HANDLE key = 0;
        ULONG disposition = 0;
        SmssInitUnicodeString(&name, path);
        attr.Length = sizeof(attr);
        attr.RootDirectory = 0;
        attr.ObjectName = &name;
        attr.Attributes = OBJ_CASE_INSENSITIVE;
        attr.SecurityDescriptor = 0;
        attr.SecurityQualityOfService = 0;
        NTSTATUS status = NtCreateKey(&key, KEY_ALL_ACCESS, &attr, 0, 0, 0, &disposition);
        if (status != STATUS_SUCCESS)
            return status;
        if (c == 0)
        {
            UNICODE_STRING valueName;
            SmssInitUnicodeString(&valueName, valueNameStr);
            unsigned int chars = 0;
            while (value[chars] != 0)
                chars++;
            status = NtSetValueKey(key, &valueName, 0, REG_SZ, (void *)value,
                                   (chars + 1) * sizeof(WCHAR));
            NtClose(key);
            return status;
        }
        NtClose(key);
        path[n++] = '\\';
    }
}

static void SmssShellDesktopConfig(void)
{
    static const struct
    {
        const WCHAR *key;
        const WCHAR *name;
        const WCHAR *value;
    } values[] = {
        {WSTR("Software\\Wine\\Explorer"), WSTR("Desktop"), WSTR("shell")},
        {WSTR("Software\\Wine\\Explorer\\Desktops"), WSTR("shell"), WSTR("1280x800")},
    };

    /* Gated on the DERIVED ShellBoot (SmssIsShellBoot; there is no
     * GUEST_SHELL -- tools/qemu.sh says so) and on the boot
     * being interactive: these values arrange the AUTO-LAUNCH, which is the
     * shell session a human gets. The gui6 leg is a shell boot too but not
     * an interactive one — it launches explorer explicitly with
     * /desktop=shell,WxH and needs no routing values, and writing them there
     * would hand firstboot's transient rundll32 children a desktop
     * auto-launch of their own, changing what its golden pinned. */
    /* No probe: one image carries explorer.exe on every boot, so its
     * presence decides nothing. SmssIsShellBoot does. */
    if (!SmssIsShellBoot() || !SmssIsInteractiveBoot())
        return;

    for (unsigned int i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        NTSTATUS status = SmssWriteUserValue(values[i].key, values[i].name, values[i].value);
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] shellcfg FAIL (write=%x)\n", SMSS_HEX(status));
            return;
        }
    }
    SmssSay("[KTEST] shellcfg PASS\n");
}

/* AUD-2 (docs/23 §4c): select winevsnd as mmdevapi's driver by the registry
 * mechanism mmdevapi already reads (HKCU Software\Wine\Drivers, value
 * "Audio" -- dlls/mmdevapi/main.c init_driver). Gated on the driver
 * actually being on the image: with the value absent mmdevapi walks its
 * default list (pulse,alsa,oss,coreaudio), none of which the image
 * carries, and honestly enumerates zero endpoints -- a machine with no
 * sound device, which is what an image without winevsnd.drv is. Written by
 * smss with native Nt* calls before any audio client, the shell desktop
 * routing's precedent. */
static void SmssAudioDriverConfig(void)
{
    /* No probe: one image carries winevsnd.drv on every boot. Whether the
     * machine HAS a sound device is a QEMU command-line question, and
     * mmdevapi honestly enumerating zero endpoints on a boot without
     * virtio-snd is the right answer either way -- naming the driver here
     * does not conjure one. */
    NTSTATUS status =
        SmssWriteUserValue(WSTR("Software\\Wine\\Drivers"), WSTR("Audio"), WSTR("vsnd"));
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] audiocfg FAIL (write=%x)\n", SMSS_HEX(status));
        return;
    }
    SmssSay("[KTEST] audiocfg PASS\n");
}

void SmssStart(void *pebArg)
{
    PEB *peb = pebArg;
    SmssOwnParams = peb != 0 ? peb->ProcessParameters : 0;

    SmssSay("smss: session manager up\n");
    int abiFailures = SmssParseAbiFailures();
    int registryOk = SmssRegistryReachable();

    /* The servers, in dependency order (launch.c): wineserver-lite before
     * ANY win32u client — firstboot's wineboot is one, and so is the GUI-5
     * windowed conhost — then conhost itself. The shell desktop routing
     * must land BETWEEN them: the windowed conhost picks its desktop at
     * win32u attach (winstation_init reads the registry), so the values
     * have to be in the hive before the first client and cannot wait for
     * firstboot. */
    /* Before the servers: conhost, the desktop server and winefb.drv all
     * read the derived values, and the server is the first client's first
     * stop. */
    SmssPublishShellBoot();
    SmssStartWineServer();
    SmssShellDesktopConfig();
    SmssAudioDriverConfig();
    SmssStartConhost();

    int failures = SmssRunFirstboot();

    /* The interactive boot (make run): a human owns the serial console — the
     * test session is skipped and the console goes straight to cmd.exe. The
     * QEMU command line, not the image, decides (SmssIsInteractiveBoot). */
    if (SmssIsInteractiveBoot())
    {
        SessionInteractive();
        NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, 0);
    }

    failures += SessionRun(abiFailures, registryOk);
    NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, failures);
    for (;;)
    {
    }
}
