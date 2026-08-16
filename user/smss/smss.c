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

/* The interactive boot, read from the same place the kernel reads it: the
 * volatile \Registry\Machine\Hardware\qemu key the kernel published from the
 * QEMU command line's fw_cfg items (kernel/cm/registry.c, HACK-006). No key
 * means no fw_cfg device, i.e. not a QEMU guest — nothing there is scraping a
 * serial log, so a human is assumed and the session goes interactive. The
 * kernel's KiIsInteractiveBoot states the same rule for its own half of the
 * boot; the two are separate address spaces, not a second authority. */
int SmssIsInteractiveBoot(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key;
    SmssInitUnicodeString(&name, WSTR("\\Registry\\Machine\\Hardware\\qemu"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS open = NtOpenKey(&key, KEY_QUERY_VALUE, &attr);
    if (open == STATUS_OBJECT_NAME_NOT_FOUND || open == STATUS_OBJECT_PATH_NOT_FOUND)
        return 1; /* no fw_cfg device published it: not a QEMU guest */
    if (open != STATUS_SUCCESS)
    {
        /* Absent is the only failure that means "not QEMU". Anything else is
         * a broken registry, and answering it "interactive" would park a
         * scripted leg at a prompt nobody is typing into — the loud, harmless
         * way round is to say so and run the ordinary session. */
        SmssPrintf("smss: HKLM\\Hardware\\qemu open failed (%x); assuming not interactive\n",
                   SMSS_HEX(open));
        return 0;
    }

    UNICODE_STRING valueName;
    SmssInitUnicodeString(&valueName, WSTR("Interactive"));
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    ULONG resultLength = 0;
    NTSTATUS status = NtQueryValueKey(key, &valueName, KeyValuePartialInformation, buffer,
                                      sizeof(buffer), &resultLength);
    NtClose(key);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return 0; /* the key exists, so QEMU decided: an absent flag is off */
    if (status != STATUS_SUCCESS || info->Type != REG_DWORD || info->DataLength != sizeof(ULONG))
    {
        /* The key is volatile, not read-only, so ring 3 can have overwritten
         * the flag with anything; 0 is the safe reading, but not a silent one
         * (the kernel's CmQueryQemuBootFlag says the same). */
        SmssPrintf("smss: HKLM\\Hardware\\qemu Interactive is not a REG_DWORD (%x); reading 0\n",
                   SMSS_HEX(status));
        return 0;
    }

    ULONG value;
    for (unsigned int i = 0; i < sizeof(value); i++)
        ((UCHAR *)&value)[i] = info->Data[i];
    return value != 0;
}

int SmssFileExists(const WCHAR *ntPath, NTSTATUS *statusOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    SmssInitUnicodeString(&name, ntPath);
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (statusOut != 0)
        *statusOut = status;
    if (status != STATUS_SUCCESS)
        return 0;
    NtClose(handle);
    return 1;
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
 * hive. Probe/skip on the image content: images without wineboot.exe — the
 * driver/filesystem images, which carry no Wine userland at all — skip
 * silently; every image with the CUI userland runs it, because every one of
 * them is baked from the same Makefile $(WINFILES). wineboot's own
 * .update-timestamp freshness check makes non-first boots near-instant. */
static int SmssRunFirstboot(void)
{
    if (!SmssFileExists(WSTR("\\??\\C:\\windows\\system32\\wineboot.exe"), 0))
        return 0;
    NTSTATUS exitStatus = FirstbootRun();
    if (exitStatus != 0)
    {
        SmssPrintf("[KTEST] firstboot FAIL (exit=%x)\n", SMSS_HEX(exitStatus));
        return 1;
    }
    SmssSay("[KTEST] firstboot PASS\n");
    return 0;
}

/* GUI-6, the interactive shell session (`make rungui`, the gui5con image):
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
 * Gated on the interactive flag, not on explorer's presence: the gui6 leg
 * (same shell payload, no interactive flag) launches explorer explicitly
 * with /desktop=shell,WxH and needs no routing values -- and writing them
 * there would hand firstboot's transient rundll32 children a desktop
 * auto-launch of their own, changing what its golden pinned. */
static void SmssShellDesktopConfig(void)
{
    static const struct
    {
        const WCHAR *key; /* under \Registry\User\<sid> -- the fixed Se
                           * identity (kernel/se/token.c); the skeleton root
                           * exists from boot (kernel/cm/registry.c) */
        const WCHAR *name;
        const WCHAR *value;
    } values[] = {
        {WSTR("Software\\Wine\\Explorer"), WSTR("Desktop"), WSTR("shell")},
        {WSTR("Software\\Wine\\Explorer\\Desktops"), WSTR("shell"), WSTR("1280x800")},
    };

    if (!SmssIsInteractiveBoot())
        return;
    if (!SmssFileExists(WSTR("\\??\\C:\\windows\\system32\\explorer.exe"), 0))
        return;

    for (unsigned int i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        WCHAR path[128];
        unsigned int n = 0;
        const WCHAR *prefix = WSTR("\\Registry\\User\\S-1-5-21-0-0-0-1000\\");
        while (prefix[n] != 0)
        {
            path[n] = prefix[n];
            n++;
        }
        /* NtCreateKey creates one level, so walk the subkey path and create
         * each component -- the parents may not exist on a virgin hive. */
        for (unsigned int j = 0;; j++)
        {
            WCHAR c = values[i].key[j];
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
            {
                SmssPrintf("[KTEST] shellcfg FAIL (create=%x)\n", SMSS_HEX(status));
                return;
            }
            if (c == 0)
            {
                UNICODE_STRING valueName;
                SmssInitUnicodeString(&valueName, values[i].name);
                unsigned int chars = 0;
                while (values[i].value[chars] != 0)
                    chars++;
                status = NtSetValueKey(key, &valueName, 0, REG_SZ, (void *)values[i].value,
                                       (chars + 1) * sizeof(WCHAR));
                NtClose(key);
                if (status != STATUS_SUCCESS)
                {
                    SmssPrintf("[KTEST] shellcfg FAIL (set=%x)\n", SMSS_HEX(status));
                    return;
                }
                break;
            }
            NtClose(key);
            path[n++] = '\\';
        }
    }
    SmssSay("[KTEST] shellcfg PASS\n");
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
    SmssStartWineServer();
    SmssShellDesktopConfig();
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
