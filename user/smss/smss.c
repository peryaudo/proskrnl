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
 *   4. an interactive boot (C:\interactive.flag) hands the console to a
 *      human cmd.exe; otherwise the acceptance flows and test sweeps run
 *      (session.c) and smss exits with the failure count.
 *
 * Verdict lines go out through NtDisplayString — the same serial transport
 * the kernel's [KTEST] lines use (kernel/ps/display.c), so the harness
 * greps are unchanged. A native ntdll-only PE, like hello.exe.
 *
 * User clients follow the test-code conventions (Wine style, docs/15
 * exemption).
 */
#include "user/smss/smss.h"

#include "abi/ntregapi.h"

#include <stdarg.h>

void smss_say(const char *ascii)
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

static void fmt_char(char *buf, unsigned size, unsigned *pos, char c)
{
    if (*pos + 1 < size)
        buf[(*pos)++] = c;
}

static void fmt_unsigned(char *buf, unsigned size, unsigned *pos, unsigned long long value,
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
        fmt_char(buf, size, pos, digits[--n]);
}

void smss_printf(const char *fmt, ...)
{
    char buf[192];
    unsigned pos = 0;
    va_list ap;
    va_start(ap, fmt);
    for (; *fmt != '\0'; fmt++)
    {
        if (*fmt != '%')
        {
            fmt_char(buf, sizeof(buf), &pos, *fmt);
            continue;
        }
        fmt++;
        switch (*fmt)
        {
        case 's':
        {
            const char *s = va_arg(ap, const char *);
            while (*s != '\0')
                fmt_char(buf, sizeof(buf), &pos, *s++);
            break;
        }
        case 'd':
        {
            int v = va_arg(ap, int);
            unsigned long long u = (unsigned long long)v;
            if (v < 0)
            {
                fmt_char(buf, sizeof(buf), &pos, '-');
                u = (unsigned long long)-(long long)v;
            }
            fmt_unsigned(buf, sizeof(buf), &pos, u, 10);
            break;
        }
        case 'u':
            fmt_unsigned(buf, sizeof(buf), &pos, va_arg(ap, unsigned), 10);
            break;
        case 'x':
        {
            /* The kernel DbgPrint %#lx spelling: always 0x-prefixed
             * ("exit=0x0"), so smss verdict lines match the historical ones. */
            fmt_char(buf, sizeof(buf), &pos, '0');
            fmt_char(buf, sizeof(buf), &pos, 'x');
            fmt_unsigned(buf, sizeof(buf), &pos, va_arg(ap, unsigned long long), 16);
            break;
        }
        case '%':
            fmt_char(buf, sizeof(buf), &pos, '%');
            break;
        default:
            fmt_char(buf, sizeof(buf), &pos, '%');
            if (*fmt != '\0')
                fmt_char(buf, sizeof(buf), &pos, *fmt);
            break;
        }
        if (*fmt == '\0')
            break;
    }
    va_end(ap);
    buf[pos] = '\0';
    smss_say(buf);
}

void smss_init_ustr(UNICODE_STRING *str, const WCHAR *wide)
{
    USHORT n = 0;
    while (wide[n] != 0)
        n++;
    str->Length = (USHORT)(n * sizeof(WCHAR));
    str->MaximumLength = (USHORT)(str->Length + sizeof(WCHAR));
    str->Buffer = (PWSTR)wide;
}

void smss_sleep_ms(ULONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)milliseconds * 10000; /* relative, 100 ns */
    NtDelayExecution(FALSE, &interval);
}

int smss_file_exists(const WCHAR *nt_path, NTSTATUS *status_out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    smss_init_ustr(&name, nt_path);
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status_out != 0)
        *status_out = status;
    if (status != STATUS_SUCCESS)
        return 0;
    NtClose(handle);
    return 1;
}

RTL_USER_PROCESS_PARAMETERS *smss_own_params;

/* The kernel passes its pre-session context on the command line
 * (KiRunSessionManager): "abi=<n>" is the ABI conformance probe's failure
 * count, folded into the M9 verdict exactly as the kernel runner folded it
 * (an unconsumed-convention regression must still flip `make test`). */
static int parse_abi_failures(void)
{
    if (smss_own_params == 0 || smss_own_params->CommandLine.Buffer == 0)
        return 0;
    const WCHAR *cmd = smss_own_params->CommandLine.Buffer;
    USHORT len = (USHORT)(smss_own_params->CommandLine.Length / sizeof(WCHAR));
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
static int registry_reachable(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE machine;
    smss_init_ustr(&name, WSTR("\\Registry\\Machine"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtOpenKey(&machine, KEY_READ, &attr);
    if (status != STATUS_SUCCESS)
    {
        smss_say("smss: registry not reachable\n");
        return 0;
    }
    NtClose(machine);
    return 1;
}

/* CUI-1 firstboot: run `wineboot --init` (firstboot.c) so wine.inf's
 * machine-state registry payload is applied before anything else uses the
 * hive. Probe/skip on the image content: images without wineboot.exe — the
 * hermetic ntapi/wtest images — skip silently. wineboot's own
 * .update-timestamp freshness check makes non-first boots near-instant. */
static int run_firstboot(void)
{
    if (!smss_file_exists(WSTR("\\??\\C:\\windows\\system32\\wineboot.exe"), 0))
        return 0;
    NTSTATUS exit_status = firstboot_run();
    if (exit_status != 0)
    {
        smss_printf("[KTEST] firstboot FAIL (exit=%x)\n", SMSS_HEX(exit_status));
        return 1;
    }
    smss_say("[KTEST] firstboot PASS\n");
    return 0;
}

void smss_start(void *peb_arg)
{
    PEB *peb = peb_arg;
    smss_own_params = peb != 0 ? peb->ProcessParameters : 0;

    smss_say("smss: session manager up\n");
    int abi_failures = parse_abi_failures();
    int registry_ok = registry_reachable();

    /* The servers, in dependency order (launch.c): wineserver-lite before
     * ANY win32u client — firstboot's wineboot is one, and so is the GUI-5
     * windowed conhost — then conhost itself. */
    smss_start_wineserver();
    smss_start_conhost();

    int failures = run_firstboot();

    /* The interactive boot (make run): the image carries C:\interactive.flag
     * (Makefile IMG_RUN), meaning a human owns the serial console — the test
     * session is skipped and the console goes straight to cmd.exe. The
     * image, not a kernel- or smss-side switch, decides. */
    if (smss_file_exists(WSTR("\\??\\C:\\interactive.flag"), 0))
    {
        session_interactive();
        NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, 0);
    }

    failures += session_run(abi_failures, registry_ok);
    NtTerminateProcess((HANDLE) ~(ULONG_PTR)0, failures);
    for (;;)
    {
    }
}
