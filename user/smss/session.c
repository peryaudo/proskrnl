/* user/smss/session.c — the acceptance flows and test sweeps, in the
 * historical kernel-runner order (they lived in kernel/init/main.c until
 * smss became the session manager; the [KTEST] verdict lines are kept
 * byte-identical so the harness greps are unchanged, docs/08):
 *
 *   hello/M8 chain -> m9_smoke/M9 -> the ntapi sweep -> the winetest sweep
 *   -> m9_echo -> the cmd console -> the GUI legs.
 *
 * Every flow probes the boot volume and skips when its subject is not baked
 * — the image, not a switch, decides what runs. The GUI legs deliberately
 * never return on their images (the host screendumps live windows), so smss
 * parks with them and the kernel's end-of-boot verdict is never reached
 * there — exactly the old behavior.
 */
#include "user/smss/smss.h"

/* --- hello/M8: the initial chain ------------------------------------------- */

/* The M8 chain (docs/02 "boot completes as kernel → smss-equiv → test
 * process") and the M7 Wine acceptance rolled into one run: hello.exe beside
 * the unmodified Wine PE ntdll, spawned through NtCreateUserProcess. The
 * registry check (smss.c) counts here — it was the chain's first duty. */
static int flow_m8(int registry_ok)
{
    int failures = registry_ok ? 0 : 1;
    static const WCHAR path[] = WSTR("\\??\\C:\\hello.exe");

    /* The hermetic test images carry the windows/ tree but not hello.exe;
     * skip cleanly there. The `make test` image ships it (Makefile
     * WINFILES), so a load failure on it IS a FAIL, not a skip. */
    NTSTATUS probe;
    if (!smss_file_exists(path, &probe))
    {
        if (probe == STATUS_OBJECT_NAME_NOT_FOUND || probe == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            smss_say("[KTEST] module hello.exe SKIP (not on the boot volume)\n");
        }
        else
        {
            smss_printf("[KTEST] module hello.exe FAIL (probe=%x)\n", SMSS_HEX(probe));
            failures++;
        }
    }
    else
    {
        NTSTATUS exit_status = 0;
        NTSTATUS status = smss_run(path, 0, 0, 0, &exit_status);
        if (status != STATUS_SUCCESS)
        {
            smss_printf("[KTEST] module hello.exe FAIL (create=%x)\n", SMSS_HEX(status));
            failures++;
        }
        else
        {
            smss_printf("[KTEST] module hello.exe %s (exit=%x)\n",
                        exit_status == 0 ? "PASS" : "FAIL", SMSS_HEX(exit_status));
            if (exit_status != 0)
                failures++;
        }
    }
    if (failures == 0)
        smss_say("[KTEST] M8 PASS\n");
    else
        smss_printf("[KTEST] M8 FAIL failures=%d\n", failures);
    return failures;
}

/* --- m9_smoke/M9: the console stack ---------------------------------------- */

/* The M9 acceptance client (docs/02 "Done when"): m9_smoke.exe drives the
 * threaded blocking-pipe protocol and writes through the real console stack
 * — kernelbase -> ConDrv -> conhost -> serial. The M9 line is the verdict
 * tools/qemu.sh greps for (PASS_RE), so it aggregates the kernel's ABI
 * conformance probe too (passed on smss's command line) — an
 * unconsumed-convention regression must flip `make test`. */
static int flow_m9(int abi_failures)
{
    int failures = 0;
    static const WCHAR path[] = WSTR("\\??\\C:\\m9_smoke.exe");

    NTSTATUS probe;
    if (!smss_file_exists(path, &probe))
    {
        if (probe == STATUS_OBJECT_NAME_NOT_FOUND || probe == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            smss_say("[KTEST] module m9_smoke.exe SKIP (not on the boot volume)\n");
        }
        else
        {
            smss_printf("[KTEST] module m9_smoke.exe FAIL (probe=%x)\n", SMSS_HEX(probe));
            failures++;
        }
    }
    else if (!smss_console_available())
    {
        smss_say("[KTEST] module m9_smoke.exe FAIL (no conhost)\n");
        failures++;
    }
    else
    {
        NTSTATUS exit_status = 0;
        NTSTATUS status = smss_run(path, 0, 1, 0, &exit_status);
        if (status != STATUS_SUCCESS)
        {
            smss_printf("[KTEST] module m9_smoke.exe FAIL (create=%x)\n", SMSS_HEX(status));
            failures++;
        }
        else
        {
            smss_printf("[KTEST] module m9_smoke.exe %s (exit=%x)\n",
                        exit_status == 0 ? "PASS" : "FAIL", SMSS_HEX(exit_status));
            if (exit_status != 0)
                failures++;
        }
    }
    failures += abi_failures;
    if (failures == 0)
        smss_say("[KTEST] M9 PASS\n");
    else
        smss_printf("[KTEST] M9 FAIL failures=%d\n", failures);
    return failures;
}

/* --- the ntapi single-binary test sweep (docs/14) -------------------------- */

/* Every tests/ntapi test is ONE PE .exe that runs unmodified on the Wine
 * oracle and here. tests/run/run.sh proskrnl bakes them all under C:\ntapi;
 * this sweep enumerates the directory — the image, not an smss-side list,
 * decides what runs — and each test prints its own [KTEST] <name> PASS/FAIL
 * line, which the runner script greps off the serial log. Absence of
 * C:\ntapi (the `make test` image) is silent. Tests run WITHOUT a console
 * on purpose: no std handles is the harness's "running on proskrnl"
 * discriminator (tests/ntapi/ntapi.c). */
#define NTAPI_MAX_TESTS  96
#define NTAPI_NAME_CHARS 64

struct ntapi_list
{
    WCHAR names[NTAPI_MAX_TESTS][NTAPI_NAME_CHARS];
    int count;
    int overflow;
};

static void ntapi_collect(struct ntapi_list *list, const WCHAR *name, ULONG chars, ULONG attributes)
{
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || chars < 5 || chars >= NTAPI_NAME_CHARS)
        return;
    if (name[chars - 4] != '.' || (name[chars - 3] | 0x20) != 'e' ||
        (name[chars - 2] | 0x20) != 'x' || (name[chars - 1] | 0x20) != 'e')
        return;
    if (list->count >= NTAPI_MAX_TESTS)
    {
        list->overflow = 1; /* a silent cap would read as "all covered" */
        return;
    }
    for (ULONG i = 0; i < chars; i++)
        list->names[list->count][i] = name[i];
    list->names[list->count][chars] = 0;
    list->count++;
}

static NTSTATUS ntapi_enumerate(struct ntapi_list *list)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir;
    smss_init_ustr(&name, WSTR("\\??\\C:\\ntapi"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status =
        NtOpenFile(&dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, FILE_SHARE_READ,
                   FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (status != STATUS_SUCCESS)
        return status;

    static unsigned char buffer[4096]; /* sequential sweep: bss, not stack */
    for (;;)
    {
        status = NtQueryDirectoryFile(dir, 0, 0, 0, &iosb, buffer, sizeof(buffer),
                                      FileDirectoryInformation, FALSE, 0, FALSE);
        if (status == STATUS_NO_MORE_FILES)
        {
            status = STATUS_SUCCESS;
            break;
        }
        if (status != STATUS_SUCCESS)
            break;
        ULONG offset = 0;
        for (;;)
        {
            FILE_DIRECTORY_INFORMATION *entry = (FILE_DIRECTORY_INFORMATION *)(buffer + offset);
            ntapi_collect(list, entry->FileName, entry->FileNameLength / sizeof(WCHAR),
                          entry->FileAttributes);
            if (entry->NextEntryOffset == 0)
                break;
            offset += entry->NextEntryOffset;
        }
    }
    NtClose(dir);
    return status;
}

/* Case-insensitive ASCII order, so the run order (and the serial log) is
 * stable regardless of FAT directory layout. */
static void ntapi_sort(struct ntapi_list *list)
{
    for (int i = 1; i < list->count; i++)
    {
        WCHAR key[NTAPI_NAME_CHARS];
        for (int k = 0; k < NTAPI_NAME_CHARS; k++)
            key[k] = list->names[i][k];
        int j = i - 1;
        while (j >= 0)
        {
            const WCHAR *a = list->names[j];
            const WCHAR *b = key;
            int cmp = 0;
            while (*a != 0 || *b != 0)
            {
                WCHAR ca = (*a >= 'A' && *a <= 'Z') ? (WCHAR)(*a + 32) : *a;
                WCHAR cb = (*b >= 'A' && *b <= 'Z') ? (WCHAR)(*b + 32) : *b;
                if (ca != cb)
                {
                    cmp = ca < cb ? -1 : 1;
                    break;
                }
                a++;
                b++;
            }
            if (cmp <= 0)
                break;
            for (int k = 0; k < NTAPI_NAME_CHARS; k++)
                list->names[j + 1][k] = list->names[j][k];
            j--;
        }
        for (int k = 0; k < NTAPI_NAME_CHARS; k++)
            list->names[j + 1][k] = key[k];
    }
}

static int flow_ntapi(void)
{
    static struct ntapi_list list; /* 12 KiB: bss, not this thread's stack */
    list.count = 0;
    list.overflow = 0;
    NTSTATUS status = ntapi_enumerate(&list);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
        return 0; /* not an ntapi image */
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] ntapi FAIL (enumerate=%x)\n", SMSS_HEX(status));
        return 1;
    }
    ntapi_sort(&list);

    int failures = 0;
    for (int i = 0; i < list.count; i++)
    {
        static WCHAR wide_path[32 + NTAPI_NAME_CHARS];
        static char ascii[NTAPI_NAME_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\ntapi\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            wide_path[n] = prefix[n];
            n++;
        }
        int m = 0;
        while (list.names[i][m] != 0)
        {
            wide_path[n + m] = list.names[i][m];
            ascii[m] = (char)list.names[i][m];
            m++;
        }
        wide_path[n + m] = 0;
        ascii[m] = 0;

        NTSTATUS exit_status = 0;
        status = smss_run(wide_path, 0, 0, 0, &exit_status);
        if (status != STATUS_SUCCESS)
        {
            smss_printf("[KTEST] module ntapi/%s FAIL (create=%x)\n", ascii, SMSS_HEX(status));
            failures++;
        }
        else if (exit_status != 0)
        {
            smss_printf("[KTEST] module ntapi/%s FAIL (exit=%x)\n", ascii, SMSS_HEX(exit_status));
            failures++;
        }
        else
        {
            smss_printf("[KTEST] module ntapi/%s PASS\n", ascii);
        }
    }
    if (list.overflow)
    {
        smss_printf("[KTEST] ntapi FAIL (more than %d tests; raise NTAPI_MAX_TESTS)\n",
                    NTAPI_MAX_TESTS);
        failures++;
    }
    smss_printf("[KTEST] ntapi done tests=%d failures=%d\n", list.count, failures);
    return failures;
}

/* --- the winetest sweep (M10 stretch: docs/02 "Ideal regression") ---------- */

/* tests/run/run.sh winetest bakes standalone Wine-test binaries (the pinned
 * tree's own test objects, docs/14) under C:\wtests plus a manifest of
 * <exe>:<subtest> pairs curated to be green on the oracle. Each pair runs
 * WITH a console (winetest prints through msvcrt stdout -> condrv -> conhost
 * -> serial) and its exit code — winetest's failure count — is the verdict.
 * Absence of the manifest (every other image) is silent. A pair that times
 * out cannot be reaped (no foreign terminate — docs/03), so the sweep aborts
 * rather than running more clients against a wedged console. */
#define WTEST_MAX_PAIRS     128
#define WTEST_EXE_CHARS     40
#define WTEST_SUBTEST_CHARS 32
#define WTEST_MANIFEST_MAX  (64 * 1024)
#define WTEST_TIMEOUT_MS                                                                           \
    (300 * 1000) /* TCG is ~10x native; the string tests are millions of ok()s */

struct wtest_list
{
    struct
    {
        char exe[WTEST_EXE_CHARS];
        char subtest[WTEST_SUBTEST_CHARS];
        ULONG timeout_ms; /* 0 = WTEST_TIMEOUT_MS (the two-field lines) */
    } pairs[WTEST_MAX_PAIRS];
    int count;
    int overflow;
};

/* Whole-file read into the static manifest buffer; 0 on any miss. */
static int wtest_read_manifest(unsigned char *buffer, ULONG capacity, ULONG *length_out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    smss_init_ustr(&name, WSTR("\\??\\C:\\wtests\\manifest.txt"));
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor = 0;
    attr.SecurityQualityOfService = 0;
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (status != STATUS_SUCCESS)
        return 0;
    int ok = 0;
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    if (status == STATUS_SUCCESS && standard.EndOfFile.QuadPart > 0 &&
        standard.EndOfFile.QuadPart <= capacity)
    {
        ULONG length = (ULONG)standard.EndOfFile.QuadPart;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, length, &offset, 0);
        if (status == STATUS_SUCCESS && iosb.Information == length)
        {
            *length_out = length;
            ok = 1;
        }
    }
    NtClose(handle);
    return ok;
}

/* Parse `<exe>:<subtest>[:<timeout_s>]` lines; '#' comments and blank
 * lines skipped, CRLF tolerated. The optional third field (GUI-5: a whole
 * user32:msg run outlasts the default bound under TCG) is seconds, decimal,
 * nonzero; absent means WTEST_TIMEOUT_MS. Malformed/oversized lines are
 * loud (a silently dropped pair would read as "covered"). Returns 0 on a
 * parse failure. */
static int wtest_parse_manifest(const unsigned char *buffer, ULONG length, struct wtest_list *list)
{
    ULONG pos = 0;
    while (pos < length)
    {
        ULONG end = pos;
        while (end < length && buffer[end] != '\n')
            end++;
        ULONG line_end = end;
        while (line_end > pos && (buffer[line_end - 1] == '\r' || buffer[line_end - 1] == ' '))
            line_end--;
        if (line_end > pos && buffer[pos] != '#')
        {
            ULONG colon = pos;
            while (colon < line_end && buffer[colon] != ':')
                colon++;
            ULONG sub_end = colon + 1;
            while (sub_end < line_end && buffer[sub_end] != ':')
                sub_end++;
            ULONG exe_chars = colon - pos;
            ULONG sub_chars = (colon < line_end) ? sub_end - colon - 1 : 0;
            ULONG timeout_ms = 0;
            int timeout_bad = 0;
            if (sub_end < line_end)
            {
                ULONG seconds = 0, digits = 0;
                for (ULONG i = sub_end + 1; i < line_end; i++)
                {
                    if (buffer[i] < '0' || buffer[i] > '9' || seconds > 100000)
                    {
                        timeout_bad = 1;
                        break;
                    }
                    seconds = seconds * 10 + (buffer[i] - '0');
                    digits++;
                }
                if (digits == 0 || seconds == 0)
                    timeout_bad = 1;
                timeout_ms = seconds * 1000;
            }
            if (colon >= line_end || exe_chars == 0 || exe_chars >= WTEST_EXE_CHARS ||
                sub_chars == 0 || sub_chars >= WTEST_SUBTEST_CHARS || timeout_bad)
            {
                smss_printf("[KTEST] wtest FAIL (manifest line at byte %u malformed)\n",
                            (unsigned)pos);
                return 0;
            }
            if (list->count >= WTEST_MAX_PAIRS)
            {
                list->overflow = 1;
                pos = end + 1;
                continue;
            }
            for (ULONG i = 0; i < exe_chars; i++)
                list->pairs[list->count].exe[i] = (char)buffer[pos + i];
            list->pairs[list->count].exe[exe_chars] = 0;
            for (ULONG i = 0; i < sub_chars; i++)
                list->pairs[list->count].subtest[i] = (char)buffer[colon + 1 + i];
            list->pairs[list->count].subtest[sub_chars] = 0;
            list->pairs[list->count].timeout_ms = timeout_ms;
            list->count++;
        }
        pos = end + 1;
    }
    return 1;
}

static int flow_wtest(void)
{
    static struct wtest_list list; /* pairs table: bss, not this thread's stack */
    static unsigned char manifest[WTEST_MANIFEST_MAX];
    list.count = 0;
    list.overflow = 0;

    ULONG manifest_length = 0;
    if (!wtest_read_manifest(manifest, sizeof(manifest), &manifest_length))
        return 0; /* not a wtest image */
    if (!wtest_parse_manifest(manifest, manifest_length, &list))
        return 1;

    int failures = 0;
    for (int i = 0; i < list.count; i++)
    {
        /* Sequential runs, one static path set. */
        static WCHAR wide_path[16 + WTEST_EXE_CHARS];
        static WCHAR cmdline[16 + WTEST_EXE_CHARS + 1 + WTEST_SUBTEST_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\wtests\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            wide_path[n] = prefix[n];
            n++;
        }
        for (int m = 0;; m++)
        {
            wide_path[n + m] = (WCHAR)(unsigned char)list.pairs[i].exe[m];
            if (list.pairs[i].exe[m] == 0)
                break;
        }
        int c = 0;
        for (int k = 4; wide_path[k] != 0; k++) /* past "\??\" */
            cmdline[c++] = wide_path[k];
        cmdline[c++] = ' ';
        for (int m = 0;; m++)
        {
            cmdline[c + m] = (WCHAR)(unsigned char)list.pairs[i].subtest[m];
            if (list.pairs[i].subtest[m] == 0)
                break;
        }

        NTSTATUS exit_status = 0;
        ULONG timeout_ms = list.pairs[i].timeout_ms ? list.pairs[i].timeout_ms : WTEST_TIMEOUT_MS;
        NTSTATUS status = smss_run(wide_path, cmdline, 1, timeout_ms, &exit_status);
        if (status == STATUS_TIMEOUT)
        {
            /* The wedged process owns the console; further pairs would be
             * noise. Abort loudly — the runner sees the missing PASSes. */
            smss_printf("[KTEST] wtest %s:%s FAIL (timeout)\n", list.pairs[i].exe,
                        list.pairs[i].subtest);
            failures += list.count - i;
            break;
        }
        if (status != STATUS_SUCCESS)
        {
            smss_printf("[KTEST] wtest %s:%s FAIL (create=%x)\n", list.pairs[i].exe,
                        list.pairs[i].subtest, SMSS_HEX(status));
            failures++;
        }
        else if (exit_status != 0)
        {
            smss_printf("[KTEST] wtest %s:%s FAIL (exit=%x)\n", list.pairs[i].exe,
                        list.pairs[i].subtest, SMSS_HEX(exit_status));
            failures++;
        }
        else
        {
            smss_printf("[KTEST] wtest %s:%s PASS\n", list.pairs[i].exe, list.pairs[i].subtest);
        }
    }
    if (list.overflow)
    {
        smss_printf("[KTEST] wtest FAIL (more than %d pairs; raise WTEST_MAX_PAIRS)\n",
                    WTEST_MAX_PAIRS);
        failures++;
    }
    smss_printf("[KTEST] wtest done tests=%d failures=%d\n", list.count, failures);
    return failures;
}

/* --- the console-mode flows ------------------------------------------------- */

/* The M9 interactive-echo client when (and only when) the image carries it —
 * the console-mode image (Makefile console-img). It blocks on console input
 * until the runner types a line into the serial socket, so the plain image
 * must never include it; absence is silent. */
static int flow_m9_echo(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\m9_echo.exe");
    if (!smss_file_exists(path, 0))
        return 0; /* not a console-mode image */

    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(path, 0, 1, 0, &exit_status);
    int pass = status == STATUS_SUCCESS && exit_status == 0;
    smss_printf("[KTEST] module m9_echo.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
                SMSS_HEX(exit_status));
    return pass ? 0 : 1;
}

/* The M10 acceptance (docs/02): an INTERACTIVE cmd.exe on the serial
 * console, driven by tests/run/console_expect.py. Present only on the
 * console-mode image (probe/skip on hello_crt.exe, its subject). */
static int flow_cmd_console(void)
{
    if (!smss_file_exists(WSTR("\\??\\C:\\hello_crt.exe"), 0))
        return 0; /* not a console-mode image */

    smss_say("[KTEST] cmd interactive start\n");
    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"), 0, 1, 0, &exit_status);
    int pass = status == STATUS_SUCCESS && exit_status == 0;
    smss_printf("[KTEST] module cmd.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
                SMSS_HEX(exit_status));
    return pass ? 0 : 1;
}

/* --- the GUI legs ----------------------------------------------------------- */

/* GUI-1 (docs/02 "a user program maps the framebuffer and draws a rectangle
 * visible in a screendump"): gui_smoke.exe opens \Device\Fb0 and
 * \Device\Input0, paints, and parks in a blocking read. Does not return on
 * its image — see session_run. */
static void flow_gui_smoke(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\gui_smoke.exe");
    if (!smss_file_exists(path, 0))
        return; /* not a gui image */

    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(path, 0, 0, 0, &exit_status);
    /* Only reached if the client exited, which it is written never to do:
     * say so rather than letting the boot fall through to a sweep verdict
     * the harness would read as a healthy end (Art. 12). */
    smss_printf("[KTEST] gui FAIL (gui_smoke.exe returned %x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));
}

/* GUI-2 (docs/02 "winemine.exe appears on screen"): the whole Wine GUI
 * stack painting through winefb.drv onto \Device\Fb0. */
static void flow_gui2(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\winemine.exe");
    if (!smss_file_exists(path, 0))
        return; /* not a gui2 image */

    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(path, 0, 0, 0, &exit_status);
    /* Reached when the window is closed (the harness's Alt+F4 probe) or
     * when the app dies. Either way the exit code is the diagnosis. */
    smss_printf("[KTEST] gui2 exit (status=%x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));
}

/* GUI-3 (docs/02 "two GUI processes run at once"): wineserver-lite (already
 * started before firstboot — smss.c) with two GUI clients above it. gui3a
 * is fire-and-forget (its window must still be up for the screendumps);
 * gui3b prints the verdict and parks. */
static void flow_gui3(void)
{
    if (!smss_file_exists(WSTR("\\??\\C:\\gui3a.exe"), 0))
        return; /* not a gui3 image */

    static HANDLE a_process, a_thread;
    NTSTATUS status = smss_spawn(WSTR("\\??\\C:\\gui3a.exe"), 0, 0, &a_process, &a_thread);
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] gui3 A FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    NTSTATUS exit_status = 0;
    status = smss_run(WSTR("\\??\\C:\\gui3b.exe"), 0, 0, 0, &exit_status);
    smss_printf("[KTEST] gui3 exit (status=%x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));
}

/* GUI-4 (docs/02 "windows can be grabbed and moved"): the gui3 arrangement
 * with overlapping windows, driven by the harness through the tablet and
 * keyboard. Both clients park pumping forever; the leg owns QEMU's
 * lifetime. */
static void flow_gui4(void)
{
    if (!smss_file_exists(WSTR("\\??\\C:\\gui4a.exe"), 0))
        return; /* not a gui4 image */

    static HANDLE a_process, a_thread;
    NTSTATUS status = smss_spawn(WSTR("\\??\\C:\\gui4a.exe"), 0, 0, &a_process, &a_thread);
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] gui4 A FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    NTSTATUS exit_status = 0;
    status = smss_run(WSTR("\\??\\C:\\gui4b.exe"), 0, 0, 0, &exit_status);
    smss_printf("[KTEST] gui4 exit (status=%x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));
}

/* GUI-5 (docs/02 "GUI finishing"): clipboard, hooks and AttachThreadInput
 * cross-process, plus the guest half of the font-metrics differential.
 * fontdiff runs FIRST and is waited on: its metric lines must land
 * un-interleaved with the clients' output, and it must have exited —
 * releasing any exclusively-opened input device its winefb instance won —
 * before gui5a starts and becomes the leg's input host (docs/03 GUI-4
 * notes). Then the gui3/gui4 shape. */
static void flow_gui5(void)
{
    if (!smss_file_exists(WSTR("\\??\\C:\\gui5a.exe"), 0))
        return; /* not a gui5 image */

    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(WSTR("\\??\\C:\\fontdiff.exe"), 0, 0, 0, &exit_status);
    smss_printf("[KTEST] gui5 fontdiff exit (status=%x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));

    static HANDLE a_process, a_thread;
    status = smss_spawn(WSTR("\\??\\C:\\gui5a.exe"), 0, 0, &a_process, &a_thread);
    if (status != STATUS_SUCCESS)
    {
        smss_printf("[KTEST] gui5 A FAIL (create=%x)\n", SMSS_HEX(status));
        return;
    }

    status = smss_run(WSTR("\\??\\C:\\gui5b.exe"), 0, 0, 0, &exit_status);
    smss_printf("[KTEST] gui5 exit (status=%x, exit=%x)\n", SMSS_HEX(status),
                SMSS_HEX(exit_status));
}

/* --- the session ------------------------------------------------------------ */

int session_run(int abi_failures, int registry_ok)
{
    int failures = 0;
    failures += flow_m8(registry_ok);
    failures += flow_m9(abi_failures);

    /* The ntapi image only (tests/run/run.sh proskrnl). Absence is silent. */
    failures += flow_ntapi();

    /* The wtest image only (tests/run/run.sh winetest). Absence is silent. */
    failures += flow_wtest();

    /* Console-mode image only: block on the interactive echo (the M9
     * acceptance's other half). AFTER the M9 verdict so the runner knows
     * the boot suite is already green. Then the interactive cmd session. */
    failures += flow_m9_echo();
    failures += flow_cmd_console();

    /* GUI images only: deliberately LAST and deliberately never returning —
     * the host has to see the painted frames in screendumps, so the guest
     * must not tear the windows down or power off underneath them. Every
     * verdict above has already printed by this point. */
    flow_gui_smoke();
    flow_gui2();
    flow_gui3();
    flow_gui4();
    flow_gui5();

    return failures;
}

/* Hand the console to a human-driven cmd.exe; the kernel powers the VM off
 * when smss exits (`exit` at the prompt). A start failure still returns —
 * an interactive boot has no runner watching a timeout. */
void session_interactive(void)
{
    smss_say("\nproskrnl: interactive console - starting cmd.exe (type 'exit' to power off)\n\n");
    NTSTATUS exit_status = 0;
    NTSTATUS status = smss_run(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"), 0, 1, 0, &exit_status);
    if (status != STATUS_SUCCESS)
        smss_printf("proskrnl: cmd.exe failed to start (%x)\n", SMSS_HEX(status));
}
