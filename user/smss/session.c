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
static int SessionFlowM8(int registryOk)
{
    int failures = registryOk ? 0 : 1;
    static const WCHAR path[] = WSTR("\\??\\C:\\hello.exe");

    /* The hermetic test images carry the windows/ tree but not hello.exe;
     * skip cleanly there. The `make test` image ships it (Makefile
     * WINFILES), so a load failure on it IS a FAIL, not a skip. */
    NTSTATUS probe;
    if (!SmssFileExists(path, &probe))
    {
        if (probe == STATUS_OBJECT_NAME_NOT_FOUND || probe == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            SmssSay("[KTEST] module hello.exe SKIP (not on the boot volume)\n");
        }
        else
        {
            SmssPrintf("[KTEST] module hello.exe FAIL (probe=%x)\n", SMSS_HEX(probe));
            failures++;
        }
    }
    else
    {
        NTSTATUS exitStatus = 0;
        NTSTATUS status = SmssRun(path, 0, 0, 0, &exitStatus);
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] module hello.exe FAIL (create=%x)\n", SMSS_HEX(status));
            failures++;
        }
        else
        {
            SmssPrintf("[KTEST] module hello.exe %s (exit=%x)\n", exitStatus == 0 ? "PASS" : "FAIL",
                       SMSS_HEX(exitStatus));
            if (exitStatus != 0)
                failures++;
        }
    }
    if (failures == 0)
        SmssSay("[KTEST] M8 PASS\n");
    else
        SmssPrintf("[KTEST] M8 FAIL failures=%d\n", failures);
    return failures;
}

/* --- m9_smoke/M9: the console stack ---------------------------------------- */

/* The M9 acceptance client (docs/02 "Done when"): m9_smoke.exe drives the
 * threaded blocking-pipe protocol and writes through the real console stack
 * — kernelbase -> ConDrv -> conhost -> serial. The M9 line is the verdict
 * tools/qemu.sh greps for (PASS_RE), so it aggregates the kernel's ABI
 * conformance probe too (passed on smss's command line) — an
 * unconsumed-convention regression must flip `make test`. */
static int SessionFlowM9(int abiFailures)
{
    int failures = 0;
    static const WCHAR path[] = WSTR("\\??\\C:\\m9_smoke.exe");

    NTSTATUS probe;
    if (!SmssFileExists(path, &probe))
    {
        if (probe == STATUS_OBJECT_NAME_NOT_FOUND || probe == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            SmssSay("[KTEST] module m9_smoke.exe SKIP (not on the boot volume)\n");
        }
        else
        {
            SmssPrintf("[KTEST] module m9_smoke.exe FAIL (probe=%x)\n", SMSS_HEX(probe));
            failures++;
        }
    }
    else if (!SmssConsoleAvailable())
    {
        SmssSay("[KTEST] module m9_smoke.exe FAIL (no conhost)\n");
        failures++;
    }
    else
    {
        NTSTATUS exitStatus = 0;
        NTSTATUS status = SmssRun(path, 0, 1, 0, &exitStatus);
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] module m9_smoke.exe FAIL (create=%x)\n", SMSS_HEX(status));
            failures++;
        }
        else
        {
            SmssPrintf("[KTEST] module m9_smoke.exe %s (exit=%x)\n",
                       exitStatus == 0 ? "PASS" : "FAIL", SMSS_HEX(exitStatus));
            if (exitStatus != 0)
                failures++;
        }
    }
    failures += abiFailures;
    if (failures == 0)
        SmssSay("[KTEST] M9 PASS\n");
    else
        SmssPrintf("[KTEST] M9 FAIL failures=%d\n", failures);
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
#define NTAPI_MAX_TESTS  256
#define NTAPI_NAME_CHARS 64

typedef struct
{
    WCHAR names[NTAPI_MAX_TESTS][NTAPI_NAME_CHARS];
    int count;
    int overflow;
} NTAPI_LIST, *PNTAPI_LIST;

static void SessionCollectNtapiName(NTAPI_LIST *list, const WCHAR *name, ULONG chars,
                                    ULONG attributes)
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

static NTSTATUS SessionEnumerateNtapi(NTAPI_LIST *list)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE dir;
    SmssInitUnicodeString(&name, WSTR("\\??\\C:\\ntapi"));
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

    static unsigned char SessionNtapiBuffer[4096]; /* sequential sweep: bss, not stack */
    for (;;)
    {
        status = NtQueryDirectoryFile(dir, 0, 0, 0, &iosb, SessionNtapiBuffer,
                                      sizeof(SessionNtapiBuffer), FileDirectoryInformation, FALSE,
                                      0, FALSE);
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
            FILE_DIRECTORY_INFORMATION *entry =
                (FILE_DIRECTORY_INFORMATION *)(SessionNtapiBuffer + offset);
            SessionCollectNtapiName(list, entry->FileName, entry->FileNameLength / sizeof(WCHAR),
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
static void SessionSortNtapi(NTAPI_LIST *list)
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

static int SessionFlowNtapi(void)
{
    static NTAPI_LIST SessionNtapiList; /* 12 KiB: bss, not this thread's stack */
    SessionNtapiList.count = 0;
    SessionNtapiList.overflow = 0;
    NTSTATUS status = SessionEnumerateNtapi(&SessionNtapiList);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
        return 0; /* not an ntapi image */
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] ntapi FAIL (enumerate=%x)\n", SMSS_HEX(status));
        return 1;
    }
    SessionSortNtapi(&SessionNtapiList);

    int failures = 0;
    for (int i = 0; i < SessionNtapiList.count; i++)
    {
        static WCHAR SessionNtapiPath[32 + NTAPI_NAME_CHARS];
        static char SessionNtapiName[NTAPI_NAME_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\ntapi\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            SessionNtapiPath[n] = prefix[n];
            n++;
        }
        int m = 0;
        while (SessionNtapiList.names[i][m] != 0)
        {
            SessionNtapiPath[n + m] = SessionNtapiList.names[i][m];
            SessionNtapiName[m] = (char)SessionNtapiList.names[i][m];
            m++;
        }
        SessionNtapiPath[n + m] = 0;
        SessionNtapiName[m] = 0;

        NTSTATUS exitStatus = 0;
        status = SmssRun(SessionNtapiPath, 0, 0, 0, &exitStatus);
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] module ntapi/%s FAIL (create=%x)\n", SessionNtapiName,
                       SMSS_HEX(status));
            failures++;
        }
        else if (exitStatus != 0)
        {
            SmssPrintf("[KTEST] module ntapi/%s FAIL (exit=%x)\n", SessionNtapiName,
                       SMSS_HEX(exitStatus));
            failures++;
        }
        else
        {
            SmssPrintf("[KTEST] module ntapi/%s PASS\n", SessionNtapiName);
        }
    }
    if (SessionNtapiList.overflow)
    {
        SmssPrintf("[KTEST] ntapi FAIL (more than %d tests; raise NTAPI_MAX_TESTS)\n",
                   NTAPI_MAX_TESTS);
        failures++;
    }
    SmssPrintf("[KTEST] ntapi done tests=%d failures=%d\n", SessionNtapiList.count, failures);
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
/* The manifest is mostly TRIAGE COMMENTS and grows with every frontier item
 * worked, so the headroom is deliberate rather than round: 66 KiB of file
 * against a 64 KiB buffer is what made this constant matter. */
#define WTEST_MANIFEST_MAX (256 * 1024)
#define WTEST_TIMEOUT_MS                                                                           \
    (300 * 1000) /* TCG is ~10x native; the string tests are millions of ok()s */

typedef struct
{
    struct
    {
        char exe[WTEST_EXE_CHARS];
        char subtest[WTEST_SUBTEST_CHARS];
        ULONG timeoutMs; /* 0 = WTEST_TIMEOUT_MS (the two-field lines) */
    } pairs[WTEST_MAX_PAIRS];
    int count;
    int overflow;
} WTEST_LIST, *PWTEST_LIST;

/* Whole-file read into the static manifest buffer.
 *
 * Three answers, not two, and the distinction is load-bearing: 0 means the
 * file is ABSENT, which is every non-wtest image and is silent by design;
 * -1 means it is THERE and could not be read whole, which must be loud. The
 * two were one answer until the manifest's triage comments grew it past this
 * buffer — at which point the entire sweep stopped running and reported
 * itself as "not a wtest image", so all 49 pairs read FAIL with nothing on
 * serial saying why. A silent skip that looks like an absent feature is the
 * fabricated-plausible-answer shape (Art. 12) in the harness. */
static int SessionReadWtestManifest(unsigned char *buffer, ULONG capacity, ULONG *lengthOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    SmssInitUnicodeString(&name, WSTR("\\??\\C:\\wtests\\manifest.txt"));
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
    int ok = -1;
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] wtest FAIL (manifest size query -> %08lx)\n", (unsigned long)status);
    }
    else if (standard.EndOfFile.QuadPart <= 0 || standard.EndOfFile.QuadPart > capacity)
    {
        SmssPrintf("[KTEST] wtest FAIL (manifest is %u bytes, buffer is %u)\n",
                   (unsigned)standard.EndOfFile.QuadPart, (unsigned)capacity);
    }
    else
    {
        ULONG length = (ULONG)standard.EndOfFile.QuadPart;
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, length, &offset, 0);
        if (status == STATUS_SUCCESS && iosb.Information == length)
        {
            *lengthOut = length;
            ok = 1;
        }
        else
        {
            SmssPrintf("[KTEST] wtest FAIL (manifest read -> %08lx, %u of %u bytes)\n",
                       (unsigned long)status, (unsigned)iosb.Information, (unsigned)length);
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
static int SessionParseWtestManifest(const unsigned char *buffer, ULONG length, WTEST_LIST *list)
{
    ULONG pos = 0;
    while (pos < length)
    {
        ULONG end = pos;
        while (end < length && buffer[end] != '\n')
            end++;
        ULONG lineEnd = end;
        while (lineEnd > pos && (buffer[lineEnd - 1] == '\r' || buffer[lineEnd - 1] == ' '))
            lineEnd--;
        if (lineEnd > pos && buffer[pos] != '#')
        {
            ULONG colon = pos;
            while (colon < lineEnd && buffer[colon] != ':')
                colon++;
            ULONG subEnd = colon + 1;
            while (subEnd < lineEnd && buffer[subEnd] != ':')
                subEnd++;
            ULONG exeChars = colon - pos;
            ULONG subChars = (colon < lineEnd) ? subEnd - colon - 1 : 0;
            ULONG timeoutMs = 0;
            int timeoutBad = 0;
            if (subEnd < lineEnd)
            {
                ULONG seconds = 0, digits = 0;
                for (ULONG i = subEnd + 1; i < lineEnd; i++)
                {
                    if (buffer[i] < '0' || buffer[i] > '9' || seconds > 100000)
                    {
                        timeoutBad = 1;
                        break;
                    }
                    seconds = seconds * 10 + (buffer[i] - '0');
                    digits++;
                }
                if (digits == 0 || seconds == 0)
                    timeoutBad = 1;
                timeoutMs = seconds * 1000;
            }
            if (colon >= lineEnd || exeChars == 0 || exeChars >= WTEST_EXE_CHARS || subChars == 0 ||
                subChars >= WTEST_SUBTEST_CHARS || timeoutBad)
            {
                SmssPrintf("[KTEST] wtest FAIL (manifest line at byte %u malformed)\n",
                           (unsigned)pos);
                return 0;
            }
            if (list->count >= WTEST_MAX_PAIRS)
            {
                list->overflow = 1;
                pos = end + 1;
                continue;
            }
            for (ULONG i = 0; i < exeChars; i++)
                list->pairs[list->count].exe[i] = (char)buffer[pos + i];
            list->pairs[list->count].exe[exeChars] = 0;
            for (ULONG i = 0; i < subChars; i++)
                list->pairs[list->count].subtest[i] = (char)buffer[colon + 1 + i];
            list->pairs[list->count].subtest[subChars] = 0;
            list->pairs[list->count].timeoutMs = timeoutMs;
            list->count++;
        }
        pos = end + 1;
    }
    return 1;
}

static int SessionFlowWtest(void)
{
    static WTEST_LIST SessionWtestList; /* pairs table: bss, not this thread's stack */
    static unsigned char SessionWtestManifest[WTEST_MANIFEST_MAX];
    SessionWtestList.count = 0;
    SessionWtestList.overflow = 0;

    ULONG manifestLength = 0;
    int read = SessionReadWtestManifest(SessionWtestManifest, sizeof(SessionWtestManifest),
                                        &manifestLength);
    if (read == 0)
        return 0; /* not a wtest image */
    if (read < 0)
        return 1; /* there, unreadable — already named itself on serial */
    if (!SessionParseWtestManifest(SessionWtestManifest, manifestLength, &SessionWtestList))
        return 1;

    int failures = 0;
    for (int i = 0; i < SessionWtestList.count; i++)
    {
        /* Sequential runs, one static path set. */
        static WCHAR SessionWtestPath[16 + WTEST_EXE_CHARS];
        static WCHAR SessionWtestCmdline[16 + WTEST_EXE_CHARS + 1 + WTEST_SUBTEST_CHARS];
        static const WCHAR prefix[] = WSTR("\\??\\C:\\wtests\\");
        int n = 0;
        while (prefix[n] != 0)
        {
            SessionWtestPath[n] = prefix[n];
            n++;
        }
        for (int m = 0;; m++)
        {
            SessionWtestPath[n + m] = (WCHAR)(unsigned char)SessionWtestList.pairs[i].exe[m];
            if (SessionWtestList.pairs[i].exe[m] == 0)
                break;
        }
        int c = 0;
        for (int k = 4; SessionWtestPath[k] != 0; k++) /* past "\??\" */
            SessionWtestCmdline[c++] = SessionWtestPath[k];
        SessionWtestCmdline[c++] = ' ';
        for (int m = 0;; m++)
        {
            SessionWtestCmdline[c + m] = (WCHAR)(unsigned char)SessionWtestList.pairs[i].subtest[m];
            if (SessionWtestList.pairs[i].subtest[m] == 0)
                break;
        }

        NTSTATUS exitStatus = 0;
        ULONG timeoutMs = SessionWtestList.pairs[i].timeoutMs ? SessionWtestList.pairs[i].timeoutMs
                                                              : WTEST_TIMEOUT_MS;
        NTSTATUS status = SmssRun(SessionWtestPath, SessionWtestCmdline, 1, timeoutMs, &exitStatus);
        if (status == STATUS_TIMEOUT)
        {
            /* The wedged process owns the console; further pairs would be
             * noise. Abort loudly — the runner sees the missing PASSes. */
            SmssPrintf("[KTEST] wtest %s:%s FAIL (timeout)\n", SessionWtestList.pairs[i].exe,
                       SessionWtestList.pairs[i].subtest);
            failures += SessionWtestList.count - i;
            break;
        }
        if (status != STATUS_SUCCESS)
        {
            SmssPrintf("[KTEST] wtest %s:%s FAIL (create=%x)\n", SessionWtestList.pairs[i].exe,
                       SessionWtestList.pairs[i].subtest, SMSS_HEX(status));
            failures++;
        }
        else if (exitStatus != 0)
        {
            SmssPrintf("[KTEST] wtest %s:%s FAIL (exit=%x)\n", SessionWtestList.pairs[i].exe,
                       SessionWtestList.pairs[i].subtest, SMSS_HEX(exitStatus));
            failures++;
        }
        else
        {
            SmssPrintf("[KTEST] wtest %s:%s PASS\n", SessionWtestList.pairs[i].exe,
                       SessionWtestList.pairs[i].subtest);
        }
    }
    if (SessionWtestList.overflow)
    {
        SmssPrintf("[KTEST] wtest FAIL (more than %d pairs; raise WTEST_MAX_PAIRS)\n",
                   WTEST_MAX_PAIRS);
        failures++;
    }
    SmssPrintf("[KTEST] wtest done tests=%d failures=%d\n", SessionWtestList.count, failures);
    return failures;
}

/* --- the console-mode flows ------------------------------------------------- */

/* The M9 interactive-echo client when (and only when) the image carries it —
 * the console-mode image (Makefile console-img). It blocks on console input
 * until the runner types a line into the serial socket, so the plain image
 * must never include it; absence is silent. */
static int SessionFlowM9Echo(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\m9_echo.exe");
    if (!SmssFileExists(path, 0))
        return 0; /* not a console-mode image */

    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(path, 0, 1, 0, &exitStatus);
    int pass = status == STATUS_SUCCESS && exitStatus == 0;
    SmssPrintf("[KTEST] module m9_echo.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
               SMSS_HEX(exitStatus));
    return pass ? 0 : 1;
}

/* The M10 acceptance (docs/02): an INTERACTIVE cmd.exe on the serial
 * console, driven by tests/run/console_expect.py. Present only on the
 * console-mode image (probe/skip on hello_crt.exe, its subject). */
static int SessionFlowCmdConsole(void)
{
    if (!SmssFileExists(WSTR("\\??\\C:\\hello_crt.exe"), 0))
        return 0; /* not a console-mode image */

    SmssSay("[KTEST] cmd interactive start\n");
    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"), 0, 1, 0, &exitStatus);
    int pass = status == STATUS_SUCCESS && exitStatus == 0;
    SmssPrintf("[KTEST] module cmd.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
               SMSS_HEX(exitStatus));
    return pass ? 0 : 1;
}

/* --- the GUI legs ----------------------------------------------------------- */

/*
 * One shape, five images. Every GUI milestone lands the same three steps in
 * some subset: run a prologue to completion, spawn a client that must still
 * be on screen when the host screendumps, then run the client that reports
 * the verdict. Written out one milestone at a time, that shape became five
 * near-identical probe functions in the session manager -- scaffolding that
 * grows with every GUI milestone whether or not anything about the milestone
 * is new. It is a table now: the shape is stated once, and a new leg is a
 * row.
 *
 * `probe` is the image file that SELECTS the leg -- the image decides what
 * runs, not a switch (the file's own convention) -- and every path is a
 * verbatim [KTEST] tag away from the lines the harness greps, which are
 * unchanged byte for byte.
 *
 * None of these return on their own image: the host has to screendump live
 * windows, so the leg parks in `foreground` and the boot's end-of-boot
 * verdict is deliberately never reached (see SessionRun).
 */
typedef struct
{
    const WCHAR *probe;             /* on the volume => this is the leg's image */
    const WCHAR *prologue;          /* run to completion first, or NULL */
    const WCHAR *background;        /* spawned and left up for the screendump, or NULL */
    const WCHAR *foreground;        /* run last; the leg parks here */
    const WCHAR *foregroundCmdline; /* the foreground's command line, or NULL for the path */
    const char *tag;                /* the [KTEST] prefix: "gui", "gui2", ... */
    const char *prologueTag;        /* names the prologue in its exit line */
    const char *foregroundName;     /* set when returning at all is a FAIL */
} GUI_LEG, *PGUI_LEG;

/* Designated initializers throughout: an omitted field is the absent case
 * (no prologue, no background client, returning is not a failure), so a row
 * names only what its leg actually does. */

static const GUI_LEG SessionGuiLegs[] = {
    /* GUI-1 (docs/02 "a user program maps the framebuffer and draws a
     * rectangle visible in a screendump"): gui_smoke.exe opens \Device\Fb0
     * and \Device\Input0, paints, and parks in a blocking read. It is
     * written never to return, so returning is the verdict. */
    {.probe = WSTR("\\??\\C:\\gui_smoke.exe"),
     .foreground = WSTR("\\??\\C:\\gui_smoke.exe"),
     .tag = "gui",
     .foregroundName = "gui_smoke.exe"},

    /* GUI-2 (docs/02 "winemine.exe appears on screen"): the whole Wine GUI
     * stack painting through winefb.drv onto \Device\Fb0. Reached when the
     * window is closed (the harness's Alt+F4 probe) or when the app dies --
     * either way the exit code is the diagnosis. */
    {.probe = WSTR("\\??\\C:\\winemine.exe"),
     .foreground = WSTR("\\??\\C:\\winemine.exe"),
     .tag = "gui2"},

    /* GUI-3 (docs/02 "two GUI processes run at once"): wineserver-lite
     * (already started before firstboot -- smss.c) with two GUI clients above
     * it. gui3a is fire-and-forget (its window must still be up for the
     * screendumps); gui3b prints the verdict and parks. */
    {.probe = WSTR("\\??\\C:\\gui3a.exe"),
     .background = WSTR("\\??\\C:\\gui3a.exe"),
     .foreground = WSTR("\\??\\C:\\gui3b.exe"),
     .tag = "gui3"},

    /* GUI-4 (docs/02 "windows can be grabbed and moved"): the gui3
     * arrangement with overlapping windows, driven by the harness through
     * the tablet and keyboard. Both clients park pumping forever; the leg
     * owns QEMU's lifetime. */
    {.probe = WSTR("\\??\\C:\\gui4a.exe"),
     .background = WSTR("\\??\\C:\\gui4a.exe"),
     .foreground = WSTR("\\??\\C:\\gui4b.exe"),
     .tag = "gui4"},

    /* GUI-5 (docs/02 "GUI finishing"): clipboard, hooks and AttachThreadInput
     * cross-process, plus the guest half of the font-metrics differential.
     * fontdiff is the prologue for two reasons: its metric lines must land
     * un-interleaved with the clients' output, and it must have EXITED --
     * releasing any exclusively-opened input device its winefb instance won
     * -- before gui5a starts and becomes the leg's input host (docs/03 GUI-4
     * notes). */
    {.probe = WSTR("\\??\\C:\\gui5a.exe"),
     .prologue = WSTR("\\??\\C:\\fontdiff.exe"),
     .background = WSTR("\\??\\C:\\gui5a.exe"),
     .foreground = WSTR("\\??\\C:\\gui5b.exe"),
     .tag = "gui5",
     .prologueTag = "fontdiff"},

    /* GUI-6 (docs/02 "Desktop"): Wine's explorer owns the desktop. One
     * foreground, explorer itself: /desktop=shell,WxH creates and owns the
     * desktop (the shim's fixtures are off -- explorer.exe is on this
     * image), and the trailing command line is executed by explorer's own
     * manage_desktop as its CreateProcessW child: a second explorer showing
     * C:\shelf -- the file window, landing on desktop "shell" through the
     * connect-time inheritance (wineserver-lite shim.c create_client).
     * C:\shelf, not C:\ -- the golden is an exact byte compare and the
     * shelf's listing is pinned (Makefile GUI6_SHELF), where C:\ would show
     * bake timestamps and artifact sizes that move with every build.
     * 1280x800 is the scanout mode (one mode, HACK-001; qemu stdvga --
     * tests/gui/golden/desktop.ppm pins it, so a mode change shows up as a
     * size mismatch, not a silent drift). Explorer never exits: the leg
     * parks in its message loop and the harness owns QEMU's lifetime. */
    {.probe = WSTR("\\??\\C:\\gui6.flag"),
     .foreground = WSTR("\\??\\C:\\windows\\system32\\explorer.exe"),
     .foregroundCmdline = WSTR("explorer.exe /desktop=shell,1280x800 "
                               "C:\\windows\\system32\\explorer.exe C:\\shelf"),
     .tag = "gui6",
     .foregroundName = "explorer.exe"},
};

static void SessionFlowGui(void)
{
    /* Kept for the process's lifetime on purpose: the background client must
     * still be running when the host takes its screendumps, so its handles
     * are never closed. One pair is enough -- the probes are disjoint, so at
     * most one leg runs per image. */
    static HANDLE SessionGuiBackground, SessionGuiBackgroundThread;

    for (unsigned int i = 0; i < sizeof(SessionGuiLegs) / sizeof(SessionGuiLegs[0]); i++)
    {
        const GUI_LEG *leg = &SessionGuiLegs[i];
        NTSTATUS exitStatus = 0;
        NTSTATUS status;

        if (!SmssFileExists(leg->probe, 0))
            continue; /* not this leg's image */

        if (leg->prologue)
        {
            status = SmssRun(leg->prologue, 0, 0, 0, &exitStatus);
            SmssPrintf("[KTEST] %s %s exit (status=%x, exit=%x)\n", leg->tag, leg->prologueTag,
                       SMSS_HEX(status), SMSS_HEX(exitStatus));
        }

        if (leg->background)
        {
            status = SmssSpawn(leg->background, 0, 0, &SessionGuiBackground,
                               &SessionGuiBackgroundThread);
            if (status != STATUS_SUCCESS)
            {
                SmssPrintf("[KTEST] %s A FAIL (create=%x)\n", leg->tag, SMSS_HEX(status));
                return;
            }
        }

        status = SmssRun(leg->foreground, leg->foregroundCmdline, 0, 0, &exitStatus);
        /* Only reached if the client exited. Where it is written never to,
         * say FAIL by name rather than letting the boot fall through to a
         * sweep verdict the harness would read as a healthy end (Art. 12). */
        if (leg->foregroundName)
            SmssPrintf("[KTEST] %s FAIL (%s returned %x, exit=%x)\n", leg->tag, leg->foregroundName,
                       SMSS_HEX(status), SMSS_HEX(exitStatus));
        else
            SmssPrintf("[KTEST] %s exit (status=%x, exit=%x)\n", leg->tag, SMSS_HEX(status),
                       SMSS_HEX(exitStatus));
        return;
    }
}

/* The WOW64 acceptance (docs/02 "a 32-bit CUI app runs"): hello32.exe is an
 * ordinary 32-bit Win32 console program, so a PASS here means the whole
 * chain worked — the kernel built a WOW64 process, the 64-bit ntdll found
 * WowTebOffset set and loaded wow64.dll, wow64cpu far-jumped into compat
 * mode, and every syscall the guest made came back through it. Present only
 * on the wow64 image (Makefile IMG_WOW64); absence is silent, as with every
 * other image-specific flow. */
static int SessionFlowWow64(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\hello32.exe");
    if (!SmssFileExists(path, 0))
        return 0; /* not the wow64 image */

    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(path, 0, 1, 0, &exitStatus);
    if (status != STATUS_SUCCESS)
    {
        SmssPrintf("[KTEST] wow64 hello32.exe FAIL (create=%x)\n", SMSS_HEX(status));
        return 1;
    }
    int pass = exitStatus == 0;
    SmssPrintf("[KTEST] wow64 hello32.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
               SMSS_HEX(exitStatus));
    return pass ? 0 : 1;
}

/* --- the session ------------------------------------------------------------ */

int SessionRun(int abiFailures, int registryOk)
{
    int failures = 0;
    failures += SessionFlowM8(registryOk);
    failures += SessionFlowM9(abiFailures);

    /* The ntapi image only (tests/run/run.sh proskrnl). Absence is silent. */
    failures += SessionFlowNtapi();

    /* The wtest image only (tests/run/run.sh winetest). Absence is silent. */
    failures += SessionFlowWtest();

    /* Console-mode image only: block on the interactive echo (the M9
     * acceptance's other half). AFTER the M9 verdict so the runner knows
     * the boot suite is already green. Then the interactive cmd session. */
    failures += SessionFlowM9Echo();

    /* The wow64 image only. Before the interactive cmd flow, which blocks. */
    failures += SessionFlowWow64();

    failures += SessionFlowCmdConsole();

    /* GUI images only: deliberately LAST and deliberately never returning —
     * the host has to see the painted frames in screendumps, so the guest
     * must not tear the windows down or power off underneath them. Every
     * verdict above has already printed by this point. */
    SessionFlowGui();

    return failures;
}

/* Hand the console to a human-driven cmd.exe; the kernel powers the VM off
 * when smss exits (`exit` at the prompt). A start failure still returns —
 * an interactive boot has no runner watching a timeout. */
void SessionInteractive(void)
{
    SmssSay("\nproskrnl: interactive console - starting cmd.exe (type 'exit' to power off)\n\n");
    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"), 0, 1, 0, &exitStatus);
    if (status != STATUS_SUCCESS)
        SmssPrintf("proskrnl: cmd.exe failed to start (%x)\n", SMSS_HEX(status));
}
