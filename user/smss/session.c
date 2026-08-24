/* user/smss/session.c — the acceptance flows and test sweeps, in the
 * historical kernel-runner order (they lived in kernel/init/main.c until
 * smss became the session manager; the [KTEST] verdict lines are kept
 * byte-identical so the harness greps are unchanged, docs/08):
 *
 *   hello/M8 chain -> m9_smoke/M9 -> the leg the boot selected.
 *
 * WHICH leg runs is a property of the BOOT, not of the media: the QEMU
 * command line names it (tools/qemu.sh GUEST_LEG) and the kernel publishes
 * it as \Registry\Machine\Hardware\qemu "Leg" (kernel/cm/registry.c,
 * HACK-006). Every flow below used to probe the boot volume for its own
 * subject and skip when it was absent, which made "which test runs" a
 * property of which of a dozen disk images had been baked — so a leg could
 * only be selected by rebuilding its image, and two legs could never share
 * one. One image carries every subject now and the flag picks.
 *
 * The GUI legs deliberately never return (the host screendumps live
 * windows), so smss parks with them and the kernel's end-of-boot verdict is
 * never reached there — exactly the old behavior.
 */
#include "user/smss/smss.h"

/* --- the leg the boot selected --------------------------------------------- */

/* The two REG_SZ boot strings, read ONCE at the top of SessionRun and held
 * as ASCII: every consumer below compares them against literal names, and a
 * per-consumer re-read would be a second reading of "unspecified". */
static char SessionLeg[SMSS_QEMU_STRING_MAX + 1];
static char SessionSubtests[SMSS_QEMU_STRING_MAX + 1];

/* The kernel publishes what the command line carried, and a QEMU command
 * line is ASCII (`-fw_cfg ...,string=`), so the widening the kernel did on
 * the way in is undone here rather than every comparison being widened. A
 * character outside ASCII cannot have come from the command line; it is
 * dropped to '?' so a corrupted value cannot silently equal a leg name. */
static void SessionReadBootString(const WCHAR *valueName, char *out, ULONG outChars)
{
    static WCHAR SessionBootStringWide[SMSS_QEMU_STRING_MAX + 1];
    SmssQemuString(valueName, SessionBootStringWide, SMSS_QEMU_STRING_MAX + 1);
    ULONG i = 0;
    while (SessionBootStringWide[i] != 0 && i + 1 < outChars)
    {
        out[i] = SessionBootStringWide[i] < 0x80 ? (char)SessionBootStringWide[i] : '?';
        i++;
    }
    out[i] = 0;
}

/* Read the two boot strings once, whoever asks first. SessionRun wants them
 * at the top of the test session; SessionIsWindowedConsoleLeg and
 * SessionIsShellIntegrationLeg are asked much earlier, before the servers
 * start, because whether this boot HAS a shell is a property of the leg
 * (below). Every reader of SessionLeg calls this first -- the one that did
 * not is what published ShellBoot=1 on a boot that then evaluated 0. */
void SessionLoadBootStrings(void)
{
    static int SessionBootStringsLoaded;
    if (SessionBootStringsLoaded)
        return;
    SessionBootStringsLoaded = 1;
    SessionReadBootString(WSTR("Leg"), SessionLeg, sizeof(SessionLeg));
    SessionReadBootString(WSTR("Subtests"), SessionSubtests, sizeof(SessionSubtests));
}

/* The leg this boot read, for whoever wants to SAY which one. */
const char *SessionLegName(void)
{
    SessionLoadBootStrings();
    return SessionLeg;
}

/* Is the selected leg exactly `name`? The empty leg — no GUEST_LEG on the
 * command line — is the plain boot suite and matches nothing here. */
static int SessionLegIs(const char *name)
{
    /* Load first, like every other reader of SessionLeg. It is correct today
     * without this only because it is static and every caller runs after
     * SessionRun's load -- and "a leg-name reader consulted before the load"
     * is precisely the defect that made SmssIsShellBoot publish 1 and then
     * evaluate 0, so the next early caller written with this function would
     * reproduce it exactly. Idempotent (SessionBootStringsLoaded). */
    SessionLoadBootStrings();
    int i = 0;
    while (SessionLeg[i] != 0 && name[i] != 0 && SessionLeg[i] == name[i])
        i++;
    return SessionLeg[i] == 0 && name[i] == 0;
}

/* --- the two leg-name boot decisions ----------------------------------------
 *
 * Both of the following answer a question smss ASKS from SmssIsShellBoot, so
 * the reasoning they share sits here once rather than in either body.
 *
 * A machine a human sits at has a shell, so an interactive desktop boot whose
 * console is NOT on the serial transport gets one (`make rungui`). A scripted
 * GUI gate is a different thing: it runs a
 * purpose-built client against the compositor, the message path or the
 * clipboard, and explorer on the desktop is scenery its golden was never
 * measured against — so those legs keep the server's own desktop fixtures
 * (user/wine/wineserver-lite/common/shim.c request_forces_desktop), where the
 * desktop is created for whoever asks first.
 *
 * GUI-6 is the exception, because GUI-6 IS the shell: its milestone is Wine's
 * explorer owning the desktop, photographed against
 * tests/gui/golden/desktop.ppm. A leg whose subject is the shell asks for the
 * shell; nothing else does. */
/* The one leg whose subject is a CONSOLE WINDOW: GUI-5's conhost dual-mode
 * gate, which locates the window on the scanout, clicks it, types into it and
 * compares its pixels.
 *
 * One of the two boot decisions that read a leg NAME (GUI-6's shell
 * integration, just above, is the other). It is here rather than in a flag
 * because there is no flag that could carry it: this machine
 * has exactly ONE console -- smss creates it at startup and `ConsoleWindow`
 * picks its destination -- so a boot has a serial console or a windowed one,
 * never both. `Serial`=1 would leave this leg no window to drive, and
 * `Serial`=0 alone is indistinguishable from `make rungui`, which must land
 * on the shell. (A CUI leg that wants a prompt does not need `Serial` at all
 * -- with `Gui`=0 the console is on serial already and the flag is a no-op;
 * `Serial`=1 is how a leg that HAS a desktop asks for the same thing.)
 *
 * The exit is a second console, not a cleverer derivation: give smss a way to
 * open one on the desktop while its own stays on serial, and this row goes. */
static int SessionIsWindowedConsoleLegName(const char *leg)
{
    const char *consoleLeg = "gui5con";
    int i = 0;
    while (leg[i] != 0 && consoleLeg[i] != 0 && leg[i] == consoleLeg[i])
        i++;
    return leg[i] == 0 && consoleLeg[i] == 0;
}

int SessionIsWindowedConsoleLeg(void)
{
    SessionLoadBootStrings(); /* asked before SessionRun: nothing else has */
    return SessionIsWindowedConsoleLegName(SessionLeg);
}

static int SessionIsShellIntegrationLegName(const char *leg)
{
    const char *shellLeg = "gui6";
    int i = 0;
    while (leg[i] != 0 && shellLeg[i] != 0 && leg[i] == shellLeg[i])
        i++;
    return leg[i] == 0 && shellLeg[i] == 0;
}

int SessionIsShellIntegrationLeg(void)
{
    SessionLoadBootStrings();
    return SessionIsShellIntegrationLegName(SessionLeg);
}

/* --- the subtest filter ----------------------------------------------------- */

/* `*` and `?` against an ASCII name — the same glob the harness applies host
 * side (tests/run/run.sh `selected` / `wtest_matches`), so a query means the
 * same thing whichever leg reads it. Iterative backtracking: no recursion in
 * a session manager whose stack is the kernel's default. */
static int SessionGlobMatch(const char *pattern, ULONG patternChars, const char *name)
{
    ULONG p = 0, n = 0, starP = patternChars, starN = 0;
    while (name[n] != 0)
    {
        if (p < patternChars && (pattern[p] == '?' || pattern[p] == name[n]))
        {
            p++;
            n++;
        }
        else if (p < patternChars && pattern[p] == '*')
        {
            starP = p++;
            starN = n;
        }
        else if (starP != patternChars)
        {
            p = starP + 1;
            n = ++starN;
        }
        else
        {
            return 0;
        }
    }
    while (p < patternChars && pattern[p] == '*')
        p++;
    return p == patternChars;
}

/* TRUE when the command line carried no filter at all — every case runs, so
 * an unfiltered leg behaves exactly as it did before there was a filter. */
static int SessionNoFilter(void)
{
    /* Load first, for SessionLegIs's reason: an unloaded SessionSubtests reads
     * as "no filter", i.e. EVERY case, which is the silent-widening direction.
     * Correct today only because every caller runs after SessionRun's load. */
    SessionLoadBootStrings();
    return SessionSubtests[0] == 0;
}

/* Walk the whitespace-separated patterns of the query, calling `match` for
 * each with its length. `context` is the caller's subject. Returns non-zero
 * as soon as one pattern says yes. */
typedef int (*SESSION_PATTERN_TEST)(const char *pattern, ULONG chars, const void *context);

static int SessionQuerySelects(SESSION_PATTERN_TEST test, const void *context)
{
    if (SessionNoFilter())
        return 1;
    ULONG i = 0;
    while (SessionSubtests[i] != 0)
    {
        while (SessionSubtests[i] == ' ')
            i++;
        ULONG start = i;
        while (SessionSubtests[i] != 0 && SessionSubtests[i] != ' ')
            i++;
        if (i > start && test(&SessionSubtests[start], i - start, context))
            return 1;
    }
    return 0;
}

/* --- hello/M8: the initial chain ------------------------------------------- */

/* The M8 chain (docs/02 "boot completes as kernel → smss-equiv → test
 * process") and the M7 Wine acceptance rolled into one run: hello.exe beside
 * the unmodified Wine PE ntdll, spawned through NtCreateUserProcess. The
 * registry check (smss.c) counts here — it was the chain's first duty. */
static int SessionFlowM8(int registryOk)
{
    int failures = registryOk ? 0 : 1;
    static const WCHAR path[] = WSTR("\\??\\C:\\hello.exe");

    /* No probe: the PRODUCT image carries hello.exe on every boot, so a
     * missing one is a broken bake to FAIL on, not a case to skip. The probe
     * this replaced dated from when an image without the windows/ tree was a
     * thing a boot could be -- and one still is, so the BOOT says so
     * (`Userland`, derived from the leg name -- kernel/cm/registry.c) instead
     * of the flow guessing from the volume. */
    if (!SmssHasUserland())
    {
        SmssSay("smss: no Windows userland on this boot; M8 skipped\n");
        return failures;
    }
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

    /* No probe: the PRODUCT image carries m9_smoke.exe on every boot, so a
     * missing one is a broken bake to FAIL on, not a case to skip. A hermetic
     * kernel fixture carries neither it nor the conhost it drives, and says so
     * on the command line rather than being probed for. */
    if (!SmssHasUserland())
    {
        SmssSay("smss: no Windows userland on this boot; M9 skipped\n");
        return failures;
    }
    if (!SmssConsoleAvailable())
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
 * oracle and here. The Makefile bakes them ALL under C:\ntapi; this sweep
 * enumerates the directory and runs the ones the boot's filter selects, each
 * test printing its own [KTEST] <name> PASS/FAIL line for the runner script
 * to grep off the serial log.
 *
 * The FILTER is the BOOT's, not the image's: a subset run used to mean
 * baking an image holding only the selected .exes, so the media recorded
 * which subset had last been asked for and a partial image could be taken
 * for the gate's. Every image carries every case now and
 * `-fw_cfg opt/org.proskrnl/subtests` says which of them to run.
 *
 * Tests run WITHOUT a console on purpose: no std handles is the harness's
 * "running on proskrnl" discriminator (tests/ntapi/ntapi.c). */
#define NTAPI_MAX_TESTS  320 /* Net-3's sem_nsi pushed the suite past 256 */
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

/* The ntapi query filters BASE NAMES (`query_dir`, `se_*`) — the .exe suffix
 * is not part of a case's name in either runner. */
static int SessionNtapiPatternMatches(const char *pattern, ULONG chars, const void *context)
{
    return SessionGlobMatch(pattern, chars, (const char *)context);
}

static int SessionFlowNtapi(void)
{
    static NTAPI_LIST SessionNtapiList; /* 12 KiB: bss, not this thread's stack */
    SessionNtapiList.count = 0;
    SessionNtapiList.overflow = 0;
    NTSTATUS status = SessionEnumerateNtapi(&SessionNtapiList);
    if (status != STATUS_SUCCESS)
    {
        /* The leg asked for this sweep, so C:\ntapi not being there is a
         * broken image rather than "another image" — say so instead of
         * reporting an empty sweep as a clean one (Art. 12). */
        SmssPrintf("[KTEST] ntapi FAIL (enumerate=%x)\n", SMSS_HEX(status));
        return 1;
    }
    SessionSortNtapi(&SessionNtapiList);

    int failures = 0;
    int selected = 0;
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

        /* The query matches the BASE name, so the ".exe" the directory entry
         * carries is cut off before asking. */
        static char SessionNtapiBase[NTAPI_NAME_CHARS];
        int b = 0;
        while (b < m - 4 && b + 1 < NTAPI_NAME_CHARS)
        {
            SessionNtapiBase[b] = SessionNtapiName[b];
            b++;
        }
        SessionNtapiBase[b] = 0;
        if (!SessionQuerySelects(SessionNtapiPatternMatches, SessionNtapiBase))
            continue;
        selected++;

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
    SmssPrintf("[KTEST] ntapi done tests=%d failures=%d\n", selected, failures);
    return failures;
}

/* --- the winetest sweep (M10 stretch: docs/02 "Ideal regression") ---------- */

/* The Makefile bakes standalone Wine-test binaries (the pinned tree's own
 * test objects, docs/14) under C:\wtests, beside BOTH curated manifests of
 * <exe>:<subtest> pairs: manifest.txt (the CUI gate) and manifest-gui.txt
 * (the GUI-5 trophy). The boot's leg picks which file this sweep reads and
 * the boot's filter picks which of its pairs run — neither is baked, so the
 * two gates and every subset of them share one image.
 *
 * Each pair runs WITH a console (winetest prints through msvcrt stdout ->
 * condrv -> conhost -> serial) and its exit code — winetest's failure count
 * — is the verdict. A pair that times out cannot be reaped (no foreign
 * terminate — docs/03), so the sweep aborts rather than running more clients
 * against a wedged console. */
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

/* Whole-file read into the static manifest buffer. Non-zero on success.
 *
 * Every failure is LOUD, including the file being absent: the leg asked for
 * this manifest by name, so a missing one is a broken image and not "another
 * image". It used to be the silent case, and that silence is what hid the
 * manifest outgrowing this buffer — the sweep stopped running and reported
 * itself as "not a wtest image", so all 49 pairs read FAIL with nothing on
 * serial saying why. A silent skip that looks like an absent feature is the
 * fabricated-plausible-answer shape (Art. 12) in the harness. */
static int SessionReadWtestManifest(const WCHAR *path, unsigned char *buffer, ULONG capacity,
                                    ULONG *lengthOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    SmssInitUnicodeString(&name, path);
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
    {
        SmssPrintf("[KTEST] wtest FAIL (manifest open -> %x)\n", SMSS_HEX(status));
        return 0;
    }
    int ok = 0;
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

/* One manifest pair, for the query filter below. */
typedef struct
{
    const char *exe;     /* "ntdll_test.exe" */
    const char *subtest; /* "env" */
} WTEST_PAIR_NAME;

/* The winetest query filters PAIRS, matching what the harness matches host
 * side (tests/run/run.sh wtest_matches, one spelling of the rule in two
 * languages): `<module>:<subtest>` or `<exe>:<subtest>`, and a pattern with
 * no ':' in it matches either half on its own — so `ntdll` is a module,
 * `printf` is a subtest of two modules, and `rtl*` is a glob over subtests.
 *
 * The MODULE is the exe with its shared `_test.exe` tail dropped
 * (cmd.exe_test.exe -> cmd), computed here rather than stored: the tail is a
 * property of how the binaries are named, not of the pair. */
static int SessionWtestPatternMatches(const char *pattern, ULONG chars, const void *context)
{
    const WTEST_PAIR_NAME *pair = context;
    /* "<exe>:<subtest>" and "<module>:<subtest>", built once into one buffer
     * each so the glob matcher sees a plain NUL-terminated name. */
    static char SessionWtestFullKey[WTEST_EXE_CHARS + 1 + WTEST_SUBTEST_CHARS];
    static char SessionWtestShortKey[WTEST_EXE_CHARS + 1 + WTEST_SUBTEST_CHARS];
    static char SessionWtestModule[WTEST_EXE_CHARS];
    int m = 0;
    while (pair->exe[m] != 0 && m + 1 < WTEST_EXE_CHARS)
    {
        SessionWtestModule[m] = pair->exe[m];
        m++;
    }
    SessionWtestModule[m] = 0;
    /* Drop the "_test.exe" tail if that is how this name ends. */
    static const char tail[] = "_test.exe";
    const int tailChars = (int)sizeof(tail) - 1;
    if (m >= tailChars)
    {
        int t = 0;
        while (t < tailChars && SessionWtestModule[m - tailChars + t] == tail[t])
            t++;
        if (t == tailChars)
        {
            m -= tailChars;
            SessionWtestModule[m] = 0;
            /* cmd.exe_test.exe -> "cmd.exe" -> "cmd". */
            static const char dotExe[] = ".exe";
            const int dotChars = (int)sizeof(dotExe) - 1;
            if (m >= dotChars)
            {
                int d = 0;
                while (d < dotChars && SessionWtestModule[m - dotChars + d] == dotExe[d])
                    d++;
                if (d == dotChars)
                    SessionWtestModule[m - dotChars] = 0;
            }
        }
    }

    int c = 0;
    for (int i = 0; pair->exe[i] != 0 && c + 1 < (int)sizeof(SessionWtestFullKey); i++)
        SessionWtestFullKey[c++] = pair->exe[i];
    SessionWtestFullKey[c++] = ':';
    for (int i = 0; pair->subtest[i] != 0 && c + 1 < (int)sizeof(SessionWtestFullKey); i++)
        SessionWtestFullKey[c++] = pair->subtest[i];
    SessionWtestFullKey[c] = 0;
    c = 0;
    for (int i = 0; SessionWtestModule[i] != 0 && c + 1 < (int)sizeof(SessionWtestShortKey); i++)
        SessionWtestShortKey[c++] = SessionWtestModule[i];
    SessionWtestShortKey[c++] = ':';
    for (int i = 0; pair->subtest[i] != 0 && c + 1 < (int)sizeof(SessionWtestShortKey); i++)
        SessionWtestShortKey[c++] = pair->subtest[i];
    SessionWtestShortKey[c] = 0;

    if (SessionGlobMatch(pattern, chars, SessionWtestFullKey) ||
        SessionGlobMatch(pattern, chars, SessionWtestShortKey))
        return 1;
    for (ULONG i = 0; i < chars; i++)
    {
        if (pattern[i] == ':')
            return 0; /* a qualified pattern matches nothing but a pair */
    }
    return SessionGlobMatch(pattern, chars, SessionWtestModule) ||
           SessionGlobMatch(pattern, chars, pair->subtest);
}

static int SessionFlowWtest(const WCHAR *manifestPath)
{
    static WTEST_LIST SessionWtestList; /* pairs table: bss, not this thread's stack */
    static unsigned char SessionWtestManifest[WTEST_MANIFEST_MAX];
    SessionWtestList.count = 0;
    SessionWtestList.overflow = 0;

    ULONG manifestLength = 0;
    if (!SessionReadWtestManifest(manifestPath, SessionWtestManifest, sizeof(SessionWtestManifest),
                                  &manifestLength))
        return 1; /* already named itself on serial */
    if (!SessionParseWtestManifest(SessionWtestManifest, manifestLength, &SessionWtestList))
        return 1;

    int failures = 0;
    int selected = 0;
    for (int i = 0; i < SessionWtestList.count; i++)
    {
        WTEST_PAIR_NAME pairName;
        pairName.exe = SessionWtestList.pairs[i].exe;
        pairName.subtest = SessionWtestList.pairs[i].subtest;
        if (!SessionQuerySelects(SessionWtestPatternMatches, &pairName))
            continue;
        selected++;

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
            /* Every pair still to come is unrun, and the runner grades by
             * the absence of their PASS lines; one failure is enough to
             * make the sweep's own count non-zero. */
            failures++;
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
    SmssPrintf("[KTEST] wtest done tests=%d failures=%d\n", selected, failures);
    return failures;
}

/* --- the console-mode flows ------------------------------------------------- */

/* The M9 interactive-echo client, run when (and only when) the boot asks for
 * the `console` leg. It blocks on console input until the runner types a line
 * into the serial socket, so no other leg may reach it -- which used to be
 * arranged by keeping it off every other image, and is now the leg name. */
static int SessionFlowM9Echo(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\m9_echo.exe");
    /* No probe: SessionRun reaches this only on the `console` leg, so the
     * boot has already said it wants this. The probe was how a boot told
     * console-mode images from plain ones back when that was a property of
     * the media. */
    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(path, 0, 1, 0, &exitStatus);
    int pass = status == STATUS_SUCCESS && exitStatus == 0;
    SmssPrintf("[KTEST] module m9_echo.exe %s (exit=%x)\n", pass ? "PASS" : "FAIL",
               SMSS_HEX(exitStatus));
    return pass ? 0 : 1;
}

/* The M10 acceptance (docs/02): a cmd.exe on the serial console driven by
 * tests/run/console_expect.py -- the `console` leg's second half. (It is not
 * an `Interactive` boot in the fw_cfg sense: that flag means a human owns the
 * console, and this one is typed at by a script.) */
static int SessionFlowCmdConsole(void)
{
    /* No probe, for the same reason as M9Echo above: the `console` leg is
     * what selects this now. */
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
 * One shape, eleven legs. Every GUI milestone lands the same three steps in
 * some subset: run a prologue to completion, spawn a client that must still
 * be on screen when the host screendumps, then run the client that reports
 * the verdict. Written out one milestone at a time, that shape became five
 * near-identical probe functions in the session manager -- scaffolding that
 * grows with every GUI milestone whether or not anything about the milestone
 * is new. It is a table now: the shape is stated once, and a new leg is a
 * row.
 *
 * `leg` is the NAME the QEMU command line selects the row by (GUEST_LEG).
 * It was the leg's client file, present on the leg's own image and absent
 * everywhere else, which is what made eleven images of the same userland
 * exist; every path here is a verbatim [KTEST] tag away from the lines the
 * harness greps, which are unchanged byte for byte.
 *
 * None of these return: the host has to screendump live windows, so the leg
 * parks in `foreground` and the boot's end-of-boot verdict is deliberately
 * never reached (see SessionRun).
 */
typedef struct
{
    const char *leg;                /* the GUEST_LEG name that selects this row */
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
    {.leg = "gui",
     .foreground = WSTR("\\??\\C:\\gui_smoke.exe"),
     .tag = "gui",
     .foregroundName = "gui_smoke.exe"},

    /* AUD-1 (docs/02 "a guest client plays a deterministic S16 pattern"):
     * aud_smoke.exe negotiates \Device\Snd0 and plays through blocking
     * period writes, then parks -- the host reads the recorded WAV back.
     * Written never to return, so returning is the verdict. */
    {.leg = "audio",
     .foreground = WSTR("\\??\\C:\\aud_smoke.exe"),
     .tag = "audio",
     .foregroundName = "aud_smoke.exe"},

    /* AUD-3 (docs/02 "AUD-3 — capture"): cap_smoke.exe finds the capture
     * node by its own direction claim and blocking-reads silence periods
     * from the `none` audiodev's cadence. Written never to return, so
     * returning is the verdict. */
    {.leg = "capture",
     .foreground = WSTR("\\??\\C:\\cap_smoke.exe"),
     .tag = "audio",
     .foregroundName = "cap_smoke.exe"},

    /* AUD-2 (docs/02 "winevsnd.drv: WASAPI render"): the same pattern
     * through the whole PE audio stack — CoCreateInstance -> IAudioClient
     * over mmdevapi + winevsnd.drv — with the underrun count on its
     * verdict line. Written never to return, so returning is the verdict. */
    {.leg = "wasapi",
     .foreground = WSTR("\\??\\C:\\wasapi_smoke.exe"),
     .tag = "audio",
     .foregroundName = "wasapi_smoke.exe"},

    /* AUD-3, one layer up: event-driven WASAPI capture through mmdevapi +
     * winevsnd.drv on the `none`-audiodev boot. Written never to return,
     * so returning is the verdict. */
    {.leg = "wasapicap",
     .foreground = WSTR("\\??\\C:\\wasapi_cap_smoke.exe"),
     .tag = "audio",
     .foregroundName = "wasapi_cap_smoke.exe"},

    /* AUD-2, i386 (docs/23 §6f): the SAME source as wasapi_smoke.exe built
     * by the i686 cross, run as a WOW64 guest. Its own row and its own file
     * name, so which BITNESS the leg ran is stated rather than inferred —
     * the 32-bit client used to be baked OVER the 64-bit one's name because
     * the foreground was picked by probing for that name. Written never to
     * return, so returning is the verdict. */
    {.leg = "wasapi32",
     .foreground = WSTR("\\??\\C:\\wasapi_smoke32.exe"),
     .tag = "audio",
     .foregroundName = "wasapi_smoke32.exe"},

    /* GUI-2 (docs/02 "winemine.exe appears on screen"): the whole Wine GUI
     * stack painting through winefb.drv onto \Device\Fb0. Reached when the
     * app dies; the leg itself screendumps and quits QEMU rather than closing
     * the window, so in practice returning here IS the diagnosis. */
    {.leg = "gui2", .foreground = WSTR("\\??\\C:\\winemine.exe"), .tag = "gui2"},

    /* GUI-3 (docs/02 "two GUI processes run at once"): wineserver-lite
     * (already started before firstboot -- smss.c) with two GUI clients above
     * it. gui3a is fire-and-forget (its window must still be up for the
     * screendumps); gui3b prints the verdict and parks. */
    {.leg = "gui3",
     .background = WSTR("\\??\\C:\\gui3a.exe"),
     .foreground = WSTR("\\??\\C:\\gui3b.exe"),
     .tag = "gui3"},

    /* GUI-4 (docs/02 "windows can be grabbed and moved"): the gui3
     * arrangement with overlapping windows, driven by the harness through
     * the tablet and keyboard. Both clients park pumping forever; the leg
     * owns QEMU's lifetime. */
    {.leg = "gui4",
     .background = WSTR("\\??\\C:\\gui4a.exe"),
     .foreground = WSTR("\\??\\C:\\gui4b.exe"),
     .tag = "gui4"},

    /* GUI-5 (docs/02 "GUI finishing"): clipboard, hooks and AttachThreadInput
     * cross-process, plus the guest half of the font-metrics differential.
     * fontdiff is the prologue for two reasons: its metric lines must land
     * un-interleaved with the clients' output, and it must have EXITED --
     * releasing any exclusively-opened input device its winefb instance won
     * -- before gui5a starts (docs/03 GUI-4 notes). Which process ends up
     * HOSTING the readers is no longer gui5a's by construction: conhost links
     * the real user32 on every Gui boot and can win the exclusive opens
     * first. The readers post to the foreground window and the server routes
     * globally, so the leg's markers appear either way. */
    {.leg = "gui5",
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
    /* Net-3 (docs/02 "an off-the-shelf tool completes an HTTPS fetch over
     * virtio-net"): UNMODIFIED curl.exe, bundled TLS, driven by the
     * per-run config the harness mcopy'd to C:\net3\job.txt. (That file used
     * to be the PROBE that selected this flow; the leg name selects it now,
     * and the file is only curl's input.) The
     * config carries the URL, the test CA, the output path and a retry
     * budget that outlasts the DHCP bind. curl EXITS, so the verdict is
     * the leg's plain exit line ("[KTEST] net3 exit (status=0x0, exit=0x0)")
     * — the harness reads it, ends the guest, and convicts the fetched
     * bytes by hash from the image (tests/run/run.sh net3). */
    {.leg = "net3",
     .foreground = WSTR("\\??\\C:\\curl.exe"),
     .foregroundCmdline = WSTR("curl.exe -K C:\\net3\\job.txt"),
     .tag = "net3"},

    /* WOW64 GUI (docs/23): a 32-bit Win32 client on the SAME desktop the
     * 64-bit stack serves. It used to be typed at a windowed cmd -- which is
     * why it used to need an interactive boot and a leg NAME to be told from
     * `make rungui` -- but the console was only ever the way to start it, and
     * a leg row starts a client without one. `Serial`=1 now, like every other
     * scripted GUI gate: its verdicts are serial lines and the picture the
     * host takes is the CLIENT's window. */
    {.leg = "wow64gui",
     .foreground = WSTR("\\??\\C:\\wow64gui.exe"),
     .tag = "wow64gui",
     .foregroundName = "wow64gui.exe"},

    {.leg = "gui6",
     .foreground = WSTR("\\??\\C:\\windows\\system32\\explorer.exe"),
     .foregroundCmdline = WSTR("explorer.exe /desktop=shell,1280x800 "
                               "C:\\windows\\system32\\explorer.exe C:\\shelf"),
     .tag = "gui6",
     .foregroundName = "explorer.exe"},
};

/* Non-zero when a row matched the boot's leg — the caller convicts an
 * unknown leg name rather than letting it read as "no leg". A row that runs
 * usually never returns (see the table's note). */
static int SessionFlowGui(void)
{
    /* Kept for the process's lifetime on purpose: the background client must
     * still be running when the host takes its screendumps, so its handles
     * are never closed. One pair is enough -- a boot names ONE leg, so at
     * most one row runs. */
    static HANDLE SessionGuiBackground, SessionGuiBackgroundThread;

    for (unsigned int i = 0; i < sizeof(SessionGuiLegs) / sizeof(SessionGuiLegs[0]); i++)
    {
        const GUI_LEG *leg = &SessionGuiLegs[i];
        NTSTATUS exitStatus = 0;
        NTSTATUS status;

        if (!SessionLegIs(leg->leg))
            continue; /* not the leg this boot asked for */

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
                return 1;
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
        return 1;
    }
    return 0;
}

/* The WOW64 acceptance (docs/02 "a 32-bit CUI app runs"): hello32.exe is an
 * ordinary 32-bit Win32 console program, so a PASS here means the whole
 * chain worked — the kernel built a WOW64 process, the 64-bit ntdll found
 * WowTebOffset set and loaded wow64.dll, wow64cpu far-jumped into compat
 * mode, and every syscall the guest made came back through it. Selected by
 * the wow64 leg; the client is on the TEST image (not the dev one, which
 * carries no test payload -- there its absence is a loud create failure,
 * which is the right answer for a leg asked of the wrong image). */
static int SessionFlowWow64(void)
{
    static const WCHAR path[] = WSTR("\\??\\C:\\hello32.exe");
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
    SessionLoadBootStrings();
    SmssPrintf("smss: leg=\"%s\" subtests=\"%s\"\n", SessionLeg, SessionSubtests);

    /* The boot suite: on every leg, because it is what says the machine
     * this leg's verdict was measured on came up at all. */
    int failures = 0;
    failures += SessionFlowM8(registryOk);
    failures += SessionFlowM9(abiFailures);

    /* Then exactly one leg. The order below is the historical one, so a leg
     * that used to share an image with another still reports in the same
     * place on serial. */
    /* `fuzz` runs the same sweep as `ntapi` and is a separate NAME because it
     * is a separate MACHINE: a hermetic fixture volume carrying ntdll, smss
     * and the interpreter, from which the kernel derives `Userland`=0. Sharing
     * the name would mean the product regression gate and the fuzzer's boot
     * could not be told apart by the one thing that says what a boot is. */
    if (SessionLegIs("ntapi") || SessionLegIs("fuzz"))
    {
        failures += SessionFlowNtapi();
    }
    else if (SessionLegIs("wtest"))
    {
        failures += SessionFlowWtest(WSTR("\\??\\C:\\wtests\\manifest.txt"));
    }
    else if (SessionLegIs("winetest-gui"))
    {
        /* GUI-5's trophy gate: the same sweep over its own curated list
         * (tests/winetest/manifest-gui.txt), which is baked beside the CUI
         * one rather than over it. */
        failures += SessionFlowWtest(WSTR("\\??\\C:\\wtests\\manifest-gui.txt"));
    }
    else if (SessionLegIs("console"))
    {
        /* Block on the interactive echo (the M9 acceptance's other half),
         * AFTER the M9 verdict so the runner knows the boot suite is already
         * green; then the interactive cmd session. */
        failures += SessionFlowM9Echo();
        failures += SessionFlowCmdConsole();
    }
    else if (SessionLegIs("wow64"))
    {
        failures += SessionFlowWow64();
    }
    else
    {
        /* Either a GUI leg (the table above) or the empty leg, which is the
         * boot suite and nothing else. A leg NAME this build does not know
         * must not read as the empty one: the run would report a healthy
         * boot for a test that never ran (Art. 12). */
        if (SessionLeg[0] != 0 && !SessionFlowGui())
        {
            SmssPrintf("[KTEST] leg FAIL (no leg named \"%s\")\n", SessionLeg);
            failures++;
        }
    }

    return failures;
}

/* Hand the console to a human-driven cmd.exe; the kernel powers the VM off
 * when smss exits (`exit` at the prompt). A start failure still returns —
 * an interactive boot has no runner watching a timeout. */
void SessionInteractive(void)
{
    /* A SHELL session does not get a console opened FOR it. explorer IS the
     * launcher — that is what a shell is — so a human lands on the desktop
     * and starts what they want from it, exactly as they would on Windows.
     * Opening cmd.exe on top of that is a serial-console habit: there, the
     * console is the only way in, so smss has to hand it over.
     *
     * A scripted boot that drives a CONSOLE session says so with `Serial`,
     * which is what SmssIsShellBoot subtracts -- the Flash fixtures start the
     * projector from a prompt and read their verdicts off that transport.
     * `make rungui` asks for no such thing and lands on the desktop; `make
     * run` has no desktop to land on and takes the console either way. GUI-5's
     * console-window leg is the one that still needs its NAME to be told from
     * `make rungui`, and SmssIsShellBoot is where that is said.
     *
     * Blocking on explorer is the park: the desktop shell does not exit, and
     * when it does the session is over and the kernel powers the VM off —
     * the same contract `exit` has in the console session. */
    if (SmssIsShellBoot())
    {
        SmssSay("\nproskrnl: interactive desktop - explorer is the launcher\n\n");
        NTSTATUS exitStatus = 0;
        NTSTATUS status = SmssRun(WSTR("\\??\\C:\\windows\\system32\\explorer.exe"),
                                  WSTR("explorer.exe /desktop=shell,1280x800"), 0, 0, &exitStatus);
        if (status != STATUS_SUCCESS)
            SmssPrintf("proskrnl: explorer.exe failed to start (%x)\n", SMSS_HEX(status));
        return;
    }

    SmssSay("\nproskrnl: interactive console - starting cmd.exe (type 'exit' to power off)\n\n");
    NTSTATUS exitStatus = 0;
    NTSTATUS status = SmssRun(WSTR("\\??\\C:\\windows\\system32\\cmd.exe"), 0, 1, 0, &exitStatus);
    if (status != STATUS_SUCCESS)
        SmssPrintf("proskrnl: cmd.exe failed to start (%x)\n", SMSS_HEX(status));
}
