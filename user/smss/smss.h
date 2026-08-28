/* user/smss/smss.h — the proskrnl session manager (shared decls).
 *
 * smss.exe is the single process the kernel launches at the end of boot
 * (kernel/init/main.c KiRunSessionManager); everything user-mode after that
 * — servers, firstboot, the acceptance flows, the test sweeps, the GUI legs
 * — is spawned from here through the real NtCreateUserProcess boundary.
 * This is our own code, not Wine glue, so it follows the kernel style rules
 * (docs/15) — only user/wine/ is exempt. */
#ifndef PROSKRNL_USER_SMSS_H
#define PROSKRNL_USER_SMSS_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntobapi.h"
#include "abi/ntioapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntpebteb.h"

/* char16_t literal; a bare u"" prefix does not survive clang-format. */
#define WSTR(s) u##s

/* Sign-extend an NTSTATUS the way the kernel's DbgPrint("%#lx",
 * (unsigned long)status) did, so FAIL lines keep their historical spelling
 * (0xffffffffc0000005, not 0xc0000005). */
#define SMSS_HEX(v) ((unsigned long long)(long long)(LONG)(v))

/* --- smss.c: output + small utilities ------------------------------------- */

void SmssSay(const char *ascii);
/* Minimal formatter over NtDisplayString (the serial [KTEST] transport —
 * kernel/ps/display.c). %s (ascii), %d, %u, and %x with the kernel DbgPrint
 * %#lx spelling (always 0x-prefixed); %x consumes unsigned long long — cast
 * at the call site (SMSS_HEX for NTSTATUS values). */
void SmssPrintf(const char *fmt, ...);
void SmssInitUnicodeString(UNICODE_STRING *str, const WCHAR *wide);
void SmssSleep(ULONG milliseconds);

/* The boot profiler's ring-3 half (smss.c, kernel/init/profile.h): print how
 * long the step that just finished took, and how far into the session it
 * ends. Silent unless the boot armed the profiler (Hardware\qemu "Profile",
 * tools/qemu.sh GUEST_PROFILE=1). */
int SmssIsProfileBoot(void);
void SmssMark(const char *step);

/* The QEMU boot flags, read out of the volatile
 * \Registry\Machine\Hardware\qemu key the kernel published from the command
 * line's fw_cfg items (kernel/cm/registry.c, HACK-006). An absent key means
 * we are not on QEMU at all, which is what `whenNotQemu` answers. */
ULONG SmssQemuFlag(const WCHAR *valueName, ULONG whenNotQemu);

/* The longest fw_cfg STRING the kernel publishes under that key
 * (kernel/cm/registry.c CMP_QEMU_STRING_MAX). One number for both sides —
 * a smaller one here would read a value the kernel published in full as the
 * empty string, which for the sweep filter means "every case". */
#define SMSS_QEMU_STRING_MAX 4096

/* The REG_SZ twin of SmssQemuFlag: copies the value into `out` (at most
 * `outChars` including the terminator). Every failure — no QEMU, no value,
 * a wrong type — is the EMPTY string, which is each consumer's "unspecified"
 * (no leg = the plain boot suite; no filter = every case). */
void SmssQemuString(const WCHAR *valueName, WCHAR *out, ULONG outChars);

/* Did the QEMU command line ask for an interactive boot? Reads "Interactive";
 * an absent key means we are not on QEMU at all, which defaults to
 * interactive (smss.c). */
int SmssIsInteractiveBoot(void);

/* Does this boot bring up the DESKTOP stack? Reads "Gui", which defaults
 * ON: the desktop is the product, and a CUI-only boot says so
 * (tools/qemu.sh GUEST_GUI=0). The boot console is on the serial wire
 * either way (issue #232) — `Gui` decides the desktop, not the console. */
int SmssIsGuiBoot(void);
int SmssHasUserland(void);

/* Does explorer own the desktop on this boot? DERIVED from `Gui`, `Interactive`,
 * `Serial` and the leg name -- there is no `Shell` flag -- and published as
 * `ShellBoot` for the PE side, which is what
 * user/wine/wineserver-lite/common/shim.c probe_shell reads. The scripted GUI
 * legs derive 0 and run purpose-built clients over the desktop server's own
 * fixtures. */
int SmssIsShellBoot(void);

/* Does this boot keep its console on the serial transport? (`Serial`) */
int SmssIsSerialBoot(void);

/* Publish SmssIsShellBoot's answer for the PE side (the desktop server and
 * winefb.drv). Call before any win32u client starts. */
void SmssPublishShellBoot(void);

/* --- launch.c: spawning over NtCreateUserProcess --------------------------- */

/* smss's own process parameters (set at entry): children built with an
 * explicit parameter block reuse this furniture — DllPath, current
 * directory, environment — so they match what the kernel synthesizes for a
 * params-less create (kernel/ps/peb.c PspBuildDefaultParams). */
extern RTL_USER_PROCESS_PARAMETERS *SmssOwnParams;

/* Spawn `ntPath` ("\??\C:\...") and return its handles. `cmdline` 0 means
 * the DOS image path. `console` seeds the child's console process-parameter
 * fields: 0 = console-less (CONSOLE_HANDLE_SHELL_NO_WINDOW, the oracle's
 * runner shape — launch.c says why), 1 = attach to the BOOT console (valid
 * only once SmssStartConhost reported the server up), 2 = the client
 * allocates its own console (the CONSOLE_HANDLE_ALLOC sentinel; a CUI
 * child's kernelbase spawns its own windowed conhost).
 *
 * `currentDirectory` is the DOS directory the child starts in; 0 means
 * smss's own, which is the kernel default C:\windows\system32\. Only the
 * winetest sweep names one, because only it has an ORACLE half whose
 * directory it must match (session.c SessionFlowWtest). */
NTSTATUS SmssSpawn(const WCHAR *ntPath, const WCHAR *cmdline, int console,
                   const WCHAR *currentDirectory, HANDLE *processOut, HANDLE *threadOut);
/* Spawn and wait. timeoutMs 0 = forever. On STATUS_TIMEOUT the child is
 * STILL RUNNING and cannot be reaped (no foreign terminate — docs/03); its
 * handles are deliberately leaked and the caller must not run further
 * console clients. */
NTSTATUS SmssRun(const WCHAR *ntPath, const WCHAR *cmdline, int console,
                 const WCHAR *currentDirectory, ULONG timeoutMs, NTSTATUS *exitOut);

/* The system servers, in dependency order: wineserver-lite (HACK-003) first
 * — anything that loads win32u is its client, including the GUI-5 windowed
 * conhost — then conhost with the ConDrv attach wait. Both probe/skip on
 * the image content and are fire-and-forget (permanent processes; the
 * handles are kept forever). */
void SmssStartWineServer(void);
void SmssStartConhost(void);
int SmssConsoleAvailable(void);

/* --- session.c: the acceptance flows --------------------------------------- */

/* The test session: the hello/M8 chain and m9_smoke/M9 (folding the kernel's
 * ABI-probe failures passed on the command line) on every boot, then whatever
 * the QEMU command line's LEG selected — the ntapi or winetest sweep, the
 * console flows, wow64, or one of the GUI legs (which park forever). Returns
 * the failure count smss exits with. */
int SessionRun(int abiFailures, int registryOk);

/* Read the `Leg`/`Subtests` boot strings, once. Idempotent: the shell
 * derivation below asks before the servers start, SessionRun asks again at
 * the top of the test session. */
void SessionLoadBootStrings(void);

/* The leg this boot read, for diagnostics. */
const char *SessionLegName(void);

/* Is the selected leg ABOUT the shell (GUI-6)? The one scripted leg that
 * wants explorer owning the desktop — see session.c. */
int SessionIsShellIntegrationLeg(void);
/* The interactive boot (make run): hand the console to a human cmd.exe;
 * returns when the user typed `exit` (the kernel powers off on smss exit). */
void SessionInteractive(void);

/* --- firstboot.c ----------------------------------------------------------- */

/* Run `wineboot.exe --init` synchronously; returns the exit status (0 =
 * machine state populated / already fresh). */
NTSTATUS FirstbootRun(void);

#endif /* PROSKRNL_USER_SMSS_H */
