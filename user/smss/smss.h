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
/* Existence probe on the boot volume; *statusOut (optional) gets the raw
 * NtCreateFile status so callers can tell "not found" from a broken open. */
int SmssFileExists(const WCHAR *ntPath, NTSTATUS *statusOut);

/* Did the QEMU command line ask for an interactive boot? Reads
 * \Registry\Machine\Hardware\qemu "Interactive"; an absent key means we are
 * not on QEMU at all, which defaults to interactive (smss.c). */
int SmssIsInteractiveBoot(void);

/* --- launch.c: spawning over NtCreateUserProcess --------------------------- */

/* smss's own process parameters (set at entry): children built with an
 * explicit parameter block reuse this furniture — DllPath, current
 * directory, environment — so they match what the kernel synthesizes for a
 * params-less create (kernel/ps/peb.c PspBuildDefaultParams). */
extern RTL_USER_PROCESS_PARAMETERS *SmssOwnParams;

/* Spawn `ntPath` ("\??\C:\...") and return its handles. `cmdline` 0 means
 * the DOS image path; `console` seeds the child's ConsoleHandle/hStd*
 * process-parameter fields from smss's ConDrv handles (valid only once
 * SmssStartConhost reported the server up). */
NTSTATUS SmssSpawn(const WCHAR *ntPath, const WCHAR *cmdline, int console, HANDLE *processOut,
                   HANDLE *threadOut);
/* Spawn and wait. timeoutMs 0 = forever. On STATUS_TIMEOUT the child is
 * STILL RUNNING and cannot be reaped (no foreign terminate — docs/03); its
 * handles are deliberately leaked and the caller must not run further
 * console clients. */
NTSTATUS SmssRun(const WCHAR *ntPath, const WCHAR *cmdline, int console, ULONG timeoutMs,
                 NTSTATUS *exitOut);

/* The system servers, in dependency order: wineserver-lite (HACK-003) first
 * — anything that loads win32u is its client, including the GUI-5 windowed
 * conhost — then conhost with the ConDrv attach wait. Both probe/skip on
 * the image content and are fire-and-forget (permanent processes; the
 * handles are kept forever). */
void SmssStartWineServer(void);
void SmssStartConhost(void);
int SmssConsoleAvailable(void);

/* --- session.c: the acceptance flows --------------------------------------- */

/* The test session, in the historical kernel-runner order: hello/M8 chain,
 * m9_smoke/M9 (folding the kernel's ABI-probe failures passed on the
 * command line), the ntapi and winetest sweeps, m9_echo, the cmd console,
 * and the GUI legs (which park forever on GUI images). Returns the failure
 * count smss exits with. */
int SessionRun(int abiFailures, int registryOk);
/* The interactive boot (make run): hand the console to a human cmd.exe;
 * returns when the user typed `exit` (the kernel powers off on smss exit). */
void SessionInteractive(void);

/* --- firstboot.c ----------------------------------------------------------- */

/* Run `wineboot.exe --init` synchronously; returns the exit status (0 =
 * machine state populated / already fresh). */
NTSTATUS FirstbootRun(void);

#endif /* PROSKRNL_USER_SMSS_H */
